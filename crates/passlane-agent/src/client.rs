//! The blocking client the `passlane` CLI (and tests) use to talk to a
//! running agent. One request is outstanding per connection at a time;
//! for pushed events use [`AgentClient::subscribe`].
//!
//! Unix-only in practice, but the type and its full method surface
//! compile everywhere (the CLI is built on Windows too): on non-Unix
//! platforms [`AgentClient::connect`] always fails with
//! [`AgentError::NotRunning`] and every other method is an unreachable
//! stub, so the CLI's optional-agent code paths degrade to their
//! agent-absent behavior.

#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use passlane_approval::message::Scope;
use zeroize::Zeroizing;

use crate::error::AgentError;
use crate::protocol::{
    ChallengeResponseMaterial, Event, GrantSpec, MAX_FRAME_LEN, PROTOCOL_VERSION, Request,
    Response, SessionInfo, decode, read_frame, write_frame,
};

/// How long a client waits for the agent's answer to one request. The
/// agent is local and answers at once; silence means it is wedged, and a
/// command must not wait on it for good. Subscribed event streams are not
/// subject to it — they wait for events by design.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// How long establishing a connection to the agent may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// A connection to a running agent.
pub struct AgentClient {
    #[cfg(unix)]
    stream: UnixStream,
    path: PathBuf,
    #[cfg(unix)]
    request_timeout: Duration,
}

/// What [`AgentClient::ping`] learned about the agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PongInfo {
    /// Protocol dialect version.
    pub version: u32,
    /// The agent's session-duration cap, seconds.
    pub max_session_secs: u64,
    /// Live session count.
    pub sessions: usize,
}

/// A freshly created session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedSession {
    /// Session id.
    pub id: String,
    /// Expiry, unix seconds (`None` for `once`).
    pub expires_at: Option<u64>,
}

/// The unlock factors a live session holds for a vault. `Debug` redacts
/// the password.
#[derive(Clone, PartialEq, Eq)]
pub struct UnlockFactors {
    /// The vault's master password.
    pub master_password: Zeroizing<String>,
    /// The vault's challenge-response factor, when the session holds it.
    pub challenge_response: Option<ChallengeResponseMaterial>,
    /// When the serving session expires, unix seconds (`None` for a
    /// consumed `once` session) so long-running callers can revalidate.
    pub expires_at: Option<u64>,
}

impl std::fmt::Debug for UnlockFactors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockFactors")
            .field("master_password", &"***")
            .field("challenge_response", &self.challenge_response)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// The answer to a reveal check: allowed (with the covering session's
/// expiry, or `None` when a `once` approval was just consumed) or not
/// covered by any live session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevealAnswer {
    /// A live session covers the reveal. `until` is its expiry (unix
    /// seconds) for timed sessions, or `None` for a consumed `once`
    /// approval.
    Allowed {
        /// Expiry of the covering session, if any.
        until: Option<u64>,
    },
    /// No live session covers this reveal.
    Denied,
}

impl AgentClient {
    /// The socket this client is connected to (or attempted).
    pub fn socket_path(&self) -> &Path {
        &self.path
    }
}

impl std::fmt::Debug for AgentClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentClient")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

#[cfg(unix)]
impl AgentClient {
    /// Connect to the agent listening on `path`. Connection-refused and
    /// no-such-socket map to [`AgentError::NotRunning`] so callers can
    /// degrade gracefully (the agent is optional).
    ///
    /// Before anything is sent, the socket is validated — and after
    /// connecting it is *re*-validated: it must be an actual socket,
    /// owned by the connecting user, with no group/other access bits.
    /// The double check closes the create/replace race on explicitly
    /// configured shared-directory paths (nothing is transmitted during
    /// `connect`, so a mismatch is closed before any secret can leak),
    /// and metadata errors fail closed instead of skipping validation.
    ///
    /// Establishing the connection is bounded like every exchange with
    /// the agent: a daemon wedged with a full listen queue would
    /// otherwise hold the command inside `connect` forever.
    pub fn connect(path: &Path) -> Result<AgentClient, AgentError> {
        socket_is_trusted(path)?;
        let owned_path = path.to_path_buf();
        match answer_within(CONNECT_TIMEOUT, move || UnixStream::connect(&owned_path)) {
            Some(Ok(stream)) => {
                // The connection is established; make sure the path we
                // connected to is still the one we validated.
                socket_is_trusted(path)?;
                // A trusted socket whose listener never answers must not
                // hold the command for good.
                stream.set_read_timeout(Some(REQUEST_TIMEOUT))?;
                Ok(AgentClient {
                    stream,
                    path: path.to_path_buf(),
                    request_timeout: REQUEST_TIMEOUT,
                })
            }
            Some(Err(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
                ) =>
            {
                Err(AgentError::NotRunning(path.display().to_string()))
            }
            Some(Err(e)) => Err(e.into()),
            None => Err(AgentError::TimedOut(CONNECT_TIMEOUT)),
        }
    }

    /// How long to wait for the agent's answer to one request (see
    /// [`REQUEST_TIMEOUT`]).
    pub fn set_request_timeout(&mut self, timeout: Duration) -> Result<(), AgentError> {
        self.stream.set_read_timeout(Some(timeout))?;
        self.request_timeout = timeout;
        Ok(())
    }

    fn call(&mut self, request: Request) -> Result<Response, AgentError> {
        write_frame(&mut self.stream, &request)?;
        // One deadline for the whole answer, not per read: a peer that
        // delivers a byte at a time would otherwise stretch a frame out
        // indefinitely, each read inside its own timeout.
        let deadline = std::time::Instant::now() + self.request_timeout;
        let frame = read_frame_deadlined(&mut self.stream, deadline, self.request_timeout)?;
        match decode(&frame)? {
            Response::Error { code, message } => Err(AgentError::Server { code, message }),
            response => Ok(response),
        }
    }

    /// Probe the agent: version, session cap and live session count.
    pub fn ping(&mut self) -> Result<PongInfo, AgentError> {
        match self.call(Request::Ping)? {
            Response::Pong {
                version,
                max_session_secs,
                sessions,
            } => Ok(PongInfo {
                version,
                max_session_secs,
                sessions,
            }),
            other => Err(AgentError::Protocol(format!(
                "unexpected answer: {other:?}"
            ))),
        }
    }

    /// Make sure the agent speaks this client's protocol dialect, and
    /// return what [`AgentClient::ping`] learned about it. An agent left
    /// running from an older binary would take every request and quietly
    /// drop the factors it does not know about, so a mismatch is reported
    /// as [`AgentError::VersionMismatch`] instead.
    pub fn check_version(&mut self) -> Result<PongInfo, AgentError> {
        let pong = self.ping()?;
        if pong.version != PROTOCOL_VERSION {
            return Err(AgentError::VersionMismatch {
                agent: pong.version,
                client: PROTOCOL_VERSION,
            });
        }
        Ok(pong)
    }

    /// Create a session. `Err(AgentError::Server { code:
    /// ErrorCode::TooLong, .. })` means the requested duration exceeds
    /// the agent's cap.
    pub fn create_session(
        &mut self,
        vault: &str,
        grant: GrantSpec,
        scope: Scope,
    ) -> Result<CreatedSession, AgentError> {
        match self.call(Request::CreateSession {
            vault: vault.to_string(),
            grant,
            scope,
        })? {
            Response::SessionCreated { id, expires_at } => Ok(CreatedSession { id, expires_at }),
            other => Err(AgentError::Protocol(format!(
                "unexpected answer: {other:?}"
            ))),
        }
    }

    /// Fetch the unlock factors a live session holds for the vault — the
    /// master password and, when the session carries it, the
    /// challenge-response material — plus the serving session's expiry
    /// (unix seconds; `None` for a consumed `once` session). Consumes a
    /// `once`-scoped session.
    pub fn get_unlock_factors(&mut self, vault: &str) -> Result<UnlockFactors, AgentError> {
        match self.call(Request::GetUnlockFactors {
            vault: vault.to_string(),
        })? {
            Response::UnlockFactors {
                master_password,
                challenge_response,
                expires_at,
            } => Ok(UnlockFactors {
                master_password: master_password.into_inner(),
                challenge_response,
                expires_at,
            }),
            other => Err(AgentError::Protocol(format!(
                "unexpected answer: {other:?}"
            ))),
        }
    }

    /// Does a live reveal session cover this entry field, matched by the
    /// entry's stable UUID? An `Allowed` answer consumes a `once`-scoped
    /// approval; `Denied` means the caller falls back to the ask flow.
    pub fn check_reveal(
        &mut self,
        vault: &str,
        id: &str,
        field: &str,
    ) -> Result<RevealAnswer, AgentError> {
        match self.call(Request::CheckReveal {
            vault: vault.to_string(),
            id: id.to_string(),
            field: field.to_string(),
        })? {
            Response::RevealCheck { allowed, until } => Ok(if allowed {
                RevealAnswer::Allowed { until }
            } else {
                RevealAnswer::Denied
            }),
            other => Err(AgentError::Protocol(format!(
                "unexpected answer: {other:?}"
            ))),
        }
    }

    /// Live sessions, oldest first. Never contains secrets.
    pub fn list_sessions(&mut self) -> Result<Vec<SessionInfo>, AgentError> {
        match self.call(Request::ListSessions)? {
            Response::Sessions { list } => Ok(list),
            other => Err(AgentError::Protocol(format!(
                "unexpected answer: {other:?}"
            ))),
        }
    }

    /// Revoke one session by id.
    pub fn revoke_session(&mut self, id: &str) -> Result<usize, AgentError> {
        match self.call(Request::RevokeSession { id: id.to_string() })? {
            Response::Revoked { count } => Ok(count),
            other => Err(AgentError::Protocol(format!(
                "unexpected answer: {other:?}"
            ))),
        }
    }

    /// Revoke every session of one vault.
    pub fn revoke_vault(&mut self, vault: &str) -> Result<usize, AgentError> {
        match self.call(Request::RevokeVault {
            vault: vault.to_string(),
        })? {
            Response::Revoked { count } => Ok(count),
            other => Err(AgentError::Protocol(format!(
                "unexpected answer: {other:?}"
            ))),
        }
    }

    /// Revoke every session.
    pub fn revoke_all(&mut self) -> Result<usize, AgentError> {
        match self.call(Request::RevokeAll)? {
            Response::Revoked { count } => Ok(count),
            other => Err(AgentError::Protocol(format!(
                "unexpected answer: {other:?}"
            ))),
        }
    }

    /// Revoke everything the agent holds (it keeps running).
    pub fn lock(&mut self) -> Result<(), AgentError> {
        match self.call(Request::Lock)? {
            Response::Locked => Ok(()),
            other => Err(AgentError::Protocol(format!(
                "unexpected answer: {other:?}"
            ))),
        }
    }

    /// Turn this connection into an event stream. After subscribing, the
    /// agent pushes [`Event`] frames (revocation, expiry, lock
    /// notifications); no further requests can be sent on it.
    pub fn subscribe(mut self) -> Result<EventStream, AgentError> {
        match self.call(Request::Subscribe)? {
            Response::Subscribed => {
                // From here on the stream only carries events, whenever
                // they come: it must not time out.
                self.stream.set_read_timeout(None)?;
                Ok(EventStream {
                    stream: self.stream,
                })
            }
            other => Err(AgentError::Protocol(format!(
                "unexpected answer: {other:?}"
            ))),
        }
    }
}

/// A subscribed connection receiving pushed events.
#[cfg(unix)]
pub struct EventStream {
    stream: UnixStream,
}

#[cfg(unix)]
impl EventStream {
    /// Block until the next event, or error when the agent goes away.
    pub fn next_event(&mut self) -> Result<Event, AgentError> {
        let frame = read_frame(&mut self.stream)?;
        decode(&frame)
    }

    /// Bound how long [`EventStream::next_event`] blocks (tests and
    /// polling callers).
    pub fn set_read_timeout(&self, timeout: std::time::Duration) -> Result<(), AgentError> {
        self.stream.set_read_timeout(Some(timeout))?;
        Ok(())
    }
}

/// Run `work` on its own thread and wait for its answer at most `bound`.
/// `None` when it has not answered by then (the thread is left to finish
/// or linger on its own). Used to bound things std offers no timeout for,
/// like connecting to a socket whose peer stopped accepting.
fn answer_within<T: Send + 'static>(
    bound: Duration,
    work: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("passlane-agent-connect".into())
        .spawn(move || {
            let _ = tx.send(work());
        })
        .ok()?;
    rx.recv_timeout(bound).ok()
}

/// [`read_frame`] with an absolute deadline for the whole frame: every
/// read is given only the time left, so a peer drip-feeding bytes — each
/// read within its own slice — still ends at the deadline.
fn read_frame_deadlined(
    stream: &mut UnixStream,
    deadline: std::time::Instant,
    timeout: Duration,
) -> Result<Zeroizing<Vec<u8>>, AgentError> {
    let mut len_buf = [0u8; 4];
    read_exact_deadlined(stream, &mut len_buf, deadline, timeout)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_LEN {
        return Err(AgentError::Protocol(format!(
            "announced frame of {len} bytes exceeds the {MAX_FRAME_LEN}-byte limit"
        )));
    }
    let mut buf = Zeroizing::new(vec![0u8; len]);
    read_exact_deadlined(stream, &mut buf, deadline, timeout)?;
    Ok(buf)
}

/// [`std::io::Read::read_exact`] with an absolute deadline, adjusting the
/// socket's read timeout to the time left before every read.
fn read_exact_deadlined(
    stream: &mut UnixStream,
    mut buf: &mut [u8],
    deadline: std::time::Instant,
    timeout: Duration,
) -> Result<(), AgentError> {
    use std::io::Read;
    while !buf.is_empty() {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(AgentError::TimedOut(timeout));
        }
        // Whole milliseconds: sub-millisecond read timeouts can be refused.
        if let Err(e) = stream.set_read_timeout(Some(remaining.max(Duration::from_millis(1)))) {
            // macOS refuses to set a read timeout on a socket whose peer
            // has already closed, even with data still readable. The read
            // below reports that state; only the deadline still guards it.
            if e.kind() != std::io::ErrorKind::InvalidInput {
                return Err(e.into());
            }
        }
        match stream.read(buf) {
            Ok(0) => {
                return Err(AgentError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "the agent closed the connection",
                )));
            }
            Ok(n) => buf = &mut buf[n..],
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err(AgentError::TimedOut(timeout));
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Validate a socket path before any secret can travel over it: it must
/// be a socket, carry no group/other permission bits, and be owned by
/// the connecting user. Ownership is established without libc by
/// creating a probe file next to the socket — whatever uid creates files
/// in that directory is us — and comparing owners.
#[cfg(unix)]
fn socket_is_trusted(path: &Path) -> Result<(), AgentError> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

    let refuse = |reason: String| {
        Err(AgentError::Protocol(format!(
            "untrusted socket '{}': {reason} (the session agent socket must be a \
             user-owned socket with 0600 permissions in a private directory)",
            path.display()
        )))
    };

    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        // A missing path is not a trust question — connect reports
        // NotRunning. Every other metadata failure (permissions, a
        // dangling symlink, ...) fails closed: no validation, no
        // connection.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return refuse(format!("could not inspect it ({e})")),
    };
    if !meta.file_type().is_socket() {
        return refuse("not a socket".into());
    }
    if meta.permissions().mode() & 0o077 != 0 {
        return refuse("group/other access bits set".into());
    }
    // Ownership: a socket anyone could create in a shared directory
    // would otherwise receive the master password. Probe with a file we
    // create ourselves in the same directory.
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let probe = parent.join(format!(".passlane-probe-{}", uuid::Uuid::new_v4()));
    let probe_uid = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
        .and_then(|_| std::fs::metadata(&probe))
        .map(|m| m.uid());
    let _ = std::fs::remove_file(&probe);
    match probe_uid {
        Ok(uid) if uid == meta.uid() => Ok(()),
        Ok(_) => refuse("owned by another user".into()),
        Err(e) => refuse(format!("could not verify ownership ({e})")),
    }
}

// Non-Unix platforms have no Unix domain sockets. Keep the full method
// surface so the CLI (built on Windows too) compiles unchanged; nothing
// here is reachable because `connect` never succeeds.

#[cfg(not(unix))]
impl AgentClient {
    /// There is no agent to talk to on this platform.
    pub fn connect(path: &Path) -> Result<AgentClient, AgentError> {
        Err(AgentError::NotRunning(format!(
            "the session agent requires a Unix domain socket (macOS/Linux); \
             not available on this platform (tried {})",
            path.display()
        )))
    }
}

#[cfg(not(unix))]
macro_rules! unsupported {
    () => {
        Err(AgentError::Protocol(
            "the session agent requires a Unix domain socket (macOS/Linux)".into(),
        ))
    };
}

#[cfg(not(unix))]
impl AgentClient {
    /// Unsupported on this platform (see [`AgentClient::connect`]).
    pub fn ping(&mut self) -> Result<PongInfo, AgentError> {
        unsupported!()
    }
    /// Unsupported on this platform (see [`AgentClient::connect`]).
    pub fn check_version(&mut self) -> Result<PongInfo, AgentError> {
        unsupported!()
    }
    /// Unsupported on this platform (see [`AgentClient::connect`]).
    pub fn set_request_timeout(&mut self, _timeout: Duration) -> Result<(), AgentError> {
        unsupported!()
    }
    /// Unsupported on this platform (see [`AgentClient::connect`]).
    pub fn create_session(
        &mut self,
        _vault: &str,
        _grant: GrantSpec,
        _scope: Scope,
    ) -> Result<CreatedSession, AgentError> {
        unsupported!()
    }
    /// Unsupported on this platform (see [`AgentClient::connect`]).
    pub fn get_unlock_factors(&mut self, _vault: &str) -> Result<UnlockFactors, AgentError> {
        unsupported!()
    }
    /// Unsupported on this platform (see [`AgentClient::connect`]).
    pub fn check_reveal(
        &mut self,
        _vault: &str,
        _id: &str,
        _field: &str,
    ) -> Result<RevealAnswer, AgentError> {
        unsupported!()
    }
    /// Unsupported on this platform (see [`AgentClient::connect`]).
    pub fn list_sessions(&mut self) -> Result<Vec<SessionInfo>, AgentError> {
        unsupported!()
    }
    /// Unsupported on this platform (see [`AgentClient::connect`]).
    pub fn revoke_session(&mut self, _id: &str) -> Result<usize, AgentError> {
        unsupported!()
    }
    /// Unsupported on this platform (see [`AgentClient::connect`]).
    pub fn revoke_vault(&mut self, _vault: &str) -> Result<usize, AgentError> {
        unsupported!()
    }
    /// Unsupported on this platform (see [`AgentClient::connect`]).
    pub fn revoke_all(&mut self) -> Result<usize, AgentError> {
        unsupported!()
    }
    /// Unsupported on this platform (see [`AgentClient::connect`]).
    pub fn lock(&mut self) -> Result<(), AgentError> {
        unsupported!()
    }
    /// Unsupported on this platform (see [`AgentClient::connect`]).
    pub fn subscribe(self) -> Result<EventStream, AgentError> {
        unsupported!()
    }
}

/// A subscribed connection receiving pushed events.
#[cfg(not(unix))]
pub struct EventStream;

#[cfg(not(unix))]
impl EventStream {
    /// Unsupported on this platform (see [`AgentClient::connect`]).
    pub fn next_event(&mut self) -> Result<Event, AgentError> {
        unsupported!()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::time::Instant;

    /// An agent that answers `ping` with the given dialect and nothing
    /// else: enough to test what a client does before trusting it.
    fn scripted_agent(version: u32) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let Ok(frame) = read_frame(&mut stream) else {
                return;
            };
            assert!(matches!(decode::<Request>(&frame), Ok(Request::Ping)));
            let pong = Response::Pong {
                version,
                max_session_secs: 900,
                sessions: 0,
            };
            let _ = write_frame(&mut stream, &pong);
        });
        (dir, path)
    }

    #[test]
    fn a_client_refuses_an_agent_speaking_another_dialect() {
        let (_dir, path) = scripted_agent(PROTOCOL_VERSION + 1);
        let mut client = AgentClient::connect(&path).unwrap();
        match client.check_version() {
            Err(AgentError::VersionMismatch { agent, client }) => {
                assert_eq!(agent, PROTOCOL_VERSION + 1);
                assert_eq!(client, PROTOCOL_VERSION);
            }
            other => panic!("expected VersionMismatch, got {other:?}"),
        }

        let (_dir, path) = scripted_agent(PROTOCOL_VERSION);
        let mut client = AgentClient::connect(&path).unwrap();
        assert_eq!(client.check_version().unwrap().version, PROTOCOL_VERSION);
    }

    /// A request timeout that keeps the test short.
    const SHORT_TIMEOUT: Duration = Duration::from_millis(100);

    /// A trusted socket whose listener accepts and then says nothing:
    /// an agent that is wedged.
    fn silent_agent() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::thread::spawn(move || {
            // Hold the connection open without ever answering.
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            std::thread::sleep(Duration::from_secs(10));
            drop(stream);
        });
        (dir, path)
    }

    #[test]
    fn a_wait_is_bounded_even_when_the_work_never_answers() {
        let started = Instant::now();
        assert_eq!(
            answer_within(SHORT_TIMEOUT, || {
                std::thread::sleep(SHORT_TIMEOUT * 20);
            }),
            None
        );
        assert!(
            started.elapsed() < SHORT_TIMEOUT * 5,
            "the wait ends at the bound"
        );
    }

    /// An agent that answers, but slowly: one byte at a time, each within
    /// the request timeout, forever.
    #[test]
    fn a_slowly_delivered_answer_is_not_waited_for() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::thread::spawn(move || {
            use std::io::Write;
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let Ok(frame) = read_frame(&mut stream) else {
                return;
            };
            let pong = Response::Pong {
                version: PROTOCOL_VERSION,
                max_session_secs: 900,
                sessions: 0,
            };
            let mut answer = Vec::new();
            write_frame(&mut answer, &pong).unwrap();
            // Drip it out: a byte every so often, far past the deadline,
            // always within a single read's timeout.
            let _ = frame;
            for byte in answer {
                let _ = stream.write_all(&[byte]);
                let _ = stream.flush();
                std::thread::sleep(SHORT_TIMEOUT / 2);
            }
        });

        let mut client = AgentClient::connect(&path).unwrap();
        client.set_request_timeout(SHORT_TIMEOUT).unwrap();
        let started = Instant::now();
        match client.check_version() {
            // The connection may also break when the test's server thread
            // is still dribbling into a socket nobody reads — either way
            // the wait ended at the deadline, not after the whole frame.
            Err(AgentError::TimedOut(_)) | Err(AgentError::Io(_)) => {}
            other => panic!("expected the deadline, got {other:?}"),
        }
        assert!(
            started.elapsed() < SHORT_TIMEOUT * 4,
            "the wait ends at the deadline: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_client_gives_up_on_an_agent_that_never_answers() {
        let (_dir, path) = silent_agent();
        let mut client = AgentClient::connect(&path).unwrap();
        client.set_request_timeout(SHORT_TIMEOUT).unwrap();
        let started = Instant::now();
        match client.check_version() {
            Err(AgentError::TimedOut(timeout)) => assert_eq!(timeout, SHORT_TIMEOUT),
            other => panic!("expected TimedOut, got {other:?}"),
        }
        assert!(
            started.elapsed() < SHORT_TIMEOUT + Duration::from_secs(2),
            "the wait must end at the bound"
        );
    }

    #[test]
    fn unlock_factors_debug_redacts_the_password() {
        let factors = UnlockFactors {
            master_password: Zeroizing::new("canary-pw".to_string()),
            challenge_response: Some(ChallengeResponseMaterial::Secret {
                secret_hex: crate::protocol::SecretString::new("canary-secret"),
            }),
            expires_at: None,
        };
        let debug = format!("{factors:?}");
        assert!(debug.contains("challenge_response"), "{debug}");
        assert!(!debug.contains("canary"), "{debug}");
    }
}
