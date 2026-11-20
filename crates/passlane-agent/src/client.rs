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

use passlane_approval::message::Scope;
use zeroize::Zeroizing;

use crate::error::AgentError;
use crate::protocol::{
    Event, GrantSpec, Request, Response, SessionInfo, decode, read_frame, write_frame,
};

/// A connection to a running agent.
pub struct AgentClient {
    #[cfg(unix)]
    stream: UnixStream,
    path: PathBuf,
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
    /// Before anything is sent, the socket is validated: it must be an
    /// actual socket, owned by the connecting user, with no group/other
    /// access bits. Without this, a socket pre-created by another user
    /// in a shared directory (e.g. an explicit `PASSLANE_AGENT_SOCK`
    /// pointing into `/tmp`) would receive the master password.
    pub fn connect(path: &Path) -> Result<AgentClient, AgentError> {
        socket_is_trusted(path)?;
        match UnixStream::connect(path) {
            Ok(stream) => Ok(AgentClient {
                stream,
                path: path.to_path_buf(),
            }),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
                ) =>
            {
                Err(AgentError::NotRunning(path.display().to_string()))
            }
            Err(e) => Err(e.into()),
        }
    }

    fn call(&mut self, request: Request) -> Result<Response, AgentError> {
        write_frame(&mut self.stream, &request)?;
        let frame = read_frame(&mut self.stream)?;
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

    /// Fetch a vault's unlock factors from a live session (consuming a
    /// `once`-scoped one).
    pub fn get_unlock_factors(&mut self, vault: &str) -> Result<Zeroizing<String>, AgentError> {
        match self.call(Request::GetUnlockFactors {
            vault: vault.to_string(),
        })? {
            Response::UnlockFactors { master_password } => Ok(master_password.into_inner()),
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
            Response::Subscribed => Ok(EventStream {
                stream: self.stream,
            }),
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
        Err(_) => return Ok(()), // no file yet: connect reports NotRunning
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
    pub fn create_session(
        &mut self,
        _vault: &str,
        _grant: GrantSpec,
        _scope: Scope,
    ) -> Result<CreatedSession, AgentError> {
        unsupported!()
    }
    /// Unsupported on this platform (see [`AgentClient::connect`]).
    pub fn get_unlock_factors(&mut self, _vault: &str) -> Result<Zeroizing<String>, AgentError> {
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
