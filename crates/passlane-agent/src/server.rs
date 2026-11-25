//! The agent's server side: socket setup, the connection loop, the
//! session store, expiry sweeping and event broadcast.
//!
//! Everything is `std`-only: one thread per connection, a mutex-guarded
//! session map and a sweeper thread that expires sessions and pushes
//! [`Event::SessionExpired`] to subscribed clients. The daemon writes
//! nothing to disk except the socket file itself.

use std::collections::HashMap;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use passlane_approval::message::Scope;
use passlane_approval::policy::Policy;

use crate::error::AgentError;
use crate::protocol::{
    self, CHALLENGE_HEX_LEN, ChallengeResponseMaterial, ErrorCode, Event, GrantInfo, GrantSpec,
    MAX_ENTRY_NAME_LEN, MAX_FIELD_NAME_LEN, MAX_ID_LEN, MAX_SECRET_LEN, MAX_VAULT_NAME_LEN,
    PROTOCOL_VERSION, RESPONSE_HEX_LEN, Request, Response, SessionInfo, is_hex_of_len,
};
use crate::session::{ChallengeMaterial, Grant, KeyMaterial, Session};

/// The hard ceiling on any session duration, regardless of
/// configuration: long-lived unlock factors widen the window on a
/// compromised host, so no agent will ever hold one longer than this.
pub const HARD_MAX_SESSION_SECS: u64 = 8 * 60 * 60;

/// The default session cap: the approval protocol's own default
/// (`Policy::max_session_secs`, 15 minutes).
pub fn default_max_session_secs() -> u64 {
    Policy::default().max_session_secs
}

/// Daemon configuration.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// Socket path to listen on.
    pub socket_path: PathBuf,
    /// Maximum session duration this agent will hold (already clamped
    /// to [`HARD_MAX_SESSION_SECS`]).
    pub max_session_secs: u64,
    /// How often the sweeper looks for expired sessions.
    pub sweep_interval: Duration,
}

impl AgentConfig {
    /// Defaults for `socket_path`: cap 900s, sweep every second.
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            max_session_secs: default_max_session_secs().min(HARD_MAX_SESSION_SECS),
            sweep_interval: Duration::from_secs(1),
        }
    }

    /// Raise the session cap (clamped to the hard cap).
    pub fn with_max_session_secs(mut self, secs: u64) -> Self {
        self.max_session_secs = secs.min(HARD_MAX_SESSION_SECS);
        self
    }

    /// Change the expiry-sweep interval (tests use a few milliseconds).
    pub fn with_sweep_interval(mut self, interval: Duration) -> Self {
        self.sweep_interval = interval;
        self
    }
}

/// A running agent's shared state, also handed out as a lightweight
/// [`ServerHandle`] for stopping the server from another thread (signal
/// handlers, tests).
struct Shared {
    inner: Mutex<HashMap<String, Session>>,
    subscribers: Mutex<Vec<Subscriber>>,
    /// Live connections; shutdown closes their sockets so blocked
    /// readers wake and no request is served after the wipe.
    connections: Mutex<Vec<ConnHandle>>,
    max_session_secs: u64,
    stop: AtomicBool,
}

struct Subscriber {
    id: u64,
    tx: mpsc::Sender<Event>,
}

struct ConnHandle {
    id: u64,
    /// A dedicated duplicate of the socket used only for shutdown, so
    /// stopping the agent never waits on a worker's writer mutex (a
    /// blocked write must not be able to stall a SIGTERM).
    shutdown_stream: UnixStream,
}

static NEXT_SUBSCRIBER_ID: AtomicU64 = AtomicU64::new(1);

/// A handle for stopping a running agent (from a signal handler or a
/// test). `stop()` is idempotent; the socket is removed when the server
/// finishes serving.
#[derive(Clone)]
pub struct ServerHandle {
    shared: Arc<Shared>,
    socket_path: PathBuf,
}

impl ServerHandle {
    /// Ask the server to stop serving, wipe its sessions and unlink the
    /// socket.
    pub fn stop(&self) {
        self.shared.stop.store(true, Ordering::SeqCst);
    }

    /// The socket this server listens on.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

/// The agent server. [`AgentServer::bind`] claims the socket,
/// [`AgentServer::serve`] runs the accept loop until stopped.
pub struct AgentServer {
    shared: Arc<Shared>,
    config: AgentConfig,
    listener: UnixListener,
    /// The inode of the socket this server published, captured at bind:
    /// shutdown unlinks the path only while it still leads to *our*
    /// socket — a replacement's must survive our exit (passlane#77).
    socket_identity: Option<u64>,
}

impl std::fmt::Debug for AgentServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentServer")
            .field("socket_path", &self.config.socket_path)
            .finish_non_exhaustive()
    }
}

impl AgentServer {
    /// Bind the socket. Fails with [`AgentError::AlreadyRunning`] when
    /// another agent answers on it; replaces a stale socket left behind
    /// by a crashed agent; refuses to delete a non-socket file that
    /// happens to sit on the path.
    ///
    /// **Concurrent starters converge on one live agent** (auto-start,
    /// passlane#77). The whole look-then-publish sequence runs under an
    /// exclusive advisory lock on the socket's *directory* — no lock
    /// file is created; `flock(2)` works on any descriptor, a
    /// directory's included — so two starters cannot interleave a
    /// liveness probe with another's publication. The listener is
    /// created *beside* the target, fully bound, listening and
    /// permissioned under a short private name, then `rename`d onto it:
    /// the target never holds a socket that is not accepting, the
    /// rename is atomic, and a starter renamed-over (possible only
    /// against non-locking strangers, or after a crash mid-rename)
    /// detects it by the inode the rename preserves. Shutdown unlinks
    /// the socket only when it is still the one this server published.
    pub fn bind(config: AgentConfig) -> Result<AgentServer, AgentError> {
        let path = config.socket_path.clone();
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        std::fs::create_dir_all(&parent)?;
        // Serialize against every starter that locks this directory.
        let _serialization = lock_directory(&parent)?;
        match beside(&path) {
            // The target's pathname is short enough for a sibling: the
            // rename flow above.
            Some(temp) => Self::bind_by_rename(config, path, temp),
            // No sibling fits the kernel's pathname limit for sockets
            // (sun_path): publish directly at the target, still under
            // the lock, keeping the probe/remove/publish semantics of
            // the pre-serialization bind.
            None => Self::bind_in_place(config, path),
        }
    }

    /// The rename flow: listen beside the target, then publish
    /// atomically.
    fn bind_by_rename(
        config: AgentConfig,
        path: PathBuf,
        temp: PathBuf,
    ) -> Result<AgentServer, AgentError> {
        let listener = UnixListener::bind(&temp)?;
        let assembled = (|| -> Result<Option<u64>, AgentError> {
            // Owner-only permissions while it still lives under our
            // private name: the target never shows looser bits, even to
            // a client that connects the instant it appears.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(&temp)?.permissions();
                perms.set_mode(0o600);
                std::fs::set_permissions(&temp, perms)?;
            }
            // Identity for after the rename: the inode rename preserves.
            let identity = file_inode(&temp);
            refuse_to_replace_non_sockets(&path)?;
            if UnixStream::connect(&path).is_ok() {
                return Err(AgentError::AlreadyRunning(path));
            }
            // Not connectable: a leftover socket from a crashed agent.
            // The rename replaces it atomically — no remove-then-bind
            // window for a racing starter to slip into — and only a
            // socket: whatever appeared at the path since the check
            // above must not be destroyed by the rename.
            refuse_to_replace_non_sockets(&path)?;
            std::fs::rename(&temp, &path)?;
            if file_inode(&path) != identity {
                // Another starter renamed onto the path between our
                // rename and this look: it serves, and we must not.
                return Err(AgentError::AlreadyRunning(path));
            }
            log::info!(
                "listening on {} (cap {}s)",
                path.display(),
                config.max_session_secs
            );
            Ok(identity)
        })();
        match assembled {
            Ok(identity) => Ok(AgentServer::new(config, listener, identity)),
            Err(e) => {
                // The temporary socket is ours alone: remove it on every
                // failure. The target path was never touched unless we
                // renamed onto it — and only atomically.
                let _ = std::fs::remove_file(&temp);
                Err(e)
            }
        }
    }

    /// The long-path fallback: publish directly at the target, under the
    /// same directory lock.
    fn bind_in_place(config: AgentConfig, path: PathBuf) -> Result<AgentServer, AgentError> {
        refuse_to_replace_non_sockets(&path)?;
        if UnixStream::connect(&path).is_ok() {
            return Err(AgentError::AlreadyRunning(path));
        }
        // A leftover socket from a crashed agent. Re-verified as a
        // socket right before the removal — whatever appeared at the
        // path since the refusal above is not ours to delete.
        match std::fs::symlink_metadata(&path) {
            Ok(meta) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::FileTypeExt;
                    if !meta.file_type().is_socket() {
                        return Err(AgentError::Protocol(format!(
                            "'{}' appeared and is not a socket; refusing to remove it",
                            path.display()
                        )));
                    }
                }
                std::fs::remove_file(&path)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let listener = UnixListener::bind(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&path, perms)?;
        }
        let identity = file_inode(&path);
        if file_inode(&path) != identity {
            return Err(AgentError::AlreadyRunning(path));
        }
        log::info!(
            "listening on {} (cap {}s)",
            path.display(),
            config.max_session_secs
        );
        Ok(AgentServer::new(config, listener, identity))
    }

    fn new(config: AgentConfig, listener: UnixListener, socket_identity: Option<u64>) -> Self {
        AgentServer {
            shared: Arc::new(Shared {
                inner: Mutex::new(HashMap::new()),
                subscribers: Mutex::new(Vec::new()),
                connections: Mutex::new(Vec::new()),
                max_session_secs: config.max_session_secs,
                stop: AtomicBool::new(false),
            }),
            config,
            listener,
            socket_identity,
        }
    }

    /// The socket path being served.
    pub fn socket_path(&self) -> &Path {
        &self.config.socket_path
    }

    /// A handle usable from another thread to stop this server.
    pub fn handle(&self) -> ServerHandle {
        ServerHandle {
            shared: Arc::clone(&self.shared),
            socket_path: self.config.socket_path.clone(),
        }
    }

    /// Serve until [`ServerHandle::stop`] (or a fatal listener error).
    /// On exit every session is dropped — key material wiped — the
    /// subscribers are released, accepted connections are shut down so
    /// their workers cannot accept or serve anything further, and the
    /// socket file is unlinked.
    pub fn serve(self) -> Result<(), AgentError> {
        let sweeper = {
            let shared = Arc::clone(&self.shared);
            let interval = self.config.sweep_interval;
            std::thread::Builder::new()
                .name("passlane-agent-sweeper".into())
                .spawn(move || sweep_loop(&shared, interval))?
        };
        self.listener.set_nonblocking(true)?;
        loop {
            if self.shared.stop.load(Ordering::SeqCst) {
                break;
            }
            match self.listener.accept() {
                Ok((stream, _addr)) => {
                    let shared = Arc::clone(&self.shared);
                    std::thread::Builder::new()
                        .name("passlane-agent-conn".into())
                        .spawn(move || handle_connection(shared, stream))?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => {
                    log::warn!("accept failed: {e}");
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
        self.shutdown();
        let _ = sweeper.join();
        Ok(())
    }

    fn shutdown(&self) {
        // Dropping the map drops every Session → key material zeroized.
        self.shared.inner.lock().map(|mut m| m.clear()).ok();
        // Dropping the senders closes the channels; the pump threads
        // exit and the connection threads notice the closed peer.
        self.shared.subscribers.lock().map(|mut s| s.clear()).ok();
        // Close accepted sockets so connection workers blocked in a read
        // wake up immediately and stop; dispatch also refuses everything
        // once `stop` is set (belt and braces — a worker may be between
        // frames when the wipe starts). The shutdown uses a dedicated
        // duplicate per connection: no writer lock is taken, so a worker
        // blocked mid-write on a full socket cannot stall the shutdown.
        if let Ok(connections) = self.shared.connections.lock() {
            for conn in connections.iter() {
                let _ = conn.shutdown_stream.shutdown(std::net::Shutdown::Both);
            }
        }
        self.shared.connections.lock().map(|mut c| c.clear()).ok();
        // Unlink only what we published: a starter that lost the path to
        // a replacement must not delete the winner's socket on its way
        // out (passlane#77).
        let still_ours = self
            .socket_identity
            .is_none_or(|identity| file_inode(&self.config.socket_path) == Some(identity));
        if still_ours {
            let _ = std::fs::remove_file(&self.config.socket_path);
        }
        log::info!("stopped; all sessions were dropped");
    }
}

/// Where the soon-to-be socket listens while it is being created:
/// beside the target, under a short name that hashes the target's own
/// path (so different sockets in one directory never collide) plus this
/// process's id and a per-process counter. Short, because the kernel's
/// pathname limit for sockets (`sun_path`, 104 bytes on macOS and Linux)
/// must also fit the *sibling*: a target whose parent directory already
/// straddles the limit gets `None` and the direct-publish fallback.
fn beside(path: &std::path::Path) -> Option<PathBuf> {
    use std::hash::{DefaultHasher, Hash, Hasher};
    static NAMING: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let mut hasher = DefaultHasher::new();
    path.hash(&mut hasher);
    let name = format!(
        ".pa{:08x}.{}.{}",
        hasher.finish(),
        std::process::id(),
        NAMING.fetch_add(1, Ordering::Relaxed)
    );
    let candidate = path.with_file_name(name);
    // Leave headroom against the sun_path limit (NUL included).
    (candidate.as_os_str().len() < 96).then_some(candidate)
}

/// The inode of the file at `path`, if it can be read — the identity a
/// `rename` preserves, and therefore the proof of who owns the target
/// after concurrent starters race onto it.
fn file_inode(path: &std::path::Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|meta| meta.ino())
}

/// Whatever sits at the target path, only a socket may be replaced: a
/// `--socket` typo must not destroy the user's file.
fn refuse_to_replace_non_sockets(path: &std::path::Path) -> Result<(), AgentError> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::FileTypeExt;
                if !meta.file_type().is_socket() {
                    return Err(AgentError::Protocol(format!(
                        "'{}' exists and is not a socket; refusing to remove it",
                        path.display()
                    )));
                }
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// An exclusive advisory lock on the socket's directory, held across the
/// look-then-publish sequence so concurrent auto-starts serialize
/// (passlane#77). `flock(2)` locks any descriptor — a directory's
/// included — so no lock file is ever created; dropping the handle
/// releases the lock.
struct DirectoryLock {
    /// Held open for the lock's lifetime; dropping it releases.
    _directory: std::fs::File,
}

fn lock_directory(dir: &Path) -> Result<DirectoryLock, AgentError> {
    use std::os::unix::io::AsRawFd;
    let directory = std::fs::File::open(dir)?;
    // SAFETY: `flock` on a descriptor this handle owns; the lock is
    // advisory and released on drop.
    if unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(DirectoryLock {
        _directory: directory,
    })
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sweep_loop(shared: &Shared, interval: Duration) {
    loop {
        // Sleep in small slices so a stop is noticed within ~50ms even
        // with a long sweep interval.
        let mut remaining = interval;
        while !remaining.is_zero() {
            if shared.stop.load(Ordering::SeqCst) {
                return;
            }
            let step = remaining.min(Duration::from_millis(50));
            std::thread::sleep(step);
            remaining -= step;
        }
        let expired = collect_expired(shared);
        for (id, vault) in expired {
            broadcast(shared, Event::SessionExpired { id, vault });
        }
    }
}

/// Remove and return the ids/vaults of sessions past their expiry.
/// Dropping them here wipes their key material.
fn collect_expired(shared: &Shared) -> Vec<(String, String)> {
    let now = now_secs();
    match shared.inner.lock() {
        Ok(mut sessions) => {
            let expired: Vec<(String, String)> = sessions
                .iter()
                .filter(|(_, s)| s.expired(now))
                .map(|(id, s)| (id.clone(), s.vault.clone()))
                .collect();
            for (id, _) in &expired {
                sessions.remove(id);
            }
            expired
        }
        Err(_) => Vec::new(),
    }
}

fn broadcast(shared: &Shared, event: Event) {
    if let Ok(subscribers) = shared.subscribers.lock() {
        for subscriber in subscribers.iter() {
            // A send error means the client went away; its connection
            // thread deregisters it.
            let _ = subscriber.tx.send(event.clone());
        }
    }
}

fn error_response(code: ErrorCode, message: impl Into<String>) -> Response {
    Response::Error {
        code,
        message: message.into(),
    }
}

/// Handle one client connection: read a frame, answer, repeat. EOF, a
/// malformed frame, or a stop ends the connection.
fn handle_connection(shared: Arc<Shared>, stream: UnixStream) {
    // The listener is non-blocking for the accept poll; make sure the
    // connection itself blocks normally (accepted sockets may inherit
    // the flag on some platforms).
    let _ = stream.set_nonblocking(false);
    let Ok(write_half) = stream.try_clone() else {
        return;
    };
    let writer = Arc::new(Mutex::new(write_half));
    // A separate duplicate reserved for shutdown (see `ConnHandle`).
    let shutdown_stream = stream.try_clone().ok();
    // Register so shutdown can close this socket and the worker exits
    // promptly instead of lingering on a blocked read. The registered
    // handle is a separate duplicate reserved for shutdown.
    let conn_id = NEXT_SUBSCRIBER_ID.fetch_add(1, Ordering::SeqCst);
    if let (Some(shutdown_stream), Ok(mut connections)) =
        (shutdown_stream, shared.connections.lock())
    {
        connections.push(ConnHandle {
            id: conn_id,
            shutdown_stream,
        });
    }
    let mut reader = stream;
    let mut subscriber_id: Option<u64> = None;

    loop {
        if shared.stop.load(Ordering::SeqCst) {
            break;
        }
        let frame = match protocol::read_frame(&mut reader) {
            Ok(frame) => frame,
            Err(_) => break, // EOF or protocol garbage: close quietly
        };
        let request: Request = match protocol::decode(&frame) {
            Ok(request) => request,
            Err(e) => {
                let _ = write_frame(&writer, &error_response(ErrorCode::Protocol, e.to_string()));
                break;
            }
        };
        if matches!(request, Request::Subscribe) {
            // Register *before* acknowledging so no event can slip by in
            // between (they queue on the channel), then write the ack
            // directly, and only then start the event pump — the pump
            // must never write an Event frame ahead of the ack. If the
            // ack fails, deregister so queued events die with the
            // channel.
            let (tx, rx) = mpsc::channel();
            let id = NEXT_SUBSCRIBER_ID.fetch_add(1, Ordering::SeqCst);
            if let Ok(mut subscribers) = shared.subscribers.lock() {
                subscribers.push(Subscriber { id, tx });
            }
            subscriber_id = Some(id);
            if write_frame(&writer, &Response::Subscribed).is_err() {
                break;
            }
            // Pump events to this client from its own thread; responses
            // and events share the write half behind one mutex, so
            // frames never interleave.
            let pump_writer = Arc::clone(&writer);
            let _ = std::thread::Builder::new()
                .name("passlane-agent-events".into())
                .spawn(move || {
                    while let Ok(event) = rx.recv() {
                        if write_frame(&pump_writer, &event).is_err() {
                            break;
                        }
                    }
                });
            continue;
        }
        let response = dispatch(&shared, request);
        if write_frame(&writer, &response).is_err() {
            break;
        }
    }
    if let Some(id) = subscriber_id
        && let Ok(mut subscribers) = shared.subscribers.lock()
    {
        subscribers.retain(|s| s.id != id);
    }
    if let Ok(mut connections) = shared.connections.lock() {
        connections.retain(|c| c.id != conn_id);
    }
}

fn write_frame<T: serde::Serialize>(
    writer: &Arc<Mutex<UnixStream>>,
    message: &T,
) -> Result<(), AgentError> {
    let mut guard = writer
        .lock()
        .map_err(|_| AgentError::Protocol("writer mutex poisoned".into()))?;
    protocol::write_frame(&mut *guard, message)
}

/// Apply one request. Pure with respect to `Shared`: takes the locks it
/// needs, never blocks on the network, never logs secrets. Refuses
/// everything once a stop has been signaled, so no session can appear
/// after the shutdown wipe.
fn dispatch(shared: &Shared, request: Request) -> Response {
    if shared.stop.load(Ordering::SeqCst) {
        return error_response(ErrorCode::Protocol, "the agent is shutting down");
    }
    // Drop anything already expired first, so every request sees a
    // consistent store and expiry events fire promptly even between
    // sweeps.
    let expired = collect_expired(shared);
    for (id, vault) in expired {
        broadcast(shared, Event::SessionExpired { id, vault });
    }

    match request {
        Request::Ping => {
            let sessions = shared.inner.lock().map(|s| s.len()).unwrap_or(0);
            Response::Pong {
                version: PROTOCOL_VERSION,
                max_session_secs: shared.max_session_secs,
                sessions,
            }
        }
        Request::CreateSession {
            vault,
            grant,
            scope,
        } => {
            if vault.is_empty() || vault.len() > MAX_VAULT_NAME_LEN {
                return error_response(
                    ErrorCode::Invalid,
                    format!("vault name must be 1..={MAX_VAULT_NAME_LEN} bytes"),
                );
            }
            if let GrantSpec::Reveal { id, entry, field } = &grant {
                if id.is_empty() || id.len() > MAX_ID_LEN {
                    return error_response(
                        ErrorCode::Invalid,
                        format!("entry id must be 1..={MAX_ID_LEN} bytes"),
                    );
                }
                if entry.is_empty() || entry.len() > MAX_ENTRY_NAME_LEN {
                    return error_response(
                        ErrorCode::Invalid,
                        format!("entry name must be 1..={MAX_ENTRY_NAME_LEN} bytes"),
                    );
                }
                if field.is_empty() || field.len() > MAX_FIELD_NAME_LEN {
                    return error_response(
                        ErrorCode::Invalid,
                        format!("field name must be 1..={MAX_FIELD_NAME_LEN} bytes"),
                    );
                }
            }
            // A phone-held key's answer: both fields become keys for
            // lookups (the challenge) and vault key material (the
            // answer), so anything but the exact hex shape is refused
            // rather than stored.
            if let GrantSpec::ChallengeResponse {
                challenge,
                response,
            } = &grant
                && (!is_hex_of_len(challenge.expose(), CHALLENGE_HEX_LEN)
                    || !is_hex_of_len(response.expose(), RESPONSE_HEX_LEN))
            {
                return error_response(
                    ErrorCode::Invalid,
                    format!(
                        "a challenge response needs a {CHALLENGE_HEX_LEN}-hex challenge and a \
                         {RESPONSE_HEX_LEN}-hex answer, lower-case"
                    ),
                );
            }
            // An unlock session's challenge-response material: a
            // secret-backed factor whose hex must be present and bounded.
            if let GrantSpec::Unlock {
                challenge_response: Some(ChallengeResponseMaterial::Secret { secret_hex }),
                ..
            } = &grant
                && (secret_hex.expose().is_empty() || secret_hex.expose().len() > MAX_SECRET_LEN)
            {
                return error_response(
                    ErrorCode::Invalid,
                    format!("challenge-response secret must be 1..={MAX_SECRET_LEN} bytes"),
                );
            }
            let seconds = scope.seconds();
            if seconds > shared.max_session_secs {
                return error_response(
                    ErrorCode::TooLong,
                    format!(
                        "session of {seconds}s exceeds this agent's cap of {}s",
                        shared.max_session_secs
                    ),
                );
            }
            let now = now_secs();
            let grant = match grant {
                GrantSpec::Unlock {
                    master_password,
                    challenge_response,
                } => {
                    let mut material = KeyMaterial::new(master_password.expose());
                    if let Some(challenge_response) = challenge_response {
                        material = material.with_challenge_response(challenge_response);
                    }
                    Grant::Unlock(material)
                }
                GrantSpec::Reveal { id, entry, field } => Grant::Reveal { id, entry, field },
                GrantSpec::ChallengeResponse {
                    challenge,
                    response,
                } => Grant::ChallengeResponse(ChallengeMaterial::new(
                    challenge.expose(),
                    response.expose(),
                )),
            };
            let vault_name = vault.clone();
            // Only the grant's kind is logged — never what it holds.
            let grant_kind = match grant.info() {
                GrantInfo::Unlock {
                    challenge_response: false,
                } => "unlock",
                GrantInfo::Unlock {
                    challenge_response: true,
                } => "unlock with challenge-response",
                GrantInfo::Reveal { .. } => "reveal",
                GrantInfo::ChallengeResponse => "challenge_response",
            };
            let session = Session::new(vault, grant, scope, now);
            let response = Response::SessionCreated {
                id: session.id.clone(),
                expires_at: session.expires_at,
            };
            log::info!(
                "session {} created (vault '{vault_name}', grant {grant_kind})",
                session.id
            );
            match shared.inner.lock() {
                Ok(mut sessions) => {
                    sessions.insert(session.id.clone(), session);
                    response
                }
                Err(_) => error_response(ErrorCode::Protocol, "state mutex poisoned"),
            }
        }
        Request::GetUnlockFactors { vault } => match shared.inner.lock() {
            Ok(mut sessions) => {
                let now = now_secs();
                // Of the live unlock sessions for the vault, serve the one
                // holding the whole factor set — map order must not decide
                // whether a hardware-key vault can be opened unattended —
                // and between equals a timed session (reusable) before a
                // once session (consumed by this call).
                let chosen = sessions
                    .iter()
                    .filter(|(_, s)| s.vault == vault && s.grant.is_unlock() && !s.expired(now))
                    .max_by_key(|(_, s)| {
                        (
                            s.grant.holds_challenge_response(),
                            matches!(s.scope, Scope::Timed { .. }),
                        )
                    })
                    .map(|(id, s)| (id.clone(), matches!(s.scope, Scope::Timed { .. })));
                match chosen {
                    Some((id, true)) => {
                        let session = sessions.get(&id).expect("chosen from the same map");
                        let Grant::Unlock(material) = &session.grant else {
                            unreachable!("filtered to unlock grants above");
                        };
                        Response::UnlockFactors {
                            master_password: crate::protocol::SecretString::new(
                                material.master_password(),
                            ),
                            challenge_response: material.challenge_response().cloned(),
                            expires_at: session.expires_at,
                        }
                    }
                    // The removed session's key material wipes on drop;
                    // the copy below is zeroizing on both sides.
                    Some((id, false)) => {
                        let session = sessions.remove(&id).expect("chosen from the same map");
                        let Grant::Unlock(material) = session.grant else {
                            unreachable!("filtered to unlock grants above");
                        };
                        Response::UnlockFactors {
                            master_password: crate::protocol::SecretString::new(
                                material.master_password(),
                            ),
                            challenge_response: material.challenge_response().cloned(),
                            // A once session: no expiry to revalidate.
                            expires_at: None,
                        }
                    }
                    None => error_response(
                        ErrorCode::NotFound,
                        format!("no unlock session for vault '{vault}'"),
                    ),
                }
            }
            Err(_) => error_response(ErrorCode::Protocol, "state mutex poisoned"),
        },
        Request::GetChallengeResponse { vault, challenge } => {
            if !is_hex_of_len(&challenge, CHALLENGE_HEX_LEN) {
                return error_response(
                    ErrorCode::Invalid,
                    format!("the challenge must be {CHALLENGE_HEX_LEN} hex characters"),
                );
            }
            match shared.inner.lock() {
                Ok(mut sessions) => {
                    let now = now_secs();
                    // A timed session serves until it expires; a once
                    // session is spent by this call. Either way only for
                    // the exact challenge asked for.
                    let timed = sessions.values().find(|s| {
                        s.vault == vault
                            && s.grant.challenge_response_for(&challenge).is_some()
                            && !s.expired(now)
                            && matches!(s.scope, Scope::Timed { .. })
                    });
                    if let Some(session) = timed {
                        let answer = session
                            .grant
                            .challenge_response_for(&challenge)
                            .expect("filtered to matching grants above")
                            .to_string();
                        return Response::ChallengeResponse {
                            response: crate::protocol::SecretString::new(answer),
                            expires_at: session.expires_at,
                        };
                    }
                    let once_id = sessions
                        .values()
                        .find(|s| {
                            s.vault == vault
                                && s.grant.challenge_response_for(&challenge).is_some()
                                && matches!(s.scope, Scope::Once)
                        })
                        .map(|s| s.id.clone());
                    match once_id.and_then(|id| sessions.remove(&id)) {
                        // The removed session's answer wipes on drop; the
                        // copy below is zeroizing on both sides.
                        Some(session) => Response::ChallengeResponse {
                            response: crate::protocol::SecretString::new(
                                session
                                    .grant
                                    .challenge_response_for(&challenge)
                                    .expect("filtered to matching grants above"),
                            ),
                            expires_at: None,
                        },
                        None => error_response(
                            ErrorCode::NotFound,
                            format!("no challenge response for vault '{vault}' and that challenge"),
                        ),
                    }
                }
                Err(_) => error_response(ErrorCode::Protocol, "state mutex poisoned"),
            }
        }
        Request::CheckReveal { vault, id, field } => match shared.inner.lock() {
            Ok(mut sessions) => {
                let now = now_secs();
                let timed = sessions.values().find(|s| {
                    s.vault == vault
                        && s.grant.covers_reveal(&id, &field)
                        && !s.expired(now)
                        && matches!(s.scope, Scope::Timed { .. })
                });
                if let Some(session) = timed {
                    return Response::RevealCheck {
                        allowed: true,
                        until: session.expires_at,
                    };
                }
                // Consume a once-scoped reveal approval if one covers it.
                let once_id = sessions
                    .values()
                    .find(|s| {
                        s.vault == vault
                            && s.grant.covers_reveal(&id, &field)
                            && matches!(s.scope, Scope::Once)
                    })
                    .map(|s| s.id.clone());
                match once_id {
                    Some(id) => {
                        sessions.remove(&id); // drop wipes nothing (no secret), but ends it
                        Response::RevealCheck {
                            allowed: true,
                            until: None,
                        }
                    }
                    None => Response::RevealCheck {
                        allowed: false,
                        until: None,
                    },
                }
            }
            Err(_) => error_response(ErrorCode::Protocol, "state mutex poisoned"),
        },
        Request::ListSessions => {
            let list = match shared.inner.lock() {
                Ok(sessions) => {
                    let mut list: Vec<SessionInfo> = sessions.values().map(|s| s.info()).collect();
                    list.sort_by(|a, b| {
                        a.created_at
                            .cmp(&b.created_at)
                            .then_with(|| a.id.cmp(&b.id))
                    });
                    list
                }
                Err(_) => return error_response(ErrorCode::Protocol, "state mutex poisoned"),
            };
            Response::Sessions { list }
        }
        Request::RevokeSession { id } => {
            let removed = shared
                .inner
                .lock()
                .ok()
                .and_then(|mut sessions| sessions.remove(&id));
            match removed {
                Some(session) => {
                    let vault = session.vault.clone();
                    broadcast(shared, Event::SessionRevoked { id, vault });
                    Response::Revoked { count: 1 }
                }
                None => error_response(ErrorCode::NotFound, format!("no session '{id}'")),
            }
        }
        Request::RevokeVault { vault } => {
            let removed = shared.inner.lock().ok().map(|mut sessions| {
                let ids: Vec<String> = sessions
                    .values()
                    .filter(|s| s.vault == vault)
                    .map(|s| s.id.clone())
                    .collect();
                let removed: Vec<Session> =
                    ids.iter().filter_map(|id| sessions.remove(id)).collect();
                removed
            });
            match removed {
                Some(removed) => {
                    let count = removed.len();
                    for session in removed {
                        broadcast(
                            shared,
                            Event::SessionRevoked {
                                id: session.id,
                                vault: session.vault,
                            },
                        );
                    }
                    Response::Revoked { count }
                }
                None => error_response(ErrorCode::Protocol, "state mutex poisoned"),
            }
        }
        Request::RevokeAll => {
            let removed = shared.inner.lock().ok().map(|mut sessions| {
                let ids: Vec<(String, String)> = sessions
                    .values()
                    .map(|s| (s.id.clone(), s.vault.clone()))
                    .collect();
                sessions.clear();
                ids
            });
            match removed {
                Some(ids) => {
                    let count = ids.len();
                    for (id, vault) in ids {
                        broadcast(shared, Event::SessionRevoked { id, vault });
                    }
                    Response::Revoked { count }
                }
                None => error_response(ErrorCode::Protocol, "state mutex poisoned"),
            }
        }
        Request::Lock => {
            let count = shared.inner.lock().ok().map(|mut sessions| {
                let count = sessions.len();
                sessions.clear();
                count
            });
            match count {
                Some(_) => {
                    broadcast(shared, Event::SessionsLocked);
                    Response::Locked
                }
                None => error_response(ErrorCode::Protocol, "state mutex poisoned"),
            }
        }
        Request::Subscribe => {
            // Handled at the connection level (needs the writer half).
            error_response(
                ErrorCode::Protocol,
                "subscribe must be the first message on a connection",
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shared(cap: u64) -> Arc<Shared> {
        Arc::new(Shared {
            inner: Mutex::new(HashMap::new()),
            subscribers: Mutex::new(Vec::new()),
            connections: Mutex::new(Vec::new()),
            max_session_secs: cap,
            stop: AtomicBool::new(false),
        })
    }

    fn unlock_grant(pw: &str) -> GrantSpec {
        GrantSpec::Unlock {
            master_password: crate::protocol::SecretString::new(pw),
            challenge_response: None,
        }
    }

    fn keyed_grant(pw: &str, secret: &str) -> GrantSpec {
        GrantSpec::Unlock {
            master_password: crate::protocol::SecretString::new(pw),
            challenge_response: Some(ChallengeResponseMaterial::Secret {
                secret_hex: crate::protocol::SecretString::new(secret),
            }),
        }
    }

    #[test]
    fn unlock_session_hands_out_the_challenge_response_it_was_given() {
        let shared = shared(60);
        let created = match dispatch(
            &shared,
            Request::CreateSession {
                vault: "keyed".into(),
                grant: keyed_grant("pw", "aabbcc"),
                scope: Scope::Timed { seconds: 60 },
            },
        ) {
            Response::SessionCreated { id, .. } => id,
            other => panic!("{other:?}"),
        };
        // A timed session serves the whole factor set, as often as asked.
        for _ in 0..2 {
            match dispatch(
                &shared,
                Request::GetUnlockFactors {
                    vault: "keyed".into(),
                },
            ) {
                Response::UnlockFactors {
                    master_password,
                    challenge_response,
                    expires_at,
                } => {
                    assert_eq!(master_password.expose(), "pw");
                    assert_eq!(
                        challenge_response,
                        Some(ChallengeResponseMaterial::Secret {
                            secret_hex: crate::protocol::SecretString::new("aabbcc")
                        })
                    );
                    assert!(expires_at.is_some());
                }
                other => panic!("{other:?}"),
            }
        }
        // The listing says the factor is held — and nothing about it.
        match dispatch(&shared, Request::ListSessions) {
            Response::Sessions { list } => {
                assert_eq!(
                    list[0].grant,
                    GrantInfo::Unlock {
                        challenge_response: true
                    }
                );
                assert!(!format!("{:?}", list[0].grant).contains("aabbcc"));
                assert_eq!(list[0].id, created);
            }
            other => panic!("{other:?}"),
        }
    }

    /// A vault can have a password-only session and one holding its key
    /// factor live at once (say, one created before the factor could be
    /// handed over). Whichever came first, the complete one is served.
    #[test]
    fn the_session_holding_the_key_factor_is_preferred() {
        for plain_scope in [Scope::Timed { seconds: 60 }, Scope::Once] {
            for keyed_scope in [Scope::Timed { seconds: 60 }, Scope::Once] {
                for keyed_first in [true, false] {
                    let shared = shared(60);
                    let plain = (unlock_grant("pw"), plain_scope);
                    let keyed = (keyed_grant("pw", "aabb"), keyed_scope);
                    let grants = if keyed_first {
                        [keyed, plain]
                    } else {
                        [plain, keyed]
                    };
                    for (grant, scope) in grants {
                        assert!(matches!(
                            dispatch(
                                &shared,
                                Request::CreateSession {
                                    vault: "keyed".into(),
                                    grant,
                                    scope,
                                }
                            ),
                            Response::SessionCreated { .. }
                        ));
                    }
                    // The complete grant is served even when the incomplete
                    // one is the reusable one.
                    match dispatch(
                        &shared,
                        Request::GetUnlockFactors {
                            vault: "keyed".into(),
                        },
                    ) {
                        Response::UnlockFactors {
                            challenge_response, ..
                        } => assert!(
                            challenge_response.is_some(),
                            "keyed first: {keyed_first}, plain {plain_scope:?}, keyed {keyed_scope:?}"
                        ),
                        other => panic!("{other:?}"),
                    }
                    // Only a once grant that was chosen is consumed; the
                    // password-only grant stays if it was not.
                    let remaining = match dispatch(&shared, Request::ListSessions) {
                        Response::Sessions { list } => list,
                        other => panic!("{other:?}"),
                    };
                    let once_left = remaining
                        .iter()
                        .filter(|s| s.vault == "keyed" && matches!(s.scope, Scope::Once))
                        .count();
                    assert_eq!(
                        once_left,
                        usize::from(matches!(plain_scope, Scope::Once)),
                        "only the once grant that served is consumed"
                    );
                }
            }
        }
    }

    #[test]
    fn malformed_challenge_response_secrets_are_refused() {
        let shared = shared(60);
        for secret in ["", &"a".repeat(MAX_SECRET_LEN + 1)] {
            match dispatch(
                &shared,
                Request::CreateSession {
                    vault: "keyed".into(),
                    grant: keyed_grant("pw", secret),
                    scope: Scope::Timed { seconds: 60 },
                },
            ) {
                Response::Error { code, .. } => assert_eq!(code, ErrorCode::Invalid),
                other => panic!("{other:?}"),
            }
        }
        assert!(matches!(
            dispatch(
                &shared,
                Request::CreateSession {
                    vault: "keyed".into(),
                    grant: keyed_grant("pw", &"a".repeat(MAX_SECRET_LEN)),
                    scope: Scope::Timed { seconds: 60 },
                }
            ),
            Response::SessionCreated { .. }
        ));
    }

    #[test]
    fn challenge_responses_are_keyed_by_the_exact_challenge() {
        let shared = shared(60);
        let answer = GrantSpec::ChallengeResponse {
            challenge: crate::protocol::SecretString::new("ab".repeat(32)),
            response: crate::protocol::SecretString::new("ef".repeat(20)),
        };
        assert!(matches!(
            dispatch(
                &shared,
                Request::CreateSession {
                    vault: "work".into(),
                    grant: answer,
                    scope: Scope::Timed { seconds: 60 },
                }
            ),
            Response::SessionCreated { .. }
        ));

        let get = |challenge: &str| {
            dispatch(
                &shared,
                Request::GetChallengeResponse {
                    vault: "work".into(),
                    challenge: challenge.to_string(),
                },
            )
        };
        // The right challenge, reusable while timed.
        for _ in 0..2 {
            assert!(matches!(
                get(&"ab".repeat(32)),
                Response::ChallengeResponse { ref response, expires_at: Some(_) }
                    if response.expose() == "ef".repeat(20)
            ));
        }
        // A re-saved vault has a new seed: its old answer is not served.
        assert!(matches!(
            get(&"ac".repeat(32)),
            Response::Error {
                code: ErrorCode::NotFound,
                ..
            }
        ));
        assert!(matches!(
            get("not hex"),
            Response::Error {
                code: ErrorCode::Invalid,
                ..
            }
        ));

        // A once answer is spent by the first command that uses it.
        assert!(matches!(
            dispatch(
                &shared,
                Request::CreateSession {
                    vault: "home".into(),
                    grant: GrantSpec::ChallengeResponse {
                        challenge: crate::protocol::SecretString::new("11".repeat(32)),
                        response: crate::protocol::SecretString::new("22".repeat(20)),
                    },
                    scope: Scope::Once,
                }
            ),
            Response::SessionCreated { .. }
        ));
        let get_home = || {
            dispatch(
                &shared,
                Request::GetChallengeResponse {
                    vault: "home".into(),
                    challenge: "11".repeat(32),
                },
            )
        };
        assert!(matches!(
            get_home(),
            Response::ChallengeResponse { ref response, expires_at: None }
                if response.expose() == "22".repeat(20)
        ));
        assert!(matches!(
            get_home(),
            Response::Error {
                code: ErrorCode::NotFound,
                ..
            }
        ));
    }

    #[test]
    fn malformed_challenge_responses_are_refused_at_create() {
        let shared = shared(60);
        for (challenge, response) in [
            ("ab".repeat(31), "ef".repeat(20)), // short challenge
            ("ab".repeat(32), "ef".repeat(21)), // long answer
            ("AB".repeat(32), "ef".repeat(20)), // upper-case
            ("ab".repeat(32), "zz".repeat(20)), // not hex
        ] {
            let resp = dispatch(
                &shared,
                Request::CreateSession {
                    vault: "work".into(),
                    grant: GrantSpec::ChallengeResponse {
                        challenge: crate::protocol::SecretString::new(challenge),
                        response: crate::protocol::SecretString::new(response),
                    },
                    scope: Scope::Timed { seconds: 60 },
                },
            );
            assert!(
                matches!(
                    resp,
                    Response::Error {
                        code: ErrorCode::Invalid,
                        ..
                    }
                ),
                "{resp:?}"
            );
        }
        assert!(
            shared.inner.lock().unwrap().is_empty(),
            "nothing was stored"
        );
    }

    #[test]
    fn cap_is_enforced_at_create() {
        let shared = shared(60);
        let resp = dispatch(
            &shared,
            Request::CreateSession {
                vault: "work".into(),
                grant: unlock_grant("pw"),
                scope: Scope::Timed { seconds: 61 },
            },
        );
        match resp {
            Response::Error { code, message } => {
                assert_eq!(code, ErrorCode::TooLong);
                assert!(message.contains("61s"), "{message}");
                assert!(message.contains("60s"), "{message}");
            }
            other => panic!("expected TooLong, got {other:?}"),
        }
        // Exactly at the cap is allowed.
        assert!(matches!(
            dispatch(
                &shared,
                Request::CreateSession {
                    vault: "work".into(),
                    grant: unlock_grant("pw"),
                    scope: Scope::Timed { seconds: 60 },
                }
            ),
            Response::SessionCreated { .. }
        ));
    }

    #[test]
    fn config_never_exceeds_the_hard_cap() {
        assert_eq!(
            AgentConfig::new("/nope")
                .with_max_session_secs(HARD_MAX_SESSION_SECS * 10)
                .max_session_secs,
            HARD_MAX_SESSION_SECS
        );
        assert_eq!(default_max_session_secs(), 900);
    }

    #[test]
    fn invalid_names_are_refused() {
        let shared = shared(60);
        let resp = dispatch(
            &shared,
            Request::CreateSession {
                vault: String::new(),
                grant: unlock_grant("pw"),
                scope: Scope::Once,
            },
        );
        match resp {
            Response::Error { code, .. } => assert_eq!(code, ErrorCode::Invalid),
            other => panic!("{other:?}"),
        }
        let resp = dispatch(
            &shared,
            Request::CreateSession {
                vault: "work".into(),
                grant: GrantSpec::Reveal {
                    id: "11111111-1111-1111-1111-111111111111".into(),
                    entry: "e".repeat(MAX_ENTRY_NAME_LEN + 1),
                    field: "password".into(),
                },
                scope: Scope::Once,
            },
        );
        match resp {
            Response::Error { code, .. } => assert_eq!(code, ErrorCode::Invalid),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn bind_refuses_to_delete_a_non_socket_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("precious.txt");
        std::fs::write(&path, "data").unwrap();
        let err = AgentServer::bind(AgentConfig::new(&path)).unwrap_err();
        match err {
            AgentError::Protocol(msg) => assert!(msg.contains("refusing"), "{msg}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "data");
    }

    #[test]
    fn socket_is_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        let server = AgentServer::bind(AgentConfig::new(&path)).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        server.handle().stop();
        server.serve().unwrap();
        assert!(!path.exists(), "socket must be unlinked on stop");
    }

    /// The inode identity a rename preserves — the check a renamed-over
    /// starter runs after its own swap: only the starter whose socket
    /// the path still leads to keeps serving (passlane#77).
    #[test]
    fn the_path_leads_to_the_last_renamer_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        // Two starters listen beside the target and swap onto it.
        let first_temp = beside(&path).expect("a short sibling fits");
        let _first = std::os::unix::net::UnixListener::bind(&first_temp).unwrap();
        let first_identity = file_inode(&first_temp);
        std::fs::rename(&first_temp, &path).unwrap();
        assert_eq!(file_inode(&path), first_identity, "the rename preserved it");
        let second_temp = beside(&path).expect("a short sibling fits");
        let _second = std::os::unix::net::UnixListener::bind(&second_temp).unwrap();
        let second_identity = file_inode(&second_temp);
        std::fs::rename(&second_temp, &path).unwrap();
        // The last rename wins the inode at the path…
        assert_eq!(file_inode(&path), second_identity);
        // …so the first starter's check sees a foreign socket and must
        // yield.
        assert_ne!(
            file_inode(&path),
            first_identity,
            "the renamed-over starter no longer owns the path"
        );
    }

    /// The sibling name stays inside the kernel's socket-pathname limit
    /// where the target itself does, and gives up (None) before it would
    /// exceed it.
    #[test]
    fn the_sibling_name_respects_the_pathname_limit() {
        let dir = tempfile::tempdir().unwrap();
        assert!(beside(&dir.path().join("agent.sock")).is_some());
        // A parent near the 104-byte sun_path limit: any sibling of a
        // fitting target may not fit, and `beside` must say so rather
        // than hand out a path the kernel would refuse.
        let long = "a".repeat(90);
        let straddling = dir.path().join(&long).join("s.sock");
        std::fs::create_dir_all(straddling.parent().unwrap()).unwrap();
        let sibling = beside(&straddling);
        if let Some(sibling) = &sibling {
            assert!(
                sibling.as_os_str().len() < 104,
                "a sibling must fit sun_path: {:?}",
                sibling
            );
        }
    }

    /// Concurrent `bind`s on one path leave exactly one server; the
    /// loser reports `AlreadyRunning` and takes no socket with it. All
    /// starters are joined (and only then stopped) so a descheduled
    /// loser cannot observe the winner's cleanup and rebind.
    #[test]
    fn concurrent_binds_converge_on_one_server() {
        let dir = tempfile::tempdir().unwrap();
        let path = std::sync::Arc::new(dir.path().join("agent.sock"));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let starters: Vec<_> = (0..2)
            .map(|_| {
                let path = std::sync::Arc::clone(&path);
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    AgentServer::bind(AgentConfig::new(&*path))
                })
            })
            .collect();
        let outcomes: Vec<_> = starters
            .into_iter()
            .map(|starter| starter.join().unwrap())
            .collect();
        let mut live = 0;
        for outcome in outcomes {
            match outcome {
                Ok(server) => {
                    live += 1;
                    server.handle().stop();
                    server.serve().unwrap();
                }
                Err(AgentError::AlreadyRunning(_)) => {}
                Err(other) => panic!("unexpected: {other:?}"),
            }
        }
        assert_eq!(live, 1, "exactly one starter ended up serving");

        // And no temporary sibling is left behind by the loser.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name())
            .filter(|name| name.to_string_lossy().contains(".pa"))
            .collect();
        assert!(leftovers.is_empty(), "temp sockets cleaned: {leftovers:?}");
    }

    /// A serialized loser yields before serving, and shutdown never
    /// unlinks a socket the server does not own: a replacement placed at
    /// the path behind a live server's back survives the server's stop
    /// (passlane#77).
    #[test]
    fn shutdown_unlinks_only_the_owned_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        let server = AgentServer::bind(AgentConfig::new(&path)).unwrap();
        // A stranger's socket takes the path (possible only after a
        // crash-mid-rename or against non-locking strangers; the lock
        // keeps locking starters out of this state).
        std::fs::remove_file(&path).unwrap();
        let stranger = std::os::unix::net::UnixListener::bind(&path).unwrap();
        server.handle().stop();
        server.serve().unwrap();
        assert!(
            path.exists(),
            "the replacement survives the renamed-over server's stop"
        );
        drop(stranger);
        std::fs::remove_file(&path).unwrap();
    }
}
