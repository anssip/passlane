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
    /// passlane#77): the exists()/connect probe and the bind can
    /// interleave with another starter's, so a bind lost to a socket
    /// file that appeared meanwhile is re-evaluated, and after binding
    /// the path must *still reach this listener* — proven by a probe
    /// connection — before the server claims it. A starter that finds
    /// another's socket at the path exits with `AlreadyRunning`. The
    /// proof is a snapshot, not a lock: a starter replaced a heartbeat
    /// after proving may linger as an idle daemon reachable by no one —
    /// nothing is ever deposited with it (clients connect through the
    /// path, i.e. to the owner), and its sessions die with it, by
    /// design.
    pub fn bind(config: AgentConfig) -> Result<AgentServer, AgentError> {
        let path = config.socket_path.clone();
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        for attempt in 0..3 {
            if path.exists() {
                if UnixStream::connect(&path).is_ok() {
                    return Err(AgentError::AlreadyRunning(path));
                }
                // Not connectable: a leftover socket from a crashed agent.
                // Only sockets are removed — never some other file the user
                // may care about (e.g. a --socket typo). A file that
                // vanishes while we look at it is a racing starter's
                // remove/rebind, not an error: the loop re-evaluates.
                let meta = match std::fs::symlink_metadata(&path) {
                    Ok(meta) => meta,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(e.into()),
                };
                #[cfg(unix)]
                {
                    use std::os::unix::fs::FileTypeExt;
                    if meta.file_type().is_socket() {
                        match std::fs::remove_file(&path) {
                            Ok(()) => {}
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                            Err(e) => return Err(e.into()),
                        }
                    } else {
                        return Err(AgentError::Protocol(format!(
                            "'{}' exists and is not a socket; refusing to remove it",
                            path.display()
                        )));
                    }
                }
            }
            match UnixListener::bind(&path) {
                Ok(listener) => return Self::claim(config, path, listener),
                // EEXIST: a file appeared at the path since the probe.
                // EADDRINUSE (macOS): it is already bound. Either way
                // another starter is mid-flight — re-evaluate rather
                // than fail: it may be live now (we yield) or stale
                // again (we replace it).
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::AddrInUse
                    ) && attempt < 2 =>
                {
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }
        unreachable!("the loop returns, or retries twice and returns on the third")
    }

    /// Take ownership of the just-bound socket: owner-only permissions,
    /// then the proof that the path still leads to *this* listener. A
    /// starter whose socket was replaced underneath it loses — the
    /// winner serves — and must not run a daemon reachable by no one.
    fn claim(
        config: AgentConfig,
        path: PathBuf,
        listener: UnixListener,
    ) -> Result<AgentServer, AgentError> {
        // Owner-only permissions first: chmod'ing the path is benign
        // whoever it leads to right now (same user, same 0600), while
        // doing it after the proof would race the replacement's
        // remove/rebind of the very file being permissioned.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = match std::fs::metadata(&path) {
                Ok(meta) => meta.permissions(),
                // Our just-bound socket was removed by a racing starter
                // mid-rebind: the path is theirs now, and the loser
                // yields rather than errors.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(AgentError::AlreadyRunning(path));
                }
                Err(e) => return Err(e.into()),
            };
            perms.set_mode(0o600);
            match std::fs::set_permissions(&path, perms) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(AgentError::AlreadyRunning(path));
                }
                Err(e) => return Err(e.into()),
            }
        }
        if !path_reaches(&listener, &path) {
            return Err(AgentError::AlreadyRunning(path));
        }
        log::info!(
            "listening on {} (cap {}s)",
            path.display(),
            config.max_session_secs
        );
        Ok(AgentServer {
            shared: Arc::new(Shared {
                inner: Mutex::new(HashMap::new()),
                subscribers: Mutex::new(Vec::new()),
                connections: Mutex::new(Vec::new()),
                max_session_secs: config.max_session_secs,
                stop: AtomicBool::new(false),
            }),
            config,
            listener,
        })
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
        let _ = std::fs::remove_file(&self.config.socket_path);
        log::info!("stopped; all sessions were dropped");
    }
}

/// Whether a connection made through the path arrives at *this*
/// listener — the proof that the path still leads to us and not to a
/// starter that replaced our socket while we were setting up
/// (concurrent auto-start, passlane#77). A socket fd's `fstat` identity
/// does not match its filesystem entry on every platform, so the
/// routing itself is checked: the probe connection either lands in our
/// accept queue or in the replacement's. A failure to prove ownership
/// fails closed.
fn path_reaches(listener: &UnixListener, path: &std::path::Path) -> bool {
    let Ok(probe) = UnixStream::connect(path) else {
        return false;
    };
    drop(probe);
    if listener.set_nonblocking(true).is_err() {
        return false;
    }
    let deadline = std::time::Instant::now() + Duration::from_millis(250);
    loop {
        match listener.accept() {
            Ok((connection, _)) => {
                drop(connection);
                return true;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if std::time::Instant::now() >= deadline {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(_) => return false,
        }
    }
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

    /// A listener whose socket file was replaced no longer owns the path
    /// — the routing check at the heart of making concurrent starters
    /// converge (passlane#77): a connection through the path must arrive
    /// at this listener, not at the replacement's.
    #[test]
    fn a_replaced_listener_no_longer_owns_the_path() {
        use std::os::unix::net::UnixListener;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        let first = UnixListener::bind(&path).unwrap();
        assert!(path_reaches(&first, &path));
        // Another starter removes the socket and binds its own.
        std::fs::remove_file(&path).unwrap();
        let second = UnixListener::bind(&path).unwrap();
        assert!(
            !path_reaches(&first, &path),
            "the first listener's socket is gone from the path"
        );
        assert!(path_reaches(&second, &path));
        // A path that vanished entirely proves nothing — but must fail
        // closed, not panic.
        std::fs::remove_file(&path).unwrap();
        assert!(!path_reaches(&second, &path));
    }

    /// The claim step a starter runs after binding: a starter whose
    /// socket was replaced underneath it yields (`AlreadyRunning`) and
    /// never serves a socket nobody can reach; the replacement claims.
    #[test]
    fn a_starter_that_lost_its_socket_yields_the_path() {
        use std::os::unix::net::UnixListener;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        let loser = UnixListener::bind(&path).unwrap();
        // The race lost: another starter replaced the socket at the path.
        std::fs::remove_file(&path).unwrap();
        let winner = UnixListener::bind(&path).unwrap();
        let config = AgentConfig::new(&path);
        match AgentServer::claim(config.clone(), path.clone(), loser) {
            Err(AgentError::AlreadyRunning(p)) => assert_eq!(p, path),
            other => panic!("the loser must yield, got {other:?}"),
        }
        AgentServer::claim(config, path, winner).unwrap();
    }
}
