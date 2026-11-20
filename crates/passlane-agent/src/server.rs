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
    self, ErrorCode, Event, GrantInfo, GrantSpec, MAX_ENTRY_NAME_LEN, MAX_FIELD_NAME_LEN,
    MAX_VAULT_NAME_LEN, PROTOCOL_VERSION, Request, Response, SessionInfo,
};
use crate::session::{Grant, KeyMaterial, Session};

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
    max_session_secs: u64,
    stop: AtomicBool,
}

struct Subscriber {
    id: u64,
    tx: mpsc::Sender<Event>,
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
    pub fn bind(config: AgentConfig) -> Result<AgentServer, AgentError> {
        let path = config.socket_path.clone();
        if path.exists() {
            if UnixStream::connect(&path).is_ok() {
                return Err(AgentError::AlreadyRunning(path));
            }
            // Not connectable: a leftover socket from a crashed agent.
            // Only sockets are removed — never some other file the user
            // may care about (e.g. a --socket typo).
            let meta = std::fs::symlink_metadata(&path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::FileTypeExt;
                if meta.file_type().is_socket() {
                    std::fs::remove_file(&path)?;
                } else {
                    return Err(AgentError::Protocol(format!(
                        "'{}' exists and is not a socket; refusing to remove it",
                        path.display()
                    )));
                }
            }
        }
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let listener = UnixListener::bind(&path)?;
        // Owner-only socket: local, same-user access only.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&path, perms)?;
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
    /// subscribers are released and the socket file is unlinked.
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
        let _ = std::fs::remove_file(&self.config.socket_path);
        log::info!("stopped; all sessions were dropped");
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

/// Handle one client connection: read a frame, answer, repeat. EOF or a
/// malformed frame ends the connection.
fn handle_connection(shared: Arc<Shared>, stream: UnixStream) {
    // The listener is non-blocking for the accept poll; make sure the
    // connection itself blocks normally (accepted sockets may inherit
    // the flag on some platforms).
    let _ = stream.set_nonblocking(false);
    let Ok(write_half) = stream.try_clone() else {
        return;
    };
    let writer = Arc::new(Mutex::new(write_half));
    let mut reader = stream;
    let mut subscriber_id: Option<u64> = None;

    loop {
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
            let (tx, rx) = mpsc::channel();
            let id = NEXT_SUBSCRIBER_ID.fetch_add(1, Ordering::SeqCst);
            if let Ok(mut subscribers) = shared.subscribers.lock() {
                subscribers.push(Subscriber { id, tx });
            }
            subscriber_id = Some(id);
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
            if write_frame(&writer, &Response::Subscribed).is_err() {
                break;
            }
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
/// needs, never blocks on the network, never logs secrets.
fn dispatch(shared: &Shared, request: Request) -> Response {
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
            if let GrantSpec::Reveal { entry, field } = &grant {
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
                GrantSpec::Unlock { master_password } => {
                    Grant::Unlock(KeyMaterial::new(master_password.expose()))
                }
                GrantSpec::Reveal { entry, field } => Grant::Reveal { entry, field },
            };
            let vault_name = vault.clone();
            let grant_kind = match grant.info() {
                GrantInfo::Unlock => "unlock",
                GrantInfo::Reveal { .. } => "reveal",
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
                // A timed session is reusable until expiry; a once
                // session is consumed by this call.
                let timed = sessions.values().find(|s| {
                    s.vault == vault
                        && s.grant.is_unlock()
                        && !s.expired(now)
                        && matches!(s.scope, Scope::Timed { .. })
                });
                if let Some(session) = timed {
                    if let Grant::Unlock(material) = &session.grant {
                        return Response::UnlockFactors {
                            master_password: crate::protocol::SecretString::new(
                                material.master_password(),
                            ),
                        };
                    }
                    unreachable!("filtered to unlock grants above");
                }
                let once_id = sessions
                    .values()
                    .find(|s| {
                        s.vault == vault && s.grant.is_unlock() && matches!(s.scope, Scope::Once)
                    })
                    .map(|s| s.id.clone());
                match once_id.and_then(|id| sessions.remove(&id)) {
                    // The removed session's key material wipes on drop;
                    // the copy below is zeroizing on both sides.
                    Some(session) => match session.grant {
                        Grant::Unlock(material) => Response::UnlockFactors {
                            master_password: crate::protocol::SecretString::new(
                                material.master_password(),
                            ),
                        },
                        _ => unreachable!("filtered to unlock grants above"),
                    },
                    None => error_response(
                        ErrorCode::NotFound,
                        format!("no unlock session for vault '{vault}'"),
                    ),
                }
            }
            Err(_) => error_response(ErrorCode::Protocol, "state mutex poisoned"),
        },
        Request::CheckReveal {
            vault,
            entry,
            field,
        } => match shared.inner.lock() {
            Ok(mut sessions) => {
                let now = now_secs();
                let timed = sessions.values().find(|s| {
                    s.vault == vault
                        && s.grant.covers_reveal(&entry, &field)
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
                            && s.grant.covers_reveal(&entry, &field)
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
            max_session_secs: cap,
            stop: AtomicBool::new(false),
        })
    }

    fn unlock_grant(pw: &str) -> GrantSpec {
        GrantSpec::Unlock {
            master_password: crate::protocol::SecretString::new(pw),
        }
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
}
