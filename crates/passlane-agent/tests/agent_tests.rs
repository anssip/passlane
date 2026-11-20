//! End-to-end tests over a real socket: session lifecycle, once-vs-timed
//! semantics, expiry, revocation with cooperative notification,
//! concurrent clients, the duration cap, and the never-on-disk guarantee.

// The daemon and its Unix domain sockets are Unix-only; this whole
// target is skipped elsewhere (the portable protocol/client tests live
// in the lib).
#![cfg(unix)]

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use passlane_agent::client::AgentClient;
use passlane_agent::error::AgentError;
use passlane_agent::protocol::{ErrorCode, Event, GrantSpec, SecretString};
use passlane_agent::server::{AgentConfig, AgentServer};
use passlane_approval::message::Scope;
use zeroize::Zeroizing;

/// A server running on its own thread with a millisecond sweep, plus the
/// handle to stop it.
struct RunningAgent {
    socket: std::path::PathBuf,
    handle: passlane_agent::server::ServerHandle,
    done: Arc<std::sync::Mutex<Option<std::thread::JoinHandle<()>>>>,
    /// Kept alive so the socket's directory outlives the server; the
    /// field itself is intentionally never read.
    #[allow(dead_code)]
    dir: tempfile::TempDir,
}

impl RunningAgent {
    fn start() -> RunningAgent {
        Self::start_with_cap(900)
    }

    fn start_with_cap(cap: u64) -> RunningAgent {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("agent.sock");
        let config = AgentConfig::new(&socket)
            .with_max_session_secs(cap)
            .with_sweep_interval(Duration::from_millis(20));
        let server = AgentServer::bind(config).expect("bind");
        let handle = server.handle();
        let done = std::thread::spawn(move || {
            server.serve().expect("serve");
        });
        // The socket must exist before clients connect.
        let deadline = Instant::now() + Duration::from_secs(5);
        while !socket.exists() {
            assert!(Instant::now() < deadline, "server never bound the socket");
            std::thread::sleep(Duration::from_millis(5));
        }
        RunningAgent {
            socket,
            handle,
            done: Arc::new(std::sync::Mutex::new(Some(done))),
            dir,
        }
    }

    fn client(&self) -> AgentClient {
        AgentClient::connect(&self.socket).expect("agent is running")
    }

    fn stop(&self) {
        self.handle.stop();
        // serve() returns shortly after stop.
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.socket.exists() {
            assert!(
                Instant::now() < deadline,
                "server did not stop (socket still present)"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for RunningAgent {
    fn drop(&mut self) {
        self.handle.stop();
        if let Some(done) = self.done.lock().unwrap().take() {
            let _ = done.join();
        }
    }
}

fn unlock_grant(pw: &str) -> GrantSpec {
    GrantSpec::Unlock {
        master_password: SecretString::new(pw),
    }
}

fn reveal_grant(id: &str, entry: &str, field: &str) -> GrantSpec {
    GrantSpec::Reveal {
        id: id.to_string(),
        entry: entry.to_string(),
        field: field.to_string(),
    }
}

const GITHUB_ID: &str = "11111111-1111-1111-1111-111111111111";
const STRIPE_ID: &str = "22222222-2222-2222-2222-222222222222";

#[test]
fn session_lifecycle_create_list_use_reuse_revoke() {
    let agent = RunningAgent::start();
    let mut client = agent.client();
    let pong = client.ping().unwrap();
    assert_eq!(pong.version, 1);
    assert_eq!(pong.sessions, 0);

    let created = client
        .create_session(
            "work",
            unlock_grant("master-pw"),
            Scope::Timed { seconds: 300 },
        )
        .unwrap();
    assert!(created.expires_at.is_some());

    // Listed with the right shape, no secrets.
    let list = client.list_sessions().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].id, created.id);
    assert_eq!(list[0].vault, "work");
    assert_eq!(list[0].grant, passlane_agent::protocol::GrantInfo::Unlock);

    // A timed session is reusable: two fetches, same password.
    let (pw1, expires1) = client.get_unlock_factors("work").unwrap();
    assert_eq!(*pw1, "master-pw");
    assert!(expires1.is_some(), "a timed session reports its expiry");
    let (pw2, expires2) = client.get_unlock_factors("work").unwrap();
    assert_eq!(*pw2, "master-pw");
    assert_eq!(expires2, expires1, "reuse does not change the expiry");

    // Revoke: the session is gone.
    assert_eq!(client.revoke_session(&created.id).unwrap(), 1);
    assert!(client.list_sessions().unwrap().is_empty());
    match client.get_unlock_factors("work") {
        Err(AgentError::Server { code, .. }) => assert_eq!(code, ErrorCode::NotFound),
        other => panic!("expected NotFound after revoke, got {other:?}"),
    }
    // Revoking it again is NotFound, not a crash.
    match client.revoke_session(&created.id) {
        Err(AgentError::Server { code, .. }) => assert_eq!(code, ErrorCode::NotFound),
        other => panic!("{other:?}"),
    }
    agent.stop();
}

#[test]
fn once_scoped_unlock_session_is_consumed_by_first_use() {
    let agent = RunningAgent::start();
    let mut owner = agent.client();
    owner
        .create_session("work", unlock_grant("one-time-pw"), Scope::Once)
        .unwrap();
    let mut user = agent.client();
    let (pw, expires) = user.get_unlock_factors("work").unwrap();
    assert_eq!(*pw, "one-time-pw");
    assert_eq!(
        expires, None,
        "a consumed once session has no expiry to revalidate"
    );
    match user.get_unlock_factors("work") {
        Err(AgentError::Server { code, .. }) => assert_eq!(code, ErrorCode::NotFound),
        other => panic!("once session must be consumed, got {other:?}"),
    }
    agent.stop();
}

#[test]
fn reveal_sessions_cover_entry_and_field_once_or_timed() {
    let agent = RunningAgent::start();
    let mut owner = agent.client();
    owner
        .create_session(
            "work",
            reveal_grant(GITHUB_ID, "github.com", "password"),
            Scope::Timed { seconds: 300 },
        )
        .unwrap();
    owner
        .create_session(
            "work",
            reveal_grant(STRIPE_ID, "stripe", "password"),
            Scope::Once,
        )
        .unwrap();

    let mut user = agent.client();
    // Timed: reusable, with an expiry.
    match user.check_reveal("work", GITHUB_ID, "password").unwrap() {
        passlane_agent::client::RevealAnswer::Allowed { until } => assert!(until.is_some()),
        passlane_agent::client::RevealAnswer::Denied => panic!("timed session must cover"),
    }
    assert!(matches!(
        user.check_reveal("work", GITHUB_ID, "password").unwrap(),
        passlane_agent::client::RevealAnswer::Allowed { until: Some(_) }
    ));
    // A different field (or entry) is not covered.
    assert_eq!(
        user.check_reveal("work", GITHUB_ID, "code").unwrap(),
        passlane_agent::client::RevealAnswer::Denied
    );
    // A different entry reusing the SAME TITLE must not inherit the
    // approval — reveal sessions are keyed by the entry's stable UUID.
    assert_eq!(
        user.check_reveal("work", "33333333-3333-3333-3333-333333333333", "password")
            .unwrap(),
        passlane_agent::client::RevealAnswer::Denied
    );
    // Once: the first use is allowed and consumes the approval...
    assert_eq!(
        user.check_reveal("work", STRIPE_ID, "password").unwrap(),
        passlane_agent::client::RevealAnswer::Allowed { until: None }
    );
    // ...and the second is not covered anymore.
    assert_eq!(
        user.check_reveal("work", STRIPE_ID, "password").unwrap(),
        passlane_agent::client::RevealAnswer::Denied
    );
    agent.stop();
}

#[test]
fn timed_sessions_expire_and_notify_subscribers() {
    let agent = RunningAgent::start();
    let mut owner = agent.client();
    let created = owner
        .create_session(
            "work",
            unlock_grant("expiring-pw"),
            Scope::Timed { seconds: 1 },
        )
        .unwrap();

    let mut events = owner.subscribe().unwrap();
    let mut watcher = agent.client();
    watcher
        .create_session(
            "other",
            unlock_grant("stays"),
            Scope::Timed { seconds: 600 },
        )
        .unwrap();

    // Wait past the expiry (sweeper runs every 20ms).
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut got_expired = false;
    while Instant::now() < deadline {
        if matches!(
            events.next_event(),
            Ok(Event::SessionExpired { id, .. }) if id == created.id
        ) {
            got_expired = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(got_expired, "subscriber must see SessionExpired");

    // The expired session is gone...
    assert!(
        watcher
            .list_sessions()
            .unwrap()
            .iter()
            .all(|s| s.id != created.id)
    );
    // ...while the unexpired one survives.
    assert!(watcher.get_unlock_factors("other").is_ok());
    agent.stop();
}

#[test]
fn revocation_notifies_connected_clients_and_blocks_use() {
    let agent = RunningAgent::start();
    let mut owner = agent.client();
    let created = owner
        .create_session("work", unlock_grant("pw"), Scope::Timed { seconds: 600 })
        .unwrap();

    let mut events = owner.subscribe().unwrap();
    let mut user = agent.client();
    assert!(user.get_unlock_factors("work").is_ok());

    let mut revoker = agent.client();
    revoker.revoke_session(&created.id).unwrap();

    match events.next_event() {
        Ok(Event::SessionRevoked { id, vault }) => {
            assert_eq!(id, created.id);
            assert_eq!(vault, "work");
        }
        other => panic!("expected SessionRevoked, got {other:?}"),
    }
    match user.get_unlock_factors("work") {
        Err(AgentError::Server { code, .. }) => assert_eq!(code, ErrorCode::NotFound),
        other => panic!("revoked session must not serve factors, got {other:?}"),
    }
    agent.stop();
}

#[test]
fn lock_drops_every_session_and_broadcasts() {
    let agent = RunningAgent::start();
    let subscriber_client = agent.client();
    let mut events = subscriber_client.subscribe().unwrap();
    let mut filler = agent.client();
    filler
        .create_session("a", unlock_grant("1"), Scope::Timed { seconds: 600 })
        .unwrap();
    filler
        .create_session(
            "b",
            reveal_grant(GITHUB_ID, "e", "password"),
            Scope::Timed { seconds: 600 },
        )
        .unwrap();

    let mut locker = agent.client();
    locker.lock().unwrap();
    assert!(locker.list_sessions().unwrap().is_empty());
    match events.next_event() {
        Ok(Event::SessionsLocked) => {}
        other => panic!("expected SessionsLocked, got {other:?}"),
    }
    // The agent keeps serving after a lock.
    assert_eq!(locker.ping().unwrap().sessions, 0);
    agent.stop();
}

#[test]
fn duration_cap_is_enforced() {
    let agent = RunningAgent::start_with_cap(60);
    let mut client = agent.client();
    match client.create_session("work", unlock_grant("pw"), Scope::Timed { seconds: 61 }) {
        Err(AgentError::Server { code, message }) => {
            assert_eq!(code, ErrorCode::TooLong);
            assert!(message.contains("60s"), "{message}");
        }
        other => panic!("over-cap session must be refused, got {other:?}"),
    }
    assert!(
        client
            .create_session("work", unlock_grant("pw"), Scope::Timed { seconds: 60 })
            .is_ok()
    );
    // Once sessions carry no duration and are always allowed.
    assert!(
        client
            .create_session("work", unlock_grant("pw"), Scope::Once)
            .is_ok()
    );
    agent.stop();
}

#[test]
fn stale_socket_from_a_crashed_agent_is_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("agent.sock");
    // A listener that dies without unlinking leaves a stale socket.
    {
        let _stale = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    } // dropped: file remains, nothing accepts

    let agent = RunningAgent::start(); // separate dir; now emulate reuse:
    agent.stop();
    // Bind directly on the stale path.
    let config = AgentConfig::new(&socket).with_sweep_interval(Duration::from_millis(20));
    let server = AgentServer::bind(config).expect("stale socket must be replaced");
    let handle = server.handle();
    let thread = std::thread::spawn(move || server.serve().unwrap());
    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket.exists() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    let mut client = AgentClient::connect(&socket).unwrap();
    assert!(client.ping().is_ok());
    handle.stop();
    thread.join().unwrap();
}

#[test]
fn second_agent_on_the_same_socket_is_refused() {
    let agent = RunningAgent::start();
    let config = AgentConfig::new(&agent.socket);
    match AgentServer::bind(config) {
        Err(AgentError::AlreadyRunning(path)) => assert_eq!(path, agent.socket),
        other => panic!("expected AlreadyRunning, got {other:?}"),
    }
    // And the first agent is unaffected.
    assert!(agent.client().ping().is_ok());
    agent.stop();
}

#[test]
fn concurrent_cli_clients_hammer_the_agent() {
    let agent = RunningAgent::start();
    const CLIENTS: usize = 8;
    const OPS: usize = 10;
    let barrier = Arc::new(Barrier::new(CLIENTS));
    let errors = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();
    for c in 0..CLIENTS {
        let socket = agent.socket.clone();
        let barrier = Arc::clone(&barrier);
        let errors = Arc::clone(&errors);
        handles.push(std::thread::spawn(move || {
            let mut client = AgentClient::connect(&socket).expect("connect");
            barrier.wait();
            for i in 0..OPS {
                let vault = format!("vault-{c}");
                // Create, use twice (timed reuse), list, all concurrent
                // with the other clients.
                let created = client
                    .create_session(
                        &vault,
                        unlock_grant(&format!("pw-{c}-{i}")),
                        Scope::Timed { seconds: 300 },
                    )
                    .expect("create");
                let (pw, _) = client.get_unlock_factors(&vault).expect("get");
                assert_eq!(*pw, format!("pw-{c}-{i}"));
                client.get_unlock_factors(&vault).expect("get again");
                let list = client.list_sessions().expect("list");
                assert!(list.iter().any(|s| s.id == created.id));
                // Revoke our own session; others must survive.
                client.revoke_session(&created.id).expect("revoke");
                if client.get_unlock_factors(&vault).is_ok() {
                    errors.fetch_add(1, Ordering::SeqCst);
                }
            }
        }));
    }
    for handle in handles {
        handle.join().expect("client thread");
    }
    assert_eq!(
        errors.load(Ordering::SeqCst),
        0,
        "revocation must take effect"
    );

    // Every thread revoked its own sessions; the store must be empty.
    let mut client = agent.client();
    assert_eq!(client.list_sessions().unwrap().len(), 0);
    agent.stop();
}

/// Env vars are process-global; tests that set them must not race.
static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn discovery_rejects_shared_runtime_directories() {
    let _guard = ENV_MUTEX.lock().unwrap();
    let shared = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(shared.path()).unwrap().permissions();
    perms.set_mode(0o1777); // a /tmp-like sticky, world-writable dir
    std::fs::set_permissions(shared.path(), perms).unwrap();

    // SAFETY of test hygiene: save and restore both vars.
    let saved_tmpdir = std::env::var_os("TMPDIR");
    let saved_sock = std::env::var_os("PASSLANE_AGENT_SOCK");
    unsafe { std::env::set_var("TMPDIR", shared.path()) };
    unsafe { std::env::remove_var("PASSLANE_AGENT_SOCK") };
    // No XDG_RUNTIME_DIR in the test env normally; remove defensively.
    let saved_xdg = std::env::var_os("XDG_RUNTIME_DIR");
    unsafe { std::env::remove_var("XDG_RUNTIME_DIR") };

    assert_eq!(
        passlane_agent::default_socket_path(),
        None,
        "a world-writable TMPDIR must not be used for discovery"
    );

    // A private directory qualifies.
    let mut perms = std::fs::metadata(shared.path()).unwrap().permissions();
    perms.set_mode(0o700);
    std::fs::set_permissions(shared.path(), perms).unwrap();
    assert_eq!(
        passlane_agent::default_socket_path(),
        Some(shared.path().join("passlane-agent.sock"))
    );
    // An explicit PASSLANE_AGENT_SOCK always wins.
    unsafe { std::env::set_var("PASSLANE_AGENT_SOCK", "/explicit/agent.sock") };
    assert_eq!(
        passlane_agent::default_socket_path(),
        Some("/explicit/agent.sock".into())
    );

    unsafe {
        match saved_sock {
            Some(v) => std::env::set_var("PASSLANE_AGENT_SOCK", v),
            None => std::env::remove_var("PASSLANE_AGENT_SOCK"),
        }
        match saved_xdg {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
        match saved_tmpdir {
            Some(v) => std::env::set_var("TMPDIR", v),
            None => std::env::remove_var("TMPDIR"),
        }
    }
}

#[test]
fn client_refuses_untrusted_sockets() {
    let dir = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    // A regular file where the socket should be: refused.
    let not_socket = dir.path().join("plain.file");
    std::fs::write(&not_socket, "x").unwrap();
    let err = AgentClient::connect(&not_socket).unwrap_err();
    assert!(err.to_string().contains("untrusted"), "{err}");

    // A socket with group/other permission bits: refused.
    let permissive = dir.path().join("permissive.sock");
    let listener = UnixListener::bind(&permissive).unwrap();
    let mut perms = std::fs::metadata(&permissive).unwrap().permissions();
    perms.set_mode(0o666);
    std::fs::set_permissions(&permissive, perms).unwrap();
    let err = AgentClient::connect(&permissive).unwrap_err();
    assert!(err.to_string().contains("untrusted"), "{err}");
    drop(listener);

    // An owner-only socket in a private directory: accepted (NotRunning,
    // not untrusted — nothing is listening, but the path itself is fine).
    let ok = dir.path().join("good.sock");
    let listener = UnixListener::bind(&ok).unwrap();
    let mut perms = std::fs::metadata(&ok).unwrap().permissions();
    perms.set_mode(0o600); // as AgentServer::bind would have it
    std::fs::set_permissions(&ok, perms).unwrap();
    drop(listener); // stale but 0600: the path is trusted, just dead
    match AgentClient::connect(&ok) {
        Err(AgentError::NotRunning(_)) => {}
        other => panic!("expected NotRunning for a trusted dead socket, got {other:?}"),
    }
}

#[test]
fn stopping_the_agent_closes_open_connections() {
    let agent = RunningAgent::start();
    let client = agent.client();
    let mut events = client.subscribe().unwrap();
    events
        .set_read_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    // Server stops: the subscriber must see EOF promptly (its socket is
    // shut down) instead of waiting forever.
    agent.stop();
    match events.next_event() {
        Err(_) => {} // EOF / closed peer: exactly what we want
        Ok(ev) => panic!("unexpected event while shutting down: {ev:?}"),
    }
}

#[test]
fn key_material_never_reaches_disk() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let socket = dir.path().join("agent.sock");
    let config = AgentConfig::new(&socket).with_sweep_interval(Duration::from_millis(20));
    let server = AgentServer::bind(config).unwrap();
    let handle = server.handle();
    let thread = std::thread::spawn(move || server.serve().unwrap());
    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket.exists() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }

    // Canary secrets that must never appear in any file.
    let canary_pw = format!("CANARY-pw-{}", uuid::Uuid::new_v4());
    let canary_entry = format!("CANARY-entry-{}", uuid::Uuid::new_v4());
    {
        let mut client = AgentClient::connect(&socket).unwrap();
        client
            .create_session(
                "work",
                unlock_grant(&canary_pw),
                Scope::Timed { seconds: 300 },
            )
            .unwrap();
        client
            .create_session(
                "work",
                reveal_grant(GITHUB_ID, &canary_entry, "password"),
                Scope::Timed { seconds: 300 },
            )
            .unwrap();
        let (pw, _): (Zeroizing<String>, _) = client.get_unlock_factors("work").unwrap();
        assert_eq!(*pw, canary_pw);
        client
            .check_reveal("work", &canary_entry, "password")
            .unwrap();
        client.list_sessions().unwrap();
    }

    handle.stop();
    thread.join().unwrap();

    // The socket directory is clean (no leftover files at all).
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert!(
        leftovers.is_empty(),
        "the agent must not leave files behind: {leftovers:?}"
    );

    // No file under either scratch directory contains the canaries.
    for root in [dir.path(), home.path()] {
        assert_no_canary(root, &[&canary_pw, &canary_entry]);
    }
}

fn assert_no_canary(root: &Path, canaries: &[&str]) {
    fn walk(root: &Path, canaries: &[&str], found: &mut Vec<String>) {
        if root.is_dir() {
            for entry in std::fs::read_dir(root).unwrap() {
                walk(&entry.unwrap().path(), canaries, found);
            }
            return;
        }
        if root.is_file() {
            let bytes = std::fs::read(root).unwrap_or_default();
            for canary in canaries {
                if bytes.windows(canary.len()).any(|w| w == canary.as_bytes()) {
                    found.push(format!("{} contains {}", root.display(), canary));
                }
            }
        }
    }
    let mut found = Vec::new();
    walk(root, canaries, &mut found);
    assert!(found.is_empty(), "key material leaked to disk: {found:?}");
}
