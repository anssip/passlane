//! End-to-end tests over a real socket: session lifecycle, once-vs-timed
//! semantics, expiry, revocation with cooperative notification,
//! concurrent clients, the duration cap, and the never-on-disk guarantee.

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

fn reveal_grant(entry: &str, field: &str) -> GrantSpec {
    GrantSpec::Reveal {
        entry: entry.to_string(),
        field: field.to_string(),
    }
}

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
    let pw1 = client.get_unlock_factors("work").unwrap();
    assert_eq!(*pw1, "master-pw");
    let pw2 = client.get_unlock_factors("work").unwrap();
    assert_eq!(*pw2, "master-pw");

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
    let pw = user.get_unlock_factors("work").unwrap();
    assert_eq!(*pw, "one-time-pw");
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
            reveal_grant("github.com", "password"),
            Scope::Timed { seconds: 300 },
        )
        .unwrap();
    owner
        .create_session("work", reveal_grant("stripe", "password"), Scope::Once)
        .unwrap();

    let mut user = agent.client();
    // Timed: reusable, with an expiry.
    match user.check_reveal("work", "github.com", "password").unwrap() {
        passlane_agent::client::RevealAnswer::Allowed { until } => assert!(until.is_some()),
        passlane_agent::client::RevealAnswer::Denied => panic!("timed session must cover"),
    }
    assert!(matches!(
        user.check_reveal("work", "github.com", "password").unwrap(),
        passlane_agent::client::RevealAnswer::Allowed { until: Some(_) }
    ));
    // A different field (or entry) is not covered.
    assert_eq!(
        user.check_reveal("work", "github.com", "code").unwrap(),
        passlane_agent::client::RevealAnswer::Denied
    );
    assert_eq!(
        user.check_reveal("work", "gitlab", "password").unwrap(),
        passlane_agent::client::RevealAnswer::Denied
    );
    // Once: the first use is allowed and consumes the approval...
    assert_eq!(
        user.check_reveal("work", "stripe", "password").unwrap(),
        passlane_agent::client::RevealAnswer::Allowed { until: None }
    );
    // ...and the second is not covered anymore.
    assert_eq!(
        user.check_reveal("work", "stripe", "password").unwrap(),
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
            reveal_grant("e", "password"),
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
                let pw = client.get_unlock_factors(&vault).expect("get");
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
                reveal_grant(&canary_entry, "password"),
                Scope::Timed { seconds: 300 },
            )
            .unwrap();
        let pw: Zeroizing<String> = client.get_unlock_factors("work").unwrap();
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
