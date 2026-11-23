//! End-to-end regression tests for passlane#65: the compiled `passlane`
//! binary must open a vault through a live session-agent session from a
//! context that has nothing to prompt on — no terminal, a `TMPDIR` that
//! hides the default socket path, the socket named explicitly — for vaults
//! with and without a hardware-key factor. And when nothing prompt-free can
//! open the vault, it must fail at once with a reason, never wait.
//!
//! The hardware-key vault uses a secret-backed challenge-response key
//! (`LocalChallenge`: what the lost-key recovery path and passlane-core's
//! own tests use as a stand-in for a hardware key), since no test can
//! touch a physical one.

// The daemon and its Unix domain sockets are Unix-only.
#![cfg(unix)]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime};

use keepass_ng::ChallengeResponseKey;
use passlane_agent::client::AgentClient;
use passlane_agent::protocol::{ChallengeResponseMaterial, GrantSpec, SecretString};
use passlane_agent::server::{AgentConfig, AgentServer, ServerHandle};
use passlane_approval::message::Scope;
use passlane_core::vault::entities::Credential;
use passlane_core::vault::keepass_vault::KeepassVault;
use passlane_core::vault::vault_trait::PasswordVault;

const PASSWORD: &str = "cli65-master-password";
const ENTRY_PASSWORD: &str = "cli65-entry-password";
/// The HMAC-SHA1 secret of the vault's challenge-response slot, hex.
const SLOT_SECRET: &str = "0102030405060708090a0b0c0d0e0f1011121314";
/// What the `allow` entry prints with `show --out`.
const SHOWN: &str = "Found 1 credentials:\ncli65-entry-password\n\n";

/// Everything one test needs: a scratch `HOME` holding the registry and the
/// vault files, a second scratch directory the CLI gets as `TMPDIR` (so
/// default socket discovery cannot find the agent), and the agent itself,
/// served from this test process.
struct Fixture {
    home: tempfile::TempDir,
    foreign_tmp: tempfile::TempDir,
    /// Kept alive so the socket's directory outlives the server.
    agent_dir: tempfile::TempDir,
    socket: PathBuf,
    handle: ServerHandle,
    server: Option<std::thread::JoinHandle<()>>,
}

impl Fixture {
    /// Start the agent on an explicit socket in its own private directory.
    fn start() -> Self {
        let agent_dir = tempfile::tempdir().unwrap();
        let socket = agent_dir.path().join("agent.sock");
        let server = AgentServer::bind(
            AgentConfig::new(&socket).with_sweep_interval(Duration::from_millis(20)),
        )
        .expect("bind the agent socket");
        let handle = server.handle();
        let served = std::thread::spawn(move || server.serve().expect("serve"));
        Self {
            home: tempfile::tempdir().unwrap(),
            foreign_tmp: tempfile::tempdir().unwrap(),
            agent_dir,
            socket,
            handle,
            server: Some(served),
        }
    }

    fn client(&self) -> AgentClient {
        AgentClient::connect(&self.socket).expect("the agent is running")
    }

    /// Create a vault file with one `agent=allow` credential and register
    /// it in the scratch registry (the first one becomes the active vault;
    /// every test addresses its vaults by name anyway).
    fn add_vault(&self, name: &str, with_hardware_key: bool) {
        let file = self.home.path().join(format!("{name}.kdbx"));
        let file = file.to_str().unwrap();
        let factor = with_hardware_key.then(local_challenge);
        let mut vault =
            KeepassVault::new(file, PASSWORD, None, factor.as_ref()).expect("create the vault");
        vault
            .save_one_credential(
                Credential::new(None, ENTRY_PASSWORD, "github.com", "alice", None, None)
                    .with_custom_attributes(&[("agent".to_string(), "allow".to_string())]),
            )
            .expect("seed the vault");

        let registry = self.home.path().join(".passlane");
        std::fs::create_dir_all(&registry).unwrap();
        let registry_file = registry.join("vaults.json");
        let mut vaults: Vec<serde_json::Value> = match std::fs::read_to_string(&registry_file) {
            Ok(text) => serde_json::from_str::<serde_json::Value>(&text).unwrap()["vaults"]
                .as_array()
                .expect("a registry has a vaults array")
                .clone(),
            Err(_) => Vec::new(),
        };
        let mut entry = serde_json::json!({"name": name, "path": file});
        if with_hardware_key {
            entry["hwkey"] = serde_json::json!({"slot": 1});
        }
        vaults.push(entry);
        std::fs::write(
            &registry_file,
            serde_json::json!({"version": 1, "vaults": vaults}).to_string(),
        )
        .unwrap();
        let active = registry.join(".active_vault");
        if !active.exists() {
            std::fs::write(active, name).unwrap();
        }
    }

    /// What `passlane unlock --session` hands the agent: the vault's master
    /// password, and the key factor when `unlock --session` can hand it
    /// over (a secret-backed key). Timed.
    fn create_unlock_session(&self, name: &str, with_key_factor: bool) {
        self.client()
            .create_session(
                name,
                GrantSpec::Unlock {
                    master_password: SecretString::new(PASSWORD),
                    challenge_response: with_key_factor.then(|| {
                        ChallengeResponseMaterial::Secret {
                            secret_hex: SecretString::new(SLOT_SECRET),
                        }
                    }),
                },
                Scope::Timed { seconds: 600 },
            )
            .expect("create the unlock session");
    }

    /// Run the real CLI exactly the way an agent platform does: stdin is
    /// not a terminal, output is piped, `TMPDIR` points somewhere the
    /// socket is not, and the socket is named explicitly. Returns the
    /// output and how long the command took.
    fn passlane(&self, args: &[&str]) -> (Output, Duration) {
        self.passlane_with_socket(args, &self.socket)
    }

    fn passlane_with_socket(&self, args: &[&str], socket: &Path) -> (Output, Duration) {
        let started = Instant::now();
        let mut child = Command::new(env!("CARGO_BIN_EXE_passlane"))
            .args(args)
            .env("HOME", self.home.path())
            .env("TMPDIR", self.foreign_tmp.path())
            .env("PASSLANE_AGENT_SOCK", socket)
            .env_remove("PASSLANE_VAULT")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn passlane");
        // A hang is the failure this file guards against: bound the wait
        // instead of letting a wedged prompt block the test run forever.
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = child.try_wait().expect("wait for passlane") {
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                child
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_end(&mut stdout)
                    .unwrap();
                child
                    .stderr
                    .take()
                    .unwrap()
                    .read_to_end(&mut stderr)
                    .unwrap();
                let output = Output {
                    status,
                    stdout,
                    stderr,
                };
                // The tests never touch a hardware key: a panic says the
                // CLI reached for one (or for a prompt) it should not have.
                assert!(
                    !stderr_of(&output).contains("panicked"),
                    "passlane {} panicked instead of failing cleanly:\n{}",
                    args.join(" "),
                    stderr_of(&output)
                );
                return (output, started.elapsed());
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "passlane {} did not finish within 60s — it is blocked on a prompt",
                    args.join(" ")
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.handle.stop();
        if let Some(server) = self.server.take() {
            let _ = server.join();
        }
    }
}

fn local_challenge() -> ChallengeResponseKey {
    ChallengeResponseKey::LocalChallenge(SLOT_SECRET.to_string())
}

fn stdout_of(output: &Output) -> &str {
    std::str::from_utf8(&output.stdout).unwrap()
}

fn stderr_of(output: &Output) -> &str {
    std::str::from_utf8(&output.stderr).unwrap()
}

fn show_entry(fixture: &Fixture, vault: &str) -> (Output, Duration) {
    fixture.passlane(&["--vault", vault, "show", "--out", "github.com"])
}

#[test]
fn password_only_vault_opens_through_a_live_session_without_a_terminal() {
    let fixture = Fixture::start();
    fixture.add_vault("plain", false);
    fixture.create_unlock_session("plain", false);

    let (output, _) = show_entry(&fixture, "plain");
    assert!(
        output.status.success(),
        "rc={:?} stdout={:?} stderr={:?}",
        output.status,
        stdout_of(&output),
        stderr_of(&output)
    );
    assert_eq!(stdout_of(&output), SHOWN);
    assert!(
        stderr_of(&output).contains("via the session agent"),
        "{:?}",
        stderr_of(&output)
    );
}

/// The reproduction of passlane#65: before the fix this blocked on the
/// hardware key's touch, with nobody to touch it.
#[test]
fn hardware_key_vault_opens_through_a_live_session_without_a_terminal() {
    let fixture = Fixture::start();
    fixture.add_vault("keyed", true);
    fixture.create_unlock_session("keyed", true);

    let (output, elapsed) = show_entry(&fixture, "keyed");
    assert!(
        output.status.success(),
        "rc={:?} stdout={:?} stderr={:?}",
        output.status,
        stdout_of(&output),
        stderr_of(&output)
    );
    assert_eq!(stdout_of(&output), SHOWN);
    assert!(
        !stderr_of(&output).contains("hardware key"),
        "no hardware-key prompt: {:?}",
        stderr_of(&output)
    );
    assert!(
        elapsed < Duration::from_secs(20),
        "opened promptly, took {elapsed:?}"
    );

    // The session keeps serving — a write too: a save issues a fresh
    // challenge, which the held secret answers just like the device would.
    let csv = fixture.home.path().join("more.csv");
    std::fs::write(
        &csv,
        "username,password,title,custom_attributes\ncarol,another-pw,stripe.test,agent=allow\n",
    )
    .unwrap();
    let csv = csv.to_str().unwrap();
    let (output, _) = fixture.passlane(&["--vault", "keyed", "csv", csv]);
    assert!(
        output.status.success(),
        "a save through the session: {:?}",
        stderr_of(&output)
    );
    let (output, _) = fixture.passlane(&["--vault", "keyed", "list", "--json", "stripe"]);
    assert!(output.status.success(), "{:?}", stderr_of(&output));
    let json: serde_json::Value = serde_json::from_str(stdout_of(&output))
        .expect("a session-backed unlock leaves stdout pure JSON");
    assert_eq!(json["entries"][0]["password"], "another-pw");

    // The listing tells the owner the key factor is held.
    let (output, _) = fixture.passlane(&["sessions", "list"]);
    assert!(output.status.success(), "{:?}", stderr_of(&output));
    assert!(
        stdout_of(&output).contains("unlock + hwkey"),
        "{:?}",
        stdout_of(&output)
    );
}

#[test]
fn a_session_holding_only_the_password_cannot_open_a_hardware_key_vault_unattended() {
    let fixture = Fixture::start();
    fixture.add_vault("keyed", true);
    // A physical key's factor cannot be handed to the agent: this is what
    // `unlock --session` leaves for such a vault.
    fixture.create_unlock_session("keyed", false);

    let (output, elapsed) = show_entry(&fixture, "keyed");
    assert!(!output.status.success(), "stdout={:?}", stdout_of(&output));
    assert_eq!(stdout_of(&output), "", "nothing is revealed");
    let stderr = stderr_of(&output);
    assert!(stderr.contains("hardware key"), "{stderr}");
    assert!(stderr.contains("without a terminal"), "{stderr}");
    assert!(stderr.contains("master password only"), "{stderr}");
    assert!(
        elapsed < Duration::from_secs(10),
        "failed fast rather than waiting for a touch: {elapsed:?}"
    );
}

#[test]
fn a_hardware_key_vault_with_no_session_fails_fast_unattended() {
    let fixture = Fixture::start();
    fixture.add_vault("keyed", true);

    let (output, elapsed) = show_entry(&fixture, "keyed");
    assert!(!output.status.success());
    let stderr = stderr_of(&output);
    assert!(stderr.contains("hardware key"), "{stderr}");
    assert!(
        !stderr.contains("master password only"),
        "no session exists to describe: {stderr}"
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "nothing was waited on: {elapsed:?}"
    );
}

#[test]
fn a_locked_vault_fails_with_guidance_instead_of_prompting() {
    let fixture = Fixture::start();
    fixture.add_vault("plain", false);

    let (output, elapsed) = show_entry(&fixture, "plain");
    assert!(!output.status.success());
    assert_eq!(stdout_of(&output), "");
    let stderr = stderr_of(&output);
    assert!(stderr.contains("without a terminal"), "{stderr}");
    assert!(
        stderr.contains("'passlane --vault plain unlock --session'"),
        "{stderr}"
    );
    assert!(
        stderr.contains("'passlane --vault plain unlock'"),
        "{stderr}"
    );
    assert!(
        elapsed < Duration::from_secs(20),
        "no unbounded wait on the keychain: {elapsed:?}"
    );
}

#[test]
fn a_stale_completion_cache_is_refreshed_from_the_vault_a_command_opens() {
    let fixture = Fixture::start();
    fixture.add_vault("plain", false);
    fixture.create_unlock_session("plain", false);
    let cache = fixture
        .home
        .path()
        .join(".passlane")
        .join(".completion_cache.plain");
    std::fs::write(&cache, "stale.example:nobody\n").unwrap();
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&cache)
        .unwrap();
    file.set_modified(SystemTime::now() - Duration::from_secs(8 * 24 * 60 * 60))
        .unwrap();
    drop(file);

    // A command that does not open the vault does not read the keychain
    // for the cache when nobody could answer for it: the stale file stays.
    let (output, _) = fixture.passlane(&["sessions", "list"]);
    assert!(output.status.success(), "{:?}", stderr_of(&output));
    assert_eq!(
        std::fs::read_to_string(&cache).unwrap(),
        "stale.example:nobody\n"
    );

    // A command that does open the vault brings the cache up to date from
    // it — no keychain involved.
    let (output, _) = show_entry(&fixture, "plain");
    assert!(output.status.success(), "{:?}", stderr_of(&output));
    let cache = std::fs::read_to_string(&cache).unwrap();
    assert!(cache.contains("github.com:alice"), "{cache}");
    assert!(!cache.contains("stale.example"), "{cache}");
}

#[test]
fn a_revoked_session_no_longer_opens_the_vault() {
    let fixture = Fixture::start();
    fixture.add_vault("plain", false);
    fixture.create_unlock_session("plain", false);
    let (output, _) = show_entry(&fixture, "plain");
    assert!(output.status.success(), "{:?}", stderr_of(&output));

    fixture.client().revoke_vault("plain").unwrap();
    let (output, _) = show_entry(&fixture, "plain");
    assert!(!output.status.success());
    assert_eq!(stdout_of(&output), "", "a revoked session reveals nothing");
    assert!(
        stderr_of(&output).contains("without a terminal"),
        "{:?}",
        stderr_of(&output)
    );
}

#[test]
fn a_socket_nobody_listens_on_is_an_error_not_a_silent_fallback() {
    let fixture = Fixture::start();
    fixture.add_vault("plain", false);
    fixture.create_unlock_session("plain", false);

    // Named but missing.
    let missing = fixture.agent_dir.path().join("nowhere.sock");
    let (output, _) = fixture.passlane_with_socket(
        &["--vault", "plain", "show", "--out", "github.com"],
        &missing,
    );
    assert!(!output.status.success());
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains(&missing.display().to_string()),
        "the error names the socket: {stderr}"
    );
    assert!(stderr.contains("PASSLANE_AGENT_SOCK"), "{stderr}");
    assert!(stderr.contains("passlane-agent"), "{stderr}");
    assert_eq!(stdout_of(&output), "");

    // Left behind by a crashed agent: a socket file nothing accepts on.
    let stale = fixture.agent_dir.path().join("stale.sock");
    let listener = std::os::unix::net::UnixListener::bind(&stale).unwrap();
    let mut perms = std::fs::metadata(&stale).unwrap().permissions();
    use std::os::unix::fs::PermissionsExt;
    perms.set_mode(0o600);
    std::fs::set_permissions(&stale, perms).unwrap();
    drop(listener);
    let (output, _) =
        fixture.passlane_with_socket(&["--vault", "plain", "show", "--out", "github.com"], &stale);
    assert!(!output.status.success());
    assert!(
        stderr_of(&output).contains("PASSLANE_AGENT_SOCK"),
        "{:?}",
        stderr_of(&output)
    );
}

#[test]
fn an_untrusted_socket_is_refused_before_anything_is_sent() {
    let fixture = Fixture::start();
    fixture.add_vault("plain", false);
    fixture.create_unlock_session("plain", false);

    let not_a_socket = fixture.home.path().join("agent.pid");
    std::fs::write(&not_a_socket, "1234").unwrap();
    let (output, _) = fixture.passlane_with_socket(
        &["--vault", "plain", "show", "--out", "github.com"],
        &not_a_socket,
    );
    assert!(!output.status.success());
    let stderr = stderr_of(&output);
    assert!(stderr.contains("untrusted"), "{stderr}");
    assert!(stderr.contains("PASSLANE_AGENT_SOCK"), "{stderr}");
    assert_eq!(stdout_of(&output), "");
}

/// A trusted socket whose listener accepts connections and never answers
/// them: an agent that is wedged.
fn wedged_agent(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let socket = dir.join("wedged.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::thread::spawn(move || {
        // Hold the connection open and say nothing, for longer than any
        // test is willing to wait.
        let Ok((stream, _)) = listener.accept() else {
            return;
        };
        std::thread::sleep(Duration::from_secs(120));
        drop(stream);
    });
    socket
}

#[test]
fn an_agent_that_never_answers_does_not_hang_the_command() {
    let fixture = Fixture::start();
    fixture.add_vault("plain", false);
    let wedged_dir = tempfile::tempdir().unwrap();
    let wedged = wedged_agent(wedged_dir.path());

    let (output, elapsed) = fixture.passlane_with_socket(
        &["--vault", "plain", "show", "--out", "github.com"],
        &wedged,
    );
    assert!(!output.status.success());
    let stderr = stderr_of(&output);
    assert!(stderr.contains("did not answer within"), "{stderr}");
    assert!(stderr.contains("Restart passlane-agent"), "{stderr}");
    assert!(
        elapsed < Duration::from_secs(20),
        "bounded by the request timeout, not by the wedged agent: {elapsed:?}"
    );
}

#[test]
fn hardware_key_commands_never_wait_unattended() {
    let fixture = Fixture::start();
    fixture.add_vault("plain", false);
    fixture.add_vault("keyed", true);
    // Enrolling needs the new key touched to save; recovery needs the
    // secret typed in; an ordinary removal needs the enrolled key. None of
    // that happens for a command without a terminal, and each is refused
    // before anything is resolved, asked or touched.
    for args in [
        vec!["--vault", "plain", "hwkey", "add", "--slot", "1"],
        vec!["--vault", "keyed", "hwkey", "remove", "--secret"],
        vec!["--vault", "keyed", "hwkey", "remove"],
    ] {
        let (output, elapsed) = fixture.passlane(&args);
        let stderr = stderr_of(&output);
        assert!(!output.status.success(), "{args:?}");
        assert!(stderr.contains("from a terminal"), "{args:?}: {stderr}");
        assert!(
            elapsed < Duration::from_secs(10),
            "{args:?} failed fast: {elapsed:?}"
        );
    }
}

#[test]
fn a_session_holding_the_key_factor_lets_the_key_be_removed_unattended() {
    let fixture = Fixture::start();
    fixture.add_vault("keyed", true);
    fixture.create_unlock_session("keyed", true);

    // The session opens the vault with no key present, and the save that
    // drops the factor needs no challenge.
    let (output, elapsed) = fixture.passlane(&["--vault", "keyed", "hwkey", "remove"]);
    assert!(
        output.status.success(),
        "rc={:?} stderr={:?}",
        output.status,
        stderr_of(&output)
    );
    assert!(
        !stderr_of(&output).contains("Touch"),
        "{:?}",
        stderr_of(&output)
    );
    assert!(elapsed < Duration::from_secs(10), "{elapsed:?}");

    // The vault itself no longer requires the factor, and the registry
    // no longer records one.
    let vault = fixture.home.path().join("keyed.kdbx");
    KeepassVault::open(PASSWORD, vault.to_str().unwrap(), None, None)
        .expect("the vault opens with the master password alone");
    let registry =
        std::fs::read_to_string(fixture.home.path().join(".passlane").join("vaults.json")).unwrap();
    assert!(!registry.contains("hwkey"), "{registry}");
}

#[test]
fn a_password_only_session_does_not_let_the_key_be_removed_unattended() {
    let fixture = Fixture::start();
    fixture.add_vault("keyed", true);
    fixture.create_unlock_session("keyed", false);

    let (output, _) = fixture.passlane(&["--vault", "keyed", "hwkey", "remove"]);
    let stderr = stderr_of(&output);
    assert!(!output.status.success());
    assert!(stderr.contains("hardware key"), "{stderr}");
    assert!(stderr.contains("from a terminal"), "{stderr}");
    // Nothing changed: the vault still requires the factor.
    let vault = fixture.home.path().join("keyed.kdbx");
    assert!(KeepassVault::open(PASSWORD, vault.to_str().unwrap(), None, None).is_err());
}

#[test]
fn an_agent_speaking_another_dialect_is_refused() {
    // An agent left running from an older binary would accept every
    // request and quietly drop the factors it does not know about.
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("old-agent.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    std::thread::spawn(move || {
        use passlane_agent::protocol::{Request, Response, decode, read_frame, write_frame};
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let Ok(frame) = read_frame(&mut stream) else {
            return;
        };
        assert!(matches!(decode::<Request>(&frame), Ok(Request::Ping)));
        let _ = write_frame(
            &mut stream,
            &Response::Pong {
                version: passlane_agent::protocol::PROTOCOL_VERSION - 1,
                max_session_secs: 900,
                sessions: 0,
            },
        );
    });

    let fixture = Fixture::start();
    fixture.add_vault("plain", false);
    let (output, _) = fixture.passlane_with_socket(
        &["--vault", "plain", "show", "--out", "github.com"],
        &socket,
    );
    assert!(!output.status.success());
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("Restart passlane-agent"),
        "says what to do about it: {stderr}"
    );
    assert_eq!(stdout_of(&output), "");
}

/// Manual verification against the real `passlane` and `passlane-agent`
/// binaries (the `passlane-cli-verify` skill). No CLI command enrolls a
/// secret-backed hardware key yet, so this stands in for `unlock
/// --session` where that command cannot run:
///
/// - `PASSLANE_VERIFY_VAULT_DIR` writes the hardware-key vault
///   `keyed.kdbx` (password [`PASSWORD`]) into that directory;
/// - `PASSLANE_VERIFY_SOCKET` and `PASSLANE_VERIFY_VAULT` open a timed
///   session holding the key factor for that vault on the agent listening
///   on that socket.
///
/// Ignored by default: `cargo test --test session_agent_unlock -- --ignored
/// verification_fixture`.
#[test]
#[ignore = "manual verification aid; needs PASSLANE_VERIFY_* to say where to write"]
fn verification_fixture() {
    let mut did = false;
    if let Some(dir) = std::env::var_os("PASSLANE_VERIFY_VAULT_DIR") {
        let path = Path::new(&dir).join("keyed.kdbx");
        let path = path.to_str().unwrap();
        let mut vault =
            KeepassVault::new(path, PASSWORD, None, Some(&local_challenge())).expect("vault");
        vault
            .save_one_credential(
                Credential::new(None, ENTRY_PASSWORD, "github.com", "alice", None, None)
                    .with_custom_attributes(&[("agent".to_string(), "allow".to_string())]),
            )
            .expect("seed");
        eprintln!("wrote {path}");
        did = true;
    }
    if let (Ok(socket), Ok(vault)) = (
        std::env::var("PASSLANE_VERIFY_SOCKET"),
        std::env::var("PASSLANE_VERIFY_VAULT"),
    ) {
        let mut client = AgentClient::connect(Path::new(&socket)).expect("the real agent");
        client.check_version().expect("it speaks this dialect");
        client
            .create_session(
                &vault,
                GrantSpec::Unlock {
                    master_password: SecretString::new(PASSWORD),
                    challenge_response: Some(ChallengeResponseMaterial::Secret {
                        secret_hex: SecretString::new(SLOT_SECRET),
                    }),
                },
                Scope::Timed { seconds: 900 },
            )
            .expect("create the session");
        eprintln!("opened a keyed session for '{vault}' on {socket}");
        did = true;
    }
    if !did {
        eprintln!("nothing to do: set PASSLANE_VERIFY_VAULT_DIR or PASSLANE_VERIFY_SOCKET");
    }
}
