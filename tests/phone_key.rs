//! Phone-held key, end to end (passlane#53): the real `passlane` binary,
//! the real `passlane-agent` on a scratch socket, and a mocked phone
//! standing in for the approval page that holds the vault's key.
//!
//! The mock is the page's logic, not a stub of the CLI's: it opens each
//! request envelope with the page's ECDH key, checks the CLI's signature,
//! and answers with a WebAuthn-signed `Allow` carrying the HMAC-SHA1 of
//! the challenge under the secret it holds — creating that secret (and
//! demanding the recovery sheet be scanned back) at enrollment. Every
//! secret stays inside the mock; the CLI only ever sees 20-byte answers.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use passlane_agent::client::AgentClient;
use passlane_agent::protocol::{GrantSpec, SecretString};
use passlane_agent::server::{AgentConfig, AgentServer};
use passlane_approval::envelope::Envelope;
use passlane_approval::keys::{IdentityKeys, PeerPin, PublicKey, WebauthnPin};
use passlane_approval::message::{Body, Decision, Operation, Scope, SecretHex};
use passlane_approval::policy::Policy;
use passlane_approval::replay::InMemoryNonceStore;
use passlane_approval::store::{save_identity, save_peers};
use passlane_core::vault::keepass_vault::KeepassVault;
use rand::RngCore;
use rand::rngs::OsRng;
use sha1::Sha1;
use zeroize::Zeroizing;

/// The mocked approver's WebAuthn coordinates.
const RP_ID: &str = "page.test";
const ORIGIN: &str = "https://page.test";
const MASTER_PW: &str = "wt53-master-pw";

fn now_secs() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0)
}

fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; 20] {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// A page that holds phone keys: one ECDH identity (matching the CLI's
/// pin of it), one passkey stand-in, and the secrets it has created.
struct MockPhone {
    page: IdentityKeys,
    passkey: p256::ecdsa::SigningKey,
    /// The CLI's pinned public keys, to open and answer its requests.
    cli_enc: PublicKey,
    cli_sig: PublicKey,
    /// Secrets it holds, by vault id — created at enrollment, after the
    /// recovery sheet was scanned back.
    keys: Mutex<HashMap<String, Zeroizing<Vec<u8>>>>,
    /// The recovery sheet exists in the world: the mock has "printed" it
    /// and the person has scanned it back on the device.
    sheet_scanned_back: AtomicBool,
    /// A denial to answer the next request with, once.
    deny_next: Mutex<Option<String>>,
    asked: Mutex<Vec<Operation>>,
}

impl MockPhone {
    fn new(cli: &IdentityKeys) -> Self {
        let page = IdentityKeys::generate(&mut OsRng).unwrap();
        let passkey = {
            let mut scalar = Zeroizing::new([0u8; 32]);
            loop {
                OsRng.fill_bytes(&mut scalar[..]);
                if let Ok(key) = p256::ecdsa::SigningKey::from_slice(scalar.as_slice()) {
                    break key;
                }
            }
        };
        Self {
            page,
            passkey,
            cli_enc: PublicKey(cli.encryption_public()),
            cli_sig: PublicKey::from_bytes(&cli.verifying_key().to_sec1_bytes()).unwrap(),
            keys: Mutex::new(HashMap::new()),
            sheet_scanned_back: AtomicBool::new(false),
            deny_next: Mutex::new(None),
            asked: Mutex::new(Vec::new()),
        }
    }

    /// The pin the CLI holds of this page.
    fn pin(&self) -> PeerPin {
        PeerPin {
            label: "approval-page".into(),
            enc_pub: passlane_approval::encoding::hex_encode(&self.page.encryption_public()),
            sig_pub: passlane_approval::encoding::hex_encode(
                &self.passkey.verifying_key().to_sec1_bytes(),
            ),
            paired_at: 0,
            webauthn: Some(WebauthnPin {
                rp_id: RP_ID.into(),
                origin: ORIGIN.into(),
            }),
        }
    }

    fn kid(&self) -> String {
        self.pin().enc_kid().unwrap()
    }

    /// The recovery sheet exists and was scanned back on the device.
    fn scan_back(&self) {
        self.sheet_scanned_back.store(true, Ordering::SeqCst);
    }

    /// The secret printed on a vault's recovery sheet — the only other
    /// copy of the key, which is what a lost phone is recovered with.
    fn sheet_secret(&self, vault: &str) -> Option<Vec<u8>> {
        self.keys
            .lock()
            .unwrap()
            .get(vault)
            .map(|secret| secret.to_vec())
    }

    /// Deny the next request with this reason.
    fn deny_next(&self, reason: &str) {
        *self.deny_next.lock().unwrap() = Some(reason.into());
    }

    fn asked(&self) -> Vec<Operation> {
        self.asked.lock().unwrap().clone()
    }

    /// Open the request in `link` as the page does, and produce the signed
    /// response blob to hand to `passlane approve --response`.
    fn approve_link(&self, link: &str) -> Result<String, String> {
        let fragment = link.split('#').nth(1).ok_or("the link has no fragment")?;
        let envelope = Envelope::from_base64url(fragment).map_err(|e| e.to_string())?;
        let cli_pin = PeerPin::new("cli", self.cli_enc, self.cli_sig, 0);
        let opened = passlane_approval::envelope::open(
            &self.page,
            std::slice::from_ref(&cli_pin),
            &envelope,
            now_secs(),
            &Policy::default(),
            &mut InMemoryNonceStore::default(),
        )
        .map_err(|e| format!("the page rejected the request: {e}"))?;
        let Body::ApprovalRequest {
            vault_id,
            operation,
            challenge,
            ..
        } = &*opened
        else {
            return Err("not an approval request".into());
        };
        self.asked.lock().unwrap().push(operation.clone());
        let challenge = challenge
            .as_ref()
            .and_then(|c| c.as_bytes().ok())
            .map(|b| b.to_vec())
            .ok_or("no challenge in the request")?;

        let decision = match self.deny_next.lock().unwrap().take() {
            Some(reason) => Decision::Deny {
                reason: Some(reason),
            },
            None => Decision::Allow,
        };
        let answer = match decision {
            Decision::Allow => {
                let secret = match operation {
                    Operation::EnrollKey => {
                        // The page creates the key — but only once its
                        // recovery sheet has been scanned back.
                        if !self.sheet_scanned_back.load(Ordering::SeqCst) {
                            return Err(
                                "the recovery sheet was not scanned back; no answer is sent".into(),
                            );
                        }
                        let mut secret = Zeroizing::new(vec![0u8; 20]);
                        OsRng.fill_bytes(&mut secret);
                        self.keys
                            .lock()
                            .unwrap()
                            .insert(vault_id.clone(), secret.clone());
                        secret
                    }
                    _ => self
                        .keys
                        .lock()
                        .unwrap()
                        .get(vault_id)
                        .cloned()
                        .ok_or_else(|| {
                            format!("this device holds no key for vault '{vault_id}'")
                        })?,
                };
                Some(hmac_sha1(&secret, &challenge))
            }
            Decision::Deny { .. } => None,
        };

        let (pending, webauthn_challenge) = passlane_approval::envelope::seal_webauthn(
            &mut OsRng,
            &self.page,
            &cli_pin,
            Body::ApprovalResponse {
                decision,
                scope: Scope::Once,
                response: answer.map(|a| SecretHex::from_bytes(&a)),
            },
            &envelope.header().rid,
            now_secs(),
            &Policy::default(),
        )
        .map_err(|e| e.to_string())?;

        // The passkey (a local ECDSA key stands in for the authenticator)
        // signs the assertion over the transcript challenge.
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        use sha2::{Digest, Sha256};
        let rp_hash = Sha256::digest(RP_ID.as_bytes());
        let mut auth_data = Vec::with_capacity(37);
        auth_data.extend_from_slice(&rp_hash);
        auth_data.push(0x01); // UP flag
        auth_data.extend_from_slice(&0u32.to_be_bytes());
        let client_data_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{webauthn_challenge}","origin":"{ORIGIN}"}}"#
        );
        let mut digest = Sha256::new();
        digest.update(&auth_data);
        digest.update(Sha256::digest(client_data_json.as_bytes()));
        let sig: p256::ecdsa::Signature = self.passkey.sign_prehash(&digest.finalize()).unwrap();
        let assertion = passlane_approval::webauthn::WebauthnAssertion::from_raw(
            &auth_data,
            client_data_json.as_bytes(),
            sig.to_der().as_bytes(),
        );
        Ok(
            passlane_approval::envelope::attach_webauthn_assertion(pending, assertion)
                .unwrap()
                .to_base64url(),
        )
    }
}

/// A running agent on a scratch socket, stopped on drop.
struct Agent {
    socket: PathBuf,
    handle: passlane_agent::server::ServerHandle,
    done: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl Agent {
    fn start(socket: &Path) -> Self {
        let config = AgentConfig::new(socket).with_sweep_interval(Duration::from_millis(50));
        let server = AgentServer::bind(config).expect("agent binds its socket");
        let handle = server.handle();
        let socket = socket.to_path_buf();
        let done = std::thread::Builder::new()
            .name("passlane-agent-under-test".into())
            .spawn(move || server.serve().expect("agent serves"))
            .unwrap();
        Self {
            socket,
            handle,
            done: Mutex::new(Some(done)),
        }
    }

    fn client(&self) -> AgentClient {
        AgentClient::connect(&self.socket).expect("the agent under test is running")
    }

    fn stop(&self) {
        self.handle.stop();
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.socket.exists() {
            assert!(
                Instant::now() < deadline,
                "the agent under test did not stop"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        if let Some(done) = self.done.lock().unwrap().take() {
            let _ = done.join();
        }
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        self.handle.stop();
        if let Some(done) = self.done.lock().unwrap().take() {
            let _ = done.join();
        }
    }
}

/// A scratch everything: home with one registered vault, approvals state
/// with a pinned mocked page, and a running session agent.
struct World {
    keeper: tempfile::TempDir,
    home: PathBuf,
    approvals: PathBuf,
    vault_name: String,
    vault_path: PathBuf,
    agent: Agent,
    #[allow(dead_code)]
    cli: IdentityKeys,
    phone: Arc<MockPhone>,
    vault_before_enrollment: Vec<u8>,
}

impl World {
    fn new() -> Self {
        let keeper = tempfile::tempdir().unwrap();
        let home = keeper.path().join("home");
        let passlane_dir = home.join(".passlane");
        std::fs::create_dir_all(&passlane_dir).unwrap();

        // One vault, registered and active. The name is unique to this
        // run so no real keychain entry can ever match it.
        let vault_name = format!("wt53work{}", std::process::id());
        let vault_path = keeper.path().join("work.kdbx");
        KeepassVault::new(vault_path.to_str().unwrap(), MASTER_PW, None, None).unwrap();
        let vault_before_enrollment = std::fs::read(&vault_path).unwrap();
        std::fs::write(
            passlane_dir.join("vaults.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "version": 1,
                "vaults": [{ "name": vault_name, "path": vault_path }]
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(passlane_dir.join(".active_vault"), &vault_name).unwrap();

        // The CLI's approval identity and its pin of the mocked page.
        let approvals = keeper.path().join("approvals");
        std::fs::create_dir_all(&approvals).unwrap();
        let cli = IdentityKeys::generate(&mut OsRng).unwrap();
        save_identity(&approvals, &cli).unwrap();
        let phone = Arc::new(MockPhone::new(&cli));
        save_peers(&approvals, std::slice::from_ref(&phone.pin())).unwrap();

        // The session agent, and an unlock session holding the master
        // password so no child ever prompts for it.
        let agent = Agent::start(&keeper.path().join("agent.sock"));
        agent
            .client()
            .create_session(
                &vault_name,
                GrantSpec::Unlock {
                    master_password: SecretString::new(MASTER_PW),
                    challenge_response: None,
                },
                Scope::Timed { seconds: 900 },
            )
            .unwrap();

        Self {
            keeper,
            home,
            approvals,
            vault_name,
            vault_path,
            agent,
            cli,
            phone,
            vault_before_enrollment,
        }
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_passlane"));
        command
            .args(args)
            .env("HOME", &self.home)
            .env("PASSLANE_APPROVALS_DIR", &self.approvals)
            .env(
                "PASSLANE_APPROVAL_LOG",
                self.approvals.join("approvals.log"),
            )
            .env("PASSLANE_AGENT_SOCK", self.agent.socket.to_str().unwrap())
            .env_remove("PASSLANE_VAULT");
        command
    }

    /// A run that is expected to finish on its own.
    fn run(&self, args: &[&str]) -> Output {
        self.command(args)
            .stdin(Stdio::null())
            .output()
            .expect("the passlane binary runs")
    }

    fn run_ok(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "`{}` failed: {}\n{}",
            args.join(" "),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).to_string()
    }

    /// A run that is expected to fail with guidance (a request emitted).
    fn run_refused(&self, args: &[&str]) -> (String, String) {
        let out = self.run(args);
        assert!(
            !out.status.success(),
            "`{}` unexpectedly succeeded: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stdout)
        );
        (
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    }

    /// A run whose output arrives while it waits for an approval.
    fn spawn(&self, args: &[&str]) -> Child {
        self.command(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the passlane binary starts")
    }

    fn registry(&self) -> serde_json::Value {
        serde_json::from_slice(
            &std::fs::read(self.home.join(".passlane").join("vaults.json")).unwrap(),
        )
        .unwrap()
    }

    fn phone_key(&self) -> Option<serde_json::Value> {
        match &self.registry()["vaults"][0]["phone_key"] {
            serde_json::Value::Null => None,
            value => Some(value.clone()),
        }
    }

    /// The owner approves a request from elsewhere: the phone answers the
    /// link, and `passlane approve --response` hands the answer over.
    fn approve(&self, link: &str) -> Output {
        let blob = self.phone.approve_link(link).expect("the phone answers");
        let path = self.keeper.path().join("response.b64");
        std::fs::write(&path, blob).unwrap();
        self.run(&["approve", "--response", &format!("@{}", path.display())])
    }

    fn approve_ok(&self, link: &str) -> String {
        let out = self.approve(link);
        assert!(
            out.status.success(),
            "approve failed: {}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).to_string()
    }

    /// The full enrollment: exit with the link, approve from elsewhere
    /// (after the recovery sheet is scanned back), re-run, approve the
    /// re-key. Leaves the vault phone-gated.
    fn enroll(&self) {
        let (stdout, stderr) = self.run_refused(&["hwkey", "add", "--phone"]);
        let link = first_link(&stdout).expect("the enrollment link is on stdout");
        assert!(stderr.contains("passlane approve --response"), "{stderr}");
        // Nothing has happened to the vault yet: no key exists, no factor
        // is recorded, the file is byte for byte as it was.
        assert_eq!(
            std::fs::read(&self.vault_path).unwrap(),
            self.vault_before_enrollment
        );
        assert!(self.phone_key().is_none());
        assert!(
            self.phone.sheet_secret(&self.vault_name).is_none(),
            "no key exists before the sheet is scanned back"
        );

        self.phone.scan_back();
        let approved = self.approve_ok(&link);
        assert!(
            approved.contains("enrolling a phone-held key"),
            "{approved}"
        );

        // The re-run answers the enrollment from the agent, then asks for
        // the re-key and waits for it.
        let mut child = self.spawn(&["hwkey", "add", "--phone"]);
        let mut reader = BufReader::new(child.stdout.take().unwrap());
        let save_link = read_until_link(&mut reader);
        assert!(save_link.contains("approve.html#"), "{save_link}");
        let approved = self.approve_ok(&save_link);
        assert!(
            approved.contains("saving vault"),
            "the re-key is a save approval: {approved}"
        );
        let rest = finish(child, reader);
        assert!(
            rest.status.success(),
            "enrollment did not finish: {}",
            String::from_utf8_lossy(&rest.stderr)
        );
        let out = String::from_utf8_lossy(&rest.stdout);
        assert!(out.contains("Phone-held key enrolled"), "{out}");
        assert!(out.contains("recovery sheet"), "{out}");

        let phone_key = self.phone_key().expect("the factor is recorded");
        assert_eq!(phone_key["holder_kid"], self.phone.kid());
        assert_ne!(
            std::fs::read(&self.vault_path).unwrap(),
            self.vault_before_enrollment,
            "the vault was re-keyed"
        );
    }
}

/// The page's real phone-key code (node WebCrypto standing in for the
/// browser's) answered a fixed challenge under a fixed secret; this test
/// opens that envelope with passlane-approval and recomputes the answer
/// independently. Both sides must agree on HMAC-SHA1(secret, challenge)
/// and on the envelope that carries it.
#[test]
fn page_phone_key_fixture_opens_and_answers_in_rust() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("page")
        .join("tests")
        .join("fixtures")
        .join("page-phone-key-v1.json");
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("fixture committed"))
            .expect("fixture is valid JSON");
    let recipient = {
        let r = &doc["recipient"];
        IdentityKeys::from_bytes(
            &passlane_approval::encoding::hex_decode(r["enc_secret"].as_str().unwrap()).unwrap(),
            &passlane_approval::encoding::hex_decode(r["sig_secret"].as_str().unwrap()).unwrap(),
        )
        .unwrap()
    };
    let pin: PeerPin = serde_json::from_value(doc["sender_pin"].clone()).unwrap();
    let envelope = Envelope::from_base64url(doc["envelope_base64url"].as_str().unwrap()).unwrap();
    let now = doc["now"].as_u64().unwrap();
    let secret =
        passlane_approval::encoding::hex_decode(doc["secret_hex"].as_str().unwrap()).unwrap();
    let challenge =
        passlane_approval::encoding::hex_decode(doc["challenge_hex"].as_str().unwrap()).unwrap();
    assert_eq!(envelope.header().rid, doc["rid"].as_str().unwrap());

    let body = passlane_approval::envelope::open(
        &recipient,
        std::slice::from_ref(&pin),
        &envelope,
        now,
        &Policy::default(),
        &mut InMemoryNonceStore::default(),
    )
    .expect("the page's phone-key envelope verifies");
    let Body::ApprovalResponse {
        decision: Decision::Allow,
        response,
        ..
    } = &*body
    else {
        panic!("expected an allowing response carrying an answer");
    };
    // The recomputation: the same HMAC-SHA1 keepass-ng's LocalChallenge
    // (and a YubiKey slot programmed with the sheet secret) computes.
    let answer = response.as_ref().unwrap().as_bytes().unwrap();
    assert_eq!(answer.as_slice(), hmac_sha1(&secret, &challenge));
    assert_eq!(answer.len(), 20);
}

/// The first `https://…/approve.html#…` in some output.
fn first_link(text: &str) -> Option<String> {
    text.lines()
        .flat_map(str::split_whitespace)
        .find(|word| word.contains("/approve.html#"))
        .map(str::to_string)
}

/// Read lines (blocking) until a request link is printed; the CLI prints
/// the link as soon as it needs the approval.
fn read_until_link(reader: &mut impl BufRead) -> String {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        assert!(Instant::now() < deadline, "no request link was printed");
        let mut line = String::new();
        let read = reader.read_line(&mut line).expect("the command's stdout");
        assert!(read > 0, "the command exited before asking for approval");
        if let Some(link) = first_link(&line) {
            return link;
        }
    }
}

/// Wait for a spawned child to finish, collecting what remained of its
/// output after the lines already read.
fn finish(mut child: Child, mut reader: impl BufRead) -> Output {
    let mut stdout = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let read = reader.read(&mut buffer).expect("the command's stdout");
        if read == 0 {
            break;
        }
        stdout.extend_from_slice(&buffer[..read]);
    }
    let mut stderr = Vec::new();
    if let Some(mut pipe) = child.stderr.take() {
        pipe.read_to_end(&mut stderr).unwrap();
    }
    let status = child.wait().expect("the command finishes");
    Output {
        status,
        stdout,
        stderr,
    }
}

#[test]
fn enrollment_rekeys_the_vault_through_two_remote_approvals() {
    let world = World::new();
    world.enroll();

    // The vault now needs the phone, and the sheet secret — which is all
    // that exists outside it — still opens it, exactly like a YubiKey
    // programmed from the sheet would.
    assert!(KeepassVault::open(MASTER_PW, world.vault_path.to_str().unwrap(), None, None).is_err());
    let sheet = world
        .phone
        .sheet_secret(&world.vault_name)
        .expect("the sheet exists");
    let as_a_yubikey_slot = keepass_ng::ChallengeResponseKey::LocalChallenge(
        passlane_approval::encoding::hex_encode(&sheet),
    );
    assert!(
        KeepassVault::open(
            MASTER_PW,
            world.vault_path.to_str().unwrap(),
            None,
            Some(&as_a_yubikey_slot)
        )
        .is_ok(),
        "the sheet secret opens the phone-enrolled vault"
    );

    // What the CLI asked of the phone: create the key, then the re-key.
    assert_eq!(world.phone.asked(), [Operation::EnrollKey, Operation::Save]);

    // The audit trail correlates both approvals.
    let log = std::fs::read_to_string(world.approvals.join("approvals.log")).unwrap();
    let events: Vec<serde_json::Value> = log
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(
        events
            .iter()
            .any(|e| e["field"] == "enroll_key" && e["event"] == "request")
    );
    assert!(
        events.iter().any(|e| e["field"] == "save"
            && e["event"] == "decision"
            && e["decision"] == "approved")
    );
}

#[test]
fn an_enrollment_without_the_scan_back_leaves_the_vault_unchanged() {
    let world = World::new();

    // The phone never answers an enrollment whose sheet was not scanned
    // back — and without an answer there is nothing to approve.
    let (stdout, _) = world.run_refused(&["hwkey", "add", "--phone"]);
    let link = first_link(&stdout).expect("the enrollment link is on stdout");
    let refusal = world.phone.approve_link(&link).unwrap_err();
    assert!(
        refusal.contains("the recovery sheet was not scanned back"),
        "{refusal}"
    );

    // The vault is untouched, no key exists, no factor is recorded.
    assert_eq!(
        std::fs::read(&world.vault_path).unwrap(),
        world.vault_before_enrollment
    );
    assert!(world.phone_key().is_none());
    assert!(world.phone.sheet_secret(&world.vault_name).is_none());

    // The request is still pending, waiting for an answer that will not
    // come; it expires on its own.
    let pending = world.run_ok(&["approvals", "pending"]);
    assert!(pending.contains("create a phone-held key"), "{pending}");
    assert!(pending.contains("awaiting the approver"), "{pending}");
}

#[test]
fn a_denied_enrollment_leaves_the_vault_unchanged() {
    let world = World::new();
    let (stdout, _) = world.run_refused(&["hwkey", "add", "--phone"]);
    let link = first_link(&stdout).unwrap();
    world.phone.scan_back();
    world.phone.deny_next("not this vault");
    let out = world.approve(&link);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("denied enrolling a phone-held key"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read(&world.vault_path).unwrap(),
        world.vault_before_enrollment
    );
    assert!(
        world.phone.sheet_secret(&world.vault_name).is_none(),
        "no key was created"
    );
}

#[test]
fn opening_without_a_terminal_is_approved_remotely_and_used_once() {
    let world = World::new();
    world.enroll();

    // No terminal, no keychain: the command emits the request and exits
    // with what to do instead.
    let (stdout, stderr) = world.run_refused(&["list"]);
    let link = first_link(&stdout).expect("the unlock link is on stdout");
    assert!(link.contains("/approve.html#"));
    assert!(stderr.contains("re-run this command"), "{stderr}");
    assert!(stderr.contains("phone-held key"), "{stderr}");

    // The owner approves from anywhere; the answer is kept in memory by
    // the session agent — nowhere else.
    let approved = world.approve_ok(&link);
    assert!(approved.contains("opening vault"), "{approved}");
    assert!(approved.contains("held in memory"), "{approved}");

    // The re-run opens the vault and lists (an empty vault).
    world.run_ok(&["list"]);

    // A single-use answer: presenting a fresh response for the same
    // request is refused — the request is already answered, and the
    // answer it produced was the one that opened the vault.
    let blob = world.phone.approve_link(&link).unwrap();
    let replay = world.run(&["approve", "--response", &blob]);
    assert!(!replay.status.success());
    assert!(
        String::from_utf8_lossy(&replay.stderr).contains("already approved"),
        "{}",
        String::from_utf8_lossy(&replay.stderr)
    );

    // And the next command asks again, by name of what it wants.
    let (stdout, _) = world.run_refused(&["list"]);
    assert!(first_link(&stdout).is_some());
}

#[test]
fn saving_without_a_terminal_waits_for_its_approval() {
    let world = World::new();
    world.enroll();

    // Importing one entry saves the vault: first the open has to be
    // approved, and the command exits to be re-run.
    let csv = world.keeper.path().join("import.csv");
    std::fs::write(&csv, "username,password,title\nuser,secret,Example Site\n").unwrap();
    let (stdout, _) = world.run_refused(&["csv", csv.to_str().unwrap()]);
    let unlock = first_link(&stdout).expect("the unlock link is on stdout");
    world.approve_ok(&unlock);

    // Re-run: the open is answered from the agent, the save emits its own
    // request and — needing an answer to a seed that only exists inside
    // the save — waits for it instead of exiting.
    let mut child = world.spawn(&["csv", csv.to_str().unwrap()]);
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let save = read_until_link(&mut reader);
    let approved = world.approve_ok(&save);
    assert!(approved.contains("saving vault"), "{approved}");
    assert!(
        approved.contains("The command that is saving continues now"),
        "{approved}"
    );

    let done = finish(child, reader);
    assert!(
        done.status.success(),
        "the save did not finish: {}",
        String::from_utf8_lossy(&done.stderr)
    );
    assert!(
        String::from_utf8_lossy(&done.stdout).contains("Imported 1 entries"),
        "{}",
        String::from_utf8_lossy(&done.stdout)
    );

    // The seed rotated with the save: reading it needs a fresh approval,
    // and the imported entry is there.
    let (stdout, _) = world.run_refused(&["list"]);
    let reopen = first_link(&stdout).expect("a fresh approval for the new seed");
    world.approve_ok(&reopen);
    let listed = world.run_ok(&["list"]);
    assert!(listed.contains("Example Site"), "{listed}");
}

#[test]
fn a_denied_save_waits_it_out_and_changes_nothing() {
    let world = World::new();
    world.enroll();

    let csv = world.keeper.path().join("import.csv");
    std::fs::write(&csv, "username,password,title\nuser,secret,Example Site\n").unwrap();
    let (stdout, _) = world.run_refused(&["csv", csv.to_str().unwrap()]);
    let unlock = first_link(&stdout).unwrap();
    world.approve_ok(&unlock);

    let before = std::fs::read(&world.vault_path).unwrap();
    let mut child = world.spawn(&["csv", csv.to_str().unwrap()]);
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let save = read_until_link(&mut reader);
    world.phone.deny_next("not now");
    let denied = world.approve(&save);
    assert!(!denied.status.success());

    // The waiting command sees the refusal and stops; the file is as it was.
    let done = finish(child, reader);
    assert!(!done.status.success(), "a denied save must not succeed");
    // The waiting command is told it was refused (the reason itself was
    // shown by the `approve --response` that recorded it).
    assert!(
        String::from_utf8_lossy(&done.stderr).contains("refused by the approver"),
        "{}",
        String::from_utf8_lossy(&done.stderr)
    );
    let denied_out = String::from_utf8_lossy(&denied.stderr);
    assert!(denied_out.contains("denied saving vault"), "{denied_out}");
    assert!(denied_out.contains("not now"), "{denied_out}");
    assert_eq!(std::fs::read(&world.vault_path).unwrap(), before);
}

#[test]
fn with_no_agent_to_keep_it_the_answer_is_refused_and_still_presentable() {
    let mut world = World::new();
    world.enroll();

    let (stdout, _) = world.run_refused(&["list"]);
    let link = first_link(&stdout).unwrap();

    // The agent goes away between the request and the approval: there is
    // nowhere to keep the answer, so `approve --response` refuses —
    // before recording anything, or the answer would be lost.
    world.agent.stop();
    let refused = world.approve(&link);
    assert!(!refused.status.success());
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(stderr.contains("nowhere to keep it"), "{stderr}");
    assert!(stderr.contains("'passlane-agent'"), "{stderr}");
    assert!(stderr.contains("present the response again"), "{stderr}");

    // Once it is back, the same response still works.
    world.agent = Agent::start(&world.keeper.path().join("agent.sock"));
    // The password session died with the old agent: hold it again, or the
    // next command would have nothing but a prompt.
    world
        .agent
        .client()
        .create_session(
            &world.vault_name,
            GrantSpec::Unlock {
                master_password: SecretString::new(MASTER_PW),
                challenge_response: None,
            },
            Scope::Timed { seconds: 900 },
        )
        .unwrap();
    let approved = world.approve_ok(&link);
    assert!(approved.contains("opening vault"), "{approved}");
    world.run_ok(&["list"]);
}

#[test]
fn lock_ends_the_held_answer_and_password() {
    let world = World::new();
    world.enroll();

    let (stdout, _) = world.run_refused(&["list"]);
    world.approve_ok(&first_link(&stdout).unwrap());

    // Locking the vault drops the agent's sessions for it: the held
    // answer and the stored password both go.
    let locked = world.run_ok(&["lock"]);
    assert!(
        locked.contains("revoked") || locked.contains("locked"),
        "{locked}"
    );

    // The password session died with the lock; hold it again so the next
    // command can run without a prompt — and it asks for a fresh
    // approval, because the held answer died too.
    world
        .agent
        .client()
        .create_session(
            &world.vault_name,
            GrantSpec::Unlock {
                master_password: SecretString::new(MASTER_PW),
                challenge_response: None,
            },
            Scope::Timed { seconds: 900 },
        )
        .unwrap();
    let (stdout, _) = world.run_refused(&["list"]);
    assert!(
        first_link(&stdout).is_some(),
        "a fresh approval is requested"
    );
}

#[test]
fn removing_the_phone_key_takes_two_approvals_and_none_after() {
    let world = World::new();
    world.enroll();

    // Open to remove: one approval for the open; the save that strips the
    // factor needs none.
    let (stdout, _) = world.run_refused(&["hwkey", "remove"]);
    let link = first_link(&stdout).expect("the unlock link is on stdout");
    world.approve_ok(&link);
    let removed = world.run_ok(&["hwkey", "remove"]);
    assert!(removed.contains("Second factor removed"), "{removed}");

    // The vault opens on the master password alone, from this process.
    assert!(KeepassVault::open(MASTER_PW, world.vault_path.to_str().unwrap(), None, None).is_ok());
    assert!(world.phone_key().is_none());

    // And the phone's key is no longer asked for anything.
    assert!(
        !world.registry()["vaults"][0]
            .to_string()
            .contains("phone_key")
    );
    let status = world.run_ok(&["hwkey", "status"]);
    assert!(status.contains("No phone-held key enrolled"), "{status}");
}

#[test]
fn status_and_vault_info_show_the_enrolled_holder() {
    let world = World::new();
    world.enroll();

    let status = world.run_ok(&["hwkey", "status"]);
    assert!(
        status.contains(&format!(
            "Phone-held key enrolled for vault '{}'",
            world.vault_name
        )),
        "{status}"
    );
    assert!(status.contains("held by 'approval-page'"), "{status}");

    let info = world.run_ok(&["vault", "info"]);
    assert!(info.contains("Phone key:"), "{info}");
    assert!(info.contains("held by 'approval-page'"), "{info}");

    let list = world.run_ok(&["vault", "list"]);
    assert!(list.contains("Phone key"), "{list}");

    // The pending store shows the phone-key requests by what they ask.
    let (stdout, _) = world.run_refused(&["list"]);
    let link = first_link(&stdout).unwrap();
    let pending = world.run_ok(&["approvals", "pending"]);
    assert!(pending.contains("open vault"), "{pending}");
    assert!(pending.contains("phone-held key"), "{pending}");

    // ...and the link can be shown again for relaying.
    let rid = Envelope::from_base64url(link.split('#').nth(1).unwrap())
        .unwrap()
        .header()
        .rid
        .clone();
    let again = world.run_ok(&["approvals", "link", &rid[..8]]);
    assert!(again.starts_with("https://"), "{again}");
    assert!(again.contains('#'), "{again}");

    // An unknown rid is an error, not a panic.
    let missing = world.run(&["approvals", "link", "ffffffff"]);
    assert!(!missing.status.success());
}

#[test]
fn a_second_enrollment_is_refused_and_paring_is_needed_without_a_pin() {
    let world = World::new();
    world.enroll();
    let out = world.run(&["hwkey", "add", "--phone"]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("A phone-held key is already enrolled"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        world.phone.asked().len(),
        2,
        "the phone is asked nothing new"
    );

    // A world with nothing pinned needs a terminal to pair, and says so.
    let bare = World::new();
    std::fs::remove_file(bare.approvals.join("approval_peers.json")).unwrap();
    let out = bare.run(&["hwkey", "add", "--phone"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("'passlane approvals enroll' at a terminal"),
        "{stderr}"
    );
}
