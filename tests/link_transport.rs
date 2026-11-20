//! Link-transport integration tests (passlane#51): the JS page side and
//! the Rust CLI side speak the same protocol.
//!
//! 1. The committed fixture `page/tests/fixtures/page-response-v1.json`
//!    was produced by the page's own JS (node WebCrypto standing in for
//!    the browser's, an ECDSA key for the passkey) via
//!    `page/tests/run.mjs --write-fixture`. Opening it here with
//!    passlane-approval — full WebAuthn assertion verification, HPKE
//!    open, replay store — proves the page composes DHKEM and the
//!    envelope framing exactly as SPEC §3 specifies.
//! 2. The rest drive the compiled `passlane` binary end-to-end over a
//!    scratch approvals directory: a pending request is emitted (the same
//!    way the ask flow emits it), a mocked page answers, and
//!    `passlane approve --response` verifies and releases it — exactly
//!    once.

use std::io::Write as _;
use std::path::Path;
use std::process::Command;

use passlane_approval::keys::{IdentityKeys, PeerPin, PublicKey, WebauthnPin};
use passlane_approval::message::{Body, Decision, Scope};
use passlane_approval::policy::Policy;
use passlane_approval::prelude::*;
use passlane_approval::replay::{FileNonceStore, InMemoryNonceStore};
use passlane_approval::store::{save_identity, save_peers};
use rand::rngs::OsRng;

/// The mocked approver's WebAuthn coordinates.
const RP_ID: &str = "page.test";
const ORIGIN: &str = "https://page.test";

fn fixture_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("page")
        .join("tests")
        .join("fixtures")
        .join("page-response-v1.json")
}

#[test]
fn page_fixture_opens_in_rust() {
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixture_path()).expect("fixture committed"))
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
    let envelope =
        Envelope::from_base64url(doc["envelope_base64url"].as_str().unwrap()).unwrap();
    let now = doc["now"].as_u64().unwrap();

    // The rid must be echoed (SPEC §4).
    assert_eq!(envelope.header().rid, doc["rid"].as_str().unwrap());
    assert_eq!(envelope.header().t, 4, "approval response");

    // Full verification: pinning, WebAuthn assertion (origin, RP hash, UP,
    // passkey signature over the transcript challenge), AEAD, freshness,
    // replay. This is everything `passlane approve --response` runs.
    let mut nonces = FileNonceStore::load(&std::env::temp_dir().join("unused-nonces.json"))
        .expect("scratch replay store");
    let body = passlane_approval::envelope::open(
        &recipient,
        std::slice::from_ref(&pin),
        &envelope,
        now,
        &Policy::default(),
        &mut nonces,
    )
    .expect("the page's envelope verifies");
    assert_eq!(
        serde_json::to_value(&*body).unwrap(),
        doc["expected_body"],
        "body must match what the page sealed"
    );
}

// -- the binary loop -----------------------------------------------------------

/// A scratch approvals directory holding a CLI identity, a pinned mocked
/// page, and the pending request its link transport emitted.
struct Scratch {
    dir: std::path::PathBuf,
    #[allow(dead_code)]
    keeper: tempfile::TempDir,
    cli: IdentityKeys,
    page: IdentityKeys,
    passkey: p256::ecdsa::SigningKey,
}

impl Scratch {
    fn new() -> Self {
        let keeper = tempfile::tempdir().unwrap();
        let dir = keeper.path().join("approvals");
        std::fs::create_dir_all(&dir).unwrap();
        let cli = IdentityKeys::generate(&mut OsRng).unwrap();
        let page = IdentityKeys::generate(&mut OsRng).unwrap();
        let passkey = {
            use rand::RngCore;
            let mut scalar = zeroize::Zeroizing::new([0u8; 32]);
            loop {
                OsRng.fill_bytes(&mut scalar[..]);
                if let Ok(k) = p256::ecdsa::SigningKey::from_slice(scalar.as_slice()) {
                    break k;
                }
            }
        };
        save_identity(&dir, &cli).unwrap();
        save_peers(&dir, std::slice::from_ref(&Self::page_pin(&page, &passkey))).unwrap();
        Self {
            dir,
            keeper,
            cli,
            page,
            passkey,
        }
    }

    fn page_pin(page: &IdentityKeys, passkey: &p256::ecdsa::SigningKey) -> PeerPin {
        PeerPin {
            label: "approval-page".into(),
            enc_pub: passlane_approval::encoding::hex_encode(&page.encryption_public()),
            sig_pub: passlane_approval::encoding::hex_encode(
                &passkey.verifying_key().to_sec1_bytes(),
            ),
            paired_at: 0,
            webauthn: Some(WebauthnPin {
                rp_id: RP_ID.into(),
                origin: ORIGIN.into(),
            }),
        }
    }

    /// Emit a request exactly the way the ask flow does (seal + pending
    /// record), returning its rid.
    fn emit_request(&self, entry: &str, field: &str) -> String {
        let now = passlane_time();
        let envelope = passlane_approval::envelope::seal(
            &mut OsRng,
            &self.cli,
            &Self::page_pin(&self.page, &self.passkey),
            Body::ApprovalRequest {
                vault_id: "default".into(),
                vault_name: "default".into(),
                operation: passlane_approval::message::Operation::Reveal {
                    entry: entry.into(),
                    field: field.into(),
                },
                requester: "link-transport-test".into(),
                scope: Scope::Once,
                challenge: None,
            },
            now,
            &Policy::default(),
        )
        .unwrap();
        let rid = envelope.header().rid.clone();
        let pending = serde_json::json!([{
            "rid": rid,
            "vault": "default",
            "entry_id": format!("uuid-{entry}"),
            "entry": entry,
            "field": field,
            "created": now,
            "exp": envelope.header().exp,
            "state": { "kind": "pending" },
        }]);
        std::fs::write(
            self.dir.join("approval_pending.json"),
            serde_json::to_vec(&pending).unwrap(),
        )
        .unwrap();
        rid
    }

    /// The mocked page's signed Allow response for `rid`.
    fn page_response(&self, rid: &str, decision: Decision) -> String {
        let cli_pin = PeerPin::new(
            "cli",
            PublicKey(self.cli.encryption_public()),
            PublicKey::from_bytes(&self.cli.verifying_key().to_sec1_bytes()).unwrap(),
            0,
        );
        let (pending, challenge) = passlane_approval::envelope::seal_webauthn(
            &mut OsRng,
            &self.page,
            &cli_pin,
            Body::ApprovalResponse {
                decision,
                scope: Scope::Once,
                response: None,
            },
            rid,
            passlane_time(),
            &Policy::default(),
        )
        .unwrap();

        // The passkey stand-in signs the transcript challenge.
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        use sha2::{Digest, Sha256};
        let rp_hash = Sha256::digest(RP_ID.as_bytes());
        let mut auth_data = Vec::with_capacity(37);
        auth_data.extend_from_slice(&rp_hash);
        auth_data.push(0x01); // UP
        auth_data.extend_from_slice(&0u32.to_be_bytes());
        let client_data_json =
            format!(r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"{ORIGIN}"}}"#);
        let mut digest = Sha256::new();
        digest.update(&auth_data);
        digest.update(Sha256::digest(client_data_json.as_bytes()));
        let sig: p256::ecdsa::Signature = self.passkey.sign_prehash(&digest.finalize()).unwrap();
        let assertion = WebauthnAssertion::from_raw(
            &auth_data,
            client_data_json.as_bytes(),
            sig.to_der().as_bytes(),
        );
        passlane_approval::envelope::attach_webauthn_assertion(pending, assertion)
            .unwrap()
            .to_base64url()
    }

    /// Run the compiled binary against this scratch state.
    fn run(&self, args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_passlane"))
            .args(args)
            .env("PASSLANE_APPROVALS_DIR", &self.dir)
            .env(
                "PASSLANE_APPROVAL_LOG",
                self.dir.join("approvals.log").to_string_lossy().as_ref(),
            )
            .output()
            .expect("the passlane binary runs")
    }
}

fn passlane_time() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0)
}

/// Write the blob to a file and hand `--response @file` over — the same
/// shape a script (or the session agent) uses.
fn response_file(dir: &Path, blob: &str) -> String {
    let path = dir.join("response.b64");
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(blob.as_bytes()).unwrap();
    format!("@{}", path.display())
}

#[test]
fn binary_approve_releases_and_replays_exactly_once() {
    let scratch = Scratch::new();
    let rid = scratch.emit_request("GitHub", "password");

    // The pinned approver is visible to the CLI.
    let list = scratch.run(&["approvals", "list"]);
    assert!(list.status.success());
    let stdout = String::from_utf8_lossy(&list.stdout);
    assert!(stdout.contains("approval-page"), "{stdout}");
    assert!(stdout.contains(RP_ID), "{stdout}");

    // The pending request is visible before the answer.
    let pending = scratch.run(&["approvals", "pending"]);
    assert!(pending.status.success());
    assert!(String::from_utf8_lossy(&pending.stdout).contains(&rid[..8]));

    // The page answers; the binary verifies and releases.
    let blob = scratch.page_response(&rid, Decision::Allow);
    let approve = scratch.run(&["approve", "--response", &response_file(&scratch.dir, &blob)]);
    assert!(
        approve.status.success(),
        "approve must succeed: {}",
        String::from_utf8_lossy(&approve.stderr)
    );
    let out = String::from_utf8_lossy(&approve.stdout);
    assert!(out.contains("Approved"), "{out}");
    assert!(out.contains("GitHub"), "{out}");

    // The grant is recorded as live (single-use, unconsumed).
    let pending = scratch.run(&["approvals", "pending"]);
    let out = String::from_utf8_lossy(&pending.stdout);
    assert!(out.contains("granted (single use, unconsumed)"), "{out}");

    // The decision landed in the approval log, correlated by rid.
    let log = std::fs::read_to_string(scratch.dir.join("approvals.log")).unwrap();
    let last = log.lines().last().unwrap();
    let event: serde_json::Value = serde_json::from_str(last).unwrap();
    assert_eq!(event["event"], "decision");
    assert_eq!(event["decision"], "approved");
    assert_eq!(event["id"].as_str().unwrap(), rid);

    // The same response pasted again: refused, exactly once.
    let replay = scratch.run(&["approve", "--response", &response_file(&scratch.dir, &blob)]);
    assert!(!replay.status.success(), "a replay must fail");
    assert!(
        String::from_utf8_lossy(&replay.stderr).contains("already approved"),
        "{}",
        String::from_utf8_lossy(&replay.stderr)
    );
}

#[test]
fn binary_approve_records_denial() {
    let scratch = Scratch::new();
    let rid = scratch.emit_request("prod-db", "password");

    let blob = scratch.page_response(
        &rid,
        Decision::Deny {
            reason: Some("not from this device".into()),
        },
    );
    let approve = scratch.run(&["approve", "--response", &response_file(&scratch.dir, &blob)]);
    assert!(!approve.status.success(), "a denial must exit non-zero");
    let stderr = String::from_utf8_lossy(&approve.stderr);
    assert!(stderr.contains("denied"), "{stderr}");
    assert!(stderr.contains("not from this device"), "{stderr}");

    // The entry was not released.
    let pending = scratch.run(&["approvals", "pending"]);
    assert!(String::from_utf8_lossy(&pending.stdout).contains("denied"));
}

#[test]
fn binary_approve_refuses_unknown_request() {
    let scratch = Scratch::new();
    // A perfectly valid response — for a rid nothing requested.
    let blob = scratch.page_response(&"f".repeat(32), Decision::Allow);
    let approve = scratch.run(&["approve", "--response", &blob]);
    assert!(!approve.status.success());
    assert!(String::from_utf8_lossy(&approve.stderr).contains("no pending approval request"));
}

#[test]
fn binary_approve_rejects_garbage() {
    let scratch = Scratch::new();
    for garbage in ["", "not-an-envelope", "!!!!", "UExBUA"] {
        let out = scratch.run(&["approve", "--response", garbage]);
        assert!(!out.status.success(), "garbage must be refused: {garbage:?}");
    }
}

#[test]
fn binary_approvals_remove_and_relist() {
    let scratch = Scratch::new();
    let rid = scratch.emit_request("GitHub", "password");

    // Removing an unknown label fails with guidance.
    let missing = scratch.run(&["approvals", "remove", "no-such-label"]);
    assert!(!missing.status.success());

    // Removing the pinned label works (positional arg id regression: this
    // used to panic on an argument-id mismatch) and leaves no approvers.
    let removed = scratch.run(&["approvals", "remove", "approval-page"]);
    assert!(
        removed.status.success(),
        "{}",
        String::from_utf8_lossy(&removed.stderr)
    );
    let list = scratch.run(&["approvals", "list"]);
    assert!(String::from_utf8_lossy(&list.stdout).contains("No approvers pinned"));

    // The pending request is untouched by pin bookkeeping.
    assert!(String::from_utf8_lossy(&scratch.run(&["approvals", "pending"]).stdout)
        .contains(&rid[..8]));
}

#[test]
fn binary_pending_survives_across_invocations() {
    // The replay store and pending store are files: separate processes see
    // the same state (the acceptance criterion "the CLI proceeds exactly
    // once" spans invocations).
    let scratch = Scratch::new();
    let rid = scratch.emit_request("GitHub", "password");
    let blob = scratch.page_response(&rid, Decision::Allow);

    // First invocation in "another shell": consumes the response.
    let first = scratch.run(&["approve", "--response", &response_file(&scratch.dir, &blob)]);
    assert!(first.status.success());
    // Second: the nonce store (file-backed) plus the pending state both
    // refuse, without needing in-process memory.
    let second = scratch.run(&["approve", "--response", &response_file(&scratch.dir, &blob)]);
    assert!(!second.status.success());
}

// Keep the InMemoryNonceStore import honest: it is the crate's own replay
// surface; the binary loop above uses the file-backed store the CLI ships.
#[test]
fn envelope_replay_is_rejected_by_the_file_store() {
    let scratch = Scratch::new();
    let rid = scratch.emit_request("GitHub", "password");
    let blob = scratch.page_response(&rid, Decision::Allow);
    let envelope = Envelope::from_base64url(&blob).unwrap();

    let path = scratch.dir.join(".approval_nonces");
    let peers = passlane_approval::store::load_peers(&scratch.dir).unwrap();
    {
        let mut nonces = FileNonceStore::load(&path).unwrap();
        passlane_approval::envelope::open(
            &scratch.cli,
            &peers,
            &envelope,
            passlane_time(),
            &Policy::default(),
            &mut nonces,
        )
        .unwrap();
        nonces.save().unwrap();
    }
    let mut nonces = FileNonceStore::load(&path).unwrap();
    let mut scratch_store = InMemoryNonceStore::default();
    let _ = &mut scratch_store;
    assert!(matches!(
        passlane_approval::envelope::open(
            &scratch.cli,
            &peers,
            &envelope,
            passlane_time(),
            &Policy::default(),
            &mut nonces
        ),
        Err(Error::Replay)
    ));
}
