//! Round-trips and rejection paths for the approval-protocol FFI surface
//! (passlane#82): the flows the iOS app drives — pair, open a request,
//! answer it — exercised at the Rust level through exactly the
//! FFI-visible functions.
//!
//! Each round-trip plays the two sides the way they really run: the
//! **phone** through this crate's exported surface, the **CLI** through
//! `passlane_approval` directly (the code `src/approvals` calls), so the
//! tests prove the app opens and answers exactly what the CLI seals —
//! real interop, not a self-test.

use std::sync::Arc;

use passlane_approval::keys::{IdentityKeys, PeerPin};
use passlane_approval::message::{Body, Decision, Operation, Scope, SecretHex};
use passlane_approval::pairing::{
    PairingSecret, open_pairing_response, seal_pairing_request,
};
use passlane_approval::policy::Policy;
use passlane_approval::replay::InMemoryNonceStore;
use passlane_approval::{encoding, envelope};
use passlane_ffi::approval::*;
use rand::rngs::OsRng;

const NOW: u64 = 1_760_000_000;
/// A 32-byte KDF seed, the shape `Unlock` requests carry.
const CHALLENGE: [u8; 32] = [0x5fu8; 32];

fn device(kind: &str, name: &str) -> ApprovalDeviceInfo {
    ApprovalDeviceInfo {
        kind: kind.to_string(),
        name: name.to_string(),
        version: "test".to_string(),
    }
}

/// The message of an error result, failing the test if there is none.
fn err_message<T>(result: Result<T, ApprovalError>) -> ApprovalError {
    match result {
        Ok(_) => panic!("expected an error"),
        Err(e) => e,
    }
}

/// One completed pairing ceremony, both sides as the real devices hold
/// them: the CLI's keys and its pin of the phone (protocol-crate types,
/// as `src/approvals` persists them), and the phone's FFI identity and
/// its pin of the CLI (FFI records, as the app persists them). The
/// request was sealed by the CLI, opened by the phone, answered, and the
/// response verified by the CLI — all through the real paths.
struct Paired {
    cli: IdentityKeys,
    /// The phone's pin of the CLI, as the FFI handed it to the app.
    cli_pin: ApprovalPeerPin,
    /// The app's identity, as the app holds it.
    phone: Arc<ApprovalIdentity>,
    /// The CLI's pin of the phone, as the CLI holds it.
    phone_pin: PeerPin,
    /// The pairing secret, for confirmation-code tests.
    secret: PairingSecret,
    /// Where the phone-side replay store lives (one file per ceremony).
    _dir: tempfile::TempDir,
    /// ... and its path.
    nonce_path: String,
}

impl Paired {
    /// A fresh phone-side replay store over the ceremony's file, as the
    /// app loads one per push/notification. Dropping the returned Arc
    /// releases the file's lock.
    fn phone_store(&self) -> Arc<ApprovalNonceStore> {
        Arc::new(ApprovalNonceStore::load(self.nonce_path.clone()).unwrap())
    }
}

fn paired(now: u64) -> Paired {
    let cli = IdentityKeys::generate(&mut OsRng).unwrap();
    let phone = Arc::new(ApprovalIdentity::generate().unwrap());
    let secret = PairingSecret::generate(&mut OsRng);
    let policy = approval_default_policy();
    let cli_policy = Policy::default();
    let dir = tempfile::tempdir().unwrap();
    let nonce_path = dir.path().join("nonces.json").to_str().unwrap().to_string();

    // CLI → phone: the pairing request, sealed the way the CLI seals it.
    let request = seal_pairing_request(
        &mut OsRng,
        &secret,
        &cli,
        passlane_approval::message::DeviceInfo {
            kind: "cli".into(),
            name: "mbp".into(),
            version: "test".into(),
        },
        now,
        &cli_policy,
    )
    .unwrap();

    // The phone opens it through the FFI (the app's path).
    let handshake = approval_open_pairing_request(
        secret.as_bytes().to_vec(),
        request.to_base64url(),
        now + 1,
        policy,
        Arc::new(ApprovalNonceStore::load(nonce_path.clone()).unwrap()),
    )
    .unwrap();
    assert_eq!(handshake.device.name, "mbp");

    // The phone answers through the FFI.
    let response = approval_seal_pairing_response(
        phone.clone(),
        secret.as_bytes().to_vec(),
        handshake.sender.clone(),
        request.to_base64url(),
        device("phone", "anssi-iphone"),
        now + 2,
        policy,
    )
    .unwrap();

    // The CLI verifies the response the way the CLI does.
    let response = envelope::Envelope::from_base64url(&response).unwrap();
    let (_body, phone_pin) = open_pairing_response(
        &cli,
        &secret,
        &response,
        now + 3,
        &cli_policy,
        &mut InMemoryNonceStore::default(),
    )
    .unwrap();
    assert_eq!(phone_pin.enc_pub, encoding::hex_encode(&phone.encryption_public()));

    Paired {
        cli,
        cli_pin: handshake.sender,
        phone,
        phone_pin,
        secret,
        _dir: dir,
        nonce_path,
    }
}

/// A sealed approval request from the CLI to the phone, in link form.
fn unlock_request(paired: &Paired, now: u64) -> String {
    let policy = Policy::default();
    let request = envelope::seal(
        &mut OsRng,
        &paired.cli,
        &paired.phone_pin,
        Body::ApprovalRequest {
            vault_id: "default".into(),
            vault_name: "Main".into(),
            operation: Operation::Unlock,
            requester: "anssi@mbp".into(),
            scope: Scope::Once,
            challenge: Some(SecretHex::from_bytes(&CHALLENGE)),
        },
        now,
        &policy,
    )
    .unwrap();
    request.to_base64url()
}

// -- round-trips -------------------------------------------------------------

#[test]
fn identity_round_trips_through_secret_bytes() {
    let identity = Arc::new(ApprovalIdentity::generate().unwrap());
    assert_eq!(identity.encryption_public().len(), 65);
    assert_eq!(identity.verifying_public().len(), 65);
    assert_eq!(identity.encryption_kid().len(), 16);
    assert_ne!(identity.encryption_kid(), identity.signing_kid());

    // What the app persists is what restores the identity.
    let enc = identity.secret_encryption_key();
    let sig = identity.secret_signing_key();
    assert_eq!(enc.as_bytes().len(), 32);
    assert_eq!(sig.as_bytes().len(), 32);
    let restored = Arc::new(
        ApprovalIdentity::from_secret_bytes(enc.as_bytes(), sig.as_bytes()).unwrap(),
    );
    assert_eq!(restored.encryption_kid(), identity.encryption_kid());
    assert_eq!(restored.signing_kid(), identity.signing_kid());
    assert_eq!(restored.encryption_public(), identity.encryption_public());
    assert_eq!(restored.verifying_public(), identity.verifying_public());

    // Bad key material is refused, not coerced.
    let short = err_message(
        ApprovalIdentity::from_secret_bytes(vec![0u8; 31], vec![0u8; 32]).map(|_| ()),
    );
    assert!(matches!(short, ApprovalError::Key { .. }), "{short:?}");
}

#[test]
fn a_pairing_round_trips_through_the_ffi() {
    let paired = paired(NOW);

    // The pins each side ends up holding are the other side's real keys.
    assert_eq!(paired.cli_pin.enc_pub, encoding::hex_encode(&paired.cli.encryption_public()));
    assert_eq!(
        paired.cli_pin.sig_pub,
        encoding::hex_encode(&paired.cli.verifying_key().to_sec1_bytes())
    );
    // And the pin's kid routes the way the protocol does.
    assert_eq!(
        approval_pin_enc_kid(paired.cli_pin.clone()).unwrap(),
        paired.cli.encryption_kid()
    );

    // The first human check: the confirmation code, bound to the CLI
    // identity being pinned — a substituted identity changes it.
    let code = approval_pairing_confirmation_code(
        paired.secret.as_bytes().to_vec(),
        paired.cli_pin.clone(),
    )
    .unwrap();
    assert_eq!(code.len(), 13, "formatted 123456-789012");
    let impostor = Arc::new(ApprovalIdentity::generate().unwrap());
    let impostor_pin = approval_new_pin(
        "impostor".into(),
        impostor.encryption_public(),
        impostor.verifying_public(),
        0,
    )
    .unwrap();
    assert_ne!(
        code,
        approval_pairing_confirmation_code(paired.secret.as_bytes().to_vec(), impostor_pin.clone())
            .unwrap()
    );

    // The mutual code binds both identities: the terminal's view (CLI
    // keys + response keys) equals the phone's view (CLI keys + its own
    // keys) for the genuine pairing.
    let phone_pin = approval_new_pin(
        "anssi-iphone".into(),
        paired.phone.encryption_public(),
        paired.phone.verifying_public(),
        0,
    )
    .unwrap();
    let mutual = approval_pairing_mutual_confirmation_code(
        paired.secret.as_bytes().to_vec(),
        paired.cli_pin.clone(),
        phone_pin,
    )
    .unwrap();
    assert_eq!(mutual.len(), 13);
    let mutual_impostor = approval_pairing_mutual_confirmation_code(
        paired.secret.as_bytes().to_vec(),
        paired.cli_pin.clone(),
        approval_new_pin(
            "evil".into(),
            impostor.encryption_public(),
            impostor.verifying_public(),
            0,
        )
        .unwrap(),
    )
    .unwrap();
    assert_ne!(mutual, mutual_impostor, "a substituted responder shows a different code");

    // The FFI's CLI-role halves are the same protocol: sealing a request
    // through the FFI opens through the crate.
    let policy = approval_default_policy();
    let (cli_enc, cli_sig) = paired.cli.secret_bytes();
    let cli_identity = Arc::new(
        ApprovalIdentity::from_secret_bytes(cli_enc.to_vec(), cli_sig.to_vec()).unwrap(),
    );
    let request = approval_seal_pairing_request(
        cli_identity,
        paired.secret.as_bytes().to_vec(),
        device("cli", "mbp"),
        NOW,
        policy,
    )
    .unwrap();
    let (_body, pin) = passlane_approval::pairing::open_pairing_request(
        &paired.secret,
        &envelope::Envelope::from_base64url(&request).unwrap(),
        NOW + 1,
        &Policy::default(),
        &mut InMemoryNonceStore::default(),
    )
    .unwrap();
    assert_eq!(pin.enc_kid().unwrap(), paired.cli.encryption_kid());

    // A wrong-length pairing secret is a clear caller error.
    let bad = err_message(
        approval_open_pairing_request(
            vec![0u8; 31],
            request.clone(),
            NOW + 1,
            policy,
            Arc::new(
                ApprovalNonceStore::load(
                    tempfile::tempdir()
                        .unwrap()
                        .path()
                        .join("n.json")
                        .to_str()
                        .unwrap()
                        .to_string(),
                )
                .unwrap(),
            ),
        )
        .map(|_| ()),
    );
    assert!(matches!(bad, ApprovalError::Pairing { .. }), "{bad:?}");
}

#[test]
fn a_request_opens_and_a_decision_round_trips() {
    let paired = paired(NOW);
    let policy = approval_default_policy();
    let link = unlock_request(&paired, NOW);

    // The app opens the link's envelope through the FFI.
    let opened = approval_open_request(
        paired.phone.clone(),
        vec![paired.cli_pin.clone()],
        link,
        NOW + 10,
        policy,
        paired.phone_store(),
    )
    .unwrap();
    let view = opened.view();
    assert_eq!(view.vault_id, "default");
    assert_eq!(view.vault_name, "Main");
    assert_eq!(view.operation, ApprovalOperation::Unlock);
    assert_eq!(view.requester, "anssi@mbp");
    assert_eq!(view.scope, ApprovalScope::Once);
    assert_eq!(view.sender_kid, paired.cli.encryption_kid());
    assert_eq!(view.sent_at, NOW);
    assert_eq!(view.expires_at, NOW + Policy::default().ttl_secs);
    assert!(!view.request_id.is_empty());

    // The request's challenge comes out as a zeroized secret.
    let challenge = opened.challenge().expect("Unlock carries a challenge");
    assert_eq!(challenge.as_bytes(), CHALLENGE.to_vec());

    // Face ID happened: the phone answers with the held secret.
    let secret = approval_generate_phone_key_secret();
    assert_eq!(secret.as_bytes().len(), 20);
    let answer = approval_answer_challenge(secret.as_bytes(), challenge.as_bytes()).unwrap();
    assert_eq!(answer.as_bytes().len(), 20);

    let response = approval_seal_decision(
        paired.phone.clone(),
        paired.cli_pin.clone(),
        ApprovalDecision::Allow,
        ApprovalScope::Once,
        Some(answer.clone()),
        view.request_id.clone(),
        NOW + 20,
        policy,
    )
    .unwrap();
    assert!(!response.contains('='));

    // The CLI redeems it the way the CLI does: open_reply against the
    // request's window.
    let response = envelope::Envelope::from_base64url(&response).unwrap();
    assert_eq!(response.header().rid, view.request_id);
    let mut store = InMemoryNonceStore::default();
    let body = envelope::open_reply(
        &paired.cli,
        std::slice::from_ref(&paired.phone_pin),
        &response,
        NOW,
        NOW + Policy::default().ttl_secs,
        NOW + 30,
        &Policy::default(),
        &mut store,
    )
    .unwrap();
    match &*body {
        Body::ApprovalResponse {
            decision,
            scope,
            response,
        } => {
            assert_eq!(*decision, Decision::Allow);
            assert_eq!(*scope, Scope::Once);
            // The answer is exactly HMAC-SHA1(secret, challenge) — the
            // agent-answer path end to end.
            assert_eq!(
                response.as_ref().unwrap().as_bytes().unwrap().as_slice(),
                passlane_approval::message::answer_challenge(&secret.as_bytes(), &CHALLENGE)
                    .unwrap()
                    .as_slice()
            );
        }
        other => panic!("expected an approval response, got {other:?}"),
    }
}

#[test]
fn a_denial_round_trips_with_its_reason() {
    let paired = paired(NOW);
    let policy = approval_default_policy();
    let link = unlock_request(&paired, NOW);
    let opened = approval_open_request(
        paired.phone.clone(),
        vec![paired.cli_pin.clone()],
        link,
        NOW + 10,
        policy,
        paired.phone_store(),
    )
    .unwrap();

    let response = approval_seal_decision(
        paired.phone.clone(),
        paired.cli_pin.clone(),
        ApprovalDecision::Deny {
            reason: Some("not now".to_string()),
        },
        ApprovalScope::Once,
        None,
        opened.view().request_id,
        NOW + 20,
        policy,
    )
    .unwrap();

    let response = envelope::Envelope::from_base64url(&response).unwrap();
    let body = envelope::open_reply(
        &paired.cli,
        std::slice::from_ref(&paired.phone_pin),
        &response,
        NOW,
        NOW + Policy::default().ttl_secs,
        NOW + 30,
        &Policy::default(),
        &mut InMemoryNonceStore::default(),
    )
    .unwrap();
    match &*body {
        Body::ApprovalResponse { decision, response, .. } => {
            assert_eq!(
                *decision,
                Decision::Deny {
                    reason: Some("not now".to_string())
                }
            );
            assert!(response.is_none(), "a denial carries no challenge answer");
        }
        other => panic!("expected an approval response, got {other:?}"),
    }
}

// -- rejection paths ---------------------------------------------------------

#[test]
fn a_request_from_an_unpinned_sender_is_rejected() {
    let paired = paired(NOW);
    let link = unlock_request(&paired, NOW);

    // No pins at all.
    let nobody = err_message(
        approval_open_request(
            paired.phone.clone(),
            vec![],
            link.clone(),
            NOW + 10,
            approval_default_policy(),
            paired.phone_store(),
        )
        .map(|_| ()),
    );
    assert!(
        matches!(nobody, ApprovalError::UnknownSender { .. }),
        "{nobody:?}"
    );

    // A pin of someone else.
    let stranger = Arc::new(ApprovalIdentity::generate().unwrap());
    let stranger_pin = approval_new_pin(
        "stranger".into(),
        stranger.encryption_public(),
        stranger.verifying_public(),
        0,
    )
    .unwrap();
    let wrong_pin = err_message(
        approval_open_request(
            paired.phone.clone(),
            vec![stranger_pin],
            link,
            NOW + 10,
            approval_default_policy(),
            paired.phone_store(),
        )
        .map(|_| ()),
    );
    assert!(
        matches!(wrong_pin, ApprovalError::UnknownSender { .. }),
        "{wrong_pin:?}"
    );
}

#[test]
fn a_replayed_request_is_rejected_even_after_restart() {
    let paired = paired(NOW);
    let link = unlock_request(&paired, NOW);

    // First open succeeds; the store persists the recorded nonce.
    approval_open_request(
        paired.phone.clone(),
        vec![paired.cli_pin.clone()],
        link.clone(),
        NOW + 10,
        approval_default_policy(),
        paired.phone_store(),
    )
    .unwrap();

    // The same blob again, in the same process.
    let replayed = err_message(
        approval_open_request(
            paired.phone.clone(),
            vec![paired.cli_pin.clone()],
            link.clone(),
            NOW + 10,
            approval_default_policy(),
            paired.phone_store(),
        )
        .map(|_| ()),
    );
    assert!(matches!(replayed, ApprovalError::Replay), "{replayed:?}");

    // And after a restart: a fresh store over the same file (the first
    // store was dropped with its Arc, so the lock is free).
    let replayed_after_restart = err_message(
        approval_open_request(
            paired.phone.clone(),
            vec![paired.cli_pin.clone()],
            link,
            NOW + 10,
            approval_default_policy(),
            paired.phone_store(),
        )
        .map(|_| ()),
    );
    assert!(
        matches!(replayed_after_restart, ApprovalError::Replay),
        "{replayed_after_restart:?}"
    );
}

#[test]
fn a_tampered_envelope_is_rejected() {
    let paired = paired(NOW);
    let link = unlock_request(&paired, NOW);
    let wire = encoding::base64url_decode(&link).unwrap();

    // Flip a byte in the signature block (the tail).
    let mut tampered = wire.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    let signature_flip = err_message(
        approval_open_request(
            paired.phone.clone(),
            vec![paired.cli_pin.clone()],
            encoding::base64url_encode(&tampered),
            NOW + 10,
            approval_default_policy(),
            paired.phone_store(),
        )
        .map(|_| ()),
    );
    assert!(
        matches!(signature_flip, ApprovalError::Signature | ApprovalError::Malformed { .. }),
        "{signature_flip:?}"
    );

    // Flip a byte inside the ciphertext: framing stays valid, the
    // signature over the transcript breaks.
    let header_len = u16::from_le_bytes([wire[7], wire[8]]) as usize;
    let request = envelope::Envelope::from_base64url(&link).unwrap();
    let ct_offset = 9 + header_len + 2 + request.enc.len() + 4 + 5;
    let mut tampered = wire;
    tampered[ct_offset] ^= 0x01;
    let ciphertext_flip = err_message(
        approval_open_request(
            paired.phone.clone(),
            vec![paired.cli_pin.clone()],
            encoding::base64url_encode(&tampered),
            NOW + 10,
            approval_default_policy(),
            paired.phone_store(),
        )
        .map(|_| ()),
    );
    assert!(
        matches!(ciphertext_flip, ApprovalError::Signature | ApprovalError::Malformed { .. }),
        "{ciphertext_flip:?}"
    );
}

#[test]
fn an_expired_request_is_rejected() {
    let paired = paired(NOW);
    let link = unlock_request(&paired, NOW);

    let expired = err_message(
        approval_open_request(
            paired.phone.clone(),
            vec![paired.cli_pin.clone()],
            link,
            NOW + Policy::default().ttl_secs,
            approval_default_policy(),
            paired.phone_store(),
        )
        .map(|_| ()),
    );
    assert!(matches!(expired, ApprovalError::Expired { .. }), "{expired:?}");
}

#[test]
fn a_wrong_pairing_secret_is_rejected() {
    let cli = IdentityKeys::generate(&mut OsRng).unwrap();
    let secret = PairingSecret::generate(&mut OsRng);
    let wrong = PairingSecret::generate(&mut OsRng);
    let policy = approval_default_policy();
    let request = seal_pairing_request(
        &mut OsRng,
        &secret,
        &cli,
        passlane_approval::message::DeviceInfo {
            kind: "cli".into(),
            name: "mbp".into(),
            version: "test".into(),
        },
        NOW,
        &Policy::default(),
    )
    .unwrap();

    let rejected = err_message(
        approval_open_pairing_request(
            wrong.as_bytes().to_vec(),
            request.to_base64url(),
            NOW + 1,
            policy,
            Arc::new(ApprovalNonceStore::load(
                tempfile::tempdir().unwrap().path().join("n.json").to_str().unwrap().to_string(),
            )
            .unwrap()),
        )
        .map(|_| ()),
    );
    // The PSK layer fails: decryption under the wrong secret.
    assert!(matches!(rejected, ApprovalError::Decrypt), "{rejected:?}");
}

#[test]
fn answer_challenge_rejects_wrong_lengths_and_matches_the_protocol() {
    let secret = approval_generate_phone_key_secret();

    // The FFI's answer is the protocol crate's answer.
    let answer = approval_answer_challenge(secret.as_bytes(), CHALLENGE.to_vec()).unwrap();
    assert_eq!(
        answer.as_bytes(),
        passlane_approval::message::answer_challenge(&secret.as_bytes(), &CHALLENGE)
            .unwrap()
            .to_vec()
    );

    // Shape violations are caller bugs, refused with the lengths named.
    let short_secret = err_message(
        approval_answer_challenge(vec![0u8; 19], CHALLENGE.to_vec()).map(|_| ()),
    );
    assert!(matches!(short_secret, ApprovalError::Malformed { .. }), "{short_secret:?}");
    let short_challenge = err_message(
        approval_answer_challenge(secret.as_bytes(), vec![0u8; 31]).map(|_| ()),
    );
    assert!(
        matches!(short_challenge, ApprovalError::Malformed { .. }),
        "{short_challenge:?}"
    );
}

// -- the enrollment helpers --------------------------------------------------

#[test]
fn webauthn_helpers_and_assertion_verification() {
    // The enrollment challenge is deterministic and bound to every input.
    let challenge = approval_enrollment_challenge(
        vec![0x0a; 16],
        vec![0x04; 65],
        vec![0x11; 65],
        vec![0x22; 65],
    );
    assert_eq!(
        challenge,
        approval_enrollment_challenge(vec![0x0a; 16], vec![0x04; 65], vec![0x11; 65], vec![0x22; 65])
    );
    assert_ne!(
        challenge,
        approval_enrollment_challenge(vec![0x0b; 16], vec![0x04; 65], vec![0x11; 65], vec![0x22; 65])
    );

    // The confirmation code: twelve digits in two groups, bound to all
    // four keys.
    let (a, b, c, d) = (vec![0x01u8; 65], vec![0x02u8; 65], vec![0x03u8; 65], vec![0x04u8; 65]);
    let code = approval_enrollment_confirmation_code(a.clone(), b.clone(), c.clone(), d.clone());
    assert_eq!(code.len(), 13);
    assert_eq!(code.as_bytes()[6], b'-');
    assert_ne!(code, approval_enrollment_confirmation_code(vec![0x09u8; 65], b, c, d));

    // A real assertion verifies; a wrong challenge or key does not.
    const RP_ID: &str = "approve.passlane.test";
    const ORIGIN: &str = "https://approve.passlane.test";
    let (passkey, assertion) = make_passkey_assertion(RP_ID, ORIGIN);
    approval_verify_webauthn_assertion(
        passkey.verifying_key().to_sec1_bytes().to_vec(),
        RP_ID.to_string(),
        ORIGIN.to_string(),
        assertion.authenticator_data.clone(),
        assertion.client_data_json.clone(),
        assertion.signature_der.clone(),
        assertion.challenge.clone(),
    )
    .unwrap();

    let wrong_challenge = err_message(
        approval_verify_webauthn_assertion(
            passkey.verifying_key().to_sec1_bytes().to_vec(),
            RP_ID.to_string(),
            ORIGIN.to_string(),
            assertion.authenticator_data,
            assertion.client_data_json,
            assertion.signature_der,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        )
        .map(|_| ()),
    );
    assert!(
        matches!(wrong_challenge, ApprovalError::Webauthn { .. }),
        "{wrong_challenge:?}"
    );
}

/// A passkey plus the assertion it makes over a challenge derived from
/// the transcript — built the way the page's WebCrypto would (and
/// passlane-approval's own tests do).
struct MockAssertion {
    challenge: String,
    authenticator_data: Vec<u8>,
    client_data_json: Vec<u8>,
    signature_der: Vec<u8>,
}

fn make_passkey_assertion(rp_id: &str, origin: &str) -> (p256::ecdsa::SigningKey, MockAssertion) {
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use sha2::{Digest, Sha256};

    // A random scalar (rejection-sampled the way the protocol crate does
    // — p256's own rand traits live on another rand_core version).
    let mut scratch = [0u8; 32];
    let secret = loop {
        use rand::RngCore;
        OsRng.fill_bytes(&mut scratch);
        if let Ok(key) = p256::SecretKey::from_slice(&scratch) {
            break key;
        }
    };
    let passkey = p256::ecdsa::SigningKey::from(&secret);

    let challenge = "c-freejOBBZtFkVCmM4soo0nOsrjvaPsdGM9fDpyKcNs".to_string();
    let rp_hash = Sha256::digest(rp_id.as_bytes());
    let mut auth_data = Vec::with_capacity(37);
    auth_data.extend_from_slice(&rp_hash);
    auth_data.push(0x01); // user-present flag
    auth_data.extend_from_slice(&0u32.to_be_bytes());
    let client_data_json = format!(
        r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"{origin}"}}"#
    );
    let mut digest = Sha256::new();
    digest.update(&auth_data);
    digest.update(Sha256::digest(client_data_json.as_bytes()));
    let sig: p256::ecdsa::Signature = passkey.sign_prehash(&digest.finalize()).unwrap();
    (
        passkey,
        MockAssertion {
            challenge,
            authenticator_data: auth_data,
            client_data_json: client_data_json.into_bytes(),
            signature_der: sig.to_der().as_bytes().to_vec(),
        },
    )
}

// -- the scaffolding ---------------------------------------------------------

#[test]
fn the_scaffolding_exports_the_documented_ffi_symbols() {
    // The UniFFI scaffolding exists under the documented symbol names —
    // the same cheap roundtrip check the vault surface makes, proving
    // the proc-macro setup generated the externs for the approval
    // surface without linking a foreign language here. The approval
    // surface's symbols live under the `approval` module (the vault
    // surface's are at the crate root).
    use passlane_ffi::approval::{
        uniffi_passlane_ffi_fn_constructor_approvalidentity_generate,
        uniffi_passlane_ffi_fn_constructor_approvalnoncestore_load,
        uniffi_passlane_ffi_fn_func_approval_answer_challenge,
        uniffi_passlane_ffi_fn_func_approval_generate_phone_key_secret,
        uniffi_passlane_ffi_fn_func_approval_open_request,
        uniffi_passlane_ffi_fn_func_approval_seal_decision,
        uniffi_passlane_ffi_fn_func_approval_seal_pairing_request,
        uniffi_passlane_ffi_fn_method_approvalnoncestore_prune,
        uniffi_passlane_ffi_fn_method_openedapprovalrequest_challenge,
    };
    let symbols = [
        uniffi_passlane_ffi_fn_func_approval_open_request as *const (),
        uniffi_passlane_ffi_fn_func_approval_seal_decision as *const (),
        uniffi_passlane_ffi_fn_func_approval_answer_challenge as *const (),
        uniffi_passlane_ffi_fn_func_approval_generate_phone_key_secret as *const (),
        uniffi_passlane_ffi_fn_func_approval_seal_pairing_request as *const (),
        uniffi_passlane_ffi_fn_constructor_approvalidentity_generate as *const (),
        uniffi_passlane_ffi_fn_constructor_approvalnoncestore_load as *const (),
        uniffi_passlane_ffi_fn_method_openedapprovalrequest_challenge as *const (),
        uniffi_passlane_ffi_fn_method_approvalnoncestore_prune as *const (),
    ];
    assert!(symbols.iter().all(|s| !s.is_null()));
}
