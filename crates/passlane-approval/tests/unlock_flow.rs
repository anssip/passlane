//! End-to-end protocol flow: the exact sequence the v1 wedge will run,
//! including the KeePass-compatible HMAC-SHA1 challenge/response that the
//! phone-held key exists to answer (passlane#49, passlane#53).
//!
//! The phone side computes the response exactly like keepass-ng's
//! `LocalChallenge` factor would — HMAC-SHA1 over the vault's challenge —
//! proving the protocol carries the factor without knowing anything about
//! kdbx.

use passlane_approval::prelude::*;
use passlane_approval::replay::{FileNonceStore, InMemoryNonceStore};
use rand::rngs::OsRng;

fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; 20] {
    // The crate itself never computes this (the approver does, with the
    // held secret); the test uses the same HMAC-SHA1 construction
    // keepass-ng's LocalChallenge and CryptoKit's
    // HMAC<Insecure.SHA1> implement.
    use hmac::{Hmac, Mac};
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(key).expect("any key length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

#[test]
fn phone_held_key_unlock_flow() {
    let mut rng = OsRng;
    let policy = Policy::default();
    let now = 1_760_000_000;

    // -- pairing (once) --
    let cli = IdentityKeys::generate(&mut rng).unwrap();
    let phone = IdentityKeys::generate(&mut rng).unwrap();
    let secret = PairingSecret::generate(&mut rng);
    let code = secret.confirmation_code();
    assert_eq!(code.len(), 7, "formatted as 123-456");

    let request = seal_pairing_request(
        &mut rng,
        &secret,
        &cli,
        DeviceInfo {
            kind: "cli".into(),
            name: "macbook-pro".into(),
            version: "test".into(),
        },
        now,
        &policy,
    )
    .unwrap();
    let mut store = InMemoryNonceStore::default();
    let (_body, cli_pin) =
        open_pairing_request(&secret, &request, now + 1, &policy, &mut store).unwrap();

    let response = seal_pairing_response(
        &mut rng,
        &phone,
        &cli_pin.clone(),
        DeviceInfo {
            kind: "phone".into(),
            name: "anssi-iphone".into(),
            version: "test".into(),
        },
        now,
        &policy,
    )
    .unwrap();
    let (_body, phone_pin) =
        open_pairing_response(&cli, &response, now + 1, &policy, &mut store).unwrap();

    // -- unlock request (every vault open) --
    // keepass-ng derives a per-vault challenge when a challenge-response
    // factor is enrolled; the CLI sends it, the phone answers it.
    let vault_challenge = [0x5fu8; 20];
    let request = seal(
        &mut rng,
        &cli,
        &phone_pin,
        Body::ApprovalRequest {
            vault_id: "default".into(),
            vault_name: "Main".into(),
            operation: Operation::Unlock,
            requester: "anssi@macbook-pro".into(),
            scope: Scope::Once,
            challenge: Some(SecretHex::from_bytes(&vault_challenge)),
        },
        now,
        &policy,
    )
    .unwrap();

    // The envelope is link-safe: base64url, no padding, bounded size.
    let link = request.to_base64url();
    assert!(!link.contains(['=', '+', '/']));
    assert!(
        link.len() < 1500,
        "fits a QR code comfortably: {}",
        link.len()
    );

    // -- the phone approves (Face ID stands in for the test's judgment) --
    let opened = open(
        &phone,
        std::slice::from_ref(&cli_pin),
        &request,
        now + 10,
        &policy,
        &mut store,
    )
    .unwrap();
    let Body::ApprovalRequest {
        challenge,
        operation,
        ..
    } = &*opened
    else {
        panic!("expected approval request");
    };
    assert_eq!(*operation, Operation::Unlock);
    let challenge = challenge.as_ref().unwrap().as_bytes().unwrap();
    assert_eq!(challenge, vault_challenge.to_vec());

    // The phone computes the HMAC-SHA1 response with the held secret and
    // answers (encrypted to the CLI's pinned key).
    let held_secret = [0xa1u8; 20]; // lives only on the phone
    let response = hmac_sha1(&held_secret, &challenge);
    let answer = seal(
        &mut rng,
        &phone,
        &cli_pin.clone(),
        Body::ApprovalResponse {
            decision: Decision::Allow,
            scope: Scope::Timed { seconds: 300 },
            response: Some(SecretHex::from_bytes(&response)),
        },
        now + 10,
        &policy,
    )
    .unwrap();

    // -- the CLI verifies the answer --
    let answer_body = open(&cli, &[phone_pin], &answer, now + 20, &policy, &mut store).unwrap();
    let Body::ApprovalResponse {
        decision,
        response: got,
        ..
    } = &*answer_body
    else {
        panic!("expected approval response");
    };
    assert_eq!(*decision, Decision::Allow);
    assert_eq!(got.as_ref().unwrap().as_bytes().unwrap(), response.to_vec());
}

#[test]
fn file_backed_replay_across_instances() {
    let mut rng = OsRng;
    let policy = Policy::default();
    let now = 1_760_000_000;

    let cli = IdentityKeys::generate(&mut rng).unwrap();
    let phone = IdentityKeys::generate(&mut rng).unwrap();
    let phone_pin = PeerPin::new(
        "phone",
        PublicKey(phone.encryption_public()),
        PublicKey::from_bytes(&phone.verifying_key().to_sec1_bytes()).unwrap(),
        0,
    );
    let cli_pin = PeerPin::new(
        "cli",
        PublicKey(cli.encryption_public()),
        PublicKey::from_bytes(&cli.verifying_key().to_sec1_bytes()).unwrap(),
        0,
    );

    let env = seal(
        &mut rng,
        &cli,
        &phone_pin,
        Body::ApprovalRequest {
            vault_id: "v".into(),
            vault_name: "Main".into(),
            operation: Operation::Reveal {
                entry: "GitHub".into(),
                field: "password".into(),
            },
            requester: "test".into(),
            scope: Scope::Once,
            challenge: None,
        },
        now,
        &policy,
    )
    .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nonces.json");

    {
        let mut store = FileNonceStore::load(&path).unwrap();
        assert!(
            open(
                &phone,
                std::slice::from_ref(&cli_pin),
                &env,
                now + 1,
                &policy,
                &mut store
            )
            .is_ok()
        );
        store.save().unwrap();
    }
    // A second CLI process (fresh store) sees the replay.
    let mut store2 = FileNonceStore::load(&path).unwrap();
    assert!(matches!(
        open(&phone, &[cli_pin], &env, now + 2, &policy, &mut store2),
        Err(Error::Replay)
    ));
}

#[test]
fn agent_ask_flow_shapes() {
    // The `ask` flow (passlane#50) consumes this crate's message shapes:
    // an agent-triggered reveal produces an approval request whose
    // requester identifies the agent context, and a denial carries a reason.
    let mut rng = OsRng;
    let policy = Policy::default();
    let now = 1_760_000_000;

    let cli = IdentityKeys::generate(&mut rng).unwrap();
    let phone = IdentityKeys::generate(&mut rng).unwrap();
    let phone_pin = PeerPin::new(
        "phone",
        PublicKey(phone.encryption_public()),
        PublicKey::from_bytes(&phone.verifying_key().to_sec1_bytes()).unwrap(),
        0,
    );
    let cli_pin = PeerPin::new(
        "cli",
        PublicKey(cli.encryption_public()),
        PublicKey::from_bytes(&cli.verifying_key().to_sec1_bytes()).unwrap(),
        0,
    );

    let request = seal(
        &mut rng,
        &cli,
        &phone_pin,
        Body::ApprovalRequest {
            vault_id: "default".into(),
            vault_name: "Main".into(),
            operation: Operation::Reveal {
                entry: "prod-db".into(),
                field: "password".into(),
            },
            requester: "claude-agent (deploy task)".into(),
            scope: Scope::Once,
            challenge: None,
        },
        now,
        &policy,
    )
    .unwrap();
    let mut store = InMemoryNonceStore::default();
    let body = open(
        &phone,
        std::slice::from_ref(&cli_pin),
        &request,
        now + 1,
        &policy,
        &mut store,
    )
    .unwrap();
    let Body::ApprovalRequest {
        requester,
        operation,
        ..
    } = &*body
    else {
        panic!()
    };
    assert!(requester.contains("agent"));
    assert!(matches!(operation, Operation::Reveal { .. }));

    let deny = seal(
        &mut rng,
        &phone,
        &cli_pin,
        Body::ApprovalResponse {
            decision: Decision::Deny {
                reason: Some("not while I'm afk".into()),
            },
            scope: Scope::Once,
            response: None,
        },
        now + 1,
        &policy,
    )
    .unwrap();
    let body = open(&cli, &[phone_pin], &deny, now + 2, &policy, &mut store).unwrap();
    let Body::ApprovalResponse { decision, .. } = &*body else {
        panic!()
    };
    assert!(matches!(decision, Decision::Deny { .. }));
}
