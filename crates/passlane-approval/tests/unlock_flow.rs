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
    // The code is bound to the CLI identity the QR introduces.
    let cli_enc = passlane_approval::encoding::hex_encode(&cli.encryption_public());
    let cli_sig = passlane_approval::encoding::hex_encode(&cli.verifying_key().to_sec1_bytes());
    let code = secret.confirmation_code(&cli_enc, &cli_sig);
    assert_eq!(code.len(), 13, "formatted as 123456-789012");
    // A substituted identity must produce a different code (QR-swap defense).
    let impostor = IdentityKeys::generate(&mut rng).unwrap();
    let imp_enc = passlane_approval::encoding::hex_encode(&impostor.encryption_public());
    let imp_sig =
        passlane_approval::encoding::hex_encode(&impostor.verifying_key().to_sec1_bytes());
    assert_ne!(code, secret.confirmation_code(&imp_enc, &imp_sig));

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
        &secret,
        &phone,
        &cli_pin.clone(),
        &request,
        DeviceInfo {
            kind: "phone".into(),
            name: "anssi-iphone".into(),
            version: "test".into(),
        },
        now,
        &policy,
    )
    .unwrap();
    // The response answers the request: rid echo (SPEC §4).
    assert_eq!(response.header().rid, request.header().rid);
    let (_body, phone_pin) =
        open_pairing_response(&cli, &secret, &response, now + 1, &policy, &mut store).unwrap();

    // -- unlock request (every vault open) --
    // keepass-ng derives a per-vault challenge when a challenge-response
    // factor is enrolled; the CLI sends it, the phone answers it.
    let vault_challenge = [0x5fu8; 32];
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
    assert_eq!(challenge.as_slice(), vault_challenge.as_slice());

    // The phone computes the HMAC-SHA1 response with the held secret and
    // answers (encrypted to the CLI's pinned key), echoing the request id.
    let held_secret = [0xa1u8; 20]; // lives only on the phone
    let response = hmac_sha1(&held_secret, &challenge);
    let request_rid = request.header().rid.clone();
    let answer = seal_reply(
        &mut rng,
        &phone,
        &cli_pin.clone(),
        Body::ApprovalResponse {
            decision: Decision::Allow,
            scope: Scope::Timed { seconds: 300 },
            response: Some(SecretHex::from_bytes(&response)),
        },
        &request_rid,
        now + 10,
        &policy,
    )
    .unwrap();
    assert_eq!(answer.header().rid, request_rid);

    // -- the CLI verifies the answer (rid match first, per SPEC §4) --
    assert_eq!(answer.header().rid, request.header().rid);
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
    assert_eq!(
        got.as_ref().unwrap().as_bytes().unwrap().as_slice(),
        response.as_slice()
    );
}

#[test]
fn phone_held_key_enrollment_flow() {
    // Enrollment (SPEC §7, passlane#53) in the order the issue requires:
    // the holder creates the key, answers the EnrollKey request only once
    // the recovery sheet is scanned back, and the CLI does not re-key the
    // vault before that answer arrives. Re-keying and every later open are
    // then ordinary challenge rounds against the one held secret.
    let mut rng = OsRng;
    let policy = Policy::default();
    let now = 1_760_000_000;
    let cli = IdentityKeys::generate(&mut rng).unwrap();
    let phone = IdentityKeys::generate(&mut rng).unwrap();
    let cli_pin = PeerPin::new(
        "cli",
        PublicKey(cli.encryption_public()),
        PublicKey::from_bytes(&cli.verifying_key().to_sec1_bytes()).unwrap(),
        now,
    );
    let phone_pin = PeerPin::new(
        "phone",
        PublicKey(phone.encryption_public()),
        PublicKey::from_bytes(&phone.verifying_key().to_sec1_bytes()).unwrap(),
        now,
    );
    let mut store = InMemoryNonceStore::default();

    // One round trip: the CLI asks, the holder answers from `secret`.
    let mut round_trip = |sent: Operation, challenge: &[u8; 32], secret: &[u8]| {
        let request = seal(
            &mut rng,
            &cli,
            &phone_pin,
            Body::ApprovalRequest {
                vault_id: "work".into(),
                vault_name: "work".into(),
                operation: sent.clone(),
                requester: "anssi@macbook-pro".into(),
                scope: Scope::Once,
                challenge: Some(SecretHex::from_bytes(challenge)),
            },
            now,
            &policy,
        )
        .unwrap();
        let opened = open(
            &phone,
            std::slice::from_ref(&cli_pin),
            &request,
            now + 1,
            &policy,
            &mut store,
        )
        .unwrap();
        let Body::ApprovalRequest {
            operation,
            challenge: got,
            ..
        } = &*opened
        else {
            panic!("expected approval request");
        };
        // The holder sees exactly the operation and challenge the CLI sent.
        assert_eq!(operation, &sent);
        assert_eq!(
            got.as_ref().unwrap().as_bytes().unwrap().as_slice(),
            challenge
        );
        let answer = seal_reply(
            &mut rng,
            &phone,
            &cli_pin,
            Body::ApprovalResponse {
                decision: Decision::Allow,
                scope: Scope::Once,
                response: Some(SecretHex::from_bytes(&hmac_sha1(
                    secret,
                    got.as_ref().unwrap().as_bytes().unwrap().as_slice(),
                ))),
            },
            &request.header().rid,
            now + 1,
            &policy,
        )
        .unwrap();
        let body = open(
            &cli,
            std::slice::from_ref(&phone_pin),
            &answer,
            now + 2,
            &policy,
            &mut store,
        )
        .unwrap();
        let Body::ApprovalResponse { response, .. } = &*body else {
            panic!("expected approval response");
        };
        response.as_ref().unwrap().as_bytes().unwrap().to_vec()
    };

    // -- enrollment: create the key, scan the sheet back, then answer --
    let proof_challenge = [0x11u8; 32];
    let held_secret = [0xa1u8; 20];
    let proof = round_trip(Operation::EnrollKey, &proof_challenge, &held_secret);
    assert_eq!(proof, hmac_sha1(&held_secret, &proof_challenge).to_vec());

    // -- re-key: the response to the new KDF seed --
    let new_seed = [0x22u8; 32];
    let save_response = round_trip(Operation::Save, &new_seed, &held_secret);
    // -- and the open that follows answers the same seed identically --
    let unlock_response = round_trip(Operation::Unlock, &new_seed, &held_secret);
    assert_eq!(save_response, unlock_response);
    assert_eq!(save_response, hmac_sha1(&held_secret, &new_seed).to_vec());

    // A holder with a different secret (or the wrong sheet) answers
    // differently: the vault would not open.
    let wrong_sheet = round_trip(Operation::Unlock, &new_seed, &[0xa2u8; 20]);
    assert_ne!(wrong_sheet, unlock_response);
}

/// The passlane#73 scenario, end to end at the protocol level: an
/// approval decided inside the request window but redeemed after the
/// relay round trip (link → phone → passkey → copy → paste) is honored,
/// across realistic device clock skew, exactly once, and only inside the
/// total-lifetime bound. Reported as #61 finding 1 and again during the
/// first phone-held-key enrollment (2026-11-24, 20–40 s skew observed).
#[test]
fn late_redemption_of_an_in_time_approval() {
    let mut rng = OsRng;
    let policy = Policy::default();
    let skew = policy.max_clock_skew_secs;

    let cli = IdentityKeys::generate(&mut rng).unwrap();
    let phone = IdentityKeys::generate(&mut rng).unwrap();
    let cli_pin = PeerPin::new(
        "cli",
        PublicKey(cli.encryption_public()),
        PublicKey::from_bytes(&cli.verifying_key().to_sec1_bytes()).unwrap(),
        0,
    );
    let phone_pin = PeerPin::new(
        "phone",
        PublicKey(phone.encryption_public()),
        PublicKey::from_bytes(&phone.verifying_key().to_sec1_bytes()).unwrap(),
        0,
    );

    // 09:30:00 — the CLI emits an unlock request, TTL 300 s.
    let t0 = 1_760_000_000u64;
    let request = seal(
        &mut rng,
        &cli,
        &phone_pin,
        Body::ApprovalRequest {
            vault_id: "work".into(),
            vault_name: "work".into(),
            operation: Operation::Unlock,
            requester: "anssi@macbook-pro".into(),
            scope: Scope::Once,
            challenge: Some(SecretHex::from_bytes(&[0x5fu8; 32])),
        },
        t0,
        &policy,
    )
    .unwrap();
    let (req_ts, req_exp) = (request.header().ts, request.header().exp);
    assert_eq!(req_exp - req_ts, policy.ttl_secs);

    // The phone answers with its own clock. Both observed skew
    // directions: ahead (ts stamped later than the truth) and behind.
    let answer = |decision_at: u64| {
        seal_reply(
            &mut OsRng,
            &phone,
            &cli_pin.clone(),
            Body::ApprovalResponse {
                decision: Decision::Allow,
                scope: Scope::Once,
                response: Some(SecretHex::from_bytes(&hmac_sha1(
                    &[0xa1u8; 20],
                    &[0x5fu8; 32],
                ))),
            },
            &request.header().rid,
            decision_at,
            &policy,
        )
        .unwrap()
    };

    // 09:34:xx — past the request's 09:35:00 expiry is refused; decided
    // inside the window (skew-extended) it is honored. This is the exact
    // shape of the #61 report: decision at 09:30:52, expiry 09:33:26,
    // redemption ~09:34.
    let in_time = answer(req_exp - 8); // decided just inside the window
    let mut store = InMemoryNonceStore::default();
    let redeemed_at = req_exp + 34; // the relay round trip outlasted exp
    let body = open_reply(
        &cli,
        std::slice::from_ref(&phone_pin),
        &in_time,
        req_ts,
        req_exp,
        redeemed_at,
        &policy,
        &mut store,
    )
    .expect("an in-time decision redeemed late is honored");
    assert!(matches!(
        &*body,
        Body::ApprovalResponse {
            decision: Decision::Allow,
            ..
        }
    ));

    // ...exactly once: the same blob again is a replay.
    assert!(matches!(
        open_reply(
            &cli,
            std::slice::from_ref(&phone_pin),
            &in_time,
            req_ts,
            req_exp,
            redeemed_at + 1,
            &policy,
            &mut store
        ),
        Err(Error::Replay)
    ));

    // Clock skew, both directions, on the decision stamp: the phone 40 s
    // behind stamps a decision before the request existed; 40 s ahead
    // stamps one past the expiry. Both are inside the skew window and
    // redeem late without issue.
    for decision_at in [req_ts - 40, req_exp + 40] {
        let mut store = InMemoryNonceStore::default();
        assert!(
            open_reply(
                &cli,
                std::slice::from_ref(&phone_pin),
                &answer(decision_at),
                req_ts,
                req_exp,
                req_exp + 120,
                &policy,
                &mut store,
            )
            .is_ok(),
            "decision at {decision_at} (skew-extended window) must redeem"
        );
    }

    // A decision the skew cannot explain — 121 s past expiry — is
    // refused however promptly it is redeemed.
    let late = answer(req_exp + skew + 1);
    assert!(matches!(
        open_reply(
            &cli,
            std::slice::from_ref(&phone_pin),
            &late,
            req_ts,
            req_exp,
            req_exp + 10,
            &policy,
            &mut InMemoryNonceStore::default(),
        ),
        Err(Error::DecisionOutsideWindow { .. })
    ));

    // The total-lifetime bound: 2 × the request TTL after creation,
    // nothing redeems any more.
    let bound = policy.redemption_deadline(req_ts, req_exp);
    assert_eq!(bound, req_ts + 2 * policy.ttl_secs);
    let mut fresh_store = InMemoryNonceStore::default();
    assert!(matches!(
        open_reply(
            &cli,
            std::slice::from_ref(&phone_pin),
            &answer(req_ts + 60),
            req_ts,
            req_exp,
            bound,
            &policy,
            &mut fresh_store,
        ),
        Err(Error::RedemptionTooLate { deadline, .. }) if deadline == bound
    ));
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
