//! Generate the cross-implementation test vectors (`vectors/v1.json`).
//!
//! Run from the crate directory:
//!
//! ```sh
//! cargo run --example gen-vectors
//! ```
//!
//! The vectors pin exact envelope bytes for fixed keys so the Swift (FFI)
//! and JavaScript (approval page) implementations can prove compatibility
//! without sharing code with this crate. The HPKE ephemeral is random —
//! a vector records the envelope it produced, which is all an opening
//! implementation needs.

use passlane_approval::prelude::*;
use passlane_approval::replay::InMemoryNonceStore;
use rand::SeedableRng;
use rand::rngs::StdRng;
use serde_json::json;

fn fixed_keys(seed: u64) -> (IdentityKeys, String, String) {
    // Deterministic scalars from the seed, so vector keys are stable.
    let mut material = [0u8; 32];
    let mut rng = StdRng::seed_from_u64(seed);
    use rand::RngCore;
    rng.fill_bytes(&mut material);
    // Make it a valid scalar deterministically.
    material[0] %= 0x7f; // keep below the field modulus high byte
    let enc = material.to_vec();
    let mut material2 = [0u8; 32];
    rng.fill_bytes(&mut material2);
    material2[0] %= 0x7f;
    let sig = material2.to_vec();
    let keys = IdentityKeys::from_bytes(&enc, &sig).expect("fixed scalars are valid");
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    (keys, hex(&enc), hex(&sig))
}

fn main() {
    let now = 1_760_000_000u64;
    let policy = Policy::default();

    let (cli, cli_enc, cli_sig) = fixed_keys(1);
    let (phone, phone_enc, phone_sig) = fixed_keys(2);
    let phone_pin = PeerPin::new(
        "anssi-iphone",
        PublicKey(phone.encryption_public()),
        PublicKey::from_bytes(&phone.verifying_key().to_sec1_bytes()).unwrap(),
        now,
    );
    let cli_pin = PeerPin::new(
        "macbook-pro",
        PublicKey(cli.encryption_public()),
        PublicKey::from_bytes(&cli.verifying_key().to_sec1_bytes()).unwrap(),
        now,
    );

    let mut rng = StdRng::seed_from_u64(42);
    let mut cases = Vec::new();

    // 1. Approval request with an HMAC challenge (the unlock scenario).
    let challenge = [0x2au8; 20];
    let request_body = Body::ApprovalRequest {
        vault_id: "default".into(),
        vault_name: "Main".into(),
        operation: Operation::Unlock,
        requester: "anssi@macbook-pro".into(),
        scope: Scope::Once,
        challenge: Some(SecretHex::from_bytes(&challenge)),
    };
    let request_body_json = serde_json::to_value(&request_body).unwrap();
    let request = seal(&mut rng, &cli, &phone_pin, request_body, now, &policy).unwrap();
    let mut store = InMemoryNonceStore::default();
    let opened = open(
        &phone,
        std::slice::from_ref(&cli_pin),
        &request,
        now + 1,
        &policy,
        &mut store,
    )
    .expect("vector request must open");
    assert_eq!(serde_json::to_value(&*opened).unwrap(), request_body_json);
    cases.push(json!({
        "name": "approval_request_unlock",
        "sender": { "enc_secret": cli_enc, "sig_secret": cli_sig },
        "recipient": { "enc_secret": phone_enc, "sig_secret": phone_sig },
        "sender_pin": cli_pin,
        "now": now,
        "policy": { "ttl_secs": policy.ttl_secs, "max_ttl_secs": policy.max_ttl_secs,
                    "max_clock_skew_secs": policy.max_clock_skew_secs, "max_session_secs": policy.max_session_secs },
        "expected_header": {
            "v": request.header.v, "t": request.header.t, "ts": request.header.ts,
            "exp": request.header.exp, "skid": request.header.skid, "rkid": request.header.rkid,
        },
        "body": request_body_json,
        "envelope_base64url": request.to_base64url(),
    }));

    // 2. Approval response carrying the HMAC-SHA1 result (secret material).
    let response_bytes = [0x77u8; 20];
    let response_body = Body::ApprovalResponse {
        decision: Decision::Allow,
        scope: Scope::Timed { seconds: 300 },
        response: Some(SecretHex::from_bytes(&response_bytes)),
    };
    let response = seal(
        &mut rng,
        &phone,
        &cli_pin,
        response_body.clone(),
        now,
        &policy,
    )
    .unwrap();
    let mut store = InMemoryNonceStore::default();
    let opened = open(
        &cli,
        std::slice::from_ref(&phone_pin),
        &response,
        now + 1,
        &policy,
        &mut store,
    )
    .expect("vector response must open");
    assert_eq!(*opened, response_body);
    cases.push(json!({
        "name": "approval_response_with_secret",
        "sender": { "enc_secret": phone_enc, "sig_secret": phone_sig },
        "recipient": { "enc_secret": cli_enc, "sig_secret": cli_sig },
        "sender_pin": phone_pin,
        "now": now,
        "policy": { "ttl_secs": policy.ttl_secs, "max_ttl_secs": policy.max_ttl_secs,
                    "max_clock_skew_secs": policy.max_clock_skew_secs, "max_session_secs": policy.max_session_secs },
        "body": serde_json::to_value(&response_body).unwrap(),
        "envelope_base64url": response.to_base64url(),
    }));

    // 3. Pairing request under a fixed pairing secret (PSK mode).
    let secret = PairingSecret::from_bytes(&(0u8..32).collect::<Vec<u8>>()).unwrap();
    let pairing_request = seal_pairing_request(
        &mut rng,
        &secret,
        &cli,
        DeviceInfo {
            kind: "cli".into(),
            name: "macbook-pro".into(),
            version: "vectors".into(),
        },
        now,
        &policy,
    )
    .unwrap();
    let mut store = InMemoryNonceStore::default();
    let (_, from_request_pin) =
        open_pairing_request(&secret, &pairing_request, now + 1, &policy, &mut store)
            .expect("vector pairing request must open");
    assert_eq!(from_request_pin.enc_pub, cli_pin.enc_pub);
    cases.push(json!({
        "name": "pairing_request_psk",
        "sender": { "enc_secret": cli_enc, "sig_secret": cli_sig },
        "pairing_secret": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "confirmation_code": secret.confirmation_code(),
        "now": now,
        "policy": { "ttl_secs": policy.ttl_secs, "max_ttl_secs": policy.max_ttl_secs,
                    "max_clock_skew_secs": policy.max_clock_skew_secs, "max_session_secs": policy.max_session_secs },
        "derived_pin": from_request_pin,
        "envelope_base64url": pairing_request.to_base64url(),
    }));

    let vectors = json!({
        "format": "passlane-approval test vectors",
        "version": VERSION,
        "suite": {
            "kem": "DHKEM(P-256, HKDF-SHA256)",
            "kdf": "HKDF-SHA256",
            "aead": "AES-256-GCM",
            "signature": "ECDSA-P256/SHA-256, DER",
        },
        "note": "Open each envelope_base64url with the recipient's enc_secret and verify with \
                 sender_pin.sig_pub (hex SEC1). The ephemeral HPKE secret is inside the envelope; \
                 no RNG is needed to open.",
        "cases": cases,
    });

    let out_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors");
    std::fs::create_dir_all(&out_dir).unwrap();
    let path = out_dir.join("v1.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&vectors).unwrap()).unwrap();
    println!(
        "wrote {} ({} cases)",
        path.display(),
        vectors["cases"].as_array().unwrap().len()
    );
}
