//! Validate the committed cross-implementation vectors (`vectors/v1.json`).
//!
//! These are the vectors the Swift (UniFFI) and JavaScript (approval page)
//! sides will consume in passlane#51 — this test is the reference for what
//! "opening a vector" means.

use passlane_approval::prelude::*;
use passlane_approval::replay::InMemoryNonceStore;

#[derive(serde::Deserialize)]
struct Keys {
    enc_secret: String,
    sig_secret: String,
}

#[derive(serde::Deserialize)]
struct PolicyJson {
    ttl_secs: u64,
    max_ttl_secs: u64,
    max_clock_skew_secs: u64,
    max_session_secs: u64,
}

#[derive(serde::Deserialize)]
struct Case {
    name: String,
    #[serde(flatten)]
    fields: serde_json::Value,
}

fn keys(k: &Keys) -> IdentityKeys {
    let enc = passlane_approval::encoding::hex_decode(&k.enc_secret).unwrap();
    let sig = passlane_approval::encoding::hex_decode(&k.sig_secret).unwrap();
    IdentityKeys::from_bytes(&enc, &sig).unwrap()
}

fn to_policy(p: &PolicyJson) -> Policy {
    Policy {
        ttl_secs: p.ttl_secs,
        max_ttl_secs: p.max_ttl_secs,
        max_clock_skew_secs: p.max_clock_skew_secs,
        max_session_secs: p.max_session_secs,
    }
}

fn pin(v: &serde_json::Value) -> PeerPin {
    serde_json::from_value(v.clone()).unwrap()
}

#[test]
fn committed_vectors_open() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("vectors")
        .join("v1.json");
    let doc: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        doc["version"], VERSION,
        "vector file targets this protocol version"
    );

    let cases: Vec<Case> = serde_json::from_value(doc["cases"].clone()).unwrap();
    assert!(cases.len() >= 3, "expected the committed vector set");

    for case in &cases {
        let f = &case.fields;
        let sender: Keys = serde_json::from_value(f["sender"].clone()).unwrap();
        let policy_json: PolicyJson = serde_json::from_value(f["policy"].clone()).unwrap();
        let policy = to_policy(&policy_json);
        let now = f["now"].as_u64().unwrap();
        let envelope = Envelope::from_base64url(f["envelope_base64url"].as_str().unwrap()).unwrap();

        match case.name.as_str() {
            "approval_request_unlock" | "approval_response_with_secret" => {
                let recipient: Keys = serde_json::from_value(f["recipient"].clone()).unwrap();
                let sender_pin = pin(&f["sender_pin"]);
                let recipient = keys(&recipient);

                // The recipient opens and must see exactly the vector body.
                let mut store = InMemoryNonceStore::default();
                let body = open(
                    &recipient,
                    &[sender_pin],
                    &envelope,
                    now + 1,
                    &policy,
                    &mut store,
                )
                .unwrap_or_else(|e| panic!("{}: open failed: {e}", case.name));
                assert_eq!(
                    serde_json::to_value(&*body).unwrap(),
                    f["body"],
                    "{}: body mismatch",
                    case.name
                );

                // The sender identity matches the vector keys.
                let sender = keys(&sender);
                assert_eq!(
                    envelope.header().skid,
                    sender.encryption_kid(),
                    "{}: skid",
                    case.name
                );

                // Replay is rejected on the vector too.
                assert!(matches!(
                    open(
                        &recipient,
                        &[],
                        &envelope,
                        now + 1,
                        &policy,
                        &mut InMemoryNonceStore::default()
                    ),
                    Err(Error::UnknownSender(_))
                ));
            }
            "pairing_request_psk" => {
                let secret_hex = f["pairing_secret"].as_str().unwrap();
                let secret = PairingSecret::from_bytes(
                    &passlane_approval::encoding::hex_decode(secret_hex).unwrap(),
                )
                .unwrap();
                let expected_code = f["confirmation_code"].as_str().unwrap();
                let sender: Keys = serde_json::from_value(f["sender"].clone()).unwrap();
                let sender_keys = keys(&sender);
                let cli_enc =
                    passlane_approval::encoding::hex_encode(&sender_keys.encryption_public());
                let cli_sig = passlane_approval::encoding::hex_encode(
                    &sender_keys.verifying_key().to_sec1_bytes(),
                );
                assert_eq!(secret.confirmation_code(&cli_enc, &cli_sig), expected_code);
                assert_eq!(
                    secret.confirmation_code(&cli_enc, &cli_sig),
                    expected_code,
                    "code must be stable"
                );

                let mut store = InMemoryNonceStore::default();
                let (_body, derived_pin) =
                    open_pairing_request(&secret, &envelope, now + 1, &policy, &mut store)
                        .unwrap_or_else(|e| panic!("{}: open failed: {e}", case.name));
                let derived: PeerPin = serde_json::from_value(f["derived_pin"].clone()).unwrap();
                assert_eq!(derived_pin, derived, "{}: derived pin mismatch", case.name);
            }
            other => panic!("unknown vector case {other}"),
        }
    }
}
