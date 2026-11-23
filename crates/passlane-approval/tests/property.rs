//! Property-based tests over the envelope machinery (passlane#49):
//! round-trip, tamper rejection, replay rejection, expiry — across randomly
//! generated keys, bodies and clocks.

use passlane_approval::prelude::*;
use passlane_approval::replay::InMemoryNonceStore;
use proptest::prelude::*;
use rand::SeedableRng;
use rand::rngs::StdRng;

fn any_operation() -> impl Strategy<Value = Operation> {
    prop_oneof![
        ("[a-zA-Z0-9 .-]{1,24}", "[a-z]{1,10}")
            .prop_map(|(entry, field)| Operation::Reveal { entry, field }),
        Just(Operation::Unlock),
        Just(Operation::Save),
        Just(Operation::EnrollKey),
    ]
}

fn any_scope() -> impl Strategy<Value = Scope> {
    prop_oneof![
        Just(Scope::Once),
        (1u32..=900).prop_map(|seconds| Scope::Timed { seconds }),
    ]
}

fn any_secret20() -> impl Strategy<Value = SecretHex> {
    "[0-9a-f]{40}".prop_map(|hex| SecretHex::from_hex(&hex).unwrap())
}

fn any_request_body() -> impl Strategy<Value = Body> {
    (
        "[a-z0-9]{1,8}",
        "[a-zA-Z0-9 .-]{1,16}",
        any_operation(),
        "[a-z@0-9.-]{1,20}",
        any_scope(),
    )
        .prop_map(|(vault_id, vault_name, operation, requester, scope)| {
            Body::ApprovalRequest {
                vault_id,
                vault_name,
                operation,
                requester,
                scope,
                challenge: None,
            }
        })
}

fn any_response_body() -> impl Strategy<Value = Body> {
    (
        prop_oneof![Just(Decision::Allow), Just(Decision::Deny { reason: None })],
        any_scope(),
        prop::option::of(any_secret20()),
    )
        .prop_map(|(decision, scope, response)| Body::ApprovalResponse {
            decision,
            scope,
            response,
        })
}

fn any_body() -> impl Strategy<Value = Body> {
    prop_oneof![any_request_body(), any_response_body(),]
}

fn setup(seed: u64) -> (StdRng, IdentityKeys, IdentityKeys, PeerPin, PeerPin) {
    let mut rng = StdRng::seed_from_u64(seed);
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
    (rng, cli, phone, phone_pin, cli_pin)
}

proptest! {
    #[test]
    fn roundtrip(seed in any::<u64>(), body in any_body(), now in 1_000u64..1_000_000, ttl in 10u64..900) {
        let (mut rng, cli, phone, phone_pin, cli_pin) = setup(seed);
        let policy = Policy { ttl_secs: ttl, ..Policy::default() };
        let env = seal(&mut rng, &cli, &phone_pin, body.clone(), now, &policy).unwrap();
        let parsed = Envelope::from_bytes(&env.to_bytes()).unwrap();
        prop_assert_eq!(parsed.to_base64url(), env.to_base64url());
        let mut store = InMemoryNonceStore::default();
        let opened = open(&phone, &[cli_pin], &parsed, now + 1, &policy, &mut store).unwrap();
        prop_assert_eq!(&*opened, &body);
    }

    #[test]
    fn tamper_any_byte_rejects(
        seed in any::<u64>(),
        body in any_request_body(),
        offset in 0usize..32,
    ) {
        let (mut rng, cli, phone, phone_pin, cli_pin) = setup(seed);
        let policy = Policy::default();
        let now = 5_000u64;
        let env = seal(&mut rng, &cli, &phone_pin, body, now, &policy).unwrap();
        let wire = env.to_bytes();
        // Flip one bit in each of several distinct regions (magic, header,
        // enc, ct, sig) — chosen via `offset` buckets.
        let header_len = u16::from_le_bytes([wire[7], wire[8]]) as usize;
        let enc_start = 9 + header_len + 2;
        let candidates = [
            2usize.min(wire.len() - 1),                          // magic
            (9 + offset).min(wire.len() - 1),                    // header
            (enc_start + offset % 60).min(wire.len() - 1),       // enc
            (wire.len() / 2 + offset).min(wire.len() - 1),       // ct
            wire.len() - 1 - (offset % 64).min(wire.len() - 1),  // sig
        ];
        for &i in &candidates {
            let mut tampered = wire.clone();
            tampered[i] ^= 0x80;            let result = Envelope::from_bytes(&tampered)
                .map_err(|_| ())
                .and_then(|p| {
                    let mut store = InMemoryNonceStore::default();
                    open(&phone, std::slice::from_ref(&cli_pin), &p, now + 1, &policy, &mut store).map_err(|_| ())
                });
            prop_assert!(result.is_err(), "byte {} tamper accepted", i);
        }
    }

    #[test]
    fn replay_rejected(seed in any::<u64>(), body in any_request_body()) {
        let (mut rng, cli, phone, phone_pin, cli_pin) = setup(seed);
        let policy = Policy::default();
        let env = seal(&mut rng, &cli, &phone_pin, body, 7_000, &policy).unwrap();
        let mut store = InMemoryNonceStore::default();
        prop_assert!(open(&phone, std::slice::from_ref(&cli_pin), &env, 7_050, &policy, &mut store).is_ok());
        prop_assert!(matches!(
            open(&phone, &[cli_pin], &env, 7_051, &policy, &mut store),
            Err(Error::Replay)
        ));
    }

    #[test]
    fn expiry_rejected(seed in any::<u64>(), body in any_request_body(), ttl in 10u64..900) {
        let (mut rng, cli, phone, phone_pin, cli_pin) = setup(seed);
        let policy = Policy { ttl_secs: ttl, ..Policy::default() };
        let now = 100_000u64;
        let env = seal(&mut rng, &cli, &phone_pin, body, now, &policy).unwrap();
        let mut store = InMemoryNonceStore::default();
        prop_assert!(open(&phone, std::slice::from_ref(&cli_pin), &env, now + ttl - 1, &policy, &mut store).is_ok());
        prop_assert!(matches!(
            open(&phone, &[cli_pin], &env, now + ttl, &policy, &mut store),
            Err(Error::Expired(_))
        ));
    }

    #[test]
    fn wrong_recipient_rejected(seed in any::<u64>(), body in any_request_body()) {
        let (mut rng, cli, _phone, phone_pin, cli_pin) = setup(seed);
        let (_, other, _, _, _) = setup(seed ^ 0x5a5a);
        let policy = Policy::default();
        let env = seal(&mut rng, &cli, &phone_pin, body, 42, &policy).unwrap();
        let mut store = InMemoryNonceStore::default();
        prop_assert!(matches!(
            open(&other, &[cli_pin], &env, 43, &policy, &mut store),
            Err(Error::WrongRecipient(_))
        ));
    }
}
