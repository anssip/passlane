//! WebAuthn assertion verification — the Phase 0 bootstrap.
//!
//! Before the iOS app exists, the approver is a passkey on the static
//! approval page. The page produces a WebAuthn `get` assertion whose
//! **challenge** is the envelope's [`Envelope::webauthn_challenge()`], so the
//! hardware-backed signature commits to the exact message bytes.
//!
//! The CLI verifies:
//!
//! 1. `clientDataJSON.type == "webauthn.get"`
//! 2. `clientDataJSON.challenge` equals the expected challenge
//! 3. `clientDataJSON.origin` equals the pinned page origin
//! 4. `authenticator_data.rp_id_hash == SHA-256(rp_id)`
//! 5. the user-present (UP) flag is set
//! 6. the ECDSA-P256/SHA-256 signature over
//!    `authenticator_data || SHA-256(client_data_json)` verifies under the
//!    pinned passkey public key
//!
//! Enrollment (converting the passkey's COSE key into the pinned
//! [`crate::keys::PublicKey`]) is a CLI-side concern tracked in passlane#51;
//! this module verifies assertions once the key is pinned.

use p256::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::encoding::{base64url_decode, base64url_encode};
use crate::error::{Error, Result};

/// A serialized WebAuthn assertion, as produced by
/// `navigator.credentials.get()` on the approval page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebauthnAssertion {
    /// `authenticatorData`, base64url.
    pub authenticator_data: String,
    /// `clientDataJSON`, base64url.
    pub client_data_json: String,
    /// The `signature` (DER ECDSA), base64url.
    pub signature: String,
}

impl WebauthnAssertion {
    /// Build from the raw WebAuthn outputs (helper for the FFI/Swift side).
    pub fn from_raw(
        authenticator_data: &[u8],
        client_data_json: &[u8],
        signature_der: &[u8],
    ) -> Self {
        Self {
            authenticator_data: base64url_encode(authenticator_data),
            client_data_json: base64url_encode(client_data_json),
            signature: base64url_encode(signature_der),
        }
    }
}

#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
}

/// Verify an assertion per the module docs. `expected_challenge` is the
/// base64url challenge the relying party (here: the CLI) issued.
pub fn verify_assertion(
    passkey: &VerifyingKey,
    rp_id: &str,
    origin: &str,
    assertion: &WebauthnAssertion,
    expected_challenge: &str,
) -> Result<()> {
    let cd_bytes = base64url_decode(&assertion.client_data_json)
        .map_err(|e| Error::Webauthn(format!("client data: {e}")))?;
    let client_data: ClientData = serde_json::from_slice(&cd_bytes)
        .map_err(|e| Error::Webauthn(format!("client data is not valid JSON: {e}")))?;

    if client_data.kind != "webauthn.get" {
        return Err(Error::Webauthn(format!(
            "unexpected client data type '{}'",
            client_data.kind
        )));
    }
    if !constant_time_eq(
        client_data.challenge.as_bytes(),
        expected_challenge.as_bytes(),
    ) {
        return Err(Error::Webauthn("challenge mismatch".into()));
    }
    if client_data.origin != origin {
        return Err(Error::Webauthn(format!(
            "origin '{}' does not match pinned '{}'",
            client_data.origin, origin
        )));
    }

    let auth_data = base64url_decode(&assertion.authenticator_data)
        .map_err(|e| Error::Webauthn(format!("authenticator data: {e}")))?;
    if auth_data.len() < 37 {
        return Err(Error::Webauthn("authenticator data too short".into()));
    }
    let rp_id_hash = crate::crypto::sha256(rp_id.as_bytes());
    if auth_data[..32] != rp_id_hash {
        return Err(Error::Webauthn("relying party id hash mismatch".into()));
    }
    let flags = auth_data[32];
    if flags & 0x01 == 0 {
        return Err(Error::Webauthn("user presence flag not set".into()));
    }

    // WebAuthn signs authenticator_data || SHA-256(client_data_json).
    // `verify_prehash` takes raw digest bytes, decoupling us from the exact
    // `digest` crate version the ecdsa stack links against.
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(&auth_data);
    digest.update(Sha256::digest(&cd_bytes));
    let prehash = digest.finalize();
    let sig_bytes = base64url_decode(&assertion.signature)
        .map_err(|e| Error::Webauthn(format!("signature: {e}")))?;
    let sig = Signature::from_der(&sig_bytes)
        .map_err(|_| Error::Webauthn("signature is not valid DER".into()))?;
    passkey
        .verify_prehash(&prehash, &sig)
        .map_err(|_| Error::Webauthn("signature does not verify".into()))
}

/// The Phase 0 **enrollment** challenge (SPEC §6): the binding assertion is
/// a `credentials.get()` whose challenge is
/// `base64url(SHA-256(enrollment_nonce ‖ ECDH_public_key))`.
///
/// The credential-key signature over this value is what vouches that the
/// passkey (and the human behind it) binds to this exact ECDH encryption
/// key; the CLI issues the nonce and verifies the returned assertion
/// against this same derivation.
pub fn enrollment_challenge(enrollment_nonce: &[u8], ecdh_public_key: &[u8]) -> String {
    let mut input = Vec::with_capacity(enrollment_nonce.len() + ecdh_public_key.len());
    input.extend_from_slice(enrollment_nonce);
    input.extend_from_slice(ecdh_public_key);
    base64url_encode(&crate::crypto::sha256(&input))
}

/// Constant-time byte-string comparison (lengths are public here).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{Signature, SigningKey};
    use rand::rngs::OsRng;

    const RP_ID: &str = "approve.passlane.test";
    const ORIGIN: &str = "https://approve.passlane.test";

    /// p256's `SigningKey::random` wants its own rand_core version; build
    /// keys from scalars we generate ourselves instead.
    fn random_signing_key() -> SigningKey {
        let sk = crate::crypto::random_secret_key(&mut OsRng).unwrap();
        SigningKey::from(&sk)
    }

    fn make_assertion(
        signing: &SigningKey,
        challenge: &str,
        origin: &str,
        rp_id: &str,
    ) -> WebauthnAssertion {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        use sha2::{Digest, Sha256};
        let rp_hash = Sha256::digest(rp_id.as_bytes());
        let mut auth_data = Vec::with_capacity(37);
        auth_data.extend_from_slice(&rp_hash);
        auth_data.push(0x01); // UP flag
        auth_data.extend_from_slice(&0u32.to_be_bytes()); // sign count

        let client_data_json =
            format!(r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"{origin}"}}"#);
        let mut digest = Sha256::new();
        digest.update(&auth_data);
        digest.update(Sha256::digest(client_data_json.as_bytes()));
        let sig: Signature = signing
            .sign_prehash(&digest.finalize())
            .expect("signing succeeds");
        WebauthnAssertion::from_raw(
            &auth_data,
            client_data_json.as_bytes(),
            sig.to_der().as_bytes(),
        )
    }

    #[test]
    fn valid_assertion_verifies() {
        let passkey = random_signing_key();
        let challenge = "c-freejOBBZtFkVCmM4soo0nOsrjvaPsdGM9fDpyKcNs";
        let assertion = make_assertion(&passkey, challenge, ORIGIN, RP_ID);
        verify_assertion(
            passkey.verifying_key(),
            RP_ID,
            ORIGIN,
            &assertion,
            challenge,
        )
        .unwrap();
    }

    #[test]
    fn wrong_challenge_rejected() {
        let passkey = random_signing_key();
        let assertion = make_assertion(
            &passkey,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ORIGIN,
            RP_ID,
        );
        assert!(
            verify_assertion(
                passkey.verifying_key(),
                RP_ID,
                ORIGIN,
                &assertion,
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            )
            .is_err()
        );
    }

    #[test]
    fn wrong_origin_rejected() {
        let passkey = random_signing_key();
        let challenge = "challenge-value";
        let assertion = make_assertion(&passkey, challenge, "https://evil.example", RP_ID);
        assert!(
            verify_assertion(
                passkey.verifying_key(),
                RP_ID,
                ORIGIN,
                &assertion,
                challenge
            )
            .is_err()
        );
    }

    #[test]
    fn wrong_rp_id_rejected() {
        let passkey = random_signing_key();
        let challenge = "challenge-value";
        let assertion = make_assertion(&passkey, challenge, ORIGIN, "evil.example");
        assert!(
            verify_assertion(
                passkey.verifying_key(),
                RP_ID,
                ORIGIN,
                &assertion,
                challenge
            )
            .is_err()
        );
    }

    #[test]
    fn signature_by_other_key_rejected() {
        let passkey = random_signing_key();
        let impostor = random_signing_key();
        let challenge = "challenge-value";
        let assertion = make_assertion(&impostor, challenge, ORIGIN, RP_ID);
        assert!(
            verify_assertion(
                passkey.verifying_key(),
                RP_ID,
                ORIGIN,
                &assertion,
                challenge
            )
            .is_err()
        );
    }

    #[test]
    fn wrong_type_rejected() {
        let passkey = random_signing_key();
        let challenge = "challenge-value";
        let mut assertion = make_assertion(&passkey, challenge, ORIGIN, RP_ID);
        assertion.client_data_json = base64url_encode(
            format!(
                r#"{{"type":"webauthn.create","challenge":"{challenge}","origin":"{ORIGIN}"}}"#
            )
            .as_bytes(),
        );
        assert!(
            verify_assertion(
                passkey.verifying_key(),
                RP_ID,
                ORIGIN,
                &assertion,
                challenge
            )
            .is_err()
        );
    }

    #[test]
    fn enrollment_challenge_matches_spec_construction() {
        // SPEC §6: base64url(SHA-256(enrollment_nonce ‖ ECDH_public_key)).
        // Deterministic construction, so both sides (CLI and page) derive
        // the identical value from the same inputs.
        let nonce = [0x0au8; 16];
        let ecdh_pub = [0x04u8; 65];
        let challenge = enrollment_challenge(&nonce, &ecdh_pub);

        use sha2::{Digest, Sha256};
        let mut digest = Sha256::new();
        digest.update(nonce);
        digest.update(ecdh_pub);
        assert_eq!(
            challenge,
            crate::encoding::base64url_encode(&digest.finalize())
        );
        // Bound to both inputs: neither side can be swapped unnoticed.
        assert_ne!(challenge, enrollment_challenge(&[0x0b; 16], &ecdh_pub));
        assert_ne!(challenge, enrollment_challenge(&nonce, &[0x05; 65]));
        // It is a valid unpadded base64url string of a 32-byte digest.
        assert_eq!(
            crate::encoding::base64url_decode(&challenge).unwrap().len(),
            32
        );
        assert!(!challenge.contains('='));
    }
}
