//! Cryptographic building blocks: the HPKE suite, P-256 helpers, the
//! pairing pre-shared-key seal/open, and signature verification.

use hkdf::Hkdf;
use p256::{SecretKey, ecdsa::VerifyingKey};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Wire type alias: HPKE opaque key bytes (public = 65-byte SEC1 for P-256,
/// private = 32-byte scalar).
pub type HpkeBytes = Vec<u8>;

/// Domain-separation string prefixing every HPKE `info` input.
const INFO_PREFIX: &[u8] = b"passlane-approval/v1";

/// Salt for the pairing pre-shared key derivation (see `pairing.rs`).
const PAIRING_SALT: &[u8] = b"passlane-pairing/v1";

fn suite() -> hpke_rs::Hpke<hpke_rs::rustcrypto::HpkeRustCrypto> {
    use hpke_rs::hpke_types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
    hpke_rs::Hpke::new(
        hpke_rs::Mode::Base,
        KemAlgorithm::DhKemP256,
        KdfAlgorithm::HkdfSha256,
        AeadAlgorithm::Aes256Gcm,
    )
}

/// Random valid P-256 secret key (rejection-sampled uniform scalar).
pub(crate) fn random_secret_key(rng: &mut (impl CryptoRng + RngCore)) -> Result<SecretKey> {
    let mut scratch = Zeroizing::new([0u8; 32]);
    loop {
        rng.fill_bytes(&mut scratch[..]);
        if let Ok(key) = SecretKey::from_slice(&scratch[..]) {
            return Ok(key);
        }
    }
}

/// Validate that `bytes` is a usable 32-byte P-256 scalar.
pub(crate) fn validate_secret_scalar(bytes: &[u8]) -> Result<()> {
    if bytes.len() != 32 {
        return Err(Error::Key(format!(
            "P-256 private key must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    SecretKey::from_slice(bytes)
        .map(|_| ())
        .map_err(|_| Error::Key("scalar is not a valid P-256 key".into()))
}

pub(crate) fn secret_key_from_bytes(bytes: &[u8]) -> Result<SecretKey> {
    validate_secret_scalar(bytes)?;
    SecretKey::from_slice(bytes).map_err(|_| Error::Key("invalid secret key".into()))
}

/// Derive the 65-byte uncompressed SEC1 public key of a 32-byte scalar.
pub(crate) fn encryption_public(secret: &[u8]) -> [u8; 65] {
    let key = SecretKey::from_slice(secret).expect("validated earlier");
    let bytes = key.public_key().to_sec1_bytes();
    bytes
        .as_ref()
        .try_into()
        .expect("P-256 public keys are 65 bytes uncompressed")
}

/// HPKE single-shot seal to `recipient_public` (65-byte SEC1).
///
/// `info` binds the message type; `aad` is the cleartext envelope prefix,
/// which binds the header to the ciphertext.
pub(crate) fn hpke_seal(
    recipient_public: &[u8],
    msg_type: u8,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let info = info_for(msg_type);
    let mut hpke = suite();
    let pk = hpke_rs::HpkePublicKey::from(recipient_public.to_vec());
    let (enc, ct) = hpke
        .seal(&pk, &info, aad, plaintext, None, None, None)
        .map_err(|e| Error::Hpke(format!("seal: {e}")))?;
    Ok((enc, ct))
}

/// HPKE single-shot open with a 32-byte scalar private key.
pub(crate) fn hpke_open(
    enc: &[u8],
    recipient_secret: &[u8],
    msg_type: u8,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let info = info_for(msg_type);
    let hpke = suite();
    let sk = hpke_rs::HpkePrivateKey::from(recipient_secret.to_vec());
    hpke.open(enc, &sk, &info, aad, ciphertext, None, None, None)
        .map_err(|_| Error::Decrypt)
}

fn info_for(msg_type: u8) -> Vec<u8> {
    let mut info = INFO_PREFIX.to_vec();
    info.push(msg_type);
    info
}

/// AES-256-GCM seal under a key derived from the pairing secret.
///
/// Returns `nonce || ciphertext` (12-byte nonce prefix).
pub(crate) fn psk_seal(
    secret: &[u8; 32],
    msg_type: u8,
    aad: &[u8],
    plaintext: &[u8],
    rng: &mut (impl CryptoRng + RngCore),
) -> Result<Vec<u8>> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};

    let key = Zeroizing::new(pairing_key(secret, msg_type));
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).expect("32-byte key");
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Decrypt)?;
    let mut out = nonce_bytes.to_vec();
    out.extend_from_slice(&ct);
    Ok(out)
}

/// AES-256-GCM open for a `nonce || ciphertext` blob under the pairing key.
pub(crate) fn psk_open(
    secret: &[u8; 32],
    msg_type: u8,
    aad: &[u8],
    blob: &[u8],
) -> Result<Vec<u8>> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};

    if blob.len() < 12 + 16 {
        return Err(Error::Decrypt);
    }
    let (nonce, ct) = blob.split_at(12);
    let key = Zeroizing::new(pairing_key(secret, msg_type));
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).expect("32-byte key");
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| Error::Decrypt)
}

fn pairing_key(secret: &[u8; 32], msg_type: u8) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(PAIRING_SALT), secret);
    let mut key = [0u8; 32];
    let mut info = INFO_PREFIX.to_vec();
    info.push(msg_type);
    hk.expand(&info, &mut key)
        .expect("32 bytes fits HKDF-SHA256 output");
    key
}

/// Key that binds a pairing response to the QR-borne pairing secret.
fn pairing_binding_key(secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(PAIRING_SALT), secret);
    let mut key = [0u8; 32];
    hk.expand(b"response-binding", &mut key)
        .expect("32 bytes fits HKDF-SHA256 output");
    Zeroizing::new(key)
}

/// Key for the human-verified display code.
fn pairing_display_key(secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(PAIRING_SALT), secret);
    let mut key = [0u8; 32];
    hk.expand(b"display-code", &mut key)
        .expect("32 bytes fits HKDF-SHA256 output");
    Zeroizing::new(key)
}

/// The confirmation code digits. Twelve (two six-digit groups) puts the
/// offline grind cost for a substituted QR at ~2^40 HMACs — hours of GPU
/// time against a code that must ALSO be shoulder-surfed live. Six digits
/// would be grindable in under a second; see SPEC §5 for the full math
/// and the fingerprint escape hatch.
const CODE_DIGITS: u64 = 1_000_000_000_000;

fn format_code(n: u64) -> String {
    let d = CODE_DIGITS;
    let a = n / 1_000_000;
    let b = n % 1_000_000;
    let _ = d;
    format!("{a:06}-{b:06}")
}

/// The six-pair-digit confirmation code, bound to the **CLI identity being
/// pinned** — not to the secret alone.
///
/// Binding the identity is what defeats the naive QR-swap attack: an attacker
/// who reads the terminal's QR and re-issues it with substituted keys
/// produces a different code on the phone than the one the terminal shows
/// over its own keys, so the human comparison fails. Only a phone holding
/// the same secret *and* seeing the terminal's genuine keys can display
/// the matching digits.
///
/// This is the **first** of two checks: it authenticates the CLI side.
/// The response side needs [`pairing_mutual_confirmation_code`], because
/// anyone holding the pairing secret can produce a valid proof for their
/// own keys — the human must compare a value that covers the responder
/// too before any pin is persisted.
pub(crate) fn pairing_confirmation_code(
    secret: &[u8; 32],
    cli_enc_pub_hex: &str,
    cli_sig_pub_hex: &str,
) -> String {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(pairing_display_key(secret).as_ref())
        .expect("HMAC accepts any key length");
    mac.update(b"confirmation-code");
    mac.update(cli_enc_pub_hex.as_bytes());
    mac.update(cli_sig_pub_hex.as_bytes());
    let n = u64::from_be_bytes(
        mac.finalize().into_bytes()[..8]
            .try_into()
            .expect("8 bytes"),
    ) % CODE_DIGITS;
    format_code(n)
}

/// The **mutual** confirmation code: shown on the terminal (computed from
/// the decrypted response) and on the responder (computed from the request)
/// after the pairing response arrives, before either side persists its pin.
///
/// Unlike [`pairing_confirmation_code`], this binds **both** identities: a
/// QR-reading attacker who knows the pairing secret can still forge a
/// perfectly valid response pinning their own keys — the cryptographic proof
/// only proves knowledge of the secret, which they have. The mutual code is
/// the human check that catches the substitution: the substituted response
/// yields a different code on the terminal than the genuine responder
/// shows. Both codes must match before a pin is saved.
pub(crate) fn pairing_mutual_confirmation_code(
    secret: &[u8; 32],
    cli_enc_pub_hex: &str,
    cli_sig_pub_hex: &str,
    responder_enc_pub_hex: &str,
    responder_sig_pub_hex: &str,
) -> String {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(pairing_display_key(secret).as_ref())
        .expect("HMAC accepts any key length");
    mac.update(b"mutual-confirmation-code");
    mac.update(cli_enc_pub_hex.as_bytes());
    mac.update(cli_sig_pub_hex.as_bytes());
    mac.update(responder_enc_pub_hex.as_bytes());
    mac.update(responder_sig_pub_hex.as_bytes());
    let n = u64::from_be_bytes(
        mac.finalize().into_bytes()[..8]
            .try_into()
            .expect("8 bytes"),
    ) % CODE_DIGITS;
    format_code(n)
}

/// HMAC-SHA256 binding proof over the whole pairing context: the request
/// it answers (by `rid`) plus **both** identities being pinned. Anyone can
/// know public keys; only the holder of the pairing secret can produce
/// this, and replaying it against a different request or key set fails.
pub(crate) fn pairing_binding_proof(
    secret: &[u8; 32],
    request_rid: &str,
    cli_enc_pub_hex: &str,
    responder_enc_pub_hex: &str,
    responder_sig_pub_hex: &str,
) -> Result<Vec<u8>> {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(pairing_binding_key(secret).as_ref())
        .expect("HMAC accepts any key length");
    mac.update(b"pairing-response-bind");
    mac.update(request_rid.as_bytes());
    mac.update(cli_enc_pub_hex.as_bytes());
    mac.update(responder_enc_pub_hex.as_bytes());
    mac.update(responder_sig_pub_hex.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Verify a binding proof in constant time.
pub(crate) fn verify_pairing_binding_proof(
    secret: &[u8; 32],
    request_rid: &str,
    cli_enc_pub_hex: &str,
    responder_enc_pub_hex: &str,
    responder_sig_pub_hex: &str,
    proof: &[u8],
) -> Result<()> {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(pairing_binding_key(secret).as_ref())
        .expect("HMAC accepts any key length");
    mac.update(b"pairing-response-bind");
    mac.update(request_rid.as_bytes());
    mac.update(cli_enc_pub_hex.as_bytes());
    mac.update(responder_enc_pub_hex.as_bytes());
    mac.update(responder_sig_pub_hex.as_bytes());
    mac.verify_slice(proof)
        .map_err(|_| Error::Pairing("pairing proof mismatch".into()))
}

/// Verify an ECDSA P-256 DER signature over SHA-256(message).
pub(crate) fn verify_signature(
    verifying_key: &VerifyingKey,
    message: &[u8],
    der_signature: &[u8],
) -> Result<()> {
    use p256::ecdsa::signature::Verifier;
    let sig = p256::ecdsa::Signature::from_der(der_signature).map_err(|_| Error::Signature)?;
    verifying_key
        .verify(message, &sig)
        .map_err(|_| Error::Signature)
}

/// SHA-256 convenience (used for key ids and the WebAuthn challenge).
pub(crate) fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn hpke_roundtrip() {
        let sk = random_secret_key(&mut OsRng).unwrap();
        let pk = encryption_public(&sk.to_bytes());
        let (enc, ct) = hpke_seal(&pk, 3, b"aad", b"hello passlane").unwrap();
        assert_eq!(enc.len(), 65);
        let pt = hpke_open(&enc, &sk.to_bytes(), 3, b"aad", &ct).unwrap();
        assert_eq!(pt, b"hello passlane");
    }

    #[test]
    fn hpke_tamper_fails() {
        let sk = random_secret_key(&mut OsRng).unwrap();
        let pk = encryption_public(&sk.to_bytes());
        let (enc, mut ct) = hpke_seal(&pk, 3, b"aad", b"hello").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(hpke_open(&enc, &sk.to_bytes(), 3, b"aad", &ct).is_err());
    }

    #[test]
    fn hpke_aad_mismatch_fails() {
        let sk = random_secret_key(&mut OsRng).unwrap();
        let pk = encryption_public(&sk.to_bytes());
        let (enc, ct) = hpke_seal(&pk, 3, b"aad-1", b"hello").unwrap();
        assert!(hpke_open(&enc, &sk.to_bytes(), 3, b"aad-2", &ct).is_err());
    }

    #[test]
    fn hpke_wrong_recipient_fails() {
        let sk1 = random_secret_key(&mut OsRng).unwrap();
        let sk2 = random_secret_key(&mut OsRng).unwrap();
        let pk1 = encryption_public(&sk1.to_bytes());
        let (enc, ct) = hpke_seal(&pk1, 3, b"aad", b"hello").unwrap();
        assert!(hpke_open(&enc, &sk2.to_bytes(), 3, b"aad", &ct).is_err());
    }

    #[test]
    fn psk_roundtrip_and_wrong_secret() {
        let secret = [7u8; 32];
        let blob = psk_seal(&secret, 1, b"aad", b"pair me", &mut OsRng).unwrap();
        assert_eq!(psk_open(&secret, 1, b"aad", &blob).unwrap(), b"pair me");
        let wrong = [8u8; 32];
        assert!(psk_open(&wrong, 1, b"aad", &blob).is_err());
        // AAD binding
        assert!(psk_open(&secret, 1, b"other", &blob).is_err());
    }

    #[test]
    fn scalar_validation() {
        assert!(validate_secret_scalar(&[0u8; 32]).is_err()); // zero scalar
        assert!(validate_secret_scalar(&[1u8; 31]).is_err()); // wrong length
        assert!(validate_secret_scalar(&[42u8; 32]).is_ok());
    }

    #[test]
    fn public_derivation_matches() {
        let sk = random_secret_key(&mut OsRng).unwrap();
        let derived = encryption_public(&sk.to_bytes());
        let direct = sk.public_key().to_sec1_bytes();
        assert_eq!(derived.as_slice(), &*direct);
    }
}
