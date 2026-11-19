//! Pairing: establishing the mutual pin between a CLI and an approver.
//!
//! The first message cannot be encrypted to an unknown key, so the pairing
//! request travels under a **pre-shared key** that arrives out-of-band: a
//! 32-byte random [`PairingSecret`] printed by the CLI inside its QR code
//! (URL fragment — never sent to any server). Both sides derive:
//!
//! - the pairing AEAD key: `HKDF-SHA256(salt = "passlane-pairing/v1",
//!   ikm = secret, info = "passlane-approval/v1" || msg_type)`;
//! - a six-digit **confirmation code**: the human compares `123-456` on the
//!   phone against the same digits in the terminal, defeating a swapped-QR
//!   attack. The code is a display check, not a cryptographic secret.
//!
//! The flow (see SPEC.md §Pairing):
//!
//! 1. CLI → phone: `PairingRequest` (PSK-sealed, signed by the CLI) carrying
//!    the CLI's public keys and device info.
//! 2. Phone displays the confirmation code and the CLI's identity; the human
//!    confirms the codes match.
//! 3. Phone → CLI: `PairingResponse` (HPKE-sealed to the CLI's encryption
//!    key, signed by the phone) carrying the phone's public keys.
//! 4. Both sides pin each other. The pairing secret is discarded.
//!
//! Away-from-desk pairing (relaying the QR payload through chat) is
//! **forbidden for initial pairing** — the QR scan is the out-of-band
//! channel. Re-approvals of an existing pairing may travel over relays.

use rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto;
use crate::encoding::hex_encode;
use crate::envelope::{Envelope, Signature, seal};
use crate::error::{Error, Result};
use crate::keys::{IdentityKeys, PeerPin, PublicKey, kid};
use crate::message::{Body, DeviceInfo, Header, MessageType, VERSION};
use crate::policy::Policy;
use crate::replay::NonceStore;
use zeroize::Zeroizing;

/// A 32-byte one-time pairing secret carried in the enrollment QR.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PairingSecret([u8; 32]);

impl PairingSecret {
    /// Generate a fresh secret for an enrollment QR.
    pub fn generate(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Adopt bytes scanned from a QR payload.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; 32] = bytes.try_into().map_err(|_| {
            Error::Pairing(format!(
                "pairing secret must be 32 bytes, got {}",
                bytes.len()
            ))
        })?;
        Ok(Self(arr))
    }

    /// The raw secret bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Hex form for embedding in the QR payload.
    pub fn to_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex_encode(&self.0))
    }

    /// Six-digit confirmation code (`123-456`), derived from the secret.
    ///
    /// Both endpoints display it; the human compares them before continuing.
    /// It is a display check, not a cryptographic secret: its only job is to
    /// prove both sides derived their keys from the same QR payload.
    pub fn confirmation_code(&self) -> String {
        use hkdf::Hkdf;
        use sha2::Sha256;
        let hk = Hkdf::<Sha256>::new(Some(b"passlane-pairing-confirm"), &self.0);
        let mut out = [0u8; 4];
        hk.expand(b"confirmation-code", &mut out)
            .expect("4 bytes fit HKDF output");
        let n = u32::from_be_bytes(out) % 1_000_000;
        format!("{:03}-{:03}", n / 1000, n % 1000)
    }
}

/// Seal a pairing request under the pairing secret, signed by the CLI.
pub fn seal_pairing_request(
    rng: &mut (impl CryptoRng + RngCore),
    secret: &PairingSecret,
    local: &IdentityKeys,
    device: DeviceInfo,
    now: u64,
    policy: &Policy,
) -> Result<Envelope> {
    let body = Body::PairingRequest {
        device,
        enc_pub: hex_encode(&local.encryption_public()),
        sig_pub: hex_encode(&local.verifying_key().to_sec1_bytes()),
    };
    let header = Header {
        v: VERSION,
        t: MessageType::PairingRequest as u8,
        n: crate::envelope::random_nonce_hex(rng)?,
        ts: now,
        exp: now + policy.ttl_secs,
        skid: local.encryption_kid(),
        rkid: String::new(), // no recipient key yet; PSK mode
        rid: crate::envelope::random_nonce_hex(rng)?,
    };
    let header_bytes = serde_json::to_vec(&header)?;
    let plaintext = Zeroizing::new(serde_json::to_vec(&body)?);

    let frame = Envelope {
        header: header.clone(),
        header_bytes: header_bytes.clone(),
        enc: Vec::new(),
        ct: Vec::new(),
        signature: Some(Signature::EcdsaP256(Vec::new())),
    };
    let ct = crypto::psk_seal(secret.as_bytes(), header.t, &frame.aad(), &plaintext, rng)?;

    let mut env = Envelope {
        header,
        header_bytes,
        enc: Vec::new(),
        ct,
        signature: Some(Signature::EcdsaP256(Vec::new())),
    };
    let sig = local.sign(&env.signed_transcript());
    env.signature = Some(Signature::EcdsaP256(sig.to_der().as_bytes().to_vec()));
    Ok(env)
}

/// Open a pairing request with the scanned secret. Returns the CLI's pin
/// (from the decrypted, signature-verified body) for the phone to store.
pub fn open_pairing_request(
    secret: &PairingSecret,
    envelope: &Envelope,
    now: u64,
    policy: &Policy,
    nonce_store: &mut dyn NonceStore,
) -> Result<(Zeroizing<Body>, PeerPin)> {
    open_psk_envelope(
        MessageType::PairingRequest,
        secret,
        envelope,
        now,
        policy,
        nonce_store,
    )
}

/// Seal the pairing response: normal HPKE to the CLI's key, signed by us.
pub fn seal_pairing_response(
    rng: &mut (impl CryptoRng + RngCore),
    local: &IdentityKeys,
    cli: &PeerPin,
    device: DeviceInfo,
    now: u64,
    policy: &Policy,
) -> Result<Envelope> {
    let body = Body::PairingResponse {
        device,
        enc_pub: hex_encode(&local.encryption_public()),
        sig_pub: hex_encode(&local.verifying_key().to_sec1_bytes()),
    };
    seal(rng, local, cli, body, now, policy)
}

/// Open a pairing response on the CLI side. The phone is not pinned yet, so
/// the sender is authenticated by the pairing channel: the response is
/// HPKE-encrypted to *our* key (only the holder of the request context can
/// read it) and signed by a key declared inside the encrypted body — a key
/// the attacker cannot possess without the pairing secret.
///
/// The caller pins the returned [`PeerPin`] only after the human confirms
/// the confirmation codes match.
pub fn open_pairing_response(
    local: &IdentityKeys,
    envelope: &Envelope,
    now: u64,
    policy: &Policy,
    nonce_store: &mut dyn NonceStore,
) -> Result<(Zeroizing<Body>, PeerPin)> {
    if envelope.header.v != VERSION {
        return Err(Error::Version(envelope.header.v));
    }
    if envelope.header.t != MessageType::PairingResponse as u8 {
        return Err(Error::MessageTypeMismatch(MessageType::PairingResponse));
    }
    policy.validate(&envelope.header, now)?;
    if envelope.header.rkid != kid(b"enc", &local.encryption_public()) {
        return Err(Error::WrongRecipient(envelope.header.rkid.clone()));
    }

    let plaintext = Zeroizing::new(crypto::hpke_open(
        &envelope.enc,
        &local.hpke_secret(),
        envelope.header.t,
        &envelope.aad(),
        &envelope.ct,
    )?);
    let body: Body = serde_json::from_slice(&plaintext)?;
    if body.message_type() != MessageType::PairingResponse {
        return Err(Error::MessageTypeMismatch(body.message_type()));
    }
    let Body::PairingResponse {
        device,
        enc_pub,
        sig_pub,
    } = &body
    else {
        return Err(Error::MessageTypeMismatch(MessageType::PairingResponse));
    };

    // The signature must be made with the key the body declares.
    let sig_key = PublicKey::from_hex(sig_pub.as_str())?;
    let transcript = envelope.signed_transcript();
    match &envelope.signature {
        Some(Signature::EcdsaP256(der)) => {
            crypto::verify_signature(&sig_key.verifying_key()?, &transcript, der)?;
        }
        _ => return Err(Error::Signature),
    }
    let enc_key = PublicKey::from_hex(enc_pub.as_str())?;
    // The header's sender kid must match the declared encryption key.
    if envelope.header.skid != kid(b"enc", &enc_key.0) {
        return Err(Error::Pairing(
            "sender key id does not match declared key".into(),
        ));
    }

    if nonce_store.seen(&envelope.header.skid, &envelope.header.n) {
        return Err(Error::Replay);
    }
    nonce_store.record(
        &envelope.header.skid,
        &envelope.header.n,
        envelope.header.exp,
    );

    let pin = PeerPin {
        label: device.name.clone(),
        enc_pub: enc_key.to_hex(),
        sig_pub: sig_key.to_hex(),
        paired_at: now,
        webauthn: None,
    };
    Ok((Zeroizing::new(body), pin))
}

fn open_psk_envelope(
    expected: MessageType,
    secret: &PairingSecret,
    envelope: &Envelope,
    now: u64,
    policy: &Policy,
    nonce_store: &mut dyn NonceStore,
) -> Result<(Zeroizing<Body>, PeerPin)> {
    if envelope.header.v != VERSION {
        return Err(Error::Version(envelope.header.v));
    }
    if envelope.header.t != expected as u8 {
        return Err(Error::MessageTypeMismatch(expected));
    }
    if !envelope.enc.is_empty() {
        return Err(Error::Pairing(
            "pairing envelope must not carry an HPKE enc".into(),
        ));
    }
    policy.validate(&envelope.header, now)?;

    let plaintext = Zeroizing::new(crypto::psk_open(
        secret.as_bytes(),
        envelope.header.t,
        &envelope.aad(),
        &envelope.ct,
    )?);
    let body: Body = serde_json::from_slice(&plaintext)?;
    if body.message_type() != expected {
        return Err(Error::MessageTypeMismatch(body.message_type()));
    }

    let (device, enc_pub, sig_pub) = match &body {
        Body::PairingRequest {
            device,
            enc_pub,
            sig_pub,
        } => (device, enc_pub, sig_pub),
        _ => return Err(Error::MessageTypeMismatch(expected)),
    };
    let sig_key = PublicKey::from_hex(sig_pub.as_str())?;
    let enc_key = PublicKey::from_hex(enc_pub.as_str())?;
    let transcript = envelope.signed_transcript();
    match &envelope.signature {
        Some(Signature::EcdsaP256(der)) => {
            crypto::verify_signature(&sig_key.verifying_key()?, &transcript, der)?;
        }
        _ => return Err(Error::Signature),
    }
    if envelope.header.skid != kid(b"enc", &enc_key.0) {
        return Err(Error::Pairing(
            "sender key id does not match declared key".into(),
        ));
    }

    if nonce_store.seen(&envelope.header.skid, &envelope.header.n) {
        return Err(Error::Replay);
    }
    nonce_store.record(
        &envelope.header.skid,
        &envelope.header.n,
        envelope.header.exp,
    );

    let pin = PeerPin {
        label: device.name.clone(),
        enc_pub: enc_key.to_hex(),
        sig_pub: sig_key.to_hex(),
        paired_at: now,
        webauthn: None,
    };
    Ok((Zeroizing::new(body), pin))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replay::InMemoryNonceStore;
    use rand::rngs::OsRng;

    fn full_flow() {
        let mut rng = OsRng;
        let cli = IdentityKeys::generate(&mut rng).unwrap();
        let phone = IdentityKeys::generate(&mut rng).unwrap();
        let secret = PairingSecret::generate(&mut rng);
        let policy = Policy::default();
        let now = 1000;

        let cli_pin_from_secret = PeerPin {
            label: "mbp".into(),
            enc_pub: hex_encode(&cli.encryption_public()),
            sig_pub: hex_encode(&cli.verifying_key().to_sec1_bytes()),
            paired_at: now,
            webauthn: None,
        };

        let request = seal_pairing_request(
            &mut rng,
            &secret,
            &cli,
            DeviceInfo {
                kind: "cli".into(),
                name: "mbp".into(),
                version: "4".into(),
            },
            now,
            &policy,
        )
        .unwrap();
        let mut store = InMemoryNonceStore::default();
        let (_body, cli_pin) =
            open_pairing_request(&secret, &request, now + 1, &policy, &mut store).unwrap();
        assert_eq!(cli_pin.enc_pub, cli_pin_from_secret.enc_pub);
        assert_eq!(cli_pin.sig_pub, cli_pin_from_secret.sig_pub);
        assert_eq!(cli_pin.label, "mbp");

        // Phone -> CLI response (normal HPKE now that the CLI key is known).
        let response = seal_pairing_response(
            &mut rng,
            &phone,
            &cli_pin,
            DeviceInfo {
                kind: "phone".into(),
                name: "anssi-iphone".into(),
                version: "1".into(),
            },
            now,
            &policy,
        )
        .unwrap();
        let (_body, phone_pin) =
            open_pairing_response(&cli, &response, now + 1, &policy, &mut store).unwrap();
        assert_eq!(phone_pin.enc_pub, hex_encode(&phone.encryption_public()));
        assert_eq!(
            phone_pin.sig_pub,
            hex_encode(&phone.verifying_key().to_sec1_bytes())
        );
        assert_eq!(phone_pin.label, "anssi-iphone");
    }

    #[test]
    fn pairing_full_flow() {
        full_flow();
    }

    #[test]
    fn wrong_secret_rejected() {
        let mut rng = OsRng;
        let cli = IdentityKeys::generate(&mut rng).unwrap();
        let secret = PairingSecret::generate(&mut rng);
        let wrong = PairingSecret::generate(&mut rng);
        let policy = Policy::default();
        let request = seal_pairing_request(
            &mut rng,
            &secret,
            &cli,
            DeviceInfo {
                kind: "cli".into(),
                name: "mbp".into(),
                version: "4".into(),
            },
            1,
            &policy,
        )
        .unwrap();
        let mut store = InMemoryNonceStore::default();
        assert!(open_pairing_request(&wrong, &request, 2, &policy, &mut store).is_err());
    }

    #[test]
    fn tampered_pairing_request_rejected() {
        let mut rng = OsRng;
        let cli = IdentityKeys::generate(&mut rng).unwrap();
        let secret = PairingSecret::generate(&mut rng);
        let policy = Policy::default();
        let request = seal_pairing_request(
            &mut rng,
            &secret,
            &cli,
            DeviceInfo {
                kind: "cli".into(),
                name: "mbp".into(),
                version: "4".into(),
            },
            1,
            &policy,
        )
        .unwrap();
        let mut wire = request.to_bytes();
        let last = wire.len() - 1;
        wire[last] ^= 1;
        let parsed = Envelope::from_bytes(&wire).unwrap();
        let mut store = InMemoryNonceStore::default();
        assert!(open_pairing_request(&secret, &parsed, 2, &policy, &mut store).is_err());
    }

    #[test]
    fn replayed_pairing_request_rejected() {
        let mut rng = OsRng;
        let cli = IdentityKeys::generate(&mut rng).unwrap();
        let secret = PairingSecret::generate(&mut rng);
        let policy = Policy::default();
        let request = seal_pairing_request(
            &mut rng,
            &secret,
            &cli,
            DeviceInfo {
                kind: "cli".into(),
                name: "mbp".into(),
                version: "4".into(),
            },
            1,
            &policy,
        )
        .unwrap();
        let mut store = InMemoryNonceStore::default();
        assert!(open_pairing_request(&secret, &request, 2, &policy, &mut store).is_ok());
        assert!(matches!(
            open_pairing_request(&secret, &request, 2, &policy, &mut store),
            Err(Error::Replay)
        ));
    }

    #[test]
    fn pairing_response_from_unrequested_key_fails() {
        let mut rng = OsRng;
        let cli = IdentityKeys::generate(&mut rng).unwrap();
        let phone = IdentityKeys::generate(&mut rng).unwrap();
        let policy = Policy::default();
        // Response sealed to a *different* CLI key than the one opening it.
        let other_cli = IdentityKeys::generate(&mut rng).unwrap();
        let cli_pin = PeerPin {
            label: "mbp".into(),
            enc_pub: hex_encode(&other_cli.encryption_public()),
            sig_pub: hex_encode(&other_cli.verifying_key().to_sec1_bytes()),
            paired_at: 0,
            webauthn: None,
        };
        let response = seal_pairing_response(
            &mut rng,
            &phone,
            &cli_pin,
            DeviceInfo {
                kind: "phone".into(),
                name: "p".into(),
                version: "1".into(),
            },
            1,
            &policy,
        )
        .unwrap();
        let mut store = InMemoryNonceStore::default();
        assert!(open_pairing_response(&cli, &response, 2, &policy, &mut store).is_err());
    }
}
