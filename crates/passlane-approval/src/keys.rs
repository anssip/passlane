//! Identity keys, key ids and pinned peers.
//!
//! Every party in the protocol holds two P-256 key pairs:
//!
//! - an **encryption** key pair, used as the HPKE recipient identity
//!   (`DHKEM(P-256)`); on the phone this key can live in the Secure Enclave,
//!   which supports P-256 ECDH;
//! - a **signing** key pair (ECDSA P-256, SHA-256), used to authenticate
//!   outgoing envelopes; on the phone this is the Secure Enclave key gated
//!   by `biometryCurrentSet`.
//!
//! A key id (`kid`) is the first 8 bytes of `SHA-256(purpose || public_key)`
//! in hex — 16 characters, enough to route and pin without collisions in a
//! personal fleet of devices.

use std::fmt;

use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::crypto::{self, HpkeBytes};
use crate::encoding::{hex_decode, hex_encode};
use crate::error::{Error, Result};

/// A full set of protocol identity keys for one party.
///
/// Both fields wipe themselves on drop (`Zeroizing` and the ecdsa crate's
/// `SigningKey` drop-guard respectively).
pub struct IdentityKeys {
    /// HPKE (encryption) private key: a raw 32-byte P-256 scalar.
    enc_secret: Zeroizing<Vec<u8>>,
    /// ECDSA P-256 signing key.
    sig_secret: SigningKey,
}

impl IdentityKeys {
    /// Generate fresh identity keys.
    pub fn generate(rng: &mut (impl CryptoRng + RngCore)) -> Result<Self> {
        let enc = crypto::random_secret_key(rng)?;
        let sig = crypto::random_secret_key(rng)?;
        Ok(Self {
            enc_secret: Zeroizing::new(enc.to_bytes().to_vec()),
            sig_secret: SigningKey::from(&sig),
        })
    }

    /// Restore identity keys from persisted bytes (see [`crate::store`]).
    pub fn from_bytes(enc_secret: &[u8], sig_secret: &[u8]) -> Result<Self> {
        crypto::validate_secret_scalar(enc_secret)?;
        let sig = crypto::secret_key_from_bytes(sig_secret)?;
        Ok(Self {
            enc_secret: Zeroizing::new(enc_secret.to_vec()),
            sig_secret: SigningKey::from(&sig),
        })
    }

    /// The private key bytes, for persistence by the caller.
    pub fn secret_bytes(&self) -> (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>) {
        (
            Zeroizing::new(self.enc_secret.to_vec()),
            Zeroizing::new(self.sig_secret.to_bytes().to_vec()),
        )
    }

    /// The HPKE public key (65-byte uncompressed SEC1).
    pub fn encryption_public(&self) -> [u8; 65] {
        crypto::encryption_public(&self.enc_secret)
    }

    /// The ECDSA verifying key.
    pub fn verifying_key(&self) -> VerifyingKey {
        *self.sig_secret.verifying_key()
    }

    pub(crate) fn hpke_secret(&self) -> HpkeBytes {
        self.enc_secret.to_vec()
    }

    /// Key id of this party's encryption identity (see [`crate::keys`] docs).
    pub fn encryption_kid(&self) -> String {
        kid(b"enc", &self.encryption_public())
    }

    /// Key id of this party's signing identity.
    pub fn signing_kid(&self) -> String {
        kid(b"sig", &self.verifying_key().to_sec1_bytes())
    }

    pub(crate) fn sign(&self, message: &[u8]) -> Signature {
        use p256::ecdsa::signature::Signer;
        self.sig_secret.sign(message)
    }
}

impl fmt::Debug for IdentityKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityKeys")
            .field("encryption_kid", &self.encryption_kid())
            .field("signing_kid", &self.signing_kid())
            .finish_non_exhaustive()
    }
}

/// Compute a key id: first 8 bytes of `SHA-256(purpose || public)` as hex.
pub fn kid(purpose: &[u8], public: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(purpose);
    h.update(public);
    let digest = h.finalize();
    hex_encode(&digest[..8])
}

/// A public P-256 key, hex-encoded SEC1 (uncompressed, 65 bytes).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(pub [u8; 65]);

impl PublicKey {
    /// Parse a 65-byte uncompressed SEC1 key from hex.
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex_decode(s)?;
        Self::from_bytes(&bytes)
    }

    /// Parse a 65-byte uncompressed SEC1 key; rejects points not on the curve.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; 65] = bytes.try_into().map_err(|_| {
            Error::Key(format!(
                "expected 65-byte SEC1 key, got {} bytes",
                bytes.len()
            ))
        })?;
        // Reject invalid points early with a clear error.
        VerifyingKey::from_sec1_bytes(&arr)
            .map_err(|_| Error::Key("point is not on P-256".into()))?;
        Ok(Self(arr))
    }

    /// Hex form (65 bytes uncompressed SEC1).
    pub fn to_hex(self) -> String {
        hex_encode(&self.0)
    }

    /// The ECDSA verifying key for signature checks.
    pub fn verifying_key(&self) -> Result<VerifyingKey> {
        VerifyingKey::from_sec1_bytes(&self.0)
            .map_err(|_| Error::Key("invalid verifying key".into()))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.to_hex())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Extra pinning metadata for Phase 0 approvers that are WebAuthn passkeys
/// on the static approval page rather than (yet) the iOS app.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WebauthnPin {
    /// The WebAuthn Relying Party id (a registrable domain), e.g. `approve.passlane.app`.
    pub rp_id: String,
    /// The origin the client data must carry, e.g. `https://approve.passlane.app`.
    pub origin: String,
}
/// A pinned peer: the keys this device trusts for the other end.
///
/// Pins are established by the pairing exchange (see [`crate::pairing`]) or —
/// for Phase 0 passkeys — by an explicit enrollment ceremony.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PeerPin {
    /// Human-facing label, e.g. `anssi-iphone` or `macbook-pro`.
    pub label: String,
    /// Pinned HPKE (encryption) public key, hex SEC1.
    pub enc_pub: String,
    /// Pinned ECDSA verifying key, hex SEC1.
    pub sig_pub: String,
    /// Unix time the pin was created.
    pub paired_at: u64,
    /// Present when the peer is a WebAuthn passkey (Phase 0 page).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webauthn: Option<WebauthnPin>,
}

impl PeerPin {
    /// Build a pin from public keys.
    pub fn new(label: &str, enc_pub: PublicKey, sig_pub: PublicKey, paired_at: u64) -> Self {
        Self {
            label: label.to_string(),
            enc_pub: enc_pub.to_hex(),
            sig_pub: sig_pub.to_hex(),
            paired_at,
            webauthn: None,
        }
    }

    /// The key id of the pinned encryption key.
    pub fn enc_kid(&self) -> Result<String> {
        let key = PublicKey::from_hex(&self.enc_pub)?;
        Ok(kid(b"enc", &key.0))
    }

    /// The pinned verifying key.
    pub fn sig_pub_key(&self) -> Result<PublicKey> {
        PublicKey::from_hex(&self.sig_pub)
    }

    /// The pinned encryption key as raw SEC1 bytes.
    pub fn enc_pub_bytes(&self) -> Result<[u8; 65]> {
        Ok(PublicKey::from_hex(&self.enc_pub)?.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn identity_keys_roundtrip_through_bytes() {
        let keys = IdentityKeys::generate(&mut OsRng).unwrap();
        let (enc, sig) = keys.secret_bytes();
        let restored = IdentityKeys::from_bytes(&enc, &sig).unwrap();
        assert_eq!(restored.encryption_public(), keys.encryption_public());
        assert_eq!(
            restored.verifying_key().to_sec1_bytes(),
            keys.verifying_key().to_sec1_bytes()
        );
        assert_eq!(restored.encryption_kid(), keys.encryption_kid());
        assert_eq!(restored.signing_kid(), keys.signing_kid());
    }

    #[test]
    fn kids_are_stable_and_purpose_separated() {
        let keys = IdentityKeys::generate(&mut OsRng).unwrap();
        let pub_hex = keys.encryption_public();
        assert_eq!(keys.encryption_kid(), kid(b"enc", &pub_hex));
        assert_ne!(keys.encryption_kid(), keys.signing_kid());
        assert_eq!(keys.encryption_kid().len(), 16);
    }

    #[test]
    fn public_key_rejects_wrong_lengths() {
        assert!(PublicKey::from_bytes(&[0u8; 64]).is_err());
        assert!(PublicKey::from_bytes(&[0x04; 65]).is_err()); // not on curve
        assert!(PublicKey::from_hex("0102").is_err());
    }

    #[test]
    fn peer_pin_kid_matches() {
        let keys = IdentityKeys::generate(&mut OsRng).unwrap();
        let pin = PeerPin::new(
            "test",
            PublicKey(keys.encryption_public()),
            PublicKey::from_bytes(&keys.verifying_key().to_sec1_bytes()).unwrap(),
            0,
        );
        assert_eq!(pin.enc_kid().unwrap(), keys.encryption_kid());
        assert!(pin.webauthn.is_none());
    }
}
