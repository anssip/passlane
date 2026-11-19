//! The wire envelope: framing, sealing and opening.
//!
//! Layout (all integers little-endian):
//!
//! ```text
//! offset  size  field
//! 0       4     magic "PLAP"
//! 4       1     version (= message::VERSION)
//! 5       1     message type (u8 form of MessageType)
//! 6       1     signature kind: 0 none, 1 ECDSA-P256 DER, 2 WebAuthn ES256
//! 7       2     header length
//! 9       n     header (compact JSON, cleartext)
//! .       2     enc length        } HPKE: 65 bytes; PSK pairing: 0
//! .       n     enc (ephemeral)   }
//! .       4     ciphertext length
//! .       n     ciphertext (AEAD, includes tag)
//! .       2     signature length
//! .       n     signature
//! ```
//!
//! The **AAD** for the AEAD layer is everything before the ciphertext —
//! the header is cleartext but cannot be modified without breaking
//! decryption. The **signature** covers everything before the signature
//! block, so a pinned sender is bound to the exact bytes of the message.
//!
//! `seal`/`open` handle HPKE-encrypted messages between pinned peers.
//! Pairing envelopes (PSK mode, no recipient key yet) live in [`crate::pairing`].

use zeroize::Zeroizing;

use crate::crypto;
use crate::encoding::{base64url_decode, base64url_encode};
use crate::error::{Error, Result};
use crate::keys::{IdentityKeys, PeerPin, kid};
use crate::message::{Body, Header, MessageType, VERSION};
use crate::policy::Policy;
use crate::replay::NonceStore;
use crate::webauthn::WebauthnAssertion;

/// Envelope magic bytes (`PLAP`).
pub const MAGIC: [u8; 4] = *b"PLAP";

const SIG_KIND_NONE: u8 = 0;
const SIG_KIND_ECDSA_P256: u8 = 1;
const SIG_KIND_WEBAUTHN: u8 = 2;

/// Decode limits, so hostile input cannot request absurd allocations.
const MAX_HEADER_LEN: usize = 4096;
const MAX_ENC_LEN: usize = 1024;
const MAX_CT_LEN: usize = 1 << 20;
/// Ceiling on the base64url form — real envelopes are under 2 KiB encoded.
const MAX_ENCODED_LEN: usize = 8192;

/// The signature block of an envelope.
#[derive(Clone, PartialEq)]
pub enum Signature {
    /// DER-encoded ECDSA P-256 over SHA-256(transcript).
    EcdsaP256(Vec<u8>),
    /// A WebAuthn assertion whose challenge commits to the transcript
    /// (Phase 0 approvers: passkeys on the static page).
    WebauthnEs256(WebauthnAssertion),
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EcdsaP256(bytes) => f
                .debug_struct("EcdsaP256")
                .field("len", &bytes.len())
                .finish(),
            Self::WebauthnEs256(a) => f.debug_tuple("WebauthnEs256").field(a).finish(),
        }
    }
}

/// A sealed message, decodable from (and encodable to) exact wire bytes.
#[derive(Clone, Debug, PartialEq)]
pub struct Envelope {
    /// The cleartext routing header. crate-private: the authenticated wire
    /// form is cached in `header_bytes`, and callers must not be able to
    /// mutate the parsed copy — the freshness/replay checks read it while
    /// the signature and AEAD authenticate the cached bytes. External
    /// readers get [`Envelope::header`].
    pub(crate) header: Header,
    /// The exact header bytes as they appear on the wire (signed verbatim).
    pub(crate) header_bytes: Vec<u8>,
    /// HPKE ephemeral shared secret (`enc`); empty for PSK envelopes.
    pub enc: Vec<u8>,
    /// AEAD ciphertext including the authentication tag.
    pub ct: Vec<u8>,
    /// The sender's signature, if any.
    pub signature: Option<Signature>,
}

impl Envelope {
    /// Serialize to wire bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let sig = match &self.signature {
            None => (SIG_KIND_NONE, Vec::new()),
            Some(Signature::EcdsaP256(der)) => (SIG_KIND_ECDSA_P256, der.clone()),
            Some(Signature::WebauthnEs256(a)) => (
                SIG_KIND_WEBAUTHN,
                serde_json::to_vec(a).expect("assertion serializes"),
            ),
        };
        let mut out = Vec::with_capacity(
            9 + self.header_bytes.len() + 2 + self.enc.len() + 4 + self.ct.len() + 2 + sig.1.len(),
        );
        out.extend_from_slice(&MAGIC);
        out.push(self.header.v);
        out.push(self.header.t);
        out.push(sig.0);
        out.extend_from_slice(&(self.header_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.header_bytes);
        out.extend_from_slice(&(self.enc.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.enc);
        out.extend_from_slice(&(self.ct.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.ct);
        out.extend_from_slice(&(sig.1.len() as u16).to_le_bytes());
        out.extend_from_slice(&sig.1);
        out
    }

    /// Parse wire bytes. Strict: trailing garbage is rejected.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader { bytes, pos: 0 };

        let magic: [u8; 4] = r.take(4)?.try_into().unwrap();
        if magic != MAGIC {
            return Err(Error::Malformed("bad magic".into()));
        }
        let version = r.u8()?;
        if version != VERSION {
            return Err(Error::Version(version));
        }
        let msg_type = r.u8()?;
        MessageType::from_u8(msg_type)?; // validate early
        let sig_kind = r.u8()?;

        let header_len = r.u16()? as usize;
        if header_len == 0 || header_len > MAX_HEADER_LEN {
            return Err(Error::Malformed(format!(
                "header length {header_len} out of bounds"
            )));
        }
        let header_bytes = r.take(header_len)?.to_vec();
        let header: Header = serde_json::from_slice(&header_bytes)?;
        if header.v != VERSION || header.t != msg_type {
            return Err(Error::Malformed("header/version mismatch".into()));
        }

        let enc_len = r.u16()? as usize;
        if enc_len > MAX_ENC_LEN {
            return Err(Error::Malformed(format!(
                "enc length {enc_len} out of bounds"
            )));
        }
        let enc = r.take(enc_len)?.to_vec();

        let ct_len = r.u32()? as usize;
        if ct_len == 0 || ct_len > MAX_CT_LEN {
            return Err(Error::Malformed(format!(
                "ciphertext length {ct_len} out of bounds"
            )));
        }
        let ct = r.take(ct_len)?.to_vec();

        let sig_len = r.u16()? as usize;
        let sig_bytes = r.take(sig_len)?.to_vec();
        r.expect_end()?;

        let signature = match sig_kind {
            SIG_KIND_NONE => {
                if !sig_bytes.is_empty() {
                    return Err(Error::Malformed("signature bytes with kind none".into()));
                }
                None
            }
            SIG_KIND_ECDSA_P256 => Some(Signature::EcdsaP256(sig_bytes)),
            SIG_KIND_WEBAUTHN => Some(Signature::WebauthnEs256(serde_json::from_slice(
                &sig_bytes,
            )?)),
            other => return Err(Error::Malformed(format!("unknown signature kind {other}"))),
        };

        Ok(Self {
            header,
            header_bytes,
            enc,
            ct,
            signature,
        })
    }

    /// Wire bytes as unpadded base64url — the form that travels in links
    /// and QR payloads.
    pub fn to_base64url(&self) -> String {
        base64url_encode(&self.to_bytes())
    }

    /// Parse from unpadded base64url.
    ///
    /// Rejects oversized input up front: real envelopes are under 2 KiB
    /// encoded, and letting `base64url_decode` allocate first would let a
    /// hostile relay exhaust memory before framing is even checked.
    pub fn from_base64url(s: &str) -> Result<Self> {
        if s.len() > MAX_ENCODED_LEN {
            return Err(Error::Malformed(format!(
                "encoded envelope is {} bytes; the protocol never exceeds {MAX_ENCODED_LEN}",
                s.len()
            )));
        }
        Self::from_bytes(&base64url_decode(s)?)
    }

    /// The parsed header (read-only). The authenticated wire form is cached
    /// internally; callers cannot mutate the parsed copy out from under the
    /// signature and AEAD binding.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// The bytes covered by the signature: everything before the signature
    /// block (magic .. ciphertext).
    pub fn signed_transcript(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            9 + self.header_bytes.len() + 2 + self.enc.len() + 4 + self.ct.len(),
        );
        out.extend_from_slice(&MAGIC);
        out.push(self.header.v);
        out.push(self.header.t);
        // Signature kind is part of the transcript: flipping 1 <-> 2 must
        // invalidate.
        out.push(self.signature_kind());
        out.extend_from_slice(&(self.header_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.header_bytes);
        out.extend_from_slice(&(self.enc.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.enc);
        out.extend_from_slice(&(self.ct.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.ct);
        out
    }

    /// The AEAD AAD: everything before the `enc` field (magic .. header).
    pub fn aad(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(9 + self.header_bytes.len());
        out.extend_from_slice(&MAGIC);
        out.push(self.header.v);
        out.push(self.header.t);
        out.push(self.signature_kind());
        out.extend_from_slice(&(self.header_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.header_bytes);
        out
    }

    /// The WebAuthn challenge for a Phase 0 response: base64url of
    /// SHA-256(transcript). The assertion is made over this value.
    pub fn webauthn_challenge(&self) -> String {
        base64url_encode(&crypto::sha256(&self.signed_transcript()))
    }

    fn signature_kind(&self) -> u8 {
        match &self.signature {
            None => SIG_KIND_NONE,
            Some(Signature::EcdsaP256(_)) => SIG_KIND_ECDSA_P256,
            Some(Signature::WebauthnEs256(_)) => SIG_KIND_WEBAUTHN,
        }
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.bytes.len() {
            return Err(Error::Malformed("envelope truncated".into()));
        }
        let out = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn expect_end(&self) -> Result<()> {
        if self.pos != self.bytes.len() {
            return Err(Error::Malformed("trailing bytes after envelope".into()));
        }
        Ok(())
    }
}

fn random_hex32(rng: &mut (impl rand::CryptoRng + rand::RngCore)) -> Result<String> {
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes); // OsRng-style fill
    Ok(crate::encoding::hex_encode(&bytes))
}

/// Random 16-byte nonce/request-id, hex-encoded (32 chars).
pub(crate) fn random_nonce_hex(rng: &mut (impl rand::CryptoRng + rand::RngCore)) -> Result<String> {
    random_hex32(rng)
}

/// Seal a body into an HPKE envelope for a pinned peer, signed by us.
/// Generates a fresh request id (`rid`).
pub fn seal(
    rng: &mut (impl rand::CryptoRng + rand::RngCore),
    local: &IdentityKeys,
    peer: &PeerPin,
    body: Body,
    now: u64,
    policy: &Policy,
) -> Result<Envelope> {
    seal_inner(
        rng,
        local,
        peer,
        body,
        None,
        Signature::EcdsaP256(Vec::new()),
        now,
        policy,
    )
}

/// Seal a **response** that answers a specific request: the header echoes
/// `in_reply_to` (the request's `rid`), as SPEC §4 requires — receivers
/// match pending requests by `rid` before accepting an approval.
pub fn seal_reply(
    rng: &mut (impl rand::CryptoRng + rand::RngCore),
    local: &IdentityKeys,
    peer: &PeerPin,
    body: Body,
    in_reply_to: &str,
    now: u64,
    policy: &Policy,
) -> Result<Envelope> {
    seal_inner(
        rng,
        local,
        peer,
        body,
        Some(in_reply_to),
        Signature::EcdsaP256(Vec::new()),
        now,
        policy,
    )
}

/// Begin a Phase 0 **WebAuthn** response: seals the body with the
/// signature-kind byte set to 2 (so the AAD binds the assertion form) and
/// returns the unsigned envelope plus the base64url challenge the page's
/// `navigator.credentials.get()` must sign. Finish with
/// [`attach_webauthn_assertion`].
// Eight parameters: the pairing context (secret + request) is part of the
// ceremony and splitting it into a builder would obscure the flow.
#[allow(clippy::too_many_arguments)]
pub fn seal_webauthn(
    rng: &mut (impl rand::CryptoRng + rand::RngCore),
    local: &IdentityKeys,
    peer: &PeerPin,
    body: Body,
    in_reply_to: &str,
    now: u64,
    policy: &Policy,
) -> Result<(Envelope, String)> {
    let env = seal_inner(
        rng,
        local,
        peer,
        body,
        Some(in_reply_to),
        Signature::WebauthnEs256(crate::webauthn::WebauthnAssertion {
            authenticator_data: String::new(),
            client_data_json: String::new(),
            signature: String::new(),
        }),
        now,
        policy,
    )?;
    let challenge = env.webauthn_challenge();
    Ok((env, challenge))
}

/// Complete a [`seal_webauthn`] envelope with the assertion produced over
/// its challenge. The envelope is otherwise ready; no re-encryption happens.
pub fn attach_webauthn_assertion(
    mut env: Envelope,
    assertion: crate::webauthn::WebauthnAssertion,
) -> Envelope {
    // The placeholder assertion only shaped the kind byte and byte lengths;
    // the three fields serialize to fixed-shape empty strings, so swapping
    // in the real assertion preserves the signed framing exactly.
    env.signature = Some(Signature::WebauthnEs256(assertion));
    env
}

// The internal core shares the full parameter set by design (see the
// public wrappers' note).
#[allow(clippy::too_many_arguments)]
fn seal_inner(
    rng: &mut (impl rand::CryptoRng + rand::RngCore),
    local: &IdentityKeys,
    peer: &PeerPin,
    body: Body,
    in_reply_to: Option<&str>,
    placeholder_signature: Signature,
    now: u64,
    policy: &Policy,
) -> Result<Envelope> {
    body.validate()?;
    if let Body::ApprovalRequest { scope, .. } | Body::ApprovalResponse { scope, .. } = &body {
        policy.validate_scope(*scope)?;
    }
    let msg_type = body.message_type();
    let header = Header {
        v: VERSION,
        t: msg_type as u8,
        n: random_hex32(rng)?,
        ts: now,
        exp: now + policy.ttl_secs,
        skid: local.encryption_kid(),
        rkid: kid(b"enc", &peer.enc_pub_bytes()?),
        rid: match in_reply_to {
            Some(rid) => rid.to_string(),
            None => random_hex32(rng)?,
        },
    };
    let header_bytes = serde_json::to_vec(&header)?;
    let plaintext = Zeroizing::new(serde_json::to_vec(&body)?);

    // AAD and transcript both embed the signature-kind byte, so build the
    // frame with the final kind and a placeholder signature first.
    let frame = Envelope {
        header: header.clone(),
        header_bytes: header_bytes.clone(),
        enc: Vec::new(),
        ct: Vec::new(),
        signature: Some(placeholder_signature),
    };
    let (enc, ct) = crypto::hpke_seal(&peer.enc_pub_bytes()?, header.t, &frame.aad(), &plaintext)?;

    let mut env = Envelope {
        header,
        header_bytes,
        enc,
        ct,
        signature: frame.signature,
    };
    if matches!(env.signature, Some(Signature::EcdsaP256(_))) {
        // CLI/app path: sign directly with our signing key.
        let transcript = env.signed_transcript();
        let der = local.sign(&transcript).to_der();
        env.signature = Some(Signature::EcdsaP256(der.as_bytes().to_vec()));
    }
    // WebAuthn path: the assertion arrives out-of-band (the page);
    // the placeholder framing stays untouched.
    Ok(env)
}

/// Open an HPKE envelope from a pinned peer.
///
/// Verification order (cheapest and least secret-leaking first):
/// version → freshness policy → sender pinning → signature → AEAD →
/// body consistency → replay recording.
pub fn open(
    local: &IdentityKeys,
    peers: &[PeerPin],
    envelope: &Envelope,
    now: u64,
    policy: &Policy,
    nonce_store: &mut dyn NonceStore,
) -> Result<Zeroizing<Body>> {
    if envelope.header.v != VERSION {
        return Err(Error::Version(envelope.header.v));
    }
    policy.validate(&envelope.header, now)?;

    let peer = peers
        .iter()
        .find(|p| p.enc_kid().ok().as_deref() == Some(envelope.header.skid.as_str()))
        .ok_or_else(|| Error::UnknownSender(envelope.header.skid.clone()))?;

    let verifying_key = peer.sig_pub_key()?.verifying_key()?;
    let transcript = envelope.signed_transcript();
    match &envelope.signature {
        Some(Signature::EcdsaP256(der)) => {
            crypto::verify_signature(&verifying_key, &transcript, der)?;
        }
        Some(Signature::WebauthnEs256(assertion)) => {
            // WebAuthn assertions only verify for peers pinned as passkeys:
            // the pinned RP id and origin bind the page that produced them.
            let pin = peer.webauthn.as_ref().ok_or(Error::Signature)?;
            crate::webauthn::verify_assertion(
                &verifying_key,
                &pin.rp_id,
                &pin.origin,
                assertion,
                &envelope.webauthn_challenge(),
            )?;
        }
        None => return Err(Error::Signature),
    }

    let expected_rkid = kid(b"enc", &local.encryption_public());
    if envelope.header.rkid != expected_rkid {
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
    if body.message_type() as u8 != envelope.header.t {
        return Err(Error::MessageTypeMismatch(body.message_type()));
    }
    body.validate()?;
    if let Body::ApprovalRequest { scope, .. } | Body::ApprovalResponse { scope, .. } = &body {
        policy.validate_scope(*scope)?;
    }

    if nonce_store.seen(&envelope.header.skid, &envelope.header.n) {
        return Err(Error::Replay);
    }
    nonce_store.record(
        &envelope.header.skid,
        &envelope.header.n,
        envelope.header.exp,
    );
    Ok(Zeroizing::new(body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::PublicKey;
    use crate::message::{Decision, Operation, Scope};
    use rand::rngs::OsRng;

    fn cli_and_phone() -> (IdentityKeys, IdentityKeys, PeerPin, PeerPin) {
        let cli = IdentityKeys::generate(&mut OsRng).unwrap();
        let phone = IdentityKeys::generate(&mut OsRng).unwrap();
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
        (cli, phone, phone_pin, cli_pin)
    }

    fn sample_request() -> Body {
        Body::ApprovalRequest {
            vault_id: "vault-1".into(),
            vault_name: "Main".into(),
            operation: Operation::Reveal {
                entry: "GitHub".into(),
                field: "password".into(),
            },
            requester: "anssi@macbook".into(),
            scope: Scope::Once,
            challenge: Some(crate::message::SecretHex::from_bytes(&[9u8; 32])),
        }
    }

    #[test]
    fn seal_open_roundtrip_all_types() {
        let (cli, phone, phone_pin, cli_pin) = cli_and_phone();
        let policy = Policy::default();
        let bodies = vec![
            sample_request(),
            Body::ApprovalResponse {
                decision: Decision::Allow,
                scope: Scope::Timed { seconds: 60 },
                response: Some(crate::message::SecretHex::from_bytes(&[3u8; 20])),
            },
            Body::SessionRevoke {
                session_id: "s1".into(),
                reason: "rotating".into(),
            },
        ];
        for body in bodies {
            let env = seal(&mut OsRng, &cli, &phone_pin, body.clone(), 1000, &policy).unwrap();
            let wire = env.to_bytes();
            let parsed = Envelope::from_bytes(&wire).unwrap();
            assert_eq!(parsed, env);
            let mut store = crate::replay::InMemoryNonceStore::default();
            let opened = open(
                &phone,
                std::slice::from_ref(&cli_pin),
                &parsed,
                1100,
                &policy,
                &mut store,
            )
            .unwrap();
            assert_eq!(*opened, body);
        }
    }

    #[test]
    fn base64url_roundtrip() {
        let (cli, _p, phone_pin, _) = cli_and_phone();
        let env = seal(
            &mut OsRng,
            &cli,
            &phone_pin,
            sample_request(),
            1,
            &Policy::default(),
        )
        .unwrap();
        let b64 = env.to_base64url();
        assert!(!b64.contains('='));
        assert_eq!(Envelope::from_base64url(&b64).unwrap(), env);
    }

    #[test]
    fn tamper_header_rejected() {
        let (cli, phone, phone_pin, cli_pin) = cli_and_phone();
        let env = seal(
            &mut OsRng,
            &cli,
            &phone_pin,
            sample_request(),
            1000,
            &Policy::default(),
        )
        .unwrap();
        let mut wire = env.to_bytes();
        // Flip a byte inside the header region (offset 9..header_len).
        wire[12] ^= 0x01;
        // The flip either breaks parsing outright or must fail open().
        if let Ok(parsed) = Envelope::from_bytes(&wire) {
            let mut store = crate::replay::InMemoryNonceStore::default();
            assert!(
                open(
                    &phone,
                    &[cli_pin],
                    &parsed,
                    1100,
                    &Policy::default(),
                    &mut store
                )
                .is_err()
            );
        }
    }

    #[test]
    fn tamper_ciphertext_rejected() {
        let (cli, phone, phone_pin, cli_pin) = cli_and_phone();
        let env = seal(
            &mut OsRng,
            &cli,
            &phone_pin,
            sample_request(),
            1000,
            &Policy::default(),
        )
        .unwrap();
        let mut wire = env.to_bytes();
        // Flip a byte inside the ciphertext: framing stays valid, the
        // signature over the transcript breaks.
        let header_len = u16::from_le_bytes([wire[7], wire[8]]) as usize;
        let ct_offset = 9 + header_len + 2 + env.enc.len() + 4 + 5;
        wire[ct_offset] ^= 0x01;
        let parsed = Envelope::from_bytes(&wire).unwrap();
        let mut store = crate::replay::InMemoryNonceStore::default();
        assert!(matches!(
            open(
                &phone,
                &[cli_pin],
                &parsed,
                1100,
                &Policy::default(),
                &mut store
            ),
            Err(Error::Signature)
        ));
    }

    #[test]
    fn tamper_signature_rejected() {
        let (cli, phone, phone_pin, cli_pin) = cli_and_phone();
        let env = seal(
            &mut OsRng,
            &cli,
            &phone_pin,
            sample_request(),
            1000,
            &Policy::default(),
        )
        .unwrap();
        let mut wire = env.to_bytes();
        let last = wire.len() - 1;
        wire[last] ^= 0x02;
        let parsed = Envelope::from_bytes(&wire).unwrap();
        let mut store = crate::replay::InMemoryNonceStore::default();
        assert!(matches!(
            open(
                &phone,
                &[cli_pin],
                &parsed,
                1100,
                &Policy::default(),
                &mut store
            ),
            Err(Error::Signature)
        ));
    }

    #[test]
    fn replay_rejected() {
        let (cli, phone, phone_pin, cli_pin) = cli_and_phone();
        let env = seal(
            &mut OsRng,
            &cli,
            &phone_pin,
            sample_request(),
            1000,
            &Policy::default(),
        )
        .unwrap();
        let mut store = crate::replay::InMemoryNonceStore::default();
        assert!(
            open(
                &phone,
                std::slice::from_ref(&cli_pin),
                &env,
                1100,
                &Policy::default(),
                &mut store
            )
            .is_ok()
        );
        assert!(matches!(
            open(
                &phone,
                &[cli_pin],
                &env,
                1100,
                &Policy::default(),
                &mut store
            ),
            Err(Error::Replay)
        ));
    }

    #[test]
    fn unknown_sender_rejected() {
        let (cli, phone, phone_pin, _cli_pin) = cli_and_phone();
        let env = seal(
            &mut OsRng,
            &cli,
            &phone_pin,
            sample_request(),
            1000,
            &Policy::default(),
        )
        .unwrap();
        let mut store = crate::replay::InMemoryNonceStore::default();
        // phone opens but no pins configured
        assert!(matches!(
            open(&phone, &[], &env, 1100, &Policy::default(), &mut store),
            Err(Error::UnknownSender(_))
        ));
    }

    #[test]
    fn wrong_recipient_rejected() {
        let (cli, _phone, phone_pin, cli_pin) = cli_and_phone();
        let bystander = IdentityKeys::generate(&mut OsRng).unwrap();
        let env = seal(
            &mut OsRng,
            &cli,
            &phone_pin,
            sample_request(),
            1000,
            &Policy::default(),
        )
        .unwrap();
        let mut store = crate::replay::InMemoryNonceStore::default();
        // Signature verifies (sender is pinned) but the envelope is addressed
        // to the phone, not the bystander.
        assert!(matches!(
            open(
                &bystander,
                &[cli_pin],
                &env,
                1100,
                &Policy::default(),
                &mut store
            ),
            Err(Error::WrongRecipient(_))
        ));
    }

    #[test]
    fn expired_rejected() {
        let (cli, phone, phone_pin, cli_pin) = cli_and_phone();
        let env = seal(
            &mut OsRng,
            &cli,
            &phone_pin,
            sample_request(),
            1000,
            &Policy::default(),
        )
        .unwrap();
        let mut store = crate::replay::InMemoryNonceStore::default();
        let later = 1000 + Policy::default().ttl_secs;
        assert!(matches!(
            open(
                &phone,
                &[cli_pin],
                &env,
                later,
                &Policy::default(),
                &mut store
            ),
            Err(Error::Expired(_))
        ));
    }

    #[test]
    fn truncated_and_garbage_rejected() {
        let (cli, _p, phone_pin, _) = cli_and_phone();
        let env = seal(
            &mut OsRng,
            &cli,
            &phone_pin,
            sample_request(),
            1,
            &Policy::default(),
        )
        .unwrap();
        let wire = env.to_bytes();
        for cut in [0usize, 3, 9, 15, wire.len() - 1] {
            assert!(
                Envelope::from_bytes(&wire[..cut]).is_err(),
                "cut {cut} must fail"
            );
        }
        assert!(Envelope::from_bytes(b"XXXX").is_err());
        // trailing garbage
        let mut extended = wire.clone();
        extended.push(0);
        assert!(Envelope::from_bytes(&extended).is_err());
    }

    #[test]
    fn oversized_session_scope_rejected_at_seal() {
        let (cli, _p, phone_pin, _) = cli_and_phone();
        let policy = Policy::default();
        let body = Body::ApprovalResponse {
            decision: Decision::Allow,
            scope: Scope::Timed { seconds: u32::MAX },
            response: None,
        };
        assert!(seal(&mut OsRng, &cli, &phone_pin, body, 1, &policy).is_err());
    }

    #[test]
    fn webauthn_challenge_is_stable_serialization() {
        let (cli, _p, phone_pin, _) = cli_and_phone();
        let env = seal(
            &mut OsRng,
            &cli,
            &phone_pin,
            sample_request(),
            1,
            &Policy::default(),
        )
        .unwrap();
        let reparsed = Envelope::from_bytes(&env.to_bytes()).unwrap();
        assert_eq!(env.webauthn_challenge(), reparsed.webauthn_challenge());
        assert!(!env.webauthn_challenge().is_empty());
    }

    #[test]
    fn oversized_base64url_rejected_before_decoding() {
        let huge = "A".repeat(8193);
        assert!(matches!(
            Envelope::from_base64url(&huge),
            Err(Error::Malformed(_))
        ));
        // A normal envelope still parses.
        let (cli, _p, phone_pin, _) = cli_and_phone();
        let env = seal(
            &mut OsRng,
            &cli,
            &phone_pin,
            sample_request(),
            1,
            &Policy::default(),
        )
        .unwrap();
        assert!(env.to_base64url().len() <= 8192);
        assert!(Envelope::from_base64url(&env.to_base64url()).is_ok());
    }

    #[test]
    fn webauthn_seal_open_roundtrip() {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        use p256::ecdsa::{Signature, SigningKey};
        use sha2::{Digest, Sha256};

        // The CLI and a Phase 0 approver: a page holding a WebCrypto ECDH
        // key (the encryption identity) and a passkey (the signing
        // identity). A local key stands in for the authenticator. The CLI's
        // pin of the page carries the passkey's public key plus the WebAuthn
        // RP metadata; the page's pin of the CLI is the recipient pin.
        let (cli, page, _phone_pin, cli_pin) = cli_and_phone();
        let passkey = SigningKey::from(&crate::crypto::random_secret_key(&mut OsRng).unwrap());
        let page_pin = crate::keys::PeerPin {
            label: "approval-page".into(),
            enc_pub: crate::encoding::hex_encode(&page.encryption_public()),
            sig_pub: crate::encoding::hex_encode(&passkey.verifying_key().to_sec1_bytes()),
            paired_at: 0,
            webauthn: Some(crate::keys::WebauthnPin {
                rp_id: "approve.passlane.test".into(),
                origin: "https://approve.passlane.test".into(),
            }),
        };

        let policy = Policy::default();
        let now = 1_000u64;
        let body = Body::ApprovalResponse {
            decision: Decision::Allow,
            scope: Scope::Once,
            response: None,
        };
        let (pending, challenge) = seal_webauthn(
            &mut OsRng,
            &page,
            &cli_pin,
            body.clone(),
            &"a".repeat(32),
            now,
            &policy,
        )
        .unwrap();

        // The page signs the WebAuthn transcript with the passkey.
        let rp_hash = Sha256::digest(b"approve.passlane.test");
        let mut auth_data = Vec::with_capacity(37);
        auth_data.extend_from_slice(&rp_hash);
        auth_data.push(0x01); // UP flag
        auth_data.extend_from_slice(&0u32.to_be_bytes());
        let client_data_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"https://approve.passlane.test"}}"#
        );
        let mut digest = Sha256::new();
        digest.update(&auth_data);
        digest.update(Sha256::digest(client_data_json.as_bytes()));
        let sig: Signature = passkey.sign_prehash(&digest.finalize()).unwrap();
        let assertion = crate::webauthn::WebauthnAssertion::from_raw(
            &auth_data,
            client_data_json.as_bytes(),
            sig.to_der().as_bytes(),
        );

        let env = attach_webauthn_assertion(pending, assertion);
        let mut store = crate::replay::InMemoryNonceStore::default();
        let opened = open(
            &cli,
            std::slice::from_ref(&page_pin),
            &env,
            now + 1,
            &policy,
            &mut store,
        )
        .unwrap();
        assert_eq!(*opened, body);
        assert_eq!(env.header().rid, "a".repeat(32));
    }
}
