//! # passlane-approval
//!
//! Message format and cryptography for the passlane approval protocol: the
//! shared implementation behind **phone-as-key** vault unlocking and **agent
//! approvals**.
//!
//! Messages are self-contained, end-to-end-encrypted, one-shot envelopes that
//! travel over untrusted relays — a QR code in the terminal and a link in a
//! chat (v1), Bluetooth LE (v1.1), the user's own CloudKit (v1.2). No
//! channel is trusted; all security lives in this format.
//!
//! The crate is deliberately standalone: no keepass-ng, no I/O, no CLI
//! concepts. The CLI, the future session agent, and (via UniFFI) the iOS app
//! and the static approval page all consume the same wire format.
//!
//! ## Cryptographic profile
//!
//! - **HPKE** (RFC 9180) base mode, `DHKEM(P-256)` + `HKDF-SHA256` +
//!   `AES-256-GCM` — one-shot public-key encryption to a pinned peer.
//! - **ECDSA P-256 / SHA-256** sender signatures over the envelope
//!   transcript; on the phone these are Secure Enclave keys gated by
//!   biometry, on the Phase 0 page they are WebAuthn passkey assertions.
//! - **AES-256-GCM under an HKDF-derived key** for the pairing exchange,
//!   which cannot use public-key encryption because no keys are pinned yet.
//!
//! ## Example
//!
//! Pair two parties, then run an approval round-trip:
//!
//! ```
//! use passlane_approval::prelude::*;
//! use zeroize::Zeroizing;
//! # fn main() -> passlane_approval::Result<()> {
//! use rand::rngs::OsRng;
//! let mut rng = OsRng;
//! let policy = Policy::default();
//!
//! // -- one-time pairing (QR scan stands in for the transport) --
//! let cli = IdentityKeys::generate(&mut rng)?;
//! let phone = IdentityKeys::generate(&mut rng)?;
//! let secret = PairingSecret::generate(&mut rng);
//! assert_eq!(secret.confirmation_code(), secret.confirmation_code());
//!
//! let request = seal_pairing_request(
//!     &mut rng, &secret, &cli,
//!     DeviceInfo { kind: "cli".into(), name: "macbook".into(), version: "4".into() },
//!     1_000, &policy)?;
//! let mut store = InMemoryNonceStore::default();
//! let (_body, cli_pin) = open_pairing_request(&secret, &request, 1_001, &policy, &mut store)?;
//!
//! let response = seal_pairing_response(
//!     &mut rng, &phone, &cli_pin,
//!     DeviceInfo { kind: "phone".into(), name: "iphone".into(), version: "1".into() },
//!     1_000, &policy)?;
//! let (_body, phone_pin) = open_pairing_response(&cli, &response, 1_001, &policy, &mut store)?;
//!
//! // -- an approval round-trip (link/QR transport) --
//! let request = seal(&mut rng, &cli, &phone_pin, Body::ApprovalRequest {
//!     vault_id: "v1".into(),
//!     vault_name: "Main".into(),
//!     operation: Operation::Unlock,
//!     requester: "anssi@macbook".into(),
//!     scope: Scope::Once,
//!     challenge: Some(SecretHex::from_bytes(&[0x11; 20])),
//! }, 2_000, &policy)?;
//!
//! // ... the envelope travels as `request.to_base64url()` ...
//!
//! let opened: Zeroizing<Body> = open(&phone, &[cli_pin], &request, 2_050, &policy, &mut store)?;
//! assert_eq!(opened.message_type(), MessageType::ApprovalRequest);
//! # Ok(())
//! # }
//! ```
//!
//! See `SPEC.md` for the full protocol, threat model and the
//! HPKE-versus-Noise rationale.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod crypto;
pub mod encoding;
pub mod error;
pub mod keys;
pub mod message;
pub mod pairing;
pub mod policy;
pub mod replay;
pub mod store;
pub mod webauthn;

pub mod envelope;

pub use crate::error::{Error, Result};

/// Everything worth importing in one `use`.
pub mod prelude {
    pub use crate::envelope::{Envelope, Signature, open, seal};
    pub use crate::error::{Error, Result};
    pub use crate::keys::{IdentityKeys, PeerPin, PublicKey, WebauthnPin};
    pub use crate::message::{
        Body, Decision, DeviceInfo, Header, MessageType, Operation, Scope, SecretHex, VERSION,
    };
    pub use crate::pairing::{
        PairingSecret, open_pairing_request, open_pairing_response, seal_pairing_request,
        seal_pairing_response,
    };
    pub use crate::policy::{Policy, RateLimiter, SlidingWindowRateLimiter};
    pub use crate::replay::{FileNonceStore, InMemoryNonceStore, NonceStore};
    pub use crate::webauthn::WebauthnAssertion;
}
