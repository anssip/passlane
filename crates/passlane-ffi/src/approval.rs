//! The approval-protocol surface for the iOS phone-key service
//! (passlane#82, feeding [passlane-ios#2]).
//!
//! A thin, byte-oriented image of [`passlane_approval`]: every function
//! maps types and bytes and nothing more — the protocol logic stays in
//! the protocol crate. The surface is **stateless where possible**:
//! key material, pins and results cross as explicit bytes or records,
//! because the app persists in its own Keychain and app-group container,
//! not in any directory the CLI owns. The two objects that do hold state
//! hold exactly the app's session:
//!
//! - [`ApprovalIdentity`] — this device's protocol identity keys, built
//!   from Keychain bytes or generated, zeroized when released;
//! - [`ApprovalNonceStore`] — replay protection over a file path the app
//!   passes (its app-group container; see its docs for why the
//!   file-backed store won over a byte snapshot).
//!
//! # What the app drives
//!
//! - **Pairing**: [`approval_open_pairing_request`] (the QR's secret and
//!   the request envelope in, the CLI's pin out), then the human confirms
//!   [`approval_pairing_confirmation_code`] /
//!   [`approval_pairing_mutual_confirmation_code`] across the two
//!   displays, then [`approval_seal_pairing_response`] back. The
//!   CLI-side halves ([`approval_seal_pairing_request`],
//!   [`approval_open_pairing_response`]) are exposed for symmetry and
//!   the round-trip tests.
//! - **Approving**: [`approval_open_request`] verifies and decrypts a
//!   request envelope (peer-pin check, freshness, signature, replay) and
//!   returns [`OpenedApprovalRequest`] for the approval screen; Face ID
//!   gates what the app does next; [`approval_answer_challenge`] turns
//!   the held phone-key secret plus the request's challenge into the
//!   20-byte answer; [`approval_seal_decision`] signs and seals the
//!   decision, echoing the request id, as the base64url blob the CLI
//!   redeems.
//! - **Enrollment** (the sheet scan-back check): the
//!   [`approval_enrollment_challenge`] /
//!   [`approval_enrollment_confirmation_code`] /
//!   [`approval_verify_webauthn_assertion`] trio from the protocol
//!   crate's Phase 0 ceremony, plus
//!   [`approval_generate_phone_key_secret`] for the key the recovery
//!   sheet carries.
//!
//! # The agent-answer path (the recorded decision)
//!
//! The HMAC-SHA1 answer the session agent redeems — HMAC over the vault
//! challenge with the phone-held secret — is **not** covered by the
//! existing vault surface: [`ChallengeFactor`][crate::ChallengeFactor] +
//! `PasslaneVault::open` *verify* a secret by opening a vault **file**,
//! and the phone-key service has no vault file at hand — the challenge
//! arrives inside the request envelope. So the computation had to join
//! the surface, and it lives in the protocol crate
//! (`passlane_approval::message::answer_challenge`, the same
//! construction keepass-ng's `LocalChallenge` and CryptoKit implement)
//! with [`approval_answer_challenge`] as its byte-oriented FFI image:
//! secret and challenge in as `Data`, answer out as [`SecretBytes`].
//!
//! # Secrets and Swift shapes
//!
//! Secrets — the identity scalars, the phone-held key, the challenge
//! answer, the pairing secret — cross as `Data` parameters (scrubbed by
//! the callee) or as [`SecretBytes`] objects (zeroized on release),
//! never as fields of a record: every record and enum below maps to a
//! Swift *value* type holding only values (strings, integers, bytes),
//! so the generated Swift stays `Sendable`-friendly with no
//! reference-type escapes. Public keys inside [`ApprovalPeerPin`] are
//! hex strings, the pin's exact persisted form — they are public
//! material, not secrets. Envelopes cross as the unpadded base64url
//! string that is the wire form in links and QR codes (whitespace is
//! tolerated, as the CLI's paste path tolerates it).
//!
//! [passlane-ios#2]: https://github.com/anssip/passlane-ios/issues/2

use std::sync::{Arc, Mutex};

use passlane_approval::keys::{IdentityKeys, PeerPin, PublicKey};
use passlane_approval::message::{self, Body, Decision, DeviceInfo, Operation, Scope, SecretHex};
use passlane_approval::pairing::{
    PairingSecret, open_pairing_request, open_pairing_response, seal_pairing_request,
    seal_pairing_response,
};
use passlane_approval::policy::Policy;
use passlane_approval::replay::{FileNonceStore, NonceStore};
use passlane_approval::webauthn;
use passlane_approval::{envelope, error};
use rand::rngs::OsRng;
use zeroize::{Zeroize, Zeroizing};

use crate::SecretBytes;

// -- errors ------------------------------------------------------------------

/// An approval-protocol operation failed. The variants the app can act on
/// (replay, expiry, an unpinned sender, a wrong recipient) are
/// distinguished; everything else carries the protocol crate's
/// user-presentable message, which never contains secret material.
#[derive(Debug, uniffi::Error)]
pub enum ApprovalError {
    /// The message's nonce was already seen for this sender — the same
    /// envelope presented twice.
    Replay,
    /// The message expired at `at` (unix seconds).
    Expired { at: u64 },
    /// The sender's key id is not pinned (an unknown device).
    UnknownSender { kid: String },
    /// The envelope is addressed to a different device's key.
    WrongRecipient { kid: String },
    /// The signature did not verify — tampering or a wrong pinned key.
    Signature,
    /// Decryption failed — wrong keys, or the ciphertext was modified.
    Decrypt,
    /// A freshness rule refused the message (clock skew, TTL shape, a
    /// decision outside its request's window, redemption past the bound).
    Freshness { message: String },
    /// The input bytes are not a well-formed envelope / key / hex.
    Malformed { message: String },
    /// Key material is invalid (wrong length, not on the curve).
    Key { message: String },
    /// A pairing envelope was rejected.
    Pairing { message: String },
    /// A WebAuthn assertion failed verification.
    Webauthn { message: String },
    /// An I/O error (the nonce store's file).
    Io { message: String },
}

impl From<error::Error> for ApprovalError {
    fn from(e: error::Error) -> Self {
        match e {
            error::Error::Replay => Self::Replay,
            error::Error::Expired(at) => Self::Expired { at },
            error::Error::UnknownSender(kid) => Self::UnknownSender { kid },
            error::Error::WrongRecipient(kid) => Self::WrongRecipient { kid },
            error::Error::Signature => Self::Signature,
            error::Error::Decrypt | error::Error::Hpke(_) => Self::Decrypt,
            error::Error::ClockSkew(_)
            | error::Error::Ttl
            | error::Error::DecisionOutsideWindow { .. }
            | error::Error::RedemptionTooLate { .. }
            | error::Error::SessionTooLong(_) => Self::Freshness {
                message: e.to_string(),
            },
            error::Error::Version(v) => Self::Malformed {
                message: format!("unsupported envelope version {v}"),
            },
            error::Error::Malformed(m) => Self::Malformed { message: m },
            error::Error::Encoding(m) => Self::Malformed { message: m },
            error::Error::Json(e) => Self::Malformed {
                message: e.to_string(),
            },
            error::Error::MessageTypeMismatch(t) => Self::Malformed {
                message: format!("the message type {t:?} does not match the body"),
            },
            error::Error::Key(m) => Self::Key { message: m },
            error::Error::Webauthn(m) => Self::Webauthn { message: m },
            error::Error::Pairing(m) => Self::Pairing { message: m },
            error::Error::Io(e) => Self::Io {
                message: e.to_string(),
            },
        }
    }
}

impl std::fmt::Display for ApprovalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // User-presentable text: the protocol crate's messages already
        // read as sentences, and none of them carries secret material.
        match self {
            Self::Replay => {
                write!(f, "This message was already used; a fresh request is needed.")
            }
            Self::Expired { at } => write!(f, "The message expired at {at}."),
            Self::UnknownSender { kid } => write!(
                f,
                "The sender (key id {kid}) is not a paired device; nothing was answered."
            ),
            Self::WrongRecipient { kid } => write!(
                f,
                "The message is addressed to another device's key (key id {kid})."
            ),
            Self::Signature => write!(f, "The message's signature did not verify."),
            Self::Decrypt => write!(
                f,
                "The message could not be decrypted: wrong keys, or the bytes were modified."
            ),
            Self::Freshness { message }
            | Self::Malformed { message }
            | Self::Key { message }
            | Self::Pairing { message }
            | Self::Webauthn { message }
            | Self::Io { message } => write!(f, "{message}"),
        }
    }
}

// -- records and enums -------------------------------------------------------

/// Descriptive identity of the sending device, shown on approval screens.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ApprovalDeviceInfo {
    /// One of `cli`, `phone`, `page`.
    pub kind: String,
    /// Free-form name, e.g. `macbook-pro` or `anssi-iphone`.
    pub name: String,
    /// Software version of the sender.
    pub version: String,
}

impl From<&DeviceInfo> for ApprovalDeviceInfo {
    fn from(device: &DeviceInfo) -> Self {
        Self {
            kind: device.kind.clone(),
            name: device.name.clone(),
            version: device.version.clone(),
        }
    }
}

impl From<ApprovalDeviceInfo> for DeviceInfo {
    fn from(device: ApprovalDeviceInfo) -> Self {
        Self {
            kind: device.kind,
            name: device.name,
            version: device.version,
        }
    }
}

/// Extra pinning metadata when the peer is a WebAuthn passkey (the
/// Phase 0 static approval page rather than the app).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ApprovalWebauthnPin {
    /// The WebAuthn Relying Party id (a registrable domain).
    pub rp_id: String,
    /// The origin the client data must carry, e.g. `https://…`.
    pub origin: String,
}

/// A pinned peer: the public keys this device trusts for the other end,
/// exactly as the protocol crate persists them. Public material, not
/// secret — the hex strings are the pin's canonical form, so the app can
/// persist the record's fields as-is in its Keychain.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ApprovalPeerPin {
    /// Human-facing label, e.g. `anssi-iphone` or `macbook-pro`.
    pub label: String,
    /// The pinned HPKE (encryption) public key: 65-byte uncompressed
    /// SEC1, hex (130 characters).
    pub enc_pub: String,
    /// The pinned ECDSA verifying key: 65-byte uncompressed SEC1, hex.
    pub sig_pub: String,
    /// Unix time the pin was created.
    pub paired_at: u64,
    /// Present when the peer is a WebAuthn passkey (the Phase 0 page).
    pub webauthn: Option<ApprovalWebauthnPin>,
}

impl ApprovalPeerPin {
    /// The protocol crate's pin, validating the key shapes first so a
    /// corrupt pin surfaces here rather than deep inside an open path.
    fn to_protocol(&self) -> Result<PeerPin, ApprovalError> {
        PublicKey::from_hex(&self.enc_pub)?;
        PublicKey::from_hex(&self.sig_pub)?;
        Ok(PeerPin {
            label: self.label.clone(),
            enc_pub: self.enc_pub.clone(),
            sig_pub: self.sig_pub.clone(),
            paired_at: self.paired_at,
            webauthn: self.webauthn.as_ref().map(|w| passlane_approval::keys::WebauthnPin {
                rp_id: w.rp_id.clone(),
                origin: w.origin.clone(),
            }),
        })
    }
}

impl From<PeerPin> for ApprovalPeerPin {
    fn from(pin: PeerPin) -> Self {
        Self {
            label: pin.label,
            enc_pub: pin.enc_pub,
            sig_pub: pin.sig_pub,
            paired_at: pin.paired_at,
            webauthn: pin.webauthn.map(|w| ApprovalWebauthnPin {
                rp_id: w.rp_id,
                origin: w.origin,
            }),
        }
    }
}

/// The freshness and session limits applied to every opened envelope.
/// Built with [`approval_default_policy`] (or
/// [`approval_ceremony_policy`] for the single-shot human ceremonies);
/// one struct so the CLI, the agent and the app agree on the numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct ApprovalPolicy {
    /// How long a sealed message stays valid.
    pub ttl_secs: u64,
    /// TTL for single-shot human ceremonies (`enroll_key`, `save`).
    pub ceremony_ttl_secs: u64,
    /// Ceiling on message TTLs a receiver accepts.
    pub max_ttl_secs: u64,
    /// How far a sender timestamp may lie from the receiver's clock.
    pub max_clock_skew_secs: u64,
    /// Ceiling on a timed approval's reuse window.
    pub max_session_secs: u64,
}

impl ApprovalPolicy {
    fn to_protocol(self) -> Policy {
        Policy {
            ttl_secs: self.ttl_secs,
            ceremony_ttl_secs: self.ceremony_ttl_secs,
            max_ttl_secs: self.max_ttl_secs,
            max_clock_skew_secs: self.max_clock_skew_secs,
            max_session_secs: self.max_session_secs,
        }
    }
}

impl From<Policy> for ApprovalPolicy {
    fn from(policy: Policy) -> Self {
        Self {
            ttl_secs: policy.ttl_secs,
            ceremony_ttl_secs: policy.ceremony_ttl_secs,
            max_ttl_secs: policy.max_ttl_secs,
            max_clock_skew_secs: policy.max_clock_skew_secs,
            max_session_secs: policy.max_session_secs,
        }
    }
}

/// What the request asks the approver to permit.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum ApprovalOperation {
    /// Reveal one secret field of one entry.
    Reveal {
        /// Entry title (or match string) identifying the entry.
        entry: String,
        /// The field being revealed, e.g. `password`.
        field: String,
    },
    /// Supply the challenge-response needed to open the vault.
    Unlock,
    /// Permit a save.
    Save,
    /// Create a phone-held challenge-response key for the vault and
    /// answer the request's challenge with it (the enrollment ceremony;
    /// the answer doubles as the recovery-sheet scan-back confirmation).
    EnrollKey,
}

impl From<&Operation> for ApprovalOperation {
    fn from(operation: &Operation) -> Self {
        match operation {
            Operation::Reveal { entry, field } => Self::Reveal {
                entry: entry.clone(),
                field: field.clone(),
            },
            Operation::Unlock => Self::Unlock,
            Operation::Save => Self::Save,
            Operation::EnrollKey => Self::EnrollKey,
        }
    }
}

impl From<ApprovalOperation> for Operation {
    fn from(operation: ApprovalOperation) -> Self {
        match operation {
            ApprovalOperation::Reveal { entry, field } => Self::Reveal { entry, field },
            ApprovalOperation::Unlock => Self::Unlock,
            ApprovalOperation::Save => Self::Save,
            ApprovalOperation::EnrollKey => Self::EnrollKey,
        }
    }
}

/// How long an approval may be reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ApprovalScope {
    /// Single use.
    Once,
    /// Reusable for `seconds` (validated against the policy cap).
    Timed { seconds: u32 },
}

impl From<Scope> for ApprovalScope {
    fn from(scope: Scope) -> Self {
        match scope {
            Scope::Once => Self::Once,
            Scope::Timed { seconds } => Self::Timed { seconds },
        }
    }
}

impl From<ApprovalScope> for Scope {
    fn from(scope: ApprovalScope) -> Self {
        match scope {
            ApprovalScope::Once => Self::Once,
            ApprovalScope::Timed { seconds } => Self::Timed { seconds },
        }
    }
}

/// The approver's answer to seal with [`approval_seal_decision`].
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum ApprovalDecision {
    /// Approved.
    Allow,
    /// Refused, with an optional reason shown to the requester.
    Deny { reason: Option<String> },
}

impl From<ApprovalDecision> for Decision {
    fn from(decision: ApprovalDecision) -> Self {
        match decision {
            ApprovalDecision::Allow => Self::Allow,
            ApprovalDecision::Deny { reason } => Self::Deny { reason },
        }
    }
}

impl From<&Decision> for ApprovalDecision {
    fn from(decision: &Decision) -> Self {
        match decision {
            Decision::Allow => Self::Allow,
            Decision::Deny { reason } => Self::Deny {
                reason: reason.clone(),
            },
        }
    }
}

/// The verified, decrypted approval request for the approval screen:
/// every field the PLAN §3.2 UI shows — the vault, the operation, the
/// requester's stated identity — plus the header ids that drive the
/// answer (`request_id` to echo, `sender_kid` to resolve the asking
/// device's label from the app's own pin list; the request body itself
/// carries no device info).
///
/// Metadata only: the request's challenge is fetched through
/// [`OpenedApprovalRequest::challenge`] when the approved operation
/// needs it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ApprovalRequestView {
    /// Registry id of the target vault.
    pub vault_id: String,
    /// Display name of the target vault.
    pub vault_name: String,
    /// What is being asked.
    pub operation: ApprovalOperation,
    /// Who is asking (user@host for the CLI).
    pub requester: String,
    /// How long the requester suggests the approval be reusable.
    pub scope: ApprovalScope,
    /// The request id the response must echo.
    pub request_id: String,
    /// The sender's key id — match it against the app's pins' `enc_kid`
    /// (see [`approval_pin_enc_kid`]) to name the asking device on the
    /// approval screen.
    pub sender_kid: String,
    /// When the request was sealed (unix seconds).
    pub sent_at: u64,
    /// When the request expires (unix seconds).
    pub expires_at: u64,
}

/// The result of opening a pairing envelope: who introduced itself, and
/// the pin to persist — only after the human confirms the confirmation
/// codes match across the two displays (the open functions succeeding
/// is *not* enough; see the confirmation-code functions).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ApprovalPairingHandshake {
    /// The sender's descriptive identity.
    pub device: ApprovalDeviceInfo,
    /// The sender's pin, built from the decrypted, verified body.
    pub sender: ApprovalPeerPin,
}

// -- objects -----------------------------------------------------------------

/// This device's protocol identity: one HPKE (encryption) key pair and
/// one ECDSA (signing) key pair, held in Rust memory and zeroized when
/// the object is released.
///
/// Built by [`ApprovalIdentity::generate`] on first run or
/// [`ApprovalIdentity::from_secret_bytes`] from the Keychain bytes
/// [`ApprovalIdentity::secret_encryption_key`] /
/// [`ApprovalIdentity::secret_signing_key`] hand out for persistence.
/// v1 holds software keys; a Secure-Enclave identity (non-extractable,
/// biometry-gated) would need a signing callback in a later revision —
/// deliberately out of this surface, which has no callbacks.
///
/// The private scalars never appear in `Debug` output and never cross
/// back out except through the two secret accessors.
#[derive(uniffi::Object)]
pub struct ApprovalIdentity {
    keys: IdentityKeys,
}

#[uniffi::export]
impl ApprovalIdentity {
    /// Generate fresh identity keys (rejection-sampled P-256 scalars).
    #[uniffi::constructor]
    pub fn generate() -> Result<Self, ApprovalError> {
        Ok(Self {
            keys: IdentityKeys::generate(&mut OsRng)?,
        })
    }

    /// Restore the identity from persisted secret bytes: the HPKE
    /// private key (32 bytes) and the ECDSA private key (32 bytes), as
    /// handed out by the secret accessors. Both parameter buffers are
    /// scrubbed once the keys are built, whatever the outcome.
    #[uniffi::constructor]
    pub fn from_secret_bytes(
        enc_secret: Vec<u8>,
        sig_secret: Vec<u8>,
    ) -> Result<Self, ApprovalError> {
        let mut enc_secret = enc_secret;
        let mut sig_secret = sig_secret;
        let keys = IdentityKeys::from_bytes(&enc_secret, &sig_secret);
        enc_secret.zeroize();
        sig_secret.zeroize();
        Ok(Self { keys: keys? })
    }

    /// The HPKE private key bytes (32) for Keychain persistence, as a
    /// zeroized [`SecretBytes`].
    pub fn secret_encryption_key(&self) -> Arc<SecretBytes> {
        let (enc, _) = self.keys.secret_bytes();
        Arc::new(SecretBytes { bytes: enc })
    }

    /// The ECDSA private key bytes (32) for Keychain persistence, as a
    /// zeroized [`SecretBytes`].
    pub fn secret_signing_key(&self) -> Arc<SecretBytes> {
        let (_, sig) = self.keys.secret_bytes();
        Arc::new(SecretBytes { bytes: sig })
    }

    /// The HPKE public key: 65-byte uncompressed SEC1.
    pub fn encryption_public(&self) -> Vec<u8> {
        self.keys.encryption_public().to_vec()
    }

    /// The ECDSA verifying key: 65-byte uncompressed SEC1.
    pub fn verifying_public(&self) -> Vec<u8> {
        self.keys.verifying_key().to_sec1_bytes().to_vec()
    }

    /// The key id of the encryption identity (16 hex characters).
    pub fn encryption_kid(&self) -> String {
        self.keys.encryption_kid()
    }

    /// The key id of the signing identity (16 hex characters).
    pub fn signing_kid(&self) -> String {
        self.keys.signing_kid()
    }
}

impl std::fmt::Debug for ApprovalIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApprovalIdentity")
            .field("encryption_kid", &self.keys.encryption_kid())
            .field("signing_kid", &self.keys.signing_kid())
            .finish_non_exhaustive()
    }
}

/// Replay protection for opened envelopes, over a file the app owns.
///
/// **The recorded decision** (passlane#82): the app drives the window /
/// nonce check against its app-group container by passing this store a
/// path in it, reusing the protocol crate's `FileNonceStore` rather than
/// a byte-snapshot API. The file-backed store already gives what a
/// snapshot would make the app reimplement in Swift — atomic
/// write-then-rename persistence, owner-only permissions, and an
/// exclusive advisory lock, so the app and its extensions serialize on
/// one view of the nonces. No CLI-global state is involved: nothing is
/// read or written outside the path the app passes.
///
/// Hold one only while processing: the exclusive lock is held for the
/// object's lifetime, and a long-lived store would block another
/// process (an app extension) that loads the same path. The open
/// functions record a verified envelope's nonce and persist it before
/// returning, so dropping the object after one open loses nothing.
#[derive(uniffi::Object)]
pub struct ApprovalNonceStore {
    inner: Mutex<FileNonceStore>,
}

impl ApprovalNonceStore {
    /// Lock the store and run `f` against the file-backed one.
    fn with_inner<T>(
        &self,
        f: impl FnOnce(&mut FileNonceStore) -> Result<T, ApprovalError>,
    ) -> Result<T, ApprovalError> {
        // A panic while holding the lock leaves the map consistent (a
        // single insert at a time); poisoning is not a state to recover
        // from.
        let mut store = self
            .inner
            .lock()
            .expect("the nonce store is only locked while one envelope is opened");
        f(&mut store)
    }
}

#[uniffi::export]
impl ApprovalNonceStore {
    /// Load (or start) the store at `path`, taking the exclusive lock —
    /// blocks while another holder lives. `path` is a file path in the
    /// app's own containers; a sibling `<path>.lock` file is created.
    #[uniffi::constructor]
    pub fn load(path: String) -> Result<Self, ApprovalError> {
        Ok(Self {
            inner: Mutex::new(FileNonceStore::load(std::path::Path::new(&path))?),
        })
    }

    /// Persist the recorded nonces atomically (temp file + rename,
    /// owner-only permissions). The open functions already save what
    /// they recorded; this serves a caller-driven `prune`.
    pub fn save(&self) -> Result<(), ApprovalError> {
        self.with_inner(|store| Ok(store.save()?))
    }

    /// Drop entries whose expiry has passed `now`; call occasionally
    /// (the store grows by one entry per verified envelope otherwise).
    /// Persists the pruned state.
    pub fn prune(&self, now: u64) -> Result<(), ApprovalError> {
        self.with_inner(|store| {
            store.prune(now);
            Ok(store.save()?)
        })
    }
}

/// An approval request that passed full verification — version,
/// freshness, sender pinning, signature, AEAD and replay check — held
/// for the approval screen and the decision that answers it.
///
/// [`view`](Self::view) carries the metadata the UI shows;
/// [`challenge`](Self::challenge) fetches the request's 32-byte
/// challenge (present for `Unlock`/`Save`/`EnrollKey`) as a zeroized
/// [`SecretBytes`] when the approved decision needs to answer it. The
/// remaining plaintext is zeroized with the object.
#[derive(uniffi::Object)]
pub struct OpenedApprovalRequest {
    view: ApprovalRequestView,
    challenge: Option<Zeroizing<Vec<u8>>>,
}

#[uniffi::export]
impl OpenedApprovalRequest {
    /// The request's metadata for the approval screen.
    pub fn view(&self) -> ApprovalRequestView {
        self.view.clone()
    }

    /// The request's 32-byte challenge when the operation carries one
    /// (`Unlock`, `Save`, `EnrollKey`), as a zeroized [`SecretBytes`];
    /// `None` for `Reveal` requests. Feed it to
    /// [`approval_answer_challenge`] with the held phone-key secret.
    pub fn challenge(&self) -> Option<Arc<SecretBytes>> {
        self.challenge.as_ref().map(|c| secret_bytes(c))
    }
}

impl std::fmt::Debug for OpenedApprovalRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenedApprovalRequest")
            .field("view", &self.view)
            .field("challenge", &"<redacted>")
            .finish()
    }
}

/// Wrap a zeroizing copy of `bytes` (crate-internal builder for the
/// [`SecretBytes`] the approval surface hands out).
fn secret_bytes(bytes: &[u8]) -> Arc<SecretBytes> {
    Arc::new(SecretBytes {
        bytes: Zeroizing::new(bytes.to_vec()),
    })
}

// -- helpers -----------------------------------------------------------------

/// Ceiling on the raw envelope text accepted before normalization: 2×
/// the protocol decoder's encoded-envelope cap, leaving room for the
/// whitespace a pasted blob carries. Bounding here keeps a hostile link
/// from forcing an unbounded copy + scan before
/// `Envelope::from_base64url` can enforce its own limit — the guard the
/// decoder's memory-exhaustion defense relies on.
const MAX_WIRE_INPUT_LEN: usize = 16 * 1024;

/// Parse a wire envelope from the unpadded base64url form links and QR
/// codes carry. Whitespace is tolerated, as the CLI's paste path
/// tolerates it; every other deviation is rejected. The input is
/// length-bounded before the normalization allocates (see
/// [`MAX_WIRE_INPUT_LEN`]).
fn parse_envelope(encoded: &str) -> Result<envelope::Envelope, ApprovalError> {
    if encoded.len() > MAX_WIRE_INPUT_LEN {
        return Err(ApprovalError::Malformed {
            message: format!(
                "the envelope text is {} bytes; the protocol never exceeds {MAX_WIRE_INPUT_LEN}",
                encoded.len()
            ),
        });
    }
    let cleaned: String = encoded.chars().filter(|c| !c.is_whitespace()).collect();
    Ok(envelope::Envelope::from_base64url(&cleaned)?)
}

/// A 32-byte pairing secret from the bytes the app scanned out of the
/// pairing QR; the parameter buffer is the foreign side's copy and
/// leaves here zeroized.
fn pairing_secret(bytes: Vec<u8>) -> Result<PairingSecret, ApprovalError> {
    let bytes = Zeroizing::new(bytes);
    Ok(PairingSecret::from_bytes(&bytes)?)
}

// -- the surface -------------------------------------------------------------

/// The default policy: the numbers the CLI, the session agent and the
/// app all agree on (120 s clock skew, 300 s TTL, 900 s session cap).
#[uniffi::export]
pub fn approval_default_policy() -> ApprovalPolicy {
    Policy::default().into()
}

/// The ceremony policy: the default numbers with the longer single-shot
/// TTL for `enroll_key` and `save` requests, whose relay round trip
/// includes printing a recovery sheet and finding a terminal.
#[uniffi::export]
pub fn approval_ceremony_policy() -> ApprovalPolicy {
    Policy::default().for_ceremony().into()
}

/// Build a pin from public keys: `enc_pub`/`sig_pub` are 65-byte
/// uncompressed SEC1 keys, validated to be on the curve before the pin
/// is built. The pin is what the app persists after the pairing
/// ceremony's human confirmation.
#[uniffi::export]
pub fn approval_new_pin(
    label: String,
    enc_pub: Vec<u8>,
    sig_pub: Vec<u8>,
    paired_at: u64,
) -> Result<ApprovalPeerPin, ApprovalError> {
    let enc = PublicKey::from_bytes(&enc_pub)?;
    let sig = PublicKey::from_bytes(&sig_pub)?;
    Ok(PeerPin::new(&label, enc, sig, paired_at).into())
}

/// The key id of a pin's pinned encryption key — the id an opened
/// request's `sender_kid` is matched against.
#[uniffi::export]
pub fn approval_pin_enc_kid(pin: ApprovalPeerPin) -> Result<String, ApprovalError> {
    Ok(pin.to_protocol()?.enc_kid()?)
}

/// Compute a key id the way the protocol routes and pins: the first 8
/// bytes of `SHA-256(purpose ‖ public_key)` as hex (16 characters).
/// `purpose` is `"enc"` for encryption keys and `"sig"` for signing
/// keys; `public_key` is the 65-byte SEC1 key.
#[uniffi::export]
pub fn approval_kid(purpose: String, public_key: Vec<u8>) -> Result<String, ApprovalError> {
    PublicKey::from_bytes(&public_key)?;
    Ok(passlane_approval::keys::kid(
        purpose.as_bytes(),
        &public_key,
    ))
}

/// The twelve-digit pairing confirmation code bound to the CLI identity
/// being pinned — the **first** human check, shown by the phone (from
/// the QR's keys) and by the terminal. `secret` is the 32-byte pairing
/// secret scanned from the QR.
#[uniffi::export]
pub fn approval_pairing_confirmation_code(
    secret: Vec<u8>,
    cli: ApprovalPeerPin,
) -> Result<String, ApprovalError> {
    let secret = pairing_secret(secret)?;
    let cli = cli.to_protocol()?;
    Ok(secret.confirmation_code(&cli.enc_pub, &cli.sig_pub))
}

/// The twelve-digit **mutual** confirmation code binding the pairing
/// secret to **both** identities — the check that detects a substituted
/// pairing response: shown on the terminal (derived from the response's
/// keys) and on the phone (derived from the request), and compared by
/// the human before either side persists its pin.
#[uniffi::export]
pub fn approval_pairing_mutual_confirmation_code(
    secret: Vec<u8>,
    cli: ApprovalPeerPin,
    responder: ApprovalPeerPin,
) -> Result<String, ApprovalError> {
    let secret = pairing_secret(secret)?;
    let cli = cli.to_protocol()?;
    let responder = responder.to_protocol()?;
    Ok(secret.mutual_confirmation_code(
        &cli.enc_pub,
        &cli.sig_pub,
        &responder.enc_pub,
        &responder.sig_pub,
    ))
}

/// Seal a pairing request under the pairing secret, signed by `identity`
/// (the CLI role of the ceremony; the app side opens it with
/// [`approval_open_pairing_request`]). Returns the base64url envelope.
#[uniffi::export]
pub fn approval_seal_pairing_request(
    identity: Arc<ApprovalIdentity>,
    secret: Vec<u8>,
    device: ApprovalDeviceInfo,
    now: u64,
    policy: ApprovalPolicy,
) -> Result<String, ApprovalError> {
    let secret = pairing_secret(secret)?;
    let envelope = seal_pairing_request(
        &mut OsRng,
        &secret,
        &identity.keys,
        device.into(),
        now,
        &policy.to_protocol(),
    )?;
    Ok(envelope.to_base64url())
}

/// Open a pairing request with the secret scanned from the QR (the app
/// side of the ceremony). Full verification runs before the pin is
/// returned: freshness, the PSK decryption, the CLI's signature, the
/// declared keys' key id, and the replay check — the nonce is recorded
/// and persisted to the store's file before returning, so the same QR
/// cannot be answered twice even across an app restart.
///
/// The returned pin is **not yet trusted**: persist it only after the
/// human confirms [`approval_pairing_confirmation_code`] against the
/// terminal's display (and the mutual code once the response arrives).
#[uniffi::export]
pub fn approval_open_pairing_request(
    secret: Vec<u8>,
    envelope: String,
    now: u64,
    policy: ApprovalPolicy,
    nonces: Arc<ApprovalNonceStore>,
) -> Result<ApprovalPairingHandshake, ApprovalError> {
    let secret = pairing_secret(secret)?;
    let envelope = parse_envelope(&envelope)?;
    nonces.with_inner(|store| {
        let (body, pin) = open_pairing_request(
            &secret,
            &envelope,
            now,
            &policy.to_protocol(),
            store,
        )?;
        // Unreachable in practice: open_pairing_request validates the
        // body's message type — but this boundary never coerces.
        let device = match &*body {
            Body::PairingRequest { device, .. } => ApprovalDeviceInfo::from(device),
            _ => {
                return Err(ApprovalError::Malformed {
                    message: "the envelope does not carry a pairing request".to_string(),
                })
            }
        };
        store.save()?;
        Ok(ApprovalPairingHandshake {
            device,
            sender: pin.into(),
        })
    })
}

/// Seal the pairing response (the app side): HPKE-sealed to the CLI's
/// pinned key, signed by the app's identity, and bound to the pairing
/// secret via the HMAC proof that makes a forged response impossible.
/// `request_envelope` is the request exactly as it was opened, so the
/// response answers it (the request-id echo).
#[uniffi::export]
pub fn approval_seal_pairing_response(
    identity: Arc<ApprovalIdentity>,
    secret: Vec<u8>,
    cli: ApprovalPeerPin,
    request_envelope: String,
    device: ApprovalDeviceInfo,
    now: u64,
    policy: ApprovalPolicy,
) -> Result<String, ApprovalError> {
    let secret = pairing_secret(secret)?;
    let cli = cli.to_protocol()?;
    let request = parse_envelope(&request_envelope)?;
    let envelope = seal_pairing_response(
        &mut OsRng,
        &secret,
        &identity.keys,
        &cli,
        &request,
        device.into(),
        now,
        &policy.to_protocol(),
    )?;
    Ok(envelope.to_base64url())
}

/// Open a pairing response (the CLI role; exposed for symmetry and the
/// round-trip tests — the app never receives one). Verification is by
/// the pairing channel: HPKE to our key, the signature of the key the
/// body declares, and the HMAC binding proof under the QR-borne secret.
#[uniffi::export]
pub fn approval_open_pairing_response(
    identity: Arc<ApprovalIdentity>,
    secret: Vec<u8>,
    envelope: String,
    now: u64,
    policy: ApprovalPolicy,
    nonces: Arc<ApprovalNonceStore>,
) -> Result<ApprovalPairingHandshake, ApprovalError> {
    let secret = pairing_secret(secret)?;
    let envelope = parse_envelope(&envelope)?;
    nonces.with_inner(|store| {
        let (body, pin) = open_pairing_response(
            &identity.keys,
            &secret,
            &envelope,
            now,
            &policy.to_protocol(),
            store,
        )?;
        // Unreachable in practice: open_pairing_response validates the
        // body's message type — but this boundary never coerces.
        let device = match &*body {
            Body::PairingResponse { device, .. } => ApprovalDeviceInfo::from(device),
            _ => {
                return Err(ApprovalError::Malformed {
                    message: "the envelope does not carry a pairing response".to_string(),
                })
            }
        };
        store.save()?;
        Ok(ApprovalPairingHandshake {
            device,
            sender: pin.into(),
        })
    })
}

/// Open and verify an approval request (the app side). `envelope` is the
/// base64url blob the universal link's fragment carries; `pins` are the
/// app's persisted peers; `now` is the app's clock, `nonces` its replay
/// store. Verification order (cheapest and least secret-leaking first):
/// version → freshness → sender pinning → signature → AEAD → body
/// consistency → replay recording — and the recorded nonce is persisted
/// before the request is returned, so the same blob cannot survive an
/// app crash to be approved twice.
///
/// The envelope must carry an approval request; a pairing envelope or a
/// response is an error, never a coercion.
#[uniffi::export]
pub fn approval_open_request(
    identity: Arc<ApprovalIdentity>,
    pins: Vec<ApprovalPeerPin>,
    envelope: String,
    now: u64,
    policy: ApprovalPolicy,
    nonces: Arc<ApprovalNonceStore>,
) -> Result<Arc<OpenedApprovalRequest>, ApprovalError> {
    let envelope = parse_envelope(&envelope)?;
    let pins = pins
        .iter()
        .map(ApprovalPeerPin::to_protocol)
        .collect::<Result<Vec<_>, _>>()?;
    nonces.with_inner(|store| {
        let body = envelope::open(
            &identity.keys,
            &pins,
            &envelope,
            now,
            &policy.to_protocol(),
            store,
        )?;
        let header = envelope.header();
        let Body::ApprovalRequest {
            vault_id,
            vault_name,
            operation,
            requester,
            scope,
            challenge,
        } = &*body
        else {
            return Err(ApprovalError::Malformed {
                message: format!(
                    "the envelope does not carry an approval request ({:?})",
                    body.message_type()
                ),
            });
        };
        let view = ApprovalRequestView {
            vault_id: vault_id.clone(),
            vault_name: vault_name.clone(),
            operation: ApprovalOperation::from(operation),
            requester: requester.clone(),
            scope: ApprovalScope::from(*scope),
            request_id: header.rid.clone(),
            sender_kid: header.skid.clone(),
            sent_at: header.ts,
            expires_at: header.exp,
        };
        let challenge = challenge
            .as_ref()
            .map(|c| c.as_bytes())
            .transpose()?
            .map(|bytes| Zeroizing::new(bytes.to_vec()));
        store.save()?;
        Ok(Arc::new(OpenedApprovalRequest { view, challenge }))
    })
}

/// The approver-side answer to a challenge: HMAC-SHA1 over the challenge
/// with the phone-held key's 20-byte secret — the same construction
/// keepass-ng's `LocalChallenge` (a YubiKey HMAC-SHA1 slot) and CryptoKit
/// implement. `secret` is scrubbed after the answer is computed; the
/// 20-byte answer comes back as a zeroized [`SecretBytes`], ready for
/// [`approval_seal_decision`].
///
/// This is the **agent-answer path** — see the module docs for why it
/// lives here and not behind the vault surface's `ChallengeFactor`.
#[uniffi::export]
pub fn approval_answer_challenge(
    secret: Vec<u8>,
    challenge: Vec<u8>,
) -> Result<Arc<SecretBytes>, ApprovalError> {
    let secret = Zeroizing::new(secret);
    // The answer array is itself the vault-opening factor; hold it in a
    // wiping wrapper for as long as it exists outside the exported
    // object's zeroized buffer.
    let answer = Zeroizing::new(message::answer_challenge(&secret, &challenge)?);
    Ok(secret_bytes(&*answer))
}

/// Generate a fresh phone-held key secret: 20 random bytes, the HMAC-SHA1
/// slot secret whose hex form the recovery sheet carries. The responder
/// to an `EnrollKey` request creates it (showing the sheet and waiting
/// for the scan-back) before answering with
/// [`approval_answer_challenge`]; the returned bytes are what the app
/// persists in its Keychain.
#[uniffi::export]
pub fn approval_generate_phone_key_secret() -> Arc<SecretBytes> {
    // Zeroized until it lives inside the exported object's buffer (the
    // key exists as raw bytes exactly once more: on the sheet).
    let secret = Zeroizing::new(message::generate_phone_key_secret(&mut OsRng));
    secret_bytes(&*secret)
}

/// Sign and seal the approver's decision (the app side), answering the
/// request whose id is `in_reply_to` (the opened request's
/// `request_id`): HPKE-sealed to `peer`, signed by `identity`, echoing
/// the request id. `response` is the 20-byte answer of
/// [`approval_answer_challenge`] when the decision allows an
/// `Unlock`/`Save`/`EnrollKey` request; a denial must carry none — an
/// answer would still unlock the vault for the requester being refused,
/// so sealing rejects that combination outright (the approval page
/// drops the answer on denial; the CLI ignores one). The scope may be
/// narrower than requested (the approver chooses on the phone). Returns
/// the base64url envelope the CLI redeems.
#[uniffi::export]
pub fn approval_seal_decision(
    identity: Arc<ApprovalIdentity>,
    peer: ApprovalPeerPin,
    decision: ApprovalDecision,
    scope: ApprovalScope,
    response: Option<Arc<SecretBytes>>,
    in_reply_to: String,
    now: u64,
    policy: ApprovalPolicy,
) -> Result<String, ApprovalError> {
    if matches!(decision, ApprovalDecision::Deny { .. }) && response.is_some() {
        return Err(ApprovalError::Malformed {
            message: "a denial carries no challenge answer: the answer would still unlock the \
                      vault for the requester being refused"
                .to_string(),
        });
    }
    let peer = peer.to_protocol()?;
    let body = Body::ApprovalResponse {
        decision: decision.into(),
        scope: scope.into(),
        response: response
            .as_ref()
            .map(|answer| SecretHex::from_bytes(answer.as_slice())),
    };
    let envelope = envelope::seal_reply(
        &mut OsRng,
        &identity.keys,
        &peer,
        body,
        &in_reply_to,
        now,
        &policy.to_protocol(),
    )?;
    Ok(envelope.to_base64url())
}

/// The Phase 0 enrollment challenge: base64url of
/// `SHA-256(enrollment_nonce ‖ ecdh_public_key ‖ cli_enc_pub ‖
/// cli_sig_pub)` — the value the binding passkey assertion signs, and
/// the relay-swap defense (every key is covered). All parameters are
/// raw bytes; `ecdh_public_key` is the enrolling approver's HPKE key.
#[uniffi::export]
pub fn approval_enrollment_challenge(
    enrollment_nonce: Vec<u8>,
    ecdh_public_key: Vec<u8>,
    cli_enc_pub: Vec<u8>,
    cli_sig_pub: Vec<u8>,
) -> String {
    webauthn::enrollment_challenge(&enrollment_nonce, &ecdh_public_key, &cli_enc_pub, &cli_sig_pub)
}

/// The Phase 0 enrollment confirmation code: twelve digits in two
/// six-digit groups, derived from **both** parties' public keys. The
/// terminal derives it from its own identity plus the pasted enrollment
/// blob's keys; the approver derives it from the link's CLI keys plus
/// its own. The human compares the two displays before anything is
/// pinned — a substituted responder produces a different code.
#[uniffi::export]
pub fn approval_enrollment_confirmation_code(
    cli_enc_pub: Vec<u8>,
    cli_sig_pub: Vec<u8>,
    responder_enc_pub: Vec<u8>,
    responder_sig_pub: Vec<u8>,
) -> String {
    webauthn::enrollment_confirmation_code(
        &cli_enc_pub,
        &cli_sig_pub,
        &responder_enc_pub,
        &responder_sig_pub,
    )
}

/// Verify a WebAuthn assertion (the Phase 0 page's approvers): the
/// client data's type, challenge and origin, the RP-id hash and
/// user-present flag in the authenticator data, and the credential-key
/// signature. `passkey_public` is the pinned 65-byte SEC1 key;
/// `authenticator_data` / `client_data_json` / `signature_der` are the
/// assertion's raw outputs; `expected_challenge` is the base64url
/// challenge the relying party issued (for envelopes: the transcript
/// challenge the protocol crate derives).
#[uniffi::export]
pub fn approval_verify_webauthn_assertion(
    passkey_public: Vec<u8>,
    rp_id: String,
    origin: String,
    authenticator_data: Vec<u8>,
    client_data_json: Vec<u8>,
    signature_der: Vec<u8>,
    expected_challenge: String,
) -> Result<(), ApprovalError> {
    let passkey = PublicKey::from_bytes(&passkey_public)?.verifying_key()?;
    let assertion =
        webauthn::WebauthnAssertion::from_raw(&authenticator_data, &client_data_json, &signature_der);
    webauthn::verify_assertion(&passkey, &rp_id, &origin, &assertion, &expected_challenge)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pin crosses both ways without losing a field.
    #[test]
    fn pin_conversions_round_trip() {
        use passlane_approval::keys::WebauthnPin;
        let keys = IdentityKeys::generate(&mut OsRng).unwrap();
        let pin = PeerPin {
            label: "mbp".into(),
            enc_pub: passlane_approval::encoding::hex_encode(&keys.encryption_public()),
            sig_pub: passlane_approval::encoding::hex_encode(&keys.verifying_key().to_sec1_bytes()),
            paired_at: 42,
            webauthn: Some(WebauthnPin {
                rp_id: "approve.passlane.test".into(),
                origin: "https://approve.passlane.test".into(),
            }),
        };
        let ffi_pin: ApprovalPeerPin = pin.clone().into();
        assert_eq!(ffi_pin, ApprovalPeerPin {
            label: "mbp".into(),
            enc_pub: pin.enc_pub.clone(),
            sig_pub: pin.sig_pub.clone(),
            paired_at: 42,
            webauthn: Some(ApprovalWebauthnPin {
                rp_id: "approve.passlane.test".into(),
                origin: "https://approve.passlane.test".into(),
            }),
        });
        assert_eq!(ffi_pin.to_protocol().unwrap(), pin);
        // A corrupt pin (off-curve key) is refused at the boundary.
        let mut broken = ffi_pin;
        broken.enc_pub = "04".to_string() + &"11".repeat(64);
        assert!(matches!(
            broken.to_protocol(),
            Err(ApprovalError::Key { .. })
        ));
    }

    /// A response of the wrong length is refused at seal: the 20-byte
    /// shape the CLI's redemption (and keepass-ng) relies on.
    #[test]
    fn a_wrong_length_answer_is_refused_at_seal() {
        let identity = ApprovalIdentity::generate().unwrap();
        let peer = approval_new_pin(
            "self".into(),
            identity.encryption_public(),
            identity.verifying_public(),
            0,
        )
        .unwrap();
        let short = Arc::new(SecretBytes {
            bytes: Zeroizing::new(vec![0u8; 19]),
        });
        let sealed = approval_seal_decision(
            Arc::new(identity),
            peer,
            ApprovalDecision::Allow,
            ApprovalScope::Once,
            Some(short),
            "a".repeat(32),
            1_000,
            approval_default_policy(),
        );
        assert!(matches!(sealed, Err(ApprovalError::Malformed { .. })));
    }

    /// A denial accompanied by an answer is refused outright: the answer
    /// would still unlock the vault for the requester being refused (the
    /// page drops it on denial; the CLI ignores one — this boundary
    /// refuses to produce the combination at all).
    #[test]
    fn a_denial_with_an_answer_is_refused_at_seal() {
        let identity = Arc::new(ApprovalIdentity::generate().unwrap());
        let peer = approval_new_pin(
            "self".into(),
            identity.encryption_public(),
            identity.verifying_public(),
            0,
        )
        .unwrap();
        let answer = secret_bytes(&[0x42u8; 20]);
        let sealed = approval_seal_decision(
            identity.clone(),
            peer.clone(),
            ApprovalDecision::Deny { reason: None },
            ApprovalScope::Once,
            Some(answer),
            "a".repeat(32),
            1_000,
            approval_default_policy(),
        );
        assert!(matches!(
            sealed,
            Err(ApprovalError::Malformed { ref message }) if message.contains("denial")
        ));
        // A denial without an answer still seals.
        let sealed = approval_seal_decision(
            identity,
            peer,
            ApprovalDecision::Deny {
                reason: Some("not now".into()),
            },
            ApprovalScope::Once,
            None,
            "a".repeat(32),
            1_000,
            approval_default_policy(),
        );
        assert!(sealed.is_ok());
    }
}
