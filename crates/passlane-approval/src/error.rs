//! Error type for the approval protocol.

/// Errors produced by the approval protocol: malformed input, verification
/// failures, freshness violations, and key/encoding problems.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The wire bytes are not a well-formed envelope.
    #[error("malformed envelope: {0}")]
    Malformed(String),

    /// The envelope carries an unsupported protocol version.
    #[error("unsupported envelope version {0}")]
    Version(u8),

    /// AEAD decryption failed (wrong key, tampering, or wrong recipient).
    #[error("decryption failed")]
    Decrypt,

    /// The signature is missing, malformed, or did not verify.
    #[error("signature verification failed")]
    Signature,

    /// The message nonce was already seen for this sender.
    #[error("message replayed")]
    Replay,

    /// The message expiry is in the past.
    #[error("message expired at {0}")]
    Expired(u64),

    /// The sender timestamp lies outside the allowed clock-skew window.
    #[error("message timestamp {0} outside allowed clock skew")]
    ClockSkew(u64),

    /// The message TTL (expiry - timestamp) exceeds the policy maximum.
    #[error("message TTL exceeds the policy maximum")]
    Ttl,

    /// The session scope requested exceeds the policy maximum.
    #[error("session scope of {0}s exceeds the policy maximum")]
    SessionTooLong(u64),

    /// The sender key id is not pinned.
    #[error("unknown sender: key id {0} is not pinned")]
    UnknownSender(String),

    /// The envelope is addressed to a different recipient key.
    #[error("envelope is addressed to key id {0}")]
    WrongRecipient(String),

    /// The message type does not match the decoded body.
    #[error("message type {0:?} does not match the body")]
    MessageTypeMismatch(crate::message::MessageType),

    /// Key material is invalid (wrong length, not on curve, ...).
    #[error("invalid key material: {0}")]
    Key(String),

    /// Hex or base64url decoding failed.
    #[error("encoding error: {0}")]
    Encoding(String),

    /// An I/O error (nonce store, key store).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON (de)serialization failed.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// The HPKE layer rejected the operation.
    #[error("hpke error: {0}")]
    Hpke(String),

    /// A WebAuthn assertion failed verification.
    #[error("webauthn assertion rejected: {0}")]
    Webauthn(String),

    /// A pairing envelope was rejected.
    #[error("pairing rejected: {0}")]
    Pairing(String),
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;
