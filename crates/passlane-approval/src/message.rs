//! Message header and body types.
//!
//! The envelope splits each message into a small cleartext **header** (routing
//! and freshness metadata) and an encrypted **body** (everything sensitive:
//! vault names, entry titles, challenge bytes, secrets).
//!
//! See `SPEC.md` for the field-by-field rationale.

use std::fmt;

use zeroize::Zeroize;

use crate::error::{Error, Result};

/// The protocol wire version this crate speaks.
pub const VERSION: u8 = 1;

/// Which kind of message an envelope carries (mirrors the wire byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    /// PSK-sealed pairing initiation (CLI → approver).
    PairingRequest = 1,
    /// HPKE-sealed pairing answer (approver → CLI).
    PairingResponse = 2,
    /// A request for human approval (CLI → approver).
    ApprovalRequest = 3,
    /// The answer to an approval request (approver → CLI).
    ApprovalResponse = 4,
    /// Revoke a live session.
    SessionRevoke = 5,
}

impl MessageType {
    /// Parse the wire byte.
    pub fn from_u8(v: u8) -> Result<Self> {
        Ok(match v {
            1 => Self::PairingRequest,
            2 => Self::PairingResponse,
            3 => Self::ApprovalRequest,
            4 => Self::ApprovalResponse,
            5 => Self::SessionRevoke,
            other => return Err(Error::Malformed(format!("unknown message type {other}"))),
        })
    }
}

/// Cleartext routing header, carried as compact JSON inside the envelope.
///
/// Field names are deliberately short: the header is the bulk of the
/// non-ciphertext bytes, and envelopes travel in QR codes and links.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Header {
    /// Protocol version; must equal [`VERSION`] and the envelope version byte.
    pub v: u8,
    /// Message type (numeric form of [`MessageType`]).
    pub t: u8,
    /// 16-byte random nonce, hex. Unique per sender; the replay key.
    pub n: String,
    /// Sender timestamp, unix seconds.
    pub ts: u64,
    /// Expiry, unix seconds. Reject the message at `now >= exp`.
    pub exp: u64,
    /// Sender key id (encryption identity).
    pub skid: String,
    /// Recipient key id (encryption identity).
    pub rkid: String,
    /// 16-byte request id, hex. Ties a response to its request.
    pub rid: String,
}

impl Header {
    /// The message type, or an error for unknown values.
    pub fn message_type(&self) -> Result<MessageType> {
        MessageType::from_u8(self.t)
    }
}

/// Descriptive identity of the sending device, shown on approval screens.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DeviceInfo {
    /// One of `cli`, `phone`, `page`.
    pub kind: String,
    /// Free-form name, e.g. `macbook-pro` or `anssi-iphone`.
    pub name: String,
    /// Software version of the sender.
    pub version: String,
}

/// What the CLI is asking the approver to permit.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Operation {
    /// Reveal one secret field of one entry.
    Reveal {
        /// Entry title (or match string) identifying the entry.
        entry: String,
        /// The field being revealed, e.g. `password`.
        field: String,
    },
    /// Supply the challenge-response needed to open the vault.
    Unlock,
    /// Permit a save (future: v1 write path).
    Save,
}

/// How long an approval may be reused by the session agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Scope {
    /// Single use.
    Once,
    /// Reusable for `seconds` (validated against the policy cap).
    Timed {
        /// Seconds the approval may be reused.
        seconds: u32,
    },
}

impl Scope {
    /// Reuse window in seconds (`0` for [`Scope::Once`]).
    pub fn seconds(&self) -> u64 {
        match self {
            Self::Once => 0,
            Self::Timed { seconds } => *seconds as u64,
        }
    }
}

/// The approver's answer.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Decision {
    /// Approved.
    Allow,
    /// Refused.
    Deny {
        /// Optional human-readable reason, shown to the requester.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
}

/// HMAC-SHA1 outputs are 20 bytes; kept hex-encoded for transport.
pub const CHALLENGE_RESPONSE_LEN: usize = 20;

fn check_hex_field(name: &str, value: &Option<String>, len: usize) -> Result<()> {
    if let Some(v) = value
        && (v.len() != len * 2 || !v.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return Err(Error::Malformed(format!(
            "{name} must be {len}-byte hex, got {} chars",
            v.len()
        )));
    }
    Ok(())
}

/// A secret carried in a message body. Redacted in `Debug` output so the
/// HMAC-SHA1 responses that unlock vaults cannot leak into logs.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SecretHex(pub String);

impl SecretHex {
    /// Parse from hex, validating it decodes.
    pub fn from_hex(s: &str) -> Result<Self> {
        crate::encoding::hex_decode(s)?;
        Ok(Self(s.to_string()))
    }

    /// Wrap raw bytes as hex.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(crate::encoding::hex_encode(bytes))
    }

    /// Decode back to raw bytes.
    pub fn as_bytes(&self) -> Result<Vec<u8>> {
        crate::encoding::hex_decode(&self.0)
    }

    /// The hex form.
    pub fn as_hex(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretHex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretHex([{} bytes redacted])", self.0.len() / 2)
    }
}

impl Zeroize for SecretHex {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// Message body. This is what the AEAD layer encrypts.
#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Body {
    /// PSK-sealed pairing initiation (CLI → approver).
    PairingRequest {
        /// The sender's descriptive identity.
        device: DeviceInfo,
        /// Sender's HPKE public key (hex SEC1) to pin.
        enc_pub: String,
        /// Sender's ECDSA verifying key (hex SEC1) to pin.
        sig_pub: String,
    },
    /// HPKE-sealed pairing answer (approver → CLI).
    PairingResponse {
        /// The sender's descriptive identity.
        device: DeviceInfo,
        /// Sender's HPKE public key (hex SEC1) to pin.
        enc_pub: String,
        /// Sender's ECDSA verifying key (hex SEC1) to pin.
        sig_pub: String,
    },
    /// A request for human approval.
    ApprovalRequest {
        /// Registry id of the target vault.
        vault_id: String,
        /// Display name of the target vault.
        vault_name: String,
        /// What is being asked.
        operation: Operation,
        /// Who is asking (user@host for the CLI, entry point for agents).
        requester: String,
        /// How long an approval may be reused.
        scope: Scope,
        /// The 20-byte HMAC-SHA1 challenge (hex) when the operation needs a
        /// challenge-response to proceed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        challenge: Option<SecretHex>,
    },
    /// The answer to an approval request.
    ApprovalResponse {
        /// The decision.
        decision: Decision,
        /// The scope actually granted (may be narrower than requested).
        scope: Scope,
        /// The 20-byte HMAC-SHA1 response (hex) for an `Unlock` approval.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        response: Option<SecretHex>,
    },
    /// Revoke a live session (sent by the phone or the CLI).
    SessionRevoke {
        /// The session to revoke.
        session_id: String,
        /// Why, for the approval log.
        reason: String,
    },
}

impl Body {
    /// The message type this body serializes as.
    pub fn message_type(&self) -> MessageType {
        match self {
            Self::PairingRequest { .. } => MessageType::PairingRequest,
            Self::PairingResponse { .. } => MessageType::PairingResponse,
            Self::ApprovalRequest { .. } => MessageType::ApprovalRequest,
            Self::ApprovalResponse { .. } => MessageType::ApprovalResponse,
            Self::SessionRevoke { .. } => MessageType::SessionRevoke,
        }
    }

    /// Validate field shapes that serde cannot express (hex lengths).
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::ApprovalRequest { challenge, .. } => check_hex_field(
                "challenge",
                &challenge.as_ref().map(|c| c.as_hex().to_string()),
                CHALLENGE_RESPONSE_LEN,
            ),
            Self::ApprovalResponse { response, .. } => check_hex_field(
                "response",
                &response.as_ref().map(|c| c.as_hex().to_string()),
                CHALLENGE_RESPONSE_LEN,
            ),
            _ => Ok(()),
        }
    }
}

impl fmt::Debug for Body {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Manual Debug: never print secret-bearing fields verbatim.
        match self {
            Self::PairingRequest {
                device,
                enc_pub,
                sig_pub,
            } => f
                .debug_struct("Body::PairingRequest")
                .field("device", device)
                .field("enc_pub", enc_pub)
                .field("sig_pub", sig_pub)
                .finish(),
            Self::PairingResponse {
                device,
                enc_pub,
                sig_pub,
            } => f
                .debug_struct("Body::PairingResponse")
                .field("device", device)
                .field("enc_pub", enc_pub)
                .field("sig_pub", sig_pub)
                .finish(),
            Self::ApprovalRequest {
                vault_id,
                vault_name,
                operation,
                requester,
                scope,
                challenge,
            } => f
                .debug_struct("Body::ApprovalRequest")
                .field("vault_id", vault_id)
                .field("vault_name", vault_name)
                .field("operation", operation)
                .field("requester", requester)
                .field("scope", scope)
                .field(
                    "challenge",
                    &challenge.as_ref().map(|c| c.as_hex().to_string()),
                )
                .finish(),
            Self::ApprovalResponse {
                decision,
                scope,
                response,
            } => f
                .debug_struct("Body::ApprovalResponse")
                .field("decision", decision)
                .field("scope", scope)
                .field("response", &response.as_ref().map(|_| "[redacted]"))
                .finish(),
            Self::SessionRevoke { session_id, reason } => f
                .debug_struct("Body::SessionRevoke")
                .field("session_id", session_id)
                .field("reason", reason)
                .finish(),
        }
    }
}

// Bodies (including challenge responses that unlock vaults) are wiped when
// they fall out of scope.
impl Zeroize for Body {
    fn zeroize(&mut self) {
        match self {
            Self::PairingRequest {
                device,
                enc_pub,
                sig_pub,
            }
            | Self::PairingResponse {
                device,
                enc_pub,
                sig_pub,
            } => {
                device.kind.zeroize();
                device.name.zeroize();
                device.version.zeroize();
                enc_pub.zeroize();
                sig_pub.zeroize();
            }
            Self::ApprovalRequest {
                vault_id,
                vault_name,
                operation,
                requester,
                scope: _,
                challenge,
            } => {
                vault_id.zeroize();
                vault_name.zeroize();
                if let Operation::Reveal { entry, field } = operation {
                    entry.zeroize();
                    field.zeroize();
                }
                requester.zeroize();
                if let Some(c) = challenge.as_mut() {
                    c.zeroize();
                }
            }
            Self::ApprovalResponse {
                decision,
                scope: _,
                response,
            } => {
                if let Decision::Deny { reason } = decision {
                    reason.zeroize();
                }
                if let Some(r) = response.as_mut() {
                    r.zeroize();
                }
            }
            Self::SessionRevoke { session_id, reason } => {
                session_id.zeroize();
                reason.zeroize();
            }
        }
    }
}

impl Drop for Body {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request() -> Body {
        Body::ApprovalRequest {
            vault_id: "3f9c".into(),
            vault_name: "Main".into(),
            operation: Operation::Reveal {
                entry: "GitHub".into(),
                field: "password".into(),
            },
            requester: "anssi@macbook".into(),
            scope: Scope::Once,
            challenge: Some(SecretHex::from_bytes(&[0xab; 20])),
        }
    }

    #[test]
    fn message_type_roundtrip() {
        for t in [
            MessageType::PairingRequest,
            MessageType::PairingResponse,
            MessageType::ApprovalRequest,
            MessageType::ApprovalResponse,
            MessageType::SessionRevoke,
        ] {
            assert_eq!(MessageType::from_u8(t as u8).unwrap(), t);
        }
        assert!(MessageType::from_u8(0).is_err());
        assert!(MessageType::from_u8(6).is_err());
    }

    #[test]
    fn body_type_matches_tag() {
        assert_eq!(
            sample_request().message_type(),
            MessageType::ApprovalRequest
        );
        assert_eq!(
            Body::SessionRevoke {
                session_id: "s".into(),
                reason: "r".into()
            }
            .message_type(),
            MessageType::SessionRevoke
        );
    }

    #[test]
    fn json_roundtrip_all_bodies() {
        let bodies = vec![
            sample_request(),
            Body::ApprovalResponse {
                decision: Decision::Allow,
                scope: Scope::Timed { seconds: 300 },
                response: Some(SecretHex::from_bytes(&[7; 20])),
            },
            Body::ApprovalResponse {
                decision: Decision::Deny {
                    reason: Some("not now".into()),
                },
                scope: Scope::Once,
                response: None,
            },
            Body::PairingRequest {
                device: DeviceInfo {
                    kind: "cli".into(),
                    name: "mbp".into(),
                    version: "4.0".into(),
                },
                enc_pub: "04".to_string() + &"ab".repeat(64),
                sig_pub: "04".to_string() + &"cd".repeat(64),
            },
            Body::PairingResponse {
                device: DeviceInfo {
                    kind: "phone".into(),
                    name: "iphone".into(),
                    version: "1.0".into(),
                },
                enc_pub: "04".to_string() + &"ab".repeat(64),
                sig_pub: "04".to_string() + &"cd".repeat(64),
            },
            Body::SessionRevoke {
                session_id: "id".into(),
                reason: "done".into(),
            },
        ];
        for body in bodies {
            let json = serde_json::to_vec(&body).unwrap();
            let back: Body = serde_json::from_slice(&json).unwrap();
            assert_eq!(back, body);
        }
    }

    #[test]
    fn validate_rejects_bad_challenge_hex() {
        let mut body = sample_request();
        if let Body::ApprovalRequest { challenge, .. } = &mut body {
            *challenge = Some(SecretHex::from_hex("abcd").unwrap());
        }
        assert!(body.validate().is_err());
        assert!(sample_request().validate().is_ok());
    }

    #[test]
    fn validate_rejects_wrong_length_hex() {
        let mut body = sample_request();
        if let Body::ApprovalRequest { challenge, .. } = &mut body {
            *challenge = Some(SecretHex::from_hex(&"ab".repeat(19)).unwrap());
        }
        assert!(body.validate().is_err());
    }

    #[test]
    fn debug_redacts_response_secret() {
        let body = Body::ApprovalResponse {
            decision: Decision::Allow,
            scope: Scope::Once,
            response: Some(SecretHex::from_bytes(&[0x42; 20])),
        };
        let debug = format!("{body:?}");
        assert!(!debug.contains("4242"), "Debug leaked the secret: {debug}");
        assert!(debug.contains("[redacted]"));
    }

    #[test]
    fn zeroize_clears_secret() {
        let mut live = sample_request();
        let before = match &mut live {
            Body::ApprovalRequest { challenge, .. } => challenge.take().unwrap().0,
            _ => unreachable!(),
        };
        let mut secret = SecretHex(before.clone());
        secret.zeroize();
        assert_ne!(secret.0, before);
        assert!(secret.0.chars().all(|c| c == '\0'));
    }
}
