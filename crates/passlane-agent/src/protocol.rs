//! The wire protocol between the `passlane-agent` daemon and its clients.
//!
//! Framing: every message is a 4-byte big-endian length followed by that
//! many bytes of JSON. One request is outstanding per connection at a
//! time (the CLI is a short-lived, sequential client). Connections that
//! sent [`Request::Subscribe`] additionally receive [`Event`] frames
//! pushed by the server — the cooperative notification that tells a
//! connected CLI a session it relies on was revoked, expired, or locked.
//!
//! All types are JSON for inspectability; secret material travels only
//! over the 0600 Unix socket and is wrapped in [`SecretString`] so it is
//! zeroized in memory on both sides and never appears in `Debug` output
//! or logs.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::io::{Read, Write};
use zeroize::Zeroizing;

use passlane_approval::message::Scope;

use crate::error::AgentError;

/// Protocol dialect version (returned by [`Request::Ping`]). Dialect 2
/// added the challenge-response material an unlock session may hold
/// ([`ChallengeResponseMaterial`]); dialect 3 added the single-challenge
/// answer sessions a phone-held key's approvals become
/// ([`GrantSpec::ChallengeResponse`]). A client refuses an agent that
/// speaks another dialect rather than work with silently incomplete
/// factors.
pub const PROTOCOL_VERSION: u32 = 3;

/// Hard limit on one frame; every message here is far smaller.
pub const MAX_FRAME_LEN: usize = 64 * 1024;

/// Sanity limits on client-supplied strings.
pub const MAX_VAULT_NAME_LEN: usize = 256;
/// Sanity limit on a reveal entry title.
pub const MAX_ENTRY_NAME_LEN: usize = 512;
/// Sanity limit on a reveal field name.
pub const MAX_FIELD_NAME_LEN: usize = 128;
/// Sanity limit on an entry id (a KeePass UUID is 36 bytes).
pub const MAX_ID_LEN: usize = 128;
/// A challenge (a vault's 32-byte KDF seed) as lower-case hex.
pub const CHALLENGE_HEX_LEN: usize = 64;
/// A challenge response (20-byte HMAC-SHA1) as lower-case hex.
pub const RESPONSE_HEX_LEN: usize = 40;

/// `value` is exactly `len` lower-case hex characters.
pub fn is_hex_of_len(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, 'a'..='f'))
}

/// Sanity limit on a challenge-response secret (an HMAC-SHA1 slot secret
/// is 40 hex characters).
pub const MAX_SECRET_LEN: usize = 256;

/// A secret string on the wire. Serializes as a plain JSON string (the
/// socket is 0600 and local), but is held zeroized in memory and renders
/// as `SecretString(***)` in any `Debug` output.
#[derive(Clone)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    /// Wrap a secret.
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// Read the secret (handle with care; never log it).
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Unwrap into a zeroizing buffer.
    pub fn into_inner(self) -> Zeroizing<String> {
        self.0
    }
}

impl PartialEq for SecretString {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for SecretString {}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretString(***)")
    }
}

impl Serialize for SecretString {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self(Zeroizing::new(String::deserialize(deserializer)?)))
    }
}

/// What an unlock session holds for a vault's challenge-response
/// (hardware-key) factor, in the form that lets a CLI open the vault
/// without the key itself. A factor only a physical key can answer
/// cannot be held, and is simply absent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ChallengeResponseMaterial {
    /// A secret-backed key (a recovery secret, a virtual key): the HMAC-SHA1
    /// secret of its slot, hex-encoded. It answers every challenge —
    /// including the fresh one a save issues — so a session-backed vault
    /// stays writable.
    Secret {
        /// The slot's HMAC-SHA1 secret, hex.
        secret_hex: SecretString,
    },
}

/// What a session grants, as sent by the client when creating one.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GrantSpec {
    /// Hold what a CLI needs to open a vault (the ssh-agent "key") until
    /// the session expires or is revoked: the master password, plus the
    /// challenge-response material when the vault has a hardware-key
    /// factor a session can carry. Never written anywhere but memory.
    Unlock {
        /// The vault's master password.
        master_password: SecretString,
        /// The vault's challenge-response factor, when it is one a session
        /// can hold (see [`ChallengeResponseMaterial`]). Absent for
        /// password-only vaults, and for hardware keys whose secret never
        /// leaves the device.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        challenge_response: Option<ChallengeResponseMaterial>,
    },
    /// A recorded owner approval ("approve for this session") covering
    /// agent-facing reveals of one entry field. Carries no secret — it
    /// is the reusable form of an `agent = ask` approval. Keyed by the
    /// entry's **stable UUID** so a display title reused by another
    /// entry never inherits the approval; the title travels along for
    /// display and audit only.
    Reveal {
        /// Entry UUID (the id shown by the vault layer).
        id: String,
        /// Entry title (display/audit only, never matched).
        entry: String,
        /// Field the approval covers (e.g. `password`, `code`).
        field: String,
    },
    /// A challenge-response answer for one vault file version (a
    /// phone-held key, passlane#53). Both fields are lower-case hex:
    /// `challenge` is the vault's 32-byte KDF seed the answer is for, and
    /// `response` the 20-byte HMAC-SHA1 answer. The seed changes on every
    /// save, so an answer is keyed to the exact file version it opens and
    /// can never be reused after a re-save. Held in memory exactly like a
    /// master password.
    ChallengeResponse {
        /// The challenge, 64 hex characters.
        challenge: SecretString,
        /// The answer, 40 hex characters.
        response: SecretString,
    },
}

/// A request from a CLI client to the agent.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Liveness and capability probe.
    Ping,
    /// Create a session. `scope` follows the approval protocol:
    /// `{"kind":"once"}` or `{"kind":"timed","seconds":N}`; durations
    /// beyond the agent's cap are refused with [`ErrorCode::TooLong`].
    CreateSession {
        /// Vault the session is for (by name).
        vault: String,
        /// What the session grants.
        grant: GrantSpec,
        /// Once / timed, from the approval protocol.
        scope: Scope,
    },
    /// Fetch the unlock factors a live session holds for the vault — the
    /// master password and, when the session carries it, the
    /// challenge-response material. A `once`-scoped unlock session is
    /// consumed by this call.
    GetUnlockFactors {
        /// Vault name.
        vault: String,
    },
    /// Fetch the challenge response a live session holds for this vault
    /// and challenge (both keyed exactly; the challenge is 64 hex
    /// characters). Consumes a `once`-scoped session.
    GetChallengeResponse {
        /// Vault name.
        vault: String,
        /// The challenge the answer must be for, 64 hex characters.
        challenge: String,
    },
    /// Does a live reveal session cover this entry field? Consumes
    /// `once`-scoped reveal sessions. Matching is by the entry's stable
    /// UUID, never by title.
    CheckReveal {
        /// Vault name.
        vault: String,
        /// Entry UUID the approval covers.
        id: String,
        /// Field name.
        field: String,
    },
    /// List live sessions (no secrets included).
    ListSessions,
    /// Revoke one session by id.
    RevokeSession {
        /// Session id (uuid).
        id: String,
    },
    /// Revoke every session of one vault.
    RevokeVault {
        /// Vault name.
        vault: String,
    },
    /// Revoke every session.
    RevokeAll,
    /// Revoke every session and emit [`Event::SessionsLocked`]; the
    /// agent keeps running but holds nothing.
    Lock,
    /// From now on, push [`Event`] frames on this connection.
    Subscribe,
}

/// Machine-readable error codes on [`Response::Error`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// No session matched the request.
    NotFound,
    /// A matching session existed but expired.
    Expired,
    /// The requested duration exceeds the agent's session cap.
    TooLong,
    /// Malformed input (empty names, oversize fields...).
    Invalid,
    /// Wire-level misuse.
    Protocol,
}

/// One live session as listed by the agent (secret-free view).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionInfo {
    /// Session id (uuid).
    pub id: String,
    /// Vault name.
    pub vault: String,
    /// What the session grants, without secrets.
    pub grant: GrantInfo,
    /// `once` or `timed { seconds }`.
    pub scope: Scope,
    /// Creation time, unix seconds.
    pub created_at: u64,
    /// Expiry time, unix seconds (`None` for `once` sessions, which die
    /// on first use instead).
    pub expires_at: Option<u64>,
}

/// The secret-free view of what a session grants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GrantInfo {
    /// Vault unlock factors. `challenge_response` tells whether the
    /// session also holds the vault's hardware-key factor: without it, a
    /// hardware-key vault still needs the key for every use.
    Unlock {
        /// Whether the session holds the challenge-response factor.
        challenge_response: bool,
    },
    /// Agent-facing reveal of one entry field.
    Reveal {
        /// Entry UUID.
        id: String,
        /// Entry title (display only).
        entry: String,
        /// Field name.
        field: String,
    },
    /// A challenge-response answer for one vault file version.
    ChallengeResponse,
}

/// A response from the agent to a CLI client.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    /// Answer to [`Request::Ping`].
    Pong {
        /// Protocol dialect of the agent.
        version: u32,
        /// The agent's session-duration cap in seconds.
        max_session_secs: u64,
        /// Live session count.
        sessions: usize,
    },
    /// Answer to [`Request::CreateSession`].
    SessionCreated {
        /// New session id.
        id: String,
        /// Expiry, unix seconds (`None` for `once`).
        expires_at: Option<u64>,
    },
    /// Answer to [`Request::GetUnlockFactors`].
    UnlockFactors {
        /// The held master password.
        master_password: SecretString,
        /// The held challenge-response material, if any.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        challenge_response: Option<ChallengeResponseMaterial>,
        /// When the serving session expires, unix seconds (`None` when
        /// a `once` session was just consumed). Long-running callers
        /// revalidate against this after subscribing to events, so an
        /// expiry that fires during vault decryption is not missed.
        expires_at: Option<u64>,
    },
    /// Answer to [`Request::GetChallengeResponse`].
    ChallengeResponse {
        /// The held answer, 40 hex characters.
        response: SecretString,
        /// When the serving session expires, unix seconds (`None` when a
        /// `once` session was just consumed).
        expires_at: Option<u64>,
    },
    /// Answer to [`Request::CheckReveal`].
    RevealCheck {
        /// Whether a live session covers the reveal.
        allowed: bool,
        /// When the covering session expires, unix seconds (`None` when
        /// not allowed, or when a `once` approval was just consumed).
        until: Option<u64>,
    },
    /// Answer to [`Request::ListSessions`].
    Sessions {
        /// Live sessions, oldest first.
        list: Vec<SessionInfo>,
    },
    /// Answer to the revoke requests: how many sessions were dropped.
    Revoked {
        /// Number of sessions removed.
        count: usize,
    },
    /// Answer to [`Request::Lock`].
    Locked,
    /// Answer to [`Request::Subscribe`].
    Subscribed,
    /// An application-level error.
    Error {
        /// Error class.
        code: ErrorCode,
        /// Human-readable detail (never contains secret material).
        message: String,
    },
}

/// Server-pushed notification for subscribed connections.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    /// A session was revoked (`id` is no longer usable).
    SessionRevoked {
        /// Session id.
        id: String,
        /// Vault name.
        vault: String,
    },
    /// A session expired and its key material was wiped.
    SessionExpired {
        /// Session id.
        id: String,
        /// Vault name.
        vault: String,
    },
    /// Every session was dropped by [`Request::Lock`] (or shutdown):
    /// connected clients should forget all session-backed state.
    SessionsLocked,
}

/// Serialize `value` and write it as one length-prefixed frame. The
/// serialization buffer is zeroized after writing, so secret-bearing
/// responses leave no plain copies of the plaintext behind.
pub fn write_frame<W: Write>(writer: &mut W, value: &impl Serialize) -> Result<(), AgentError> {
    let mut buf = Vec::new();
    serde_json::to_writer(&mut buf, value)
        .map_err(|e| AgentError::Protocol(format!("serialization failed: {e}")))?;
    let buf = Zeroizing::new(buf);
    if buf.len() > MAX_FRAME_LEN {
        return Err(AgentError::Protocol(format!(
            "frame of {} bytes exceeds the {}-byte limit",
            buf.len(),
            MAX_FRAME_LEN
        )));
    }
    writer.write_all(&(buf.len() as u32).to_be_bytes())?;
    writer.write_all(&buf)?;
    writer.flush()?;
    Ok(())
}

/// Read one length-prefixed frame. The buffer is returned zeroizing, so
/// secret-bearing requests are wiped as soon as the caller drops them.
pub fn read_frame<R: Read>(reader: &mut R) -> Result<Zeroizing<Vec<u8>>, AgentError> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_LEN {
        return Err(AgentError::Protocol(format!(
            "announced frame of {len} bytes exceeds the {MAX_FRAME_LEN}-byte limit"
        )));
    }
    let mut buf = Zeroizing::new(vec![0u8; len]);
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

/// Parse a frame payload as `T`.
pub fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, AgentError> {
    serde_json::from_slice(bytes)
        .map_err(|e| AgentError::Protocol(format!("malformed message: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip<T>(value: T) -> T
    where
        T: Serialize + for<'de> Deserialize<'de>,
    {
        let mut buf = Vec::new();
        write_frame(&mut buf, &value).unwrap();
        let frame = read_frame(&mut buf.as_slice()).unwrap();
        decode(&frame).unwrap()
    }

    #[test]
    fn secret_string_debug_is_redacted() {
        let secret = SecretString::new("hunter2");
        assert_eq!(format!("{secret:?}"), "SecretString(***)");
        assert_eq!(secret.expose(), "hunter2");
    }

    #[test]
    #[cfg(unix)]
    fn frames_roundtrip_through_a_socketpair() {
        let (mut a, mut b) = std::os::unix::net::UnixStream::pair().unwrap();
        let req = Request::CreateSession {
            vault: "work".into(),
            grant: GrantSpec::Unlock {
                master_password: SecretString::new("canary-password"),
                challenge_response: None,
            },
            scope: Scope::Timed { seconds: 300 },
        };
        write_frame(&mut a, &req).unwrap();
        let frame = read_frame(&mut b).unwrap();
        let back: Request = decode(&frame).unwrap();
        match back {
            Request::CreateSession {
                vault,
                grant:
                    GrantSpec::Unlock {
                        master_password,
                        challenge_response,
                    },
                scope,
            } => {
                assert_eq!(vault, "work");
                assert_eq!(master_password.expose(), "canary-password");
                assert_eq!(challenge_response, None);
                assert_eq!(scope, Scope::Timed { seconds: 300 });
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    fn secret_material(secret: &str) -> ChallengeResponseMaterial {
        ChallengeResponseMaterial::Secret {
            secret_hex: SecretString::new(secret),
        }
    }

    #[test]
    fn challenge_response_material_travels_with_the_unlock_factors() {
        let grant = GrantSpec::Unlock {
            master_password: SecretString::new("master-pw"),
            challenge_response: Some(secret_material("aabbcc")),
        };
        match roundtrip(grant.clone()) {
            GrantSpec::Unlock {
                master_password,
                challenge_response,
            } => {
                assert_eq!(master_password.expose(), "master-pw");
                assert_eq!(challenge_response, Some(secret_material("aabbcc")));
            }
            other => panic!("wrong variant: {other:?}"),
        }

        let response = Response::UnlockFactors {
            master_password: SecretString::new("master-pw"),
            challenge_response: Some(secret_material("aabbcc")),
            expires_at: Some(42),
        };
        assert_eq!(roundtrip(response.clone()), response);

        // The wire shape: an internally tagged `kind`, and the field left
        // out entirely for a password-only vault so dialect-1 peers see
        // the frames they always saw.
        let json = serde_json::to_value(&grant).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "kind": "unlock",
                "master_password": "master-pw",
                "challenge_response": {"kind": "secret", "secret_hex": "aabbcc"}
            })
        );
        let plain = GrantSpec::Unlock {
            master_password: SecretString::new("master-pw"),
            challenge_response: None,
        };
        assert_eq!(
            serde_json::to_value(&plain).unwrap(),
            serde_json::json!({"kind": "unlock", "master_password": "master-pw"})
        );
    }

    #[test]
    fn challenge_response_secret_is_redacted_in_debug_output() {
        let grant = GrantSpec::Unlock {
            master_password: SecretString::new("master-canary"),
            challenge_response: Some(secret_material("secret-canary")),
        };
        let debug = format!("{grant:?}");
        assert!(debug.contains("challenge_response"), "{debug}");
        assert!(!debug.contains("secret-canary"), "{debug}");
        assert!(!debug.contains("master-canary"), "{debug}");
    }

    #[test]
    fn response_and_event_variants_roundtrip() {
        assert_eq!(
            roundtrip(Response::RevealCheck {
                allowed: true,
                until: Some(42)
            }),
            Response::RevealCheck {
                allowed: true,
                until: Some(42)
            }
        );
        assert_eq!(roundtrip(Event::SessionsLocked), Event::SessionsLocked);
        assert_eq!(
            roundtrip(Response::Error {
                code: ErrorCode::TooLong,
                message: "no".into()
            }),
            Response::Error {
                code: ErrorCode::TooLong,
                message: "no".into()
            }
        );
    }

    #[test]
    fn scope_wire_shape_matches_the_approval_protocol() {
        // The agent must speak the same JSON shape as
        // passlane-approval's Scope, or a phone-granted approval could
        // not be handed to the agent as-is.
        let once: serde_json::Value = serde_json::to_value(Scope::Once).unwrap();
        assert_eq!(once, serde_json::json!({"kind": "once"}));
        let timed: serde_json::Value = serde_json::to_value(Scope::Timed { seconds: 900 }).unwrap();
        assert_eq!(timed, serde_json::json!({"kind": "timed", "seconds": 900}));
        let back: Scope = serde_json::from_value(timed).unwrap();
        assert_eq!(back, Scope::Timed { seconds: 900 });
    }

    #[test]
    fn challenge_response_frames_roundtrip_and_validate() {
        let grant = GrantSpec::ChallengeResponse {
            challenge: SecretString::new("ab".repeat(32)),
            response: SecretString::new("cd".repeat(20)),
        };
        let back = roundtrip(Request::CreateSession {
            vault: "work".into(),
            grant,
            scope: Scope::Once,
        });
        match back {
            Request::CreateSession {
                grant:
                    GrantSpec::ChallengeResponse {
                        challenge,
                        response,
                    },
                ..
            } => {
                assert_eq!(challenge.expose(), "ab".repeat(32));
                assert_eq!(response.expose(), "cd".repeat(20));
                // Secrets never reach Debug output.
                let debug = format!(
                    "{:?}",
                    Request::CreateSession {
                        vault: "work".into(),
                        grant: GrantSpec::ChallengeResponse {
                            challenge: SecretString::new("ab".repeat(32)),
                            response: SecretString::new("cd".repeat(20)),
                        },
                        scope: Scope::Once,
                    }
                );
                assert!(!debug.contains("cdcd"), "{debug}");
            }
            other => panic!("wrong variant: {other:?}"),
        }
        let answer = roundtrip(Response::ChallengeResponse {
            response: SecretString::new("cd".repeat(20)),
            expires_at: Some(42),
        });
        assert!(matches!(
            answer,
            Response::ChallengeResponse {
                ref response,
                expires_at: Some(42)
            } if response.expose() == "cd".repeat(20)
        ));
    }

    #[test]
    fn hex_length_check() {
        assert!(is_hex_of_len(&"ab".repeat(32), CHALLENGE_HEX_LEN));
        assert!(is_hex_of_len(&"cd".repeat(20), RESPONSE_HEX_LEN));
        assert!(
            !is_hex_of_len(&"AB".repeat(32), CHALLENGE_HEX_LEN),
            "upper case"
        );
        assert!(!is_hex_of_len(&"ab".repeat(31), CHALLENGE_HEX_LEN), "short");
        assert!(!is_hex_of_len(&"ab".repeat(33), CHALLENGE_HEX_LEN), "long");
        assert!(
            !is_hex_of_len(&"gz".repeat(32), CHALLENGE_HEX_LEN),
            "not hex"
        );
    }

    #[test]
    fn oversize_frames_are_refused() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&((MAX_FRAME_LEN as u32) + 1).to_be_bytes());
        buf.extend_from_slice(&[0u8; 8]);
        let err = read_frame(&mut buf.as_slice()).unwrap_err();
        assert!(err.to_string().contains("exceeds"), "{err}");
    }

    #[test]
    fn zero_length_frame_is_a_protocol_error_not_a_hang() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_be_bytes());
        let frame = read_frame(&mut buf.as_slice()).unwrap();
        assert!(frame.is_empty());
        let err: Result<Request, _> = decode(&frame);
        assert!(err.is_err());
    }
}
