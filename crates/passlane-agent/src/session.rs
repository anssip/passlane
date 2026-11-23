//! The session model: what the agent holds, for how long, and how it is
//! wiped.
//!
//! A session is one granted approval. Its scope comes from the approval
//! protocol (`passlane_approval::Scope`): `Once` dies on first use,
//! `Timed { seconds }` is reusable until it expires. The key material a
//! session may hold (a vault's master password, or a phone-held key's
//! answer for one vault file version) lives in `zeroize`-protected
//! buffers that are wiped the moment the session is dropped — by use,
//! expiry, revocation, lock or shutdown.

use passlane_approval::message::Scope;
use zeroize::Zeroizing;

use crate::protocol::GrantInfo;

/// The unlock factors a session holds in memory. Wiped on drop.
#[derive(Debug)]
pub struct KeyMaterial {
    master_password: Zeroizing<String>,
}

impl KeyMaterial {
    /// Wrap a master password.
    pub fn new(master_password: impl Into<String>) -> Self {
        Self {
            master_password: Zeroizing::new(master_password.into()),
        }
    }

    /// The held master password.
    pub fn master_password(&self) -> &str {
        &self.master_password
    }
}

// Manual Clone so the copy is zeroizing as well.
impl Clone for KeyMaterial {
    fn clone(&self) -> Self {
        Self::new(self.master_password.as_str())
    }
}

/// A challenge response a session holds in memory, with the challenge it
/// answers. Wiped on drop.
#[derive(Debug)]
pub struct ChallengeMaterial {
    /// The vault's KDF seed the answer is for, lower-case hex. Not secret
    /// (it sits in the vault file's header in cleartext); it is what
    /// makes the answer useless once the vault is re-saved.
    challenge: Zeroizing<String>,
    /// The 20-byte HMAC-SHA1 answer, lower-case hex: a vault unlock factor.
    response: Zeroizing<String>,
}

impl ChallengeMaterial {
    /// Wrap an answer and its challenge. Both must already be validated
    /// as lower-case hex of the right length.
    pub fn new(challenge: impl Into<String>, response: impl Into<String>) -> Self {
        Self {
            challenge: Zeroizing::new(challenge.into()),
            response: Zeroizing::new(response.into()),
        }
    }

    /// The challenge the answer is for.
    pub fn challenge(&self) -> &str {
        &self.challenge
    }

    /// The held answer.
    pub fn response(&self) -> &str {
        &self.response
    }
}

// Manual Clone so the copy is zeroizing as well.
impl Clone for ChallengeMaterial {
    fn clone(&self) -> Self {
        Self::new(self.challenge.as_str(), self.response.as_str())
    }
}

/// What a session grants.
pub enum Grant {
    /// Vault unlock factors (the ssh-agent "key").
    Unlock(KeyMaterial),
    /// Agent-facing reveal of one entry field (an owner's recorded
    /// "approve for this session" choice; carries no secret). Matched by
    /// the entry's stable UUID — titles are display strings and can be
    /// reused by other entries.
    Reveal {
        /// Entry UUID the approval covers.
        id: String,
        /// Entry title (display/audit only, never matched).
        entry: String,
        /// Field the approval covers (e.g. `password`, `code`).
        field: String,
    },
    /// A challenge-response answer for one vault file version (a
    /// phone-held key). Matched by the exact challenge.
    ChallengeResponse(ChallengeMaterial),
}

impl Grant {
    /// Whether this is an unlock grant.
    pub fn is_unlock(&self) -> bool {
        matches!(self, Grant::Unlock(_))
    }

    /// The answer this grant holds for exactly `challenge`, if it is a
    /// challenge-response grant for that challenge.
    pub fn challenge_response_for(&self, challenge: &str) -> Option<&str> {
        match self {
            Grant::ChallengeResponse(material) if material.challenge() == challenge => {
                Some(material.response())
            }
            _ => None,
        }
    }

    /// Whether this grant holds a challenge response (for any challenge).
    pub fn is_challenge_response(&self) -> bool {
        matches!(self, Grant::ChallengeResponse(_))
    }

    /// Whether this grant covers the given reveal, by UUID and field.
    pub fn covers_reveal(&self, id: &str, field: &str) -> bool {
        matches!(
            self,
            Grant::Reveal { id: e, field: f, .. } if e == id && f == field
        )
    }

    /// The secret-free view for listings.
    pub fn info(&self) -> GrantInfo {
        match self {
            Grant::Unlock(_) => GrantInfo::Unlock,
            Grant::Reveal { id, entry, field } => GrantInfo::Reveal {
                id: id.clone(),
                entry: entry.clone(),
                field: field.clone(),
            },
            Grant::ChallengeResponse(_) => GrantInfo::ChallengeResponse,
        }
    }
}

/// One live session.
pub struct Session {
    /// Session id (uuid v4).
    pub id: String,
    /// Vault the session belongs to (by name).
    pub vault: String,
    /// What the session grants.
    pub grant: Grant,
    /// Once / timed.
    pub scope: Scope,
    /// Creation time, unix seconds.
    pub created_at: u64,
    /// Expiry, unix seconds; `None` for `once` (dies on first use).
    pub expires_at: Option<u64>,
}

impl Session {
    /// Create a session with a fresh id; `expires_at` follows the scope.
    pub fn new(vault: impl Into<String>, grant: Grant, scope: Scope, now: u64) -> Self {
        let expires_at = match scope {
            Scope::Once => None,
            Scope::Timed { seconds } => Some(now + seconds as u64),
        };
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            vault: vault.into(),
            grant,
            scope,
            created_at: now,
            expires_at,
        }
    }

    /// Whether the session is past its expiry at `now`.
    pub fn expired(&self, now: u64) -> bool {
        self.expires_at.is_some_and(|exp| now >= exp)
    }

    /// The secret-free view for listings.
    pub fn info(&self) -> crate::protocol::SessionInfo {
        crate::protocol::SessionInfo {
            id: self.id.clone(),
            vault: self.vault.clone(),
            grant: self.grant.info(),
            scope: self.scope,
            created_at: self.created_at,
            expires_at: self.expires_at,
        }
    }
}

// Key material inside `Grant::Unlock` is held in `Zeroizing` buffers,
// so it is wiped automatically whenever a session is dropped — by
// first use, expiry, revocation, lock or shutdown.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timed_sessions_expire_at_creation_plus_seconds() {
        let s = Session::new(
            "work",
            Grant::Unlock(KeyMaterial::new("pw")),
            Scope::Timed { seconds: 60 },
            1_000,
        );
        assert_eq!(s.expires_at, Some(1_060));
        assert!(!s.expired(1_059));
        assert!(s.expired(1_060), "expiry is inclusive");
        assert!(!s.expired(500));
    }

    #[test]
    fn once_sessions_have_no_time_expiry() {
        let s = Session::new(
            "work",
            Grant::Reveal {
                id: "11111111-1111-1111-1111-111111111111".into(),
                entry: "github.com".into(),
                field: "password".into(),
            },
            Scope::Once,
            1_000,
        );
        assert_eq!(s.expires_at, None);
        assert!(!s.expired(10_000_000), "once dies on use, not on time");
    }

    #[test]
    fn grant_matching() {
        let id = "11111111-1111-1111-1111-111111111111";
        let g = Grant::Reveal {
            id: id.into(),
            entry: "github.com".into(),
            field: "password".into(),
        };
        assert!(g.covers_reveal(id, "password"));
        assert!(!g.covers_reveal(id, "code"), "field must match");
        assert!(
            !g.covers_reveal("22222222-2222-2222-2222-222222222222", "password"),
            "id must match"
        );
        // A different entry with the SAME TITLE must not inherit the approval.
        assert!(
            !Grant::Reveal {
                id: "22222222-2222-2222-2222-222222222222".into(),
                entry: "github.com".into(),
                field: "password".into(),
            }
            .covers_reveal(id, "password"),
            "title collision must not grant access"
        );
        assert!(!g.is_unlock());

        let u = Grant::Unlock(KeyMaterial::new("pw"));
        assert!(u.is_unlock());
        assert!(!u.covers_reveal("github.com", "password"));
    }

    #[test]
    fn challenge_response_matches_only_its_own_challenge() {
        let g = Grant::ChallengeResponse(ChallengeMaterial::new("ab".repeat(32), "ef".repeat(20)));
        assert!(g.is_challenge_response());
        assert!(!g.is_unlock());
        assert!(g.challenge_response_for(&"ab".repeat(32)).is_some());
        // The seed changes on every save: an answer for the previous file
        // version is not an answer for the current one.
        assert!(g.challenge_response_for(&"ac".repeat(32)).is_none());
        assert!(g.challenge_response_for("").is_none());
        // Other grant kinds hold no answer.
        assert!(
            Grant::Unlock(KeyMaterial::new("pw"))
                .challenge_response_for(&"ab".repeat(32))
                .is_none()
        );
    }

    #[test]
    fn challenge_material_clones_and_lists_without_leaking() {
        let session = Session::new(
            "work",
            Grant::ChallengeResponse(ChallengeMaterial::new("ab".repeat(32), "canary-answer")),
            Scope::Timed { seconds: 60 },
            1_000,
        );
        assert_eq!(session.info().grant, GrantInfo::ChallengeResponse);
        let json = serde_json::to_string(&session.info()).unwrap();
        assert!(!json.contains("canary"), "{json}");
        let Grant::ChallengeResponse(material) = session.grant else {
            panic!()
        };
        let clone = material.clone();
        assert_eq!(clone.response(), "canary-answer");
        assert_eq!(clone.challenge(), &"ab".repeat(32));
    }

    #[test]
    fn info_never_carries_key_material() {
        let s = Session::new(
            "work",
            Grant::Unlock(KeyMaterial::new("canary-pw")),
            Scope::Timed { seconds: 60 },
            1_000,
        );
        let info = s.info();
        assert_eq!(info.grant, GrantInfo::Unlock);
        let json = serde_json::to_string(&info).unwrap();
        assert!(
            !json.contains("canary"),
            "listing must be secret-free: {json}"
        );
    }
}
