//! The CLI side of the session agent (passlane#54): every place the CLI
//! talks to the optional `passlane-agent` daemon goes through here.
//!
//! The agent is optional infrastructure: when it is not running, all the
//! `try_*` helpers return `None` and the CLI falls back to its normal
//! keychain/prompt flow. Only the explicit session commands
//! (`passlane sessions ...`, `passlane unlock --session`) require it and
//! say so.

use passlane_agent::client::{AgentClient, EventStream, RevealAnswer};
use passlane_agent::error::AgentError;
use passlane_agent::protocol::{ErrorCode, GrantSpec, SecretString};
use passlane_approval::message::Scope;
use passlane_core::vault::entities::Error;
use zeroize::Zeroizing;

/// How long an "Approve for this session" choice in the ask flow is
/// held. Mirrors the approval protocol's default session cap; a unit
/// test pins the two together.
pub const REVEAL_SESSION_SECS: u32 = 900;

/// Connect to the agent, or report precisely why not. `Err(NotRunning)`
/// means genuinely absent (no path configured, no socket, nothing
/// listening) — the optional path. Every other error (untrusted socket,
/// ownership probe failure, transient I/O) is returned to the caller:
/// treating it as "absent" could report a vault locked while the agent
/// still holds live sessions.
pub fn connect_result() -> Result<AgentClient, AgentError> {
    let path = passlane_agent::default_socket_path()
        .ok_or_else(|| AgentError::NotRunning("no socket path configured".into()))?;
    AgentClient::connect(&path)
}

/// Connect if an agent is running; `None` when genuinely absent (the
/// optional path). Unexpected errors are reported on stderr, never
/// silently treated as absence.
pub fn try_connect() -> Option<AgentClient> {
    match connect_result() {
        Ok(client) => Some(client),
        Err(AgentError::NotRunning(_)) => None,
        Err(e) => {
            eprintln!("Warning: could not reach the session agent: {e}");
            None
        }
    }
}

/// Connect or explain how to start the agent (the required path).
pub fn connect_or_error() -> Result<AgentClient, Error> {
    match try_connect() {
        Some(client) => Ok(client),
        None => Err(not_running_error()),
    }
}

pub(crate) fn not_running_error() -> Error {
    Error::new(
        "The passlane session agent is not running. Start it with 'passlane-agent' \
         (see docs/features/session-agent.md for autostart setup), then try again.",
    )
}

/// Map an agent error into a CLI error.
pub fn to_error(e: AgentError) -> Error {
    Error::new(&format!("session agent error: {e}"))
}

/// The vault's unlock factors held by a live agent session, if any,
/// together with the serving session's expiry (unix seconds; `None`
/// for a consumed `once` session) — long-running callers revalidate
/// against it after subscribing to events. Consumes a `once`-scoped
/// session. Returns `None` when the agent is not running or holds
/// nothing for the vault — callers fall through to the keychain/prompt
/// flow.
pub fn try_unlock_factors_with_expiry(vault: &str) -> Option<(Zeroizing<String>, Option<u64>)> {
    let mut client = try_connect()?;
    match client.get_unlock_factors(vault) {
        Ok(factors) => Some(factors),
        Err(AgentError::Server {
            code: ErrorCode::NotFound,
            ..
        }) => None,
        Err(AgentError::NotRunning(_)) => None,
        Err(e) => {
            eprintln!("Warning: the session agent errored and was skipped: {e}");
            None
        }
    }
}

/// [`try_unlock_factors_with_expiry`] without the expiry (callers that
/// only need the password).
pub fn try_unlock_factors(vault: &str) -> Option<Zeroizing<String>> {
    try_unlock_factors_with_expiry(vault).map(|(password, _)| password)
}

/// Hold a vault's master password in the agent for `secs` seconds
/// (memory only, never the keychain). Returns the session's expiry
/// (unix seconds).
pub fn create_unlock_session(vault: &str, master_password: &str, secs: u64) -> Result<u64, Error> {
    let mut client = connect_or_error()?;
    let grant = GrantSpec::Unlock {
        master_password: SecretString::new(master_password),
    };
    let secs = secs.min(u32::MAX as u64) as u32;
    match client.create_session(vault, grant, Scope::Timed { seconds: secs }) {
        Ok(created) => Ok(created.expires_at.unwrap_or(0)),
        Err(AgentError::Server {
            code: ErrorCode::TooLong,
            message,
        }) => Err(Error::new(&format!(
            "{message}. Restart passlane-agent with a higher --max-session-secs if you \
             really need a longer session (the hard cap is 28800s)."
        ))),
        Err(e) => Err(to_error(e)),
    }
}

/// Does a live agent session cover this agent-facing reveal, matched by
/// the entry's stable UUID? Returns the covering session's expiry.
/// Consumes a `once`-scoped approval.
pub fn check_reveal(vault: &str, entry_id: &str, field: &str) -> Option<u64> {
    let mut client = try_connect()?;
    match client.check_reveal(vault, entry_id, field) {
        Ok(RevealAnswer::Allowed { until }) => Some(until.unwrap_or_else(now_secs)),
        Ok(RevealAnswer::Denied) => None,
        Err(_) => None,
    }
}

/// Record an owner's "Approve for this session" choice in the agent.
/// `Ok(false)` means the agent is not running (the caller downgrades to
/// a single-use approval with a warning). The grant is keyed by the
/// entry's UUID; the title travels for display only.
pub fn open_reveal_session(
    vault: &str,
    entry_id: &str,
    entry: &str,
    field: &str,
) -> Result<bool, Error> {
    let Some(mut client) = try_connect() else {
        return Ok(false);
    };
    let grant = GrantSpec::Reveal {
        id: entry_id.to_string(),
        entry: entry.to_string(),
        field: field.to_string(),
    };
    match client.create_session(
        vault,
        grant,
        Scope::Timed {
            seconds: REVEAL_SESSION_SECS,
        },
    ) {
        Ok(_) => Ok(true),
        Err(AgentError::Server {
            code: ErrorCode::TooLong,
            message,
        }) => Err(Error::new(&format!(
            "{message}. The ask flow holds {REVEAL_SESSION_SECS}s approvals; restart \
             passlane-agent with --max-session-secs 900 or higher."
        ))),
        Err(e) => Err(to_error(e)),
    }
}

/// What happened when asking the agent to drop sessions for `lock`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeOutcome {
    /// No agent is running: nothing to revoke, nothing to report.
    AgentAbsent,
    /// The agent dropped this many sessions.
    Revoked(usize),
    /// The agent is running but the revocation failed — the vault may
    /// still be unlockable through it. `lock` must not claim success.
    Failed,
}

fn revoke(action: impl FnOnce(&mut AgentClient) -> Result<usize, AgentError>) -> RevokeOutcome {
    let mut client = match connect_result() {
        Ok(client) => client,
        // Genuinely absent: nothing to revoke, nothing to report.
        Err(AgentError::NotRunning(_)) => return RevokeOutcome::AgentAbsent,
        // Present but unreachable/untrusted: the agent may still hold
        // live sessions — never report plain success.
        Err(e) => {
            eprintln!(
                "Warning: could not reach the session agent to revoke its sessions: {e} — \
                 the vault may remain unlockable through it (run 'passlane sessions \
                 revoke all')."
            );
            return RevokeOutcome::Failed;
        }
    };
    match action(&mut client) {
        Ok(count) => RevokeOutcome::Revoked(count),
        Err(e) => {
            eprintln!(
                "Warning: could not revoke the session agent's sessions: {e} — the vault \
                 may remain unlockable through the agent (run 'passlane sessions revoke all')."
            );
            RevokeOutcome::Failed
        }
    }
}

/// Revoke every agent session of one vault (silent only when the agent
/// is absent).
pub fn revoke_vault_sessions(vault: &str) -> RevokeOutcome {
    revoke(|client| client.revoke_vault(vault))
}

/// Revoke every agent session (silent only when the agent is absent).
pub fn revoke_all_sessions() -> RevokeOutcome {
    revoke(|client| client.revoke_all())
}

/// Subscribe to the agent's push events, for long-running actions that
/// should stop when the session they rely on ends (revocation, expiry,
/// lock). `None` when no agent is running.
pub fn subscribe_to_events() -> Option<EventStream> {
    try_connect().and_then(|client| client.subscribe().ok())
}

/// Whether a pushed event means the given vault's session-backed access
/// just ended.
pub fn event_ends_access(event: &passlane_agent::protocol::Event, vault: &str) -> bool {
    use passlane_agent::protocol::Event;
    match event {
        Event::SessionsLocked => true,
        Event::SessionRevoked { vault: v, .. } | Event::SessionExpired { vault: v, .. } => {
            v == vault
        }
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use passlane_approval::policy::Policy;

    /// The ask flow's held duration must track the approval protocol's
    /// default session cap, so a phone-granted approval and an
    /// interactive one age out together.
    #[test]
    fn reveal_session_secs_mirror_the_protocol_default_cap() {
        assert_eq!(
            REVEAL_SESSION_SECS as u64,
            Policy::default().max_session_secs
        );
    }

    #[test]
    fn events_that_end_access() {
        use passlane_agent::protocol::Event;
        assert!(event_ends_access(
            &Event::SessionRevoked {
                id: "x".into(),
                vault: "work".into()
            },
            "work"
        ));
        assert!(event_ends_access(
            &Event::SessionExpired {
                id: "x".into(),
                vault: "work".into()
            },
            "work"
        ));
        assert!(!event_ends_access(
            &Event::SessionRevoked {
                id: "x".into(),
                vault: "other".into()
            },
            "work"
        ));
        // A lock drops everything, any vault.
        assert!(event_ends_access(&Event::SessionsLocked, "work"));
    }
}
