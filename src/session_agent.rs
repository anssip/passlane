//! The CLI side of the session agent (passlane#54): every place the CLI
//! talks to the optional `passlane-agent` daemon goes through here.
//!
//! The agent is optional infrastructure: when it is not running, all the
//! `try_*` helpers return `None` and the CLI falls back to its normal
//! keychain/prompt flow. Only the explicit session commands
//! (`passlane sessions ...`, `passlane unlock --session`) require it and
//! say so.

use passlane_agent::client::{AgentClient, RevealAnswer};
use passlane_agent::error::AgentError;
use passlane_agent::protocol::{ErrorCode, GrantSpec, SecretString};
use passlane_approval::message::Scope;
use passlane_core::vault::entities::Error;
use zeroize::Zeroizing;

/// How long an "Approve for this session" choice in the ask flow is
/// held. Mirrors the approval protocol's default session cap; a unit
/// test pins the two together.
pub const REVEAL_SESSION_SECS: u32 = 900;

/// Connect if an agent is running; `None` when not (the optional path).
pub fn try_connect() -> Option<AgentClient> {
    let path = passlane_agent::default_socket_path()?;
    AgentClient::connect(&path).ok()
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

/// The vault's unlock factors held by a live agent session, if any.
/// Consumes a `once`-scoped session. Returns `None` when the agent is
/// not running or holds nothing for the vault — callers fall through to
/// the keychain/prompt flow.
pub fn try_unlock_factors(vault: &str) -> Option<Zeroizing<String>> {
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

/// Does a live agent session cover this agent-facing reveal? Returns the
/// covering session's expiry. Consumes a `once`-scoped approval.
pub fn check_reveal(vault: &str, entry: &str, field: &str) -> Option<u64> {
    let mut client = try_connect()?;
    match client.check_reveal(vault, entry, field) {
        Ok(RevealAnswer::Allowed { until }) => Some(until.unwrap_or_else(now_secs)),
        Ok(RevealAnswer::Denied) => None,
        Err(_) => None,
    }
}

/// Record an owner's "Approve for this session" choice in the agent.
/// `Ok(false)` means the agent is not running (the caller downgrades to
/// a single-use approval with a warning).
pub fn open_reveal_session(vault: &str, entry: &str, field: &str) -> Result<bool, Error> {
    let Some(mut client) = try_connect() else {
        return Ok(false);
    };
    let grant = GrantSpec::Reveal {
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

/// Revoke every agent session of one vault (best-effort, silent when the
/// agent is down). Returns how many were dropped.
pub fn revoke_vault_sessions(vault: &str) -> usize {
    try_connect()
        .and_then(|mut client| client.revoke_vault(vault).ok())
        .unwrap_or(0)
}

/// Revoke every agent session (best-effort, silent when the agent is
/// down). Returns how many were dropped.
pub fn revoke_all_sessions() -> usize {
    try_connect()
        .and_then(|mut client| client.revoke_all().ok())
        .unwrap_or(0)
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
}
