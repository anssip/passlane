//! `passlane sessions …` — manage the in-memory sessions held by the
//! passlane session agent (passlane#54).

use comfy_table::Table;
use comfy_table::presets::ASCII_MARKDOWN;

use passlane_agent::client::AgentClient;
use passlane_agent::protocol::{GrantInfo, SessionInfo};
use passlane_approval::message::Scope;

use crate::actions::Action;
use passlane_core::vault::entities::Error;

/// `passlane sessions list`
pub struct SessionsListAction {}

impl SessionsListAction {
    pub fn new() -> SessionsListAction {
        SessionsListAction {}
    }
}

impl Default for SessionsListAction {
    fn default() -> Self {
        Self::new()
    }
}

impl Action for SessionsListAction {
    fn run(&self) -> Result<String, Error> {
        let mut client = crate::session_agent::connect_or_error()?;
        let sessions = client
            .list_sessions()
            .map_err(crate::session_agent::to_error)?;
        if sessions.is_empty() {
            return Ok("No sessions — the agent is holding no approvals".to_string());
        }
        Ok(render_sessions(&sessions))
    }
}

/// Render the session table (unit-tested).
fn render_sessions(sessions: &[SessionInfo]) -> String {
    let mut table = Table::new();
    table.load_preset(ASCII_MARKDOWN);
    table.set_header(vec!["Id", "Vault", "Grant", "Scope", "Expires"]);
    for session in sessions {
        table.add_row(vec![
            short_id(&session.id),
            session.vault.clone(),
            render_grant(&session.grant),
            render_scope(&session.scope),
            render_expiry(session),
        ]);
    }
    table.to_string()
}

fn short_id(id: &str) -> String {
    id.chars().take(8).collect()
}

fn render_grant(grant: &GrantInfo) -> String {
    match grant {
        GrantInfo::Unlock {
            challenge_response: false,
        } => "unlock".to_string(),
        GrantInfo::Unlock {
            challenge_response: true,
        } => "unlock + hwkey".to_string(),
        GrantInfo::Reveal { entry, field, .. } => format!("reveal {entry}/{field}"),
        // The answer itself is never listed; the grant says it exists.
        GrantInfo::ChallengeResponse => "challenge-response".to_string(),
    }
}

fn render_scope(scope: &Scope) -> String {
    match scope {
        Scope::Once => "once".to_string(),
        Scope::Timed { seconds } => format!("{seconds}s"),
    }
}

fn render_expiry(session: &SessionInfo) -> String {
    match session.expires_at {
        Some(exp) => {
            let remaining = exp.saturating_sub(now_secs());
            chrono::DateTime::from_timestamp(exp as i64, 0)
                .map(|t| format!("in {remaining}s ({})", t.to_rfc3339()))
                .unwrap_or_else(|| format!("in {remaining}s"))
        }
        None => "on first use".to_string(),
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `passlane sessions revoke <TARGET>` — one session by id, `all`, or
/// (with the global `--vault`) every session of that vault.
pub struct SessionsRevokeAction {
    pub target: String,
    pub vault: Option<String>,
}

impl SessionsRevokeAction {
    pub fn new(target: String, vault: Option<String>) -> SessionsRevokeAction {
        SessionsRevokeAction { target, vault }
    }
}

impl Action for SessionsRevokeAction {
    fn run(&self) -> Result<String, Error> {
        let mut client = crate::session_agent::connect_or_error()?;
        if self.target == "all" {
            let count = match self.vault.as_deref() {
                Some(vault) => client
                    .revoke_vault(vault)
                    .map_err(crate::session_agent::to_error)?,
                None => client
                    .revoke_all()
                    .map_err(crate::session_agent::to_error)?,
            };
            return Ok(match self.vault.as_deref() {
                Some(vault) => format!("Revoked {count} session(s) of vault '{vault}'"),
                None => format!("Revoked {count} session(s)"),
            });
        }
        revoke_one(&mut client, &self.target)
    }
}

/// Revoke by id or by the short prefix `sessions list` shows: list,
/// prefix-match, revoke the unique hit.
fn revoke_one(client: &mut AgentClient, target: &str) -> Result<String, Error> {
    let sessions = client
        .list_sessions()
        .map_err(crate::session_agent::to_error)?;
    let matches: Vec<&SessionInfo> = sessions
        .iter()
        .filter(|s| s.id == target || s.id.starts_with(target))
        .collect();
    match matches.as_slice() {
        [one] => {
            client
                .revoke_session(&one.id)
                .map_err(crate::session_agent::to_error)?;
            Ok(format!(
                "Revoked session '{}' (vault '{}')",
                one.id, one.vault
            ))
        }
        [] => Err(Error::new(&format!(
            "No session matches '{target}'. See 'passlane sessions list'."
        ))),
        many => Err(Error::new(&format!(
            "'{target}' is ambiguous: it matches {} sessions ({:?}); use more characters.",
            many.len(),
            many.iter().map(|s| short_id(&s.id)).collect::<Vec<_>>()
        ))),
    }
}

/// `passlane sessions lock` — drop everything the agent holds; it keeps
/// running (and connected CLIs are notified).
pub struct SessionsLockAction {}

impl SessionsLockAction {
    pub fn new() -> SessionsLockAction {
        SessionsLockAction {}
    }
}

impl Default for SessionsLockAction {
    fn default() -> Self {
        Self::new()
    }
}

impl Action for SessionsLockAction {
    fn run(&self) -> Result<String, Error> {
        let mut client = crate::session_agent::connect_or_error()?;
        client.lock().map_err(crate::session_agent::to_error)?;
        Ok("Session agent locked — every session was revoked and wiped".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(
        id: &str,
        vault: &str,
        grant: GrantInfo,
        scope: Scope,
        expires_at: Option<u64>,
    ) -> SessionInfo {
        SessionInfo {
            id: id.to_string(),
            vault: vault.to_string(),
            grant,
            scope,
            created_at: 1_000,
            expires_at,
        }
    }

    #[test]
    fn table_shows_grants_scopes_and_expiry() {
        let sessions = vec![
            info(
                "11111111-2222-3333-4444-555555555555",
                "work",
                GrantInfo::Unlock {
                    challenge_response: false,
                },
                Scope::Timed { seconds: 900 },
                Some(now_secs() + 900),
            ),
            info(
                "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "work",
                GrantInfo::Unlock {
                    challenge_response: true,
                },
                Scope::Timed { seconds: 900 },
                Some(now_secs() + 900),
            ),
            info(
                "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "work",
                GrantInfo::Reveal {
                    id: "11111111-1111-1111-1111-111111111111".into(),
                    entry: "github.com".into(),
                    field: "password".into(),
                },
                Scope::Once,
                None,
            ),
        ];
        let table = render_sessions(&sessions);
        assert!(table.contains("11111111"), "short id: {table}");
        // A session that also holds the vault's hardware-key factor says
        // so: with only "unlock" there is no telling whether the key is
        // still needed for every command.
        let grants: Vec<&str> = table
            .lines()
            .filter(|line| !line.starts_with("|-"))
            .filter_map(|line| line.split('|').nth(3))
            .map(str::trim)
            .collect();
        assert_eq!(
            grants,
            [
                "Grant",
                "unlock",
                "unlock + hwkey",
                "reveal github.com/password"
            ]
        );
        assert!(table.contains("reveal github.com/password"), "{table}");
        assert!(table.contains("900s"), "{table}");
        assert!(table.contains("once"), "{table}");
        assert!(table.contains("on first use"), "{table}");
        assert!(table.contains("in "), "{table}");
    }

    #[test]
    fn short_id_is_the_first_eight_characters() {
        assert_eq!(short_id("11111111-2222-3333-4444-555555555555"), "11111111");
    }
}
