//! The CLI side of the session agent (passlane#54): every place the CLI
//! talks to the optional `passlane-agent` daemon goes through here.
//!
//! The agent is optional infrastructure: when it is not running, all the
//! `try_*` helpers return `None` and the CLI falls back to its normal
//! keychain/prompt flow. Only the explicit session commands
//! (`passlane sessions ...`, `passlane unlock --session`) require it and
//! say so.
//!
//! "Not running" means no agent was found where none was promised. A
//! socket named by `PASSLANE_AGENT_SOCK` that nothing serves, an
//! untrusted socket, an agent speaking another protocol dialect — those
//! are reported, never treated as absence: quietly moving on to the
//! keychain or a password prompt is exactly how an agent context ends up
//! blocked on a dialog nobody can answer (passlane#65).

use std::path::PathBuf;

use keepass_ng::ChallengeResponseKey;
use passlane_agent::SOCKET_ENV;
use passlane_agent::client::{AgentClient, EventStream, RevealAnswer, UnlockFactors};
use passlane_agent::error::AgentError;
use passlane_agent::protocol::{ChallengeResponseMaterial, ErrorCode, GrantSpec, SecretString};
use passlane_approval::message::Scope;
use passlane_core::vault::entities::Error;

/// How long an "Approve for this session" choice in the ask flow is
/// held. Mirrors the approval protocol's default session cap; a unit
/// test pins the two together.
pub const REVEAL_SESSION_SECS: u32 = 900;

/// Connect to the agent, or report precisely why not. `Err(NotRunning)`
/// means genuinely absent (no path configured, no socket, nothing
/// listening) — the optional path. A socket named by `PASSLANE_AGENT_SOCK`
/// that nothing serves is `Err(NotListening)`: configured, not absent.
/// Every other error (untrusted socket, ownership probe failure,
/// transient I/O, an agent speaking another protocol dialect) is returned
/// to the caller as well: treating it as "absent" could report a vault
/// locked while the agent still holds live sessions.
pub fn connect_result() -> Result<AgentClient, AgentError> {
    let configured = passlane_agent::configured_socket_path();
    let path = configured
        .clone()
        .or_else(passlane_agent::default_socket_path)
        .ok_or_else(|| AgentError::NotRunning("no socket path configured".into()))?;
    let mut client = match AgentClient::connect(&path) {
        Ok(client) => client,
        // Where there are no Unix domain sockets there is never an agent,
        // however the variable is set: it stays absent there.
        Err(AgentError::NotRunning(path)) if configured.is_some() && cfg!(unix) => {
            return Err(AgentError::NotListening(PathBuf::from(path)));
        }
        Err(e) => return Err(e),
    };
    client.check_version()?;
    Ok(client)
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
    match connect_result() {
        Ok(client) => Ok(client),
        Err(AgentError::NotRunning(_)) => Err(not_running_error()),
        Err(e) => Err(to_error(e)),
    }
}

pub(crate) fn not_running_error() -> Error {
    Error::new(
        "The passlane session agent is not running. Start it with 'passlane-agent' \
         (see docs/features/session-agent.md for autostart setup), then try again.",
    )
}

/// Map an agent error into a CLI error that says what to do about it.
pub fn to_error(e: AgentError) -> Error {
    let hint = match &e {
        AgentError::NotListening(_) => Some(format!(
            "Start it with 'passlane-agent' (see docs/features/session-agent.md for autostart \
             setup), or unset {SOCKET_ENV} to use the keychain or the password prompt instead."
        )),
        AgentError::VersionMismatch { .. } => Some(
            "Restart passlane-agent so it runs the current binary, or upgrade passlane to \
             match the running agent."
                .to_string(),
        ),
        AgentError::Protocol(_) | AgentError::Io(_) => Some(format!(
            "Check {SOCKET_ENV}: it must name the socket of a running passlane-agent started \
             by your user, in a private directory."
        )),
        AgentError::NotRunning(_) | AgentError::AlreadyRunning(_) | AgentError::Server { .. } => {
            None
        }
    };
    match hint {
        Some(hint) => Error::new(&format!("session agent error: {e}. {hint}")),
        None => Error::new(&format!("session agent error: {e}")),
    }
}

/// The unlock factors a live session-agent session holds for the vault:
/// its master password and, for a hardware-key vault, the
/// challenge-response factor when the session carries it. `Ok(None)` when
/// no agent is running or it holds nothing for this vault — the keychain
/// and the prompt follow. Any other failure is returned: a configured
/// socket nothing serves, an untrusted socket, a stale agent.
pub fn unlock_factors(vault: &str) -> Result<Option<UnlockFactors>, AgentError> {
    let mut client = connect_result()?;
    match client.get_unlock_factors(vault) {
        Ok(factors) => Ok(Some(factors)),
        Err(AgentError::Server {
            code: ErrorCode::NotFound,
            ..
        }) => Ok(None),
        Err(e) => Err(e),
    }
}

/// What a session can hold of the challenge-response key a vault was
/// opened with: the secret of a secret-backed key (a recovery secret, a
/// virtual key). A physical hardware key's secret never leaves the
/// device, so there is nothing to hold — every use of such a vault still
/// needs the key, and a session covers its master password only.
pub(crate) fn challenge_response_material(
    key: Option<&ChallengeResponseKey>,
) -> Option<ChallengeResponseMaterial> {
    match key {
        Some(ChallengeResponseKey::LocalChallenge(secret_hex)) => {
            Some(ChallengeResponseMaterial::Secret {
                secret_hex: SecretString::new(secret_hex.clone()),
            })
        }
        _ => None,
    }
}

/// Revalidate, after subscribing to agent events, that the sessions
/// backing the current action are still live — closing the gap between
/// the unlock (or reveal gate) and the subscription, where a
/// revocation, lock or expiry event would be missed. Both probes are
/// non-consuming for timed sessions, which is what the CLI creates; a
/// `once` session was already consumed by the action that used it, so
/// this correctly reports it as no longer live.
pub fn session_access_live(
    unlock_backed: bool,
    reveal_backed: bool,
    vault: &str,
    entry_id: &str,
    field: &str,
) -> bool {
    let unlock_live = !unlock_backed || {
        let mut client = match connect_result() {
            Ok(client) => client,
            Err(_) => return false,
        };
        client.get_unlock_factors(vault).is_ok()
    };
    let reveal_live = !reveal_backed || check_reveal(vault, entry_id, field).is_some();
    unlock_live && reveal_live
}

/// Hold a vault's unlock factors in the agent for `secs` seconds (memory
/// only, never the keychain): the master password and, when the vault has
/// a hardware-key factor a session can carry (see
/// [`challenge_response_material`]), that factor too. Returns the
/// session's expiry (unix seconds).
pub fn create_unlock_session(
    vault: &str,
    master_password: &str,
    challenge_response: Option<ChallengeResponseMaterial>,
    secs: u64,
) -> Result<u64, Error> {
    let mut client = connect_or_error()?;
    let grant = GrantSpec::Unlock {
        master_password: SecretString::new(master_password),
        challenge_response,
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
        // Genuinely absent: nothing to revoke, nothing to report. A socket
        // named by PASSLANE_AGENT_SOCK that nothing listens on is absent
        // too — sessions die with their agent, so none can be live.
        Err(AgentError::NotRunning(_) | AgentError::NotListening(_)) => {
            return RevokeOutcome::AgentAbsent;
        }
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
    use passlane_agent::server::{AgentConfig, AgentServer};
    use passlane_approval::policy::Policy;
    use std::path::Path;
    use std::sync::Mutex;

    /// The socket the CLI talks to is process-global (an environment
    /// variable); this is the only test in the binary that sets it.
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

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
    fn only_a_secret_backed_key_can_be_held_by_a_session() {
        let held = challenge_response_material(Some(&ChallengeResponseKey::LocalChallenge(
            "aabb".to_string(),
        )));
        assert_eq!(
            held,
            Some(ChallengeResponseMaterial::Secret {
                secret_hex: SecretString::new("aabb")
            })
        );
        // No key (a password-only vault): nothing to hold. A device-backed
        // key takes the same arm — its secret never leaves the device.
        assert_eq!(challenge_response_material(None), None);
    }

    #[test]
    fn every_agent_error_says_what_to_do_about_it() {
        let socket = std::path::PathBuf::from("/run/user/501/passlane-agent.sock");
        let not_listening = to_error(AgentError::NotListening(socket.clone()));
        assert!(
            not_listening
                .message
                .contains(&socket.display().to_string()),
            "{}",
            not_listening.message
        );
        assert!(
            not_listening.message.contains("unset PASSLANE_AGENT_SOCK"),
            "{}",
            not_listening.message
        );
        assert!(
            not_listening.message.contains("passlane-agent"),
            "{}",
            not_listening.message
        );

        let mismatch = to_error(AgentError::VersionMismatch {
            agent: 1,
            client: 2,
        });
        assert!(
            mismatch.message.contains("v1") && mismatch.message.contains("v2"),
            "{}",
            mismatch.message
        );
        assert!(
            mismatch.message.contains("Restart passlane-agent"),
            "{}",
            mismatch.message
        );

        let untrusted = to_error(AgentError::Protocol("untrusted socket".into()));
        assert!(
            untrusted.message.contains("Check PASSLANE_AGENT_SOCK"),
            "{}",
            untrusted.message
        );
        // An absent agent keeps its plain message: the hint about a
        // configured socket would be wrong for it.
        let absent = to_error(AgentError::NotRunning("x".into()));
        assert_eq!(
            absent.message,
            "session agent error: the session agent is not running (no listener on x)"
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

    /// Points the CLI at a socket for as long as it lives and puts
    /// `PASSLANE_AGENT_SOCK` back afterwards — on a failing assertion too.
    struct SocketEnv(Option<std::ffi::OsString>);

    impl SocketEnv {
        fn point_at(socket: &Path) -> Self {
            let saved = std::env::var_os(SOCKET_ENV);
            // SAFETY: test hygiene — the holder holds `ENV_MUTEX`, the only
            // code in this binary that touches the variable, for as long as
            // this lives.
            unsafe { std::env::set_var(SOCKET_ENV, socket) };
            Self(saved)
        }
    }

    impl Drop for SocketEnv {
        fn drop(&mut self) {
            // SAFETY: see `point_at`.
            unsafe {
                match self.0.take() {
                    Some(value) => std::env::set_var(SOCKET_ENV, value),
                    None => std::env::remove_var(SOCKET_ENV),
                }
            }
        }
    }

    #[test]
    fn session_backed_access_is_live_exactly_while_the_session_is() {
        let _guard = ENV_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("agent.sock");
        let server = AgentServer::bind(
            AgentConfig::new(&socket).with_sweep_interval(std::time::Duration::from_millis(20)),
        )
        .unwrap();
        let handle = server.handle();
        let served = std::thread::spawn(move || server.serve().unwrap());
        let env = SocketEnv::point_at(&socket);

        let mut client = AgentClient::connect(&socket).unwrap();
        client
            .create_session(
                "work",
                GrantSpec::Unlock {
                    master_password: SecretString::new("pw"),
                    challenge_response: None,
                },
                Scope::Timed { seconds: 300 },
            )
            .unwrap();
        assert!(
            session_access_live(true, false, "work", "entry", "code"),
            "a live session backs the access"
        );
        assert!(
            !session_access_live(true, false, "other", "entry", "code"),
            "a session for another vault does not"
        );
        client.revoke_vault("work").unwrap();
        assert!(
            !session_access_live(true, false, "work", "entry", "code"),
            "a revoked session no longer does"
        );
        assert!(
            session_access_live(false, false, "work", "entry", "code"),
            "nothing is session-backed: nothing to be live"
        );

        drop(env);
        handle.stop();
        served.join().unwrap();
    }

    #[test]
    fn locking_reports_an_agent_it_cannot_trust_but_not_one_that_is_not_there() {
        let _guard = ENV_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let nowhere = SocketEnv::point_at(&dir.path().join("nowhere.sock"));
        let absent = revoke_vault_sessions("work");
        drop(nowhere);

        let not_a_socket = dir.path().join("plain.file");
        std::fs::write(&not_a_socket, "x").unwrap();
        let untrusted_env = SocketEnv::point_at(&not_a_socket);
        let untrusted = revoke_vault_sessions("work");
        drop(untrusted_env);

        assert_eq!(
            absent,
            RevokeOutcome::AgentAbsent,
            "nothing listens there: no session can be live"
        );
        assert_eq!(
            untrusted,
            RevokeOutcome::Failed,
            "an agent that may be serving from an untrusted socket is not reported absent"
        );
    }
}
