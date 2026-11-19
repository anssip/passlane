//! The per-entry agent policy (`agent = never | ask | allow`) and the CLI
//! side of its approval flow (passlane#50, PLAN §3.3 Phase 0).
//!
//! Entries carry their policy as a standard KeePass custom attribute so it
//! survives round-trips through other KeePass clients. The CLI enforces it
//! **cooperatively** on its own reveal paths: reveals aimed at program
//! consumption (stdout output such as `show --out`, `list --json`, TOTP
//! `--once`/`--code`, and anything run without an interactive terminal) are
//! agent-facing and governed by the policy, while the owner's interactive
//! use (tables, prompts, clipboard) is not.
//!
//! The `ask` policy triggers the approval flow. Until the approval link
//! transport ships, the flow defers to the interactive prompt: an
//! agent-facing reveal records an approval request in the local approval
//! log and withholds the secret; the owner resolves it by revealing the
//! entry interactively and confirming the prompt. The request is recorded
//! as the protocol's real [`Body::ApprovalRequest`] (crates/passlane-approval)
//! — the same body the link transport will later carry to the approver.
//!
//! See docs/features/agent-approvals.md for the full semantics, the
//! cooperative-enforcement caveat, and the phone-gated-vault guidance.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::Serialize;
use uuid::Uuid;

use passlane_approval::message::{Body, Operation, Scope};

use passlane_core::vault::entities::{AgentPolicy, Error};

/// The approval log file name inside the passlane config directory.
const APPROVAL_LOG_FILENAME: &str = "approvals.log";
/// Environment override for the approval log location. The CLI
/// verification flows and tests use it to avoid touching the real
/// `~/.passlane`; pointing it elsewhere only hides audit lines, it grants
/// nothing (the policy still applies).
const APPROVAL_LOG_ENV: &str = "PASSLANE_APPROVAL_LOG";

/// Who is asking for the secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevealContext {
    /// A human at the terminal: interactive tables, prompts and the
    /// clipboard. The owner's own reveal is the approval.
    Owner,
    /// A reveal aimed at program consumption: printed to stdout
    /// (`show --out`, `list --json`/`-v`, TOTP `--once`/`--code`), or any
    /// reveal attempted without an interactive terminal. These are the
    /// paths the agent skill uses, so the agent policy governs them.
    Agent,
}

impl RevealContext {
    /// Classify a reveal: the stdout-printing paths are agent-facing even
    /// at a terminal (they are the documented scripting surface), and so
    /// is everything else when stdin is not a terminal, because then
    /// there is no interactive owner to approve the reveal.
    pub fn for_reveal(stdout_reveal: bool) -> Self {
        Self::classify(stdin_is_interactive(), stdout_reveal)
    }

    /// The classification rule, with the terminal check injected so the
    /// rule itself is deterministically testable.
    pub fn classify(interactive_stdin: bool, stdout_reveal: bool) -> Self {
        if stdout_reveal || !interactive_stdin {
            Self::Agent
        } else {
            Self::Owner
        }
    }
}

fn stdin_is_interactive() -> bool {
    std::io::stdin().is_terminal()
}

/// What the policy says about a reveal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevealDecision {
    /// Reveal the secret.
    Reveal,
    /// An owner approval is required first (`agent = ask`).
    NeedApproval,
    /// The policy forbids this reveal (`agent = never`, agent-facing).
    Block,
}

/// Apply the policy to one reveal.
///
/// - `allow` always reveals.
/// - `never` blocks agent-facing reveals; the owner's interactive reveal
///   is not agent access, so it goes through.
/// - `ask` always needs an approval, in either context: interactively the
///   approval is the prompt, elsewhere it is a recorded request.
pub fn decide(policy: AgentPolicy, context: RevealContext) -> RevealDecision {
    match (policy, context) {
        (AgentPolicy::Allow, _) => RevealDecision::Reveal,
        (AgentPolicy::Never, RevealContext::Owner) => RevealDecision::Reveal,
        (AgentPolicy::Never, RevealContext::Agent) => RevealDecision::Block,
        (AgentPolicy::Ask, _) => RevealDecision::NeedApproval,
    }
}

/// One line of the append-only approval log (JSONL). Entry titles are
/// sensitive metadata, so the file is created owner-only.
#[derive(Serialize)]
struct ApprovalEvent<'a> {
    /// RFC 3339 timestamp.
    ts: String,
    /// `request`, `decision` or `blocked`.
    event: &'a str,
    /// Correlates a `decision` with its `request`.
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<&'a str>,
    vault: &'a str,
    entry: &'a str,
    field: &'a str,
    /// The policy that was in effect.
    policy: &'a str,
    requester: String,
    /// The protocol approval request this event corresponds to; the body
    /// the link transport will later carry to the approver.
    #[serde(skip_serializing_if = "Option::is_none")]
    request: Option<Body>,
    /// `approved` or `denied` on decisions.
    #[serde(skip_serializing_if = "Option::is_none")]
    decision: Option<&'a str>,
}

/// The local approval log: `~/.passlane/approvals.log` by default, plain
/// JSONL, append-only.
pub struct ApprovalLog {
    path: PathBuf,
}

impl ApprovalLog {
    /// The log every command writes to: `~/.passlane/approvals.log`,
    /// overridable with `PASSLANE_APPROVAL_LOG` for tests and scripted
    /// verification. Lazy: the directory is created only when an event is
    /// actually appended.
    pub fn default_path() -> Self {
        Self {
            path: std::env::var(APPROVAL_LOG_ENV)
                .ok()
                .filter(|p| !p.is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("~"));
                    home.join(".passlane").join(APPROVAL_LOG_FILENAME)
                }),
        }
    }

    /// A log at an explicit path (tests).
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Record an approval request for an `ask` entry and return its id.
    pub fn log_request(
        &self,
        vault: &str,
        entry: &str,
        field: &str,
        policy: AgentPolicy,
    ) -> String {
        let id = Uuid::new_v4().to_string();
        self.append(&ApprovalEvent {
            ts: Utc::now().to_rfc3339(),
            event: "request",
            id: Some(&id),
            vault,
            entry,
            field,
            policy: policy.as_str(),
            requester: requester(),
            request: Some(approval_request_body(vault, entry, field)),
            decision: None,
        });
        id
    }

    /// Record how an approval request was resolved.
    pub fn log_decision(
        &self,
        id: &str,
        vault: &str,
        entry: &str,
        field: &str,
        policy: AgentPolicy,
        approved: bool,
    ) {
        self.append(&ApprovalEvent {
            ts: Utc::now().to_rfc3339(),
            event: "decision",
            id: Some(id),
            vault,
            entry,
            field,
            policy: policy.as_str(),
            requester: requester(),
            request: None,
            decision: Some(if approved { "approved" } else { "denied" }),
        });
    }

    /// Record that an agent-facing reveal was blocked by `agent = never`.
    pub fn log_blocked(&self, vault: &str, entry: &str, field: &str) {
        self.append(&ApprovalEvent {
            ts: Utc::now().to_rfc3339(),
            event: "blocked",
            id: None,
            vault,
            entry,
            field,
            policy: AgentPolicy::Never.as_str(),
            requester: requester(),
            request: None,
            decision: None,
        });
    }

    fn append(&self, event: &ApprovalEvent<'_>) {
        match serde_json::to_string(event) {
            Ok(line) => {
                if let Err(e) = append_line(&self.path, &line) {
                    eprintln!(
                        "Warning: could not write the approval log at '{}': {}",
                        self.path.display(),
                        e
                    );
                }
            }
            Err(e) => eprintln!("Warning: could not serialize an approval event: {}", e),
        }
    }
}

/// The protocol body for a reveal approval request. This is the exact
/// message the link transport (passlane#51) will seal and carry to the
/// approver; the log records it so a pending request is already in its
/// wire shape.
fn approval_request_body(vault: &str, entry: &str, field: &str) -> Body {
    Body::ApprovalRequest {
        vault_id: vault.to_string(),
        vault_name: vault.to_string(),
        operation: Operation::Reveal {
            entry: entry.to_string(),
            field: field.to_string(),
        },
        requester: requester(),
        scope: Scope::Once,
        challenge: None,
    }
}

/// Append one line, creating the file owner-only on first use. Append
/// mode keeps earlier events intact — the log is append-only by
/// construction.
fn append_line(path: &Path, line: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    use std::io::Write;
    writeln!(file, "{}", line)
}

/// Best-effort identity of the local requester for the log: the user the
/// process runs as. (The protocol's `requester` field is "user@host for
/// the CLI"; a reliable host name needs the pairing machinery, so the
/// local log records the user only.)
fn requester() -> String {
    std::env::var("USER")
        .ok()
        .filter(|u| !u.is_empty())
        .or_else(|| std::env::var("USERNAME").ok().filter(|u| !u.is_empty()))
        .unwrap_or_else(|| "unknown".to_string())
}

/// True when a reveal would run in an agent-facing context. Convenience
/// for display code (tables) that needs the same classification as the
/// gates.
pub fn in_agent_context(stdout_reveal: bool) -> bool {
    RevealContext::for_reveal(stdout_reveal) == RevealContext::Agent
}

/// The current vault's name, best-effort, for log lines.
pub(crate) fn current_vault_name() -> String {
    crate::vault_registry::current()
        .map(|v| v.name)
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Enforce `policy` for one reveal using the default approval log, running
/// the Phase 0 ask flow (interactive prompt) for `ask` entries in an owner
/// context.
pub fn enforce_reveal(
    policy: AgentPolicy,
    context: RevealContext,
    entry: &str,
    field: &str,
) -> Result<(), Error> {
    enforce_with(&ApprovalLog::default_path(), policy, context, entry, field)
}

/// [`enforce_reveal`] with the approval log injected, and the interactive
/// approval prompt injected so the ask flow is testable without a
/// terminal.
pub fn enforce_with_prompt<F>(
    log: &ApprovalLog,
    policy: AgentPolicy,
    context: RevealContext,
    entry: &str,
    field: &str,
    prompt: F,
) -> Result<(), Error>
where
    F: FnOnce() -> bool,
{
    let vault = current_vault_name();
    match decide(policy, context) {
        RevealDecision::Reveal => Ok(()),
        RevealDecision::NeedApproval => {
            if context == RevealContext::Agent {
                let id = log.log_request(&vault, entry, field, policy);
                Err(Error::new(&format!(
                    "Entry '{}' needs owner approval (agent=ask). Approval request {} was \
                     recorded in the approval log ({}). Until the approval link ships, the \
                     owner performs the reveal interactively instead: passlane show '{}'",
                    entry,
                    id,
                    log.path().display(),
                    entry
                )))
            } else {
                let id = log.log_request(&vault, entry, field, policy);
                let approved = prompt();
                log.log_decision(&id, &vault, entry, field, policy, approved);
                if approved {
                    Ok(())
                } else {
                    Err(Error::new(&format!(
                        "Reveal of '{}' denied by the owner",
                        entry
                    )))
                }
            }
        }
        RevealDecision::Block => {
            if context == RevealContext::Agent {
                log.log_blocked(&vault, entry, field);
                Err(Error::new(&format!(
                    "Entry '{}' is not available to agents (agent=never). The owner can \
                     reveal it interactively with 'passlane show \"{}\"', or change its \
                     'agent' attribute to 'ask' or 'allow'",
                    entry, entry
                )))
            } else {
                Ok(())
            }
        }
    }
}

/// [`enforce_with_prompt`] with the real interactive prompt.
pub fn enforce_with(
    log: &ApprovalLog,
    policy: AgentPolicy,
    context: RevealContext,
    entry: &str,
    field: &str,
) -> Result<(), Error> {
    enforce_with_prompt(log, policy, context, entry, field, || {
        ask_approval(entry, field)
    })
}

/// The Phase 0 ask flow in an owner context: the interactive prompt *is*
/// the deferred approval. A failed prompt (no terminal, EOF) denies.
fn ask_approval(entry: &str, field: &str) -> bool {
    inquire::Select::new(
        &format!("Approve revealing the {field} of '{entry}'? (agent=ask)"),
        vec!["Approve once", "Deny"],
    )
    .prompt()
    .map(|answer| answer == "Approve once")
    .unwrap_or(false)
}

/// Bulk stdout outputs (`list`, `export`) withhold `ask` entries without
/// failing the command; each withheld entry still enters the ask flow with
/// a recorded approval request, so the owner sees what an agent wanted.
/// Metadata-only listings never call this. When `approved_by_owner` is set
/// (an interactive owner chose to include the entries), the request is
/// immediately resolved with a matching decision.
pub fn log_bulk_ask_requests(
    entries: impl Iterator<Item = (String, AgentPolicy)>,
    field: &str,
    approved_by_owner: bool,
) {
    log_bulk_ask_requests_with(&ApprovalLog::default_path(), entries, field, approved_by_owner);
}

/// [`log_bulk_ask_requests`] with the approval log injected (tests).
pub fn log_bulk_ask_requests_with(
    log: &ApprovalLog,
    entries: impl Iterator<Item = (String, AgentPolicy)>,
    field: &str,
    approved_by_owner: bool,
) {
    let vault = current_vault_name();
    for (entry, policy) in entries {
        if decide(policy, RevealContext::Agent) == RevealDecision::NeedApproval {
            let id = log.log_request(&vault, &entry, field, policy);
            if approved_by_owner {
                log.log_decision(&id, &vault, &entry, field, policy, true);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log_in_tempdir() -> (ApprovalLog, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let log = ApprovalLog::at(dir.path().join("approvals.log"));
        (log, dir)
    }

    fn lines(log: &ApprovalLog) -> Vec<serde_json::Value> {
        std::fs::read_to_string(log.path())
            .unwrap()
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[test]
    fn classify_rule() {
        // Stdout reveals are agent-facing even at a terminal.
        assert_eq!(RevealContext::classify(true, true), RevealContext::Agent);
        // Interactive stdin with a non-stdout reveal is the owner.
        assert_eq!(RevealContext::classify(true, false), RevealContext::Owner);
        // Without an interactive terminal there is no owner to approve.
        assert_eq!(RevealContext::classify(false, false), RevealContext::Agent);
        assert_eq!(RevealContext::classify(false, true), RevealContext::Agent);
    }

    #[test]
    fn for_reveal_stdout_is_always_agent_facing() {
        // Deterministic regardless of what stdin the test runner has.
        assert_eq!(RevealContext::for_reveal(true), RevealContext::Agent);
    }

    #[test]
    fn decide_matrix() {
        use AgentPolicy::*;
        let o = RevealContext::Owner;
        let a = RevealContext::Agent;
        assert_eq!(decide(Allow, o), RevealDecision::Reveal);
        assert_eq!(decide(Allow, a), RevealDecision::Reveal);
        // The owner's own reveal is not agent access.
        assert_eq!(decide(Never, o), RevealDecision::Reveal);
        assert_eq!(decide(Never, a), RevealDecision::Block);
        // ask needs an approval in both contexts.
        assert_eq!(decide(Ask, o), RevealDecision::NeedApproval);
        assert_eq!(decide(Ask, a), RevealDecision::NeedApproval);
    }

    #[test]
    fn request_event_carries_the_protocol_body() {
        let (log, _dir) = log_in_tempdir();
        let id = log.log_request("default", "Stripe test key", "password", AgentPolicy::Ask);

        let events = lines(&log);
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event["event"], "request");
        assert_eq!(event["id"], id.as_str());
        assert_eq!(event["vault"], "default");
        assert_eq!(event["entry"], "Stripe test key");
        assert_eq!(event["field"], "password");
        assert_eq!(event["policy"], "ask");
        assert!(event["requester"].as_str().is_some_and(|r| !r.is_empty()));
        // The real protocol body: an approval_request carrying a reveal
        // operation for the exact entry and field, scoped once.
        let request = &event["request"];
        assert_eq!(request["type"], "approval_request");
        assert_eq!(request["vault_name"], "default");
        assert_eq!(request["operation"]["kind"], "reveal");
        assert_eq!(request["operation"]["entry"], "Stripe test key");
        assert_eq!(request["operation"]["field"], "password");
        assert_eq!(request["scope"]["kind"], "once");
    }

    #[test]
    fn decision_event_correlates_with_request() {
        let (log, _dir) = log_in_tempdir();
        let id = log.log_request("default", "GitHub", "code", AgentPolicy::Ask);
        log.log_decision(&id, "default", "GitHub", "code", AgentPolicy::Ask, true);

        let events = lines(&log);
        assert_eq!(events.len(), 2, "the log is append-only");
        assert_eq!(events[0]["event"], "request");
        assert_eq!(events[1]["event"], "decision");
        assert_eq!(events[1]["id"], id.as_str());
        assert_eq!(events[1]["decision"], "approved");
    }

    #[test]
    fn blocked_event_records_a_never_reveal_attempt() {
        let (log, _dir) = log_in_tempdir();
        log.log_blocked("default", "root password", "password");

        let events = lines(&log);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["event"], "blocked");
        assert_eq!(events[0]["policy"], "never");
        assert!(events[0].get("id").is_none() || events[0]["id"].is_null());
    }

    #[cfg(unix)]
    #[test]
    fn approval_log_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let (log, _dir) = log_in_tempdir();
        log.log_request("default", "x", "password", AgentPolicy::Ask);
        let mode = std::fs::metadata(log.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn enforce_agent_never_blocks_and_logs() {
        let (log, _dir) = log_in_tempdir();
        let result = enforce_with_prompt(
            &log,
            AgentPolicy::Never,
            RevealContext::Agent,
            "Stripe test key",
            "password",
            || panic!("no prompt in an agent context"),
        );
        let err = result.expect_err("never must block an agent reveal");
        assert!(
            err.message.contains("not available to agents"),
            "{}",
            err.message
        );
        let events = lines(&log);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["event"], "blocked");
    }

    #[test]
    fn enforce_agent_ask_withholds_and_logs_request() {
        let (log, _dir) = log_in_tempdir();
        let result = enforce_with_prompt(
            &log,
            AgentPolicy::Ask,
            RevealContext::Agent,
            "Stripe test key",
            "password",
            || panic!("no prompt in an agent context"),
        );
        let err = result.expect_err("ask must withhold in an agent context");
        assert!(
            err.message.contains("needs owner approval"),
            "{}",
            err.message
        );
        assert!(err.message.contains("approval log"), "{}", err.message);
        let events = lines(&log);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["event"], "request");
        // No decision: the request stays pending until the owner resolves it.
        assert_eq!(events[0].get("decision").and_then(|d| d.as_str()), None);
    }

    #[test]
    fn enforce_owner_ask_approved_reveals() {
        let (log, _dir) = log_in_tempdir();
        enforce_with_prompt(
            &log,
            AgentPolicy::Ask,
            RevealContext::Owner,
            "Stripe test key",
            "password",
            || true,
        )
        .expect("an approved ask must reveal");
        let events = lines(&log);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["event"], "request");
        assert_eq!(events[1]["event"], "decision");
        assert_eq!(events[1]["decision"], "approved");
    }

    #[test]
    fn enforce_owner_ask_denied_errors() {
        let (log, _dir) = log_in_tempdir();
        let result = enforce_with_prompt(
            &log,
            AgentPolicy::Ask,
            RevealContext::Owner,
            "Stripe test key",
            "password",
            || false,
        );
        assert!(result.is_err());
        let events = lines(&log);
        assert_eq!(events[1]["decision"], "denied");
    }

    #[test]
    fn enforce_owner_never_and_all_allow_reveal_without_logging() {
        let (log, _dir) = log_in_tempdir();
        for policy in [AgentPolicy::Never, AgentPolicy::Allow] {
            enforce_with_prompt(
                &log,
                policy,
                RevealContext::Owner,
                "any",
                "password",
                || panic!("owner never/allow must not prompt"),
            )
            .expect("owner reveals are not agent access");
        }
        assert!(
            !log.path().exists(),
            "nothing should be logged for owner reveals"
        );
    }

    #[test]
    fn enforce_agent_allow_reveals_without_logging() {
        let (log, _dir) = log_in_tempdir();
        enforce_with_prompt(
            &log,
            AgentPolicy::Allow,
            RevealContext::Agent,
            "any",
            "password",
            || panic!("allow must not prompt"),
        )
        .expect("allow passes agent reveals");
        assert!(!log.path().exists());
    }

    #[test]
    fn bulk_ask_requests_record_only_ask_entries() {
        let (log, _dir) = log_in_tempdir();
        log_bulk_ask_requests_with(
            &log,
            vec![
                ("GitHub".to_string(), AgentPolicy::Allow),
                ("Stripe test key".to_string(), AgentPolicy::Ask),
                ("root".to_string(), AgentPolicy::Never),
            ]
            .into_iter(),
            "password",
            false,
        );
        let events = lines(&log);
        assert_eq!(events.len(), 1, "only the ask entry enters the ask flow");
        assert_eq!(events[0]["event"], "request");
        assert_eq!(events[0]["entry"], "Stripe test key");
        assert_eq!(events[0]["field"], "password");
        assert_eq!(
            events[0].get("decision").and_then(|d| d.as_str()),
            None,
            "the request stays pending when the owner did not include it"
        );
    }

    #[test]
    fn bulk_ask_requests_resolved_when_owner_includes_them() {
        let (log, _dir) = log_in_tempdir();
        log_bulk_ask_requests_with(
            &log,
            vec![("Stripe test key".to_string(), AgentPolicy::Ask)].into_iter(),
            "password",
            true,
        );
        let events = lines(&log);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["event"], "request");
        assert_eq!(events[1]["event"], "decision");
        assert_eq!(events[1]["decision"], "approved");
        assert_eq!(events[1]["id"], events[0]["id"]);
    }
}
