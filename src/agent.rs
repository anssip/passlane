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
    /// is any reveal attempted without an interactive terminal on *both*
    /// sides — without an interactive stdin there is no owner present to
    /// approve, and without an interactive stdout the display itself
    /// (verbose tables, note cells) would carry secrets into a redirect
    /// or pager instead of the owner's screen.
    pub fn for_reveal(stdout_reveal: bool) -> Self {
        Self::classify(
            stdin_is_interactive(),
            stdout_reveal,
            stdout_is_interactive(),
        )
    }

    /// The classification rule, with the terminal checks injected so the
    /// rule itself is deterministically testable.
    pub fn classify(
        interactive_stdin: bool,
        stdout_reveal: bool,
        interactive_stdout: bool,
    ) -> Self {
        if stdout_reveal || !interactive_stdin || !interactive_stdout {
            Self::Agent
        } else {
            Self::Owner
        }
    }
}

fn stdin_is_interactive() -> bool {
    std::io::stdin().is_terminal()
}

fn stdout_is_interactive() -> bool {
    std::io::stdout().is_terminal()
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
    /// `request`, `decision`, `blocked`, `session` (a reveal served from
    /// a live agent session) or `session_granted` (the owner chose
    /// "Approve for this session").
    event: &'a str,
    /// Correlates a `decision` with its `request`.
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<&'a str>,
    vault: &'a str,
    entry: &'a str,
    /// The entry's stable UUID — what reveal sessions are actually keyed
    /// by, so an audit line can be tied to the exact entry even when
    /// titles collide.
    #[serde(skip_serializing_if = "Option::is_none")]
    entry_id: Option<&'a str>,
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
    /// On `session`/`session_granted`: when the covering session expires,
    /// unix seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    session_until: Option<u64>,
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
        self.log_request_with(vault, None, entry, field, policy)
    }

    /// [`ApprovalLog::log_request`] with the entry's stable UUID, so
    /// session grants (which are keyed by UUID) can be audited against
    /// the exact entry even when titles collide.
    pub fn log_request_with(
        &self,
        vault: &str,
        entry_id: Option<&str>,
        entry: &str,
        field: &str,
        policy: AgentPolicy,
    ) -> String {
        let id = Uuid::new_v4().to_string();
        self.log_request_for(&id, vault, entry_id, entry, field, policy);
        id
    }

    /// [`Self::log_request_with`] with a caller-chosen id — the link
    /// transport correlates by the protocol request id (`rid`) instead of
    /// a fresh uuid, so `passlane approve --response` decisions line up
    /// with the request events.
    #[allow(clippy::too_many_arguments)]
    pub fn log_request_for(
        &self,
        id: &str,
        vault: &str,
        entry_id: Option<&str>,
        entry: &str,
        field: &str,
        policy: AgentPolicy,
    ) {
        self.append(&ApprovalEvent {
            ts: Utc::now().to_rfc3339(),
            event: "request",
            id: Some(id),
            vault,
            entry,
            entry_id,
            field,
            policy: policy.as_str(),
            requester: requester(),
            request: Some(approval_request_body(vault, entry, field)),
            decision: None,
            session_until: None,
        });
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
        self.log_decision_with(id, vault, None, entry, field, policy, approved)
    }

    /// [`ApprovalLog::log_decision`] with the entry's UUID.
    #[allow(clippy::too_many_arguments)]
    pub fn log_decision_with(
        &self,
        id: &str,
        vault: &str,
        entry_id: Option<&str>,
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
            entry_id,
            field,
            policy: policy.as_str(),
            requester: requester(),
            request: None,
            decision: Some(if approved { "approved" } else { "denied" }),
            session_until: None,
        });
    }

    /// Record that an agent-facing reveal was served from a live agent
    /// session (an earlier "Approve for this session"): the reusable
    /// form of an approval, audited like any other reveal.
    pub fn log_session_reveal(
        &self,
        vault: &str,
        entry_id: &str,
        entry: &str,
        field: &str,
        policy: AgentPolicy,
        until: u64,
    ) {
        self.append(&ApprovalEvent {
            ts: Utc::now().to_rfc3339(),
            event: "session",
            id: None,
            vault,
            entry,
            entry_id: Some(entry_id),
            field,
            policy: policy.as_str(),
            requester: requester(),
            request: None,
            decision: Some("approved"),
            session_until: Some(until),
        });
    }

    /// Record that the owner chose "Approve for this session" and a
    /// covering session was created in the agent.
    pub fn log_session_granted(
        &self,
        vault: &str,
        entry_id: &str,
        entry: &str,
        field: &str,
        policy: AgentPolicy,
    ) {
        self.append(&ApprovalEvent {
            ts: Utc::now().to_rfc3339(),
            event: "session_granted",
            id: None,
            vault,
            entry,
            entry_id: Some(entry_id),
            field,
            policy: policy.as_str(),
            requester: requester(),
            request: None,
            decision: Some("approved"),
            session_until: None,
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
            entry_id: None,
            field,
            policy: AgentPolicy::Never.as_str(),
            requester: requester(),
            request: None,
            decision: None,
            session_until: None,
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
/// construction — and an exclusive lock around the write keeps concurrent
/// passlane invocations from interleaving lines.
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
    use fs4::FileExt;
    use std::io::Write;
    file.lock()?;
    let result = writeln!(file, "{}", line).and_then(|()| file.flush());
    file.unlock()?;
    result
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

/// The command the owner can run to reveal an entry interactively, for
/// error-message guidance. Map by the field being revealed: a bare
/// `passlane show <pattern>` only searches credentials, so TOTP, payment
/// and note entries need their type flags. When the entry's vault is not
/// the active one, the command targets it explicitly — following the
/// guidance without `--vault` would search the wrong vault.
fn owner_reveal_command(entry: &str, field: &str, vault: &str) -> String {
    with_vault_targeting(
        owner_reveal_base_command(entry, field),
        vault,
        crate::vault_registry::get_active().as_deref(),
    )
}

/// The single-code retry command for an agent-facing `ask` TOTP entry:
/// `--once` prints exactly one code (matching the single-use approval),
/// the label is shell-quoted and `--`-separated, and the vault is
/// targeted explicitly when it is not the active one.
pub(crate) fn once_code_command(entry: &str, vault: &str) -> String {
    once_code_command_for(entry, vault, crate::vault_registry::get_active().as_deref())
}

/// [`once_code_command`] with the active vault injected (testable).
fn once_code_command_for(entry: &str, vault: &str, active: Option<&str>) -> String {
    with_vault_targeting(
        format!("passlane show -o --once -- {}", shell_quote(entry)),
        vault,
        active,
    )
}

fn owner_reveal_base_command(entry: &str, field: &str) -> String {
    match field {
        "code" | "secret" => format!("passlane show -o {}", positional(entry)),
        "number" => "passlane show -p".to_string(),
        "content" => "passlane show -n".to_string(),
        _ => format!("passlane show {}", positional(entry)),
    }
}

/// The entry pattern as a command-line argument: shell-quoted, and
/// preceded by `--` when the title starts with a dash (otherwise clap
/// parses it as an option instead of the pattern).
fn positional(entry: &str) -> String {
    if entry.starts_with('-') {
        format!("-- {}", shell_quote(entry))
    } else {
        shell_quote(entry)
    }
}

/// Quote an entry title for a shell command line the owner is told to
/// paste. Titles are arbitrary user data: without quoting, a title like
/// `x'; rm -rf ~` would escape the suggested command. Plain safe names
/// stay unquoted for readability.
fn shell_quote(value: &str) -> String {
    let safe = !value.is_empty()
        && value.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '-' | '_' | '.' | '/' | ':' | '=' | '@' | '+' | '%')
        });
    if safe {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

/// Target the entry's vault with an explicit `--vault` flag unless it
/// already is the active one (no active vault at all still needs the
/// explicit target). The flag is inserted directly after the binary name:
/// it must precede any trailing `-- <pattern>` separator, after which
/// everything is a positional.
fn with_vault_targeting(command: String, vault: &str, active: Option<&str>) -> String {
    if matches!(active, Some(active) if active == vault) {
        return command;
    }
    match command.strip_prefix("passlane ") {
        Some(rest) => format!("passlane --vault {vault} {rest}"),
        None => format!("{command} --vault {vault}"),
    }
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

/// How the owner answered the ask-flow prompt. "Approve for this
/// session" additionally records a reusable reveal session in the
/// passlane session agent (passlane#54).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalChoice {
    /// Approve this one reveal.
    Once,
    /// Approve and hold a timed session covering further agent-facing
    /// reveals of this entry field.
    Session,
    /// Deny.
    Deny,
}

/// Enforce `policy` for one reveal using the default approval log, running
/// the Phase 0 ask flow (interactive prompt) for `ask` entries in an owner
/// context.
///
/// `entry_id` is the entry's stable UUID — what reveal sessions are keyed
/// by — while `entry` is the display title used in prompts and the audit
/// log.
pub fn enforce_reveal(
    policy: AgentPolicy,
    context: RevealContext,
    entry_id: &str,
    entry: &str,
    field: &str,
) -> Result<(), Error> {
    enforce_with(
        &ApprovalLog::default_path(),
        policy,
        context,
        entry_id,
        entry,
        field,
    )
}

/// [`enforce_with_prompt`] with the real interactive prompt.
pub fn enforce_with(
    log: &ApprovalLog,
    policy: AgentPolicy,
    context: RevealContext,
    entry_id: &str,
    entry: &str,
    field: &str,
) -> Result<(), Error> {
    enforce_with_prompt(log, policy, context, entry_id, entry, field, || {
        ask_approval(entry, field)
    })
}

/// [`enforce_with`] with the approval log injected, and the interactive
/// approval prompt injected so the ask flow is testable without a
/// terminal.
pub fn enforce_with_prompt<F>(
    log: &ApprovalLog,
    policy: AgentPolicy,
    context: RevealContext,
    entry_id: &str,
    entry: &str,
    field: &str,
    prompt: F,
) -> Result<(), Error>
where
    F: FnOnce() -> ApprovalChoice,
{
    enforce_with_seams(
        log,
        &crate::approvals::state_dir(),
        policy,
        context,
        entry_id,
        entry,
        field,
        &|vault, id, _entry, field| crate::session_agent::check_reveal(vault, id, field),
        &|vault, id, entry, field| {
            crate::session_agent::open_reveal_session(vault, id, entry, field).unwrap_or(false)
        },
        GateMode::Full,
        prompt,
    )
}

/// Reveal gate for surfaces that stream secrets continuously (the TOTP
/// code view): identical to [`enforce_reveal`] except that in an
/// agent-facing context a **live reveal session is the only approval**
/// that may pass it. A single-use link-transport grant must never fund an
/// endless code stream — and a session that dies between the caller's
/// own precheck and this gate must not silently fall through to grant
/// consumption, so the gate has no grant fallback at all.
pub fn enforce_reveal_session_only(
    policy: AgentPolicy,
    context: RevealContext,
    entry_id: &str,
    entry: &str,
    field: &str,
) -> Result<(), Error> {
    enforce_with_seams(
        &ApprovalLog::default_path(),
        &crate::approvals::state_dir(),
        policy,
        context,
        entry_id,
        entry,
        field,
        &|vault, id, _entry, field| crate::session_agent::check_reveal(vault, id, field),
        &|vault, id, entry, field| {
            crate::session_agent::open_reveal_session(vault, id, entry, field).unwrap_or(false)
        },
        GateMode::SessionOnly,
        // Owner contexts keep the real three-way prompt (Once / for this
        // session / Deny) — the mode only tightens the agent-facing
        // branch, which never reaches the prompt.
        || ask_approval(entry, field),
    )
}

/// Which approvals may pass an agent-facing ask gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GateMode {
    /// Sessions, single-use link grants, and link emission (the default).
    Full,
    /// Live reveal sessions only — for continuous secret views.
    SessionOnly,
}

/// The ask flow, with the approval-log and approvals-state locations
/// injected: the link transport (emission, grants) reads the same state
/// directory `passlane approve` writes.
/// Whether the most recent reveal gate in this process passed via a
/// live agent session (set by the ask flow's session consult; see
/// [`enforce_with_seams`]). Long-running reveals (the continuous TOTP
/// view) watch for that session's end too, not just a session-backed
/// vault unlock.
pub(crate) fn last_gate_used_session() -> bool {
    LAST_GATE_USED_SESSION.load(std::sync::atomic::Ordering::Relaxed)
}

static LAST_GATE_USED_SESSION: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// The ask flow with the agent consult, the session creation and the
/// link-transport state directory injected, so both integrations are
/// testable without a running agent or a real `~/.passlane`.
#[allow(clippy::too_many_arguments)]
fn enforce_with_seams<F>(
    log: &ApprovalLog,
    approvals_dir: &std::path::Path,
    policy: AgentPolicy,
    context: RevealContext,
    entry_id: &str,
    entry: &str,
    field: &str,
    check_session: &dyn Fn(&str, &str, &str, &str) -> Option<u64>,
    open_session: &dyn Fn(&str, &str, &str, &str) -> bool,
    mode: GateMode,
    prompt: F,
) -> Result<(), Error>
where
    F: FnOnce() -> ApprovalChoice,
{
    let vault = current_vault_name();
    LAST_GATE_USED_SESSION.store(false, std::sync::atomic::Ordering::Relaxed);
    match decide(policy, context) {
        RevealDecision::Reveal => Ok(()),
        RevealDecision::NeedApproval => {
            if context == RevealContext::Agent {
                // An owner's earlier "Approve for this session" covers
                // this agent-facing reveal — the reusable form of the
                // approval (passlane#54). It is audited like any reveal.
                // The covering session is matched by the entry's stable
                // UUID, so a title reused by another entry never
                // inherits the approval.
                if let Some(until) = check_session(&vault, entry_id, entry, field) {
                    log.log_session_reveal(&vault, entry_id, entry, field, policy, until);
                    LAST_GATE_USED_SESSION.store(true, std::sync::atomic::Ordering::Relaxed);
                    return Ok(());
                }
                if mode == GateMode::SessionOnly {
                    // Continuous secret views refuse here — before any
                    // single-use grant could be consumed — and point at
                    // the one-shot form instead.
                    let id = log.log_request_with(&vault, Some(entry_id), entry, field, policy);
                    return Err(Error::new(&format!(
                        "Entry '{}' needs an interactive owner or a single approved code; this \
                         view streams secrets continuously, so a one-shot approval cannot \
                         cover it (approval request {} was recorded in the approval log). Use \
                         '{}' for the single approved code",
                        entry,
                        id,
                        once_code_command(entry, &vault)
                    )));
                }

                // A single-use grant released by 'passlane approve
                // --response' stands in for the owner's answer (passlane
                // #51): consume it and reveal — exactly once.
                if let Some(rid) =
                    crate::approvals::consume_grant(approvals_dir, &vault, entry_id, field)
                {
                    log.log_decision_with(&rid, &vault, Some(entry_id), entry, field, policy, true);
                    return Ok(());
                }

                // Emit the request over the link transport when an approver
                // is pinned: link on stdout (an agent relays it in chat),
                // QR on stderr (the human at the terminal scans it).
                match crate::approvals::emit_approval_request(
                    approvals_dir,
                    &vault,
                    entry,
                    entry_id,
                    field,
                    &requester(),
                ) {
                    Ok(emitted) => {
                        println!("{}", emitted.link);
                        if let Ok(qr) = crate::approvals::render_qr(&emitted.link) {
                            eprintln!("{qr}");
                        }
                        log.log_request_for(
                            &emitted.rid,
                            &vault,
                            Some(entry_id),
                            entry,
                            field,
                            policy,
                        );
                        Err(Error::new(&format!(
                            "Entry '{}' needs owner approval (agent=ask). Approval request {} has \
                             been emitted: scan the QR or relay the link to the approver, approve \
                             it on the page, then run 'passlane approve --response <blob-from-the-page>' \
                             and re-run this command to receive the {}. The request is recorded in \
                             the approval log ({}).",
                            entry,
                            &emitted.rid[..8],
                            field,
                            log.path().display()
                        )))
                    }
                    Err(_) => {
                        // No pinned approver (or a transport failure): the
                        // pre-link guidance, with both resolution paths.
                        let id = log.log_request_with(&vault, Some(entry_id), entry, field, policy);
                        Err(Error::new(&format!(
                            "Entry '{}' needs owner approval (agent=ask). Approval request {} was \
                             recorded in the approval log ({}). The owner can approve it \
                             interactively with {} — choosing 'Approve for this session' there \
                             covers repeated agent use until the session expires — or enroll \
                             the approval page with 'passlane approvals enroll' to approve \
                             remotely",
                            entry,
                            id,
                            log.path().display(),
                            owner_reveal_command(entry, field, &vault)
                        )))
                    }
                }
            } else {
                let id = log.log_request_with(&vault, Some(entry_id), entry, field, policy);
                match prompt() {
                    ApprovalChoice::Deny => {
                        log.log_decision_with(
                            &id,
                            &vault,
                            Some(entry_id),
                            entry,
                            field,
                            policy,
                            false,
                        );
                        Err(Error::new(&format!(
                            "Reveal of '{}' denied by the owner",
                            entry
                        )))
                    }
                    ApprovalChoice::Once => {
                        log.log_decision_with(
                            &id,
                            &vault,
                            Some(entry_id),
                            entry,
                            field,
                            policy,
                            true,
                        );
                        Ok(())
                    }
                    ApprovalChoice::Session => {
                        log.log_decision_with(
                            &id,
                            &vault,
                            Some(entry_id),
                            entry,
                            field,
                            policy,
                            true,
                        );
                        if open_session(&vault, entry_id, entry, field) {
                            log.log_session_granted(&vault, entry_id, entry, field, policy);
                            Ok(())
                        } else {
                            // Approving something weaker than the owner
                            // chose must never pass silently.
                            eprintln!(
                                "Warning: the session agent is not running, so the \
                                 approval covers this reveal only. Start 'passlane-agent' \
                                 to hold 'for this session' approvals."
                            );
                            Ok(())
                        }
                    }
                }
            }
        }
        RevealDecision::Block => {
            if context == RevealContext::Agent {
                log.log_blocked(&vault, entry, field);
                Err(Error::new(&format!(
                    "Entry '{}' is not available to agents (agent=never). The owner can \
                     reveal it interactively with '{}', or change its 'agent' attribute to \
                     'ask' or 'allow'",
                    entry,
                    owner_reveal_command(entry, field, &vault)
                )))
            } else {
                Ok(())
            }
        }
    }
}

/// The Phase 0 ask flow in an owner context: the interactive prompt *is*
/// the deferred approval. A failed prompt (no terminal, EOF) denies.
fn ask_approval(entry: &str, field: &str) -> ApprovalChoice {
    let choice = inquire::Select::new(
        &format!("Approve revealing the {field} of '{entry}'? (agent=ask)"),
        vec!["Approve once", "Approve for this session", "Deny"],
    )
    .prompt();
    match choice {
        Ok("Approve once") => ApprovalChoice::Once,
        Ok("Approve for this session") => ApprovalChoice::Session,
        _ => ApprovalChoice::Deny,
    }
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
    log_bulk_ask_requests_with(
        &ApprovalLog::default_path(),
        entries,
        field,
        approved_by_owner,
    );
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

/// Bulk stdout outputs (`list --json` and friends): may this entry's
/// field be included? `allow` passes; a live reveal session covering the
/// entry passes and its use is audited; `never` and uncovered `ask`
/// stay withheld. Sessions are matched by the entry's stable UUID.
pub fn bulk_reveal_allowed(policy: AgentPolicy, entry_id: &str, entry: &str, field: &str) -> bool {
    let log = ApprovalLog::default_path();
    bulk_reveal_allowed_with(&log, policy, entry_id, entry, field, &|vault, id, field| {
        crate::session_agent::check_reveal(vault, id, field)
    })
}

/// [`bulk_reveal_allowed`] with the log and session check injected
/// (tests).
pub fn bulk_reveal_allowed_with(
    log: &ApprovalLog,
    policy: AgentPolicy,
    entry_id: &str,
    entry: &str,
    field: &str,
    check_session: &dyn Fn(&str, &str, &str) -> Option<u64>,
) -> bool {
    match decide(policy, RevealContext::Agent) {
        RevealDecision::Reveal => true,
        RevealDecision::NeedApproval => {
            let vault = current_vault_name();
            match check_session(&vault, entry_id, field) {
                Some(until) => {
                    log.log_session_reveal(&vault, entry_id, entry, field, policy, until);
                    true
                }
                None => false,
            }
        }
        RevealDecision::Block => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENTRY_ID: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

    fn log_in_tempdir() -> (ApprovalLog, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let log = ApprovalLog::at(dir.path().join("approvals.log"));
        (log, dir)
    }

    /// The ask flow against a scratch approvals state directory (so tests
    /// never touch `~/.passlane`; a pinned approver there would turn the
    /// withheld-reveal assertions into emission paths), with the
    /// session-agent seams injected like [`enforce_sessions`].
    fn ask_flow<F>(
        log: &ApprovalLog,
        approvals_dir: &std::path::Path,
        policy: AgentPolicy,
        context: RevealContext,
        entry_id: &str,
        entry: &str,
        field: &str,
        prompt: F,
    ) -> Result<(), Error>
    where
        F: FnOnce() -> ApprovalChoice,
    {
        enforce_with_seams(
            log,
            approvals_dir,
            policy,
            context,
            entry_id,
            entry,
            field,
            &|_, _, _, _| None,
            &|_, _, _, _| false,
            GateMode::Full,
            prompt,
        )
    }

    /// [`ask_flow`] with a fresh scratch state.
    fn enforce_scratch<F>(
        log: &ApprovalLog,
        policy: AgentPolicy,
        context: RevealContext,
        entry_id: &str,
        entry: &str,
        field: &str,
        prompt: F,
    ) -> Result<(), Error>
    where
        F: FnOnce() -> ApprovalChoice,
    {
        let state = tempfile::tempdir().unwrap();
        ask_flow(log, state.path(), policy, context, entry_id, entry, field, prompt)
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
        assert_eq!(
            RevealContext::classify(true, true, true),
            RevealContext::Agent
        );
        // Interactive stdin AND stdout with a non-stdout reveal is the owner.
        assert_eq!(
            RevealContext::classify(true, false, true),
            RevealContext::Owner
        );
        // Without an interactive stdin there is no owner to approve.
        assert_eq!(
            RevealContext::classify(false, false, true),
            RevealContext::Agent
        );
        // Without an interactive stdout the display itself would carry
        // secrets into a redirect or pager.
        assert_eq!(
            RevealContext::classify(true, false, false),
            RevealContext::Agent
        );
        assert_eq!(
            RevealContext::classify(false, true, false),
            RevealContext::Agent
        );
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
    fn concurrent_appends_do_not_corrupt_the_log() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("approvals.log");
        let path = std::sync::Arc::new(path);
        let mut handles = Vec::new();
        for t in 0..4 {
            let path = path.clone();
            handles.push(std::thread::spawn(move || {
                let log = ApprovalLog::at(path.as_ref());
                for i in 0..25 {
                    log.log_request(
                        "default",
                        &format!("entry-{t}-{i}"),
                        "password",
                        AgentPolicy::Ask,
                    );
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let contents = std::fs::read_to_string(path.as_ref()).unwrap();
        let count = contents.lines().filter(|l| !l.is_empty()).count();
        assert_eq!(count, 100, "every event must survive as its own line");
        for line in contents.lines() {
            let event: serde_json::Value =
                serde_json::from_str(line).expect("no interleaved/corrupt lines");
            assert_eq!(event["event"], "request");
        }
    }

    #[test]
    fn enforce_agent_never_blocks_and_logs() {
        let (log, _dir) = log_in_tempdir();
        let result = enforce_scratch(
            &log,
            AgentPolicy::Never,
            RevealContext::Agent,
            ENTRY_ID,
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
        let result = enforce_scratch(
            &log,
            AgentPolicy::Ask,
            RevealContext::Agent,
            ENTRY_ID,
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
    fn session_only_gate_never_consumes_a_link_grant() {
        // The interleaving regression (review round 6): a reveal session
        // covered the entry moments ago but dies before the continuous
        // view's gate runs — while a single-use link-transport grant
        // happens to be available. The session-only gate must refuse and
        // leave the grant intact for the one-shot retry, not consume it
        // and start streaming codes.
        let (log, _dir) = log_in_tempdir();
        let state = tempfile::tempdir().unwrap();
        let (pin, _page, _passkey) = crate::approvals::mock_page();
        crate::approvals::pin_approver(state.path(), pin, None).unwrap();

        // Seed a live single-use grant through the real emission helper.
        crate::approvals::emit_approval_request(
            state.path(),
            "default",
            "Stripe test key",
            "uuid-stripe",
            "password",
            "test",
        )
        .unwrap();
        let pending = crate::approvals::pending::PendingStore::load(state.path()).unwrap();
        let rid = pending.records()[0].rid.clone();
        let mut store = pending;
        store.grant(&rid, true, u64::MAX - 10);
        store.save().unwrap();

        // The gate: session check says "not covered" (the session died),
        // mode SessionOnly.
        let result = enforce_with_seams(
            &log,
            state.path(),
            AgentPolicy::Ask,
            RevealContext::Agent,
            "uuid-stripe",
            "Stripe test key",
            "password",
            &|_, _, _, _| None, // session dead
            &|_, _, _, _| false,
            GateMode::SessionOnly,
            || panic!("no prompt in an agent context"),
        );
        let err = result.expect_err("the session-only gate must refuse");
        assert!(
            err.message.contains("--once") || err.message.contains("one-shot"),
            "{}",
            err.message
        );

        // The grant is untouched: still live, still single-use.
        let pending = crate::approvals::pending::PendingStore::load(state.path()).unwrap();
        let record = pending.find(&rid).unwrap();
        assert!(matches!(
            record.state,
            crate::approvals::pending::RequestState::Granted { once: true, .. }
        ));
        assert_eq!(
            crate::approvals::consume_grant(state.path(), "default", "uuid-stripe", "password"),
            Some(rid),
            "the grant must remain consumable by the one-shot retry"
        );
    }

    #[test]
    fn session_only_gate_passes_on_a_live_session() {
        let (log, _dir) = log_in_tempdir();
        let state = tempfile::tempdir().unwrap();
        enforce_with_seams(
            &log,
            state.path(),
            AgentPolicy::Ask,
            RevealContext::Agent,
            ENTRY_ID,
            "Stripe test key",
            "password",
            &|_, id, e, _f| {
                assert_eq!(id, ENTRY_ID);
                assert_eq!(e, "Stripe test key");
                Some(u64::MAX - 10)
            },
            &|_, _, _, _| false,
            GateMode::SessionOnly,
            || panic!("a live session must not prompt"),
        )
        .expect("a covering session passes the session-only gate");
        assert!(last_gate_used_session());
        let events = lines(&log);
        assert_eq!(events.last().unwrap()["event"], "session");
    }

    #[test]
    fn session_only_gate_still_prompts_the_owner() {
        // The mode tightens only the agent-facing branch: an owner at the
        // terminal still gets the interactive choice — a `Deny` is
        // honored, and nothing is auto-approved or auto-denied.
        let (log, _dir) = log_in_tempdir();
        let state = tempfile::tempdir().unwrap();
        enforce_with_seams(
            &log,
            state.path(),
            AgentPolicy::Ask,
            RevealContext::Owner,
            ENTRY_ID,
            "Stripe test key",
            "password",
            &|_, _, _, _| None,
            &|_, _, _, _| false,
            GateMode::SessionOnly,
            || ApprovalChoice::Deny,
        )
        .expect_err("the owner's Deny must be honored");
        let events = lines(&log);
        assert_eq!(events.last().unwrap()["decision"], "denied");

        let (log, _dir) = log_in_tempdir();
        enforce_with_seams(
            &log,
            state.path(),
            AgentPolicy::Ask,
            RevealContext::Owner,
            ENTRY_ID,
            "Stripe test key",
            "password",
            &|_, _, _, _| None,
            &|_, _, _, _| true,
            GateMode::SessionOnly,
            || ApprovalChoice::Session,
        )
        .expect("the owner's session choice is honored too");
    }

    #[test]
    fn enforce_agent_ask_with_pinned_approver_emits_the_link() {
        // With an approver pinned, the ask flow emits the request envelope
        // over the link transport instead of only recording it: the error
        // guides through 'passlane approve --response', and the log
        // correlates by the protocol rid.
        let (log, _dir) = log_in_tempdir();
        let state = tempfile::tempdir().unwrap();
        let (pin, _page, _passkey) = crate::approvals::mock_page();
        crate::approvals::pin_approver(state.path(), pin, None).unwrap();

        let result = ask_flow(
            &log,
            state.path(),
            AgentPolicy::Ask,
            RevealContext::Agent,
            "uuid-stripe",
            "Stripe test key",
            "password",
            || panic!("no prompt in an agent context"),
        );
        let err = result.expect_err("ask must still withhold until approved");
        assert!(
            err.message.contains("passlane approve --response"),
            "{}",
            err.message
        );

        // A pending request exists, and the log's request id is its rid.
        let pending = crate::approvals::pending::PendingStore::load(state.path()).unwrap();
        assert_eq!(pending.records().len(), 1);
        let rid = pending.records()[0].rid.clone();
        let events = lines(&log);
        assert_eq!(events[0]["id"].as_str().unwrap(), rid);
    }

    #[test]
    fn enforce_agent_ask_released_by_grant_exactly_once() {
        // A grant created by 'passlane approve --response' releases the
        // agent reveal; a Scope::Once grant works a single time.
        let (log, _dir) = log_in_tempdir();
        let state = tempfile::tempdir().unwrap();
        let (pin, page, passkey) = crate::approvals::mock_page();
        crate::approvals::pin_approver(state.path(), pin, None).unwrap();

        // The ask flow emits the request; a mocked page approves it.
        let err = ask_flow(
            &log,
            state.path(),
            AgentPolicy::Ask,
            RevealContext::Agent,
            "uuid-stripe",
            "Stripe test key",
            "password",
            || panic!("no prompt in an agent context"),
        )
        .expect_err("still withheld before the approval");
        assert!(
            err.message.contains("passlane approve --response"),
            "{}",
            err.message
        );
        let pending = crate::approvals::pending::PendingStore::load(state.path()).unwrap();
        let rid = pending.records()[0].rid.clone();
        let cli = crate::approvals::load_identity(state.path()).unwrap();
        let response =
            crate::approvals::mock_page_response(&cli, &page, &passkey, &rid, passlane_approval::message::Decision::Allow);
        crate::approvals::approve_response(state.path(), &response.to_base64url()).unwrap();

        // The re-run reveals: the grant stands in for the owner's answer.
        ask_flow(
            &log,
            state.path(),
            AgentPolicy::Ask,
            RevealContext::Agent,
            "uuid-stripe",
            "Stripe test key",
            "password",
            || panic!("a grant must not prompt"),
        )
        .expect("the grant releases the reveal");
        // The log records the approving decision, correlated by rid.
        let events = lines(&log);
        assert_eq!(events.last().unwrap()["decision"], "approved");
        assert_eq!(events.last().unwrap()["id"].as_str().unwrap(), rid);

        // Once granted, once only: the second reveal is withheld again.
        let result = ask_flow(
            &log,
            state.path(),
            AgentPolicy::Ask,
            RevealContext::Agent,
            "uuid-stripe",
            "Stripe test key",
            "password",
            || panic!("no prompt in an agent context"),
        );
        assert!(
            result.is_err(),
            "a Scope::Once grant is consumed by the first reveal"
        );
    }

    #[test]
    fn enforce_owner_ask_approved_reveals() {
        let (log, _dir) = log_in_tempdir();
        enforce_scratch(
            &log,
            AgentPolicy::Ask,
            RevealContext::Owner,
            ENTRY_ID,
            "Stripe test key",
            "password",
            || ApprovalChoice::Once,
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
        let result = enforce_scratch(
            &log,
            AgentPolicy::Ask,
            RevealContext::Owner,
            ENTRY_ID,
            "Stripe test key",
            "password",
            || ApprovalChoice::Deny,
        );
        assert!(result.is_err());
        let events = lines(&log);
        assert_eq!(events[1]["decision"], "denied");
    }

    #[test]
    fn enforce_owner_never_and_all_allow_reveal_without_logging() {
        let (log, _dir) = log_in_tempdir();
        for policy in [AgentPolicy::Never, AgentPolicy::Allow] {
            enforce_scratch(
                &log,
                policy,
                RevealContext::Owner,
                ENTRY_ID,
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
        enforce_scratch(
            &log,
            AgentPolicy::Allow,
            RevealContext::Agent,
            ENTRY_ID,
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

    /// Drive the ask flow with injected session-agent seams (and a
    /// scratch approvals state, so the link transport stays inert).
    fn enforce_sessions(
        log: &ApprovalLog,
        policy: AgentPolicy,
        context: RevealContext,
        entry: &str,
        covered: Option<u64>,
        opened: Result<bool, ()>,
    ) -> Result<(), Error> {
        let opened = opened.unwrap_or(false);
        let state = tempfile::tempdir().unwrap();
        enforce_with_seams(
            log,
            state.path(),
            policy,
            context,
            ENTRY_ID,
            entry,
            "password",
            &|_, id, e, _f| {
                assert_eq!(id, ENTRY_ID);
                assert_eq!(e, entry);
                covered
            },
            &|_, id, e, _f| {
                assert_eq!(id, ENTRY_ID);
                assert_eq!(e, entry);
                opened
            },
            GateMode::Full,
            || ApprovalChoice::Session,
        )
    }

    #[test]
    fn agent_ask_covered_by_a_session_reveals_and_audits_it() {
        let (log, _dir) = log_in_tempdir();
        enforce_sessions(
            &log,
            AgentPolicy::Ask,
            RevealContext::Agent,
            "Stripe test key",
            Some(1_800_000_000),
            Err(()),
        )
        .expect("a covering session must satisfy an agent ask");
        let events = lines(&log);
        assert_eq!(
            events.len(),
            1,
            "no request is pending: the session answers it"
        );
        assert_eq!(events[0]["event"], "session");
        assert_eq!(events[0]["decision"], "approved");
        assert_eq!(events[0]["session_until"], 1_800_000_000);
        assert_eq!(events[0]["entry"], "Stripe test key");
    }

    #[test]
    fn agent_ask_without_a_covering_session_still_withholds() {
        let (log, _dir) = log_in_tempdir();
        let result = enforce_sessions(
            &log,
            AgentPolicy::Ask,
            RevealContext::Agent,
            "Stripe test key",
            None,
            Err(()),
        );
        let err = result.expect_err("no session, no reveal");
        assert!(
            err.message.contains("needs owner approval"),
            "{}",
            err.message
        );
        let events = lines(&log);
        assert_eq!(events[0]["event"], "request");
    }

    #[test]
    fn sessions_never_override_the_never_policy() {
        let (log, _dir) = log_in_tempdir();
        let result = enforce_sessions(
            &log,
            AgentPolicy::Never,
            RevealContext::Agent,
            "root",
            Some(1_800_000_000),
            Err(()),
        );
        assert!(result.is_err(), "a session must not loosen agent=never");
        let events = lines(&log);
        assert_eq!(events[0]["event"], "blocked");
    }

    #[test]
    fn owner_approve_for_session_creates_and_grants_a_session() {
        let (log, _dir) = log_in_tempdir();
        enforce_sessions(
            &log,
            AgentPolicy::Ask,
            RevealContext::Owner,
            "Stripe test key",
            None,
            Ok(true),
        )
        .expect("approving for the session must reveal");
        let events = lines(&log);
        assert_eq!(events.len(), 3, "request, decision, session_granted");
        assert_eq!(events[1]["decision"], "approved");
        assert_eq!(events[2]["event"], "session_granted");
    }

    #[test]
    fn owner_approve_for_session_downgrades_to_once_without_an_agent() {
        let (log, _dir) = log_in_tempdir();
        enforce_sessions(
            &log,
            AgentPolicy::Ask,
            RevealContext::Owner,
            "Stripe test key",
            None,
            Ok(false),
        )
        .expect("the reveal is still approved, just single-use");
        let events = lines(&log);
        assert_eq!(events.len(), 2, "no session_granted event");
        assert_eq!(events[1]["decision"], "approved");
    }

    #[test]
    fn session_reveal_event_shape_is_stable() {
        let (log, _dir) = log_in_tempdir();
        log.log_session_reveal("default", ENTRY_ID, "GitHub", "code", AgentPolicy::Ask, 42);
        let events = lines(&log);
        assert_eq!(events[0]["event"], "session");
        assert_eq!(events[0]["session_until"], 42);
        assert_eq!(events[0]["policy"], "ask");
        assert_eq!(events[0]["entry_id"], ENTRY_ID);
        assert!(events[0].get("id").is_none() || events[0]["id"].is_null());
    }

    #[test]
    fn bulk_reveal_allowed_matrix() {
        let (log, _dir) = log_in_tempdir();
        // allow passes without consulting anything.
        assert!(bulk_reveal_allowed_with(
            &log,
            AgentPolicy::Allow,
            ENTRY_ID,
            "GitHub",
            "password",
            &|_, _, _| panic!("allow must not consult the agent"),
        ));
        // never stays withheld, session or not.
        assert!(!bulk_reveal_allowed_with(
            &log,
            AgentPolicy::Never,
            ENTRY_ID,
            "GitHub",
            "password",
            &|_, _, _| panic!("never must not consult the agent"),
        ));
        // ask + covering session (by UUID): allowed and audited.
        assert!(bulk_reveal_allowed_with(
            &log,
            AgentPolicy::Ask,
            ENTRY_ID,
            "GitHub",
            "password",
            &|_, id, field| {
                assert_eq!((id, field), (ENTRY_ID, "password"));
                Some(99)
            },
        ));
        let events = lines(&log);
        assert_eq!(events.len(), 1, "the session release is audited");
        assert_eq!(events[0]["event"], "session");
        assert_eq!(events[0]["entry_id"], ENTRY_ID);
        // ask without a session: withheld, nothing logged here (the
        // caller records the pending request).
        let (log2, _dir) = log_in_tempdir();
        assert!(!bulk_reveal_allowed_with(
            &log2,
            AgentPolicy::Ask,
            ENTRY_ID,
            "GitHub",
            "password",
            &|_, _, _| None,
        ));
        assert!(!log2.path().exists());
    }

    #[test]
    fn owner_reveal_command_selects_the_right_entry_type() {
        // A bare `passlane show <pattern>` only searches credentials; the
        // guidance must route TOTP, payment and note entries to their type
        // flags or the owner's recovery command finds nothing.
        assert_eq!(
            owner_reveal_base_command("root-server", "password"),
            "passlane show root-server"
        );
        assert_eq!(
            owner_reveal_base_command("GitHub:user", "code"),
            "passlane show -o GitHub:user"
        );
        assert_eq!(
            owner_reveal_base_command("GitHub:user", "secret"),
            "passlane show -o GitHub:user"
        );
        assert_eq!(
            owner_reveal_base_command("Visa", "number"),
            "passlane show -p"
        );
        assert_eq!(
            owner_reveal_base_command("wifi", "content"),
            "passlane show -n"
        );
    }

    #[test]
    fn shell_quote_never_lets_a_title_escape_the_command() {
        assert_eq!(shell_quote("github.com"), "github.com");
        assert_eq!(shell_quote("GitHub:user"), "GitHub:user");
        assert_eq!(shell_quote("my entry"), "'my entry'");
        // A title carrying a single quote stays inside the quoting.
        assert_eq!(shell_quote("x'; rm -rf ~"), r"'x'\''; rm -rf ~'");
        // Command substitution and backticks never reach the shell bare.
        assert_eq!(shell_quote("$(touch /tmp/pwned)"), "'$(touch /tmp/pwned)'");
        assert_eq!(shell_quote("`id`"), "'`id`'");
        assert_eq!(shell_quote(""), "''");
        // The quoted forms themselves must not contain a bare quote that
        // closes early: round-trip sanity via the base command.
        assert_eq!(
            owner_reveal_base_command("x'; rm -rf ~", "password"),
            "passlane show 'x'\\''; rm -rf ~'"
        );
    }

    #[test]
    fn dash_leading_titles_stay_a_pattern_not_an_option() {
        // Shell quoting does not protect the argument parser: a title
        // like "-root" must come after -- or clap reads it as an option.
        assert_eq!(
            owner_reveal_base_command("-root", "password"),
            "passlane show -- -root"
        );
        // Unsafe dash-leading titles are additionally shell-quoted.
        assert_eq!(
            owner_reveal_base_command("-x y", "code"),
            "passlane show -o -- '-x y'"
        );
        // Ordinary titles are unaffected.
        assert_eq!(
            owner_reveal_base_command("root", "password"),
            "passlane show root"
        );
    }

    #[test]
    fn vault_targeting_only_when_the_entry_lives_elsewhere() {
        // The active vault needs no flag; any other vault (or no active
        // vault at all) gets an explicit --vault so the command actually
        // finds the entry.
        assert_eq!(
            with_vault_targeting("passlane show 'x'".into(), "work", Some("work")),
            "passlane show 'x'"
        );
        assert_eq!(
            with_vault_targeting("passlane show 'x'".into(), "work", Some("default")),
            "passlane --vault work show 'x'"
        );
        assert_eq!(
            with_vault_targeting("passlane show 'x'".into(), "work", None),
            "passlane --vault work show 'x'"
        );
        // The flag must come before a `--` pattern separator, where
        // everything after -- is positional.
        assert_eq!(
            with_vault_targeting("passlane show -- -root".into(), "work", Some("default")),
            "passlane --vault work show -- -root"
        );
    }

    #[test]
    fn once_code_command_is_shell_safe_and_targets_the_vault() {
        let for_active = |entry: &str, vault: &str, active: Option<&str>| {
            once_code_command_for(entry, vault, active)
        };
        assert_eq!(
            for_active("GitHub:user", "work", Some("default")),
            "passlane --vault work show -o --once -- GitHub:user"
        );
        // Plain titles stay readable; the active vault needs no flag.
        assert_eq!(
            for_active("github.com", "work", Some("work")),
            "passlane show -o --once -- github.com"
        );
        assert_eq!(
            for_active("github.com", "work", None),
            "passlane --vault work show -o --once -- github.com"
        );
        // Spaces are quoted; injection attempts cannot escape the command.
        assert_eq!(
            for_active("work; printf INJECTED", "work", Some("work")),
            "passlane show -o --once -- 'work; printf INJECTED'"
        );
        assert_eq!(
            for_active("x'; rm -rf ~", "work", Some("work")),
            "passlane show -o --once -- 'x'\\''; rm -rf ~'"
        );
        // Leading dashes stay a positional after --.
        assert_eq!(
            for_active("-root", "work", Some("work")),
            "passlane show -o --once -- -root"
        );
    }
}
