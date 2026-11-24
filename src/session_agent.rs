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
//!
//! Commands that need an agent can also start one themselves
//! ([`connect_or_start`], passlane#77) — but only on a discovered
//! default socket path, never behind an explicitly configured
//! `PASSLANE_AGENT_SOCK`, and bringing up an empty daemon: auto-start
//! never creates a session and never approves anything.

use std::path::PathBuf;
use std::time::Duration;

use passlane_agent::SOCKET_ENV;
use passlane_agent::client::{AgentClient, EventStream, RevealAnswer, UnlockFactors};
use passlane_agent::error::AgentError;
use passlane_agent::protocol::{
    ChallengeResponseMaterial, ErrorCode, GrantInfo, GrantSpec, SecretString, SessionInfo,
};
use passlane_approval::message::Scope;
use passlane_core::challenge::ChallengeFactor;
use passlane_core::vault::entities::Error;
use zeroize::Zeroizing;

/// How long an "Approve for this session" choice in the ask flow is
/// held. Mirrors the approval protocol's default session cap; a unit
/// test pins the two together.
pub const REVEAL_SESSION_SECS: u32 = 900;

/// How long the deposit-offer (passlane#77) holds a phone-held key's
/// pasted answer in the agent. The approval protocol's default session
/// cap — the same duration an "Approve for this session" reveal gets —
/// so every kind of held approval ages out together; a unit test pins
/// the two together.
pub(crate) const DEPOSIT_SESSION_SECS: u32 = 900;

/// Set to `0` (or `false`/`no`/`off`) to stop the CLI from auto-starting
/// the session agent (passlane#77) — for setups where launchd/systemd
/// own the daemon and a second, privately-started one is unwanted. A
/// live agent short-circuits auto-start regardless.
pub const AUTOSTART_ENV: &str = "PASSLANE_AGENT_AUTOSTART";

/// Names the `passlane-agent` binary [`connect_or_start`] spawns,
/// overriding discovery (sibling of the CLI, then `PATH`). Tests point
/// it at a stub; an explicit value that names no executable simply means
/// "no binary found".
pub(crate) const AGENT_BIN_ENV: &str = "PASSLANE_AGENT_BIN";

/// How long [`connect_or_start`] waits, after spawning an agent, for its
/// socket to *accept* a connection: the socket file's existence is not
/// readiness, and a spawned process needs a moment to bind. Bounded so a
/// broken binary cannot stall the command that wanted it.
const AUTOSTART_ACCEPT_BUDGET: Duration = Duration::from_secs(2);

/// How often [`connect_or_start`] retries the connection while waiting
/// for the spawned agent to accept.
const AUTOSTART_POLL_INTERVAL: Duration = Duration::from_millis(50);

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

/// Connect to the agent, starting one when none is running and that is
/// allowed (passlane#77). Used wherever the CLI is otherwise about to
/// fail with "the session agent is not running": `unlock --session`, the
/// no-terminal deposit flow of `approve --response`, and an accepted
/// deposit-offer.
///
/// The boundaries that make auto-start safe:
///
/// - **Only discovered default socket paths.** A socket named by
///   `PASSLANE_AGENT_SOCK` that nothing serves stays the error it is
///   today — never a silent fallback (passlane#65).
/// - **Opt-out**: `PASSLANE_AGENT_AUTOSTART=0` restores today's behavior
///   for setups where the session manager owns the daemon.
/// - **An empty daemon only**: starting the agent creates no session and
///   approves nothing — it holds secrets only after a human hands them
///   over. Non-terminal contexts auto-start too, for the same reason:
///   spawning blocks on nothing and holds nothing.
/// - **`needed_session_secs` shapes the cap** the spawned agent gets
///   (`--max-session-secs`, floored at the default cap, bounded by the
///   hard cap): an auto-started default-cap agent that then refuses the
///   `unlock --session 3600` that spawned it would be a terrible
///   first-run experience.
/// - **A missing binary degrades** to today's message, unchanged — no
///   surprise downloads.
///
/// A live agent short-circuits everything: it is connected and returned.
pub fn connect_or_start(needed_session_secs: u64) -> Result<AgentClient, Error> {
    connect_or_start_with(needed_session_secs, &spawn_agent_detached)
}

/// What [`connect_or_start_with`] decided to launch.
#[derive(Clone)]
struct AutostartPlan {
    /// The `passlane-agent` executable.
    binary: PathBuf,
    /// The discovered default socket it is told to serve.
    socket: PathBuf,
    /// The cap to start it with: accommodating the triggering request.
    max_session_secs: u64,
}

impl std::fmt::Display for AutostartPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} --socket {} --max-session-secs {}",
            self.binary.display(),
            self.socket.display(),
            self.max_session_secs
        )
    }
}

/// [`connect_or_start`] with the spawn step injected, so the decision
/// logic — boundaries, discovery, the accept-poll — is testable against
/// an in-process server instead of a real binary.
fn connect_or_start_with(
    needed_session_secs: u64,
    spawn: &dyn Fn(&AutostartPlan) -> Result<(), String>,
) -> Result<AgentClient, Error> {
    match connect_result() {
        Ok(client) => return Ok(client),
        // The one failure auto-start may fix: genuinely absent — no path
        // configured, nothing listening where discovery looked. A socket
        // named by PASSLANE_AGENT_SOCK that nothing serves is
        // `NotListening`, and every other failure (untrusted socket,
        // dialect mismatch) is its own error: all of them are reported
        // exactly as `connect_or_error` reports them.
        Err(AgentError::NotRunning(_)) => {}
        Err(e) => return Err(to_error(e)),
    }
    if !auto_start_permitted() {
        return Err(not_running_error());
    }
    let Some(socket) = passlane_agent::default_socket_path() else {
        // No private per-user runtime directory: an agent we spawned
        // could not find the socket either.
        return Err(not_running_error());
    };
    let Some(binary) = find_agent_binary() else {
        // Graceful degradation, no surprise downloads (passlane#77).
        return Err(not_running_error());
    };
    let plan = AutostartPlan {
        binary,
        socket: socket.clone(),
        max_session_secs: autostart_cap(needed_session_secs),
    };
    if let Err(why) = spawn(&plan) {
        return Err(Error::new(&format!(
            "could not start the session agent ({plan}): {why}"
        )));
    }
    // Wait until the socket *accepts*: existence is not readiness, and
    // two racing commands may each have spawned an agent — the loser's
    // exits on the bind conflict while the winner serves both. A socket
    // that momentarily looks wrong is retried within the budget: in the
    // window between the daemon's bind() and its chmod to 0600 the
    // socket file legitimately carries group/other bits, so a trust
    // check that lands there must wait a beat, not fail. A dialect
    // mismatch is not transient — a stale binary answered — and stops
    // here with the restart guidance.
    let deadline = std::time::Instant::now() + AUTOSTART_ACCEPT_BUDGET;
    loop {
        // The failure of this attempt — retried until the budget runs
        // out, then reported with the log to consult. The connection
        // and the version exchange are each bounded by what is left of
        // the budget: a spawned binary that accepts but never answers
        // must not stretch the wait past what was promised.
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let failure = match AgentClient::connect_within(&socket, remaining) {
            Ok(mut client) => {
                let bounded = remaining.max(Duration::from_millis(1));
                match client.set_request_timeout(bounded) {
                    Ok(()) => match client.check_version() {
                        Ok(_) => return Ok(client),
                        Err(e @ AgentError::VersionMismatch { .. }) => return Err(to_error(e)),
                        Err(e) => e,
                    },
                    Err(e) => e,
                }
            }
            Err(e) => e,
        };
        if std::time::Instant::now() >= deadline {
            return Err(Error::new(&format!(
                "started the session agent but it did not serve {} within {}s (last error: \
                 {failure}); see {} for what it said, or start 'passlane-agent' yourself and \
                 try again.",
                socket.display(),
                AUTOSTART_ACCEPT_BUDGET.as_secs(),
                agent_log_path().display(),
            )));
        }
        std::thread::sleep(AUTOSTART_POLL_INTERVAL);
    }
}

/// Whether auto-start may happen at all: a Unix-socket platform, no
/// explicitly configured socket (a named-but-dead agent stays an error),
/// and no opt-out.
fn auto_start_permitted() -> bool {
    cfg!(unix) && passlane_agent::configured_socket_path().is_none() && !autostart_opted_out()
}

/// Whether an agent could be auto-started right now — asked by the
/// deposit-offer to decide whether offering is honest: an answer can be
/// held when an agent is running or one would be started on acceptance.
pub fn autostart_ready() -> bool {
    auto_start_permitted()
        && passlane_agent::default_socket_path().is_some()
        && find_agent_binary().is_some()
}

/// Whether `PASSLANE_AGENT_AUTOSTART` opts out of auto-start.
fn autostart_opted_out() -> bool {
    std::env::var_os(AUTOSTART_ENV).is_some_and(|value| {
        matches!(
            value.to_string_lossy().trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off"
        )
    })
}

/// The cap a spawned agent is started with: enough for the request that
/// triggered it, never below the default cap (a lower one would refuse
/// ordinary 900s sessions), never above the hard cap (nothing may be
/// held that long, so an over-cap request still fails honestly).
#[cfg(unix)]
fn autostart_cap(needed_session_secs: u64) -> u64 {
    use passlane_agent::server::{HARD_MAX_SESSION_SECS, default_max_session_secs};
    needed_session_secs
        .max(default_max_session_secs())
        .min(HARD_MAX_SESSION_SECS)
}

/// Non-Unix platforms never reach the spawn (see [`auto_start_permitted`]).
#[cfg(not(unix))]
fn autostart_cap(needed_session_secs: u64) -> u64 {
    needed_session_secs
}

/// Where the `passlane-agent` binary is: `$PASSLANE_AGENT_BIN` when it
/// names an executable, else a sibling of this executable
/// (`~/bin/passlane` finds the `target/release/passlane-agent` it was
/// installed beside), else `PATH`. The override is authoritative — a
/// value that names no executable means "no binary found"; it does not
/// silently fall through to a discovered one.
fn find_agent_binary() -> Option<PathBuf> {
    if let Some(named) = std::env::var_os(AGENT_BIN_ENV)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
    {
        return is_executable_file(&named).then_some(named);
    }
    let name = std::ffi::OsStr::new("passlane-agent");
    if let Ok(exe) = std::env::current_exe()
        && let Some(sibling) = exe.parent().map(|dir| dir.join(name))
        && is_executable_file(&sibling)
    {
        return Some(sibling);
    }
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(name))
            .find(|candidate| is_executable_file(candidate))
    })
}

#[cfg(unix)]
fn is_executable_file(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable_file(path: &std::path::Path) -> bool {
    std::fs::metadata(path).is_ok_and(|meta| meta.is_file())
}

/// Where a spawned agent's stdout/stderr go: `~/.passlane/agent.log`,
/// append, so a daemon nobody watches can still be asked what it said.
fn agent_log_path() -> PathBuf {
    crate::store::dir_path().join("agent.log")
}

/// Spawn the agent detached from this command (Unix only): its own
/// process group, so it survives the terminal that triggered it closing,
/// stdio appended to the log file, stdin closed — an idle daemon that
/// cannot block on anything — and **no other file descriptor inherited**:
/// a daemon that outlives its spawner must not hold the spawning
/// command's pipes open (an `expect`-style wrapper that leaks a
/// non-CLOEXEC fd would otherwise keep the command's own pipeline from
/// ever seeing EOF). The child is never waited on: it outlives this
/// command by design, and the loser of a start race exits on its own
/// (the server refuses to bind a socket a live agent answers).
#[cfg(unix)]
fn spawn_agent_detached(plan: &AutostartPlan) -> Result<(), String> {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    let log_path = agent_log_path();
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|e| format!("could not open {}: {e}", log_path.display()))?;
    let log_err = log
        .try_clone()
        .map_err(|e| format!("could not reuse {}: {e}", log_path.display()))?;
    // The sweep's bound is decided here, in the parent: descriptors have
    // no guarantee of sitting low, so everything this process could
    // hold (up to its nofile soft limit) is closed in the child. A
    // practical ceiling covers an unlimited or unreadable limit.
    let max_fd = open_fd_limit();
    // SAFETY: the callback runs between fork and exec in the child. It
    // only closes file descriptors — async-signal-safe — starting above
    // the three stdio fds std has already dup2'd into place (null in,
    // log out, log err). No locks, no allocation, no environment reads.
    let close_inherited_fds = move || {
        for fd in 3..=max_fd {
            unsafe { libc::close(fd) };
        }
        Ok(())
    };
    // SAFETY: the callback only closes file descriptors
    // (async-signal-safe); see the comment on it above. Between fork
    // and exec it must not touch locks, allocate, or read the
    // environment — it does none of that.
    unsafe {
        Command::new(&plan.binary)
            .arg("--socket")
            .arg(&plan.socket)
            .arg("--max-session-secs")
            .arg(plan.max_session_secs.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err))
            .process_group(0)
            .pre_exec(close_inherited_fds)
            .spawn()
            .map(|_| ())
            .map_err(|e| format!("could not spawn {}: {e}", plan.binary.display()))
    }
}

/// The spawn on platforms without Unix domain sockets: unreachable (see
/// [`auto_start_permitted`]), present so the code compiles everywhere.
#[cfg(not(unix))]
fn spawn_agent_detached(_plan: &AutostartPlan) -> Result<(), String> {
    Err("the session agent needs a Unix domain socket platform".into())
}

/// The highest file descriptor number worth closing in a spawned child:
/// the process's nofile soft limit (clamped to what an `i32` loop can
/// walk), or a practical ceiling when the limit is unlimited or cannot
/// be read — inherited descriptors carry no guarantee of sitting low.
#[cfg(unix)]
fn open_fd_limit() -> i32 {
    // SAFETY: `getrlimit` writes into a plain `rlimit` struct we own.
    unsafe {
        let mut limit: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0
            && limit.rlim_cur != libc::RLIM_INFINITY
        {
            return limit.rlim_cur.min(i32::MAX as u64) as i32;
        }
    }
    1 << 20
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
        AgentError::TimedOut(_) => {
            Some("Restart passlane-agent and run the command again.".to_string())
        }
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

/// What a live session-agent session holds for a vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionFactors {
    /// No session for this vault — also the answer when no agent is
    /// running: it is optional infrastructure.
    None,
    /// The master password only.
    PasswordOnly,
    /// The master password and the vault's challenge-response factor: a
    /// hardware-key vault then opens with no key present.
    WithKeyFactor,
}

impl SessionFactors {
    /// From the secret-free session listing, which asks for nothing and
    /// consumes nothing: a `once`-scoped grant must not be spent by a
    /// look.
    fn from_listing(vault: &str, sessions: &[SessionInfo]) -> Self {
        let mut held = Self::None;
        for session in sessions.iter().filter(|s| s.vault == vault) {
            held = match session.grant {
                GrantInfo::Unlock {
                    challenge_response: true,
                } => Self::WithKeyFactor,
                GrantInfo::Unlock {
                    challenge_response: false,
                } if held == Self::None => Self::PasswordOnly,
                _ => held,
            };
        }
        held
    }
}

/// What a live session holds for the vault — asked without consuming
/// anything, so it is safe to call for presence checks (an unlock through
/// the chain is what spends a `once`-scoped grant). No agent running is
/// simply no session; a socket that cannot be used is the caller's error.
pub fn session_factors(vault: &str) -> Result<SessionFactors, Error> {
    let mut client = match connect_result() {
        Ok(client) => client,
        Err(AgentError::NotRunning(_)) => return Ok(SessionFactors::None),
        Err(e) => return Err(to_error(e)),
    };
    let sessions = client
        .list_sessions()
        .map_err(to_error)?
        .into_iter()
        .collect::<Vec<_>>();
    Ok(SessionFactors::from_listing(vault, &sessions))
}

/// What a session can hold of the challenge-response factor a vault was
/// opened with: the secret of a secret-backed factor (a recovery secret, a
/// virtual key). A physical hardware key's secret never leaves the
/// device, so there is nothing to hold — every use of such a vault still
/// needs the key, and a session covers its master password only.
pub(crate) fn challenge_response_material(
    factor: Option<&ChallengeFactor>,
) -> Option<ChallengeResponseMaterial> {
    match factor {
        Some(ChallengeFactor::Virtual { secret_hex }) => Some(ChallengeResponseMaterial::Secret {
            secret_hex: SecretString::new(secret_hex.clone()),
        }),
        _ => None,
    }
}

/// Whether a session agent is reachable at all.
pub fn agent_running() -> bool {
    connect_result().is_ok()
}

/// The phone-held key's answer a live session-agent session holds for the
/// vault's **current** challenge, as the key the unlock chain opens with
/// (passlane#53). Reads the challenge from the vault file — prompt-free,
/// so this may run anywhere — and asks the agent for an answer to exactly
/// it. `Ok(None)` when no agent is running or nothing is held for that
/// challenge; an agent that is configured but cannot be used is an error,
/// like any other unusable source in the chain. The key serves only that
/// one challenge: the fresh seed a save issues goes back to the link
/// transport, so saving still asks the holder.
pub fn held_phone_answer(
    config: &crate::vault_registry::VaultConfig,
) -> Result<Option<passlane_core::challenge::ChallengeFactor>, AgentError> {
    let Some(answer) = try_challenge_response_current(config)? else {
        return Ok(None);
    };
    let seed = crate::phone_key::kdf_seed::read_kdf_seed(&config.path)
        .map_err(|e| AgentError::Protocol(e.message))?;
    // The key answers this seed with the held answer and hands the fresh
    // seed a save issues back to the link transport (resolved only then)
    // — a save always asks the holder again.
    Ok(Some(crate::phone_key::held_answer_key(
        config, seed, answer,
    )))
}

/// [`held_phone_answer`]'s agent lookup, separated so the transport's
/// warn-and-skip rule is not forced on the chain's error rule.
fn try_challenge_response_current(
    config: &crate::vault_registry::VaultConfig,
) -> Result<Option<Zeroizing<Vec<u8>>>, AgentError> {
    let seed = crate::phone_key::kdf_seed::read_kdf_seed(&config.path)
        .map_err(|e| AgentError::Protocol(e.message))?;
    let challenge_hex = passlane_approval::encoding::hex_encode(&seed);
    let mut client = connect_result()?;
    match client.get_challenge_response(&config.name, &challenge_hex) {
        Ok((response, expiry)) => {
            // Only a timed answer backs a view: a single-use one is
            // consumed by this very fetch, so nothing live remains to
            // watch — claiming backing would fail the view's liveness
            // check before any code is shown.
            if (expiry.is_some()) {
                note_phone_answer_backing();
            }
            let bytes = passlane_approval::encoding::hex_decode(&response).map_err(|e| {
                AgentError::Protocol(format!("the agent returned a malformed answer: {e}"))
            })?;
            if bytes.len() != passlane_approval::message::CHALLENGE_RESPONSE_LEN {
                return Err(AgentError::Protocol(format!(
                    "the agent returned a {}-byte answer, not 20",
                    bytes.len()
                )));
            }
            Ok(Some(Zeroizing::new(bytes)))
        }
        Err(AgentError::Server {
            code: ErrorCode::NotFound,
            ..
        }) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Whether a phone-answer session backed this process's current open:
/// set the moment an answer is fetched (from the chain or the transport),
/// reset when the next unlock attempt begins. The continuous TOTP view
/// reads it to watch a session that supplied the second factor while the
/// password came from elsewhere (the keychain, say) — and, unlike an
/// expiry comparison, it cannot turn false between the fetch and the
/// view, so the session is always revalidated and never silently
/// unwatched.
static PHONE_ANSWER_BACKED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Whether a phone-answer session backed the current open.
pub fn phone_answer_backed() -> bool {
    PHONE_ANSWER_BACKED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Begin a fresh unlock attempt: nothing has backed it yet.
pub fn reset_phone_answer_backing() {
    PHONE_ANSWER_BACKED.store(false, std::sync::atomic::Ordering::Relaxed);
}

fn note_phone_answer_backing() {
    PHONE_ANSWER_BACKED.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// The answer a live session holds for a phone-held key (passlane#53):
/// exactly this vault and challenge (lower-case hex), consumed when the
/// session is single-use. `None` when the agent is absent or holds
/// nothing for that challenge — a vault that was saved since has a new
/// seed, and answers for the old one are not answers for it.
pub fn try_challenge_response(vault: &str, challenge_hex: &str) -> Option<Zeroizing<Vec<u8>>> {
    let mut client = try_connect()?;
    match client.get_challenge_response(vault, challenge_hex) {
        Ok((response, expiry)) => {
            // Only a timed answer backs a view: a single-use one is
            // consumed by this very fetch, so nothing live remains to
            // watch — claiming backing would fail the view's liveness
            // check before any code is shown.
            if (expiry.is_some()) {
                note_phone_answer_backing();
            }
            let bytes = match passlane_approval::encoding::hex_decode(&response) {
                Ok(bytes) => bytes,
                Err(e) => {
                    eprintln!("Warning: the session agent returned a malformed answer: {e}");
                    return None;
                }
            };
            if bytes.len() != passlane_approval::message::CHALLENGE_RESPONSE_LEN {
                eprintln!(
                    "Warning: the session agent returned a {}-byte answer, not 20",
                    bytes.len()
                );
                return None;
            }
            Some(Zeroizing::new(bytes))
        }
        Err(AgentError::Server {
            code: ErrorCode::NotFound,
            ..
        }) => None,
        Err(AgentError::NotRunning(_)) => None,
        // Never silent: an agent that is running but cannot serve is
        // reported, so the next request is not mistaken for the first.
        Err(e) => {
            eprintln!("Warning: the session agent errored and was skipped: {e}");
            None
        }
    }
}

/// Hold a phone-held key's answer in the agent (memory only) for one
/// vault file version. Returns the session's expiry (unix seconds; 0 for
/// a single-use one).
pub fn create_challenge_response_session(
    vault: &str,
    challenge_hex: &str,
    response_hex: &str,
    scope: Scope,
) -> Result<u64, Error> {
    let mut client = connect_or_error()?;
    let grant = GrantSpec::ChallengeResponse {
        challenge: SecretString::new(challenge_hex),
        response: SecretString::new(response_hex),
    };
    // The agent refuses anything past its own cap with an explanation.
    match client.create_session(vault, grant, scope) {
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

/// Hold a phone-held key's freshly pasted answer in the agent so it
/// outlives the command that asked for it (the deposit-offer,
/// passlane#77). Starts an agent when none is running and auto-start is
/// allowed — the offer is only made when that could succeed — and holds
/// the answer for [`DEPOSIT_SESSION_SECS`]. An agent whose cap is below
/// that refuses the session (the agent's cap rules are obeyed, never
/// bent) and the caller reports it as a warning: the vault is already
/// open, the deposit was an offer, not a requirement. Returns the
/// session's expiry (unix seconds).
pub(crate) fn deposit_answer_session(
    vault: &str,
    challenge_hex: &str,
    response_hex: &str,
) -> Result<u64, Error> {
    let mut client = connect_or_start(DEPOSIT_SESSION_SECS as u64)?;
    let grant = GrantSpec::ChallengeResponse {
        challenge: SecretString::new(challenge_hex),
        response: SecretString::new(response_hex),
    };
    match client.create_session(
        vault,
        grant,
        Scope::Timed {
            seconds: DEPOSIT_SESSION_SECS,
        },
    ) {
        Ok(created) => Ok(created.expires_at.unwrap_or(0)),
        Err(AgentError::Server {
            code: ErrorCode::TooLong,
            message,
        }) => Err(Error::new(&format!(
            "{message}. The offer holds {DEPOSIT_SESSION_SECS}s approvals; restart \
             passlane-agent with --max-session-secs 900 or higher to accept them."
        ))),
        Err(e) => Err(to_error(e)),
    }
}

/// The session agent as a source of phone-held-key answers for the link
/// transport.
pub(crate) struct AgentAnswerStore;

impl crate::phone_key::transport::AnswerStore for AgentAnswerStore {
    fn take(&self, vault: &str, challenge_hex: &str) -> Option<Zeroizing<Vec<u8>>> {
        try_challenge_response(vault, challenge_hex)
    }

    fn is_running(&self) -> bool {
        agent_running()
    }

    fn deposit(&self, vault: &str, challenge_hex: &str, answer_hex: &str) -> Result<u64, String> {
        deposit_answer_session(vault, challenge_hex, answer_hex).map_err(|e| e.message)
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
    phone_backed: bool,
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
    // The phone-answer session is watched on its own: it can back an
    // open whose password came from the keychain, and its death (expiry,
    // revoke, lock) must end the view it funded. Probing is non-consuming
    // for timed sessions, which is what a view is backed by — a
    // single-use answer was spent by the open itself and nothing live
    // remains to watch.
    let phone_live = !phone_backed || {
        let config = crate::vault_registry::current().ok();
        config.is_some_and(|config| {
            try_challenge_response_current(&config)
                .map(|answer| answer.is_some())
                .unwrap_or(false)
        })
    };
    unlock_live && reveal_live && phone_live
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

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Forget the process-global current vault when the test ends.
    struct ResetCurrentVault;

    impl Drop for ResetCurrentVault {
        fn drop(&mut self) {
            crate::vault_registry::clear_current_for_tests();
        }
    }

    use passlane_approval::policy::Policy;

    // The agent's server is Unix-only, and so are the tests that need a
    // socket to talk to; everything else here runs everywhere.
    #[cfg(unix)]
    use passlane_agent::server::{AgentConfig, AgentServer};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// Environment variables are process-global; every test in this
    /// binary that touches them takes turns holding this. It is
    /// deliberately not Unix-only: the no-agent test below needs it too.
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

    /// The deposit-offer's duration must track the approval protocol's
    /// default session cap too: a held phone approval ages out with the
    /// reveal sessions an "Approve for this session" choice creates.
    #[test]
    fn deposit_session_secs_mirror_the_protocol_default_cap() {
        assert_eq!(
            DEPOSIT_SESSION_SECS as u64,
            Policy::default().max_session_secs
        );
    }

    #[test]
    fn only_a_secret_backed_factor_can_be_held_by_a_session() {
        let held = challenge_response_material(Some(&ChallengeFactor::Virtual {
            secret_hex: "aabb".to_string(),
        }));
        assert_eq!(
            held,
            Some(ChallengeResponseMaterial::Secret {
                secret_hex: SecretString::new("aabb")
            })
        );
        // No factor (a password-only vault): nothing to hold. A device-
        // backed factor takes the same arm — its secret never leaves the
        // device.
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

        let wedged = to_error(AgentError::TimedOut(std::time::Duration::from_secs(5)));
        assert!(
            wedged.message.contains("did not answer within 5s")
                && wedged.message.contains("Restart passlane-agent"),
            "{}",
            wedged.message
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

    /// Sets one environment variable for as long as it lives and puts it
    /// back afterwards — on a failing assertion too. Environment variables
    /// are process-global: whoever builds one holds `ENV_MUTEX`.
    struct EnvVar {
        name: &'static str,
        saved: Option<std::ffi::OsString>,
    }

    impl EnvVar {
        fn set(name: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
            let saved = std::env::var_os(name);
            // SAFETY: test hygiene — the holder holds `ENV_MUTEX`, which
            // every test in this binary that touches the environment
            // takes, for as long as this lives.
            unsafe { std::env::set_var(name, value) };
            Self { name, saved }
        }

        fn remove(name: &'static str) -> Self {
            let saved = std::env::var_os(name);
            // SAFETY: see `set`.
            unsafe { std::env::remove_var(name) };
            Self { name, saved }
        }
    }

    impl Drop for EnvVar {
        fn drop(&mut self) {
            // SAFETY: see `set`.
            unsafe {
                match self.saved.take() {
                    Some(value) => std::env::set_var(self.name, value),
                    None => std::env::remove_var(self.name),
                }
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_presence_check_consumes_nothing() {
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
        let env = EnvVar::set(SOCKET_ENV, &socket);

        // One once-scoped grant holding the key factor: the rarest thing
        // the agent can hold. Asking what is held must not spend it.
        let mut owner = AgentClient::connect(&socket).unwrap();
        owner
            .create_session(
                "keyed",
                GrantSpec::Unlock {
                    master_password: SecretString::new("pw"),
                    challenge_response: Some(ChallengeResponseMaterial::Secret {
                        secret_hex: SecretString::new("aabb"),
                    }),
                },
                Scope::Once,
            )
            .unwrap();
        for _ in 0..2 {
            assert_eq!(
                session_factors("keyed").unwrap(),
                SessionFactors::WithKeyFactor
            );
        }
        let mut user = AgentClient::connect(&socket).unwrap();
        let factors = user.get_unlock_factors("keyed").unwrap();
        assert!(
            factors.challenge_response.is_some(),
            "the once grant survived the presence checks"
        );

        // And the tri-state is right for the other kinds.
        owner
            .create_session(
                "plain",
                GrantSpec::Unlock {
                    master_password: SecretString::new("pw"),
                    challenge_response: None,
                },
                Scope::Timed { seconds: 300 },
            )
            .unwrap();
        assert_eq!(
            session_factors("plain").unwrap(),
            SessionFactors::PasswordOnly
        );
        assert_eq!(
            session_factors("other").unwrap(),
            SessionFactors::None,
            "another vault's session does not count"
        );

        drop(env);
        handle.stop();
        served.join().unwrap();
    }

    /// What `session_factors` answers when no agent can be found, with
    /// nothing else in the process any the wiser.
    ///
    /// Discovery looks in `PASSLANE_AGENT_SOCK`, then `XDG_RUNTIME_DIR`,
    /// then `TMPDIR`: with the first unset and the second a private,
    /// empty directory, there is nothing to find — and `TMPDIR` is never
    /// reached. That last part matters: `TMPDIR` is where every other
    /// test's temporary files live. Repointing it at a folder that goes
    /// away with the lookup is how `master` went red once — parallel
    /// tests had temp files created inside that folder. Nothing but this
    /// lookup reads `XDG_RUNTIME_DIR`.
    fn lookup_with_no_agent_to_find() -> Result<SessionFactors, Error> {
        let _guard = ENV_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let nowhere = tempfile::tempdir().unwrap();
        let _sock = EnvVar::remove(SOCKET_ENV);
        let _xdg = EnvVar::set("XDG_RUNTIME_DIR", nowhere.path());
        session_factors("work")
    }

    #[test]
    fn with_no_agent_at_all_there_is_simply_no_session() {
        // An absent agent is optional infrastructure: not an error, and
        // not a reason to stop a hardware-key command that can use the
        // key on its device.
        assert_eq!(
            lookup_with_no_agent_to_find().unwrap(),
            SessionFactors::None
        );
    }

    /// A stand-in for the other tests: a thread that makes a temporary
    /// directory, does a little, then writes into it by path — until it is
    /// told to stop, and no later than the test that owns it. Dropping it
    /// stops and joins the thread, on that test's panic included: a
    /// stand-in left behind would churn temp files through the rest of the
    /// run, and a failing test is exactly when that would go unnoticed.
    struct OtherTests {
        stop: Arc<AtomicBool>,
        /// Temporary directories written into so far.
        written: Arc<AtomicUsize>,
        /// Set by the thread on its way out, a panic included.
        finished: Arc<AtomicBool>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    impl OtherTests {
        fn start(written: Arc<AtomicUsize>) -> Self {
            let stop = Arc::new(AtomicBool::new(false));
            let finished = Arc::new(AtomicBool::new(false));
            let (watch, done, count) = (
                Arc::clone(&stop),
                Arc::clone(&finished),
                Arc::clone(&written),
            );
            let handle = std::thread::spawn(move || {
                struct Done(Arc<AtomicBool>);
                impl Drop for Done {
                    fn drop(&mut self) {
                        self.0.store(true, Ordering::Relaxed);
                    }
                }
                let _done = Done(done);
                while !watch.load(Ordering::Relaxed) {
                    let dir = tempfile::tempdir().unwrap();
                    std::thread::sleep(std::time::Duration::from_micros(100));
                    std::fs::write(dir.path().join("entry"), b"x").unwrap();
                    count.fetch_add(1, Ordering::Relaxed);
                }
            });
            Self {
                stop,
                written,
                finished,
                handle: Some(handle),
            }
        }

        /// Stop the stand-in and wait for it — failing the test if it could
        /// not do what the other tests do.
        fn finish(mut self) {
            self.stop.store(true, Ordering::Relaxed);
            self.handle
                .take()
                .expect("started")
                .join()
                .expect("the other tests' temp files survive the lookups");
        }
    }

    impl Drop for OtherTests {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    #[test]
    fn looking_for_an_absent_agent_never_moves_other_tests_temp_files() {
        // While the lookup runs, the stand-in does what the other tests
        // do. If the lookup pointed `TMPDIR` at a folder of its own, the
        // directory would be created inside it and vanish with it.
        let other_tests = OtherTests::start(Arc::new(AtomicUsize::new(0)));
        // Plenty of lookups for the race to have had its chance, and on a
        // loaded machine not one fewer than the stand-in needs to get
        // going — but never unbounded: the loop ends as soon as the
        // stand-in is gone, and at a hard cap otherwise.
        let mut lookups = 0;
        while (lookups < 2_000 || other_tests.written.load(Ordering::Relaxed) < 10)
            && !other_tests.finished.load(Ordering::Relaxed)
            && lookups < 50_000
        {
            assert_eq!(
                lookup_with_no_agent_to_find().unwrap(),
                SessionFactors::None
            );
            lookups += 1;
        }
        other_tests.finish();
    }

    #[test]
    fn a_failing_test_does_not_leave_the_stand_in_running() {
        use std::time::{Duration, Instant};
        let written = Arc::new(AtomicUsize::new(0));
        let got_going = Arc::new(AtomicBool::new(false));
        let outcome = std::panic::catch_unwind({
            let written = Arc::clone(&written);
            let got_going = Arc::clone(&got_going);
            move || {
                let other_tests = OtherTests::start(written);
                // Wait for the stand-in's first write rather than sleeping
                // a fixed time: a loaded runner may need a moment. Bounded,
                // and reported as its own failure outside — a stand-in that
                // never got going says nothing about the cleanup under test.
                let deadline = Instant::now() + Duration::from_secs(10);
                while other_tests.written.load(Ordering::Relaxed) == 0 && Instant::now() < deadline
                {
                    std::thread::sleep(Duration::from_millis(1));
                }
                got_going.store(
                    other_tests.written.load(Ordering::Relaxed) > 0,
                    Ordering::Relaxed,
                );
                panic!("a failing assertion in the test that owns the stand-in");
            }
        });
        // Unwinding has dropped the stand-in by now.
        assert!(outcome.is_err(), "the failing test did fail");
        assert!(
            got_going.load(Ordering::Relaxed),
            "readiness: the stand-in never wrote anything, so the cleanup is untested"
        );
        let at_the_end = written.load(Ordering::Relaxed);
        assert!(
            at_the_end > 0,
            "the stand-in got going before the test failed"
        );
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(
            written.load(Ordering::Relaxed),
            at_the_end,
            "the stand-in stopped with its test"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_phone_answer_session_backs_access_on_its_own_and_is_watched() {
        // The TOTP view's third backing: a timed phone-answer session can
        // fund an open whose password came from the keychain, so its
        // death must end the view without any unlock session existing.
        let _guard = ENV_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let state = tempfile::tempdir().unwrap();
        // A real-enough vault file: only its KDF seed matters here.
        passlane_core::vault::keepass_vault::KeepassVault::new(
            state.path().join("v.kdbx").to_str().unwrap(),
            "pw",
            None,
            None,
        )
        .unwrap();
        crate::vault_registry::set_current(crate::vault_registry::VaultConfig {
            name: "phone-watch".into(),
            path: state.path().join("v.kdbx").to_str().unwrap().to_string(),
            keyfile: None,
            hwkey: None,
            phone_key: Some(crate::vault_registry::PhoneKeyConfig {
                holder_kid: "0123456789abcdef".into(),
                vault_uid: None,
                enrolled_at: 1,
            }),
        });
        let _reset_current = ResetCurrentVault;

        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("agent.sock");
        let server = AgentServer::bind(
            AgentConfig::new(&socket).with_sweep_interval(std::time::Duration::from_millis(20)),
        )
        .unwrap();
        let handle = server.handle();
        let served = std::thread::spawn(move || server.serve().unwrap());
        let env = EnvVar::set(SOCKET_ENV, &socket);

        let config = crate::vault_registry::current().unwrap();
        let seed = crate::phone_key::kdf_seed::read_kdf_seed(&config.path).unwrap();
        let challenge_hex = passlane_approval::encoding::hex_encode(&seed);
        let answer = passlane_approval::encoding::hex_encode(&[0x5au8; 20]);
        let mut client = AgentClient::connect(&socket).unwrap();
        client
            .create_session(
                &config.name,
                GrantSpec::ChallengeResponse {
                    challenge: SecretString::new(challenge_hex.clone()),
                    response: SecretString::new(answer.clone()),
                },
                Scope::Timed { seconds: 300 },
            )
            .unwrap();

        // The fetch records what the view needs to watch.
        assert!(
            crate::session_agent::held_phone_answer(&config)
                .expect("the agent holds the answer")
                .is_some()
        );
        // The fetch records what the view needs to watch: that this open
        // was phone-backed — set by the fetch, not derived from an
        // expiry, so it survives a session that dies right after.
        assert!(phone_answer_backed(), "the fetch backs the open");
        reset_phone_answer_backing();
        assert!(!phone_answer_backed(), "a fresh unlock attempt clears it");
        // And the liveness probe sees it again once re-fetched.
        assert!(
            crate::session_agent::held_phone_answer(&config)
                .expect("the agent still holds the answer")
                .is_some()
        );
        assert!(phone_answer_backed());

        assert!(
            session_access_live(false, false, true, &config.name, "entry", "code"),
            "the phone-answer session alone backs the access"
        );
        client.revoke_vault(&config.name).unwrap();
        assert!(
            !session_access_live(false, false, true, &config.name, "entry", "code"),
            "a revoked phone-answer session no longer does"
        );
        assert!(
            session_access_live(false, false, false, &config.name, "entry", "code"),
            "nothing phone-backed is claimed: nothing to be live"
        );

        // A single-use answer does NOT back a view: the fetch consumes
        // it, so nothing live remains to watch, and claiming backing
        // would fail the view's liveness check before any code shows.
        client
            .create_session(
                &config.name,
                GrantSpec::ChallengeResponse {
                    challenge: SecretString::new(challenge_hex.clone()),
                    response: SecretString::new(answer.clone()),
                },
                Scope::Once,
            )
            .unwrap();
        reset_phone_answer_backing();
        // The timed session still holds its answer, so the single-use one
        // is not what the fetch below serves... revoke the timed one to
        // force it.
        client.revoke_vault(&config.name).unwrap();
        client
            .create_session(
                &config.name,
                GrantSpec::ChallengeResponse {
                    challenge: SecretString::new(challenge_hex.clone()),
                    response: SecretString::new(answer.clone()),
                },
                Scope::Once,
            )
            .unwrap();
        assert!(
            crate::session_agent::held_phone_answer(&config)
                .expect("the single-use answer is served")
                .is_some(),
            "the single-use answer is fetched"
        );
        assert!(
            !phone_answer_backed(),
            "a single-use answer backs nothing: it died with this fetch"
        );

        drop(env);
        handle.stop();
        served.join().unwrap();
    }

    #[cfg(unix)]
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
        let env = EnvVar::set(SOCKET_ENV, &socket);

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
            session_access_live(true, false, false, "work", "entry", "code"),
            "a live session backs the access"
        );
        assert!(
            !session_access_live(true, false, false, "other", "entry", "code"),
            "a session for another vault does not"
        );
        client.revoke_vault("work").unwrap();
        assert!(
            !session_access_live(true, false, false, "work", "entry", "code"),
            "a revoked session no longer does"
        );
        assert!(
            session_access_live(false, false, false, "work", "entry", "code"),
            "nothing is session-backed: nothing to be live"
        );

        drop(env);
        handle.stop();
        served.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn locking_reports_an_agent_it_cannot_trust_but_not_one_that_is_not_there() {
        let _guard = ENV_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let nowhere = EnvVar::set(SOCKET_ENV, dir.path().join("nowhere.sock"));
        let absent = revoke_vault_sessions("work");
        drop(nowhere);

        let not_a_socket = dir.path().join("plain.file");
        std::fs::write(&not_a_socket, "x").unwrap();
        let untrusted_env = EnvVar::set(SOCKET_ENV, &not_a_socket);
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

    // ---- auto-start (passlane#77) ----
    //
    // The decision logic runs against an injected spawn that starts an
    // in-process server (the real daemon's semantics: bind, and a bind
    // lost to a live agent means the other one serves); one test drives
    // the real process spawn with a stub binary.

    /// Point default socket discovery at a private scratch directory:
    /// with `PASSLANE_AGENT_SOCK` unset, the socket path becomes
    /// `$dir/passlane-agent.sock`. The binary override names any
    /// executable, so the injected spawn tests pass discovery without
    /// needing a real `passlane-agent` binary. Hold `ENV_MUTEX` for as
    /// long as it lives.
    struct DefaultSocketDir {
        dir: tempfile::TempDir,
        _sock: EnvVar,
        _xdg: EnvVar,
        _bin: EnvVar,
    }

    impl DefaultSocketDir {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let _sock = EnvVar::remove(SOCKET_ENV);
            let _xdg = EnvVar::set("XDG_RUNTIME_DIR", dir.path());
            let _bin = EnvVar::set(AGENT_BIN_ENV, "/bin/sh");
            Self {
                dir,
                _sock,
                _xdg,
                _bin,
            }
        }

        fn socket(&self) -> PathBuf {
            self.dir.path().join("passlane-agent.sock")
        }
    }

    /// An in-process stand-in for the spawned daemon: binds the socket it
    /// is told to serve, or yields with `AlreadyRunning` to a starter
    /// that already won — exactly the real binary's two outcomes. The
    /// server's own bind makes concurrent starts converge (it re-checks
    /// that the path still leads to its listener and re-evaluates a bind
    /// lost to a file that appeared meanwhile), so no retry logic is
    /// needed here. Returns whether *this* call is the server that ended
    /// up serving.
    #[cfg(unix)]
    fn serve_like_the_daemon(plan: &AutostartPlan) -> Result<bool, String> {
        let config = AgentConfig::new(&plan.socket)
            .with_sweep_interval(std::time::Duration::from_millis(20));
        match AgentServer::bind(config) {
            // Like a real daemon, it serves until the process ends: these
            // tests never stop it (its socket dir goes away with the
            // test, and the thread dies with the process).
            Ok(server) => {
                std::thread::spawn(move || server.serve().unwrap());
                Ok(true)
            }
            Err(AgentError::AlreadyRunning(_)) => Ok(false),
            Err(e) => Err(e.to_string()),
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_spawned_cap_accommodates_the_request_within_the_hard_cap() {
        assert_eq!(autostart_cap(60), 900, "never below the default cap");
        assert_eq!(autostart_cap(900), 900);
        assert_eq!(
            autostart_cap(3600),
            3600,
            "an unlock --session 3600 must fit"
        );
        assert_eq!(
            autostart_cap(28800),
            28800,
            "the hard cap is exactly reachable"
        );
        assert_eq!(
            autostart_cap(999_999),
            28800,
            "nothing may be held past the hard cap"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_live_agent_short_circuits_auto_start() {
        let _guard = ENV_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let defaults = DefaultSocketDir::new();
        serve_like_the_daemon(&AutostartPlan {
            binary: PathBuf::from("/nonexistent/passlane-agent"),
            socket: defaults.socket(),
            max_session_secs: 900,
        })
        .unwrap();
        let client = connect_or_start_with(900, &|_| {
            panic!("a live agent must be connected, never re-started")
        })
        .unwrap();
        assert_eq!(client.socket_path(), defaults.socket());
    }

    #[cfg(unix)]
    #[test]
    fn auto_start_brings_up_an_agent_that_serves_the_default_socket() {
        let _guard = ENV_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let defaults = DefaultSocketDir::new();
        let plans = Mutex::new(Vec::new());
        let mut client = connect_or_start_with(3600, &|plan| {
            plans.lock().unwrap().push(plan.clone());
            serve_like_the_daemon(plan).map(|_| ())
        })
        .unwrap();
        assert_eq!(client.socket_path(), defaults.socket());
        let plans = plans.into_inner().unwrap();
        assert_eq!(plans.len(), 1, "exactly one spawn");
        assert_eq!(plans[0].socket, defaults.socket());
        assert_eq!(plans[0].max_session_secs, 3600);
        // The client that started it can really use it: a session lands.
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
    }

    #[cfg(unix)]
    #[test]
    fn the_socket_must_accept_not_merely_exist() {
        // A stale socket file exists but refuses connections; the server
        // only starts listening after a delay. Existence checks would
        // return a dead "success" — the poll must keep going.
        let _guard = ENV_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _defaults = DefaultSocketDir::new();
        let started = std::time::Instant::now();
        connect_or_start_with(900, &|plan| {
            // A leftover socket from a crashed agent: exists, refuses.
            let stale = std::os::unix::net::UnixListener::bind(&plan.socket).unwrap();
            drop(stale);
            assert!(plan.socket.exists(), "the stale socket file is there");
            std::thread::sleep(std::time::Duration::from_millis(400));
            serve_like_the_daemon(plan).map(|_| ())
        })
        .unwrap();
        assert!(
            started.elapsed() >= std::time::Duration::from_millis(400),
            "the poll waited for the socket to accept, not to exist"
        );
    }

    #[cfg(unix)]
    #[test]
    fn two_racing_commands_end_up_with_one_live_agent() {
        let _guard = ENV_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let defaults = DefaultSocketDir::new();
        let bind_wins = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let racers: Vec<_> = (0..2)
            .map(|_| {
                let barrier = barrier.clone();
                let socket = defaults.socket();
                let wins = Arc::clone(&bind_wins);
                std::thread::spawn(move || {
                    barrier.wait();
                    connect_or_start_with(900, &move |plan| {
                        assert_eq!(plan.socket, socket);
                        // What a spawned daemon does: bind, and yield to
                        // a racer that is already serving — whichever way
                        // the kernel-level bind race settles.
                        serve_like_the_daemon(plan).map(|won| {
                            if won {
                                wins.fetch_add(1, Ordering::SeqCst);
                            }
                        })
                    })
                })
            })
            .collect();
        let mut clients: Vec<_> = racers
            .into_iter()
            .map(|racer| racer.join().unwrap().unwrap())
            .collect();
        assert!(
            bind_wins.load(Ordering::SeqCst) >= 1,
            "someone ended up serving the socket"
        );
        // The operational invariant: every racing command got a working
        // client on the one socket the path leads to, and the sessions
        // it creates are reachable through that path afterwards. (A
        // starter that proved ownership a heartbeat before being
        // replaced may linger as an idle, unreachable daemon — the
        // ownership proof is a snapshot, not a lock — but nothing is
        // ever deposited with it: clients only ever reach the owner of
        // the path, and its sessions die with it, by design.)
        for client in &mut clients {
            assert_eq!(client.socket_path(), defaults.socket());
            client.list_sessions().unwrap();
            client
                .create_session(
                    "work",
                    GrantSpec::Unlock {
                        master_password: SecretString::new("pw"),
                        challenge_response: None,
                    },
                    Scope::Timed { seconds: 60 },
                )
                .unwrap();
        }
        let mut after = AgentClient::connect(&defaults.socket()).unwrap();
        assert_eq!(
            after.list_sessions().unwrap().len(),
            2,
            "both racing commands' sessions are reachable through the path"
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_explicitly_configured_socket_never_auto_starts() {
        let _guard = ENV_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let dir = tempfile::tempdir().unwrap();
        // A dead socket named explicitly: an error naming it, and no
        // spawn — the configured agent is not optional (passlane#65).
        let _env = EnvVar::set(SOCKET_ENV, dir.path().join("named.sock"));
        let spawned = AtomicBool::new(false);
        let err = connect_or_start_with(900, &|_| {
            spawned.store(true, Ordering::SeqCst);
            Ok(())
        })
        .unwrap_err();
        assert!(!spawned.load(Ordering::SeqCst), "nothing was spawned");
        assert!(
            err.message.contains("unset PASSLANE_AGENT_SOCK"),
            "the error is the configured-socket one: {}",
            err.message
        );
        assert!(
            err.message.contains("named.sock"),
            "it names the dead socket: {}",
            err.message
        );
    }

    #[cfg(unix)]
    #[test]
    fn opting_out_restores_todays_error() {
        let _guard = ENV_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _defaults = DefaultSocketDir::new();
        let _opt_out = EnvVar::set(AUTOSTART_ENV, "0");
        let spawned = AtomicBool::new(false);
        let err = connect_or_start_with(900, &|_| {
            spawned.store(true, Ordering::SeqCst);
            Ok(())
        })
        .unwrap_err();
        assert!(!spawned.load(Ordering::SeqCst), "nothing was spawned");
        assert_eq!(
            err.message,
            not_running_error().message,
            "PASSLANE_AGENT_AUTOSTART=0 gives today's message unchanged"
        );
        // The spelling of the opt-out is lenient, the effect is not.
        for spelling in ["false", "NO", " off "] {
            let _alt = EnvVar::set(AUTOSTART_ENV, spelling);
            assert!(autostart_opted_out(), "{spelling:?} opts out");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_missing_binary_degrades_to_todays_error() {
        let _guard = ENV_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _defaults = DefaultSocketDir::new();
        // The override is authoritative: naming nothing means no binary.
        let _bin = EnvVar::set(AGENT_BIN_ENV, "/nonexistent/passlane-agent-stub");
        let spawned = AtomicBool::new(false);
        let err = connect_or_start_with(900, &|_| {
            spawned.store(true, Ordering::SeqCst);
            Ok(())
        })
        .unwrap_err();
        assert!(!spawned.load(Ordering::SeqCst), "nothing was spawned");
        assert_eq!(
            err.message,
            not_running_error().message,
            "a missing binary gives today's message unchanged"
        );
    }

    /// With no override, the binary is looked up beside nothing (the
    /// test binary's directory never holds a `passlane-agent`) and then
    /// on `PATH`: an executable `passlane-agent` there is what spawns.
    #[cfg(unix)]
    #[test]
    fn the_binary_is_found_on_path_when_not_overridden() {
        let _guard = ENV_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let path_dir = tempfile::tempdir().unwrap();
        let on_path = path_dir.path().join("passlane-agent");
        std::fs::write(&on_path, "#!/bin/sh\nexit 0\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&on_path, std::fs::Permissions::from_mode(0o755)).unwrap();

        let _defaults = DefaultSocketDir::new();
        let _no_bin = EnvVar::remove(AGENT_BIN_ENV);
        let _path = EnvVar::set("PATH", path_dir.path());
        let found = Mutex::new(None);
        connect_or_start_with(900, &|plan| {
            *found.lock().unwrap() = Some(plan.binary.clone());
            Err("the injected spawn never serves; the plan is all this tests".into())
        })
        .unwrap_err();
        assert_eq!(found.into_inner().unwrap(), Some(on_path));
    }

    /// The real process spawn, against a stub binary: detached, stdio
    /// appended to the agent log, and a daemon that never serves is
    /// reported with the log to consult — not spun on forever. HOME is
    /// pointed at a scratch directory so the test never touches the real
    /// `~/.passlane/agent.log`.
    #[cfg(unix)]
    #[test]
    fn a_real_spawn_of_a_stub_agent_logs_and_reports_a_daemon_that_never_serves() {
        let _guard = ENV_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let home = tempfile::tempdir().unwrap();
        let _home = EnvVar::set("HOME", home.path());
        let defaults = DefaultSocketDir::new();
        // The stub prints to stdout and exits: it proves the stdio
        // redirection and leaves the socket never accepting.
        let stub = defaults.dir.path().join("stub-agent");
        std::fs::write(
            &stub,
            "#!/bin/sh\necho \"stub passlane-agent\"\nls /dev/fd | sed 's/^/FD:/'\nexit 0\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        let _bin = EnvVar::set(AGENT_BIN_ENV, &stub);

        // A wrapper's stray fds: raw pipe duplicates (no FD_CLOEXEC) at a
        // low and a high number, both allocated with F_DUPFD so no
        // other descriptor is ever clobbered (tests run concurrently,
        // and fd numbers belong to the whole process). The daemon must
        // hold neither — a pipeline like `expect … | grep` never sees
        // EOF otherwise, and a high-numbered stray is no excuse.
        let mut pipe_fds = [0i32; 2];
        unsafe { assert_eq!(libc::pipe(pipe_fds.as_mut_ptr()), 0) };
        let stray_low = unsafe { libc::fcntl(pipe_fds[1], libc::F_DUPFD, 21) };
        assert!(stray_low >= 21, "F_DUPFD never clobbers a descriptor");
        let stray_high = unsafe { libc::fcntl(pipe_fds[1], libc::F_DUPFD, 2000) };
        let watched: Vec<i32> = [stray_low, stray_high]
            .into_iter()
            .filter(|fd| *fd >= 0)
            .collect();
        assert!(!watched.is_empty(), "at least the low fd is planted");

        let started = std::time::Instant::now();
        let err = connect_or_start(900).unwrap_err();
        unsafe {
            for fd in &watched {
                libc::close(*fd);
            }
            libc::close(pipe_fds[0]);
            libc::close(pipe_fds[1]);
        }
        assert!(
            started.elapsed() >= AUTOSTART_ACCEPT_BUDGET,
            "it polled the full budget, not longer"
        );
        assert!(
            started.elapsed() < AUTOSTART_ACCEPT_BUDGET + std::time::Duration::from_secs(10),
            "the poll is bounded"
        );
        assert!(
            err.message.contains("did not serve"),
            "names what failed: {}",
            err.message
        );
        let log = std::fs::read_to_string(agent_log_path()).unwrap();
        assert!(
            log.contains("stub passlane-agent"),
            "the stub's output was appended to the log: {log}"
        );
        for fd in &watched {
            assert!(
                !log.contains(&format!("\nFD:{fd}")),
                "the stray fd {fd} was closed in the daemon, not inherited: {log}"
            );
        }
    }
}
