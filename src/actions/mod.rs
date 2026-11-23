pub mod add;
pub mod approvals;
pub mod approve;
pub mod change_password;
pub mod completions;
pub mod delete;
pub mod edit;
pub mod export;
pub mod generate;
pub mod help;
pub mod hwkey;
pub mod import;
pub mod init;
pub mod list;
pub mod lock;
pub mod sessions;
pub mod show;
pub mod unlock;
pub mod vault;

use std::io::IsTerminal;
use std::time::Duration;

use crate::keychain;
use crate::keychain::PasswordLookup;
use crate::ui::input::ask_master_password;
use crate::vault_registry::{self, VaultConfig};
use arboard::Clipboard;
use clap::ArgMatches;
use keepass_ng::ChallengeResponseKey;
use passlane_agent::client::UnlockFactors;
use passlane_agent::error::AgentError;
use passlane_agent::protocol::ChallengeResponseMaterial;
use passlane_core::hwkey::HwKeyConfig;
use passlane_core::vault::entities::Error;
use passlane_core::vault::keepass_vault::KeepassVault;
use passlane_core::vault::vault_trait::Vault;
use zeroize::Zeroizing;

pub(crate) trait MatchHandlerTemplate
where
    Self::ItemType: Clone,
{
    type ItemType;

    fn pre_handle_matches(&self, matches: &Vec<Self::ItemType>);
    fn handle_one_match(&mut self, the_match: Self::ItemType) -> Result<Option<String>, Error>;
    fn handle_many_matches(
        &mut self,
        matches: Vec<Self::ItemType>,
    ) -> Result<Option<String>, Error>;
}

pub(crate) fn handle_matches<H>(
    matches: Vec<H::ItemType>,
    handler: &mut Box<H>,
) -> Result<Option<String>, Error>
where
    H: MatchHandlerTemplate,
    H::ItemType: Clone,
{
    if matches.is_empty() {
        Ok(Some("No matches found".to_string()))
    } else {
        handler.pre_handle_matches(&matches.clone());

        if matches.len() == 1 {
            handler.handle_one_match(matches[0].clone())
        } else {
            handler.handle_many_matches(matches)
        }
    }
}

pub trait Action {
    fn run(&self) -> Result<String, Error> {
        Ok("Success".to_string())
    }
}

/// Where the factors that opened a vault came from — used to attribute
/// open failures (a stale agent session) and to tell long-running actions
/// that they are session-backed and should watch for the agent dropping
/// that session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PasswordSource {
    /// The OS keychain (the vault was previously unlocked).
    Keychain,
    /// A live session-agent session (`once` sessions are consumed).
    SessionAgent,
    /// An interactive prompt.
    Prompt,
}

impl PasswordSource {
    fn as_u8(self) -> u8 {
        match self {
            PasswordSource::Keychain => 0,
            PasswordSource::SessionAgent => 1,
            PasswordSource::Prompt => 2,
        }
    }

    fn from_u8(v: u8) -> Self {
        match v {
            1 => PasswordSource::SessionAgent,
            2 => PasswordSource::Prompt,
            _ => PasswordSource::Keychain,
        }
    }
}

impl std::fmt::Display for PasswordSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            PasswordSource::Keychain => "the keychain",
            PasswordSource::SessionAgent => "the session agent",
            PasswordSource::Prompt => "the password prompt",
        })
    }
}

/// How the current process last unlocked a vault (see [`unlock`]), so
/// long-running actions can tell whether they are session-backed and
/// should watch for the agent dropping that session.
pub(crate) fn last_unlock_source() -> PasswordSource {
    PasswordSource::from_u8(LAST_UNLOCK_SOURCE.load(std::sync::atomic::Ordering::Relaxed))
}

fn set_last_unlock_source(source: PasswordSource) {
    LAST_UNLOCK_SOURCE.store(source.as_u8(), std::sync::atomic::Ordering::Relaxed);
}

static LAST_UNLOCK_SOURCE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Everything that opens a vault except its file: the master password and,
/// for a hardware-key vault, the challenge-response key.
pub(crate) struct VaultFactors {
    pub(crate) master_password: Zeroizing<String>,
    pub(crate) challenge_response: Option<ChallengeResponseKey>,
}

/// Opens the vault with the given factors — the real open, or whatever a
/// test injects.
type OpenVault<'a, T> = &'a dyn Fn(&VaultFactors) -> Result<T, Error>;

/// An opened vault, with the factors that opened it and where they came
/// from. `unlock --session` hands the factors to the agent.
pub(crate) struct Unlocked<T> {
    pub(crate) vault: T,
    pub(crate) source: PasswordSource,
    pub(crate) factors: VaultFactors,
}

/// How long a command that has no terminal waits for the keychain before
/// giving up on it. A stored password comes back in milliseconds; anything
/// slower is a permission dialog waiting for a click.
const KEYCHAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// What the unlock chain consults outside the process. Injected so the
/// chain's order and its fail-fast rules are testable without a keychain,
/// an agent, a hardware key or a terminal.
pub(crate) struct UnlockSources<'a> {
    /// Whether someone can answer a prompt: a terminal on stdin.
    pub(crate) interactive: bool,
    /// The master password stored in the OS keychain.
    pub(crate) keychain: &'a dyn Fn(&str) -> PasswordLookup,
    /// The unlock factors a live session-agent session holds for the vault.
    pub(crate) session: &'a dyn Fn(&str) -> Result<Option<UnlockFactors>, AgentError>,
    /// The vault's enrolled hardware key, as a connected device.
    pub(crate) hardware_key: &'a dyn Fn(&HwKeyConfig) -> Result<ChallengeResponseKey, Error>,
    /// Ask for the master password.
    pub(crate) prompt: &'a dyn Fn(&str) -> String,
    /// Tell the user which source is about to open the vault.
    pub(crate) announce: &'a dyn Fn(PasswordSource),
}

/// One source's answer: a master password and, for a session, the
/// hardware-key factor it may hold.
struct Candidate {
    master_password: Zeroizing<String>,
    held_challenge_response: Option<ChallengeResponseKey>,
    source: PasswordSource,
}

/// Which challenge-response factor opens the vault in an attempt.
#[derive(Clone, Copy)]
pub(crate) enum ChallengeKey<'a> {
    /// The one the vault is enrolled with: held by the session when it
    /// holds it, else the device's.
    Enrolled,
    /// This key, whatever the registry or a session says — for the
    /// hardware-key commands, which choose the key themselves: the
    /// recovery secret, or none while the first key is enrolled.
    Given(Option<&'a ChallengeResponseKey>),
}

impl Candidate {
    /// What opens the vault. With the enrolled key, the registry decides
    /// whether the vault has one: a session's held factor is used only when
    /// it does, and otherwise the factor comes from the device — which is
    /// why the chain only hands out such a candidate where someone can
    /// touch the key.
    fn into_factors(
        self,
        config: &VaultConfig,
        sources: &UnlockSources,
        key: ChallengeKey,
    ) -> Result<VaultFactors, Error> {
        let challenge_response = match (key, &config.hwkey, self.held_challenge_response) {
            (ChallengeKey::Given(key), _, _) => key.cloned(),
            (ChallengeKey::Enrolled, None, _) => None,
            (ChallengeKey::Enrolled, Some(_), Some(held)) => Some(held),
            (ChallengeKey::Enrolled, Some(hwkey), None) => Some((sources.hardware_key)(hwkey)?),
        };
        Ok(VaultFactors {
            master_password: self.master_password,
            challenge_response,
        })
    }
}

/// The unlock chain: candidate master passwords in the order the sources
/// are consulted (passlane#65).
///
/// 1. **The session agent.** The only source guaranteed prompt-free, so it
///    is asked first: with a live session the vault opens with no keychain
///    dialog and no hardware-key prompt, from any context. An agent that
///    is configured but cannot be used is an error, never a silent
///    fallback to a prompt.
/// 2. **The keychain** — bounded when nobody could answer its dialog.
/// 3. **The password prompt** — only with a terminal.
///
/// A hardware-key factor comes from the session when it holds one, and
/// from the device otherwise. Without a terminal the device is never
/// asked: such a command fails at once instead of waiting for a touch.
struct Candidates<'a> {
    config: &'a VaultConfig,
    sources: &'a UnlockSources<'a>,
    key: ChallengeKey<'a>,
    stage: Stage,
    /// Why the candidates already handed out did not do, for the error
    /// that ends the chain.
    failures: Vec<(PasswordSource, Error)>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Session,
    Keychain,
    Prompt,
    Done,
}

impl<'a> Candidates<'a> {
    fn new(config: &'a VaultConfig, sources: &'a UnlockSources<'a>, key: ChallengeKey<'a>) -> Self {
        Self {
            config,
            sources,
            key,
            stage: Stage::Session,
            failures: Vec::new(),
        }
    }

    /// The next candidate, or `Ok(None)` once every source has been tried.
    /// `Err` when the chain must stop and say why: an agent that is
    /// configured but unusable, or a prompt nobody could answer.
    fn next(&mut self) -> Result<Option<Candidate>, Error> {
        loop {
            match self.stage {
                Stage::Session => {
                    self.stage = Stage::Keychain;
                    if let Some(candidate) = self.session_candidate()? {
                        return Ok(Some(candidate));
                    }
                }
                Stage::Keychain => {
                    self.stage = Stage::Prompt;
                    if let Some(candidate) = self.keychain_candidate()? {
                        return Ok(Some(candidate));
                    }
                }
                Stage::Prompt => {
                    self.stage = Stage::Done;
                    return self.prompt_candidate();
                }
                Stage::Done => return Ok(None),
            }
        }
    }

    fn session_candidate(&self) -> Result<Option<Candidate>, Error> {
        let factors = match (self.sources.session)(&self.config.name) {
            Ok(factors) => factors,
            // No agent is running: it is optional infrastructure.
            Err(AgentError::NotRunning(_)) => None,
            // One is configured but cannot be used — unreachable, untrusted
            // or speaking another protocol dialect. Falling back would hide
            // that, and without a terminal hang on the prompt after it.
            Err(e) => return Err(crate::session_agent::to_error(e)),
        };
        let Some(factors) = factors else {
            // No session for this vault: a hardware-key vault then has
            // nothing left that could supply the key without a terminal.
            self.check_unattended_hardware_key(false)?;
            return Ok(None);
        };
        let held_challenge_response = match factors.challenge_response {
            Some(ChallengeResponseMaterial::Secret { secret_hex }) => Some(
                ChallengeResponseKey::LocalChallenge(secret_hex.expose().to_string()),
            ),
            // The session holds the password only — a physical key's factor
            // cannot be held — so the key has to come from the device.
            None => {
                self.check_unattended_hardware_key(true)?;
                None
            }
        };
        Ok(Some(Candidate {
            master_password: factors.master_password,
            held_challenge_response,
            source: PasswordSource::SessionAgent,
        }))
    }

    fn keychain_candidate(&mut self) -> Result<Option<Candidate>, Error> {
        self.check_unattended_hardware_key(false)?;
        match (self.sources.keychain)(&self.config.name) {
            PasswordLookup::Found(master_password) => Ok(Some(Candidate {
                master_password,
                held_challenge_response: None,
                source: PasswordSource::Keychain,
            })),
            PasswordLookup::Absent => Ok(None),
            // Without a terminal nobody can answer the keychain's permission
            // dialog: stop here and say so.
            PasswordLookup::TimedOut if !self.sources.interactive => {
                Err(self.with_failures(keychain_did_not_answer(self.config)))
            }
            // A keychain that could not be read is not a locked vault:
            // remember why, and let the next source have a turn.
            lookup => {
                let error = match lookup {
                    PasswordLookup::TimedOut => Error::new("the keychain did not answer"),
                    PasswordLookup::Failed(error) => error,
                    PasswordLookup::Found(_) | PasswordLookup::Absent => {
                        unreachable!("handled above")
                    }
                };
                self.failures.push((PasswordSource::Keychain, error));
                Ok(None)
            }
        }
    }

    fn prompt_candidate(&self) -> Result<Option<Candidate>, Error> {
        self.check_unattended_hardware_key(false)?;
        if !self.sources.interactive {
            return Err(self.with_failures(no_terminal(self.config)));
        }
        for (source, error) in &self.failures {
            if *source == PasswordSource::Keychain {
                eprintln!(
                    "Warning: the master password stored for vault '{}' could not be used \
                     ({}); asking for it instead.",
                    self.config.name, error.message
                );
            }
        }
        Ok(Some(Candidate {
            master_password: Zeroizing::new((self.sources.prompt)(&self.config.name)),
            held_challenge_response: None,
            source: PasswordSource::Prompt,
        }))
    }

    /// Called whenever the session left the vault's hardware-key factor
    /// unheld: without a terminal nobody can touch the key, so a command
    /// that would need the device fails here — before any other source
    /// waits on something. `password_only` says whether a live session
    /// holds the master password but not the key.
    fn check_unattended_hardware_key(&self, password_only: bool) -> Result<(), Error> {
        // A key given by the caller (a recovery secret) needs no device,
        // and is not what this is about.
        if matches!(self.key, ChallengeKey::Enrolled)
            && hardware_key_needs_a_touch(self.config)
            && !self.sources.interactive
        {
            return Err(
                self.with_failures(hardware_key_needs_a_terminal(self.config, password_only))
            );
        }
        Ok(())
    }

    /// Add what the sources already tried, so the error names the real
    /// cause and not only the last thing that was missing.
    fn with_failures(&self, error: Error) -> Error {
        if self.failures.is_empty() {
            return error;
        }
        let tried: Vec<String> = self
            .failures
            .iter()
            .map(|(source, error)| format!("{source}: {}", error.message))
            .collect();
        Error::new(&format!(
            "{} Also tried: {}.",
            error.message,
            tried.join("; ")
        ))
    }
}

/// Whether opening this vault means waiting for someone to touch a
/// hardware key. The registry's hardware key is a device-backed one,
/// which always does; a secret-backed factor recorded in the registry
/// (passlane#43, passlane#48) answers its challenge without a touch and
/// would be excluded here.
fn hardware_key_needs_a_touch(config: &VaultConfig) -> bool {
    config.hwkey.is_some()
}

pub(crate) fn hardware_key_needs_a_terminal(config: &VaultConfig, password_only: bool) -> Error {
    let session_note = if password_only {
        " The live session for this vault holds its master password only, not its key factor: a \
         physical key's factor cannot be handed to the session agent."
    } else {
        ""
    };
    Error::new(&format!(
        "Vault '{}' is protected by a hardware key and needs it touched to open, but this \
         command is running without a terminal, so there is no one to touch the key. Run it \
         from a terminal with the key connected.{session_note}",
        config.name
    ))
}

fn no_terminal(config: &VaultConfig) -> Error {
    Error::new(&format!(
        "Vault '{0}' is locked and this command is running without a terminal, so the master \
         password cannot be asked for. From a terminal, run 'passlane --vault {0} unlock \
         --session' — the session agent then holds the unlock factors and commands like this \
         one open the vault with no prompt — or 'passlane --vault {0} unlock' to store the \
         password in the keychain.",
        config.name
    ))
}

fn keychain_did_not_answer(config: &VaultConfig) -> Error {
    Error::new(&format!(
        "The keychain did not answer within {} seconds while unlocking vault '{1}': most \
         likely a permission dialog is waiting for a click that no one can give without a \
         terminal. Run 'passlane --vault {1} unlock --session' from a terminal to open a \
         session the agent serves without the keychain, or answer the dialog once from a \
         terminal run of this command.",
        KEYCHAIN_TIMEOUT.as_secs(),
        config.name
    ))
}

/// Open the vault through the unlock chain, with the open itself injected:
/// whatever `open` returns for the first factors that work. The tests open
/// a real vault file; the hardware-key commands get the concrete
/// `KeepassVault` they need to re-key.
fn unlock_with<T>(
    config: &VaultConfig,
    sources: &UnlockSources,
    key: ChallengeKey,
    open: OpenVault<T>,
) -> Result<Unlocked<T>, Error> {
    let mut candidates = Candidates::new(config, sources, key);
    while let Some(candidate) = candidates.next()? {
        let source = candidate.source;
        let factors = candidate.into_factors(config, sources, key)?;
        (sources.announce)(source);
        match open(&factors) {
            Ok(vault) => {
                return Ok(Unlocked {
                    vault,
                    source,
                    factors,
                });
            }
            Err(error) => {
                if source == PasswordSource::SessionAgent {
                    eprintln!(
                        "Warning: the session agent's factors did not open vault '{}': {}. \
                         Trying the other unlock sources; if the vault was re-keyed, drop the \
                         stale session with 'passlane sessions revoke'.",
                        config.name, error.message
                    );
                }
                candidates.failures.push((source, error));
            }
        }
    }
    Err(candidates
        .failures
        .pop()
        .map(|(_, error)| error)
        .unwrap_or_else(|| Error::new(&format!("Vault '{}' could not be opened.", config.name))))
}

/// Run `use_sources` with the CLI's real unlock sources. They borrow
/// each other, so they are built and used in one scope.
fn with_real_sources<T>(interactive: bool, use_sources: impl FnOnce(&UnlockSources<'_>) -> T) -> T {
    let keychain_bound = (!interactive).then_some(KEYCHAIN_TIMEOUT);
    let keychain = move |vault: &str| keychain::lookup_master_password(vault, keychain_bound);
    let session = |vault: &str| crate::session_agent::unlock_factors(vault);
    let hardware_key =
        |hwkey: &HwKeyConfig| passlane_core::hwkey::configured_challenge_response_key(hwkey);
    let prompt = |vault: &str| {
        ask_master_password(Some(&format!(
            "Please enter master password of vault '{}'",
            vault
        )))
    };
    let announce = |source: PasswordSource| {
        if source == PasswordSource::SessionAgent {
            eprintln!("Unlocking vault via the session agent...");
        } else {
            println!("Unlocking vault...");
        }
    };
    let sources = UnlockSources {
        interactive,
        keychain: &keychain,
        session: &session,
        hardware_key: &hardware_key,
        prompt: &prompt,
        announce: &announce,
    };
    use_sources(&sources)
}

/// Whether someone can answer a prompt: a terminal on stdin — the same
/// rule the agent policy uses to tell an owner from an agent context. The
/// keychain's dialog and a hardware key's touch are prompts too, and are
/// treated the same way.
pub(crate) fn at_a_terminal() -> bool {
    std::io::stdin().is_terminal()
}

/// Open the current vault through the unlock chain with the
/// challenge-response key `key`, letting `open` turn the factors that work
/// into whatever the caller needs.
fn open_through_chain<T>(
    key: ChallengeKey<'_>,
    open: impl Fn(&str, &str, Option<String>, Option<&ChallengeResponseKey>) -> Result<T, Error>,
) -> Result<Unlocked<T>, Error> {
    let config = vault_registry::current()?;
    with_real_sources(at_a_terminal(), |sources| {
        let open = |factors: &VaultFactors| {
            open(
                &factors.master_password,
                &config.path,
                config.keyfile.clone(),
                factors.challenge_response.as_ref(),
            )
        };
        unlock_with(&config, sources, key, &open)
    })
}

/// Open the current vault and remember where its factors came from (see
/// [`last_unlock_source`]).
pub(crate) fn unlock() -> Result<Box<dyn Vault>, Error> {
    let unlocked = unlock_reporting_factors()?;
    set_last_unlock_source(unlocked.source);
    Ok(unlocked.vault)
}

/// [`unlock`], also returning the factors that opened the vault:
/// `unlock --session` hands them to the agent.
pub(crate) fn unlock_reporting_factors() -> Result<Unlocked<Box<dyn Vault>>, Error> {
    open_through_chain(
        ChallengeKey::Enrolled,
        |password, path, keyfile, challenge_response| {
            KeepassVault::open(password, path, keyfile, challenge_response)
                .map(|vault| Box::new(vault) as Box<dyn Vault>)
        },
    )
}

/// The current vault as the concrete [`KeepassVault`], opened through the
/// unlock chain with the challenge-response key the caller chose — for
/// the hardware-key commands, which re-key it. Every source gets its turn
/// until one opens the vault, as for any command.
pub(crate) fn unlock_keepass(key: ChallengeKey<'_>) -> Result<Unlocked<KeepassVault>, Error> {
    open_through_chain(key, KeepassVault::open)
}

pub fn copy_to_clipboard(value: &str) {
    if let Err(e) = Clipboard::new().and_then(|mut ctx| ctx.set_text(value)) {
        eprintln!("Failed to copy to clipboard: {}", e);
    }
}

/// Copies `value` to the clipboard, then waits `timeout_secs` seconds (or until
/// Ctrl+C) and clears the clipboard if its content still matches.
/// This function **blocks** for the timeout duration.
pub fn copy_to_clipboard_timed(value: &str, timeout_secs: u64) {
    use std::sync::Once;
    use std::sync::atomic::{AtomicBool, Ordering};

    static INTERRUPTED: AtomicBool = AtomicBool::new(false);
    static HANDLER: Once = Once::new();

    let mut ctx = match Clipboard::new() {
        Ok(ctx) => ctx,
        Err(e) => {
            eprintln!("Failed to access clipboard: {}", e);
            return;
        }
    };
    if let Err(e) = ctx.set_text(value) {
        eprintln!("Failed to copy to clipboard: {}", e);
        return;
    }

    // Register the Ctrl+C handler once per process (ctrlc allows only one);
    // it just flags the wait loop below to exit early.
    HANDLER.call_once(|| {
        ctrlc::set_handler(|| {
            INTERRUPTED.store(true, Ordering::SeqCst);
        })
        .ok();
    });
    INTERRUPTED.store(false, Ordering::SeqCst);

    // Wait in 100ms increments so we notice the interrupt quickly.
    let total_ms = timeout_secs * 1000;
    let mut elapsed = 0u64;
    while elapsed < total_ms && !INTERRUPTED.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_millis(100));
        elapsed += 100;
    }

    // Clear clipboard if it still holds the password we put there.
    let result: Result<(), ()> = (|| {
        let current = ctx.get_text().map_err(|_| ())?;
        if current == value {
            ctx.clear().map_err(|_| ())?;
        }
        Ok(())
    })();
    if result.is_err() {
        log::debug!("Failed to clear clipboard after timeout");
    }
}

pub trait UnlockingAction {
    fn execute(&self) -> Result<Option<String>, Error> {
        let mut vault = unlock()?;
        // Ensure completion cache exists when vault is open
        crate::completion_cache::ensure_cache_from_vault(&vault);
        self.run_with_vault(&mut vault)
    }

    fn run_with_vault(&self, _: &mut Box<dyn Vault>) -> Result<Option<String>, Error> {
        Ok(Some("Success".to_string()))
    }
}

#[derive(Debug, PartialEq)]
pub enum ItemType {
    Credential,
    Payment,
    Note,
    Totp,
}

impl ItemType {
    pub fn new_from_args(matches: &ArgMatches) -> ItemType {
        if matches.get_one::<bool>("payments").map_or(false, |v| *v) {
            ItemType::Payment
        } else if matches.get_one("notes").map_or(false, |v| *v) {
            ItemType::Note
        } else if matches.get_one("otp").map_or(false, |v| *v) {
            ItemType::Totp
        } else {
            ItemType::Credential
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault_registry::set_current;
    use passlane_agent::protocol::SecretString;
    use passlane_core::vault::entities::Credential;
    use passlane_core::vault::vault_trait::PasswordVault;
    use std::cell::Cell;
    use std::path::PathBuf;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    const PASSWORD: &str = "chain-master-password";
    /// The HMAC-SHA1 secret of the test vault's challenge-response slot.
    const SLOT_SECRET: &str = "0102030405060708090a0b0c0d0e0f1011121314";

    /// The current vault is process-global: tests that set it take turns.
    static CURRENT: Mutex<()> = Mutex::new(());

    /// A vault file with one credential, created once per test binary.
    /// With `keyed`, it is protected by a challenge-response factor — a
    /// secret-backed one, the stand-in for a hardware key no test can
    /// touch. Nothing here writes to the file afterwards.
    fn vault_file(keyed: bool) -> &'static str {
        static PLAIN: OnceLock<String> = OnceLock::new();
        static KEYED: OnceLock<String> = OnceLock::new();
        let slot = if keyed { &KEYED } else { &PLAIN };
        slot.get_or_init(|| {
            let dir: &'static tempfile::TempDir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
            let path: PathBuf = dir.path().join("vault.kdbx");
            let path = path.to_str().unwrap().to_string();
            let factor =
                keyed.then(|| ChallengeResponseKey::LocalChallenge(SLOT_SECRET.to_string()));
            let mut vault =
                KeepassVault::new(&path, PASSWORD, None, factor.as_ref()).expect("create vault");
            vault
                .save_one_credential(Credential::new(
                    None,
                    "entry-pw",
                    "github.com",
                    "alice",
                    None,
                    None,
                ))
                .expect("seed vault");
            path
        })
    }

    /// Make the test vault current; hold the guard for the test's length.
    fn use_vault(keyed: bool) -> MutexGuard<'static, ()> {
        let guard = CURRENT
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        set_current(VaultConfig {
            name: "chain-test".to_string(),
            path: vault_file(keyed).to_string(),
            keyfile: None,
            hwkey: keyed.then_some(HwKeyConfig {
                slot: 1,
                serial: None,
            }),
        });
        guard
    }

    /// The chain against the current vault's real file, opening it with
    /// the key the vault is enrolled with.
    fn unlock_test(sources: &UnlockSources) -> Result<Unlocked<Box<dyn Vault>>, Error> {
        unlock_test_with(ChallengeKey::Enrolled, sources)
    }

    fn unlock_test_with(
        key: ChallengeKey<'_>,
        sources: &UnlockSources,
    ) -> Result<Unlocked<Box<dyn Vault>>, Error> {
        let config = vault_registry::current().unwrap();
        let path = vault_file(config.hwkey.is_some());
        let open = |factors: &VaultFactors| {
            KeepassVault::open(
                &factors.master_password,
                path,
                config.keyfile.clone(),
                factors.challenge_response.as_ref(),
            )
            .map(|vault| Box::new(vault) as Box<dyn Vault>)
        };
        unlock_with(&config, sources, key, &open)
    }

    /// What the chain reports when nothing opens the vault.
    fn unlock_error(sources: &UnlockSources, why: &str) -> Error {
        match unlock_test(sources) {
            Ok(_) => panic!("{why}"),
            Err(error) => error,
        }
    }

    /// A live session's answer for the test vault: its real master
    /// password, holding the key factor or not.
    fn session_with(
        key_factor: bool,
    ) -> impl Fn(&str) -> Result<Option<UnlockFactors>, AgentError> {
        move |vault| {
            assert_eq!(
                vault, "chain-test",
                "the session is asked about the current vault"
            );
            Ok(Some(UnlockFactors {
                master_password: Zeroizing::new(PASSWORD.to_string()),
                challenge_response: key_factor.then(|| ChallengeResponseMaterial::Secret {
                    secret_hex: SecretString::new(SLOT_SECRET),
                }),
                expires_at: Some(1_800_000_000),
            }))
        }
    }

    fn wrong_session() -> impl Fn(&str) -> Result<Option<UnlockFactors>, AgentError> {
        |_| {
            Ok(Some(UnlockFactors {
                master_password: Zeroizing::new("re-keyed-since".to_string()),
                challenge_response: None,
                expires_at: None,
            }))
        }
    }

    fn no_session() -> impl Fn(&str) -> Result<Option<UnlockFactors>, AgentError> {
        |_| Ok(None)
    }

    fn no_agent() -> impl Fn(&str) -> Result<Option<UnlockFactors>, AgentError> {
        |_| Err(AgentError::NotRunning("no socket path configured".into()))
    }

    fn stored(password: &'static str) -> impl Fn(&str) -> PasswordLookup {
        move |_| PasswordLookup::Found(Zeroizing::new(password.to_string()))
    }

    fn no_prompt() -> impl Fn(&str) -> String {
        |_| panic!("no one can answer a prompt here")
    }

    fn nothing_announced() -> impl Fn(PasswordSource) {
        |_| {}
    }

    /// The vault's key as a connected device would give it — simulated,
    /// counting how often the chain reaches for it.
    fn device_key(
        calls: &Cell<usize>,
    ) -> impl Fn(&HwKeyConfig) -> Result<ChallengeResponseKey, Error> {
        move |hwkey| {
            assert_eq!(hwkey.slot, 1);
            calls.set(calls.get() + 1);
            Ok(ChallengeResponseKey::LocalChallenge(
                SLOT_SECRET.to_string(),
            ))
        }
    }

    #[test]
    fn a_live_session_opens_a_hardware_key_vault_with_nothing_else_involved() {
        let _guard = use_vault(true);
        let sources = UnlockSources {
            interactive: false,
            keychain: &|_| panic!("a live session must not be shadowed by the keychain"),
            session: &session_with(true),
            hardware_key: &|_| panic!("the session holds the key factor: no device is needed"),
            prompt: &no_prompt(),
            announce: &|source| assert_eq!(source, PasswordSource::SessionAgent),
        };
        let unlocked = unlock_test(&sources).expect("the session opens the vault");
        assert_eq!(unlocked.source, PasswordSource::SessionAgent);
        assert_eq!(
            unlocked.vault.grep(None).len(),
            1,
            "the vault really opened"
        );
    }

    #[test]
    fn a_live_session_opens_a_password_only_vault_the_same_way() {
        let _guard = use_vault(false);
        let sources = UnlockSources {
            interactive: false,
            keychain: &|_| panic!("a live session must not be shadowed by the keychain"),
            session: &session_with(false),
            hardware_key: &|_| panic!("no hardware key is enrolled"),
            prompt: &no_prompt(),
            announce: &nothing_announced(),
        };
        let unlocked = unlock_test(&sources).expect("the session opens the vault");
        assert_eq!(unlocked.source, PasswordSource::SessionAgent);
    }

    #[test]
    fn the_registry_decides_whether_a_vault_has_a_hardware_key() {
        // A session may carry a key factor the registry on this machine
        // knows nothing about; the vault file is what is opened, with the
        // factors the registry says it takes.
        let _guard = use_vault(false);
        let sources = UnlockSources {
            interactive: false,
            keychain: &|_| panic!("a live session must not be shadowed by the keychain"),
            session: &session_with(true),
            hardware_key: &|_| panic!("no hardware key is enrolled"),
            prompt: &no_prompt(),
            announce: &nothing_announced(),
        };
        let unlocked = unlock_test(&sources).expect("the password alone opens the vault");
        assert!(unlocked.factors.challenge_response.is_none());
    }

    #[test]
    fn a_session_holding_only_the_password_leaves_the_key_to_a_terminal() {
        let _guard = use_vault(true);
        let device_calls = Cell::new(0);
        let sources = UnlockSources {
            interactive: true,
            keychain: &|_| panic!("a live session must not be shadowed by the keychain"),
            session: &session_with(false),
            hardware_key: &device_key(&device_calls),
            prompt: &no_prompt(),
            announce: &nothing_announced(),
        };
        let unlocked = unlock_test(&sources).expect("the key at the terminal opens the vault");
        assert_eq!(unlocked.source, PasswordSource::SessionAgent);
        assert_eq!(device_calls.get(), 1, "the key came from the device, once");
    }

    #[test]
    fn without_a_terminal_a_session_without_the_key_factor_fails_before_anything_waits() {
        let _guard = use_vault(true);
        let sources = UnlockSources {
            interactive: false,
            keychain: &|_| panic!("nothing may wait on the keychain: the key cannot be had"),
            session: &session_with(false),
            hardware_key: &|_| panic!("nobody can touch the key: the device must not be asked"),
            prompt: &no_prompt(),
            announce: &nothing_announced(),
        };
        let error = unlock_error(&sources, "no key factor, no terminal: fail fast");
        assert!(error.message.contains("hardware key"), "{}", error.message);
        assert!(
            error.message.contains("master password only"),
            "{}",
            error.message
        );
        assert!(
            error.message.contains("without a terminal"),
            "{}",
            error.message
        );
    }

    #[test]
    fn without_a_terminal_a_hardware_key_vault_with_no_session_never_waits_on_the_keychain() {
        let _guard = use_vault(true);
        let sources = UnlockSources {
            interactive: false,
            keychain: &|_| panic!("the stored password cannot open the vault without the key"),
            session: &no_session(),
            hardware_key: &|_| panic!("nobody can touch the key"),
            prompt: &no_prompt(),
            announce: &nothing_announced(),
        };
        let error = unlock_error(&sources, "fail fast");
        assert!(error.message.contains("hardware key"), "{}", error.message);
        assert!(
            !error.message.contains("master password only"),
            "no session exists: {}",
            error.message
        );
    }

    #[test]
    fn without_a_terminal_a_locked_vault_fails_with_guidance_not_a_prompt() {
        let _guard = use_vault(false);
        let sources = UnlockSources {
            interactive: false,
            keychain: &|_| PasswordLookup::Absent,
            session: &no_session(),
            hardware_key: &|_| panic!("no hardware key is enrolled"),
            prompt: &no_prompt(),
            announce: &nothing_announced(),
        };
        let error = unlock_error(&sources, "nothing can open the vault");
        assert!(
            error.message.contains("without a terminal"),
            "{}",
            error.message
        );
        assert!(
            error
                .message
                .contains("'passlane --vault chain-test unlock --session'"),
            "{}",
            error.message
        );
        assert!(
            error
                .message
                .contains("'passlane --vault chain-test unlock'"),
            "{}",
            error.message
        );
    }

    #[test]
    fn without_a_terminal_a_keychain_that_does_not_answer_ends_the_unlock() {
        let _guard = use_vault(false);
        let sources = UnlockSources {
            interactive: false,
            keychain: &|_| PasswordLookup::TimedOut,
            session: &no_session(),
            hardware_key: &|_| panic!("no hardware key is enrolled"),
            prompt: &no_prompt(),
            announce: &nothing_announced(),
        };
        let error = unlock_error(&sources, "the keychain never answers");
        assert!(
            error.message.contains(&format!(
                "did not answer within {} seconds",
                KEYCHAIN_TIMEOUT.as_secs()
            )),
            "{}",
            error.message
        );
    }

    #[test]
    fn a_stale_session_falls_through_to_the_keychain() {
        let _guard = use_vault(false);
        let sources = UnlockSources {
            interactive: false,
            keychain: &stored(PASSWORD),
            session: &wrong_session(),
            hardware_key: &|_| panic!("no hardware key is enrolled"),
            prompt: &no_prompt(),
            announce: &nothing_announced(),
        };
        let unlocked = unlock_test(&sources).expect("the keychain still opens the vault");
        assert_eq!(unlocked.source, PasswordSource::Keychain);
    }

    #[test]
    fn a_stale_keychain_password_falls_through_to_the_prompt() {
        let _guard = use_vault(false);
        let sources = UnlockSources {
            interactive: true,
            keychain: &stored("changed-elsewhere"),
            session: &no_session(),
            hardware_key: &|_| panic!("no hardware key is enrolled"),
            prompt: &|_| PASSWORD.to_string(),
            announce: &nothing_announced(),
        };
        let unlocked = unlock_test(&sources).expect("the owner's password opens the vault");
        assert_eq!(unlocked.source, PasswordSource::Prompt);
    }

    #[test]
    fn an_agent_that_is_configured_but_unusable_is_an_error_not_a_fallback() {
        let _guard = use_vault(false);
        type Broken = fn() -> AgentError;
        let unusable: [(&str, Broken); 4] = [
            ("PASSLANE_AGENT_SOCK", || {
                AgentError::NotListening(PathBuf::from("/run/user/501/passlane-agent.sock"))
            }),
            ("PASSLANE_AGENT_SOCK", || {
                AgentError::Protocol("untrusted socket".into())
            }),
            ("Restart passlane-agent", || AgentError::VersionMismatch {
                agent: 1,
                client: 2,
            }),
            ("PASSLANE_AGENT_SOCK", || {
                AgentError::Io(std::io::Error::other("connection reset"))
            }),
        ];
        for (hint, broken) in unusable {
            let sources = UnlockSources {
                interactive: false,
                keychain: &|_| panic!("a configured agent is not silently skipped"),
                session: &|_| Err(broken()),
                hardware_key: &|_| panic!("no hardware key is enrolled"),
                prompt: &no_prompt(),
                announce: &nothing_announced(),
            };
            let reported = unlock_error(&sources, "the agent's problem is the error");
            assert!(
                reported.message.starts_with("session agent error:"),
                "{}",
                reported.message
            );
            assert!(reported.message.contains(hint), "{}", reported.message);
        }
    }

    #[test]
    fn with_no_agent_at_all_the_keychain_comes_next() {
        let _guard = use_vault(false);
        let sources = UnlockSources {
            interactive: false,
            keychain: &stored(PASSWORD),
            session: &no_agent(),
            hardware_key: &|_| panic!("no hardware key is enrolled"),
            prompt: &no_prompt(),
            announce: &|source| assert_eq!(source, PasswordSource::Keychain),
        };
        let unlocked = unlock_test(&sources).expect("the agent is optional");
        assert_eq!(unlocked.source, PasswordSource::Keychain);
    }

    #[test]
    fn a_keychain_that_cannot_be_read_is_named_in_the_failure() {
        let _guard = use_vault(false);
        let sources = UnlockSources {
            interactive: false,
            keychain: &|_| PasswordLookup::Failed(Error::new("keychain locked")),
            session: &no_session(),
            hardware_key: &|_| panic!("no hardware key is enrolled"),
            prompt: &no_prompt(),
            announce: &nothing_announced(),
        };
        let error = unlock_error(&sources, "nothing opened the vault");
        assert!(
            error.message.contains("without a terminal"),
            "{}",
            error.message
        );
        assert!(
            error
                .message
                .contains("Also tried: the keychain: keychain locked"),
            "{}",
            error.message
        );
    }

    #[test]
    fn the_enrolled_key_is_never_resolved_unattended() {
        // `hwkey remove` opens the vault through the chain like any command.
        let _guard = use_vault(true);
        let sources = UnlockSources {
            interactive: false,
            keychain: &|_| panic!("nothing may wait on the keychain"),
            session: &session_with(false),
            hardware_key: &|_| panic!("nobody can touch the key"),
            prompt: &no_prompt(),
            announce: &nothing_announced(),
        };
        let config = vault_registry::current().unwrap();
        match Candidates::new(&config, &sources, ChallengeKey::Enrolled).next() {
            Err(error) => assert!(error.message.contains("hardware key"), "{}", error.message),
            Ok(_) => panic!("the key factor is missing and cannot be asked for"),
        }
    }

    #[test]
    fn a_key_the_command_chooses_needs_neither_a_terminal_nor_a_held_factor() {
        // `hwkey remove --secret` opens with the recovery secret the owner
        // typed in: no device is involved, whatever the registry says.
        let _guard = use_vault(true);
        let recovery = ChallengeResponseKey::LocalChallenge(SLOT_SECRET.to_string());
        let sources = UnlockSources {
            interactive: false,
            keychain: &|_| panic!("a live session supplies the password"),
            session: &session_with(false),
            hardware_key: &|_| panic!("the given key is used: no device is needed"),
            prompt: &no_prompt(),
            announce: &nothing_announced(),
        };
        let unlocked = unlock_test_with(ChallengeKey::Given(Some(&recovery)), &sources)
            .expect("the given key opens the vault");
        assert_eq!(unlocked.source, PasswordSource::SessionAgent);
    }

    #[test]
    fn a_stale_session_does_not_shadow_the_keychain_for_a_chosen_key_either() {
        // `hwkey add` opens the not-yet-keyed vault with no challenge
        // response: a stale session gives way to the keychain.
        let _guard = use_vault(false);
        let sources = UnlockSources {
            interactive: false,
            keychain: &stored(PASSWORD),
            session: &wrong_session(),
            hardware_key: &|_| panic!("no hardware key is enrolled yet"),
            prompt: &no_prompt(),
            announce: &nothing_announced(),
        };
        let unlocked = unlock_test_with(ChallengeKey::Given(None), &sources)
            .expect("the keychain opens the vault");
        assert_eq!(unlocked.source, PasswordSource::Keychain);
    }
}
