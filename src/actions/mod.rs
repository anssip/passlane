pub mod add;
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

use crate::keychain;

use crate::ui::input::ask_master_password;
use arboard::Clipboard;
use clap::ArgMatches;
use keepass_ng::ChallengeResponseKey;
use passlane_core::vault::entities::Error;
use passlane_core::vault::keepass_vault::KeepassVault;
use passlane_core::vault::vault_trait::Vault;
use zeroize::{Zeroize, Zeroizing};

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

/// Where a vault's master password came from — used to attribute open
/// failures (a stale agent session) and to tell the user what happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PasswordSource {
    /// The OS keychain (the vault was previously unlocked).
    Keychain,
    /// A live session-agent session (`once` sessions are consumed).
    SessionAgent,
    /// An interactive prompt.
    Prompt,
}

/// The master-password lookup chain with every source injected so the
/// ordering itself is hermetically testable: keychain first (persistent,
/// no session burned), then the session agent, then the prompt.
fn get_vault_password_with(
    vault_name: &str,
    keychain_lookup: &dyn Fn(&str) -> Option<String>,
    agent_lookup: &dyn Fn(&str) -> Option<Zeroizing<String>>,
    prompt: &dyn Fn(&str) -> String,
) -> (String, PasswordSource) {
    if let Some(password) = keychain_lookup(vault_name) {
        return (password, PasswordSource::Keychain);
    }
    if let Some(password) = agent_lookup(vault_name) {
        return (password.to_string(), PasswordSource::SessionAgent);
    }
    (prompt(vault_name), PasswordSource::Prompt)
}

/// The current vault's master password: from the keychain when unlocked,
/// else a live session-agent session, else prompted for.
pub(crate) fn get_vault_password(vault_name: &str) -> String {
    get_vault_password_with(
        vault_name,
        &|name| keychain::get_master_password(name).ok(),
        &|name| crate::session_agent::try_unlock_factors(name),
        &|name| {
            ask_master_password(Some(&format!(
                "Please enter master password of vault '{}'",
                name
            )))
        },
    )
    .0
}

type VaultProperties = (String, String, Option<String>, Option<ChallengeResponseKey>);

fn get_vault_properties() -> Result<(VaultProperties, PasswordSource), Error> {
    get_vault_properties_with(&|name| keychain::get_master_password(name).ok(), &|name| {
        let fetched = crate::session_agent::try_unlock_factors_with_expiry(name);
        LAST_AGENT_SESSION_EXPIRY.store(
            fetched.as_ref().and_then(|(_, exp)| *exp).unwrap_or(0),
            std::sync::atomic::Ordering::Relaxed,
        );
        fetched.map(|(password, _)| password)
    })
}

/// [`get_vault_properties`] with the keychain and agent lookups injected
/// (tests run without touching either).
fn get_vault_properties_with(
    keychain_lookup: &dyn Fn(&str) -> Option<String>,
    agent_lookup: &dyn Fn(&str) -> Option<Zeroizing<String>>,
) -> Result<(VaultProperties, PasswordSource), Error> {
    let config = crate::vault_registry::current()?;
    let (mut master_pwd, source) =
        get_vault_password_with(&config.name, keychain_lookup, agent_lookup, &|name| {
            ask_master_password(Some(&format!(
                "Please enter master password of vault '{}'",
                name
            )))
        });
    let challenge_response = match config.hwkey {
        Some(ref hwkey_config) => {
            match passlane_core::hwkey::configured_challenge_response_key(hwkey_config) {
                Ok(cr) => Some(cr),
                Err(e) => {
                    // The key not being connected lands here; keep the password
                    // zeroize discipline on this early return too.
                    master_pwd.zeroize();
                    return Err(e);
                }
            }
        }
        None => None,
    };
    Ok((
        (master_pwd, config.path, config.keyfile, challenge_response),
        source,
    ))
}

/// How the current process last unlocked a vault (see [`unlock`]), so
/// long-running actions can tell whether they are session-backed and
/// should watch for the agent dropping that session.
pub(crate) fn last_unlock_source() -> PasswordSource {
    PasswordSource::from_u8(LAST_UNLOCK_SOURCE.load(std::sync::atomic::Ordering::Relaxed))
}

/// When the session-agent session that supplied the last unlock expires
/// (unix seconds; 0 = not session-backed or a `once` session).
/// Long-running actions revalidate against this after subscribing to
/// agent events, so an expiry firing during vault decryption is not
/// missed.
pub(crate) fn last_agent_session_expiry() -> u64 {
    LAST_AGENT_SESSION_EXPIRY.load(std::sync::atomic::Ordering::Relaxed)
}

fn set_last_unlock_source(source: PasswordSource) {
    LAST_UNLOCK_SOURCE.store(source.as_u8(), std::sync::atomic::Ordering::Relaxed);
    if source != PasswordSource::SessionAgent {
        LAST_AGENT_SESSION_EXPIRY.store(0, std::sync::atomic::Ordering::Relaxed);
    }
}

static LAST_UNLOCK_SOURCE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
static LAST_AGENT_SESSION_EXPIRY: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

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

pub(crate) fn unlock() -> Result<Box<dyn Vault>, Error> {
    let ((mut master_pwd, filepath, keyfile_path, challenge_response), source) =
        get_vault_properties()?;
    set_last_unlock_source(source);
    if source == PasswordSource::SessionAgent {
        eprintln!("Unlocking vault via the session agent...");
    } else {
        println!("Unlocking vault...");
    }
    let vault = get_vault(
        &master_pwd,
        &filepath,
        keyfile_path,
        challenge_response.as_ref(),
    )
    .map_err(|e| {
        if source == PasswordSource::SessionAgent {
            Error::new(&format!(
                "{} (the unlock factors came from a session agent; if the vault was \
                     re-keyed, drop the stale session with 'passlane sessions revoke' and \
                     try again)",
                e.message
            ))
        } else {
            e
        }
    });
    master_pwd.zeroize();
    vault
}

fn get_vault(
    password: &str,
    filepath: &str,
    keyfile_path: Option<String>,
    challenge_response: Option<&ChallengeResponseKey>,
) -> Result<Box<dyn Vault>, Error> {
    // we could return some other Vault implementation here
    let vault = KeepassVault::open(password, filepath, keyfile_path, challenge_response)?;
    Ok(Box::new(vault))
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
    use crate::vault_registry::{VaultConfig, set_current};

    fn test_vault() {
        set_current(VaultConfig {
            name: "agent-test".to_string(),
            path: "/nonexistent/agent-test.kdbx".to_string(),
            keyfile: None,
            hwkey: None,
        });
    }

    fn agent_password(pw: &str) -> impl Fn(&str) -> Option<Zeroizing<String>> + '_ {
        move |vault| {
            assert_eq!(vault, "agent-test");
            Some(Zeroizing::new(pw.to_string()))
        }
    }

    #[test]
    fn password_order_keychain_first_then_agent_then_prompt() {
        test_vault();
        // Keychain hit: the agent is never consulted (no once-sessions
        // get burned while the password is already on disk).
        let (pw, source) = get_vault_password_with(
            "agent-test",
            &|_| Some("keychain-pw".to_string()),
            &|_| panic!("the agent must not be consulted on a keychain hit"),
            &|_| panic!("no prompt on a keychain hit"),
        );
        assert_eq!(pw, "keychain-pw");
        assert_eq!(source, PasswordSource::Keychain);

        // Keychain miss, agent hit.
        let (pw, source) = get_vault_password_with(
            "agent-test",
            &|_| None,
            &agent_password("agent-pw"),
            &|_| panic!("no prompt when the agent holds a session"),
        );
        assert_eq!(pw, "agent-pw");
        assert_eq!(source, PasswordSource::SessionAgent);

        // Everything misses: the prompt is the last resort.
        let (pw, source) = get_vault_password_with("agent-test", &|_| None, &|_| None, &|name| {
            format!("prompted-for-{name}")
        });
        assert_eq!(pw, "prompted-for-agent-test");
        assert_eq!(source, PasswordSource::Prompt);
    }

    #[test]
    fn vault_properties_flow_through_the_agent_source() {
        test_vault();
        let ((pw, path, keyfile, challenge), source) =
            get_vault_properties_with(&|_| None, &agent_password("agent-pw"))
                .expect("properties resolve from the agent");
        assert_eq!(pw, "agent-pw");
        assert_eq!(path, "/nonexistent/agent-test.kdbx");
        assert!(keyfile.is_none());
        assert!(challenge.is_none());
        assert_eq!(source, PasswordSource::SessionAgent);
    }
}
