use std::collections::BTreeSet;
use std::fs;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use log::debug;

use crate::keychain;
use crate::session_agent::{SessionFactors, session_factors};
use crate::vault_registry;
use passlane_core::vault::entities::Error;
use passlane_core::vault::keepass_vault::KeepassVault;
use passlane_core::vault::vault_trait::Vault;

const CACHE_FILENAME_PREFIX: &str = ".completion_cache";
const STALE_DAYS: u64 = 7;

/// One cache file per vault: `~/.passlane/.completion_cache.<name>`.
/// Path construction under an explicit config dir is split out so tests
/// never touch the real home directory.
fn cache_path_in(config_dir: &Path, vault_name: &str) -> PathBuf {
    config_dir.join(format!("{}.{}", CACHE_FILENAME_PREFIX, vault_name))
}

pub(crate) fn cache_path(vault_name: &str) -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("~"));
    cache_path_in(&home.join(".passlane"), vault_name)
}

fn current_cache_path() -> Option<PathBuf> {
    vault_registry::current().ok().map(|v| cache_path(&v.name))
}

/// Reads all credentials from the vault, extracts deduplicated service names
/// and usernames, and writes them one per line to the current vault's cache.
pub fn update_cache(vault: &Box<dyn Vault>) {
    let Some(path) = current_cache_path() else {
        return;
    };
    let entries = collect_entry_names(vault);
    if let Err(e) = write_cache(&path, &entries) {
        debug!("Failed to write completion cache: {}", e);
    }
}

/// Deletes a vault's completion cache file. No error if the file is missing.
pub fn clear_cache_for(vault_name: &str) {
    clear_cache_at(&cache_path(vault_name));
}

fn clear_cache_at(path: &Path) {
    if path.exists() {
        if let Err(e) = fs::remove_file(path) {
            debug!("Failed to remove completion cache: {}", e);
        }
    }
}

/// Reads entry names from the current vault's cache file. Returns an empty
/// vec if the file is missing or no vault is selected.
pub fn read_cache() -> Vec<String> {
    let Some(path) = current_cache_path() else {
        return Vec::new();
    };
    match fs::read_to_string(&path) {
        Ok(contents) => contents
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| l.to_string())
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// How old the cache file at `path` is, in so many words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CacheAge {
    /// There is no cache file.
    Missing,
    /// Older than [`STALE_DAYS`].
    Stale,
    /// Recent enough to be left alone.
    Fresh,
    /// The file is there but its age cannot be read: leave it alone rather
    /// than rewrite it on every command.
    Unknown,
}

fn cache_age(path: &Path) -> CacheAge {
    let Ok(meta) = fs::metadata(path) else {
        return if path.exists() {
            CacheAge::Unknown
        } else {
            CacheAge::Missing
        };
    };
    match meta.modified() {
        Ok(modified) => {
            if SystemTime::now()
                .duration_since(modified)
                .unwrap_or(Duration::ZERO)
                > Duration::from_secs(STALE_DAYS * 24 * 60 * 60)
            {
                CacheAge::Stale
            } else {
                CacheAge::Fresh
            }
        }
        Err(_) => CacheAge::Unknown,
    }
}

/// Brings the cache file up to date from the vault a command has just
/// opened, when it is missing or stale. Called from
/// `UnlockingAction::execute`, so any command that opens the vault also
/// refreshes the cache — from that vault, with no keychain read and no
/// second open.
pub fn ensure_cache_from_vault(vault: &Box<dyn Vault>) {
    let Some(path) = current_cache_path() else {
        return;
    };
    ensure_cache_at(&path, &|| update_cache(vault));
}

/// [`ensure_cache_from_vault`] with the write injected, so the rule is
/// testable without a vault.
fn ensure_cache_at(path: &Path, write: &dyn Fn()) {
    match cache_age(path) {
        CacheAge::Missing => {
            debug!("Completion cache missing, creating from open vault...");
            write();
        }
        CacheAge::Stale => {
            debug!("Completion cache is stale, refreshing from open vault...");
            write();
        }
        CacheAge::Fresh | CacheAge::Unknown => {}
    }
}

/// Refreshes the current vault's cache when it is older than 7 days, for
/// the commands that do not open the vault themselves (the others refresh
/// it from the vault they open; see [`ensure_cache_from_vault`]). It opens
/// the vault through the keychain — a read that can wait on a permission
/// dialog for as long as nobody clicks it — so it is skipped whenever no
/// one can be expected to answer one: without a terminal, or while a live
/// session-agent session serves the vault prompt-free.
pub fn refresh_if_stale() {
    refresh_if_stale_with(
        std::io::stdin().is_terminal(),
        current_cache_path(),
        &may_read_keychain_for_current_vault,
        &create_cache_from_keychain,
    );
}

/// The `may_read_keychain` answer for the current vault: only when no
/// session serves it *and* the agent's state is known.
fn may_read_keychain_for_current_vault() -> bool {
    match vault_registry::current() {
        Ok(config) => refresh_may_read_keychain(session_factors(&config.name)),
        // No vault to speak of: nothing holds it open.
        Err(_) => true,
    }
}

/// Whether the optional stale-cache refresh may read the keychain: only
/// when no session serves the vault *and* the agent's state is known. An
/// agent that cannot be used is the command's error to report — not a
/// reason to go waiting on a keychain dialog in front of it.
fn refresh_may_read_keychain(held: Result<SessionFactors, Error>) -> bool {
    matches!(held, Ok(SessionFactors::None))
}

/// [`refresh_if_stale`] with what reaches outside the process injected, so
/// the rule is testable without a terminal, a home directory, a keychain
/// or an agent. `may_read_keychain` is only asked when its answer matters:
/// it talks to the agent.
fn refresh_if_stale_with(
    interactive: bool,
    cache_path: Option<PathBuf>,
    may_read_keychain: &dyn Fn() -> bool,
    refresh: &dyn Fn(),
) {
    if !interactive {
        return;
    }
    let Some(path) = cache_path else {
        return;
    };
    if cache_age(&path) != CacheAge::Stale {
        return;
    }
    if !may_read_keychain() {
        return;
    }

    debug!("Completion cache is stale, attempting refresh...");
    refresh();
}

/// Opens the current vault using the keychain password and writes the cache.
/// Does nothing if the vault is locked (no password in keychain), or if the
/// vault is protected by a hardware key: opening it needs a physical touch
/// nobody is around to provide in this silent background path.
fn create_cache_from_keychain() {
    let Ok(config) = vault_registry::current() else {
        return;
    };
    if config.hwkey.is_some() {
        debug!("Hardware key enrolled, skipping silent cache refresh");
        return;
    }

    let master_pwd = match keychain::get_master_password(&config.name) {
        Ok(pwd) => pwd,
        Err(_) => {
            debug!("Vault is locked, skipping cache creation");
            return;
        }
    };

    match KeepassVault::open(&master_pwd, &config.path, config.keyfile, None) {
        Ok(vault) => {
            let boxed: Box<dyn Vault> = Box::new(vault);
            update_cache(&boxed);
            debug!("Completion cache created/refreshed");
        }
        Err(e) => {
            debug!("Failed to open vault for cache: {}", e);
        }
    }
}

fn collect_entry_names(vault: &Box<dyn Vault>) -> Vec<String> {
    let mut pairs = BTreeSet::new();
    for cred in vault.grep(None) {
        let title = cred.title().to_string();
        let username = cred.username().to_string();
        if !title.is_empty() || !username.is_empty() {
            pairs.insert(format!("{}:{}", title, username));
        }
    }
    pairs.into_iter().collect()
}

fn write_cache(path: &Path, entries: &[String]) -> std::io::Result<()> {
    // Ensure parent directory exists; it may have been created by
    // create_dir_all with platform-default permissions, which is too loose
    // for the cache's service:username pairs.
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        crate::store::tighten_dir_permissions(parent);
    }
    // Owner-only: the cache leaks service:username pairs on shared machines.
    let mut file = crate::store::create_private_file(path)?;
    for entry in entries {
        writeln!(file, "{}", entry)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn test_cache_path_is_per_vault() {
        let path = cache_path("work");
        let path_str = path.to_string_lossy();
        assert!(path_str.contains(".passlane"));
        assert!(path_str.ends_with(".completion_cache.work"));
        assert_ne!(
            cache_path_in(Path::new("/a"), "work"),
            cache_path_in(Path::new("/b"), "work")
        );
        assert_ne!(
            cache_path_in(Path::new("/a"), "work"),
            cache_path_in(Path::new("/a"), "personal")
        );
    }

    #[test]
    fn test_write_and_read_cache_for_vault() {
        // Everything happens under a temp dir: the cache paths derived from
        // the real home directory must never be written to by a test.
        let entries = vec![
            "github".to_string(),
            "google".to_string(),
            "alice".to_string(),
        ];
        let dir = tempfile::tempdir().unwrap();
        let path = cache_path_in(dir.path(), "work");

        write_cache(&path, &entries).unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        let read: Vec<String> = contents
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| l.to_string())
            .collect();
        assert_eq!(read, entries);

        clear_cache_at(&path);
        assert!(!path.exists());
    }

    #[test]
    fn test_write_cache_creates_parent_dir() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join(".completion_cache.work");
        write_cache(&path, &["github:alice".to_string()]).unwrap();
        assert!(path.exists());
        clear_cache_at(&path);
        assert!(!path.exists());
    }

    #[test]
    fn test_clear_cache_for_missing_vault_no_error() {
        // Should not panic even if file doesn't exist
        clear_cache_for("test-clear-missing");
    }

    #[test]
    fn test_collect_entry_pairs_deduplicates() {
        // This test verifies the BTreeSet deduplication logic for service:username pairs
        let mut pairs = std::collections::BTreeSet::new();
        pairs.insert("github:alice".to_string());
        pairs.insert("github:alice".to_string()); // duplicate
        pairs.insert("github:bob".to_string());
        let result: Vec<String> = pairs.into_iter().collect();
        assert_eq!(
            result,
            vec!["github:alice".to_string(), "github:bob".to_string()]
        );
    }

    /// The cache file of vault `name` under `dir`, its modification time
    /// set `age` back.
    fn cache_aged(dir: &Path, name: &str, age: Duration) -> PathBuf {
        let path = cache_path_in(dir, name);
        fs::write(&path, "github:alice\n").unwrap();
        let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_modified(SystemTime::now() - age).unwrap();
        path
    }

    #[test]
    fn an_agent_that_cannot_be_used_blocks_the_optional_refresh_too() {
        // The refresh must not step in front of the error the command is
        // about to report for the agent.
        assert!(refresh_may_read_keychain(Ok(SessionFactors::None)));
        assert!(!refresh_may_read_keychain(Ok(SessionFactors::PasswordOnly)));
        assert!(!refresh_may_read_keychain(Ok(
            SessionFactors::WithKeyFactor
        )));
        assert!(!refresh_may_read_keychain(Err(Error::new(
            "no passlane-agent is listening"
        ))));
    }

    #[test]
    fn a_silent_cache_refresh_never_reads_a_keychain_nobody_can_answer() {
        // The refresh reads the keychain, which can block on a permission
        // dialog nobody is there to answer — or that a live session makes
        // unnecessary in the first place.
        let dir = tempfile::tempdir().unwrap();
        let stale = cache_aged(dir.path(), "stale", Duration::from_secs(8 * 24 * 60 * 60));
        let refreshed = Cell::new(0);
        let refresh = || refreshed.set(1);
        // The agent is not even asked without a terminal.
        refresh_if_stale_with(
            false,
            Some(stale.clone()),
            &|| panic!("no reason to ask the agent without a terminal"),
            &refresh,
        );
        // Nor for a cache that does not need refreshing.
        let week = Duration::from_secs(7 * 24 * 60 * 60);
        let fresh = cache_aged(dir.path(), "fresh", week - Duration::from_secs(60));
        refresh_if_stale_with(
            true,
            Some(fresh),
            &|| panic!("no reason to ask the agent for a fresh cache"),
            &refresh,
        );
        // Asked at a terminal with a stale cache. A session serving the
        // vault, or an agent whose state is unknown, means no keychain
        // read; only a known absence of one allows it.
        refresh_if_stale_with(true, Some(stale.clone()), &|| false, &refresh);
        assert_eq!(
            refreshed.get(),
            0,
            "no keychain read while a session may serve the vault, or the agent is unusable"
        );
        let asked = Cell::new(0);
        refresh_if_stale_with(
            true,
            Some(stale),
            &|| {
                asked.set(asked.get() + 1);
                true
            },
            &refresh,
        );
        assert_eq!(asked.get(), 1, "asked exactly when it matters");
        assert_eq!(refreshed.get(), 1);
    }

    #[test]
    fn an_open_vault_brings_a_missing_or_stale_cache_up_to_date() {
        let dir = tempfile::tempdir().unwrap();
        let week = Duration::from_secs(7 * 24 * 60 * 60);
        let written = Cell::new(0);
        let write = || written.set(written.get() + 1);

        let missing = cache_path_in(dir.path(), "work");
        ensure_cache_at(&missing, &write);
        assert_eq!(written.get(), 1, "a missing cache is written");

        let stale = cache_aged(dir.path(), "stale", week + Duration::from_secs(60));
        ensure_cache_at(&stale, &write);
        assert_eq!(written.get(), 2, "a stale cache is rewritten");

        let fresh = cache_aged(dir.path(), "fresh", week - Duration::from_secs(60));
        ensure_cache_at(&fresh, &write);
        assert_eq!(written.get(), 2, "a fresh cache is left alone");
    }

    #[test]
    fn cache_age_tells_a_missing_stale_and_fresh_cache_apart() {
        let dir = tempfile::tempdir().unwrap();
        let week = Duration::from_secs(7 * 24 * 60 * 60);
        assert_eq!(
            cache_age(&cache_path_in(dir.path(), "none")),
            CacheAge::Missing
        );
        assert_eq!(
            cache_age(&cache_aged(
                dir.path(),
                "stale",
                week + Duration::from_secs(60)
            )),
            CacheAge::Stale
        );
        assert_eq!(
            cache_age(&cache_aged(
                dir.path(),
                "fresh",
                week - Duration::from_secs(60)
            )),
            CacheAge::Fresh
        );
    }

    #[test]
    fn a_stale_cache_is_refreshed_at_a_terminal() {
        let dir = tempfile::tempdir().unwrap();
        let week = Duration::from_secs(7 * 24 * 60 * 60);
        let refreshed = Cell::new(0);
        let refresh = || refreshed.set(refreshed.get() + 1);
        let may_read = || true;

        let stale = cache_aged(dir.path(), "stale", week + Duration::from_secs(60));
        refresh_if_stale_with(true, Some(stale), &may_read, &refresh);
        assert_eq!(refreshed.get(), 1);

        let fresh = cache_aged(dir.path(), "fresh", week - Duration::from_secs(60));
        refresh_if_stale_with(true, Some(fresh), &may_read, &refresh);
        assert_eq!(refreshed.get(), 1, "a fresh cache is left alone");

        let missing = cache_path_in(dir.path(), "other");
        refresh_if_stale_with(true, Some(missing), &may_read, &refresh);
        refresh_if_stale_with(true, None, &may_read, &refresh);
        assert_eq!(refreshed.get(), 1, "nothing to refresh without a cache");
    }
}
