use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use log::debug;

use crate::keychain;
use crate::vault::keepass_vault::KeepassVault;
use crate::vault::vault_trait::Vault;
use crate::vault_registry;

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

/// Ensures the cache file exists using an already-open vault.
/// Only writes if the cache file is missing. Called from UnlockingAction::execute()
/// so any command that opens the vault also creates the cache.
pub fn ensure_cache_from_vault(vault: &Box<dyn Vault>) {
    let Some(path) = current_cache_path() else {
        return;
    };
    if path.exists() {
        return;
    }
    debug!("Completion cache missing, creating from open vault...");
    update_cache(vault);
}

/// Checks if the current vault's cache file is older than 7 days. If so, and
/// the vault is unlocked (master password in keychain), silently refreshes
/// the cache.
pub fn refresh_if_stale() {
    let Some(path) = current_cache_path() else {
        return;
    };
    if !path.exists() {
        return;
    }

    let stale = match fs::metadata(&path) {
        Ok(meta) => match meta.modified() {
            Ok(modified) => {
                SystemTime::now()
                    .duration_since(modified)
                    .unwrap_or(Duration::ZERO)
                    > Duration::from_secs(STALE_DAYS * 24 * 60 * 60)
            }
            Err(_) => false,
        },
        Err(_) => false,
    };

    if !stale {
        return;
    }

    debug!("Completion cache is stale, attempting refresh...");
    create_cache_from_keychain();
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
        },
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

    #[test]
    fn test_cache_path_is_per_vault() {
        let path = cache_path("work");
        let path_str = path.to_string_lossy();
        assert!(path_str.contains(".passlane"));
        assert!(path_str.ends_with(".completion_cache.work"));
        assert_ne!(cache_path_in(Path::new("/a"), "work"), cache_path_in(Path::new("/b"), "work"));
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
        assert_eq!(result, vec!["github:alice".to_string(), "github:bob".to_string()]);
    }
}
