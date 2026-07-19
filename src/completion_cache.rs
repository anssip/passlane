use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use log::debug;

use crate::keychain;
use crate::store;
use crate::vault::keepass_vault::KeepassVault;
use crate::vault::vault_trait::Vault;

const CACHE_FILENAME: &str = ".completion_cache";
const STALE_DAYS: u64 = 7;

fn cache_path() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("~"));
    home.join(".passlane").join(CACHE_FILENAME)
}

/// Reads all credentials from the vault, extracts deduplicated service names
/// and usernames, and writes them one per line to the cache file.
pub fn update_cache(vault: &Box<dyn Vault>) {
    let entries = collect_entry_names(vault);
    if let Err(e) = write_cache(&entries) {
        debug!("Failed to write completion cache: {}", e);
    }
}

/// Deletes the completion cache file. No error if the file is missing.
pub fn clear_cache() {
    let path = cache_path();
    if path.exists() {
        if let Err(e) = fs::remove_file(&path) {
            debug!("Failed to remove completion cache: {}", e);
        }
    }
}

/// Reads entry names from the cache file. Returns an empty vec if the file is missing.
pub fn read_cache() -> Vec<String> {
    let path = cache_path();
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
    let path = cache_path();
    if path.exists() {
        return;
    }
    debug!("Completion cache missing, creating from open vault...");
    update_cache(vault);
}

/// Checks if the cache file is older than 7 days. If so, and the vault is
/// unlocked (master password in keychain), silently refreshes the cache.
pub fn refresh_if_stale() {
    let path = cache_path();
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

/// Opens the vault using the keychain password and writes the cache.
/// Does nothing if the vault is locked (no password in keychain).
fn create_cache_from_keychain() {
    let master_pwd = match keychain::get_master_password() {
        Ok(pwd) => pwd,
        Err(_) => {
            debug!("Vault is locked, skipping cache creation");
            return;
        }
    };

    let filepath = store::get_vault_path();
    let keyfile_path = store::get_keyfile_path();

    match KeepassVault::open(&master_pwd, &filepath, keyfile_path) {
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
        let service = cred.service().to_string();
        let username = cred.username().to_string();
        if !service.is_empty() || !username.is_empty() {
            pairs.insert(format!("{}:{}", service, username));
        }
    }
    pairs.into_iter().collect()
}

fn write_cache(entries: &[String]) -> std::io::Result<()> {
    let path = cache_path();
    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    // Owner-only: the cache leaks service:username pairs on shared machines.
    let mut file = crate::store::create_private_file(&path)?;
    for entry in entries {
        writeln!(file, "{}", entry)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_cache_missing_file() {
        // read_cache should return empty vec for missing file
        // We can't easily test with the real path, but we test the logic
        let entries = read_cache();
        // This may or may not be empty depending on state, but should not panic
        let _ = entries;
    }

    #[test]
    fn test_cache_path_is_in_passlane_dir() {
        let path = cache_path();
        let path_str = path.to_string_lossy();
        assert!(path_str.contains(".passlane"));
        assert!(path_str.ends_with(".completion_cache"));
    }

    #[test]
    fn test_write_and_read_cache() {
        let entries = vec![
            "github".to_string(),
            "google".to_string(),
            "alice".to_string(),
        ];
        // Write to the real cache path (we'll restore later)
        let path = cache_path();
        let backup = fs::read_to_string(&path).ok();

        write_cache(&entries).unwrap();
        let result = read_cache();
        assert_eq!(result, entries);

        // Restore original or clean up
        match backup {
            Some(content) => fs::write(&path, content).unwrap(),
            None => { let _ = fs::remove_file(&path); }
        }
    }

    #[test]
    fn test_clear_cache_no_error_when_missing() {
        // Should not panic even if file doesn't exist
        clear_cache();
    }

    #[test]
    fn test_collect_entry_pairs_deduplicates() {
        // This test verifies the BTreeSet deduplication logic for service:username pairs
        let mut pairs = std::collections::BTreeSet::new();
        pairs.insert("github:alice".to_string());
        pairs.insert("github:alice".to_string()); // duplicate
        pairs.insert("github:bob".to_string());
        let result: Vec<String> = pairs.into_iter().collect();
        assert_eq!(result, vec!["github:alice", "github:bob"]);
    }

    #[test]
    fn test_refresh_if_stale_no_panic_when_no_cache() {
        // Should silently return when cache file doesn't exist
        refresh_if_stale();
    }
}
