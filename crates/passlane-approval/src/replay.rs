//! Replay protection: nonce stores.
//!
//! Every envelope carries a random 16-byte nonce in its header. A receiver
//! records `(sender_kid, nonce)` **only after** the envelope passed signature
//! and AEAD verification — an attacker cannot poison the store with
//! unverified envelopes. Entries are pruned once their expiry has passed,
//! bounding memory (and the file-backed store's growth).

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::Result;

/// Replay protection state shared by every `open` path.
pub trait NonceStore {
    /// Has this `(sender, nonce)` pair been seen before?
    fn seen(&self, sender_kid: &str, nonce: &str) -> bool;

    /// Record a pair as seen, with the message expiry for pruning.
    fn record(&mut self, sender_kid: &str, nonce: &str, expires_at: u64);

    /// Drop entries whose expiry has passed `now`.
    fn prune(&mut self, now: u64);
}

/// In-memory store (tests, short-lived processes, the future session agent).
#[derive(Default)]
pub struct InMemoryNonceStore {
    entries: BTreeMap<(String, String), u64>,
}

impl NonceStore for InMemoryNonceStore {
    fn seen(&self, sender_kid: &str, nonce: &str) -> bool {
        self.entries
            .contains_key(&(sender_kid.to_string(), nonce.to_string()))
    }

    fn record(&mut self, sender_kid: &str, nonce: &str, expires_at: u64) {
        self.entries
            .insert((sender_kid.to_string(), nonce.to_string()), expires_at);
    }

    fn prune(&mut self, now: u64) {
        self.entries.retain(|_, exp| *exp > now);
    }
}

/// JSON-file-backed store for CLI processes that come and go
/// (`~/.passlane/.approval_nonces` in the CLI integration).
pub struct FileNonceStore {
    path: PathBuf,
    entries: BTreeMap<String, u64>,
    dirty: bool,
}

impl FileNonceStore {
    /// Load (or start) the store at `path`.
    pub fn load(path: &Path) -> Result<Self> {
        let entries = if path.exists() {
            let bytes = std::fs::read(path)?;
            serde_json::from_slice(&bytes)?
        } else {
            BTreeMap::new()
        };
        Ok(Self {
            path: path.to_path_buf(),
            entries,
            dirty: false,
        })
    }

    /// Persist to disk with owner-only permissions.
    pub fn save(&self) -> Result<()> {
        if !self.dirty {
            return Ok(());
        }
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec(&self.entries)?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&self.path)?;
        file.write_all(&bytes)?;
        Ok(())
    }

    /// The backing file path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl NonceStore for FileNonceStore {
    fn seen(&self, sender_kid: &str, nonce: &str) -> bool {
        self.entries.contains_key(&format!("{sender_kid}:{nonce}"))
    }

    fn record(&mut self, sender_kid: &str, nonce: &str, expires_at: u64) {
        self.entries
            .insert(format!("{sender_kid}:{nonce}"), expires_at);
        self.dirty = true;
    }

    fn prune(&mut self, now: u64) {
        let before = self.entries.len();
        self.entries.retain(|_, exp| *exp > now);
        if self.entries.len() != before {
            self.dirty = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_replay_and_prune() {
        let mut store = InMemoryNonceStore::default();
        assert!(!store.seen("kid", "n1"));
        store.record("kid", "n1", 100);
        assert!(store.seen("kid", "n1"));
        assert!(!store.seen("kid", "n2"));
        assert!(!store.seen("other", "n1"));
        store.prune(100);
        assert!(!store.seen("kid", "n1"), "expired entries must be pruned");
    }

    #[test]
    fn file_store_roundtrip_and_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonces.json");
        {
            let mut store = FileNonceStore::load(&path).unwrap();
            assert!(!store.seen("kid", "n1"));
            store.record("kid", "n1", 500);
            store.save().unwrap();
        }
        {
            let store = FileNonceStore::load(&path).unwrap();
            assert!(store.seen("kid", "n1"), "nonce survives process restart");
            assert!(!store.seen("kid", "n2"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "nonce file must be owner-only");
        }
    }

    #[test]
    fn file_store_prune_persists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonces.json");
        {
            let mut store = FileNonceStore::load(&path).unwrap();
            store.record("kid", "old", 100);
            store.record("kid", "new", 900);
            store.prune(200);
            store.save().unwrap();
        }
        let store = FileNonceStore::load(&path).unwrap();
        assert!(!store.seen("kid", "old"));
        assert!(store.seen("kid", "new"));
    }
}
