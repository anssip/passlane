//! Replay protection: nonce stores.
//!
//! Every envelope carries a random 16-byte nonce in its header. A receiver
//! records `(sender_kid, nonce)` **only after** the envelope passed signature
//! and AEAD verification — an attacker cannot poison the store with
//! unverified envelopes. Entries are pruned once their expiry has passed,
//! bounding memory (and the file-backed store's growth).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::error::Result;

/// The stable lock file path for a data file (`nonces.json` →
/// `nonces.json.lock`).
fn lock_path_for(path: &Path) -> std::path::PathBuf {
    let mut name = path.file_name().map_or_else(
        || "nonces.json".to_string(),
        |n| n.to_string_lossy().to_string(),
    );
    name.push_str(".lock");
    path.with_file_name(name)
}

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
///
/// **Process safety**: the store holds an exclusive advisory lock on the
/// file for its entire lifetime, so two processes can never both observe
/// the same nonce state — the second `load` blocks until the first store
/// is dropped. `save` writes to a sibling temp file and renames it over
/// the target, so a crash mid-write can never truncate the store.
pub struct FileNonceStore {
    path: PathBuf,
    entries: BTreeMap<String, u64>,
    dirty: bool,
    /// Kept alive: dropping it releases the exclusive lock.
    _lock: std::fs::File,
}

impl FileNonceStore {
    /// Load (or start) the store at `path`, taking the exclusive lock.
    ///
    /// Blocks while another process holds the store. The lock lives on a
    /// **separate, stable lock file** (`<path>.lock`), never on the data
    /// file itself — `save` replaces the data file by rename, which would
    /// strand a lock taken on the data file's original inode.
    pub fn load(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let lock_path = lock_path_for(path);
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .read(true)
            .open(&lock_path)?;
        {
            // Fully qualified: newer std (1.89+) has an inherent File::lock;
            // the fs4 call keeps our MSRV at 1.88.
            fs4::FileExt::lock(&lock)?;
        }
        let entries = if path.exists() {
            match std::fs::read(path) {
                Ok(bytes) if bytes.is_empty() => BTreeMap::new(),
                Ok(bytes) => serde_json::from_slice(&bytes)?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
                Err(e) => return Err(e.into()),
            }
        } else {
            BTreeMap::new()
        };
        Ok(Self {
            path: path.to_path_buf(),
            entries,
            dirty: false,
            _lock: lock,
        })
    }

    /// Persist to disk atomically (temp file + rename) with owner-only
    /// permissions. The lock is held on the **lock file**, not the data
    /// file, so replacing the data file by rename cannot orphan it.
    pub fn save(&self) -> Result<()> {
        if !self.dirty {
            return Ok(());
        }
        let bytes = serde_json::to_vec(&self.entries)?;
        let tmp = self.path.with_extension("json.tmp");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        {
            use std::io::Write;
            let mut file = options.open(&tmp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)?;
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
    fn file_store_lock_is_exclusive() {
        // While one process (this test) holds the store, a second load in
        // the same process must block — verified via the underlying lock
        // API rather than deadlocking ourselves. The lock sits on the
        // sidecar lock file, so this must hold across save() renames too.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonces.json");
        let mut store = FileNonceStore::load(&path).unwrap();
        store.record("kid", "n1", 900);
        store.save().unwrap(); // replaces the data file by rename
        let lock_file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .read(true)
            .open(lock_path_for(&path))
            .unwrap();
        assert!(
            fs4::FileExt::try_lock(&lock_file).is_err(),
            "a second exclusive lock must not be granted while the store lives, even after save()"
        );
        // And the recorded nonce survived the rename.
        assert!(store.seen("kid", "n1"));
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
