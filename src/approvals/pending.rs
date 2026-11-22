//! Pending approval requests and the grants their responses release.
//!
//! When the ask flow emits a request envelope, its `rid` (the envelope
//! header's request id) is recorded here together with what is being
//! asked (vault, entry — by **UUID**, so two identically-titled entries
//! can never consume each other's approval — and field).
//! `passlane approve --response` matches the response envelope's `rid`
//! against this store before doing anything else — a response that
//! answers no live request is refused — and a verified `Allow` turns the
//! record into a **grant** the ask flow consumes to release the entry.
//!
//! File: `<approvals dir>/approval_pending.json`, owner-only, replaced
//! atomically (temp file + rename). All mutations go through
//! [`PendingStore::transaction`], which holds an exclusive lock on a
//! stable sidecar file from *before* loading until *after* saving — two
//! concurrent reveals can never both observe the same once-grant, and
//! concurrent emission/approval can never overwrite a consumed record
//! with stale state. Records are pruned (and the pruning persisted) on
//! every transaction, so the store tracks only live traffic.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use passlane_approval::error::Result;

/// The store's file name inside the approvals state directory.
const PENDING_FILENAME: &str = "approval_pending.json";

/// One recorded approval request and where it stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRequest {
    /// The envelope header's request id (32 hex). The key the response
    /// must echo (SPEC §4).
    pub rid: String,
    /// Vault the reveal targets (registry name).
    pub vault: String,
    /// The entry's stable UUID — grants are matched on this, never on the
    /// display title (two entries can share a title).
    pub entry_id: String,
    /// Entry title or match string, for display only.
    pub entry: String,
    /// The field being revealed (`password`, `code`, ...).
    pub field: String,
    /// When the request was emitted, unix seconds.
    pub created: u64,
    /// Envelope expiry, unix seconds — the response must arrive before it.
    pub exp: u64,
    /// The reuse window the request asked for (SPEC §4): `None` means
    /// `Scope::Once` — a response may not grant anything wider than this.
    #[serde(default)]
    pub requested_timed: Option<u32>,
    /// Where the request stands.
    pub state: RequestState,
}

/// The lifecycle of a recorded request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RequestState {
    /// Emitted, waiting for the approver.
    Pending,
    /// A verified `Allow` released the entry. `once` grants a single
    /// reveal; otherwise reusable until `until`.
    Granted { once: bool, until: u64 },
    /// A once-grant was consumed by the reveal it released.
    Consumed,
    /// A verified `Deny` (or the owner) refused it.
    Denied,
}

impl PendingRequest {
    /// Is a granted request still usable at `now`?
    fn grant_live(&self, now: u64) -> bool {
        matches!(self.state, RequestState::Granted { until, .. } if until > now)
    }

    /// Is this record still worth keeping at `now`? A record lives until
    /// its envelope expiry; a granted record lives as long as its reuse
    /// window — which for `Scope::Timed` approvals can outlive `exp`.
    fn live_at(&self, now: u64) -> bool {
        self.exp > now || self.grant_live(now)
    }
}

/// The pending-request store.
pub struct PendingStore {
    path: PathBuf,
    records: Vec<PendingRequest>,
    /// Kept alive: dropping it releases the exclusive sidecar lock.
    _lock: Option<std::fs::File>,
}

impl PendingStore {
    /// Run a mutation under the store's exclusive lock: the lock is taken
    /// on a stable sidecar file (`approval_pending.json.lock`) *before*
    /// the store is loaded and released only after the (atomic) save, so
    /// concurrent processes serialize on the same view. The store is
    /// pruned and persisted even when `f` changes nothing.
    pub fn transaction<R>(dir: &Path, f: impl FnOnce(&mut Self) -> R) -> Result<R> {
        let mut store = Self::load_locked(dir)?;
        let out = f(&mut store);
        store.prune(seconds_now());
        store.save()?;
        Ok(out)
    }

    /// Load (or start) the store at `<dir>/approval_pending.json`, taking
    /// the exclusive lock. Blocks while another process holds the store.
    fn load_locked(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join(PENDING_FILENAME);
        let lock_path = dir.join(format!("{PENDING_FILENAME}.lock"));
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .read(true)
            .open(&lock_path)?;
        fs4::FileExt::lock(&lock)?;

        let records = if path.exists() {
            match std::fs::read(&path) {
                Ok(bytes) if bytes.is_empty() => Vec::new(),
                Ok(bytes) => serde_json::from_slice(&bytes)?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
                Err(e) => return Err(e.into()),
            }
        } else {
            Vec::new()
        };
        Ok(Self {
            path,
            records,
            _lock: Some(lock),
        })
    }

    /// Load without locking (tests, read-only display where showing a
    /// stale snapshot is acceptable — everything mutation-shaped goes
    /// through [`Self::transaction`]).
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn load(dir: &Path) -> Result<Self> {
        let path = dir.join(PENDING_FILENAME);
        let records = if path.exists() {
            match std::fs::read(&path) {
                Ok(bytes) if bytes.is_empty() => Vec::new(),
                Ok(bytes) => serde_json::from_slice(&bytes)?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
                Err(e) => return Err(e.into()),
            }
        } else {
            Vec::new()
        };
        Ok(Self {
            path,
            records,
            _lock: None,
        })
    }

    /// Persist owner-only, atomically: write a complete temp file, then
    /// rename it over the target, so no reader can observe a partial
    /// store and a crash mid-write cannot truncate it.
    pub fn save(&self) -> Result<()> {
        let bytes = serde_json::to_vec(&self.records)?;
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

    /// All records (oldest first).
    pub fn records(&self) -> &[PendingRequest] {
        &self.records
    }

    /// Insert or replace by `rid`.
    pub fn upsert(&mut self, record: PendingRequest) {
        match self.records.iter().position(|r| r.rid == record.rid) {
            Some(i) => self.records[i] = record,
            None => self.records.push(record),
        }
    }

    /// The record for `rid`, if any.
    pub fn find(&self, rid: &str) -> Option<&PendingRequest> {
        self.records.iter().find(|r| r.rid == rid)
    }

    /// Mark a request granted. Returns false if the rid is unknown.
    pub fn grant(&mut self, rid: &str, once: bool, until: u64) -> bool {
        let Some(record) = self.records.iter_mut().find(|r| r.rid == rid) else {
            return false;
        };
        record.state = RequestState::Granted { once, until };
        true
    }

    /// Mark a request denied. Returns false if the rid is unknown.
    pub fn deny(&mut self, rid: &str) -> bool {
        let Some(record) = self.records.iter_mut().find(|r| r.rid == rid) else {
            return false;
        };
        record.state = RequestState::Denied;
        true
    }

    /// Drop records that can no longer matter at `now`: past their
    /// envelope expiry and (for grants) past their reuse window.
    pub fn prune(&mut self, now: u64) {
        self.records.retain(|r| r.live_at(now));
    }

    /// Consume a live grant for exactly this vault/entry-uuid/field and
    /// return its rid, or None.
    ///
    /// A `once` grant is spent by the consumption (its record moves to the
    /// terminal [`RequestState::Consumed`], so a re-pasted response gets a
    /// clear answer instead of "unknown request"); a timed grant stays
    /// reusable until its window closes. If several grants match, the
    /// newest wins.
    pub fn take_grant(
        &mut self,
        vault: &str,
        entry_id: &str,
        field: &str,
        now: u64,
    ) -> Option<String> {
        let candidate = self
            .records
            .iter()
            .filter(|r| {
                r.vault == vault && r.entry_id == entry_id && r.field == field && r.grant_live(now)
            })
            .max_by_key(|r| r.created)?;
        let rid = candidate.rid.clone();
        let once = matches!(candidate.state, RequestState::Granted { once: true, .. });
        if once
            && let Some(record) = self.records.iter_mut().find(|r| r.rid == rid)
        {
            record.state = RequestState::Consumed;
        }
        Some(rid)
    }
}

fn seconds_now() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(rid: &str, entry: &str, state: RequestState) -> PendingRequest {
        PendingRequest {
            rid: rid.to_string(),
            vault: "default".into(),
            entry_id: format!("uuid-{entry}"),
            entry: entry.to_string(),
            field: "password".into(),
            created: 1000,
            exp: 1300,
            requested_timed: None,
            state,
        }
    }

    fn store(entries: Vec<PendingRequest>) -> PendingStore {
        PendingStore {
            path: PathBuf::from("/tmp/unused-approval-pending.json"),
            records: entries,
            _lock: None,
        }
    }

    #[test]
    fn upsert_find_and_states() {
        let mut s = store(vec![record("a", "GitHub", RequestState::Pending)]);
        assert!(s.find("a").is_some());
        assert!(s.find("b").is_none());
        assert!(s.grant("a", true, 1200));
        assert!(!s.grant("missing", true, 1200));
        assert_eq!(
            s.find("a").unwrap().state,
            RequestState::Granted { once: true, until: 1200 }
        );
        assert!(s.deny("a"));
        assert_eq!(s.find("a").unwrap().state, RequestState::Denied);
    }

    #[test]
    fn once_grant_consumes_on_first_reveal() {
        let mut s = store(vec![record(
            "a",
            "GitHub",
            RequestState::Granted { once: true, until: 1500 },
        )]);
        assert_eq!(
            s.take_grant("default", "uuid-GitHub", "password", 1000),
            Some("a".into())
        );
        // Spent: the record is terminal (a re-pasted response can be
        // answered clearly), and the second reveal finds nothing.
        assert_eq!(s.find("a").unwrap().state, RequestState::Consumed);
        assert_eq!(s.take_grant("default", "uuid-GitHub", "password", 1001), None);
    }

    #[test]
    fn timed_grant_reusable_until_window() {
        let mut s = store(vec![record(
            "a",
            "GitHub",
            RequestState::Granted { once: false, until: 1500 },
        )]);
        assert_eq!(
            s.take_grant("default", "uuid-GitHub", "password", 1000),
            Some("a".into())
        );
        assert_eq!(
            s.take_grant("default", "uuid-GitHub", "password", 1400),
            Some("a".into())
        );
        assert_eq!(s.take_grant("default", "uuid-GitHub", "password", 1500), None);
    }

    #[test]
    fn grant_matches_the_entry_uuid_not_the_title() {
        // Two entries share the display title 'GitHub'; a grant for one
        // must not release the other.
        let mut granted = record("a", "GitHub", RequestState::Granted { once: true, until: 1500 });
        granted.entry_id = "uuid-alice".into();
        let mut other = record("b", "GitHub", RequestState::Pending);
        other.entry_id = "uuid-bob".into();
        other.created = 1100;
        let mut s = store(vec![granted, other]);

        assert_eq!(s.take_grant("default", "uuid-alice", "password", 1000), Some("a".into()));
        assert_eq!(s.take_grant("default", "uuid-bob", "password", 1000), None);
        // Titles are display-only: a wrong uuid with the right title fails.
        assert_eq!(s.take_grant("default", "uuid-carol", "password", 1000), None);
    }

    #[test]
    fn grant_only_matches_the_exact_reveal() {
        let mut s = store(vec![record(
            "a",
            "GitHub",
            RequestState::Granted { once: true, until: 1500 },
        )]);
        assert_eq!(s.take_grant("default", "uuid-GitLab", "password", 1000), None);
        assert_eq!(s.take_grant("default", "uuid-GitHub", "code", 1000), None);
        assert_eq!(s.take_grant("other", "uuid-GitHub", "password", 1000), None);
    }

    #[test]
    fn pending_and_denied_never_release() {
        let mut s = store(vec![
            record("p", "GitHub", RequestState::Pending),
            record("d", "GitHub", RequestState::Denied),
        ]);
        assert_eq!(s.take_grant("default", "uuid-GitHub", "password", 1000), None);
    }

    #[test]
    fn newest_matching_grant_wins() {
        let mut older = record("old", "GitHub", RequestState::Granted { once: false, until: 1500 });
        older.created = 900;
        let mut newer = record("new", "GitHub", RequestState::Granted { once: false, until: 1600 });
        newer.created = 1100;
        let mut s = store(vec![older, newer]);
        assert_eq!(
            s.take_grant("default", "uuid-GitHub", "password", 1000),
            Some("new".into())
        );
    }

    #[test]
    fn prune_drops_dead_records_but_keeps_live_timed_grants() {
        let mut expired = record("expired", "a", RequestState::Pending);
        expired.exp = 900;
        let mut dead_grant =
            record("dead-grant", "b", RequestState::Granted { once: false, until: 900 });
        dead_grant.exp = 900;
        let mut s = store(vec![expired, dead_grant]);
        let mut live = record("live", "c", RequestState::Pending);
        live.exp = 2000;
        s.upsert(live);
        // A timed grant whose reuse window outlives the envelope expiry
        // must survive pruning until the window closes.
        let mut survivor = record("timed", "d", RequestState::Granted { once: false, until: 2200 });
        survivor.exp = 900;
        s.upsert(survivor);

        s.prune(1000);
        let rids: Vec<&str> = s.records().iter().map(|r| r.rid.as_str()).collect();
        assert_eq!(rids, vec!["live", "timed"]);

        s.prune(2300);
        assert!(s.records().is_empty());
    }

    #[test]
    fn file_roundtrip_owner_only_and_atomic_save() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = PendingStore::load(dir.path()).unwrap();
        assert!(s.records().is_empty());
        s.upsert(record("a", "GitHub", RequestState::Pending));
        s.save().unwrap();
        // No temp file left behind by the atomic replace.
        assert!(!dir.path().join("approval_pending.json.tmp").exists());

        let loaded = PendingStore::load(dir.path()).unwrap();
        assert_eq!(loaded.records(), s.records());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join(PENDING_FILENAME))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn transaction_serializes_concurrent_access_and_persists_pruning() {
        let dir = tempfile::tempdir().unwrap();
        let live_until = seconds_now() + 3600;
        // Seed through a transaction; exp is a real future timestamp so
        // the transaction's real-time pruning keeps it.
        PendingStore::transaction(dir.path(), |s| {
            let mut live = record("a", "GitHub", RequestState::Pending);
            live.exp = live_until;
            s.upsert(live);
        })
        .unwrap();

        // While one transaction holds the store, a second must wait, not
        // race: verified through the underlying lock (a second exclusive
        // lock on the sidecar is refused), mirroring the crate's own
        // nonce-store test.
        PendingStore::transaction(dir.path(), |s| {
            let lock_file = std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .read(true)
                .open(dir.path().join("approval_pending.json.lock"))
                .unwrap();
            assert!(
                fs4::FileExt::try_lock(&lock_file).is_err(),
                "the transaction must hold the exclusive lock for its whole body"
            );
            assert_eq!(s.records().len(), 1);
        })
        .unwrap();

        // An expired record is pruned and persisted by the transaction,
        // even when the body changes nothing.
        PendingStore::transaction(dir.path(), |s| {
            let mut expired = record("old", "x", RequestState::Pending);
            expired.exp = 1;
            s.upsert(expired);
        })
        .unwrap();
        PendingStore::transaction(dir.path(), |_s| ()).unwrap();
        let after = PendingStore::load(dir.path()).unwrap();
        assert_eq!(after.records().len(), 1, "only the live record survives");
        assert_eq!(after.records()[0].rid, "a");
    }
}
