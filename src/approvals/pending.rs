//! Pending approval requests and the grants their responses release.
//!
//! When the ask flow emits a request envelope, its `rid` (the envelope
//! header's request id) is recorded here together with what is being
//! asked (vault, entry, field). `passlane approve --response` matches the
//! response envelope's `rid` against this store before doing anything
//! else — a response that answers no live request is refused — and a
//! verified `Allow` turns the record into a **grant** the ask flow
//! consumes to release the entry.
//!
//! File: `<approvals dir>/approval_pending.json`, owner-only. Records are
//! pruned once expired, so the store tracks only live traffic.

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
    /// Entry title or match string.
    pub entry: String,
    /// The field being revealed (`password`, `code`, ...).
    pub field: String,
    /// When the request was emitted, unix seconds.
    pub created: u64,
    /// Envelope expiry, unix seconds — the response must arrive before it.
    pub exp: u64,
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
}

/// The pending-request store.
pub struct PendingStore {
    path: PathBuf,
    records: Vec<PendingRequest>,
}

impl PendingStore {
    /// Load (or start) the store at `<dir>/approval_pending.json`.
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
        Ok(Self { path, records })
    }

    /// Persist owner-only.
    pub fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec(&self.records)?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        use std::io::Write;
        let mut file = options.open(&self.path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
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
    /// envelope expiry, and grants past their reuse window.
    pub fn prune(&mut self, now: u64) {
        self.records
            .retain(|r| r.exp > now && !matches!(r.state, RequestState::Granted { until, .. } if until <= now));
    }

    /// Consume a live grant for exactly this vault/entry/field and return
    /// its rid, or None.
    ///
    /// A `once` grant is spent by the consumption (its record moves to the
    /// terminal [`RequestState::Consumed`], so a re-pasted response gets a
    /// clear answer instead of "unknown request"); a timed grant stays
    /// reusable until its window closes. If several grants match, the
    /// newest wins.
    pub fn take_grant(&mut self, vault: &str, entry: &str, field: &str, now: u64) -> Option<String> {
        let candidate = self
            .records
            .iter()
            .filter(|r| {
                r.vault == vault && r.entry == entry && r.field == field && r.grant_live(now)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn record(rid: &str, entry: &str, state: RequestState) -> PendingRequest {
        PendingRequest {
            rid: rid.to_string(),
            vault: "default".into(),
            entry: entry.into(),
            field: "password".into(),
            created: 1000,
            exp: 1300,
            state,
        }
    }

    fn store(entries: Vec<PendingRequest>) -> PendingStore {
        PendingStore {
            path: PathBuf::from("/tmp/unused-approval-pending.json"),
            records: entries,
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
        assert_eq!(s.take_grant("default", "GitHub", "password", 1000), Some("a".into()));
        // Spent: the record is terminal (a re-pasted response can be
        // answered clearly), and the second reveal finds nothing.
        assert_eq!(s.find("a").unwrap().state, RequestState::Consumed);
        assert_eq!(s.take_grant("default", "GitHub", "password", 1001), None);
    }

    #[test]
    fn timed_grant_reusable_until_window() {
        let mut s = store(vec![record(
            "a",
            "GitHub",
            RequestState::Granted { once: false, until: 1500 },
        )]);
        assert_eq!(s.take_grant("default", "GitHub", "password", 1000), Some("a".into()));
        assert_eq!(s.take_grant("default", "GitHub", "password", 1400), Some("a".into()));
        assert_eq!(s.take_grant("default", "GitHub", "password", 1500), None);
    }

    #[test]
    fn grant_only_matches_the_exact_reveal() {
        let mut s = store(vec![record(
            "a",
            "GitHub",
            RequestState::Granted { once: true, until: 1500 },
        )]);
        assert_eq!(s.take_grant("default", "GitLab", "password", 1000), None);
        assert_eq!(s.take_grant("default", "GitHub", "code", 1000), None);
        assert_eq!(s.take_grant("other", "GitHub", "password", 1000), None);
    }

    #[test]
    fn pending_and_denied_never_release() {
        let mut s = store(vec![
            record("p", "GitHub", RequestState::Pending),
            record("d", "GitHub", RequestState::Denied),
        ]);
        assert_eq!(s.take_grant("default", "GitHub", "password", 1000), None);
    }

    #[test]
    fn newest_matching_grant_wins() {
        let mut older = record("old", "GitHub", RequestState::Granted { once: false, until: 1500 });
        older.created = 900;
        let mut newer = record("new", "GitHub", RequestState::Granted { once: false, until: 1600 });
        newer.created = 1100;
        let mut s = store(vec![older, newer]);
        assert_eq!(s.take_grant("default", "GitHub", "password", 1000), Some("new".into()));
    }

    #[test]
    fn prune_drops_dead_records() {
        let mut s = store(vec![
            record("expired", "a", RequestState::Pending),
            record("dead-grant", "b", RequestState::Granted { once: false, until: 900 }),
        ]);
        let mut expired = s.find("expired").unwrap().clone();
        expired.exp = 900; // past the pruning clock
        s.upsert(expired);
        let mut live = record("live", "c", RequestState::Pending);
        live.exp = 2000;
        s.upsert(live);
        s.prune(1000);
        let rids: Vec<&str> = s.records().iter().map(|r| r.rid.as_str()).collect();
        assert_eq!(rids, vec!["live"]);
    }

    #[test]
    fn file_roundtrip_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = PendingStore::load(dir.path()).unwrap();
        assert!(s.records().is_empty());
        s.upsert(record("a", "GitHub", RequestState::Pending));
        s.save().unwrap();

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
}
