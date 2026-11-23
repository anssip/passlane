use keyring::Entry;
use log::debug;
use passlane_core::vault::entities::Error;
use std::sync::mpsc;
use std::time::Duration;
use zeroize::Zeroizing;

/// One master-password entry per vault: the vault name is the keychain
/// account name under a single service.
const SERVICE_NAME: &str = "passlane_master_pwd";
/// The pre-multi-vault entry used a fixed "passlane" account name.
const LEGACY_USERNAME: &str = "passlane";

/// `Error` lives in passlane-core, so the orphan rule forbids a `From`
/// impl here; keychain call sites convert explicitly instead.
fn keyring_error(e: keyring::Error) -> Error {
    Error {
        message: e.to_string(),
    }
}

fn entry(vault: &str) -> Result<Entry, Error> {
    Entry::new(SERVICE_NAME, vault).map_err(keyring_error)
}

pub fn save_master_password(vault: &str, pwd: &str) -> Result<(), Error> {
    entry(vault)?.set_password(pwd).map_err(keyring_error)
}

/// The outcome of looking up a vault's stored master password.
pub enum PasswordLookup {
    /// The stored password.
    Found(Zeroizing<String>),
    /// Nothing is stored for the vault.
    Absent,
    /// The keychain did not answer within the bound given to
    /// [`lookup_master_password`]: almost certainly a permission dialog
    /// waiting to be clicked.
    TimedOut,
    /// The keychain could not be read.
    Failed(Error),
}

/// Get a vault's stored master password from the keychain, waiting as
/// long as the keychain takes. An absent entry is an error, as it always
/// was for this function.
pub fn get_master_password(vault: &str) -> Result<String, Error> {
    match read_stored_password(vault) {
        PasswordLookup::Found(password) => Ok(password.to_string()),
        PasswordLookup::Absent => Err(keyring_error(keyring::Error::NoEntry)),
        PasswordLookup::Failed(error) => Err(error),
        PasswordLookup::TimedOut => unreachable!("an unbounded lookup does not time out"),
    }
}

/// Look up a vault's stored master password. With a `bound`, a keychain
/// that has not answered when it elapses is given up on and reported as
/// [`PasswordLookup::TimedOut`].
///
/// Reading the keychain is normally instant, but on macOS it blocks for
/// as long as a "wants to use your confidential information" dialog
/// stays unanswered — forever, when the command runs from a daemon or a
/// scheduled job and nobody is at the screen. Commands that may run
/// without a terminal therefore bound the wait; the lookup is left behind
/// on its own thread and dies with the process.
pub fn lookup_master_password(vault: &str, bound: Option<Duration>) -> PasswordLookup {
    let Some(bound) = bound else {
        return read_stored_password(vault);
    };
    let vault = vault.to_string();
    match answer_within(bound, move || read_stored_password(&vault)) {
        Some(lookup) => lookup,
        None => PasswordLookup::TimedOut,
    }
}

fn read_stored_password(vault: &str) -> PasswordLookup {
    debug!("Getting master password of vault '{}' from keychain", vault);
    let entry = match entry(vault) {
        Ok(entry) => entry,
        Err(error) => return PasswordLookup::Failed(error),
    };
    match entry.get_password() {
        Ok(password) => PasswordLookup::Found(Zeroizing::new(password)),
        Err(keyring::Error::NoEntry) => PasswordLookup::Absent,
        Err(e) => PasswordLookup::Failed(keyring_error(e)),
    }
}

/// Run `work` on its own thread and wait for its answer at most `bound`.
/// `None` when it has not answered by then (the thread is left to finish
/// or linger on its own).
fn answer_within<T: Send + 'static>(
    bound: Duration,
    work: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("passlane-keychain-lookup".into())
        .spawn(move || {
            let _ = tx.send(work());
        })
        .ok()?;
    rx.recv_timeout(bound).ok()
}

/// Whether a master password is stored for the vault. `Ok(false)` means
/// genuinely absent; keychain backend errors propagate so callers can tell
/// "locked" from "keychain unavailable".
pub fn has_master_password(vault: &str) -> Result<bool, Error> {
    match entry(vault)?.get_password() {
        Ok(_) => Ok(true),
        Err(keyring::Error::NoEntry) => Ok(false),
        Err(e) => Err(keyring_error(e)),
    }
}

/// Delete a vault's stored master password. `Ok(false)` when nothing was
/// stored; real errors propagate so callers can tell "already locked" from
/// "could not lock".
pub fn delete_master_password_if_stored(vault: &str) -> Result<bool, Error> {
    match entry(vault)?.delete_credential() {
        Ok(()) => Ok(true),
        Err(keyring::Error::NoEntry) => Ok(false),
        Err(e) => Err(keyring_error(e)),
    }
}

/// Move a pre-multi-vault keychain entry (the fixed "passlane" account under
/// one of the old service names) to the given vault's entry. Ok(false) when
/// the old entry is absent — the machine was locked and the user just
/// re-enters the password at the next unlock. Any other keychain error
/// propagates: hiding it would let the migration silently skip moving a
/// stored password.
pub(crate) fn migrate_legacy_password(from_service: &str, to_vault: &str) -> Result<bool, Error> {
    let legacy = Entry::new(from_service, LEGACY_USERNAME).map_err(keyring_error)?;
    let password = match legacy.get_password() {
        Ok(pwd) => pwd,
        Err(keyring::Error::NoEntry) => return Ok(false),
        Err(e) => return Err(keyring_error(e)),
    };
    entry(to_vault)?
        .set_password(&password)
        .map_err(keyring_error)?;
    match legacy.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(true),
        Err(e) => Err(keyring_error(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn a_bounded_wait_returns_the_answer_when_it_comes_in_time() {
        assert_eq!(answer_within(Duration::from_secs(5), || 42), Some(42));
    }

    #[test]
    fn a_bounded_wait_gives_up_rather_than_block() {
        let started = Instant::now();
        // The worker never answers while we are waiting on it.
        let answer = answer_within(Duration::from_millis(100), || {
            std::thread::sleep(Duration::from_secs(3));
            "late"
        });
        assert_eq!(answer, None);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the wait must end at the bound, not with the worker"
        );
    }
}
