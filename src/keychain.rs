use keyring::Entry;
use log::debug;
use passlane_core::vault::entities::Error;

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

pub fn get_master_password(vault: &str) -> Result<String, Error> {
    debug!("Getting master password of vault '{}' from keychain", vault);
    entry(vault)?.get_password().map_err(keyring_error)
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
