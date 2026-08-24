use crate::vault::entities::Error;
use keyring::Entry;
use log::debug;

/// One master-password entry per vault: the vault name is the keychain
/// account name under a single service.
const SERVICE_NAME: &str = "passlane_master_pwd";
/// The pre-multi-vault entry used a fixed "passlane" account name.
const LEGACY_USERNAME: &str = "passlane";

impl From<keyring::Error> for Error {
    fn from(e: keyring::Error) -> Self {
        Error {
            message: e.to_string(),
        }
    }
}

fn entry(vault: &str) -> Result<Entry, Error> {
    Ok(Entry::new(SERVICE_NAME, vault)?)
}

pub fn save_master_password(vault: &str, pwd: &str) -> Result<(), Error> {
    entry(vault)?.set_password(pwd)?;
    Ok(())
}

pub fn get_master_password(vault: &str) -> Result<String, Error> {
    debug!("Getting master password of vault '{}' from keychain", vault);
    Ok(entry(vault)?.get_password()?)
}

pub fn delete_master_password(vault: &str) -> Result<(), Error> {
    Ok(entry(vault)?.delete_credential()?)
}

/// Move a pre-multi-vault keychain entry (the fixed "passlane" account under
/// one of the old service names) to the given vault's entry. Ok(false) when
/// the old entry is absent — the machine was locked and the user just
/// re-enters the password at the next unlock.
pub(crate) fn migrate_legacy_password(from_service: &str, to_vault: &str) -> Result<bool, Error> {
    let legacy = Entry::new(from_service, LEGACY_USERNAME)?;
    let password = match legacy.get_password() {
        Ok(pwd) => pwd,
        Err(_) => return Ok(false),
    };
    entry(to_vault)?.set_password(&password)?;
    match legacy.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(true),
        Err(e) => Err(e.into()),
    }
}
