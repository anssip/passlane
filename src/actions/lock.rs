use crate::actions::Action;
use crate::completion_cache;
use crate::keychain;
use crate::vault::entities::Error;
use crate::vault_registry;

pub struct LockAction {
    /// Lock every registered vault instead of just the current one.
    pub all: bool,
}

impl LockAction {
    pub fn new(all: bool) -> LockAction {
        LockAction { all }
    }
}

/// A vault is locked when its master password is gone from the keychain.
/// "No entry" is the normal already-locked case; any other error means the
/// stored password may still be there and must not be reported as locked.
/// Cache removal is best-effort: a leftover cache only leaks service names.
fn lock_vault(name: &str) -> String {
    match keychain::delete_master_password_if_stored(name) {
        Ok(true) => {
            completion_cache::clear_cache_for(name);
            format!("Vault '{}' locked", name)
        }
        Ok(false) => format!("Vault '{}' was already locked", name),
        Err(e) => format!(
            "Warning: could not lock vault '{}': {} — its stored master password may still be in the keychain",
            name, e
        ),
    }
}

impl Action for LockAction {
    fn run(&self) -> Result<String, Error> {
        if self.all {
            let vaults = vault_registry::load()?;
            if vaults.is_empty() {
                return Ok("No vaults configured".to_string());
            }
            let lines: Vec<String> = vaults.iter().map(|v| lock_vault(&v.name)).collect();
            Ok(lines.join("\n"))
        } else {
            let config = vault_registry::current()?;
            Ok(lock_vault(&config.name))
        }
    }
}
