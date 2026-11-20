use crate::actions::Action;
use crate::completion_cache;
use crate::keychain;
use crate::vault_registry;
use passlane_core::vault::entities::Error;

pub struct LockAction {
    /// Lock every registered vault instead of just the current one.
    pub all: bool,
}

impl LockAction {
    pub fn new(all: bool) -> LockAction {
        LockAction { all }
    }
}

/// A vault is locked when its master password is gone from the keychain
/// **and** the session agent no longer holds a session for it. "No
/// entry" is the normal already-locked case; any other error means the
/// stored password may still be there and must not be reported as locked.
/// Cache removal is best-effort: a leftover cache only leaks service names.
fn lock_vault(name: &str) -> String {
    let mut message = match keychain::delete_master_password_if_stored(name) {
        Ok(true) => {
            completion_cache::clear_cache_for(name);
            format!("Vault '{}' locked", name)
        }
        Ok(false) => format!("Vault '{}' was already locked", name),
        Err(e) => format!(
            "Warning: could not lock vault '{}': {} — its stored master password may still be in the keychain",
            name, e
        ),
    };
    // Locking must not leave the vault effectively unlocked through a
    // live agent session; silent best-effort when the agent is down.
    let revoked = crate::session_agent::revoke_vault_sessions(name);
    if revoked > 0 {
        message.push_str(&format!("; revoked {revoked} agent session(s)"));
    }
    message
}

impl Action for LockAction {
    fn run(&self) -> Result<String, Error> {
        if self.all {
            let vaults = vault_registry::load()?;
            if vaults.is_empty() {
                return Ok("No vaults configured".to_string());
            }
            let lines: Vec<String> = vaults.iter().map(|v| lock_vault(&v.name)).collect();
            // Also drop any agent session left for unregistered vaults.
            let strays = crate::session_agent::revoke_all_sessions();
            let mut summary = lines.join("\n");
            if strays > 0 {
                summary.push_str(&format!(
                    "\nRevoked {strays} agent session(s) of unregistered vaults"
                ));
            }
            Ok(summary)
        } else {
            let config = vault_registry::current()?;
            Ok(lock_vault(&config.name))
        }
    }
}
