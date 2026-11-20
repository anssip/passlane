use crate::actions::{Action, unlock};
use crate::completion_cache;
use crate::keychain;
use crate::vault_registry;
use passlane_core::vault::entities::Error;

pub struct UnlockAction {
    /// Hold the unlock factors in the session agent (memory only) for
    /// this many seconds instead of storing the password in the keychain.
    session_secs: Option<u64>,
}

impl UnlockAction {
    pub fn new(session_secs: Option<u64>) -> UnlockAction {
        UnlockAction { session_secs }
    }
}

impl Action for UnlockAction {
    fn run(&self) -> Result<String, Error> {
        let config = vault_registry::current()?;
        if self.session_secs.is_some() {
            // Fail before prompting for the password if there is no
            // agent to hold the session.
            crate::session_agent::connect_or_error()?;
        }
        let vault = unlock()?;
        match self.session_secs {
            None => {
                keychain::save_master_password(&config.name, &vault.get_master_password())?;
                completion_cache::update_cache(&vault);
                Ok(format!("Vault '{}' unlocked", config.name))
            }
            Some(secs) => {
                let expires_at = crate::session_agent::create_unlock_session(
                    &config.name,
                    &vault.get_master_password(),
                    secs,
                )?;
                completion_cache::update_cache(&vault);
                let when = chrono::DateTime::from_timestamp(expires_at as i64, 0)
                    .map(|t| t.to_rfc3339())
                    .unwrap_or_else(|| format!("+{secs}s"));
                Ok(format!(
                    "Vault '{}' unlocked — the session agent holds the unlock factors until \
                     {} (memory only, nothing stored in the keychain; 'passlane lock' revokes \
                     it early)",
                    config.name, when
                ))
            }
        }
    }
}
