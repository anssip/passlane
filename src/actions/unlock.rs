use crate::actions::{Action, unlock_reporting_factors};
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
        let unlocked = unlock_reporting_factors()?;
        match self.session_secs {
            None => {
                keychain::save_master_password(&config.name, &unlocked.factors.master_password)?;
                completion_cache::update_cache(&unlocked.vault);
                Ok(format!("Vault '{}' unlocked", config.name))
            }
            Some(secs) => {
                // A hardware key whose secret stays in the device cannot be
                // handed over; say so, or the session looks like more than
                // it is the first time a command still asks for the key.
                let challenge_response = crate::session_agent::challenge_response_material(
                    unlocked.factors.challenge_response.as_ref(),
                );
                let key_note = match (&config.hwkey, &challenge_response) {
                    (None, _) => "the unlock factors",
                    (Some(_), Some(_)) => "the unlock factors, hardware key included",
                    (Some(_), None) => {
                        "the master password — the hardware key itself is still needed for \
                         every command"
                    }
                };
                let expires_at = crate::session_agent::create_unlock_session(
                    &config.name,
                    &unlocked.factors.master_password,
                    challenge_response,
                    secs,
                )?;
                completion_cache::update_cache(&unlocked.vault);
                let when = chrono::DateTime::from_timestamp(expires_at as i64, 0)
                    .map(|t| t.to_rfc3339())
                    .unwrap_or_else(|| format!("+{secs}s"));
                Ok(format!(
                    "Vault '{}' unlocked — the session agent holds {} until {} (memory only, \
                     nothing stored in the keychain; 'passlane lock' revokes it early)",
                    config.name, key_note, when
                ))
            }
        }
    }
}
