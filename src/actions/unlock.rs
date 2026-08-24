use crate::actions::{unlock, Action};
use crate::completion_cache;
use crate::keychain;
use crate::vault::entities::Error;
use crate::vault_registry;

pub struct UnlockAction {}

impl UnlockAction {
    pub fn new() -> UnlockAction {
        UnlockAction {}
    }
}

impl Action for UnlockAction {
    fn run(&self) -> Result<String, Error> {
        let config = vault_registry::current()?;
        let vault = unlock()?;
        keychain::save_master_password(&config.name, &vault.get_master_password())?;
        completion_cache::update_cache(&vault);
        Ok(format!("Vault '{}' unlocked", config.name))
    }
}
