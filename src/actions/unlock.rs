use clap::ArgMatches;
use crate::actions::{Action, unlock, unlock_totp_vault};
use crate::keychain;
use crate::vault::entities::Error;

pub struct UnlockAction {
    pub totp: bool,
}

impl UnlockAction {
    pub fn new(matches: &ArgMatches) -> UnlockAction {
        UnlockAction {
            totp: matches.get_one::<bool>("otp").map_or(false, |v| *v),
        }
    }
}

impl Action for UnlockAction {
    fn run(&self) -> Result<String, Error> {
        if self.totp {
            let vault = unlock_totp_vault()?;
            keychain::save_totp_master_password(&vault.get_master_password())?;
        } else {
            let vault = unlock()?;
            keychain::save_master_password(&vault.get_master_password())?;
        }
        Ok("Vault unlocked".to_string())
    }
}
