use clap::ArgMatches;

use crate::actions::Action;
use crate::keychain;
use crate::store;
use crate::ui::input::{ask_master_password, ask_new_master_password, ask_totp_master_password};
use crate::vault::entities::Error;
use crate::vault::keepass_vault::KeepassVault;

pub struct ChangePasswordAction {
    pub totp: bool,
}

impl ChangePasswordAction {
    pub fn new(matches: &ArgMatches) -> ChangePasswordAction {
        ChangePasswordAction {
            totp: matches.get_one::<bool>("otp").map_or(false, |v| *v),
        }
    }

    fn vault_paths(&self) -> (String, Option<String>) {
        if self.totp {
            (store::get_totp_vault_path(), store::get_totp_keyfile_path())
        } else {
            (store::get_vault_path(), store::get_keyfile_path())
        }
    }

    fn ask_current_password(&self) -> String {
        if self.totp {
            ask_totp_master_password()
        } else {
            ask_master_password(Some("Please enter current master password"))
        }
    }

    fn update_keychain_if_stored(&self, new_password: &str) -> Result<(), Error> {
        let stored = if self.totp {
            keychain::get_totp_master_password()
        } else {
            keychain::get_master_password()
        };
        if stored.is_ok() {
            if self.totp {
                keychain::save_totp_master_password(new_password)?;
            } else {
                keychain::save_master_password(new_password)?;
            }
        }
        Ok(())
    }
}

impl Action for ChangePasswordAction {
    fn run(&self) -> Result<String, Error> {
        let (filepath, keyfile_path) = self.vault_paths();
        let current_pwd = self.ask_current_password();

        let mut vault = KeepassVault::open(&current_pwd, &filepath, keyfile_path)?;

        let new_pwd = ask_new_master_password();
        if new_pwd == current_pwd {
            return Err(Error::new(
                "New master password must differ from the current one",
            ));
        }

        vault.change_master_password(new_pwd.clone())?;
        self.update_keychain_if_stored(&new_pwd)?;

        Ok("Master password changed".to_string())
    }
}
