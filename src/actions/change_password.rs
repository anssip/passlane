use crate::actions::Action;
use crate::keychain;
use crate::ui::input::{ask_master_password, ask_new_master_password};
use crate::vault::entities::Error;
use crate::vault::keepass_vault::KeepassVault;
use crate::vault_registry;

pub struct ChangePasswordAction {}

impl ChangePasswordAction {
    pub fn new() -> ChangePasswordAction {
        ChangePasswordAction {}
    }
}

impl Action for ChangePasswordAction {
    fn run(&self) -> Result<String, Error> {
        let config = vault_registry::current()?;
        let current_pwd = ask_master_password(Some(&format!(
            "Please enter current master password of vault '{}'",
            config.name
        )));
        let challenge_response = match config.hwkey {
            Some(ref hwkey_config) => {
                Some(crate::hwkey::configured_challenge_response_key(hwkey_config)?)
            }
            None => None,
        };

        let mut vault = KeepassVault::open(
            &current_pwd,
            &config.path,
            config.keyfile,
            challenge_response.as_ref(),
        )?;

        let new_pwd = ask_new_master_password();
        if new_pwd == current_pwd {
            return Err(Error::new(
                "New master password must differ from the current one",
            ));
        }

        vault.change_master_password(new_pwd.clone())?;
        // Keep the keychain entry in sync only when a password was stored.
        if keychain::get_master_password(&config.name).is_ok() {
            keychain::save_master_password(&config.name, &new_pwd)?;
        }

        Ok(format!(
            "Master password of vault '{}' changed",
            config.name
        ))
    }
}
