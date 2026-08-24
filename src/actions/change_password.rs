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
        // A keychain error must not silently skip a still-present entry —
        // that would leave the stored password stale.
        match keychain::has_master_password(&config.name) {
            Ok(true) => {
                keychain::save_master_password(&config.name, &new_pwd)?;
            }
            Ok(false) => {}
            Err(e) => eprintln!(
                "Warning: could not check whether vault '{}' has a stored master password ({}). \
                 If one is stored it is now stale — fix the keychain and re-run 'passlane unlock'.",
                config.name, e
            ),
        }

        Ok(format!(
            "Master password of vault '{}' changed",
            config.name
        ))
    }
}
