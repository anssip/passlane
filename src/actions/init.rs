use crate::actions::Action;
use crate::keychain;
use crate::store;
use crate::ui::input::{
    ask_existing_path, ask_keyfile_path, ask_new_master_password, ask_new_totp_master_password,
    ask_open_existing_totp_vault, ask_open_existing_vault, ask_store_hwkey,
    ask_store_master_password, ask_store_totp_master_password, ask_totp_vault_path,
    ask_vault_path, newline,
};
use crate::vault::entities::Error;
use crate::vault::keepass_vault::KeepassVault;
use keepass_ng::ChallengeResponseKey;

pub struct InitAction {}

impl Action for InitAction {
    fn run(&self) -> Result<String, Error> {
        // TODO: Show welcome message with ASCII art

        let (vault_location, is_new_vault) = self.initialize_vault()?;
        newline();

        let (totp_vault_location, is_new_totp_vault) = self.initialize_totp_vault()?;
        newline();

        let keyfile_location = self.init_keyfile()?;
        newline();

        let master_pwd = self.initialize_master_password()?;

        let (hwkey_key, hwkey_config) = if is_new_vault {
            self.init_hwkey()?
        } else {
            (None, None)
        };

        if is_new_vault {
            println!("Initializing new vault...");
            let mut vault = self.create_keepass_vault(
                &vault_location,
                &master_pwd,
                keyfile_location.as_deref(),
                hwkey_key.as_ref(),
            )?;
            if let Some(config) = &hwkey_config {
                // Persisted only after the vault file exists and was saved
                // with the enrolled factor.
                if let Err(e) = crate::hwkey::save_config(config) {
                    // Without the persisted config passlane would not include
                    // the factor on open: roll it back so the just-created
                    // vault stays reachable via passlane.
                    if let Err(rollback) = vault.update_challenge_response(None) {
                        eprintln!(
                            "Warning: failed to roll back the hardware key enrollment: {}",
                            rollback
                        );
                    }
                    return Err(e);
                }
                crate::hwkey::print_backup_reminder();
            }
        }

        if is_new_totp_vault {
            println!("Initializing new TOTP vault...");
            let totp_master_pwd = ask_new_totp_master_password();
            let store_totp_pwd = ask_store_totp_master_password();
            // The keyfile chosen during init protects both vaults: share it with
            // the TOTP vault unless a TOTP-specific keyfile is already configured.
            let configured_totp_keyfile = store::get_totp_keyfile_path();
            let totp_keyfile = configured_totp_keyfile
                .clone()
                .or_else(|| keyfile_location.clone());
            self.create_keepass_vault(
                &totp_vault_location,
                &totp_master_pwd,
                totp_keyfile.as_deref(),
                None,
            )?;
            if configured_totp_keyfile.is_none() {
                if let Some(keyfile) = &totp_keyfile {
                    store::save_totp_keyfile_path(keyfile)?;
                }
            }
            if store_totp_pwd {
                keychain::save_totp_master_password(&totp_master_pwd)?;
            }
        }

        Ok(String::from("Initialized"))
    }
}

impl InitAction {
    fn initialize_vault(&self) -> Result<(String, bool), Error> {
        if store::has_vault_path() {
            println!("Vault already configured");
            return Ok((store::get_vault_path(), false));
        }

        let (location, is_new_vault) = if ask_open_existing_vault() {
            (
                self.get_and_save_vault_location(ask_existing_path, "Vault")?,
                false,
            )
        } else {
            (
                self.get_and_save_vault_location(
                    || ask_vault_path(&store::get_vault_path()),
                    "Vault",
                )?,
                true,
            )
        };
        Ok((location, is_new_vault))
    }

    fn initialize_totp_vault(&self) -> Result<(String, bool), Error> {
        if store::has_totp_vault_path() {
            println!("TOTP Vault already configured");
            return Ok((store::get_totp_vault_path(), false));
        }

        let (location, is_new_vault) = if ask_open_existing_totp_vault() {
            (
                self.get_and_save_vault_location(ask_existing_path, "TOTP Vault")?,
                false,
            )
        } else {
            (
                self.get_and_save_vault_location(
                    || ask_totp_vault_path(&store::get_totp_vault_path()),
                    "TOTP Vault",
                )?,
                true,
            )
        };
        Ok((location, is_new_vault))
    }

    fn get_and_save_vault_location<F>(
        &self,
        ask_location: F,
        vault_type: &str,
    ) -> Result<String, Error>
    where
        F: Fn() -> String,
    {
        let location = ask_location();
        println!("{} location {}", vault_type, location);
        match vault_type {
            "Vault" => store::save_vault_path(&location)?,
            "TOTP Vault" => store::save_totp_vault_path(&location)?,
            _ => {
                return Err(Error {
                    message: format!("Unknown vault type: {}", vault_type),
                })
            }
        }
        Ok(location)
    }

    fn init_keyfile(&self) -> Result<Option<String>, Error> {
        if store::has_keyfile_path() {
            println!("Keyfile already configured");
            return Ok(store::get_keyfile_path());
        }
        let keyfile_location = ask_keyfile_path(store::get_keyfile_path().as_deref());
        if let Some(keyfile) = &keyfile_location {
            if keyfile != "" {
                store::save_keyfile_path(keyfile)?;
            }
        }
        Ok(keyfile_location)
    }

    /// Resolve the hardware-key factor for a vault that is about to be
    /// created: an already-enrolled key, a newly prompted enrollment (whose
    /// config the caller persists after the vault is saved), or none.
    fn init_hwkey(&self) -> Result<(Option<ChallengeResponseKey>, Option<crate::hwkey::HwKeyConfig>), Error> {
        // Load (not just check existence): an unreadable or corrupt config
        // must error or fall through to enrollment — not print "already
        // configured" and then silently skip the factor.
        if crate::hwkey::load_config()?.is_some() {
            println!("Hardware key already configured");
            return Ok((crate::hwkey::configured_challenge_response_key()?, None));
        }
        if !ask_store_hwkey() {
            return Ok((None, None));
        }
        let (key, config) = crate::hwkey::resolve_new_key(None, None)?;
        Ok((Some(key), Some(config)))
    }

    fn initialize_master_password(&self) -> Result<String, Error> {
        println!("Initializing master password... checking if already stored in keychain");
        let master_pwd = keychain::get_master_password();
        match master_pwd {
            Ok(pwd) => {
                println!("Master password already configured");
                Ok(pwd)
            }
            Err(_) => {
                println!("Initializing a new master password");
                let master_pwd = ask_new_master_password();
                if ask_store_master_password() {
                    keychain::save_master_password(&master_pwd)?;
                }
                Ok(master_pwd)
            }
        }
    }

    fn create_keepass_vault(
        &self,
        vault_location: &str,
        master_pwd: &str,
        keyfile: Option<&str>,
        challenge_response: Option<&ChallengeResponseKey>,
    ) -> Result<KeepassVault, Error> {
        KeepassVault::new(vault_location, master_pwd, keyfile, challenge_response)
    }
}
