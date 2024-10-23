use crate::actions::Action;
use crate::keychain;
use crate::store;
use crate::ui::input::{
    ask_existing_path, ask_keyfile_path, ask_new_master_password, ask_open_existing_totp_vault,
    ask_open_existing_vault, ask_store_master_password, ask_totp_vault_path, ask_vault_path,
    newline,
};
use crate::vault::entities::Error;
use crate::vault::keepass_vault::KeepassVault;

pub struct InitAction {}

impl Action for InitAction {
    fn run(&self) -> Result<String, Error> {
        // TODO: Show welcome message with ASCII art

        let (vault_location, is_new_vault) = self.initialize_vault()?;
        newline();

        self.initialize_totp_vault()?;
        newline();

        let keyfile_location = self.init_keyfile()?;
        newline();

        let master_pwd = self.initialize_master_password()?;

        if is_new_vault {
            println!("Initializing new vault...");
            self.create_keepass_vault(&vault_location, &master_pwd, keyfile_location.as_deref())?;
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

    fn initialize_totp_vault(&self) -> Result<String, Error> {
        if store::has_totp_vault_path() {
            println!("TOTP Vault already configured");
            return Ok(store::get_totp_vault_path());
        }

        let location = if ask_open_existing_totp_vault() {
            self.get_and_save_vault_location(ask_existing_path, "TOTP Vault")?
        } else {
            self.get_and_save_vault_location(
                || ask_totp_vault_path(&store::get_totp_vault_path()),
                "TOTP Vault",
            )?
        };

        Ok(location)
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
    ) -> Result<(), Error> {
        KeepassVault::new(vault_location, master_pwd, keyfile)?;
        Ok(())
    }
}
