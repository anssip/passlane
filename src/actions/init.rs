use crate::actions::Action;
use crate::store;
use crate::ui::{
    ask_keyfile_path, ask_new_master_password, ask_totp_vault_path, ask_vault_path, newline,
};
use crate::vault::entities::Error;
use crate::vault::keepass_vault::KeepassVault;

pub struct InitAction {}

impl Action for InitAction {
    fn run(&self) -> Result<String, Error> {
        // TODO: Show welcome message with ASCII art
        //
        // 1. Ask if we want to create a new vault file or open an existing one

        let vault_location = ask_vault_path(&store::get_vault_path());
        println!("Vault location {}", vault_location);
        // TODO: store vault locations in config

        newline();
        let totp_vault_location = ask_totp_vault_path(&store::get_totp_vault_path());
        println!("TOTP Vault location {}", totp_vault_location);

        newline();
        let keyfile_location = ask_keyfile_path(store::get_keyfile_path().as_deref());
        newline();
        let master_pwd = ask_new_master_password();

        // TODO: ask if to store master_pwd in keychain. If not, write to config that keychain is not used (?)
        // unlock should then remove the config as keychain is used after unlocking

        match keyfile_location {
            Some(keyfile) => {
                println!("Keyfile location {}", keyfile);
                KeepassVault::new(&vault_location, &master_pwd, Some(&keyfile))?;
            }
            None => {
                println!("Keyfile location not provided");
                KeepassVault::new(&vault_location, &master_pwd, None)?;
            }
        }

        Ok(String::from("Initialized"))
    }
}
