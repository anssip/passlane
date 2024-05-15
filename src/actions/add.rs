use clap::ArgMatches;
use clipboard::{ClipboardContext, ClipboardProvider};
use crate::actions::{Action, copy_to_clipboard, ItemType, unlock, unlock_totp_vault};
use crate::{crypto, ui};
use crate::vault::entities::Error;
use crate::vault::vault_trait::Vault;

pub struct AddAction {
    pub generate: bool,
    pub clipboard: bool,
    pub item_type: ItemType,
    pub is_totp: bool,
}

impl AddAction {
    pub fn new(matches: &ArgMatches) -> AddAction {
        AddAction {
            generate: matches
                .get_one::<bool>("generate")
                .map_or(false, |v| *v),
            clipboard: matches
                .get_one::<bool>("clipboard")
                .map_or(false, |v| *v),
            item_type: ItemType::new_from_args(matches),
            is_totp: matches.get_one::<bool>("otp").map_or(false, |v| *v),
        }
    }
    fn password_from_clipboard(&self) -> Result<String, Error> {
        let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
        let value = ctx
            .get_contents()
            .expect("Unable to retrieve value from clipboard");
        if !crypto::validate_password(&value) {
            Error::new("The text in clipboard is not a valid password");
        }
        Ok(value)
    }
    fn get_password(&self) -> Result<String, Error> {
        if self.generate {
            Ok(crypto::generate())
        } else if self.clipboard {
            self.password_from_clipboard()
        } else {
            Ok(ui::ask_password("Enter password to save: "))
        }
    }
    fn get_vault(&self) -> Result<Box<dyn Vault>, Error> {
        if self.is_totp {
            unlock_totp_vault()
        } else {
            unlock()
        }
    }
    fn add_credential(&self) -> Result<String, Error> {
        let password = self.get_password()?;

        let creds = ui::ask_credentials(&password);
        let mut vault = self.get_vault()?;
        vault.save_one_credential(creds.clone())?;
        copy_to_clipboard(&password);
        Ok(format!("Password - also copied to clipboard: {}", password))
    }
    fn add_payment(&self) -> Result<String, Error> {
        let payment = ui::ask_payment_info();
        println!("Saving...");
        let mut vault = self.get_vault()?;
        vault.save_payment(payment)?;
        Ok("Payment saved.".to_string())
    }
    fn add_note(&self) -> anyhow::Result<String, Error> {
        let note = ui::ask_note_info();
        println!("Saving...");
        let mut vault = self.get_vault()?;
        vault.save_note(&note)?;
        Ok("Note saved.".to_string())
    }
    fn add_totp(&self) -> Result<String, Error> {
        let totp = ui::ask_totp_info();
        println!("Saving...");
        let mut vault = self.get_vault()?;
        vault.save_totp(&totp)?;
        Ok("TOTP saved.".to_string())
    }

    fn add(&self) -> Result<String, Error> {
        match self.item_type {
            ItemType::Credential => self.add_credential(),
            ItemType::Payment => self.add_payment(),
            ItemType::Note => self.add_note(),
            ItemType::Totp => self.add_totp(),
        }
    }
}

impl Action for AddAction {
    fn run(&self) -> Result<String, Error> {
        self.add()
    }
}
