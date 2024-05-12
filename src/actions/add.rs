use anyhow::{bail, Context};
use clap::ArgMatches;
use clipboard::{ClipboardContext, ClipboardProvider};
use crate::actions::{Action, copy_to_clipboard, ItemType, unlock, unlock_totp_vault};
use crate::{crypto, ui};
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
            generate: *matches
                .get_one::<bool>("generate")
                .expect("defaulted to false by clap"),
            clipboard: *matches
                .get_one::<bool>("clipboard")
                .expect("defaulted to false by clap"),
            item_type: ItemType::new_from_args(matches),
            is_totp: *matches.get_one::<bool>("otp").expect("defaulted to false by clap"),
        }
    }
    fn password_from_clipboard(&self) -> anyhow::Result<String> {
        let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
        let value = ctx
            .get_contents()
            .expect("Unable to retrieve value from clipboard");
        if !crypto::validate_password(&value) {
            bail!("The text in clipboard is not a valid password");
        }
        Ok(value)
    }
    fn get_password(&self) -> anyhow::Result<String> {
        if self.generate {
            Ok(crypto::generate())
        } else if self.clipboard {
            self.password_from_clipboard()
        } else {
            Ok(ui::ask_password("Enter password to save: "))
        }
    }
    fn get_vault(&self) -> anyhow::Result<Box<dyn Vault>> {
        if self.is_totp {
            unlock_totp_vault()
        } else {
            unlock()
        }
    }
    fn add_credential(&self) -> anyhow::Result<(), anyhow::Error> {
        let password = self.get_password().context(format!(
            "Failed to get password {}",
            if self.clipboard { "from clipboard" } else { "" }
        ))?;

        let creds = ui::ask_credentials(&password);
        let mut vault = self.get_vault().context("Failed to unlock vault")?;
        vault.save_one_credential(creds.clone());
        if !self.clipboard {
            copy_to_clipboard(&password);
            println!("Password - also copied to clipboard: {}", password);
        };
        Ok(())
    }
    fn add_payment(&self) -> anyhow::Result<()> {
        let payment = ui::ask_payment_info();
        println!("Saving...");
        let mut vault = self.get_vault().context("Failed to unlock vault")?;
        vault.save_payment(payment);
        println!("Payment saved.");
        Ok(())
    }
    fn add_note(&self) -> anyhow::Result<()> {
        let note = ui::ask_note_info();
        println!("Saving...");
        let mut vault = self.get_vault().context("Failed to unlock vault")?;
        vault.save_note(&note);
        println!("Note saved.");
        Ok(())
    }
    fn add_totp(&self) -> anyhow::Result<()> {
        let totp = ui::ask_totp_info();
        println!("Saving...");
        let mut vault = self.get_vault().context("Failed to unlock vault")?;
        vault.save_totp(&totp);
        println!("TOTP saved.");
        Ok(())
    }

    fn add(&self) -> anyhow::Result<()> {
        match self.item_type {
            ItemType::Credential => self.add_credential(),
            ItemType::Payment => self.add_payment(),
            ItemType::Note => self.add_note(),
            ItemType::Totp => self.add_totp(),
        }
    }
}

impl Action for AddAction {
    fn run(&self) -> anyhow::Result<()> {
        self.add().context("Failed to add item")
    }
}
