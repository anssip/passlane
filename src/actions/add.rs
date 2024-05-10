use anyhow::{bail, Context};
use clap::ArgMatches;
use clipboard::{ClipboardContext, ClipboardProvider};
use crate::actions::{Action, copy_to_clipboard, ItemType, UnlockingAction};
use crate::{crypto, ui};
use crate::vault::entities::Credential;
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
    fn save(&self, creds: &Credential, vault: &mut Box<dyn Vault>) -> anyhow::Result<()> {
        vault.save_one_credential(creds.clone());
        println!("Saved.");
        Ok(())
    }
    fn add_credential(&self, vault: &mut Box<dyn Vault>) -> anyhow::Result<(), anyhow::Error> {
        let password = self.get_password().context(format!(
            "Failed to get password {}",
            if self.clipboard { "from clipboard" } else { "" }
        ))?;

        let creds = ui::ask_credentials(&password);
        self.save(&creds, vault)
            .context("failed to save")?;
        if !self.clipboard {
            copy_to_clipboard(&password);
            println!("Password - also copied to clipboard: {}", password);
        };
        Ok(())
    }
    fn add_payment(&self, vault: &mut Box<dyn Vault>) -> anyhow::Result<()> {
        let payment = ui::ask_payment_info();
        vault.save_payment(payment);
        Ok(())
    }
    fn add_note(&self, vault: &mut Box<dyn Vault>) -> anyhow::Result<()> {
        let note = ui::ask_note_info();
        vault.save_note(&note);
        println!("Note saved.");
        Ok(())
    }
    fn add_totp(&self, vault: &mut Box<dyn Vault>) -> anyhow::Result<()> {
        let totp = ui::ask_totp_info();
        println!("Saving...");
        vault.save_totp(&totp);
        println!("TOTP saved.");
        Ok(())
    }
}

impl Action for AddAction {}

impl UnlockingAction for AddAction {
    fn is_totp_vault(&self) -> bool {
        self.is_totp
    }

    fn run_with_vault(&self, vault: &mut Box<dyn Vault>) -> anyhow::Result<()> {
        match self.item_type {
            ItemType::Credential => self.add_credential(vault)?,
            ItemType::Payment => self.add_payment(vault)?,
            ItemType::Note => self.add_note(vault)?,
            ItemType::Totp => self.add_totp(vault)?
        };
        Ok(())
    }
}
