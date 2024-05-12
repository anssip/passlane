pub mod show;
pub mod add;
pub mod delete;

use clap::Command;
use clipboard::ClipboardContext;
use clipboard::ClipboardProvider;
use crate::{crypto, keychain};
use crate::store;
use crate::ui;
use anyhow::{bail, Context};
use clap::ArgMatches;
use log::{debug, info};
use std::io;
use crate::vault::entities::{Credential};
use crate::vault::keepass_vault::KeepassVault;
use crate::vault::vault_trait::Vault;
use anyhow::Result;

pub(crate) trait MatchHandlerTemplate where Self::ItemType: Clone {
    type ItemType;

    fn pre_handle_matches(&self, matches: &Vec<Self::ItemType>);
    fn handle_one_match(&mut self, the_match: Self::ItemType);
    fn handle_many_matches(&mut self, matches: Vec<Self::ItemType>);
}

pub(crate) fn handle_matches<H>(matches: Vec<H::ItemType>, handler: &mut Box<H>)
    where
        H: MatchHandlerTemplate,
        H::ItemType: Clone,
{
    if matches.is_empty() {
        println!("No matches found");
    } else {
        handler.pre_handle_matches(&matches.clone());

        if matches.len() == 1 {
            handler.handle_one_match(matches[0].clone());
        } else {
            handler.handle_many_matches(matches);
        }
    }
}

pub trait Action {
    fn run(&self) -> anyhow::Result<()> {
        Ok(())
    }
}

pub trait UnlockingAction: Action {
    fn execute(&self) {
        info!("Unlocking vault...");
        let result = if self.is_totp_vault() {
            self.unlock_totp_vault()
        } else {
            self.unlock()
        };
        match result {
            Ok(mut vault) => {
                match self.run_with_vault(&mut vault) {
                    Ok(_) => {
                        info!("Action completed successfully");
                    }
                    Err(e) => {
                        println!("Failed to run action: {}", e);
                    }
                }
            }
            Err(e) => {
                println!("Failed to unlock vault: {}", e);
            }
        }
    }

    fn is_totp_vault(&self) -> bool {
        false
    }

    fn run_with_vault(&self, _: &mut Box<dyn Vault>) -> anyhow::Result<()> {
        Ok(())
    }

    fn get_vault(&self, password: &str, filepath: &str, keyfile_path: Option<String>) -> anyhow::Result<Box<dyn Vault>> {
        // we could return some other Vault implementation here
        let vault = KeepassVault::new(password, filepath, keyfile_path);
        match vault {
            Ok(v) => Ok(Box::new(v)),
            Err(e) => {
                bail!("Incorrect password? {}", e.message);
            }
        }
    }
    fn unlock(&self) -> Result<Box<dyn Vault>> {
        let stored_password = keychain::get_master_password();
        let master_pwd = stored_password.unwrap_or_else(|_| ui::ask_master_password(None));
        let filepath = store::get_vault_path();
        let keyfile_path = store::get_keyfile_path();
        self.get_vault(&master_pwd, &filepath, keyfile_path)
    }

    fn unlock_totp_vault(&self) -> Result<Box<dyn Vault>> {
        let stored_password = keychain::get_totp_master_password();
        let master_pwd = stored_password.unwrap_or_else(|_| ui::ask_totp_master_password());
        let filepath = store::get_totp_vault_path();
        let keyfile_path = store::get_totp_keyfile_path();
        self.get_vault(&master_pwd, &filepath, keyfile_path)
    }
}

pub fn copy_to_clipboard(value: &String) {
    let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
    ctx.set_contents(String::from(value)).unwrap();
}

#[derive(PartialEq)]
pub enum ItemType {
    Credential,
    Payment,
    Note,
    Totp
}

impl ItemType {
    pub fn new_from_args(matches: &ArgMatches) -> ItemType {
        if *matches
            .get_one::<bool>("payments")
            .expect("defaulted to false by clap") {
            ItemType::Payment
        } else if *matches.get_one("notes").expect("defaulted to false by clap") {
            ItemType::Note
        } else if *matches.get_one("otp").expect("defaulted to false by clap") {
            ItemType::Totp
        } else {
            ItemType::Credential
        }
    }
}

pub struct ExportAction {
    pub file_path: String,
    pub item_type: ItemType,
}

impl ExportAction {
    pub fn new(matches: &ArgMatches) -> ExportAction {
        ExportAction {
            file_path: matches.get_one::<String>("file_path").expect("required").to_string(),
            item_type: ItemType::new_from_args(matches),
        }
    }
    pub fn export_csv(&self, vault: &mut Box<dyn Vault>) -> anyhow::Result<i64> {
        debug!("exporting to csv");
        if self.item_type == ItemType::Credential {
            let creds = vault.grep(&None);
            if creds.is_empty() {
                println!("No credentials found");
                return Ok(0);
            }
            store::write_credentials_to_csv(&self.file_path, &creds)
        } else if self.item_type == ItemType::Payment {
            let cards = vault.find_payments();
            store::write_payment_cards_to_csv(&self.file_path, &cards)
        } else if self.item_type == ItemType::Note {
            let notes = vault.find_notes();
            store::write_secure_notes_to_csv(&self.file_path, &notes)
        } else {
            Ok(0)
        }
    }
}

impl Action for ExportAction {}

impl UnlockingAction for ExportAction {
    fn run_with_vault(&self, vault: &mut Box<dyn Vault>) -> anyhow::Result<()> {
        match self.export_csv(vault) {
            Err(message) => println!("Failed to export: {}", message),
            Ok(count) => println!("Exported {} entries", count),
        }
        Ok(())
    }
}

pub struct ImportCsvAction {
    pub file_path: String,
}

impl ImportCsvAction {
    pub fn new(matches: &ArgMatches) -> ImportCsvAction {
        ImportCsvAction {
            file_path: matches.get_one::<String>("FILE_PATH").expect("required").to_string(),
        }
    }
}

fn push_from_csv(vault: &mut Box<dyn Vault>, file_path: &str) -> anyhow::Result<i64> {
    let input = store::read_from_csv(file_path)?;
    let creds = input.into_iter().map(|c| c.to_credential()).collect();

    vault.save_credentials(&creds);
    let num_imported = creds.len();
    Ok(num_imported.try_into().unwrap())
}


impl Action for ImportCsvAction {}

impl UnlockingAction for ImportCsvAction {
    fn run_with_vault(&self, vault: &mut Box<dyn Vault>) -> anyhow::Result<()> {
        match push_from_csv(vault, &self.file_path) {
            Err(message) => println!("Failed to import: {}", message),
            Ok(count) => println!("Imported {} entries", count),
        }
        Ok(())
    }
}

pub struct GeneratePasswordAction {}

impl Action for GeneratePasswordAction {
    fn run(&self) -> anyhow::Result<()> {
        let password = crypto::generate();
        copy_to_clipboard(&password);
        println!("Password - also copied to clipboard: {}", password);
        Ok(())
    }
}

pub struct LockAction {}

impl Action for LockAction {
    fn run(&self) -> anyhow::Result<()> {
        keychain::delete_master_password()?;
        Ok(())
    }
}

pub struct UnlockAction {}

impl Action for UnlockAction {}

impl UnlockingAction for UnlockAction {
    fn run_with_vault(&self, vault: &mut Box<dyn Vault>) -> anyhow::Result<()> {
        keychain::save_master_password(&vault.get_master_password())?;
        Ok(())
    }
}

pub struct PrintHelpAction {
    cli: Command,
}

impl PrintHelpAction {
    pub fn new(cli: Command) -> PrintHelpAction {
        PrintHelpAction {
            cli
        }
    }
}

impl Action for PrintHelpAction {
    fn run(&self) -> anyhow::Result<()> {
        let mut out = io::stdout();
        self.cli.clone().write_help(&mut out).context("Failed to display help!")?;
        Ok(())
    }
}
