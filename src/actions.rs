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

pub trait Action {
    fn run(&self) -> anyhow::Result<()> {
        Ok(())
    }
}

pub trait UnlockingAction: Action {
    fn execute(&self) -> anyhow::Result<()> {
        info!("Unlocking vault...");
        let vault = self.unlock();
        vault.and_then(|vault| self.run_with_vault(&mut Box::new(vault)))
    }

    fn run_with_vault(&self, _: &mut Box<dyn Vault>) -> anyhow::Result<()> {
        Ok(())
    }

    fn get_vault(&self, password: &str, filepath: &str, keyfile_path: Option<String>) -> anyhow::Result<Box<dyn Vault>> {
        // we could return some other Vault implementation here
        let vault = KeepassVault::new(password, filepath, keyfile_path);
        match vault {
            Some(v) => Ok(Box::new(v)),
            None => {
                bail!("Failed to open vault");
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
}

impl ItemType {
    pub fn new_from_args(matches: &ArgMatches) -> ItemType {
        if *matches
            .get_one::<bool>("payments")
            .expect("defaulted to false by clap") {
            ItemType::Payment
        } else if *matches.get_one("notes").expect("defaulted to false by clap") {
            ItemType::Note
        } else {
            ItemType::Credential
        }
    }
}

pub struct AddAction {
    pub generate: bool,
    pub clipboard: bool,
    pub item_type: ItemType,
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
}

impl Action for AddAction {}

impl UnlockingAction for AddAction {
    fn run_with_vault(&self, vault: &mut Box<dyn Vault>) -> anyhow::Result<()> {
        match self.item_type {
            ItemType::Credential => self.add_credential(vault)?,
            ItemType::Payment => self.add_payment(vault)?,
            ItemType::Note => self.add_note(vault)?
        };
        Ok(())
    }
}

pub struct ShowAction {
    pub grep: Option<String>,
    pub verbose: bool,
    pub item_type: ItemType,
}

impl ShowAction {
    pub fn new(matches: &ArgMatches) -> ShowAction {
        ShowAction {
            grep: matches.get_one::<String>("REGEXP").cloned(),
            verbose: *matches
                .get_one::<bool>("verbose")
                .expect("defaulted to false by clap"),
            item_type: ItemType::new_from_args(matches),
        }
    }
    fn show_credentials(&self, vault: &mut Box<dyn Vault>) -> anyhow::Result<()> {
        let grep = match &self.grep {
            Some(grep) => Some(String::from(grep)),
            None => panic!("-g <REGEXP> is required"),
        };
        let matches = find_credentials(&vault, grep).context("Failed to find matches. Invalid password? Try unlocking the vault with `passlane unlock`.")?;

        if matches.len() >= 1 {
            println!("Found {} matches:", matches.len());
            ui::show_credentials_table(&matches, self.verbose);
            if matches.len() == 1 {
                copy_to_clipboard(&matches[0].password);
                println!("Password copied to clipboard!", );
            } else {
                match ui::ask_index(
                    "To copy one of these passwords to clipboard, please enter a row number from the table above, or press q to exit:",
                    matches.len() as i16 - 1,
                ) {
                    Ok(index) => {
                        copy_to_clipboard(&matches[index].password);
                        println!("Password from index {} copied to clipboard!", index);
                    }
                    Err(message) => {
                        println!("{}", message);
                    }
                }
            }
        }
        Ok(())
    }

    fn show_payments(&self, vault: &mut Box<dyn Vault>) -> anyhow::Result<()> {
        debug!("showing payments");
        let matches = vault.find_payments();
        if matches.len() == 0 {
            println!("No payment cards found");
        } else {
            println!("Found {} payment cards:", matches.len());
            ui::show_payment_cards_table(&matches, self.verbose);

            if matches.len() == 1 {
                let response = ui::ask("Do you want to see the card details? (y/n)");
                if response == "y" {
                    ui::show_card(&matches[0]);
                    copy_to_clipboard(&matches[0].number);
                    println!("Card number copied to clipboard!", );
                }
            } else {
                match ui::ask_index(
                    "Enter a row number from the table above, or press q to exit:",
                    matches.len() as i16 - 1,
                ) {
                    Ok(index) => {
                        ui::show_card(&matches[index]);
                        copy_to_clipboard(&matches[index].number);
                        println!("Card number copied to clipboard!");
                    }
                    Err(message) => {
                        println!("{}", message);
                    }
                }
            }
        }
        Ok(())
    }

    fn show_notes(&self, vault: &mut Box<dyn Vault>) -> anyhow::Result<()> {
        debug!("showing notes");
        let matches = vault.find_notes();
        if matches.len() == 0 {
            println!("No notes found");
        } else {
            println!("Found {} notes:", matches.len());
            ui::show_notes_table(&matches, self.verbose);


            if matches.len() == 1 {
                let response = ui::ask("Do you want to see the full note? (y/n)");
                if response == "y" {
                    ui::show_note(&matches[0]);
                }
            } else {
                match ui::ask_index(
                    "Enter a row number from the table above, or press q to exit:",
                    matches.len() as i16 - 1,
                ) {
                    Ok(index) => {
                        ui::show_note(&matches[index]);
                    }
                    Err(message) => {
                        println!("{}", message);
                    }
                }
            }
        }
        Ok(())
    }
}

fn find_credentials(
    vault: &Box<dyn Vault>,
    grep: Option<String>,
) -> anyhow::Result<Vec<Credential>> {
    let matches = vault.grep(&grep);
    if matches.is_empty() {
        println!("No matches found");
    }
    Ok(matches)
}

impl Action for ShowAction {}

impl UnlockingAction for ShowAction {
    fn run_with_vault(&self, vault: &mut Box<dyn Vault>) -> anyhow::Result<()> {
        match self.item_type {
            ItemType::Credential => self.show_credentials(vault)?,
            ItemType::Payment => self.show_payments(vault)?,
            ItemType::Note => self.show_notes(vault)?
        };
        Ok(())
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
            let creds = find_credentials(&vault, None)?;
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

pub struct DeleteAction {
    pub grep: Option<String>,
    pub item_type: ItemType,
}

impl DeleteAction {
    pub fn new(matches: &ArgMatches) -> DeleteAction {
        DeleteAction {
            grep: matches.get_one::<String>("REGEXP").cloned(),
            item_type: ItemType::new_from_args(matches),
        }
    }
}

fn delete_credentials(vault: &mut Box<dyn Vault>, grep: &str) -> anyhow::Result<()> {
    let matches = find_credentials(&vault, Some(String::from(grep))).context("Unable to get matches. Invalid password? Try unlocking again.")?;

    if matches.is_empty() {
        debug!("no matches found to delete");
        return Ok(());
    }
    if matches.len() == 1 {
        vault.delete_credentials(&matches.get(0).unwrap().uuid);
        println!("Deleted credential for service '{}'", matches[0].service);
    }
    if matches.len() > 1 {
        ui::show_credentials_table(&matches, false);
        match ui::ask_index(
            "To delete, please enter a row number from the table above, press a to delete all, or press q to abort:",
            matches.len() as i16 - 1,
        ) {
            Ok(index) => {
                if index == usize::MAX {
                    vault.delete_matching(grep);
                    println!("Deleted all {} matches!", matches.len());
                } else {
                    vault.delete_credentials(&matches[index].uuid);
                    println!("Deleted credentials of row {}!", index);
                }
            }
            Err(message) => {
                println!("{}", message);
            }
        }
    }
    Ok(())
}

fn delete_payment(vault: &mut Box<dyn Vault>) -> anyhow::Result<()> {
    let cards = vault.find_payments();
    if cards.is_empty() {
        println!("No payment cards found");
        return Ok(());
    }
    ui::show_payment_cards_table(&cards, false);
    if cards.len() == 1 {
        let response = ui::ask("Do you want to delete this card? (y/n)");
        if response == "y" {
            vault.delete_payment(&cards[0].id);
            println!("Deleted card named '{}'!", cards[0].name);
        }
        return Ok(());
    }
    match ui::ask_index(
        "To delete, please enter a row number from the table above, or press q to abort:",
        cards.len() as i16 - 1,
    ) {
        Ok(index) => {
            if index == usize::MAX {
                // ignore                   
            } else {
                vault.delete_payment(&cards[index].id);
                println!("Deleted card named '{}'!", cards[index].name);
            }
        }
        Err(message) => {
            println!("{}", message);
        }
    }
    Ok(())
}

fn delete_note(vault: &mut Box<dyn Vault>) -> anyhow::Result<()> {
    let notes = vault.find_notes();
    if notes.len() == 0 {
        println!("No notes found");
        return Ok(());
    }
    ui::show_notes_table(&notes, false);
    if notes.len() == 1 {
        let response = ui::ask("Do you want to delete this note? (y/n)");
        if response == "y" {
            vault.delete_note(&notes[0].id);
            println!("Deleted note with title '{}'!", notes[0].title);
        }
        return Ok(());
    }
    match ui::ask_index(
        "To delete, please enter a row number from the table above, or press q to abort:",
        notes.len() as i16 - 1,
    ) {
        Ok(index) => {
            if index == usize::MAX {
                // ignore                   
            } else {
                vault.delete_note(&notes[index].id);
                println!("Deleted note with title '{}'!", notes[index].title);
            }
        }
        Err(message) => {
            println!("{}", message);
        }
    }
    Ok(())
}


impl Action for DeleteAction {}

impl UnlockingAction for DeleteAction {
    fn run_with_vault(&self, vault: &mut Box<dyn Vault>) -> anyhow::Result<()> {
        match self.item_type {
            ItemType::Credential => {
                let grep = match &self.grep {
                    Some(grep) => grep,
                    None => panic!("-g <REGEXP> is required"),
                };
                delete_credentials(vault, grep)?;
            }
            ItemType::Payment => {
                delete_payment(vault)?;
            }
            ItemType::Note => {
                delete_note(vault)?;
            }
        };
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
