use crate::crypto::derive_encryption_key;
use crate::graphql::queries::types::CredentialsIn;
use crate::online_vault::get_plain_me;
use crate::store::get_encryption_key;
use crate::store::delete_encryption_key;
use crate::AccessTokens;
use crate::Credentials;
use clap::Command;
use clipboard::ClipboardContext;
use clipboard::ClipboardProvider;

use crate::auth;
use crate::online_vault;
use crate::crypto;
use crate::store;
use crate::ui;
use anyhow::{bail, Context};
use clap::ArgMatches;
use log::{debug, info, warn};
use std::io;


pub fn get_access_token() -> anyhow::Result<AccessTokens> {
    debug!("get_access_token()");
    if !store::has_logged_in() {
        bail!("You are not logged in to the Passlane Online Vault. Please run `passlane login` to login (or signup) first.");
    }
    let token = store::get_access_token()?;
    debug!("Token expired? {}", token.is_expired());
    debug!("Token {}", token);
    if token.is_expired() {
        match auth::exchange_refresh_token(token) {
            Ok(token) => {
                store::store_access_token(&token)?;
                Ok(token)
            }
            Err(err) => {
                warn!("failed to refresh access token: {}", err);
                let token = auth::login()?;
                store::store_access_token(&token)?;
                Ok(token)
            }
        }
    } else {
        Ok(token)
    }
}

fn push_one_credential(
    credentials: &CredentialsIn,
) -> anyhow::Result<i32> {
    let token = get_access_token()?;
    let encryption_key = get_encryption_key()?;
    debug!("saving with encryption_key: {}", encryption_key);

    online_vault::push_one_credential(&token.access_token, &credentials.encrypt(&encryption_key), None)
}

pub fn copy_to_clipboard(value: &String) {
    let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
    ctx.set_contents(String::from(value)).unwrap();
}

pub trait Action {
    fn execute(&self) -> anyhow::Result<()>;
}

pub struct LoginAction {}

impl LoginAction {
    pub fn new() -> LoginAction {
        LoginAction {}
    }
    fn login(&self) -> anyhow::Result<bool> {
        let token = auth::login()?;
        store::store_access_token(&token)?;

        let is_unlocked = store::is_unlocked();
        Ok(is_unlocked)
    }
}

impl Action for LoginAction {
    fn execute(&self) -> anyhow::Result<()> {
        match self.login() {
            Ok(is_unlocked) => {
                println!("Logged in successfully. Online vaults in use.");
                if !is_unlocked {
                    println!("Use 'passlane unlock' to unlock the vault.");
                }
            }
            Err(message) => println!("Login failed: {}", message),
        };
        Ok(())
    }
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
    fn save(&self, creds: &CredentialsIn) -> anyhow::Result<()> {
        info!("saving to online vault");
        push_one_credential(&creds)?;
        println!("Saved.");
        Ok(())
    }
    fn add_credential(&self) -> anyhow::Result<(), anyhow::Error> {
        let password = self.get_password().context(format!(
            "Failed to get password {}",
            if self.clipboard { "from clipboard" } else { "" }
        ))?;

        let creds = ui::ask_credentials(&password);
        self.save(&creds)
            .context("failed to save")?;
        if !self.clipboard {
            copy_to_clipboard(&password);
            println!("Password - also copied to clipboard: {}", password);
        };
        Ok(())
    }
    fn add_payment(&self) -> anyhow::Result<()> {
        let encryption_key = get_encryption_key()?;
        let token = get_access_token()?;
        let payment = ui::ask_payment_info();
        online_vault::save_payment(&token.access_token, payment.encrypt(&encryption_key), None)?;
        Ok(())
    }
    fn add_note(&self) -> anyhow::Result<()> {
        let encryption_key = get_encryption_key()?;
        let token = get_access_token()?;
        let note = ui::ask_note_info();
        online_vault::save_note(&token.access_token, &note.encrypt(&encryption_key))?;
        println!("Note saved.");
        Ok(())
    }
}

impl Action for AddAction {
    fn execute(&self) -> anyhow::Result<()> {
        match self.item_type {
            ItemType::Credential => self.add_credential()?,
            ItemType::Payment => self.add_payment()?,
            ItemType::Note => self.add_note()?
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
    fn show_credentials(&self) -> anyhow::Result<()> {
        let grep = match &self.grep {
            Some(grep) => Some(String::from(grep)),
            None => panic!("-g <REGEXP> is required"),
        };
        let matches = find_credentials(grep).context("Failed to find matches. Invalid password? Try unlocking the vault with `passlane unlock`.")?;

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

    fn show_payments(&self) -> anyhow::Result<()> {
        debug!("showing payments");
        let token = get_access_token()?;
        let matches = online_vault::find_payment_cards(&token.access_token)?;
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

    fn show_notes(&self) -> anyhow::Result<()> {
        debug!("showing notes");
        let token = get_access_token()?;
        let matches = online_vault::find_notes(&token.access_token)?;
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
    grep: Option<String>,
) -> anyhow::Result<Vec<Credentials>> {
    info!("searching from online vault");
    let token = get_access_token()?;
    let matches = online_vault::grep(&token.access_token, grep)?;
    if matches.len() == 0 {
        println!("No matches found");
    }
    Ok(matches)
}

impl Action for ShowAction {
    fn execute(&self) -> anyhow::Result<()> {
        match self.item_type {
            ItemType::Credential => self.show_credentials()?,
            ItemType::Payment => self.show_payments()?,
            ItemType::Note => self.show_notes()?
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
    pub fn export_csv(&self) -> anyhow::Result<i64> {
        debug!("exporting to csv");
        return if self.item_type == ItemType::Credential {
            let creds = find_credentials(None)?;
            store::write_credentials_to_csv(&self.file_path, &creds)
        } else if self.item_type == ItemType::Payment {
            let token = get_access_token()?;
            let cards = online_vault::find_payment_cards(&token.access_token)?;
            store::write_payment_cards_to_csv(&self.file_path, &cards)
        } else if self.item_type == ItemType::Note {
            let token = get_access_token()?;
            let notes = online_vault::find_notes(&token.access_token)?;
            store::write_secure_notes_to_csv(&self.file_path, &notes)
        } else {
            Ok(0)
        };
    }
}


impl Action for ExportAction {
    fn execute(&self) -> anyhow::Result<()> {
        match self.export_csv() {
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


fn delete_credentials(grep: &str) -> anyhow::Result<()> {
    let matches = find_credentials(Some(String::from(grep))).context("Unable to get matches. Invalid password? Try unlocking again.")?;

    if matches.len() == 0 {
        debug!("no matches found to delete");
        return Ok(());
    }
    if matches.len() == 1 {
        let token = get_access_token()?;
        online_vault::delete_credentials(&token.access_token, grep, Some(0))?;
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
                    let token = get_access_token()?;
                    online_vault::delete_credentials(&token.access_token, grep, None)?;
                    println!("Deleted all {} matches!", matches.len());
                } else {
                    let token = get_access_token()?;
                    online_vault::delete_credentials(&token.access_token, grep, Some(index as i32))?;
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

fn delete_payment() -> anyhow::Result<()> {
    let token = get_access_token()?;
    let cards = online_vault::find_payment_cards(&token.access_token)?;
    if cards.len() == 0 {
        println!("No payment cards found");
        return Ok(());
    }
    ui::show_payment_cards_table(&cards, false);
    if cards.len() == 1 {
        let response = ui::ask("Do you want to delete this card? (y/n)");
        if response == "y" {
            online_vault::delete_payment_card(&token.access_token, cards[0].id)?;
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
                online_vault::delete_payment_card(&token.access_token, cards[index].id)?;
                println!("Deleted card named '{}'!", cards[index].name);
            }
        }
        Err(message) => {
            println!("{}", message);
        }
    }
    Ok(())
}

fn delete_note() -> anyhow::Result<()> {
    let token = get_access_token()?;
    let notes = online_vault::find_notes(&token.access_token)?;
    if notes.len() == 0 {
        println!("No notes found");
        return Ok(());
    }
    ui::show_notes_table(&notes, false);
    if notes.len() == 1 {
        let response = ui::ask("Do you want to delete this note? (y/n)");
        if response == "y" {
            online_vault::delete_note(&token.access_token, notes[0].id)?;
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
                online_vault::delete_note(&token.access_token, notes[index].id)?;
                println!("Deleted note with title '{}'!", notes[index].title);
            }
        }
        Err(message) => {
            println!("{}", message);
        }
    }
    Ok(())
}


impl Action for DeleteAction {
    fn execute(&self) -> anyhow::Result<()> {
        match self.item_type {
            ItemType::Credential => {
                let grep = match &self.grep {
                    Some(grep) => grep,
                    None => panic!("-g <REGEXP> is required"),
                };
                delete_credentials(grep)?;
            }
            ItemType::Payment => {
                delete_payment()?;
            }
            ItemType::Note => {
                delete_note()?;
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

fn import_csv(file_path: &str) -> anyhow::Result<i64> {
    let encryption_key = get_encryption_key()?;
    info!("importing to the online vault");
    push_from_csv(&encryption_key, file_path)
}

fn push_from_csv(master_pwd: &str, file_path: &str) -> anyhow::Result<i64> {
    let token = get_access_token()?;
    let input = store::read_from_csv(file_path)?;
    let creds = input.into_iter().map(|c| c.to_credentials_in().encrypt(master_pwd)).collect();

    online_vault::push_credentials(
        &token.access_token,
        &creds,
        None,
    )
        ?;
    let num_imported = creds.len();
    Ok(num_imported.try_into().unwrap())
}


impl Action for ImportCsvAction {
    fn execute(&self) -> anyhow::Result<()> {
        match import_csv(&self.file_path) {
            Err(message) => println!("Failed to import: {}", message),
            Ok(count) => println!("Imported {} entries", count),
        }
        Ok(())
    }
}

pub struct UpdateMasterPasswordAction {}

fn migrate(old_pwd: &str, new_pwd: &str) -> anyhow::Result<bool> {
    if store::has_logged_in() {
        debug!("Updating master password in online vault!");
        let token = get_access_token()?;
        let me = get_plain_me(&token.access_token)?;
        let salt = me.get_salt();
        let old_key = derive_encryption_key(&old_pwd, &salt);
        let new_key = derive_encryption_key(&new_pwd, &salt);

        let count =
            online_vault::migrate(&token.access_token, &old_key, &new_key)?;
        store::save_master_password(new_pwd);
        debug!("Updated {} passwords", count);
    }
    Ok(true)
}


impl Action for UpdateMasterPasswordAction {
    fn execute(&self) -> anyhow::Result<()> {
        let old_pwd = ui::ask_master_password(Some("Enter current master password: "));
        let new_pwd = ui::ask_new_password();


        let success = migrate(&old_pwd, &new_pwd).context("Failed to update master password")?;
        if success {
            println!("Password changed");
        } else {
            println!("Failed to change master password");
        }
        Ok(())
    }
}

pub struct GeneratePasswordAction {}


impl Action for GeneratePasswordAction {
    fn execute(&self) -> anyhow::Result<()> {
        let password = crypto::generate();
        copy_to_clipboard(&password);
        println!("Password - also copied to clipboard: {}", password);
        Ok(())
    }
}

pub struct LockAction {}


impl Action for LockAction {
    fn execute(&self) -> anyhow::Result<()> {
        delete_encryption_key()?;
        Ok(())
    }
}

pub struct UnlockAction {}


impl Action for UnlockAction {
    fn execute(&self) -> anyhow::Result<()> {
        let token = get_access_token()?;
        let master_password = ui::ask_master_password(None);
        let me = get_plain_me(&token.access_token)?;

        store::save_encryption_key(&me.get_encryption_key(&master_password))?;
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
    fn execute(&self) -> anyhow::Result<()> {
        let mut out = io::stdout();
        self.cli.clone().write_help(&mut out).context("Failed to display help!")?;
        Ok(())
    }
}