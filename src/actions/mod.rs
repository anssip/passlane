pub mod add;
pub mod delete;
pub mod export;
pub mod generate;
pub mod help;
pub mod import;
pub mod lock;
pub mod show;
pub mod unlock;

use crate::keychain;
use crate::store;
use crate::ui;
use crate::vault::entities::Error;
use crate::vault::keepass_vault::KeepassVault;
use crate::vault::vault_trait::Vault;
use clap::ArgMatches;
use clipboard::ClipboardContext;
use clipboard::ClipboardProvider;

pub(crate) trait MatchHandlerTemplate
where
    Self::ItemType: Clone,
{
    type ItemType;

    fn pre_handle_matches(&self, matches: &Vec<Self::ItemType>);
    fn handle_one_match(&mut self, the_match: Self::ItemType) -> Result<Option<String>, Error>;
    fn handle_many_matches(
        &mut self,
        matches: Vec<Self::ItemType>,
    ) -> Result<Option<String>, Error>;
}

pub(crate) fn handle_matches<H>(
    matches: Vec<H::ItemType>,
    handler: &mut Box<H>,
) -> Result<Option<String>, Error>
where
    H: MatchHandlerTemplate,
    H::ItemType: Clone,
{
    if matches.is_empty() {
        Ok(Some("No matches found".to_string()))
    } else {
        handler.pre_handle_matches(&matches.clone());

        if matches.len() == 1 {
            handler.handle_one_match(matches[0].clone())
        } else {
            handler.handle_many_matches(matches)
        }
    }
}

pub trait Action {
    fn run(&self) -> Result<String, Error> {
        Ok("Success".to_string())
    }
}

fn get_vault_properties() -> (String, String, Option<String>) {
    let stored_password = keychain::get_master_password();
    let master_pwd = stored_password.unwrap_or_else(|_| ui::ask_master_password(None));
    let filepath = store::get_vault_path();
    let keyfile_path = store::get_keyfile_path();
    (master_pwd, filepath, keyfile_path)
}

fn unlock() -> Result<Box<dyn Vault>, Error> {
    let (master_pwd, filepath, keyfile_path) = get_vault_properties();
    println!("Unlocking vault...");
    get_vault(&master_pwd, &filepath, keyfile_path)
}

fn unlock_totp_vault() -> Result<Box<dyn Vault>, Error> {
    let stored_password = keychain::get_totp_master_password();
    let master_pwd = stored_password.unwrap_or_else(|_| ui::ask_totp_master_password());
    let filepath = store::get_totp_vault_path();
    let keyfile_path = store::get_totp_keyfile_path();
    println!("Unlocking TOTP vault...");
    get_vault(&master_pwd, &filepath, keyfile_path)
}

fn get_vault(
    password: &str,
    filepath: &str,
    keyfile_path: Option<String>,
) -> Result<Box<dyn Vault>, Error> {
    // we could return some other Vault implementation here
    let vault = KeepassVault::new(password, filepath, keyfile_path)?;
    Ok(Box::new(vault))
}

pub fn copy_to_clipboard(value: &str) {
    let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
    ctx.set_contents(String::from(value)).unwrap();
}

pub trait UnlockingAction {
    fn execute(&self) -> Result<Option<String>, Error> {
        if self.is_totp_vault() {
            self.run_with_vault(&mut unlock_totp_vault()?)
        } else {
            self.run_with_vault(&mut unlock()?)
        }
    }

    fn is_totp_vault(&self) -> bool {
        false
    }

    fn run_with_vault(&self, _: &mut Box<dyn Vault>) -> Result<Option<String>, Error> {
        Ok(Some("Success".to_string()))
    }
}

#[derive(PartialEq)]
pub enum ItemType {
    Credential,
    Payment,
    Note,
    Totp,
}

impl ItemType {
    pub fn new_from_args(matches: &ArgMatches) -> ItemType {
        if matches.get_one::<bool>("payments").map_or(false, |v| *v) {
            ItemType::Payment
        } else if matches.get_one("notes").map_or(false, |v| *v) {
            ItemType::Note
        } else if matches.get_one("otp").map_or(false, |v| *v) {
            ItemType::Totp
        } else {
            ItemType::Credential
        }
    }
}
