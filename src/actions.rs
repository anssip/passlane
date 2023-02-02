use crate::credentials::derive_encryption_key;
use crate::online_vault::get_me;
use crate::store::get_encryption_key;
use crate::store::delete_encryption_key;
use crate::AccessTokens;
use crate::Credentials;
use async_trait::async_trait;
use clipboard::ClipboardContext;
use clipboard::ClipboardProvider;

use crate::auth;
use crate::online_vault;
use crate::credentials;
use crate::store;
use crate::ui;
use anyhow::{bail, Context};
use clap::ArgMatches;
use log::{debug, info, warn};
use tokio::task;

pub async fn get_access_token() -> anyhow::Result<AccessTokens> {
    debug!("get_access_token()");
    if !store::has_logged_in() {
        bail!("You are not logged in to the Passlane Online Vault. Please run `passlane login` to login (or signup) first.");
    }
    let token = store::get_access_token()?;
    debug!("Token expired? {}", token.is_expired());
    debug!("Token {}", token);
    if token.is_expired() {
        match auth::exchange_refresh_token(token).await {
            Ok(token) => {
                store::store_access_token(&token)?;
                Ok(token)
            }
            Err(err) => {
                warn!("failed to refresh access token: {}", err);
                let token = task::spawn_blocking(move || auth::login()).await??;
                store::store_access_token(&token)?;
                Ok(token)
            }
        }
    } else {
        Ok(token)
    }
}

async fn push_one_credential(
    credentials: &Credentials,
) -> anyhow::Result<i32> {
    let token = get_access_token().await?;
    let encryption_key = get_encryption_key()?;
    debug!("saving with encryption_key: {}", encryption_key);

    online_vault::push_one_credential(&token.access_token, &credentials.encrypt(&encryption_key), None)
        .await
}

pub fn copy_to_clipboard(value: &String) {
    let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
    ctx.set_contents(String::from(value)).unwrap();
}

#[async_trait]
pub trait Action {
    async fn execute(&self) -> anyhow::Result<()>;
}

pub struct LoginAction {}

impl LoginAction {
    pub fn new() -> LoginAction {
        LoginAction {}
    }
    async fn login(&self) -> anyhow::Result<bool> {
        let token = task::spawn_blocking(move || auth::login()).await??;
        let first_login = !store::has_logged_in();
        store::store_access_token(&token)?;
        Ok(first_login)
    }
}

#[async_trait]
impl Action for LoginAction {
    async fn execute(&self) -> anyhow::Result<()> {
        match self.login().await {
            Ok(is_first_login) => {
                println!("Logged in successfully. Online vaults in use.");
                if is_first_login {
                    println!("You can push all your locally stored credentials to the Online Vault with: passlane push");
                }
            }
            Err(message) => println!("Login failed: {}", message),
        };
        Ok(())
    }
}

pub struct AddAction {
    pub generate: bool,
    pub clipboard: bool,
    pub add_payment: bool,
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
            add_payment: *matches
                .get_one::<bool>("payment")
                .expect("defaulted to false by clap"),

        }
    }
    fn password_from_clipboard(&self) -> anyhow::Result<String> {
        let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
        let value = ctx
            .get_contents()
            .expect("Unable to retrieve value from clipboard");
        if !credentials::validate_password(&value) {
            bail!("The text in clipboard is not a valid password");
        }
        Result::Ok(value)
    }
    fn get_password(&self) -> anyhow::Result<String> {
        if self.generate {
            Ok(credentials::generate())
        } else if self.clipboard {
            self.password_from_clipboard()
        } else {
            Ok(ui::ask_password("Enter password to save: "))
        }
    }
    async fn save(&self, creds: &Credentials) -> anyhow::Result<()> {
        info!("saving to online vault");
        push_one_credential(&creds).await?;
        println!("Saved.");
        Ok(())
    }
    async fn add_credential(&self) -> anyhow::Result<(), anyhow::Error> {
        let password = self.get_password().context(format!(
            "Failed to get password {}",
            if self.clipboard { "from clipboard" } else { "" }
        ))?;
    
        let creds = ui::ask_credentials(&password);
        self.save(&creds)
            .await
            .context("failed to save")?;
        if !self.clipboard {
            copy_to_clipboard(&password);
            println!("Password - also copied to clipboard: {}", password);
        };
        Ok(())
    }
    async fn add_payment(&self) -> anyhow::Result<()> {
        let encryption_key = get_encryption_key()?;
        let token = get_access_token().await?;
        let payment = ui::ask_payment_info();
        online_vault::save_payment(&token.access_token, payment.encrypt(&encryption_key), None).await
    }

}

#[async_trait]
impl Action for AddAction {
    async fn execute(&self) -> anyhow::Result<()> {
        if self.add_payment {
            self.add_payment().await?;
        } else {
            self.add_credential().await?;
        }
        Ok(())
    }
}

pub struct ShowAction {
    pub grep: Option<String>,
    pub verbose: bool,
    pub payments: bool,
}

impl ShowAction {
    pub fn new(matches: &ArgMatches) -> ShowAction {
        ShowAction {
            grep: matches.get_one::<String>("REGEXP").cloned(),
            verbose: *matches
                .get_one::<bool>("verbose")
                .expect("defaulted to false by clap"),
            payments: *matches
                .get_one::<bool>("payments")
                .expect("defaulted to false by clap"),
        }
    }
    async fn show_credentials(&self) -> anyhow::Result<()> {
        let grep = match &self.grep {
            Some(grep) => grep,
            None => panic!("-g <REGEXP> is required"),
        };
        let matches = find_credentials(grep).await.context("Failed to find matches. Invalid password? Try unlocking agin.")?;

        if matches.len() >= 1 {
            println!("Found {} matches:", matches.len());
            ui::show_credentials_table(&matches, self.verbose);
            if matches.len() == 1 {
                copy_to_clipboard(&matches[0].password);
                println!("Password copied to clipboard!",);
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

    async fn show_payments(&self) -> anyhow::Result<()> {
        debug!("showing payments");
        let token = get_access_token().await?;
        let matches = online_vault::find_payment_cards(&token.access_token).await?;
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
                    println!("Card number copied to clipboard!",);
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

}

async fn find_credentials(
    grep_value: &str,
) -> anyhow::Result<Vec<Credentials>> {
    info!("searching from online vault");
    let token = get_access_token().await?;
    let matches =  online_vault::grep(&token.access_token, &grep_value).await?;
    if matches.len() == 0 {
        println!("No matches found");
    }
    Ok(matches)
}

#[async_trait]
impl Action for ShowAction {
    async fn execute(&self) -> anyhow::Result<()> {
        if self.payments {
            self.show_payments().await?;
        } else {
            self.show_credentials().await?;
        }
        Ok(())
    }
}

pub struct DeleteAction {
    pub grep: Option<String>,
    pub payments: bool,
}

impl DeleteAction {
    pub fn new(matches: &ArgMatches) -> DeleteAction {
        DeleteAction {
            grep: matches.get_one::<String>("REGEXP").cloned(),
            payments: *matches
                .get_one::<bool>("payments")
                .expect("defaulted to false by clap"),

        }
    }
}


async fn delete_credentials(grep: &str) -> anyhow::Result<()> {
    let matches = find_credentials(grep).await.context("Unable to get matches. Invalid password? Try unlocking again.")?;

    if matches.len() == 0 {
        debug!("no matches found to delete");
        return Ok(());
    }
    if matches.len() == 1 {
        let token = get_access_token().await?;
        online_vault::delete_credentials(&token.access_token, grep, Some(0)).await?;
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
                    let token = get_access_token().await?;
                    online_vault::delete_credentials(&token.access_token, grep, None).await?;            
                    println!("Deleted all {} matches!", matches.len());
                    
                } else {
                    let token = get_access_token().await?;
                    online_vault::delete_credentials(&token.access_token, grep, Some(index as i32)).await?;            
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

async fn delete_payment() -> anyhow::Result<()> {
    let token = get_access_token().await?;
    let cards = online_vault::find_payment_cards(&token.access_token).await?;
    if cards.len() == 0 {
        println!("No payment cards found");
        return Ok(());
    }
    ui::show_payment_cards_table(&cards, false);
    if cards.len() == 1 {
        let response = ui::ask("Do you want to delete this card? (y/n)");
        if response == "y" {
            online_vault::delete_payment_card(&token.access_token, cards[0].id).await?;            
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
                online_vault::delete_payment_card(&token.access_token, cards[index].id).await?;            
                println!("Deleted card named '{}'!", cards[index].name);
            }
        }
        Err(message) => {
            println!("{}", message);
        }
    }
    Ok(())
}

#[async_trait]
impl Action for DeleteAction {
    async fn execute(&self) -> anyhow::Result<()> {
        if self.payments {
            delete_payment().await?;
        } else {
            let grep = match &self.grep {
                Some(grep) => grep,
                None => panic!("-g <REGEXP> is required"),
            };    
            delete_credentials(grep).await?;
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

async fn import_csv(file_path: &str) -> anyhow::Result<i64> {
    let master_pwd = ui::ask_master_password(None);
    info!("importing to the online vault");
    push_from_csv(&master_pwd, file_path).await
}

async fn push_from_csv(master_pwd: &str, file_path: &str) -> anyhow::Result<i64> {
    let token = get_access_token().await?;
    let credentials = store::read_from_csv(file_path)?;
    online_vault::push_credentials(
        &token.access_token,
        &credentials::encrypt_all(master_pwd, &credentials),
        None,
    )
    .await?;
    let num_imported = credentials.len();
    Ok(num_imported.try_into().unwrap())
}

#[async_trait]
impl Action for ImportCsvAction {
    async fn execute(&self) -> anyhow::Result<()> {
        match import_csv(&self.file_path).await {
            Err(message) => println!("Failed to import: {}", message),
            Ok(count) => println!("Imported {} entries", count),
        }
        Ok(())
    }
}

pub struct UpdateMasterPasswordAction { }

async fn migrate(old_pwd: &str, new_pwd: &str) -> anyhow::Result<bool> {
    if store::has_logged_in() {
        debug!("Updating master password in online vault!");
        let token = get_access_token().await?;
        let me = get_me(&token.access_token).await?;
        let salt = me.get_salt();
        let old_key = derive_encryption_key(&old_pwd, &salt);
        let new_key = derive_encryption_key(&new_pwd, &salt);

        let count =
            online_vault::migrate(&token.access_token, &old_key, &new_key).await?;
        store::save_master_password(new_pwd);
        debug!("Updated {} passwords", count);
    } else {
        store::update_master_password(old_pwd, new_pwd)?;
    }
    Ok(true)
}

#[async_trait]                                                                      
impl Action for UpdateMasterPasswordAction {
    async fn execute(&self) -> anyhow::Result<()> {
        let old_pwd = ui::ask_master_password("Enter current master password: ".into());
        let new_pwd = ui::ask_new_password();


        let success = migrate(&old_pwd, &new_pwd)
            .await
            .context("Failed to update master password")?;
        if success {
            println!("Password changed");
        } else {
            println!("Failed to change master password");
        }
        Ok(())
    }
}

pub struct GeneratePasswordAction {}

#[async_trait]
impl Action for GeneratePasswordAction {
    async fn execute(&self) -> anyhow::Result<()> {
        let password = credentials::generate();
        copy_to_clipboard(&password);
        println!("Password - also copied to clipboard: {}", password);
        Ok(())
    }
}

pub struct LockAction {}

#[async_trait]
impl Action for LockAction {
    async fn execute(&self) -> anyhow::Result<()> {
        delete_encryption_key()?;
        Ok(())
    }
}

pub struct UnlockAction {}

#[async_trait]
impl Action for UnlockAction {
    async fn execute(&self) -> anyhow::Result<()> {
        let token = get_access_token().await?;
        let master_password = ui::ask_master_password(None);
        let me = online_vault::get_me(&token.access_token).await?;

        store::save_encryption_key(&me.get_encryption_key(&master_password))?;
        Ok(())
    }
}
