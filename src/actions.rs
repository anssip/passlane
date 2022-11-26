use crate::AccessTokens;
use crate::Credentials;
use async_trait::async_trait;
use clipboard::ClipboardContext;
use clipboard::ClipboardProvider;

use crate::auth;
use crate::keychain;
use crate::online_vault;
use crate::password;
use crate::store;
use crate::ui;
use anyhow::{bail, Context};
use clap::ArgMatches;
use log::{debug, info, warn};
use tokio::task;

pub async fn get_access_token() -> anyhow::Result<AccessTokens> {
    debug!("get_access_token()");
    if !store::has_logged_in() {
        bail!("You are not logged in to the Passlane Online Vault. Please run `passlane -l` to login (or signup) first.");
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
                let token = auth::login()?;
                store::store_access_token(&token)?;
                Ok(token)
            }
        }
    } else {
        Ok(token)
    }
}

async fn push_one_credential(
    master_pwd: &String,
    credentials: &Credentials,
) -> anyhow::Result<i32> {
    let token = get_access_token().await?;
    online_vault::push_one_credential(&token.access_token, &credentials.encrypt(master_pwd), None)
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
    pub keychain: bool,
    pub generate: bool,
    pub clipboard: bool,
}

impl AddAction {
    fn password_from_clipboard(&self) -> anyhow::Result<String> {
        let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
        let value = ctx
            .get_contents()
            .expect("Unable to retrieve value from clipboard");
        if !password::validate_password(&value) {
            bail!("The text in clipboard is not a valid password");
        }
        Result::Ok(value)
    }
    fn get_password(&self) -> anyhow::Result<String> {
        if self.generate {
            Ok(password::generate())
        } else if self.clipboard {
            self.password_from_clipboard()
        } else {
            Ok(ui::ask_password("Enter password to save: "))
        }
    }
    async fn save(&self, master_pwd: &String, creds: &Credentials) -> anyhow::Result<()> {
        if store::has_logged_in() {
            info!("saving to online vault");
            push_one_credential(master_pwd, &creds).await?;
        } else {
            info!("saving to local file");
            store::save(master_pwd, creds);
        }
        if self.keychain {
            keychain::save(&creds).expect("Unable to store credentials to keychain");
        }
        println!("Saved.");
        Ok(())
    }
}

impl AddAction {
    pub fn new(matches: &ArgMatches) -> AddAction {
        AddAction {
            keychain: *matches
                .get_one::<bool>("keychain")
                .expect("defaulted to false by clap"),
            generate: *matches
                .get_one::<bool>("generate")
                .expect("defaulted to false by clap"),
            clipboard: *matches
                .get_one::<bool>("clipboard")
                .expect("defaulted to false by clap"),
        }
    }
}

#[async_trait]
impl Action for AddAction {
    async fn execute(&self) -> anyhow::Result<()> {
        let password = self.get_password().context(format!(
            "Failed to get password {}",
            if self.clipboard { "from clipboard" } else { "" }
        ))?;

        let creds = ui::ask_credentials(&password);
        let master_pwd = ui::ask_master_password(None);
        self.save(&master_pwd, &creds)
            .await
            .context("failed to save")?;
        if !self.clipboard {
            copy_to_clipboard(&password);
            println!("Password - also copied to clipboard: {}", password);
        };
        Ok(())
    }
}
