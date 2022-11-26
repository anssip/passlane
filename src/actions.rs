use async_trait::async_trait;

use crate::auth;
use crate::store;
use tokio::task;

#[async_trait]
pub trait Action {
    async fn execute(&self);
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
    async fn execute(&self) {
        match self.login().await {
            Ok(is_first_login) => {
                println!("Logged in successfully. Online vaults in use.");
                if is_first_login {
                    println!("You can push all your locally stored credentials to the Online Vault with: passlane push");
                }
            }
            Err(message) => println!("Login failed: {}", message),
        }
    }
}
