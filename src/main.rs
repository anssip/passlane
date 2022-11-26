extern crate clipboard;
#[macro_use]
extern crate magic_crypt;
use crate::auth::AccessTokens;
use anyhow::Context;
use clap::{arg, ArgAction, Command};

use crate::actions::Action;
use crate::password::Credentials;

mod actions;
mod auth;
mod graphql;
mod keychain;
mod online_vault;
mod password;
mod store;
mod ui;
use log::{debug, info};
use std::env;
use std::io;

fn cli() -> Command<'static> {
    Command::new("passlane")
        .about("A password manager and a CLI client for the online Passlane Vault")
        .subcommand_required(false)
        .arg_required_else_help(false)
        .allow_external_subcommands(true)
        .subcommand(
            Command::new("login")
                .about("Login to passlanevault.com")
        )
        .subcommand(
            Command::new("password")
                .about("Change the master password.")
        )
        .subcommand(
            Command::new("push")
                .about("Pushes all local credentials to the online vault.")
        )
        .subcommand(
            Command::new("add")
                .about("Adds a new credential to the vault.")
                .arg(arg!(
                    -g --generate "Generate the password to be saved."
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    -c --clipboard "Get the password to save from the clipboard."
                ).action(ArgAction::SetTrue))
                .arg(keychain_arg())
        )
        .subcommand(
            Command::new("csv")
                .about("Imports credentials from a CSV file.")
                .arg(arg!(<FILE_PATH> "The the CSV file to import."))
        )
        .subcommand(
            Command::new("keychain-push")
                .about("Pushes all credentials to the OS specific keychain.")
        )
        .subcommand(
            Command::new("delete")
                .about("Deletes one or more credentials by searching with the specified regular expression.")
                .arg(arg!(<REGEXP> "The regular expression used to search services whose credentials to delete."))
                .arg(keychain_arg())
                .arg_required_else_help(true)
        )
        .subcommand(
            Command::new("show")
                .about("Shows one or more credentials by searching with the specified regular expression.")
                .arg(arg!(<REGEXP> "The regular expression used to search services to show.").required(true))
                .arg(arg!(
                    -v --verbose "Verbosely display the passwords when grep option finds several matches."
                ).action(ArgAction::SetTrue))
                .arg_required_else_help(true)
        )
        .subcommand(
            Command::new("migrate")
                .about("Migrate from legacy local credential store to passlane version 1.0 format")
        )
}

fn keychain_arg() -> clap::Arg<'static> {
    arg!(-k --keychain "Adds also to OS keychain").action(ArgAction::SetTrue)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let matches = cli().get_matches();

    match matches.subcommand() {
        Some(("login", _)) => actions::LoginAction::new().execute().await?,
        Some(("push", _)) => actions::PushAction {}.execute().await?,
        Some(("add", sub_matches)) => actions::AddAction::new(sub_matches).execute().await?,
        Some(("show", sub_matches)) => actions::ShowAction::new(sub_matches).execute().await?,
        Some(("delete", sub_matches)) => actions::DeleteAction::new(sub_matches).execute().await?,
        Some(("csv", sub_matches)) => {
            let file_path = sub_matches.value_of("FILE_PATH").expect("required");

            match import_csv(&file_path).await {
                Err(message) => println!("Failed to import: {}", message),
                Ok(count) => println!("Imported {} entries", count),
            }
        }
        Some(("password", _)) => {
            let old_pwd = ui::ask_master_password("Enter current master password: ".into());
            let new_pwd = ui::ask_new_password();
            let success = update_master_password(&old_pwd, &new_pwd)
                .await
                .context("Failed to update master password")?;
            if success {
                println!("Password changed");
            } else {
                println!("Failed to change master password");
            }
        }
        Some(("keychain-push", _)) => {
            let master_pwd = ui::ask_master_password(None);
            let creds = store::get_all_credentials();
            match keychain::save_all(&creds, &master_pwd) {
                Ok(len) => println!("Synced {} entries", len),
                Err(message) => println!("Failed to sync: {}", message),
            }
        }
        Some(("migrate", _)) => {
            let pwd = ui::ask_master_password(None);
            let count = store::migrate(&pwd)?;
            println!("Migrated {} credentials", count);
        }
        _ => {
            if env::args().len() == 1 {
                let password = password::generate();
                actions::copy_to_clipboard(&password);
                println!("Password - also copied to clipboard: {}", password);
            } else {
                let mut out = io::stdout();
                cli()
                    .write_help(&mut out)
                    .expect("failed to write to stdout");
            }
        }
    }
    Ok(())
}

async fn push_from_csv(master_pwd: &str, file_path: &str) -> anyhow::Result<i64> {
    let token = actions::get_access_token().await?;
    let credentials = store::read_from_csv(file_path)?;
    online_vault::push_credentials(
        &token.access_token,
        &password::encrypt_all(master_pwd, &credentials),
        None,
    )
    .await?;
    let num_imported = credentials.len();
    Ok(num_imported.try_into().unwrap())
}

async fn import_csv(file_path: &str) -> anyhow::Result<i64> {
    let master_pwd = ui::ask_master_password(None);
    if store::has_logged_in() {
        info!("importing to the online vault");
        push_from_csv(&master_pwd, file_path).await
    } else {
        info!("importing to local file");
        store::import_csv(file_path, &master_pwd)
    }
}

async fn update_master_password(old_pwd: &str, new_pwd: &str) -> anyhow::Result<bool> {
    if store::has_logged_in() {
        debug!("Updating master password in online vault!");
        let token = actions::get_access_token().await?;
        let count =
            online_vault::update_master_password(&token.access_token, old_pwd, new_pwd).await?;
        store::save_master_password(new_pwd);
        debug!("Updated {} passwords", count);
    } else {
        store::update_master_password(old_pwd, new_pwd);
    }
    Ok(true)
}
