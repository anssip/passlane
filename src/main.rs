extern crate clipboard;
#[macro_use]
extern crate magic_crypt;
use crate::auth::AccessTokens;
use clap::{arg, ArgAction, Command};

use crate::actions::Action;
use crate::credentials::Credentials;

mod actions;
mod auth;
mod graphql;
mod online_vault;
mod credentials;
mod store;
mod ui;
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
            Command::new("add")
                .about("Adds a new credential to the vault.")
                .arg(arg!(
                    -g --generate "Generate the password to be saved."
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    -c --clipboard "Get the password to save from the clipboard."
                ).action(ArgAction::SetTrue))
        )
        .subcommand(
            Command::new("add-payment")
                .about("Adds a new payment method.")
        )
        .subcommand(
            Command::new("csv")
                .about("Imports credentials from a CSV file.")
                .arg(arg!(<FILE_PATH> "The the CSV file to import."))
        )
        .subcommand(
            Command::new("delete")
                .about("Deletes one or more credentials by searching with the specified regular expression.")
                .arg(arg!(<REGEXP> "The regular expression used to search services whose credentials to delete."))
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
            Command::new("lock")
                .about("Lock the vaults to prevent access to clear-text passwords")
        )
        .subcommand(
            Command::new("unlock")
                .about("Opens the vaults and grants access to clear-text passwords")
        )
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let matches = cli().get_matches();

    match matches.subcommand() {
        Some(("login", _)) => actions::LoginAction::new().execute().await?,
        Some(("add", sub_matches)) => actions::AddAction::new(sub_matches).execute().await?,
        Some(("add-payment", _)) => actions::SavePaymentCardAction {}.execute().await?,
        Some(("show", sub_matches)) => actions::ShowAction::new(sub_matches).execute().await?,
        Some(("delete", sub_matches)) => actions::DeleteAction::new(sub_matches).execute().await?,
        Some(("csv", sub_matches)) => actions::ImportCsvAction::new(sub_matches).execute().await?,
        Some(("password", _)) => actions::UpdateMasterPasswordAction {}.execute().await?,
        Some(("lock", _)) => actions::LockAction {}.execute().await?,
        Some(("unlock", _)) => actions::UnlockAction {}.execute().await?,
        _ => {
            if env::args().len() == 1 {
                actions::GeneratePasswordAction {}.execute().await?;
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
