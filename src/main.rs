extern crate clipboard;
#[macro_use]
extern crate magic_crypt;
use crate::auth::AccessTokens;
use clap::{arg, ArgAction, Command};

use crate::actions::Action;
use crate::credentials::Credentials;

mod actions;
mod auth;
mod credentials;
mod graphql;
mod online_vault;
mod store;
mod ui;
use std::env;
use std::io;

fn cli() -> Command {
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
                .about("Adds an item to the vault. Without arguments adds a new credential, use -p to add a payemtn card.")
                .arg(arg!(
                    -p --payment "Add a payment card."
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    -g --generate "Generate the password to be saved."
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    -l --clipboard "Get the password to save from the clipboard."
                ).action(ArgAction::SetTrue))
        )
        .subcommand(
            Command::new("csv")
                .about("Imports credentials from a CSV file.")
                .arg(arg!(<FILE_PATH> "The the CSV file to import."))
        )
        .subcommand(
            Command::new("delete")
                .about("Deletes one or more entries.")
                .arg(arg!(
                    -c --credentials "Delete credentials."
                ).action(ArgAction::SetTrue).requires("search"))
                .arg(arg!(
                    -p --payments "Delete payment cards."
                ).action(ArgAction::SetTrue))
                .arg(arg!(<REGEXP> "The regular expression used to search services whose credentials to delete.").group("search").required(false))
                .arg_required_else_help(true)
            )
        .subcommand(
            Command::new("show")
                .about("Shows one or more entries.")
                .arg(arg!(
                    -v --verbose "Verbosely display matches table in clear text."
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    -p --payments "Shows payment cards."
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    -c --credentials "Shows credentials by searching with the specified regular expression."
                ).action(ArgAction::SetTrue).requires("search"))
                .arg(arg!(<REGEXP> "Regular expression used to search services to show.").group("search").required(false))
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
