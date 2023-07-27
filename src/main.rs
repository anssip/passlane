extern crate clipboard;
#[macro_use]
extern crate magic_crypt;
use crate::auth::AccessTokens;
use actions::*;
use clap::{arg, ArgAction, Command};

use crate::graphql::queries::types::*;

mod actions;
mod auth;
mod crypto;
mod graphql;
mod online_vault;
mod store;
mod ui;
use std::env;

fn cli() -> Command {
    Command::new("passlane")
        .about("A password manager and a CLI client for the online Passlane Vault")
        .subcommand_required(false)
        .arg_required_else_help(false)
        .allow_external_subcommands(true)
        .subcommand(
            Command::new("login")
                .about("Login to the online vault.")
        )
        .subcommand(
            Command::new("password")
                .about("Change the master password.")
        )
        .subcommand(
            Command::new("add")
                .about("Adds an item to the vault. Without arguments adds a new credential, use -p to add a payment card.")
                .arg(arg!(
                    -p --payments "Add a payment card."
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    -n --notes "Add a secure note."
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
                .arg(arg!(
                    -n --notes "Delete secure notes."
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
                    -n --notes "Shows secure notes."
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    -c --credentials "Shows credentials by searching with the specified regular expression."
                ).action(ArgAction::SetTrue).requires("search"))
                .arg(arg!(<REGEXP> "Regular expression used to search services to show.").group("search").required(false))
                .arg_required_else_help(true)
        )
        .subcommand(
            Command::new("lock")
                .about("Lock the vaults to prevent all access")
        )
        .subcommand(
            Command::new("unlock")
                .about("Opens the vaults and grants access to the entries")
        )
        .subcommand(
            Command::new("export")
                .about("Exports the vault contents to a CSV file.")
                .arg(arg!(
                    -p --payments "Exporet payment cards."
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    -n --notes "Export secure notes."
                ).action(ArgAction::SetTrue))
                .arg(arg!(<file_path> "The the CSV file to export to."))
        )
}

#[tokio::main]
async fn main() -> () {
    env_logger::init();
    let matches = cli().get_matches();

    let action: Box<dyn Action> = match matches.subcommand() {
        Some(("login", _)) => Box::new(LoginAction::new()),
        Some(("add", sub_matches)) => Box::new(AddAction::new(sub_matches)),
        Some(("show", sub_matches)) => Box::new(ShowAction::new(sub_matches)),
        Some(("delete", sub_matches)) => Box::new(DeleteAction::new(sub_matches)),
        Some(("csv", sub_matches)) => Box::new(ImportCsvAction::new(sub_matches)),
        Some(("password", _)) => Box::new(UpdateMasterPasswordAction {}),
        Some(("lock", _)) => Box::new(LockAction {}),
        Some(("unlock", _)) => Box::new(UnlockAction {}),
        Some(("export", sub_matches)) => Box::new(ExportAction::new(sub_matches)),
        _ => {
            if env::args().len() == 1 {
                Box::new(GeneratePasswordAction {})
            } else {
                Box::new(PrintHelpAction::new(cli()))
            }
        },
    };
    match action.execute().await {
        Ok(_) => (),
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };
}
