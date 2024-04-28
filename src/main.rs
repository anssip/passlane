extern crate clipboard;
extern crate magic_crypt;
use actions::*;
use clap::{arg, ArgAction, Command};


mod actions;
mod crypto;
mod store;
mod ui;
mod vault;
mod keychain;


use std::env;

fn cli() -> Command {
    Command::new("passlane")
        .about("A password manager using Keepass as the storage backend.")
        .subcommand_required(false)
        .arg_required_else_help(false)
        .allow_external_subcommands(true)
        .subcommand(
            Command::new("add")
                .about("Adds an item to the vault. Without arguments adds a new credential, use -p to add a payment card and -n to add a secure note.")
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

fn main() {
    env_logger::init();
    let matches = cli().get_matches();

    enum ActionOrUnlockingAction {
        Action(Box<dyn Action>),
        UnlockingAction(Box<dyn UnlockingAction>),
    }
    
    let action = match matches.subcommand() {
        Some(("add", sub_matches)) => ActionOrUnlockingAction::UnlockingAction(Box::new(AddAction::new(sub_matches))),
        Some(("show", sub_matches)) => ActionOrUnlockingAction::UnlockingAction(Box::new(ShowAction::new(sub_matches))),
        Some(("delete", sub_matches)) => ActionOrUnlockingAction::UnlockingAction(Box::new(DeleteAction::new(sub_matches))),
        Some(("csv", sub_matches)) => ActionOrUnlockingAction::UnlockingAction(Box::new(ImportCsvAction::new(sub_matches))),
        Some(("lock", _)) => ActionOrUnlockingAction::Action(Box::new(LockAction {})),
        Some(("unlock", _)) => ActionOrUnlockingAction::UnlockingAction(Box::new(UnlockAction {})),
        Some(("export", sub_matches)) => ActionOrUnlockingAction::UnlockingAction(Box::new(ExportAction::new(sub_matches))),
        _ => {
            if env::args().len() == 1 {
                ActionOrUnlockingAction::Action(Box::new(GeneratePasswordAction {}))
            } else {
                ActionOrUnlockingAction::Action(Box::new(PrintHelpAction::new(cli())))
            }
        },
    };
    match action {
        ActionOrUnlockingAction::Action(action) => {
            if let Err(e) = action.run() {
                eprintln!("{}", e);
                std::process::exit(1);
            }
        }
        ActionOrUnlockingAction::UnlockingAction(action) => {
            if let Err(e) = action.execute() {
                eprintln!("{}", e);
                std::process::exit(1);
            }
        }
    }
}
