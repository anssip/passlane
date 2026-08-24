mod actions;
mod completion_cache;
mod crypto;
mod hwkey;
mod keychain;
mod repl;
mod store;
mod ui;
mod vault;
mod vault_registry;

use crate::actions::add::AddAction;
use crate::actions::change_password::ChangePasswordAction;
use crate::actions::completions::CompletionsAction;
use crate::actions::delete::DeleteAction;
use crate::actions::edit::EditAction;
use crate::actions::export::ExportAction;
use crate::actions::generate::GeneratePasswordAction;
use crate::actions::help::PrintHelpAction;
use crate::actions::hwkey::HwKeyAction;
use crate::actions::import::ImportCsvAction;
use crate::actions::list::ListAction;
use crate::actions::lock::LockAction;
use crate::actions::show::ShowAction;
use crate::actions::unlock::UnlockAction;
use crate::actions::vault::VaultAction;
use actions::*;
use clap::{arg, ArgAction, Command};
use init::InitAction;
use std::env;

pub fn cli() -> Command {
    Command::new("passlane")
        .about("A password manager using Keepass as the storage backend.")
        .subcommand_required(false)
        .arg_required_else_help(false)
        .allow_external_subcommands(true)
        .arg(
            arg!(--vault <NAME> "Name of the vault to use for this command. Defaults to $PASSLANE_VAULT, then the active vault (see 'passlane vault use').")
                .global(true)
                .env("PASSLANE_VAULT"),
        )
        .subcommand(
            Command::new("init")
                .about("Initialize passlane. Walks you through the configuration process.")
        )
        .subcommand(
            Command::new("vault")
                .about("Manage vaults: list them, add one, switch the active vault, remove or rename.")
                .subcommand(
                    Command::new("list")
                        .about("List configured vaults and their state.")
                )
                .subcommand(
                    Command::new("add")
                        .about("Create a new vault or register an existing vault file.")
                        .arg(arg!([NAME] "Name for the vault, e.g. personal, work, family."))
                )
                .subcommand(
                    Command::new("use")
                        .about("Make a vault the active one used by default.")
                        .alias("switch")
                        .arg(arg!(<NAME> "Vault name."))
                )
                .subcommand(
                    Command::new("remove")
                        .about("Remove a vault from the configuration. The vault file is not deleted.")
                        .arg(arg!(<NAME> "Vault name."))
                )
                .subcommand(
                    Command::new("rename")
                        .about("Rename a vault.")
                        .arg(arg!(<OLD_NAME> "Current vault name."))
                        .arg(arg!(<NEW_NAME> "New vault name."))
                )
                .subcommand(
                    Command::new("info")
                        .about("Show details of a vault. Defaults to the active vault.")
                        .arg(arg!([NAME] "Vault name."))
                )
        )
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
                    -o --otp "Add a One Time Password authorizer."
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    -g --generate "Generate the password to be saved."
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    -l --clipboard "Get the password to save from the clipboard."
                ).action(ArgAction::SetTrue))
        )
        .subcommand(
            Command::new("edit")
                .about("Edit an entry.")
                .arg(arg!(-c --credentials "Edit credentials.").action(ArgAction::SetTrue).requires("search"))
                .arg(arg!(-p --payments "Edit payment cards.").action(ArgAction::SetTrue))
                .arg(arg!(-n --notes "Edit secure notes.").action(ArgAction::SetTrue))
                .arg(arg!(-o --otp "Edit One Time Password authorizer.").action(ArgAction::SetTrue))
                .arg(arg!(<REGEXP> "The regular expression used to search services whose credentials to edit.").group("search").required(false))
                .arg_required_else_help(true)
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
                .arg(arg!(
                    -o --otp "Delete One Time Password authorizer."
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
                    -o --otp "Shows one time passwords (OTPs)"
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    -n --notes "Shows secure notes."
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    -c --credentials "Shows credentials by searching with the specified regular expression."
                ).action(ArgAction::SetTrue).requires("search"))
                .arg(arg!(
                    --out "Print password to stdout instead of copying to clipboard."
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    --plain "Render tables without borders for narrower output."
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    --once "With -o, print the single matching OTP code to stdout and exit (no clipboard, no countdown). Errors if zero or multiple authorizers match. The code is valid only briefly."
                ).action(ArgAction::SetTrue))
                .arg(arg!(<REGEXP> "Regular expression used to search services to show.").group("search").required(false))
                .arg_required_else_help(true)
        )
        .subcommand(
            Command::new("list")
                .about("Lists entries from the vault for scripting and automation. WARNING: outputs passwords to stdout.")
                .arg(arg!(
                    --json "Output as JSON"
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    -v --verbose "Show full details in plain text output."
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    -p --payments "List payment cards."
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    -n --notes "List secure notes."
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    -o --otp "List TOTP entries."
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    -c --credentials "List credentials (default)."
                ).action(ArgAction::SetTrue))
                .arg(arg!(
                    --code "With -o, output the currently generated TOTP code for each match instead of the stored secret. Codes are valid only briefly (see valid_for_seconds)."
                ).action(ArgAction::SetTrue))
                .arg(arg!(<REGEXP> "Regular expression to filter entries.").required(false))
        )
        .subcommand(
            Command::new("lock")
                .about("Lock a vault by removing its stored master password. Use --all to lock every vault.")
                .arg(arg!(
                    --all "Lock all configured vaults."
                ).action(ArgAction::SetTrue))
        )
        .subcommand(
            Command::new("unlock")
                .about("Unlock a vault: open it and store the master password in the keychain.")
                .arg(arg!(
                    -o --otp "Legacy alias for --vault totp, the vault that held the one-time passwords before multi-vault support."
                ).action(ArgAction::SetTrue))
        )
        .subcommand(
            Command::new("passwd")
                .about("Change the master password of the vault.")
                .arg(arg!(
                    -o --otp "Legacy alias for --vault totp, the vault that held the one-time passwords before multi-vault support."
                ).action(ArgAction::SetTrue))
        )
        .subcommand(
            Command::new("hwkey")
                .about("Manage the hardware key (e.g. a YubiKey) that protects a vault with challenge-response.")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(
                    Command::new("add")
                        .about("Enroll a hardware key as an additional unlock factor for the main vault.")
                        .long_about("Enrolls one of the key's HMAC-SHA1 challenge-response slots (program it first with e.g. 'ykman otp chalresp'). The vault then opens only with the master password (and keyfile) plus this key; every save needs a touch.")
                        .arg(arg!(
                            --slot <SLOT> "Challenge-response slot to use (1 or 2)."
                        ).value_parser(["1", "2"]))
                        .arg(arg!(
                            --serial <SERIAL> "Serial number of the key to enroll, when several are connected."
                        ).value_parser(clap::value_parser!(u32)))
                )
                .subcommand(
                    Command::new("remove")
                        .about("Remove the hardware key from the main vault.")
                        .arg(arg!(
                            --secret "Recover with the backed-up HMAC-SHA1 slot secret instead of the (lost) hardware key."
                        ).action(ArgAction::SetTrue))
                )
                .subcommand(
                    Command::new("status")
                        .about("Show the enrolled hardware key configuration and connected keys.")
                )
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
                .arg(arg!(
                    -o --otp "Shows one time passwords (OTPs)"
                ).action(ArgAction::SetTrue))
                .arg(arg!(<file_path> "The the CSV file to export to."))
        )
        .subcommand(
            Command::new("gen")
                .about("Generate a random password and copy it to the clipboard.")
                .arg(arg!(
                    --out "Print password to stdout instead of copying to clipboard."
                ).action(ArgAction::SetTrue))
        )
        .subcommand(
            Command::new("repl")
                .about("Launch the interactive REPL session.")
        )
        .subcommand(
            Command::new("completions")
                .about("Generate shell completions and save to ~/.passlane/. Shows the line to add to your shell rc file.")
                .arg(arg!([SHELL] "Target shell (bash, zsh, fish). Auto-detected from $SHELL if omitted."))
        )

}

/// The vault a command targets: the --vault flag or $PASSLANE_VAULT first,
/// then the legacy unlock -o / passwd -o alias for the migrated TOTP vault.
fn explicit_vault(matches: &clap::ArgMatches) -> Option<String> {
    if let Some(name) = matches.get_one::<String>("vault") {
        return Some(name.clone());
    }
    match matches.subcommand() {
        Some(("unlock", sub)) | Some(("passwd", sub))
            if sub.get_one::<bool>("otp").map_or(false, |v| *v) =>
        {
            Some("totp".to_string())
        }
        _ => None,
    }
}

fn main() {
    env_logger::init();
    let matches = cli().get_matches();

    // Migrate the pre-multi-vault configuration before anything reads it.
    if let Err(e) = vault_registry::migrate_legacy() {
        eprintln!("{}", e);
        std::process::exit(1);
    }
    // Pick the target vault up front so every action, including the REPL,
    // works on the same vault. An explicitly named vault must resolve or the
    // command aborts; the implicit (active) vault may be missing for commands
    // like init or gen, which surface the error later via current().
    // Vault-management commands, vault-independent commands and the REPL are
    // exempt: a stale --vault/PASSLANE_VAULT name must not lock the user out
    // of the very commands ('vault list', 'vault add', 'init') that fix the
    // situation — and inside the REPL, 'vault use <name>' recovers. Exempted
    // commands fall back to the active (or only) vault when the explicit
    // name doesn't resolve.
    let subcommand = matches.subcommand().map(|(name, _)| name);
    let is_bare_repl = subcommand.is_none() && env::args().len() == 1;
    let needs_vault =
        !matches!(subcommand, Some("vault" | "init" | "gen" | "completions" | "repl"))
            && !is_bare_repl;
    if let Some(name) = explicit_vault(&matches) {
        if let Err(e) = vault_registry::init_current(Some(name.as_str())) {
            if needs_vault {
                eprintln!("{}", e);
                std::process::exit(1);
            }
            eprintln!(
                "Warning: ignoring the unknown vault '{}' — using the active vault instead.",
                name
            );
            let _ = vault_registry::init_current(None);
        }
    } else if let Err(e) = vault_registry::init_current(None) {
        // Fail fast with the actionable resolution error (e.g. "several
        // vaults are configured and none is active") instead of letting the
        // command die later on the generic "No vault selected".
        if needs_vault {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    }
    completion_cache::refresh_if_stale();

    enum RoutedAction {
        Action(Box<dyn Action>),
        UnlockingAction(Box<dyn UnlockingAction>),
    }

    let action = match matches.subcommand() {
        Some(("init", _)) => RoutedAction::Action(Box::new(InitAction {})),
        Some(("vault", sub_matches)) => {
            RoutedAction::Action(Box::new(VaultAction::new(sub_matches)))
        }
        Some(("add", sub_matches)) => RoutedAction::Action(Box::new(AddAction::new(sub_matches))),
        Some(("show", sub_matches)) => {
            RoutedAction::UnlockingAction(Box::new(ShowAction::new(sub_matches)))
        }
        Some(("list", sub_matches)) => {
            RoutedAction::UnlockingAction(Box::new(ListAction::new(sub_matches)))
        }
        Some(("delete", sub_matches)) => {
            RoutedAction::UnlockingAction(Box::new(DeleteAction::new(sub_matches)))
        }
        Some(("csv", sub_matches)) => {
            RoutedAction::UnlockingAction(Box::new(ImportCsvAction::new(sub_matches)))
        }
        Some(("lock", sub_matches)) => RoutedAction::Action(Box::new(LockAction::new(
            sub_matches.get_one::<bool>("all").map_or(false, |v| *v),
        ))),
        Some(("unlock", _)) => RoutedAction::Action(Box::new(UnlockAction::new())),
        Some(("passwd", _)) => RoutedAction::Action(Box::new(ChangePasswordAction::new())),
        Some(("hwkey", sub_matches)) => {
            RoutedAction::Action(Box::new(HwKeyAction::new(sub_matches)))
        }
        Some(("export", sub_matches)) => {
            RoutedAction::UnlockingAction(Box::new(ExportAction::new(sub_matches)))
        }
        Some(("edit", sub_matches)) => {
            RoutedAction::UnlockingAction(Box::new(EditAction::new(sub_matches)))
        }
        Some(("gen", sub_matches)) => {
            RoutedAction::Action(Box::new(GeneratePasswordAction::new(sub_matches)))
        }
        Some(("completions", sub_matches)) => {
            let shell = sub_matches.get_one::<String>("SHELL").cloned();
            RoutedAction::Action(Box::new(CompletionsAction::new(shell, cli())))
        }
        Some(("repl", _)) => {
            repl::start_repl();
            return;
        }
        _ => {
            if env::args().len() == 1 {
                repl::start_repl();
                return;
            } else {
                RoutedAction::Action(Box::new(PrintHelpAction::new(cli())))
            }
        }
    };
    match action {
        RoutedAction::Action(action) => {
            action
                .run()
                .map(|msg| println!("{}", msg))
                .unwrap_or_else(|e| {
                    eprintln!("{}", e);
                    std::process::exit(1);
                });
        }
        RoutedAction::UnlockingAction(action) => {
            action
                .execute()
                .map(|msg| println!("{}", msg.unwrap_or("".to_string())))
                .unwrap_or_else(|e| {
                    eprintln!("{}", e);
                    std::process::exit(1);
                });
        }
    }
}
