pub mod commands;
pub mod completer;
pub mod help;

use rustyline::error::ReadlineError;
use rustyline::{Config, Editor};

use crate::actions::add::AddAction;
use crate::actions::delete::DeleteAction;
use crate::actions::edit::EditAction;
use crate::actions::export::ExportAction;
use crate::actions::copy_to_clipboard;
use crate::actions::import::ImportCsvAction;
use crate::actions::init::InitAction;
use crate::actions::lock::LockAction;
use crate::actions::unlock::UnlockAction;
use crate::actions::show::ShowAction;
use crate::actions::{Action, ItemType, UnlockingAction};
use crate::{keychain, store};

use commands::{parse_input, ReplCommand};
use completer::ReplHelper;

const PROMPT: &str = "passlane> ";

fn history_path() -> String {
    let home = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("~"));
    home.join(".passlane").join(".repl_history").to_str().unwrap().to_string()
}

fn print_banner() {
    println!("🔐 Passlane — interactive mode");
    println!("Type 'help' for commands, 'quit' to exit.");
    println!();
}

pub fn start_repl() {
    // First-run detection
    if !store::has_vault_path() {
        println!("Welcome to Passlane! No vault configured — let's set one up.\n");
        let init = InitAction {};
        match init.run() {
            Ok(msg) => println!("{}", msg),
            Err(e) => eprintln!("Init error: {}", e),
        }
        println!();
    }

    print_banner();

    let config = Config::builder()
        .edit_mode(rustyline::EditMode::Emacs)
        .auto_add_history(true)
        .build();

    let mut rl = Editor::with_config(config).unwrap();
    rl.set_helper(Some(ReplHelper));

    // Load history (ignore error if file doesn't exist)
    let hist_path = history_path();
    let _ = rl.load_history(&hist_path);

    loop {
        match rl.readline(PROMPT) {
            Ok(line) => {
                let command = parse_input(&line);
                match command {
                    ReplCommand::Quit => {
                        let _ = rl.save_history(&hist_path);
                        break;
                    }
                    ReplCommand::Empty => continue,
                    _ => {
                        if let Err(e) = dispatch(command) {
                            eprintln!("{}", e);
                        }
                    }
                }
            }
            Err(ReadlineError::Interrupted) => {
                // Ctrl-C: return to prompt
                continue;
            }
            Err(ReadlineError::Eof) => {
                // Ctrl-D: exit
                let _ = rl.save_history(&hist_path);
                break;
            }
            Err(err) => {
                eprintln!("Error: {:?}", err);
                break;
            }
        }
    }
}

fn dispatch(command: ReplCommand) -> Result<(), String> {
    match command {
        ReplCommand::Show { item_type, grep } => {
            let is_totp = item_type == ItemType::Totp;
            let action = ShowAction {
                grep,
                verbose: false,
                item_type,
                is_totp,
                stdout_only: false,
            };
            match action.execute() {
                Ok(Some(msg)) => println!("{}", msg),
                Ok(None) => {}
                Err(e) => return Err(e.message),
            }
        }
        ReplCommand::Add { item_type } => {
            let is_totp = item_type == ItemType::Totp;
            let action = AddAction {
                generate: false,
                clipboard: false,
                item_type,
                is_totp,
            };
            match action.run() {
                Ok(msg) => println!("{}", msg),
                Err(e) => return Err(e.message),
            }
        }
        ReplCommand::Edit { item_type, grep } => {
            if item_type == ItemType::Credential && grep.is_none() {
                return Err("Usage: edit <pattern> — a search pattern is required for credentials".to_string());
            }
            let is_totp = item_type == ItemType::Totp;
            let action = EditAction {
                grep,
                item_type,
                is_totp,
            };
            match action.execute() {
                Ok(Some(msg)) => println!("{}", msg),
                Ok(None) => {}
                Err(e) => return Err(e.message),
            }
        }
        ReplCommand::Delete { item_type, grep } => {
            if item_type == ItemType::Credential && grep.is_none() {
                return Err("Usage: delete <pattern> — a search pattern is required for credentials".to_string());
            }
            let is_totp = item_type == ItemType::Totp;
            let action = DeleteAction {
                grep,
                item_type,
                is_totp,
            };
            match action.execute() {
                Ok(Some(msg)) => println!("{}", msg),
                Ok(None) => {}
                Err(e) => return Err(e.message),
            }
        }
        ReplCommand::Gen => {
            let password = crate::crypto::generate();
            copy_to_clipboard(&password);
            println!("{}", password);
            println!("Password copied to clipboard.");
        }
        ReplCommand::Import { file_path } => {
            let file_path = match file_path {
                Some(p) => p,
                None => return Err("Usage: import <file> — a CSV file path is required".to_string()),
            };
            let action = ImportCsvAction { file_path };
            match action.execute() {
                Ok(Some(msg)) => println!("{}", msg),
                Ok(None) => {}
                Err(e) => return Err(e.message),
            }
        }
        ReplCommand::Export { item_type, file_path } => {
            let file_path = match file_path {
                Some(p) => p,
                None => return Err("Usage: export [type] <file> — a file path is required".to_string()),
            };
            let action = ExportAction { file_path, item_type };
            match action.execute() {
                Ok(Some(msg)) => println!("{}", msg),
                Ok(None) => {}
                Err(e) => return Err(e.message),
            }
        }
        ReplCommand::Lock => {
            let action = LockAction {};
            match action.run() {
                Ok(msg) => println!("{}", msg),
                Err(e) => return Err(e.message),
            }
        }
        ReplCommand::Unlock { totp } => {
            let action = UnlockAction { totp };
            match action.run() {
                Ok(msg) => println!("{}", msg),
                Err(e) => return Err(e.message),
            }
        }
        ReplCommand::Status => {
            print_status();
        }
        ReplCommand::Help { command } => {
            help::print_help(command.as_deref());
        }
        ReplCommand::Unknown(cmd) => {
            return Err(format!("Unknown command: '{}'. Type 'help' for available commands.", cmd));
        }
        ReplCommand::Empty | ReplCommand::Quit => {
            // Already handled in the main loop
        }
    }
    Ok(())
}

fn print_status() {
    let vault_path = store::get_vault_path();
    let totp_vault_path = store::get_totp_vault_path();

    let vault_unlocked = keychain::get_master_password().is_ok();
    let totp_unlocked = keychain::get_totp_master_password().is_ok();

    println!("Vault:      {} ({})", vault_path, if vault_unlocked { "unlocked" } else { "locked" });
    println!("TOTP Vault: {} ({})", totp_vault_path, if totp_unlocked { "unlocked" } else { "locked" });
}
