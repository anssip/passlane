pub mod commands;
pub mod completer;
pub mod help;

use std::sync::{Arc, Mutex};

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
use crate::completion_cache;
use crate::{keychain, store};

use commands::{parse_input, ReplCommand};
use completer::ReplHelper;

const PROMPT: &str = "passlane> ";

fn history_path() -> String {
    let home = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("~"));
    home.join(".passlane").join(".repl_history").to_str().unwrap().to_string()
}

/// History reveals which services the user has accounts with — keep it 0o600.
#[cfg(unix)]
fn restrict_history_permissions(path: &str) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        eprintln!("Warning: could not restrict permissions on '{}': {}", path, e);
    }
}

#[cfg(not(unix))]
fn restrict_history_permissions(_path: &str) {}

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

    // Initialize shared entry names for tab completion
    let entry_names = Arc::new(Mutex::new(load_entry_names()));

    let config = Config::builder()
        .edit_mode(rustyline::EditMode::Emacs)
        .auto_add_history(true)
        .build();

    let mut rl = Editor::with_config(config).unwrap();
    rl.set_helper(Some(ReplHelper::new(entry_names.clone())));

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
                        restrict_history_permissions(&hist_path);
                        break;
                    }
                    ReplCommand::Empty => continue,
                    _ => {
                        let should_refresh = is_vault_modifying(&command);
                        if let Err(e) = dispatch(command) {
                            eprintln!("{}", e);
                        } else if should_refresh {
                            refresh_entry_names(&entry_names);
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
                restrict_history_permissions(&hist_path);
                break;
            }
            Err(err) => {
                eprintln!("Error: {:?}", err);
                break;
            }
        }
    }
}

/// Load entry names from the completion cache (populated by unlock/modify actions)
fn load_entry_names() -> Vec<String> {
    completion_cache::read_cache()
}

/// Refresh the shared entry name list from the cache
fn refresh_entry_names(entry_names: &Arc<Mutex<Vec<String>>>) {
    let names = load_entry_names();
    if let Ok(mut locked) = entry_names.lock() {
        *locked = names;
    }
}

/// Check if a command modifies the vault (and should trigger entry name refresh)
fn is_vault_modifying(command: &ReplCommand) -> bool {
    matches!(
        command,
        ReplCommand::Add { .. }
            | ReplCommand::Edit { .. }
            | ReplCommand::Delete { .. }
            | ReplCommand::Import { .. }
            | ReplCommand::Unlock { .. }
    )
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
                plain: false,
                once: false,
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
        ReplCommand::Completions => {
            print_completions_instructions();
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

fn print_completions_instructions() {
    let instructions = r#"
Shell completions let you press Tab to auto-complete passlane commands and flags.

To set up completions, run this from your terminal (not the REPL):

  passlane completions

This auto-detects your shell, saves the completion script to ~/.passlane/,
and tells you which line to add to your shell rc file.

You can also specify a shell explicitly:

  passlane completions bash
  passlane completions zsh
  passlane completions fish

When the vault is unlocked, completions also suggest service names and usernames.
Note: the REPL already has built-in tab completion for commands and types."#;
    println!("{}", instructions);
}

fn print_status() {
    let vault_path = store::get_vault_path();
    let totp_vault_path = store::get_totp_vault_path();

    let vault_unlocked = keychain::get_master_password().is_ok();
    let totp_unlocked = keychain::get_totp_master_password().is_ok();

    println!("Vault:      {} ({})", vault_path, if vault_unlocked { "unlocked" } else { "locked" });
    println!("TOTP Vault: {} ({})", totp_vault_path, if totp_unlocked { "unlocked" } else { "locked" });
}
