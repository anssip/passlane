extern crate clipboard;
#[macro_use]
extern crate magic_crypt;
use crate::auth::AccessTokens;
use anyhow::{bail, Context };
use clap::{arg, ArgAction, Command};

use crate::password::Credentials;
use clipboard::ClipboardContext;
use clipboard::ClipboardProvider;
use tokio::task;

mod auth;
mod graphql;
mod keychain;
mod online_vault;
mod password;
mod store;
mod ui;
use log::{debug, info, warn};
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
        Some(("login", _)) => match login().await {
            Ok(is_first_login) => {
                println!("Logged in successfully. Online vaults in use.");
                if is_first_login {
                    println!("You can push all your locally stored credentials to the Online Vault with: passlane push");
                }
            }
            Err(message) => println!("Login failed: {}", message),
        },
        Some(("push", _)) => match push_credentials().await {
            Ok(num) => println!("Pushed {} credentials online", num),
            Err(message) => println!("Push failed: {}", message),
        },
        Some(("add", sub_matches)) => {
            let keychain = *sub_matches
                .get_one::<bool>("keychain")
                .expect("defaulted to false by clap");
            let generate = *sub_matches
                .get_one::<bool>("generate")
                .expect("defaulted to false by clap");
            let clipboard = *sub_matches
                .get_one::<bool>("clipboard")
                .expect("defaulted to false by clap");
                debug!("adding to keychain? {}", keychain);
                
            let get_password = || -> anyhow::Result<String> {
                if generate {
                    Ok(password::generate())
                } else if clipboard {
                    password_from_clipboard()
                } else {
                    Ok(ui::ask_password("Enter password to save: "))
                }
            };
            let password = get_password().context(format!("Failed to get password {}", if clipboard {"from clipboard"} else {""} ))?;
            let creds = ui::ask_credentials(&password);
            let master_pwd = ui::ask_master_password();
            save(&master_pwd, &creds, keychain).await.context("failed to save")?;
            if !clipboard {
                copy_to_clipboard(&password);
                println!("Password - also copied to clipboard: {}", password);        
            }
        },
        Some(("show", sub_matches)) => {
            let grep = sub_matches.value_of("REGEXP").expect("required");
            let verbose = *sub_matches
                .get_one::<bool>("verbose")
                .expect("defaulted to false by clap");

            let master_pwd = ui::ask_master_password();
            let matches = find_matches(Some(&master_pwd), &grep).await?;
            if matches.len() >= 1 {
                println!("Found {} matches:", matches.len());
                ui::show_as_table(&matches, verbose);
                if matches.len() == 1 {
                    copy_to_clipboard(&matches[0].password);
                    println!("Password copied to clipboard!",);
                } else {
                    match ui::ask_index(
                        "To copy one of these passwords to clipboard, please enter a row number from the table above, or press q to exit:",
                        &matches,
                    ) {
                        Ok(index) => {
                            copy_to_clipboard(&matches[index].password);
                            println!("Password from index {} copied to clipboard!", index);
                        }
                        Err(message) => {
                            println!("{}", message);
                        }
                    }
                }
            }
        },
        Some(("delete", sub_matches)) => {
            let grep = sub_matches.value_of("REGEXP").expect("required");
            let keychain = *sub_matches
                .get_one::<bool>("keychain")
                .expect("defaulted to false by clap");
        
            delete(grep, keychain).await.context("failed to delete")?;
        },
        Some(("csv", sub_matches)) => {
            let file_path = sub_matches.value_of("FILE_PATH").expect("required");

            match import_csv(&file_path).await {
                Err(message) => println!("Failed to import: {}", message),
                Ok(count) => println!("Imported {} entries", count),
            }
        },
        Some(("password", _)) => {
            let old_pwd = ui::ask_master_password();
            let new_pwd = ui::ask_new_password();
            update_master_password(&old_pwd, &new_pwd);
        },
        Some(("keychain-push", _)) => {
            let master_pwd = ui::ask_master_password();
            let creds = store::get_all_credentials();
            match keychain::save_all(&creds, &master_pwd) {
                Ok(len) => println!("Synced {} entries", len),
                Err(message) => println!("Failed to sync: {}", message),
            }
        },
        Some(("migrate", _)) => {
            let pwd = ui::ask_master_password();
            let count = store::migrate(&pwd)?;
            println!("Migrated {} credentials", count);
        },
        _ => {
            if env::args().len() == 1 { 
                let password = password::generate();
                copy_to_clipboard(&password);
                println!("Password - also copied to clipboard: {}", password);
            } else {
                let mut out = io::stdout();
                cli().write_help(&mut out).expect("failed to write to stdout");
            }
        },
    }
    Ok(())
}

fn copy_to_clipboard(value: &String) {
    let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
    ctx.set_contents(String::from(value)).unwrap();
}

fn password_from_clipboard() -> anyhow::Result<String> {
    let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
    let value = ctx
        .get_contents()
        .expect("Unable to retrieve value from clipboard");
    if !password::validate_password(&value) {
        bail!("The text in clipboard is not a valid password");
    }
    Result::Ok(value)
}

async fn find_matches(
    master_pwd: Option<&str>,
    grep_value: &str,
) -> anyhow::Result<Vec<Credentials>> {
    let matches = if store::has_logged_in() {
        info!("searching from online vault");
        let token = get_access_token().await?;
        online_vault::grep(&token.access_token, master_pwd, &grep_value).await?
    } else {
        info!("searching from local file");
        store::grep(master_pwd, grep_value)
    };
    if matches.len() == 0 {
        println!("No matches found");
    }
    Ok(matches)
}

async fn get_access_token() -> anyhow::Result<AccessTokens> {
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

async fn push_credentials() -> anyhow::Result<i32> {
    let token = get_access_token().await?;
    let credentials = store::get_all_credentials();
    online_vault::push_credentials(&token.access_token, &credentials, None).await
}

async fn push_one_credential(
    master_pwd: &String,
    credentials: &Credentials,
) -> anyhow::Result<i32> {
    let token = get_access_token().await?;
    online_vault::push_one_credential(&token.access_token, &credentials.encrypt(master_pwd), None)
        .await
}

async fn save(master_pwd: &String, creds: &Credentials, keychain: bool) -> anyhow::Result<()> {
    if store::has_logged_in() {
        info!("saving to online vault");
        push_one_credential(master_pwd, &creds).await?;
    } else {
        info!("saving to local file");
        store::save(master_pwd, creds);
    }
    if keychain {
        keychain::save(&creds).expect("Unable to store credentials to keychain");
    }
    println!("Saved.");
    Ok(())
}

async fn push_from_csv(master_pwd: &str, file_path: &str) -> anyhow::Result<i64> {
    let token = get_access_token().await?;
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
    let master_pwd = ui::ask_master_password();
    if store::has_logged_in() {
        info!("importing to the online vault");
        push_from_csv(&master_pwd, file_path).await
    } else {
        info!("importing to local file");
        store::import_csv(file_path, &master_pwd)
    }
}

async fn login() -> anyhow::Result<bool> {
    let token = task::spawn_blocking(move || {
        auth::login()
    }).await??;

    let first_login = !store::has_logged_in();
    store::store_access_token(&token)?;
    Ok(first_login)
}

async fn delete(grep: &str, delete_from_keychain: bool) -> anyhow::Result<()> {
    debug!("also deleting from keychain? {}", delete_from_keychain);
    let matches = find_matches(None, grep).await?;

    if matches.len() == 0 {
        debug!("no matches found to delete");
        return Ok(());
    }
    let use_vault = store::has_logged_in();
    if matches.len() == 1 {
        if use_vault {
            let token = get_access_token().await?;
            online_vault::delete_credentials(&token.access_token, grep, Some(0)).await?;
        } else {
            store::delete(&&vec![matches[0].clone()]);
        }
        if delete_from_keychain {
            keychain::delete(&matches[0]);
        }
        println!("Deleted credential for service '{}'", matches[0].service);
    }
    if matches.len() > 1 {
        ui::show_as_table(&matches, false);
        match ui::ask_index(
            "To delete, please enter a row number from the table above, press a to delete all, or press q to abort:",
            &matches,
        ) {
            Ok(index) => {
                if index == usize::MAX {
                    // delete all
                    if use_vault {
                        let token = get_access_token().await?;
                        online_vault::delete_credentials(&token.access_token, grep, None).await?;            
                    } else {
                        store::delete(&matches);
                    }
                    if delete_from_keychain {
                        keychain::delete_all(&matches);
                    }
                    println!("Deleted all {} matches!", matches.len());
                    
                } else {
                    // delete selected index
                    if use_vault {
                        let token = get_access_token().await?;
                        online_vault::delete_credentials(&token.access_token, grep, Some(index as i32)).await?;            
                    } else {
                        store::delete(&vec![matches[index].clone()]);
                    }
                    if delete_from_keychain {
                        keychain::delete(&matches[index]);
                    }            
                    println!("Deleted credentials of row {}!", index);
                }
            }
            Err(message) => {
                println!("{}", message);
            }
        }
    }
    Ok(())
}

fn update_master_password(old_pwd: &str, new_pwd: &str) -> bool {
    if store::has_logged_in() {
        println!("Password update has not been implemented yet for the online vault!");
        false
    } else {
        store::update_master_password(old_pwd, new_pwd)
    }
}
