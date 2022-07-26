extern crate clipboard;
#[macro_use]
extern crate magic_crypt;

use crate::password::Credentials;
use clap::Parser;
use clipboard::ClipboardContext;
use clipboard::ClipboardProvider;
use std::env;

mod keychain;
mod password;
mod store;
mod ui;
mod auth;
mod online_vault;
mod graphql;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Save the last generated password
    #[clap(short, long)]
    save: bool,
    /// Grep passwords by service
    #[clap(short, long)]
    grep: Option<String>,
    /// Delete passwords by service. Use together with --keychain to
    /// also delete from the keychain.
    #[clap(short, long)]
    delete: Option<String>,
    /// Update master password
    #[clap(short, long)]
    master_pwd: bool,
    /// Import credentials from a CSV file
    #[clap(short, long)]
    csv: Option<String>,
    /// Sync credentials to Keychain. Syncs all store credentials when specified as the only option.
    /// When used together with --save, syncs only the password in question.
    #[clap(short, long)]
    keychain: bool,
    /// Verobose: show password values when grep option finds several matches
    #[clap(short, long)]
    verbose: bool,
    /// Login to passlanevault.com
    #[clap(short, long)]
    login: bool
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    match args.grep {
        Some(value) => {
            let master_pwd = ui::ask_master_password();
            let matches = find_matches(&master_pwd, &value).await.unwrap();
            if matches.len() >= 1 {
                println!("Found {} matches:", matches.len());
                ui::show_as_table(&matches, args.verbose);
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
            std::process::exit(0)
        }
        None => (),
    }
    match args.delete {
        Some(value) => {
            let master_pwd = ui::ask_master_password();
            let matches = find_matches(&master_pwd, &value).await.unwrap();
            if matches.len() == 0 {
                return
            }
            if matches.len() == 1 {
                store::delete(&&vec![matches[0].clone()]);
                if args.keychain {
                    keychain::delete(&matches[0]);
                }
            }
            if matches.len() > 1 {
                ui::show_as_table(&matches, args.verbose);
                match ui::ask_index(
                    "To delete, please enter a row number from the table above, press a to delete all, or press q to abort:",
                    &matches,
                ) {
                    Ok(index) => {
                        if index == usize::MAX {
                            store::delete(&matches);
                            if args.keychain {
                                keychain::delete_all(&matches);
                            }
                            println!("Deleted all {} matches!", matches.len());
                            
                        } else {
                            store::delete(&vec![matches[index].clone()]);
                            if args.keychain {
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
        }
        None => ()
    }
    match args.csv {
        Some(value) => {
            let master_pwd = ui::ask_master_password();
            match store::import_csv(&value, &master_pwd) {
                Err(message) => println!("Failed: {}", message),
                Ok(count) => println!("Imported {} entries", count),
            }
        }
        None => (),
    }
    if env::args().len() == 1 {
        let password = password::generate();
        copy_to_clipboard(&password);
        println!("Password - also copied to clipboard: {}", password);
    }
    if args.save {
        let master_pwd = ui::ask_master_password();
        let save = |creds| {
            store::save(&master_pwd, &creds);
            if args.keychain {
                keychain::save(&creds).expect("Unable to store credentials to keychain");
            }
        };
        match password_from_clipboard() {
            Ok(password) => {
                let creds = ui::ask_credentials(password);
                save(creds);
            }
            Err(_) => {
                println!("Unable to find a generated password in keychain - ");
                let password = ui::ask_password("Enter password: ");
                let creds = ui::ask_credentials(password);
                save(creds);
                println!("Saved.");
            }
        }
        return;
    }
    if args.master_pwd {
        let old_pwd = ui::ask_master_password();
        let new_pwd = ui::ask_new_password();
        store::update_master_password(&old_pwd, &new_pwd);
        return;
    }
    if args.keychain && (env::args().len() == 2 || args.save) {
        let master_pwd = ui::ask_master_password();
        let creds = store::get_all_credentials();
        match keychain::save_all(&creds, &master_pwd) {
            Ok(len) => println!("Synced {} entries", len),
            Err(message) => println!("Failed to sync: {}", message),
        }
    }
    if args.login {
        let token = auth::login().await.unwrap();
        match store::store_access_token(token) {
            Ok(_) => println!("Logged in successfully. Online vaults in use."),
            Err(message) => println!("Login failed: {}", message)
        } 
    }
}

fn copy_to_clipboard(value: &String) {
    let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
    ctx.set_contents(String::from(value)).unwrap();
}

fn password_from_clipboard() -> Result<String, String> {
    let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
    let value = ctx
        .get_contents()
        .expect("Unable to retrieve value from clipboard");
    if !password::validate_password(&value) {
        return Err(String::from("Unable to retrieve value from clipboard"));
    }
    Result::Ok(value)
}

async fn find_matches(master_pwd: &String, grep_value: &String) -> anyhow::Result<Vec<Credentials>> {
    let matches = if store::has_logged_in() { 
        let token = store::get_access_token()?;
        online_vault::grep(&token.access_token, &master_pwd, &grep_value).await
    } else {
        store::grep(master_pwd, grep_value)
    };
    if matches.len() == 0 {
        println!("No matches found");
    }
    Ok(matches)
}
