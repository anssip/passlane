extern crate clipboard;
#[macro_use]
extern crate magic_crypt;

use clap::Parser;
use clipboard::ClipboardContext;
use clipboard::ClipboardProvider;
use std::env;

mod keychain;
mod password;
mod store;
mod ui;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Save the last generated password
    #[clap(short, long)]
    save: bool,
    /// Grep passwords by service
    #[clap(short, long, default_value = "")]
    grep: String,
    /// Update master password
    #[clap(short, long)]
    master_pwd: bool,
    /// Import credentials from a CSV file
    #[clap(short, long, default_value = "")]
    csv: String,
    /// Sync credentials to Keychain. Syncs all store credentials when specified as the only option.
    /// When used together with --save, syncs only the password in question.
    #[clap(short, long)]
    keychain: bool,
    /// Verobose: show password values when grep option finds several matches
    #[clap(short, long)]
    verbose: bool,
}

fn main() {
    let args = Args::parse();
    if !args.grep.eq("") {
        let master_pwd = ui::ask_master_password();
        let matches = store::grep(&master_pwd, &args.grep);
        if matches.len() == 1 {
            copy_to_clipboard(&matches[0].password);
            println!("Found 1 match. Password copied to clipboard");
        }
        if matches.len() > 1 {
            println!("Found {} matches:", matches.len());
            for creds in &matches {
                print!("{:}", creds);
                if args.verbose {
                    println!(", password: {}", creds.password);
                } else {
                    println!("");
                }
            }
        }
        return;
    }
    if env::args().len() == 1 {
        let password = password::generate();
        copy_to_clipboard(&password);
        println!("Password - also copied to clipboard: {}", password);
        return;
    }
    if args.save {
        println!("Storing latest generated password from clipboard.");
        let master_pwd = ui::ask_master_password();
        match password_from_clipboard() {
            Ok(password) => {
                let creds = ui::ask_credentials(password);
                store::save(&master_pwd, &creds);
                if args.keychain {
                    keychain::save(&creds).expect("Unable to store credentials to keychain");
                }
            }
            Err(message) => {
                println!("Failed: {}", message);
                std::process::exit(1);
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
    if !args.csv.eq("") {
        let master_pwd = ui::ask_master_password();
        match store::import_csv(&args.csv, &master_pwd) {
            Err(message) => println!("Failed: {}", message),
            Ok(count) => println!("Imported {} entries", count),
        }
    }
    if args.keychain {
        let master_pwd = ui::ask_master_password();
        let creds = store::get_all_credentials();
        match keychain::save_all(&creds, &master_pwd) {
            Ok(len) => println!("Synced {} entries", len),
            Err(message) => println!("Failed to sync: {}", message),
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
