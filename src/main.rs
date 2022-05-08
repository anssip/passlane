extern crate clipboard;
#[macro_use]
extern crate magic_crypt;

use clap::Parser;
use clipboard::ClipboardContext;
use clipboard::ClipboardProvider;

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
}

fn main() {
    let password = password::generate();
    copy_to_clipboard(&password);
    println!("Password - also copied to clipboard: {}", password);

    let args = Args::parse();
    if !args.grep.eq("") {
        println!("grep");
        return;
    }
    if args.save {
        let master_pwd = ui::ask("Master password:");
        if !store::verify_master_password(&master_pwd) {
            return println!("Master password: no match");
        }
        let mut creds = ui::ask_credentials();
        creds.password = password;
        store::save(&master_pwd, &creds);
    }
}

fn copy_to_clipboard(value: &String) {
    let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
    ctx.set_contents(String::from(value)).unwrap();
}
