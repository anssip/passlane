extern crate clipboard;

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
}

fn main() {
    let password = password::generate();
    copy_to_clipboard(&password);
    println!("Password - also copied to clipboard: {}", password);

    let args = Args::parse();
    if args.save {
        let master_pwd = ui::ask("Master password:");
        let mut creds = ui::ask_credentials();
        creds.password = password;
        println!("{} {} {}", creds.username, creds.service, creds.password);
        // TODO: save to file
        store::save(&master_pwd, &creds);
    }
}

fn copy_to_clipboard(value: &String) {
    let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
    ctx.set_contents(String::from(value)).unwrap();
}
