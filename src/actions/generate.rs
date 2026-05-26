use crate::actions::{copy_to_clipboard_timed, Action};
use crate::crypto;
use crate::vault::entities::Error;
use clap::ArgMatches;

pub struct GeneratePasswordAction {
    pub stdout_only: bool,
}

impl GeneratePasswordAction {
    pub fn new(matches: &ArgMatches) -> GeneratePasswordAction {
        GeneratePasswordAction {
            stdout_only: matches.get_one::<bool>("out").map_or(false, |v| *v),
        }
    }
}

impl Action for GeneratePasswordAction {
    fn run(&self) -> Result<String, Error> {
        let password = crypto::generate();
        if self.stdout_only {
            Ok(password)
        } else {
            println!("{}", password);
            println!("Password copied to clipboard! Clipboard will be cleared in 20 seconds.");
            copy_to_clipboard_timed(&password, 20);
            Ok(String::new())
        }
    }
}
