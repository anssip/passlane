use crate::actions::Action;
use crate::vault::entities::Error;
use clap::Command;

pub struct InitAction {
    cli: Command,
}

impl InitAction {
    pub fn new(cli: Command) -> InitAction {
        InitAction { cli }
    }
}

impl Action for InitAction {
    fn run(&self) -> Result<String, Error> {
        // TODO: Ask the vault location

        // TODO: Finally, ask master password to be stored in keychain

        Ok(String::from("Initialized"))
    }
}
