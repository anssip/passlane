use clap::Command;
use crate::actions::Action;
use crate::vault::entities::Error;

pub struct PrintHelpAction {
    cli: Command,
}

impl PrintHelpAction {
    pub fn new(cli: Command) -> PrintHelpAction {
        PrintHelpAction {
            cli
        }
    }
}

impl Action for PrintHelpAction {
    fn run(&self) -> Result<String, Error> {
        // write the help to a string
        let mut help_text = Vec::new();
        self.cli.clone().write_help(&mut help_text)?;

        String::from_utf8(help_text).map(|s| s.to_string()).map_err(|_| Error::new("Failed to convert help text to string"))
    }
}
