use clap::ArgMatches;
use log::debug;
use crate::actions::{copy_to_clipboard, handle_matches, ItemType, MatchHandlerTemplate, UnlockingAction};
use crate::ui;
use crate::vault::entities::{Credential, Error, Note, PaymentCard, Totp};
use crate::vault::vault_trait::Vault;

struct ShowCredentialsTemplate {
    verbose: bool,
}

impl MatchHandlerTemplate for ShowCredentialsTemplate {
    type ItemType = Credential;

    fn pre_handle_matches(&self, matches: &Vec<Self::ItemType>) {
        println!("Found {} credentials:", matches.len());
    }

    fn handle_one_match(&mut self, the_match: Self::ItemType) -> Result<(), Error> {
        ui::show_credentials_table(&vec![the_match.clone()], self.verbose);
        copy_to_clipboard(&the_match.password);
        println!("Password copied to clipboard!");
        Ok(())
    }

    fn handle_many_matches(&mut self, matches: Vec<Self::ItemType>) -> Result<(), Error>{
        ui::show_credentials_table(&matches, self.verbose);

        match ui::ask_index(
            "To copy one of these passwords to clipboard, please enter a row number from the table above, or press q to exit:",
            matches.len() as i16 - 1,
        ) {
            Ok(index) => {
                copy_to_clipboard(&matches[index].password);
                println!("Password from index {} copied to clipboard!", index);
                Ok(())
            }
            Err(message) => {
                Err(Error { message })
            }
        }
    }
}

struct ShowPaymentsTemplate {
    show_cleartext: bool,
}

impl MatchHandlerTemplate for ShowPaymentsTemplate {
    type ItemType = PaymentCard;

    fn pre_handle_matches(&self, matches: &Vec<Self::ItemType>) {
        println!("Found {} payment cards:", matches.len());
    }

    fn handle_one_match(&mut self, the_match: Self::ItemType) -> Result<(), Error> {
        ui::show_payment_cards_table(&vec![the_match.clone()], self.show_cleartext);
        copy_to_clipboard(&the_match.number);
        println!("Card number copied to clipboard!");
        Ok(())
    }

    fn handle_many_matches(&mut self, matches: Vec<Self::ItemType>) -> Result<(), Error> {
        ui::show_payment_cards_table(&matches, self.show_cleartext);

        match ui::ask_index(
            "To see card details, enter a row number from the table above, or press q to exit:",
            matches.len() as i16 - 1,
        ) {
            Ok(index) => {
                ui::show_card(&matches[index]);
                copy_to_clipboard(&matches[index].number);
                println!("Card number from index {} copied to clipboard!", index);
                Ok(())
            }
            Err(message) => {
                Err(Error { message })
            }
        }
    }
}

struct ShowNotesTemplate {
    verbose: bool,
}

impl MatchHandlerTemplate for ShowNotesTemplate {
    type ItemType = Note;

    fn pre_handle_matches(&self, matches: &Vec<Self::ItemType>) {
        println!("Found {} notes:", matches.len());
    }

    fn handle_one_match(&mut self, the_match: Self::ItemType) -> Result<(), Error> {
        ui::show_notes_table(&vec![the_match.clone()], self.verbose);
        let response = ui::ask("Do you want to see the full note? (y/n)");
        if response == "y" {
            ui::show_note(&the_match);
        }
        Ok(())
    }

    fn handle_many_matches(&mut self, matches: Vec<Self::ItemType>) -> Result<(), Error> {
        ui::show_notes_table(&matches, self.verbose);

        match ui::ask_index(
            "To see the full note, please enter a row number from the table above, or press q to exit:",
            matches.len() as i16 - 1,
        ) {
            Ok(index) => {
                ui::show_note(&matches[index]);
                Ok(())
            }
            Err(message) => {
                Err(Error { message })
            }
        }
    }
}

struct ShowTotpTemplate;

impl MatchHandlerTemplate for ShowTotpTemplate {
    type ItemType = Totp;

    fn pre_handle_matches(&self, matches: &Vec<Self::ItemType>) {
        println!("Found {} matching OTP authorizers:", matches.len());
    }

    fn handle_one_match(&mut self, the_match: Self::ItemType) -> Result<(), Error> {
        debug!("found totp: {}", the_match);
        Self::show_code(the_match)
    }

    fn handle_many_matches(&mut self, matches: Vec<Self::ItemType>) -> Result<(), Error> {
        ui::show_totp_table(&matches);

        match ui::ask_index(
            "To see the code for one of these OTP authorizers, please enter a row number from the table above, or press q to exit:",
            matches.len() as i16 - 1,
        ) {
            Ok(index) => {
                Self::show_code(matches[index].clone())
            }
            Err(message) => {
                Err(Error { message })
            }
        }
    }
}

impl ShowTotpTemplate {
    fn show_code(the_match: Totp) -> Result<(), Error> {
        let code = the_match.get_code();
        match code {
            Ok(code) => {
                copy_to_clipboard(&code.value);
                println!("Code {} (also copied to clipboard). Valid for {} seconds.", code.value, code.valid_for_seconds);
                Ok(())
            },
            Err(e) => {
                Err(Error { message: e.message })
            }
        }
    }
}

pub struct ShowAction {
    pub grep: Option<String>,
    pub verbose: bool,
    pub item_type: ItemType,
    pub is_totp: bool,
}

impl ShowAction {
    pub fn new(matches: &ArgMatches) -> ShowAction {
        ShowAction {
            grep: matches.get_one::<String>("REGEXP").cloned(),
            verbose: matches
                .get_one::<bool>("verbose")
                .map_or(false, |v| *v),
            item_type: ItemType::new_from_args(matches),
            is_totp: matches.get_one::<bool>("otp").map_or(false, |v| *v),
        }
    }
}

impl UnlockingAction for ShowAction {
    fn is_totp_vault(&self) -> bool {
        self.is_totp
    }

    fn run_with_vault(&self, vault: &mut Box<dyn Vault>) -> Result<String, Error> {
        match self.item_type {
            ItemType::Credential => {
                let grep = match &self.grep {
                    Some(grep) => grep.as_str(),
                    None => return Err(Error { message: "No search term REGEXP provided".to_string() }),
                };
                handle_matches(vault.grep(Some(grep)), &mut Box::new(ShowCredentialsTemplate { verbose: self.verbose }))?;
            }
            ItemType::Payment => {
                handle_matches(vault.find_payments(), &mut Box::new(ShowPaymentsTemplate { show_cleartext: self.verbose }))?;
            }
            ItemType::Note => {
                handle_matches(vault.find_notes(), &mut Box::new(ShowNotesTemplate { verbose: self.verbose }))?;
            }
            ItemType::Totp => {
                handle_matches(vault.find_totp(None), &mut Box::new(ShowTotpTemplate))?;
            }
        }
        Ok("bye".to_string())
    }
}