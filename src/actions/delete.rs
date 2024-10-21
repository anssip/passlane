use crate::actions::{handle_matches, ItemType, MatchHandlerTemplate, UnlockingAction};
use crate::ui;
use crate::ui::output::{
    show_credentials_table, show_notes_table, show_payment_cards_table, show_totp_table,
};
use crate::vault::entities::{Credential, Error, Note, PaymentCard, Totp};
use crate::vault::vault_trait::Vault;
use clap::ArgMatches;

struct DeleteCredentialsTemplate<'a> {
    vault: &'a mut Box<dyn Vault>,
    grep: &'a str,
}

impl<'a> MatchHandlerTemplate for DeleteCredentialsTemplate<'a> {
    type ItemType = Credential;

    fn pre_handle_matches(&self, matches: &Vec<Self::ItemType>) {
        println!("Found {} credentials...", matches.len());
    }

    fn handle_one_match(&mut self, the_match: Self::ItemType) -> Result<Option<String>, Error> {
        self.vault.delete_credentials(the_match.uuid())?;
        Ok(Some("Deleted".to_string()))
    }

    fn handle_many_matches(
        &mut self,
        matches: Vec<Self::ItemType>,
    ) -> Result<Option<String>, Error> {
        show_credentials_table(&matches, false);
        match ui::input::ask_index(
            "To delete, please enter a row number from the table above, press a to delete all, or press q to abort",
            matches.len() as i16 - 1,
        ) {
            Ok(index) => {
                if index == usize::MAX {
                    self.vault.delete_matching(self.grep)?;
                    Ok(Some("Deleted".to_string()))
                } else {
                    println!("Deleting credential for service '{}'...", matches[index].service());
                    self.vault.delete_credentials(matches[index].uuid())?;
                    Ok(Some("Deleted".to_string()))
                }
            }
            Err(message) => {
                Err(Error { message })
            }
        }
    }
}

struct DeletePaymentTemplate<'a> {
    vault: &'a mut Box<dyn Vault>,
}

impl<'a> MatchHandlerTemplate for DeletePaymentTemplate<'a> {
    type ItemType = PaymentCard;

    fn pre_handle_matches(&self, matches: &Vec<Self::ItemType>) {
        println!("Found {} payment cards...", matches.len());
        show_payment_cards_table(matches, false);
    }

    fn handle_one_match(&mut self, the_match: Self::ItemType) -> Result<Option<String>, Error> {
        let response = ui::input::ask("Do you want to delete this card? (y/n)");
        if response == "y" {
            println!("Deleting payment card '{}'...", the_match.name());
            self.vault.delete_payment(the_match.id())?;
            return Ok(Some("Deleted".to_string()));
        }
        Ok(None)
    }

    fn handle_many_matches(
        &mut self,
        matches: Vec<Self::ItemType>,
    ) -> Result<Option<String>, Error> {
        match ui::input::ask_index(
            "To delete, please enter a row number from the table above, or press q to abort",
            matches.len() as i16 - 1,
        ) {
            Ok(index) => {
                if index == usize::MAX {
                    Ok(None)
                } else {
                    println!("Deleting payment card '{}'...", matches[index].name());
                    self.vault.delete_payment(&matches[index].id())?;
                    Ok(Some("Deleted".to_string()))
                }
            }
            Err(message) => Err(Error { message }),
        }
    }
}

struct DeleteNoteTemplate<'a> {
    vault: &'a mut Box<dyn Vault>,
}

impl<'a> MatchHandlerTemplate for DeleteNoteTemplate<'a> {
    type ItemType = Note;

    fn pre_handle_matches(&self, matches: &Vec<Self::ItemType>) {
        println!("Found {} notes", matches.len());
        show_notes_table(matches, false);
    }

    fn handle_one_match(&mut self, the_match: Self::ItemType) -> Result<Option<String>, Error> {
        let response = ui::input::ask("Do you want to delete this note? (y/n)");
        if response == "y" {
            println!("Deleting note with title '{}'...", the_match.title());
            self.vault.delete_note(&the_match.id())?;
            return Ok(Some("Deleted".to_string()));
        }
        Ok(None)
    }

    fn handle_many_matches(
        &mut self,
        matches: Vec<Self::ItemType>,
    ) -> Result<Option<String>, Error> {
        match ui::input::ask_index(
            "To delete, please enter a row number from the table above, or press q to abort",
            matches.len() as i16 - 1,
        ) {
            Ok(index) => {
                if index == usize::MAX {
                    // ignore
                    Ok(None)
                } else {
                    println!("Deleting note with title '{}'...", matches[index].title());
                    self.vault.delete_note(&matches[index].id())?;
                    Ok(Some("Deleted".to_string()))
                }
            }
            Err(message) => Err(Error { message }),
        }
    }
}

struct DeleteTotpTemplate<'a> {
    vault: &'a mut Box<dyn Vault>,
}

impl<'a> MatchHandlerTemplate for DeleteTotpTemplate<'a> {
    type ItemType = Totp;

    fn pre_handle_matches(&self, matches: &Vec<Self::ItemType>) {
        println!("Found {} TOTP entries", matches.len());
        show_totp_table(matches);
    }

    fn handle_one_match(&mut self, the_match: Self::ItemType) -> Result<Option<String>, Error> {
        let response = ui::input::ask("Do you want to delete this TOTP entry? (y/n)");
        if response == "y" {
            println!("Deleting TOTP entry '{}'...", the_match.label());
            self.vault.delete_totp(&the_match.id())?;
            return Ok(Some("Deleted".to_string()));
        }
        Ok(None)
    }

    fn handle_many_matches(
        &mut self,
        matches: Vec<Self::ItemType>,
    ) -> Result<Option<String>, Error> {
        match ui::input::ask_index(
            "To delete, please enter a row number from the table above, or press q to abort",
            matches.len() as i16 - 1,
        ) {
            Ok(index) => {
                if index == usize::MAX {
                    Ok(None)
                } else {
                    println!(
                        "Deleting TOTP entry labeled '{}'...",
                        matches[index].label()
                    );
                    self.vault.delete_totp(&matches[index].id())?;
                    Ok(Some("Deleted".to_string()))
                }
            }
            Err(message) => Err(Error { message }),
        }
    }
}

pub struct DeleteAction {
    pub grep: Option<String>,
    pub item_type: ItemType,
    pub is_totp: bool,
}

impl DeleteAction {
    pub fn new(matches: &ArgMatches) -> DeleteAction {
        DeleteAction {
            grep: matches.get_one::<String>("REGEXP").cloned(),
            item_type: ItemType::new_from_args(matches),
            is_totp: matches.get_one::<bool>("otp").map_or(false, |v| *v),
        }
    }
}

impl UnlockingAction for DeleteAction {
    fn is_totp_vault(&self) -> bool {
        self.is_totp
    }

    fn run_with_vault(&self, vault: &mut Box<dyn Vault>) -> Result<Option<String>, Error> {
        match self.item_type {
            ItemType::Credential => {
                let grep = match &self.grep {
                    Some(grep) => grep.as_str(),
                    None => {
                        return Err(Error {
                            message: "No search term provided".to_string(),
                        })
                    }
                };
                handle_matches(
                    vault.grep(Some(grep)),
                    &mut Box::new(DeleteCredentialsTemplate { vault, grep }),
                )
            }
            ItemType::Payment => handle_matches(
                vault.find_payments(),
                &mut Box::new(DeletePaymentTemplate { vault }),
            ),
            ItemType::Note => handle_matches(
                vault.find_notes(),
                &mut Box::new(DeleteNoteTemplate { vault }),
            ),
            ItemType::Totp => handle_matches(
                vault.find_totp(self.grep.as_deref()),
                &mut Box::new(DeleteTotpTemplate { vault }),
            ),
        }
    }
}
