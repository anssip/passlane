use clap::ArgMatches;

use crate::ui::output::{
    show_credentials_table, show_notes_table, show_payment_cards_table, show_totp_table,
};
use crate::vault::entities::{Credential, Error, Note, PaymentCard, Totp};
use crate::vault::vault_trait::Vault;
use crate::{handle_matches, ui, ItemType, MatchHandlerTemplate, UnlockingAction};

struct EditCredentialsTemplate<'a> {
    vault: &'a mut Box<dyn Vault>,
}

impl<'a> EditCredentialsTemplate<'a> {
    fn edit_and_save_credential(
        &mut self,
        credential: &Credential,
    ) -> Result<Option<String>, Error> {
        let updated = ui::ask_modified_credential(credential);
        println!("Saving...");
        self.vault.update_credential(updated)?;
        Ok(Some("Saved".to_string()))
    }
}

impl<'a> MatchHandlerTemplate for EditCredentialsTemplate<'a> {
    type ItemType = Credential;

    fn pre_handle_matches(&self, matches: &Vec<Self::ItemType>) {
        println!("Found {} credentials...", matches.len());
    }

    fn handle_one_match(&mut self, the_match: Self::ItemType) -> Result<Option<String>, Error> {
        self.edit_and_save_credential(&the_match)
    }

    fn handle_many_matches(
        &mut self,
        matches: Vec<Self::ItemType>,
    ) -> Result<Option<String>, Error> {
        show_credentials_table(&matches, false);
        match ui::ask_index(
            "To edit, please enter a row number from the table above, or press q to abort",
            matches.len() as i16 - 1,
        ) {
            Ok(index) => {
                println!(
                    "Editing credential for service '{}'...",
                    matches[index].service()
                );
                self.edit_and_save_credential(&matches[index])
            }
            Err(message) => Err(Error { message }),
        }
    }
}

struct EditNoteTemplate<'a> {
    vault: &'a mut Box<dyn Vault>,
}

impl<'a> EditNoteTemplate<'a> {
    fn edit_and_save_note(&mut self, note: &Note) -> Result<Option<String>, Error> {
        let updated = ui::ask_modified_note(note);
        println!("Saving...");
        self.vault.update_note(updated)?;
        Ok(Some("Saved".to_string()))
    }
}

impl<'a> MatchHandlerTemplate for EditNoteTemplate<'a> {
    type ItemType = Note;

    fn pre_handle_matches(&self, matches: &Vec<Self::ItemType>) {
        println!("Found {} payment cards", matches.len());
        show_notes_table(matches, false);
    }

    fn handle_one_match(&mut self, the_match: Self::ItemType) -> Result<Option<String>, Error> {
        self.edit_and_save_note(&the_match)
    }

    fn handle_many_matches(
        &mut self,
        matches: Vec<Self::ItemType>,
    ) -> Result<Option<String>, Error> {
        match ui::ask_index(
            "To edit, please enter a row number from the table above, or press q to abort",
            matches.len() as i16 - 1,
        ) {
            Ok(index) => {
                if index == usize::MAX {
                    // ignore
                    Ok(None)
                } else {
                    println!("Editing card with title '{}'...", matches[index].title());
                    self.edit_and_save_note(&matches[index])
                }
            }
            Err(message) => Err(Error { message }),
        }
    }
}

struct EditPaymentTemplate<'a> {
    vault: &'a mut Box<dyn Vault>,
}

impl<'a> EditPaymentTemplate<'a> {
    fn edit_and_save(&mut self, card: &PaymentCard) -> Result<Option<String>, Error> {
        let updated = ui::ask_modified_payment_info(card);
        println!("Saving...");
        self.vault.update_payment(updated)?;
        Ok(Some("Saved".to_string()))
    }
}

impl<'a> MatchHandlerTemplate for EditPaymentTemplate<'a> {
    type ItemType = PaymentCard;

    fn pre_handle_matches(&self, matches: &Vec<Self::ItemType>) {
        println!("Found {} payment cards", matches.len());
        show_payment_cards_table(matches, false);
    }

    fn handle_one_match(&mut self, the_match: Self::ItemType) -> Result<Option<String>, Error> {
        self.edit_and_save(&the_match)
    }

    fn handle_many_matches(
        &mut self,
        matches: Vec<Self::ItemType>,
    ) -> Result<Option<String>, Error> {
        match ui::ask_index(
            "To edit, please enter a row number from the table above, or press q to abort",
            matches.len() as i16 - 1,
        ) {
            Ok(index) => {
                if index == usize::MAX {
                    // ignore
                    Ok(None)
                } else {
                    println!("Editing card with title '{}'...", matches[index].name());
                    self.edit_and_save(&matches[index])
                }
            }
            Err(message) => Err(Error { message }),
        }
    }
}

struct EditTotpTemplate<'a> {
    vault: &'a mut Box<dyn Vault>,
}

impl<'a> EditTotpTemplate<'a> {
    fn edit_and_save(&mut self, totp: &Totp) -> Result<Option<String>, Error> {
        let updated = ui::ask_modified_totp(totp);
        println!("Saving...");
        self.vault.update_totp(updated)?;
        Ok(Some("Saved".to_string()))
    }
}

impl<'a> MatchHandlerTemplate for EditTotpTemplate<'a> {
    type ItemType = Totp;

    fn pre_handle_matches(&self, matches: &Vec<Self::ItemType>) {
        println!("Found {} TOTP entries", matches.len());
        show_totp_table(matches);
    }

    fn handle_one_match(&mut self, the_match: Self::ItemType) -> Result<Option<String>, Error> {
        self.edit_and_save(&the_match)
    }

    fn handle_many_matches(
        &mut self,
        matches: Vec<Self::ItemType>,
    ) -> Result<Option<String>, Error> {
        match ui::ask_index(
            "To edit, please enter a row number from the table above, or press q to abort",
            matches.len() as i16 - 1,
        ) {
            Ok(index) => {
                if index == usize::MAX {
                    // ignore
                    Ok(None)
                } else {
                    println!("Editing TOTP with label '{}'...", matches[index].label());
                    self.edit_and_save(&matches[index])
                }
            }
            Err(message) => Err(Error { message }),
        }
    }
}

pub struct EditAction {
    pub grep: Option<String>,
    pub item_type: ItemType,
    pub is_totp: bool,
}

impl EditAction {
    pub fn new(matches: &ArgMatches) -> EditAction {
        EditAction {
            grep: matches.get_one::<String>("REGEXP").cloned(),
            item_type: ItemType::new_from_args(matches),
            is_totp: matches.get_one::<bool>("otp").map_or(false, |v| *v),
        }
    }
}

impl UnlockingAction for EditAction {
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
                    &mut Box::new(EditCredentialsTemplate { vault }),
                )
            }
            ItemType::Payment => handle_matches(
                vault.find_payments(),
                &mut Box::new(EditPaymentTemplate { vault }),
            ),
            ItemType::Note => handle_matches(
                vault.find_notes(),
                &mut Box::new(EditNoteTemplate { vault }),
            ),
            ItemType::Totp => handle_matches(
                vault.find_totp(self.grep.as_deref()),
                &mut Box::new(EditTotpTemplate { vault }),
            ),
        }
    }
}
