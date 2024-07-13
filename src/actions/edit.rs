use clap::ArgMatches;

use crate::vault::entities::{Credential, Error, Note, PaymentCard, Totp};
use crate::vault::vault_trait::Vault;
use crate::{handle_matches, ui, ItemType, MatchHandlerTemplate, UnlockingAction};

struct EditCredentialsTemplate<'a> {
    vault: &'a mut Box<dyn Vault>,
    grep: &'a str,
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
        ui::show_credentials_table(&matches, false);
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
                    &mut Box::new(EditCredentialsTemplate { vault, grep }),
                )
            }
            ItemType::Payment => {
                todo!("Edit payment card")
            }
            ItemType::Note => {
                todo!("Edit note")
            }
            ItemType::Totp => {
                todo!("Edit totp")
            }
        }
    }
}
