use clap::ArgMatches;
use crate::actions::{Action, handle_matches, ItemType, MatchHandlerTemplate, UnlockingAction};
use crate::ui;
use crate::vault::entities::{Credential, Note, PaymentCard, Totp};
use crate::vault::vault_trait::Vault;

struct DeleteCredentialsTemplate<'a> {
    vault: &'a mut Box<dyn Vault>,
    grep: &'a str,
}

impl<'a> MatchHandlerTemplate for DeleteCredentialsTemplate<'a> {
    type ItemType = Credential;

    fn pre_handle_matches(&self, matches: &Vec<Self::ItemType>) {
        println!("Found {} credentials...", matches.len());
    }

    fn handle_one_match(&mut self, the_match: Self::ItemType) {
        self.vault.delete_credentials(&the_match.uuid);
        println!("Deleted credential for service '{}'", the_match.service);
    }

    fn handle_many_matches(&mut self, matches: Vec<Self::ItemType>) {
        ui::show_credentials_table(&matches, false);
        match ui::ask_index(
            "To delete, please enter a row number from the table above, press a to delete all, or press q to abort:",
            matches.len() as i16 - 1,
        ) {
            Ok(index) => {
                if index == usize::MAX {
                    self.vault.delete_matching(self.grep);
                    println!("Deleted all {} matches!", matches.len());
                } else {
                    println!("Deleting credential for service '{}'...", matches[index].service);
                    self.vault.delete_credentials(&matches[index].uuid);
                    println!("Deleted!");
                }
            }
            Err(message) => {
                println!("{}", message);
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
    }

    fn handle_one_match(&mut self, the_match: Self::ItemType) {
        let response = ui::ask("Do you want to delete this card? (y/n)");
        if response == "y" {
            println!("Deleting payment card '{}'...", the_match.name);
            self.vault.delete_payment(&the_match.id);
            println!("Deleted!");
        }
    }

    fn handle_many_matches(&mut self, matches: Vec<Self::ItemType>) {
        ui::show_payment_cards_table(&matches, false);
        match ui::ask_index(
            "To delete, please enter a row number from the table above, or press q to abort:",
            matches.len() as i16 - 1,
        ) {
            Ok(index) => {
                if index == usize::MAX {
                    // ignore
                } else {
                    println!("Deleting payment card '{}'...", matches[index].name);
                    self.vault.delete_payment(&matches[index].id);
                    println!("Deleted!");
                }
            }
            Err(message) => {
                println!("{}", message);
            }
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
        ui::show_notes_table(matches, false);
    }

    fn handle_one_match(&mut self, the_match: Self::ItemType) {
        let response = ui::ask("Do you want to delete this note? (y/n)");
        if response == "y" {
            println!("Deleting note with title '{}'...", the_match.title);
            self.vault.delete_note(&the_match.id);
            println!("Deleted!");
        }
    }

    fn handle_many_matches(&mut self, matches: Vec<Self::ItemType>) {
        match ui::ask_index(
            "To delete, please enter a row number from the table above, or press q to abort:",
            matches.len() as i16 - 1,
        ) {
            Ok(index) => {
                if index == usize::MAX {
                    // ignore
                } else {
                    println!("Deleting note with title '{}'...", matches[index].title);
                    self.vault.delete_note(&matches[index].id);
                    println!("Deleted!");
                }
            }
            Err(message) => {
                println!("{}", message);
            }
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
        ui::show_totp_table(matches);
    }

    fn handle_one_match(&mut self, the_match: Self::ItemType) {
        let response = ui::ask("Do you want to delete this TOTP entry? (y/n)");
        if response == "y" {
            println!("Deleting TOTP entry '{}'...", the_match.label);
            self.vault.delete_totp(&the_match.id);
            println!("Deleted!");
        }
    }

    fn handle_many_matches(&mut self, matches: Vec<Self::ItemType>) {
        match ui::ask_index(
            "To delete, please enter a row number from the table above, or press q to abort:",
            matches.len() as i16 - 1,
        ) {
            Ok(index) => {
                if index == usize::MAX {
                    // ignore
                } else {
                    println!("Deleting TOTP entry labeled '{}'...", matches[index].label);
                    self.vault.delete_totp(&matches[index].id);
                    println!("Deleted!");
                }
            }
            Err(message) => {
                println!("{}", message);
            }
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
            is_totp: *matches.get_one::<bool>("otp").expect("defaulted to false by clap"),
        }
    }
}

fn delete_credentials(vault: &mut Box<dyn Vault>, grep: &str) {
    let matches = vault.grep(&Some(String::from(grep)));
    handle_matches(matches, &mut Box::new(DeleteCredentialsTemplate { vault, grep }));
}

fn delete_payment(vault: &mut Box<dyn Vault>) {
    let cards = vault.find_payments();
    handle_matches(cards, &mut Box::new(DeletePaymentTemplate { vault }));
}

fn delete_note(vault: &mut Box<dyn Vault>) {
    let notes = vault.find_notes();
    handle_matches(notes, &mut Box::new(DeleteNoteTemplate { vault }));
}

fn delete_totp(vault: &mut Box<dyn Vault>) {
    let totps = vault.find_totp(&None);
    handle_matches(totps, &mut Box::new(DeleteTotpTemplate { vault }));
}

impl Action for DeleteAction {}

impl UnlockingAction for DeleteAction {
    fn is_totp_vault(&self) -> bool {
        self.is_totp
    }

    fn run_with_vault(&self, vault: &mut Box<dyn Vault>) -> anyhow::Result<()> {
        match self.item_type {
            ItemType::Credential => {
                let grep = match &self.grep {
                    Some(grep) => grep,
                    None => panic!("-g <REGEXP> is required"),
                };
                delete_credentials(vault, grep);
            }
            ItemType::Payment => {
                delete_payment(vault);
            }
            ItemType::Note => {
                delete_note(vault);
            }
            ItemType::Totp => {
                delete_totp(vault);
            }
        };
        Ok(())
    }
}
