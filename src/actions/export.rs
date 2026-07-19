use clap::ArgMatches;
use log::debug;
use crate::actions::{ItemType, UnlockingAction};
use crate::store;
use crate::vault::entities::Error;
use crate::vault::vault_trait::Vault;

pub struct ExportAction {
    pub file_path: String,
    pub item_type: ItemType,
}

impl ExportAction {
    pub fn new(matches: &ArgMatches) -> ExportAction {
        ExportAction {
            file_path: matches.get_one::<String>("file_path").expect("required").to_string(),
            item_type: ItemType::new_from_args(matches),
        }
    }
    pub fn export_csv(&self, vault: &mut Box<dyn Vault>) -> Result<i64, Error> {
        debug!("exporting to csv");
        if self.item_type == ItemType::Credential {
            let creds = vault.grep(None);
            if creds.is_empty() {
                println!("No credentials found");
                return Ok(0);
            }
            store::write_credentials_to_csv(&self.file_path, &creds)
        } else if self.item_type == ItemType::Payment {
            let cards = vault.find_payments();
            store::write_payment_cards_to_csv(&self.file_path, &cards)
        } else if self.item_type == ItemType::Note {
            let notes = vault.find_notes();
            store::write_secure_notes_to_csv(&self.file_path, &notes)
        } else {
            Ok(0)
        }
    }
}

impl UnlockingAction for ExportAction {
    fn run_with_vault(&self, vault: &mut Box<dyn Vault>) -> Result<Option<String>, Error> {
        let count = self.export_csv(vault)?;
        // Payment and note exports write the file even when empty; credential
        // exports return early without touching the file when there are none.
        let file_written = match self.item_type {
            ItemType::Credential => count > 0,
            ItemType::Payment | ItemType::Note => true,
            ItemType::Totp => false,
        };
        if file_written {
            eprintln!(
                "Warning: '{}' contains your secrets in plaintext. Store it safely and delete it when done.",
                self.file_path
            );
        }
        Ok(Some(format!("Exported {} entries", count)))
    }
}
