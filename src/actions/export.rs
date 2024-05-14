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
    fn run_with_vault(&self, vault: &mut Box<dyn Vault>) -> Result<String, Error> {
        self.export_csv(vault).map(|count| format!("Exported {} entries", count))
    }
}
