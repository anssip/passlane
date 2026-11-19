use clap::ArgMatches;
use log::debug;
use std::io::IsTerminal;

use crate::actions::{ItemType, UnlockingAction};
use crate::agent::{decide, RevealContext, RevealDecision};
use crate::store;
use passlane_core::vault::entities::{AgentPolicy, Credential, Error, Note, PaymentCard};
use passlane_core::vault::vault_trait::Vault;

pub struct ExportAction {
    pub file_path: String,
    pub item_type: ItemType,
}

/// An export writes every secret to a plaintext file, which makes it an
/// agent-facing bulk reveal: entries the agent policy restricts are skipped
/// unless an interactive owner explicitly includes them.
fn restricted(entries: &[AgentPolicy]) -> usize {
    entries
        .iter()
        .filter(|p| decide(**p, RevealContext::Agent) != RevealDecision::Reveal)
        .count()
}

/// At an interactive terminal the owner may choose to include restricted
/// entries (e.g. when migrating to another password manager). Without a
/// terminal there is no owner to approve, so restricted entries are skipped.
fn confirm_include_restricted(restricted_count: usize) -> bool {
    if restricted_count == 0 || !std::io::stdin().is_terminal() {
        return false;
    }
    inquire::Confirm::new(&format!(
        "{} entries are restricted by their agent policy (agent=never/ask). Include them in \
         the export anyway?",
        restricted_count
    ))
    .with_default(false)
    .prompt()
    .unwrap_or(false)
}

fn skip_notice(restricted_count: usize) {
    if restricted_count > 0 {
        eprintln!(
            "Skipped {} entries restricted by their agent policy. Reveal them interactively or \
             set their 'agent' attribute to 'allow' to export them.",
            restricted_count
        );
    }
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
            let restricted_count =
                restricted(&creds.iter().map(|c| c.agent_policy()).collect::<Vec<_>>());
            let exported: Vec<Credential> = if confirm_include_restricted(restricted_count) {
                creds
            } else {
                skip_notice(restricted_count);
                creds
                    .into_iter()
                    .filter(|c| decide(c.agent_policy(), RevealContext::Agent) == RevealDecision::Reveal)
                    .collect()
            };
            if exported.is_empty() {
                println!("No agent-allowed credentials to export");
                return Ok(0);
            }
            store::write_credentials_to_csv(&self.file_path, &exported)
        } else if self.item_type == ItemType::Payment {
            let cards = vault.find_payments();
            let restricted_count =
                restricted(&cards.iter().map(|c| c.agent_policy()).collect::<Vec<_>>());
            let exported: Vec<PaymentCard> = if confirm_include_restricted(restricted_count) {
                cards
            } else {
                skip_notice(restricted_count);
                cards
                    .into_iter()
                    .filter(|c| decide(c.agent_policy(), RevealContext::Agent) == RevealDecision::Reveal)
                    .collect()
            };
            store::write_payment_cards_to_csv(&self.file_path, &exported)
        } else if self.item_type == ItemType::Note {
            let notes = vault.find_notes();
            let restricted_count =
                restricted(&notes.iter().map(|n| n.agent_policy()).collect::<Vec<_>>());
            let exported: Vec<Note> = if confirm_include_restricted(restricted_count) {
                notes
            } else {
                skip_notice(restricted_count);
                notes
                    .into_iter()
                    .filter(|n| decide(n.agent_policy(), RevealContext::Agent) == RevealDecision::Reveal)
                    .collect()
            };
            store::write_secure_notes_to_csv(&self.file_path, &exported)
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
