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
            let include = confirm_include_restricted(restricted_count);
            // Ask entries enter the approval flow in either outcome;
            // `never` entries have no ask flow.
            crate::agent::log_bulk_ask_requests(
                creds
                    .iter()
                    .map(|c| (c.title().to_string(), c.agent_policy())),
                "password",
                include,
            );
            let exported: Vec<Credential> = if include {
                creds
            } else {
                skip_notice(restricted_count);
                creds
                    .into_iter()
                    .filter(|c| decide(c.agent_policy(), RevealContext::Agent) == RevealDecision::Reveal)
                    .collect()
            };
            if exported.is_empty() {
                // Still truncate the target: leaving a previous export's
                // file in place would keep its secrets readable.
                println!("No agent-allowed credentials to export");
                return store::write_credentials_to_csv(&self.file_path, &vec![]);
            }
            store::write_credentials_to_csv(&self.file_path, &exported)
        } else if self.item_type == ItemType::Payment {
            let cards = vault.find_payments();
            let restricted_count =
                restricted(&cards.iter().map(|c| c.agent_policy()).collect::<Vec<_>>());
            let include = confirm_include_restricted(restricted_count);
            crate::agent::log_bulk_ask_requests(
                cards.iter().map(|c| (c.name().to_string(), c.agent_policy())),
                "number",
                include,
            );
            let exported: Vec<PaymentCard> = if include {
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
            let include = confirm_include_restricted(restricted_count);
            crate::agent::log_bulk_ask_requests(
                notes.iter().map(|n| (n.title().to_string(), n.agent_policy())),
                "content",
                include,
            );
            let exported: Vec<Note> = if include {
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

#[cfg(test)]
mod tests {
    use super::*;
    use passlane_core::vault::entities::{Credential, Note, PaymentCard};
    use passlane_core::vault::vault_trait::{NoteVault, PasswordVault, PaymentVault, TotpVault};

    /// A vault stub returning fixed entries, so the export filtering is
    /// testable without a kdbx file.
    struct StubVault {
        credentials: Vec<Credential>,
    }

    impl PasswordVault for StubVault {
        fn get_master_password(&self) -> String {
            String::new()
        }
        fn grep(&self, _: Option<&str>) -> Vec<Credential> {
            self.credentials.clone()
        }
        fn save_credentials(&mut self, _: &Vec<Credential>) -> Result<i8, Error> {
            Ok(0)
        }
        fn save_one_credential(&mut self, _: Credential) -> Result<(), Error> {
            Ok(())
        }
        fn update_credential(&mut self, _: Credential) -> Result<(), Error> {
            Ok(())
        }
        fn delete_credentials(&mut self, _: &uuid::Uuid) -> Result<(), Error> {
            Ok(())
        }
        fn delete_matching(&mut self, _: &str) -> Result<i8, Error> {
            Ok(0)
        }
    }

    impl PaymentVault for StubVault {
        fn find_payments(&self) -> Vec<PaymentCard> {
            Vec::new()
        }
        fn save_payment(&mut self, _: PaymentCard) -> Result<(), Error> {
            Ok(())
        }
        fn delete_payment(&mut self, _: &uuid::Uuid) -> Result<(), Error> {
            Ok(())
        }
        fn update_payment(&mut self, _: PaymentCard) -> Result<(), Error> {
            Ok(())
        }
    }

    impl NoteVault for StubVault {
        fn find_notes(&self) -> Vec<Note> {
            Vec::new()
        }
        fn save_note(&mut self, _: &Note) -> Result<(), Error> {
            Ok(())
        }
        fn delete_note(&mut self, _: &uuid::Uuid) -> Result<(), Error> {
            Ok(())
        }
        fn update_note(&mut self, _: Note) -> Result<(), Error> {
            Ok(())
        }
    }

    impl TotpVault for StubVault {
        fn find_totp(&self, _: Option<&str>) -> Vec<passlane_core::vault::entities::Totp> {
            Vec::new()
        }
        fn save_totp(
            &mut self,
            _: &passlane_core::vault::entities::Totp,
        ) -> Result<(), Error> {
            Ok(())
        }
        fn delete_totp(&mut self, _: &uuid::Uuid) -> Result<(), Error> {
            Ok(())
        }
        fn update_totp(
            &mut self,
            _: passlane_core::vault::entities::Totp,
        ) -> Result<(), Error> {
            Ok(())
        }
    }

    impl passlane_core::vault::vault_trait::Vault for StubVault {}

    fn export_action(path: &str) -> ExportAction {
        ExportAction {
            file_path: path.to_string(),
            item_type: ItemType::Credential,
        }
    }

    fn cred(title: &str, agent: Option<&str>) -> Credential {
        let mut c = Credential::new(None, "pw", title, "user", None, None);
        if let Some(agent) = agent {
            c = c.with_custom_attributes(&[("agent".to_string(), agent.to_string())]);
        }
        c
    }

    #[test]
    fn export_with_all_restricted_truncates_a_stale_previous_export() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.csv");
        // A previous, unrestricted export left secrets at the path.
        crate::store::write_credentials_to_csv(
            path.to_str().unwrap(),
            &vec![cred("github.com", Some("allow"))],
        )
        .unwrap();
        let stale = std::fs::read_to_string(&path).unwrap();
        assert!(stale.contains("github.com"));

        // A non-interactive export with only restricted entries must not
        // leave the old secrets readable.
        let mut vault: Box<dyn Vault> = Box::new(StubVault {
            credentials: vec![cred("root", None)],
        });
        export_action(path.to_str().unwrap())
            .export_csv(&mut vault)
            .unwrap();
        let fresh = std::fs::read_to_string(&path).unwrap();
        assert!(!fresh.contains("github.com"), "stale secrets survived");
        assert!(!fresh.contains("root"), "restricted entry leaked");
        // The file is truncated (at most a header row remains).
        assert!(fresh.lines().count() <= 1);
    }

    #[test]
    fn export_filters_to_allowed_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.csv");
        let mut vault: Box<dyn Vault> = Box::new(StubVault {
            credentials: vec![
                cred("github.com", Some("allow")),
                cred("root", None),
                cred("stripe", Some("ask")),
            ],
        });
        let count = export_action(path.to_str().unwrap())
            .export_csv(&mut vault)
            .unwrap();
        assert_eq!(count, 1);
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("github.com"));
        assert!(!content.contains("stripe"));
        assert!(!content.contains(",root,"));
    }
}
