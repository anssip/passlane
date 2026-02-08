use crate::actions::{ItemType, UnlockingAction};
use crate::vault::entities::{Credential, Error, Note, PaymentCard, Totp};
use crate::vault::vault_trait::Vault;
use clap::ArgMatches;
use serde::Serialize;

#[derive(Serialize)]
pub struct ListOutput<T: Serialize> {
    #[serde(rename = "type")]
    pub type_name: String,
    pub count: usize,
    pub entries: Vec<T>,
}

impl<T: Serialize> ListOutput<T> {
    pub fn new(type_name: &str, entries: Vec<T>) -> Self {
        let count = entries.len();
        ListOutput {
            type_name: type_name.to_string(),
            count,
            entries,
        }
    }

    pub fn to_json(&self) -> Result<String, Error> {
        serde_json::to_string_pretty(self)
            .map_err(|e| Error::new(&format!("JSON serialization error: {}", e)))
    }
}

pub struct ListAction {
    pub item_type: ItemType,
    pub search_pattern: Option<String>,
    pub json_output: bool,
    pub verbose: bool,
    pub is_totp: bool,
}

impl ListAction {
    pub fn new(matches: &ArgMatches) -> ListAction {
        ListAction {
            item_type: ItemType::new_from_args(matches),
            search_pattern: matches.get_one::<String>("REGEXP").cloned(),
            json_output: matches.get_one::<bool>("json").map_or(false, |v| *v),
            verbose: matches.get_one::<bool>("verbose").map_or(false, |v| *v),
            is_totp: matches.get_one::<bool>("otp").map_or(false, |v| *v),
        }
    }

    fn list_credentials(&self, vault: &mut Box<dyn Vault>) -> Result<Option<String>, Error> {
        let entries = vault.grep(self.search_pattern.as_deref());
        if self.json_output {
            let output = ListOutput::new("credentials", entries);
            Ok(Some(output.to_json()?))
        } else {
            Ok(Some(Self::format_credentials_plain(&entries, self.verbose)))
        }
    }

    fn list_payments(&self, vault: &mut Box<dyn Vault>) -> Result<Option<String>, Error> {
        let entries = vault.find_payments();
        if self.json_output {
            let output = ListOutput::new("payment_cards", entries);
            Ok(Some(output.to_json()?))
        } else {
            Ok(Some(Self::format_payments_plain(&entries)))
        }
    }

    fn list_notes(&self, vault: &mut Box<dyn Vault>) -> Result<Option<String>, Error> {
        let entries = vault.find_notes();
        if self.json_output {
            let output = ListOutput::new("notes", entries);
            Ok(Some(output.to_json()?))
        } else {
            Ok(Some(Self::format_notes_plain(&entries)))
        }
    }

    fn list_totp(&self, vault: &mut Box<dyn Vault>) -> Result<Option<String>, Error> {
        let entries = vault.find_totp(self.search_pattern.as_deref());
        if self.json_output {
            let output = ListOutput::new("totp", entries);
            Ok(Some(output.to_json()?))
        } else {
            Ok(Some(Self::format_totp_plain(&entries)))
        }
    }

    fn format_credentials_plain(entries: &[Credential], verbose: bool) -> String {
        let count = entries.len();
        if count == 0 {
            return "Found 0 credentials.".to_string();
        }
        let mut lines = vec![format!("Found {} credentials:", count)];
        for entry in entries {
            lines.push(String::new());
            lines.push(format!("Service: {}", entry.service()));
            lines.push(format!("Username: {}", entry.username()));
            if verbose {
                lines.push(format!("Password: {}", entry.password()));
                lines.push(format!("Last Modified: {}", entry.last_modified()));
            }
        }
        lines.join("\n")
    }

    fn format_payments_plain(entries: &[PaymentCard]) -> String {
        let count = entries.len();
        if count == 0 {
            return "Found 0 payment cards.".to_string();
        }
        let mut lines = vec![format!("Found {} payment cards:", count)];
        for entry in entries {
            lines.push(String::new());
            lines.push(format!("Name: {}", entry.name()));
            lines.push(format!("Name on Card: {}", entry.name_on_card()));
            lines.push(format!("Number: {}", entry.number()));
            lines.push(format!("CVV: {}", entry.cvv()));
            lines.push(format!("Expiry: {}", entry.expiry()));
            if let Some(color) = entry.color() {
                lines.push(format!("Color: {}", color));
            }
            if let Some(address) = entry.billing_address() {
                lines.push(format!("Billing Address: {}", address));
            }
            lines.push(format!("Last Modified: {}", entry.last_modified()));
        }
        lines.join("\n")
    }

    fn format_notes_plain(entries: &[Note]) -> String {
        let count = entries.len();
        if count == 0 {
            return "Found 0 notes.".to_string();
        }
        let mut lines = vec![format!("Found {} notes:", count)];
        for entry in entries {
            lines.push(String::new());
            lines.push(format!("Title: {}", entry.title()));
            lines.push(format!("Content: {}", entry.content()));
            lines.push(format!("Last Modified: {}", entry.last_modified()));
        }
        lines.join("\n")
    }

    fn format_totp_plain(entries: &[Totp]) -> String {
        let count = entries.len();
        if count == 0 {
            return "Found 0 TOTP entries.".to_string();
        }
        let mut lines = vec![format!("Found {} TOTP entries:", count)];
        for entry in entries {
            lines.push(String::new());
            lines.push(format!("Label: {}", entry.label()));
            lines.push(format!("Issuer: {}", entry.issuer()));
            lines.push(format!("Secret: {}", entry.secret()));
            lines.push(format!("Last Modified: {}", entry.last_modified()));
        }
        lines.join("\n")
    }
}

impl UnlockingAction for ListAction {
    fn is_totp_vault(&self) -> bool {
        self.is_totp
    }

    fn run_with_vault(&self, vault: &mut Box<dyn Vault>) -> Result<Option<String>, Error> {
        match self.item_type {
            ItemType::Credential => self.list_credentials(vault),
            ItemType::Payment => self.list_payments(vault),
            ItemType::Note => self.list_notes(vault),
            ItemType::Totp => self.list_totp(vault),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::entities::{Address, Expiry};
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn test_credential_json_serialization() {
        let cred = Credential::new(
            Some(&Uuid::nil()),
            "secret123",
            "google.com",
            "user@example.com",
            Some(Utc::now()),
        );
        let json = serde_json::to_string(&cred).unwrap();
        assert!(json.contains("\"uuid\""));
        assert!(json.contains("\"service\""));
        assert!(json.contains("\"username\""));
        assert!(json.contains("\"password\""));
        assert!(json.contains("\"last_modified\""));
        assert!(json.contains("google.com"));
        assert!(json.contains("user@example.com"));
        assert!(json.contains("secret123"));
    }

    #[test]
    fn test_payment_card_json_serialization() {
        let card = PaymentCard::new(
            Some(&Uuid::nil()),
            "Visa Gold",
            "John Doe",
            "4532123456789012",
            "123",
            Expiry { month: 6, year: 2025 },
            Some("Gold"),
            Some(&Address::new(None, "123 Main St", "Springfield", "US", Some("IL"), "62701")),
            Some(Utc::now()),
        );
        let json = serde_json::to_string(&card).unwrap();
        assert!(json.contains("\"id\""));
        assert!(json.contains("\"name\""));
        assert!(json.contains("\"name_on_card\""));
        assert!(json.contains("\"number\""));
        assert!(json.contains("\"cvv\""));
        assert!(json.contains("\"expiry\""));
        assert!(json.contains("\"month\""));
        assert!(json.contains("\"year\""));
        assert!(json.contains("\"color\""));
        assert!(json.contains("\"billing_address\""));
    }

    #[test]
    fn test_note_json_serialization() {
        let note = Note::new(
            Some(&Uuid::nil()),
            "WiFi Passwords",
            "Home: password123",
            Some(Utc::now()),
        );
        let json = serde_json::to_string(&note).unwrap();
        assert!(json.contains("\"id\""));
        assert!(json.contains("\"title\""));
        assert!(json.contains("\"content\""));
        assert!(json.contains("\"last_modified\""));
        assert!(json.contains("WiFi Passwords"));
    }

    #[test]
    fn test_totp_json_serialization() {
        let totp = Totp::new(
            Some(&Uuid::nil()),
            "otpauth://totp/GitHub:user?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
            "user@example.com",
            "GitHub",
            "JBSWY3DPEHPK3PXP",
            "SHA1",
            30,
            6,
            Some(Utc::now()),
        );
        let json = serde_json::to_string(&totp).unwrap();
        assert!(json.contains("\"id\""));
        assert!(json.contains("\"label\""));
        assert!(json.contains("\"issuer\""));
        assert!(json.contains("\"secret\""));
        assert!(json.contains("\"algorithm\""));
        assert!(json.contains("\"period\""));
        assert!(json.contains("\"digits\""));
        assert!(json.contains("\"last_modified\""));
        // url should be skipped
        assert!(!json.contains("\"url\""));
    }

    #[test]
    fn test_list_output_envelope_credentials() {
        let cred = Credential::new(
            Some(&Uuid::nil()),
            "pass",
            "example.com",
            "user",
            Some(Utc::now()),
        );
        let output = ListOutput::new("credentials", vec![cred]);
        let json = output.to_json().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["type"], "credentials");
        assert_eq!(parsed["count"], 1);
        assert!(parsed["entries"].is_array());
        assert_eq!(parsed["entries"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_list_output_envelope_empty() {
        let output: ListOutput<Credential> = ListOutput::new("credentials", vec![]);
        let json = output.to_json().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["type"], "credentials");
        assert_eq!(parsed["count"], 0);
        assert_eq!(parsed["entries"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn test_format_credentials_plain_empty() {
        let result = ListAction::format_credentials_plain(&[], false);
        assert_eq!(result, "Found 0 credentials.");
    }

    #[test]
    fn test_format_credentials_plain_non_verbose() {
        let cred = Credential::new(None, "secret", "google.com", "user@test.com", None);
        let result = ListAction::format_credentials_plain(&[cred], false);
        assert!(result.contains("Found 1 credentials:"));
        assert!(result.contains("Service: google.com"));
        assert!(result.contains("Username: user@test.com"));
        assert!(!result.contains("Password:"));
    }

    #[test]
    fn test_format_credentials_plain_verbose() {
        let cred = Credential::new(None, "secret", "google.com", "user@test.com", None);
        let result = ListAction::format_credentials_plain(&[cred], true);
        assert!(result.contains("Found 1 credentials:"));
        assert!(result.contains("Service: google.com"));
        assert!(result.contains("Username: user@test.com"));
        assert!(result.contains("Password: secret"));
        assert!(result.contains("Last Modified:"));
    }

    #[test]
    fn test_format_payments_plain() {
        let card = PaymentCard::new(
            None, "Visa", "John Doe", "4532123456789012", "123",
            Expiry { month: 6, year: 2025 }, Some("Gold"), None, None,
        );
        let result = ListAction::format_payments_plain(&[card]);
        assert!(result.contains("Found 1 payment cards:"));
        assert!(result.contains("Name: Visa"));
        assert!(result.contains("Name on Card: John Doe"));
        assert!(result.contains("Number: 4532123456789012"));
        assert!(result.contains("CVV: 123"));
        assert!(result.contains("Expiry: 6/2025"));
        assert!(result.contains("Color: Gold"));
    }

    #[test]
    fn test_format_notes_plain() {
        let note = Note::new(None, "My Note", "Some content", None);
        let result = ListAction::format_notes_plain(&[note]);
        assert!(result.contains("Found 1 notes:"));
        assert!(result.contains("Title: My Note"));
        assert!(result.contains("Content: Some content"));
    }

    #[test]
    fn test_format_totp_plain() {
        let totp = Totp::new(
            None, "otpauth://totp/test", "user@test.com", "GitHub",
            "JBSWY3DPEHPK3PXP", "SHA1", 30, 6, None,
        );
        let result = ListAction::format_totp_plain(&[totp]);
        assert!(result.contains("Found 1 TOTP entries:"));
        assert!(result.contains("Label: user@test.com"));
        assert!(result.contains("Issuer: GitHub"));
        assert!(result.contains("Secret: JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn test_format_payments_plain_empty() {
        let result = ListAction::format_payments_plain(&[]);
        assert_eq!(result, "Found 0 payment cards.");
    }

    #[test]
    fn test_format_notes_plain_empty() {
        let result = ListAction::format_notes_plain(&[]);
        assert_eq!(result, "Found 0 notes.");
    }

    #[test]
    fn test_format_totp_plain_empty() {
        let result = ListAction::format_totp_plain(&[]);
        assert_eq!(result, "Found 0 TOTP entries.");
    }
}
