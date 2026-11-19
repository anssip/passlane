use crate::actions::{ItemType, UnlockingAction};
use crate::agent::{self, decide, RevealContext, RevealDecision};
use chrono::{DateTime, Utc};
use passlane_core::vault::entities::{AgentPolicy, Credential, Error, Note, PaymentCard, Totp};
use passlane_core::vault::vault_trait::Vault;
use clap::ArgMatches;
use serde::Serialize;

/// Why a secret was withheld from `list` output (agent policy applied to a
/// stdout reveal).
fn withheld_reason(policy: AgentPolicy) -> Option<&'static str> {
    match decide(policy, RevealContext::Agent) {
        RevealDecision::Reveal => None,
        RevealDecision::NeedApproval => Some("agent=ask, needs owner approval"),
        RevealDecision::Block => Some("agent=never"),
    }
}

/// `list` prints to stdout, which is an agent-facing reveal: the agent
/// policy applies to every secret field. Collects how many entries had
/// secrets withheld and reports it on stderr, so stdout stays parseable.
struct WithheldSummary {
    never: usize,
    ask: usize,
}

impl WithheldSummary {
    fn new() -> Self {
        Self { never: 0, ask: 0 }
    }

    fn tally(policies: impl Iterator<Item = AgentPolicy>) -> Self {
        let mut summary = Self::new();
        for policy in policies {
            summary.record(policy);
        }
        summary
    }

    fn record(&mut self, policy: AgentPolicy) {
        match withheld_reason(policy) {
            Some(reason) if reason.starts_with("agent=never") => self.never += 1,
            Some(_) => self.ask += 1,
            None => {}
        }
    }

    fn total(&self) -> usize {
        self.never + self.ask
    }

    fn report(&self) {
        if self.total() > 0 {
            let mut parts = Vec::new();
            if self.never > 0 {
                parts.push(format!("{} agent=never", self.never));
            }
            if self.ask > 0 {
                parts.push(format!("{} agent=ask", self.ask));
            }
            eprintln!(
                "Withheld secrets of {} entries per their agent policy ({}). Set an entry's \
                 'agent' attribute to 'allow' to include it, or reveal it interactively \
                 ('passlane show').",
                self.total(),
                parts.join(", ")
            );
        }
    }
}

/// A credential as listed. Same shape as the entity's serialization, except
/// `password` is `null` when the agent policy withheld it, and `agent`
/// states the policy that applied.
#[derive(Serialize)]
struct ListedCredential {
    uuid: String,
    title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
    tags: Vec<String>,
    expires: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    expiry_time: Option<DateTime<Utc>>,
    custom_attributes: Vec<(String, String)>,
    agent: String,
    password: Option<String>,
    last_modified: DateTime<Utc>,
}

impl ListedCredential {
    fn from_entry(entry: &Credential) -> Self {
        let restricted = withheld_reason(entry.agent_policy()).is_some();
        Self {
            uuid: entry.uuid().to_string(),
            title: entry.title().to_string(),
            url: entry.url().map(str::to_string),
            username: entry.username().to_string(),
            // Notes and custom attributes can carry secrets (recovery
            // codes, tokens); restricted entries keep only the policy
            // attribute itself as metadata.
            note: if restricted {
                None
            } else {
                entry.note().map(str::to_string)
            },
            tags: entry.tags().to_vec(),
            expires: entry.expires(),
            expiry_time: entry.expiry_time(),
            custom_attributes: if restricted {
                vec![(
                    passlane_core::vault::entities::AGENT_ATTRIBUTE.to_string(),
                    entry.agent_policy().as_str().to_string(),
                )]
            } else {
                entry.custom_attributes().to_vec()
            },
            agent: entry.agent_policy().as_str().to_string(),
            password: withheld_reason(entry.agent_policy())
                .is_none()
                .then(|| entry.password().to_string()),
            last_modified: *entry.last_modified(),
        }
    }
}

/// A payment card as listed; `number` and `cvv` are `null` when withheld.
#[derive(Serialize)]
struct ListedPayment {
    id: String,
    name: String,
    name_on_card: String,
    number: Option<String>,
    cvv: Option<String>,
    expiry: passlane_core::vault::entities::Expiry,
    #[serde(skip_serializing_if = "Option::is_none")]
    color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    billing_address: Option<passlane_core::vault::entities::Address>,
    agent: String,
    last_modified: DateTime<Utc>,
}

impl ListedPayment {
    fn from_entry(entry: &PaymentCard, withheld: bool) -> Self {
        Self {
            id: entry.id().to_string(),
            name: entry.name().to_string(),
            name_on_card: entry.name_on_card().to_string(),
            number: (!withheld).then(|| entry.number().to_string()),
            cvv: (!withheld).then(|| entry.cvv().to_string()),
            expiry: entry.expiry().clone(),
            color: entry.color().cloned(),
            billing_address: entry.billing_address().cloned(),
            agent: entry.agent_policy().as_str().to_string(),
            last_modified: *entry.last_modified(),
        }
    }
}

/// A note as listed; `content` is `null` when withheld.
#[derive(Serialize)]
struct ListedNote {
    id: String,
    title: String,
    content: Option<String>,
    agent: String,
    last_modified: DateTime<Utc>,
}

impl ListedNote {
    fn from_entry(entry: &Note, withheld: bool) -> Self {
        Self {
            id: entry.id().to_string(),
            title: entry.title().to_string(),
            content: (!withheld).then(|| entry.content().to_string()),
            agent: entry.agent_policy().as_str().to_string(),
            last_modified: entry.last_modified(),
        }
    }
}

/// A TOTP entry as listed; `secret` is `null` when withheld.
#[derive(Serialize)]
struct ListedTotp {
    id: String,
    label: String,
    issuer: String,
    secret: Option<String>,
    algorithm: String,
    period: u64,
    digits: u32,
    agent: String,
    last_modified: DateTime<Utc>,
}

impl ListedTotp {
    fn from_entry(entry: &Totp, withheld: bool) -> Self {
        Self {
            id: entry.id().to_string(),
            label: entry.label().to_string(),
            issuer: entry.issuer().to_string(),
            secret: (!withheld).then(|| entry.secret().to_string()),
            algorithm: entry.algorithm().to_string(),
            period: entry.period(),
            digits: entry.digits(),
            agent: entry.agent_policy().as_str().to_string(),
            last_modified: *entry.last_modified(),
        }
    }
}

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

/// A generated TOTP code entry. Deliberately excludes the stored secret.
/// `code` is `null` when the agent policy withheld it.
#[derive(Serialize)]
pub struct TotpCodeEntry {
    pub label: String,
    pub issuer: String,
    pub code: Option<String>,
    pub valid_for_seconds: u64,
    pub agent: String,
}

pub struct ListAction {
    pub item_type: ItemType,
    pub search_pattern: Option<String>,
    pub json_output: bool,
    pub verbose: bool,
    pub code: bool,
}

impl ListAction {
    pub fn new(matches: &ArgMatches) -> ListAction {
        ListAction {
            item_type: ItemType::new_from_args(matches),
            search_pattern: matches.get_one::<String>("REGEXP").cloned(),
            json_output: matches.get_one::<bool>("json").map_or(false, |v| *v),
            verbose: matches.get_one::<bool>("verbose").map_or(false, |v| *v),
            code: matches.get_one::<bool>("code").map_or(false, |v| *v),
        }
    }

    fn list_credentials(&self, vault: &mut Box<dyn Vault>) -> Result<Option<String>, Error> {
        let entries = vault.grep(self.search_pattern.as_deref());
        // Only verbose plain output (and JSON, which always serializes the
        // password) reveals passwords; the metadata listing never did.
        if self.json_output || self.verbose {
            agent::log_bulk_ask_requests(
                entries
                    .iter()
                    .map(|e| (e.title().to_string(), e.agent_policy())),
                "password",
                false,
            );
        }
        if self.json_output {
            let mut withheld = WithheldSummary::new();
            let listed: Vec<ListedCredential> = entries
                .iter()
                .map(|entry| {
                    withheld.record(entry.agent_policy());
                    ListedCredential::from_entry(entry)
                })
                .collect();
            withheld.report();
            let output = ListOutput::new("credentials", listed);
            Ok(Some(output.to_json()?))
        } else {
            if self.verbose {
                WithheldSummary::tally(entries.iter().map(|e| e.agent_policy())).report();
            }
            Ok(Some(Self::format_credentials_plain(&entries, self.verbose)))
        }
    }

    fn list_payments(&self, vault: &mut Box<dyn Vault>) -> Result<Option<String>, Error> {
        let entries = vault.find_payments();
        // Card numbers and CVVs are always part of payment listings.
        agent::log_bulk_ask_requests(
            entries
                .iter()
                .map(|e| (e.name().to_string(), e.agent_policy())),
            "number",
            false,
        );
        let mut withheld = WithheldSummary::new();
        let listed: Vec<ListedPayment> = entries
            .iter()
            .map(|entry| {
                let reason = withheld_reason(entry.agent_policy());
                withheld.record(entry.agent_policy());
                ListedPayment::from_entry(entry, reason.is_some())
            })
            .collect();
        withheld.report();
        if self.json_output {
            let output = ListOutput::new("payment_cards", listed);
            Ok(Some(output.to_json()?))
        } else {
            Ok(Some(Self::format_payments_plain(&entries)))
        }
    }

    fn list_notes(&self, vault: &mut Box<dyn Vault>) -> Result<Option<String>, Error> {
        let entries = vault.find_notes();
        // Note content is always part of note listings.
        agent::log_bulk_ask_requests(
            entries
                .iter()
                .map(|e| (e.title().to_string(), e.agent_policy())),
            "content",
            false,
        );
        let mut withheld = WithheldSummary::new();
        let listed: Vec<ListedNote> = entries
            .iter()
            .map(|entry| {
                let reason = withheld_reason(entry.agent_policy());
                withheld.record(entry.agent_policy());
                ListedNote::from_entry(entry, reason.is_some())
            })
            .collect();
        withheld.report();
        if self.json_output {
            let output = ListOutput::new("notes", listed);
            Ok(Some(output.to_json()?))
        } else {
            Ok(Some(Self::format_notes_plain(&entries)))
        }
    }

    fn list_totp(&self, vault: &mut Box<dyn Vault>) -> Result<Option<String>, Error> {
        let entries = vault.find_totp(self.search_pattern.as_deref());
        if self.code {
            return self.list_totp_codes(&entries);
        }
        if self.json_output || self.verbose {
            // Only verbose output (and JSON, which always serializes the
            // secret) reveals the stored secrets.
            agent::log_bulk_ask_requests(
                entries
                    .iter()
                    .map(|e| (e.label().to_string(), e.agent_policy())),
                "secret",
                false,
            );
        }
        if self.json_output {
            // JSON always serializes the stored secret.
            let mut withheld = WithheldSummary::new();
            let listed: Vec<ListedTotp> = entries
                .iter()
                .map(|entry| {
                    let reason = withheld_reason(entry.agent_policy());
                    withheld.record(entry.agent_policy());
                    ListedTotp::from_entry(entry, reason.is_some())
                })
                .collect();
            withheld.report();
            let output = ListOutput::new("totp", listed);
            Ok(Some(output.to_json()?))
        } else {
            if self.verbose {
                WithheldSummary::tally(entries.iter().map(|e| e.agent_policy())).report();
            }
            Ok(Some(Self::format_totp_plain(&entries, self.verbose)))
        }
    }

    fn list_totp_codes(&self, entries: &[Totp]) -> Result<Option<String>, Error> {
        agent::log_bulk_ask_requests(
            entries
                .iter()
                .map(|e| (e.label().to_string(), e.agent_policy())),
            "code",
            false,
        );
        let mut withheld = WithheldSummary::new();
        let mut codes = Vec::with_capacity(entries.len());
        for entry in entries {
            let reason = withheld_reason(entry.agent_policy());
            withheld.record(entry.agent_policy());
            // Do not even compute a code the policy withholds.
            match reason {
                None => {
                    let code = entry.get_code()?;
                    codes.push(TotpCodeEntry {
                        label: entry.label().to_string(),
                        issuer: entry.issuer().to_string(),
                        code: Some(code.value),
                        valid_for_seconds: code.valid_for_seconds,
                        agent: entry.agent_policy().as_str().to_string(),
                    });
                }
                Some(_) => codes.push(TotpCodeEntry {
                    label: entry.label().to_string(),
                    issuer: entry.issuer().to_string(),
                    code: None,
                    valid_for_seconds: 0,
                    agent: entry.agent_policy().as_str().to_string(),
                }),
            }
        }
        withheld.report();
        if self.json_output {
            let output = ListOutput::new("totp_codes", codes);
            Ok(Some(output.to_json()?))
        } else {
            Ok(Some(Self::format_totp_codes_plain(&codes)))
        }
    }

    fn format_totp_codes_plain(entries: &[TotpCodeEntry]) -> String {
        let count = entries.len();
        if count == 0 {
            return "Found 0 TOTP entries.".to_string();
        }
        let mut lines = vec![format!("Found {} TOTP entries:", count)];
        for entry in entries {
            lines.push(String::new());
            lines.push(format!("Label: {}", entry.label));
            lines.push(format!("Issuer: {}", entry.issuer));
            match &entry.code {
                Some(code) => {
                    lines.push(format!("Code: {}", code));
                    lines.push(format!("Valid for: {} seconds", entry.valid_for_seconds));
                }
                None => lines.push(format!("Code: [withheld: agent={}]", entry.agent)),
            }
        }
        lines.join("\n")
    }

    fn format_credentials_plain(entries: &[Credential], verbose: bool) -> String {
        let count = entries.len();
        if count == 0 {
            return "Found 0 credentials.".to_string();
        }
        let mut lines = vec![format!("Found {} credentials:", count)];
        for entry in entries {
            let restricted = withheld_reason(entry.agent_policy()).is_some();
            lines.push(String::new());
            lines.push(format!("Title: {}", entry.title()));
            if let Some(url) = entry.url() {
                lines.push(format!("URL: {}", url));
            }
            lines.push(format!("Username: {}", entry.username()));
            if let Some(note) = entry.note().filter(|_| !restricted) {
                lines.push(format!("Note: {}", note));
            }
            if !entry.tags().is_empty() {
                lines.push(format!("Tags: {}", entry.tags().join(", ")));
            }
            if let Some(expiry) = entry.expiry_time().filter(|_| entry.expires()) {
                lines.push(format!("Expires: {}", expiry.format("%d.%m.%Y")));
            }
            if restricted {
                // Notes and custom attributes can carry secrets; keep only
                // the policy attribute itself visible.
                lines.push(format!(
                    "agent: {}",
                    entry.agent_policy().as_str()
                ));
            } else {
                for (key, value) in entry.custom_attributes() {
                    lines.push(format!("{}: {}", key, value));
                }
            }
            if verbose {
                match withheld_reason(entry.agent_policy()) {
                    None => {
                        lines.push(format!("Password: {}", entry.password()));
                    }
                    Some(reason) => {
                        lines.push(format!("Password: [withheld: {}]", reason));
                    }
                }
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
            let withheld = withheld_reason(entry.agent_policy());
            lines.push(String::new());
            lines.push(format!("Name: {}", entry.name()));
            lines.push(format!("Name on Card: {}", entry.name_on_card()));
            match withheld {
                None => {
                    lines.push(format!("Number: {}", entry.number()));
                    lines.push(format!("CVV: {}", entry.cvv()));
                }
                Some(reason) => {
                    lines.push(format!("Number: [withheld: {}]", reason));
                    lines.push("CVV: [withheld]".to_string());
                }
            }
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
            match withheld_reason(entry.agent_policy()) {
                None => lines.push(format!("Content: {}", entry.content())),
                Some(reason) => lines.push(format!("Content: [withheld: {}]", reason)),
            }
            lines.push(format!("Last Modified: {}", entry.last_modified()));
        }
        lines.join("\n")
    }

    fn format_totp_plain(entries: &[Totp], verbose: bool) -> String {
        let count = entries.len();
        if count == 0 {
            return "Found 0 TOTP entries.".to_string();
        }
        let mut lines = vec![format!("Found {} TOTP entries:", count)];
        for entry in entries {
            lines.push(String::new());
            lines.push(format!("Label: {}", entry.label()));
            lines.push(format!("Issuer: {}", entry.issuer()));
            if verbose {
                match withheld_reason(entry.agent_policy()) {
                    None => lines.push(format!("Secret: {}", entry.secret())),
                    Some(reason) => lines.push(format!("Secret: [withheld: {}]", reason)),
                }
            }
            lines.push(format!("Last Modified: {}", entry.last_modified()));
        }
        lines.join("\n")
    }
}

impl UnlockingAction for ListAction {
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
    use passlane_core::vault::entities::{Address, Expiry};
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn test_credential_json_serialization() {
        let cred = Credential::new(
            Some(&Uuid::nil()),
            "secret123",
            "google.com",
            "user@example.com",
            None,
            Some(Utc::now()),
        );
        let json = serde_json::to_string(&cred).unwrap();
        assert!(json.contains("\"uuid\""));
        assert!(json.contains("\"title\""));
        assert!(json.contains("\"url\""));
        assert!(json.contains("\"username\""));
        assert!(json.contains("\"password\""));
        assert!(json.contains("\"tags\""));
        assert!(json.contains("\"expires\""));
        assert!(json.contains("\"custom_attributes\""));
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
            None,
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
        let cred = Credential::new(None, "secret", "google.com", "user@test.com", None, None)
            .with_url(Some("https://google.com"));
        let result = ListAction::format_credentials_plain(&[cred], false);
        assert!(result.contains("Found 1 credentials:"));
        assert!(result.contains("Title: google.com"));
        assert!(result.contains("URL: https://google.com"));
        assert!(result.contains("Username: user@test.com"));
        assert!(!result.contains("Password:"));
    }

    #[test]
    fn test_format_credentials_plain_verbose() {
        let cred = Credential::new(None, "secret", "google.com", "user@test.com", None, None)
            .with_tags(&["work".to_string()])
            .with_custom_attributes(&[("agent".to_string(), "allow".to_string())]);
        let result = ListAction::format_credentials_plain(&[cred], true);
        assert!(result.contains("Found 1 credentials:"));
        assert!(result.contains("Title: google.com"));
        assert!(result.contains("Username: user@test.com"));
        assert!(result.contains("Tags: work"));
        assert!(result.contains("Password: secret"));
        assert!(result.contains("Last Modified:"));
    }

    #[test]
    fn test_format_credentials_plain_verbose_withholds_restricted() {
        // Default (no attribute) is `never`: the password is withheld.
        let never = Credential::new(None, "secret", "root", "admin", Some("root note"), None)
            .with_custom_attributes(&[
                ("agent".to_string(), "never".to_string()),
                ("Recovery code".to_string(), "12345".to_string()),
            ]);
        let ask = Credential::new(None, "secret", "stripe", "api", None, None)
            .with_custom_attributes(&[("agent".to_string(), "ask".to_string())]);
        let result = ListAction::format_credentials_plain(&[never.clone(), ask], true);
        assert!(!result.contains("Password: secret"), "passwords must be withheld");
        assert!(result.contains("Password: [withheld: agent=never]"));
        assert!(result.contains("Password: [withheld: agent=ask, needs owner approval]"));
        // Notes and custom attribute values can carry secrets: restricted
        // entries keep only the policy attribute itself.
        assert!(!result.contains("root note"), "notes must be withheld");
        assert!(!result.contains("12345"), "custom attribute values must be withheld");
        assert!(result.contains("agent: never"));
        // Metadata stays so the entry is identifiable.
        assert!(result.contains("Title: root"));
        assert!(result.contains("Username: admin"));
        // Allowed entries keep their notes and attributes.
        let allow = Credential::new(None, "secret", "github.com", "ci", Some("ci note"), None)
            .with_custom_attributes(&[
                ("agent".to_string(), "allow".to_string()),
                ("Recovery code".to_string(), "99999".to_string()),
            ]);
        let result = ListAction::format_credentials_plain(&[allow], true);
        assert!(result.contains("Note: ci note"));
        assert!(result.contains("Recovery code: 99999"));
    }

    fn allow_cred(title: &str) -> Credential {
        Credential::new(None, "secret", title, "user@test.com", None, None)
            .with_custom_attributes(&[("agent".to_string(), "allow".to_string())])
    }

    #[test]
    fn test_format_payments_plain() {
        let card = PaymentCard::new(
            None, "Visa", "John Doe", "4532123456789012", "123",
            Expiry { month: 6, year: 2025 }, Some("Gold"), None, None,
        )
        .with_agent_policy(AgentPolicy::Allow);
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
    fn test_format_payments_plain_withholds_restricted() {
        let card = PaymentCard::new(
            None, "Visa", "John Doe", "4532123456789012", "123",
            Expiry { month: 6, year: 2025 }, None, None, None,
        );
        let result = ListAction::format_payments_plain(&[card]);
        assert!(!result.contains("4532123456789012"), "card number must be withheld");
        assert!(!result.contains("CVV: 123"));
        assert!(result.contains("Number: [withheld: agent=never]"));
        assert!(result.contains("CVV: [withheld]"));
        // Metadata survives so the entry is still identifiable.
        assert!(result.contains("Name: Visa"));
    }

    #[test]
    fn test_format_notes_plain() {
        let note = Note::new(None, "My Note", "Some content", None)
            .with_agent_policy(AgentPolicy::Allow);
        let result = ListAction::format_notes_plain(&[note]);
        assert!(result.contains("Found 1 notes:"));
        assert!(result.contains("Title: My Note"));
        assert!(result.contains("Content: Some content"));
    }

    #[test]
    fn test_format_notes_plain_withholds_restricted() {
        let note = Note::new(None, "My Note", "Some content", None)
            .with_agent_policy(AgentPolicy::Ask);
        let result = ListAction::format_notes_plain(&[note]);
        assert!(!result.contains("Some content"), "note content must be withheld");
        assert!(result.contains("Content: [withheld: agent=ask, needs owner approval]"));
        assert!(result.contains("Title: My Note"));
    }

    #[test]
    fn test_format_totp_plain_non_verbose() {
        let totp = Totp::new(
            None, "otpauth://totp/test", "user@test.com", "GitHub",
            "JBSWY3DPEHPK3PXP", "SHA1", 30, 6, None,
        );
        let result = ListAction::format_totp_plain(&[totp], false);
        assert!(result.contains("Found 1 TOTP entries:"));
        assert!(result.contains("Label: user@test.com"));
        assert!(result.contains("Issuer: GitHub"));
        assert!(!result.contains("Secret:"));
        assert!(!result.contains("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn test_format_totp_plain_verbose() {
        let totp = Totp::new(
            None, "otpauth://totp/test", "user@test.com", "GitHub",
            "JBSWY3DPEHPK3PXP", "SHA1", 30, 6, None,
        )
        .with_agent_policy(AgentPolicy::Allow);
        let result = ListAction::format_totp_plain(&[totp], true);
        assert!(result.contains("Secret: JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn test_format_totp_plain_verbose_withholds_restricted() {
        let totp = Totp::new(
            None, "otpauth://totp/test", "user@test.com", "GitHub",
            "JBSWY3DPEHPK3PXP", "SHA1", 30, 6, None,
        );
        let result = ListAction::format_totp_plain(&[totp], true);
        assert!(!result.contains("JBSWY3DPEHPK3PXP"), "secret must be withheld");
        assert!(result.contains("Secret: [withheld: agent=never]"));
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
        let result = ListAction::format_totp_plain(&[], false);
        assert_eq!(result, "Found 0 TOTP entries.");
    }

    #[test]
    fn test_format_totp_codes_plain() {
        let entries = vec![
            TotpCodeEntry {
                label: "user@test.com".to_string(),
                issuer: "GitHub".to_string(),
                code: Some("123456".to_string()),
                valid_for_seconds: 17,
                agent: "allow".to_string(),
            },
            TotpCodeEntry {
                label: "admin@root".to_string(),
                issuer: "Root".to_string(),
                code: None,
                valid_for_seconds: 0,
                agent: "never".to_string(),
            },
        ];
        let result = ListAction::format_totp_codes_plain(&entries);
        assert!(result.contains("Found 2 TOTP entries:"));
        assert!(result.contains("Label: user@test.com"));
        assert!(result.contains("Issuer: GitHub"));
        assert!(result.contains("Code: 123456"));
        assert!(result.contains("Valid for: 17 seconds"));
        // The stored secret must never appear in code output.
        assert!(!result.contains("Secret"));
        // Withheld codes are explicit, not silently missing.
        assert!(result.contains("Code: [withheld: agent=never]"));
    }

    #[test]
    fn test_format_totp_codes_plain_empty() {
        let result = ListAction::format_totp_codes_plain(&[]);
        assert_eq!(result, "Found 0 TOTP entries.");
    }

    #[test]
    fn test_totp_codes_json_envelope() {
        let entries = vec![
            TotpCodeEntry {
                label: "a@test.com".to_string(),
                issuer: "GitHub".to_string(),
                code: Some("111111".to_string()),
                valid_for_seconds: 30,
                agent: "allow".to_string(),
            },
            TotpCodeEntry {
                label: "b@test.com".to_string(),
                issuer: "GitLab".to_string(),
                code: Some("222222".to_string()),
                valid_for_seconds: 12,
                agent: "allow".to_string(),
            },
        ];
        let output = ListOutput::new("totp_codes", entries);
        let json = output.to_json().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["type"], "totp_codes");
        assert_eq!(parsed["count"], 2);
        let arr = parsed["entries"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
        for entry in arr {
            assert!(entry.get("label").is_some());
            assert!(entry.get("issuer").is_some());
            assert!(entry.get("code").is_some());
            assert!(entry.get("valid_for_seconds").is_some());
            // The stored secret must never be serialized in code output.
            assert!(entry.get("secret").is_none());
        }
        assert_eq!(arr[0]["code"], "111111");
        assert_eq!(arr[1]["valid_for_seconds"], 12);
    }

    #[test]
    fn test_listed_credential_json_withholds_restricted_passwords() {
        let allowed = allow_cred("github.com");
        let never = Credential::new(None, "root-secret", "root", "admin", Some("root note"), None)
            .with_custom_attributes(&[
                ("agent".to_string(), "never".to_string()),
                ("Recovery code".to_string(), "12345".to_string()),
            ]);
        let ask = Credential::new(None, "stripe-secret", "stripe", "api", None, None)
            .with_custom_attributes(&[("agent".to_string(), "ask".to_string())]);

        let json = ListOutput::new(
            "credentials",
            vec![
                ListedCredential::from_entry(&allowed),
                ListedCredential::from_entry(&never),
                ListedCredential::from_entry(&ask),
            ],
        )
        .to_json()
        .unwrap();

        assert!(!json.contains("root-secret"), "never entries must be redacted");
        assert!(!json.contains("stripe-secret"), "ask entries must be redacted");
        assert!(!json.contains("root note"), "notes must be redacted");
        assert!(!json.contains("12345"), "custom attribute values must be redacted");
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let entries = parsed["entries"].as_array().unwrap();
        assert_eq!(entries[0]["password"], "secret");
        assert_eq!(entries[0]["agent"], "allow");
        assert!(entries[1]["password"].is_null());
        assert_eq!(entries[1]["agent"], "never");
        // Only the policy attribute survives on restricted entries.
        assert_eq!(
            entries[1]["custom_attributes"],
            serde_json::json!([["agent", "never"]])
        );
        assert!(entries[2]["password"].is_null());
        assert_eq!(entries[2]["agent"], "ask");
        // Metadata stays so the entry is still identifiable.
        assert_eq!(entries[1]["title"], "root");
    }

    #[test]
    fn test_listed_payment_note_totp_json_withhold_secrets() {
        let card = PaymentCard::new(
            None, "Visa", "Jane", "4532123456789012", "123",
            Expiry { month: 6, year: 2025 }, None, None, None,
        );
        let card_json = serde_json::to_string(&ListedPayment::from_entry(&card, true)).unwrap();
        assert!(!card_json.contains("4532123456789012"));
        assert!(!card_json.contains("\"cvv\":\"123\""));
        assert!(card_json.contains("\"agent\":\"never\""));

        let note = Note::new(None, "wifi", "wpa-key", None);
        let note_json = serde_json::to_string(&ListedNote::from_entry(&note, true)).unwrap();
        assert!(!note_json.contains("wpa-key"));
        assert!(note_json.contains("\"title\":\"wifi\""));

        let totp = Totp::new(
            None, "otpauth://totp/t?secret=JBSWY3DPEHPK3PXP", "l", "i",
            "JBSWY3DPEHPK3PXP", "SHA1", 30, 6, None,
        );
        let totp_json = serde_json::to_string(&ListedTotp::from_entry(&totp, true)).unwrap();
        assert!(!totp_json.contains("JBSWY3DPEHPK3PXP"));
        assert!(totp_json.contains("\"label\":\"l\""));
    }

    #[test]
    fn test_withheld_reason_matches_policy() {
        assert_eq!(withheld_reason(AgentPolicy::Allow), None);
        assert_eq!(withheld_reason(AgentPolicy::Never), Some("agent=never"));
        let ask_reason = withheld_reason(AgentPolicy::Ask).unwrap();
        assert!(ask_reason.starts_with("agent=ask"));
    }
}
