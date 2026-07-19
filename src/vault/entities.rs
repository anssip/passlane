use chrono::{DateTime, Utc};
use keepass_ng::db::TOTP;
use log::debug;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fmt::{Display, Formatter};
use std::num::ParseIntError;
use std::str::FromStr;
use std::time::SystemTimeError;
use uuid::Uuid;

use crate::crypto::SPECIAL;

#[derive(Debug)]
pub struct Error {
    pub message: String,
}

impl Error {
    pub fn new(message: &str) -> Self {
        Error {
            message: message.to_string(),
        }
    }
}

impl From<SystemTimeError> for Error {
    fn from(err: SystemTimeError) -> Self {
        Error {
            message: err.to_string(),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error {
            message: err.to_string(),
        }
    }
}

impl From<anyhow::Error> for Error {
    fn from(err: anyhow::Error) -> Self {
        Error {
            message: err.to_string(),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.message)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Credential {
    uuid: Uuid,
    password: String,
    service: String,
    username: String,
    #[serde(default)]
    note: Option<String>,
    #[serde(default = "default_last_modified")]
    last_modified: DateTime<Utc>,
}

fn default_last_modified() -> DateTime<Utc> {
    Utc::now()
}

impl Credential {
    pub fn new(
        uuid: Option<&Uuid>,
        password: &str,
        service: &str,
        username: &str,
        note: Option<&str>,
        last_modified: Option<DateTime<Utc>>,
    ) -> Self {
        Credential {
            uuid: uuid.map(|id| id.clone()).unwrap_or_else(|| Uuid::new_v4()),
            password: password.to_string(),
            service: sanitize(service),
            username: sanitize(username),
            note: note.map(|n| sanitize(n)).filter(|n| !n.is_empty()),
            last_modified: last_modified.unwrap_or(Utc::now()),
        }
    }

    pub fn uuid(&self) -> &Uuid {
        &self.uuid
    }

    pub fn password(&self) -> &str {
        &self.password
    }

    pub fn service(&self) -> &str {
        &self.service
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn note(&self) -> Option<&str> {
        self.note.as_deref()
    }

    pub fn last_modified(&self) -> &DateTime<Utc> {
        &self.last_modified
    }
}

#[derive(Clone, Serialize)]
pub struct PaymentCard {
    id: Uuid,
    name: String,
    name_on_card: String,
    number: String,
    cvv: String,
    expiry: Expiry,
    color: Option<String>,
    billing_address: Option<Address>,
    last_modified: DateTime<Utc>,
}

impl PaymentCard {
    pub fn new(
        id: Option<&Uuid>,
        name: &str,
        name_on_card: &str,
        number: &str,
        cvv: &str,
        expiry: Expiry,
        color: Option<&str>,
        billing_address: Option<&Address>,
        last_modified: Option<DateTime<Utc>>,
    ) -> Self {
        PaymentCard {
            id: id.map(|id| id.clone()).unwrap_or_else(|| Uuid::new_v4()),
            name: sanitize(name),
            name_on_card: sanitize(name_on_card),
            number: sanitize(number),
            cvv: sanitize(cvv),
            expiry,
            color: color.map(sanitize),
            billing_address: billing_address.cloned(),
            last_modified: last_modified.unwrap_or_else(|| Utc::now()),
        }
    }

    pub fn id(&self) -> &Uuid {
        &self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn name_on_card(&self) -> &str {
        &self.name_on_card
    }

    pub fn number(&self) -> &str {
        &self.number
    }

    pub fn cvv(&self) -> &str {
        &self.cvv
    }

    pub fn expiry(&self) -> &Expiry {
        &self.expiry
    }

    pub fn color(&self) -> Option<&String> {
        self.color.as_ref()
    }

    pub fn billing_address(&self) -> Option<&Address> {
        self.billing_address.as_ref()
    }

    pub fn last_modified(&self) -> &DateTime<Utc> {
        &self.last_modified
    }

    pub fn last4(&self) -> String {
        let num = &self.number;
        if num.len() >= 4 {
            format!("•••• {}", &num[num.len() - 4..])
        } else {
            format!("•••• {}", num)
        }
    }
}

#[derive(Clone, Serialize)]
pub struct Totp {
    id: Uuid,
    #[serde(skip_serializing)]
    url: String,
    label: String,
    issuer: String,
    secret: String,
    algorithm: String,
    period: u64,
    digits: u32,
    last_modified: DateTime<Utc>,
}

impl Totp {
    pub fn new(
        id: Option<&Uuid>,
        url: &str,
        label: &str,
        issuer: &str,
        secret: &str,
        algorithm: &str,
        period: u64,
        digits: u32,
        last_modified: Option<DateTime<Utc>>,
    ) -> Self {
        Totp {
            id: id.map(|id| id.clone()).unwrap_or_else(|| Uuid::new_v4()),
            url: url.to_string(),
            label: sanitize(label),
            issuer: issuer.to_string(),
            secret: secret.to_string(),
            algorithm: algorithm.to_string(),
            period,
            digits,
            last_modified: last_modified.unwrap_or_else(|| Utc::now()),
        }
    }

    pub fn id(&self) -> &Uuid {
        &self.id
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn secret(&self) -> &str {
        &self.secret
    }

    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    pub fn period(&self) -> u64 {
        self.period
    }

    pub fn digits(&self) -> u32 {
        self.digits
    }

    pub fn last_modified(&self) -> &DateTime<Utc> {
        &self.last_modified
    }
}

impl Display for Totp {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "label: {}, issuer: {}, algo: {}, digits: {}",
            self.label, self.issuer, self.algorithm, self.digits
        )
    }
}

pub struct TotpCode {
    pub value: String,
    pub valid_for_seconds: u64,
}

impl Totp {
    pub fn get_code(&self) -> Result<TotpCode, Error> {
        let totp = TOTP::from_str(&self.url)
            .map_err(|e| Error::new(&format!("Failed to parse totp url: {:?}", e)))?;

        debug!("Getting code for totp: {}", totp.label);
        let code = totp.value_now()?;
        Ok(TotpCode {
            value: code.code,
            valid_for_seconds: code.valid_for.as_secs(),
        })
    }
}

impl PaymentCard {
    pub fn color_str(&self) -> String {
        if let Some(color) = &self.color {
            color.clone()
        } else {
            "".to_string()
        }
    }
    pub fn expiry_str(&self) -> String {
        self.expiry.to_string()
    }
}

#[derive(Clone, Serialize)]
pub struct Expiry {
    pub month: u32,
    pub year: u32,
}

impl Display for Expiry {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.month, self.year)
    }
}

#[derive(Debug)]
pub enum ExpiryParseError {
    InvalidFormat,
    ParseError(ParseIntError),
}

impl fmt::Display for ExpiryParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ExpiryParseError::InvalidFormat => write!(f, "Invalid format. Expected MM/YYYY"),
            ExpiryParseError::ParseError(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for ExpiryParseError {}

impl From<ParseIntError> for ExpiryParseError {
    fn from(err: ParseIntError) -> ExpiryParseError {
        ExpiryParseError::ParseError(err)
    }
}

impl FromStr for Expiry {
    type Err = ExpiryParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() != 2 {
            return Err(ExpiryParseError::InvalidFormat);
        }
        let month = parts[0]
            .parse::<u32>()
            .map_err(ExpiryParseError::ParseError)?;
        let year = parts[1]
            .parse::<u32>()
            .map_err(ExpiryParseError::ParseError)?;
        Ok(Expiry { month, year })
    }
}

#[derive(Clone, Serialize)]
pub struct Address {
    id: Uuid,
    street: String,
    city: String,
    country: String,
    state: Option<String>,
    zip: String,
}

impl Address {
    pub fn new(
        id: Option<&Uuid>,
        street: &str,
        city: &str,
        country: &str,
        state: Option<&str>,
        zip: &str,
    ) -> Self {
        Address {
            id: id.map(|id| id.clone()).unwrap_or_else(|| Uuid::new_v4()),
            street: sanitize(street),
            city: sanitize(city),
            country: sanitize(country),
            state: state.map(sanitize),
            zip: sanitize(zip),
        }
    }

    pub fn id(&self) -> &Uuid {
        &self.id
    }

    pub fn street(&self) -> &str {
        &self.street
    }

    pub fn city(&self) -> &str {
        &self.city
    }

    pub fn country(&self) -> &str {
        &self.country
    }

    pub fn state(&self) -> Option<&String> {
        self.state.as_ref()
    }

    pub fn zip(&self) -> &str {
        &self.zip
    }
}

#[derive(Clone, Serialize)]
pub struct Note {
    id: Uuid,
    title: String,
    content: String,
    last_modified: DateTime<Utc>,
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_alphanumeric() || c.is_whitespace() || SPECIAL.contains(*c))
        .collect::<String>()
}

impl Note {
    pub fn new(
        id: Option<&Uuid>,
        title: &str,
        content: &str,
        last_modified: Option<DateTime<Utc>>,
    ) -> Self {
        Note {
            id: id.map(|id| id.clone()).unwrap_or_else(|| Uuid::new_v4()),
            title: sanitize(title),
            content: sanitize(content),
            last_modified: last_modified.unwrap_or_else(Utc::now),
        }
    }
    pub fn id(&self) -> Uuid {
        self.id
    }
    pub fn title(&self) -> &str {
        &self.title
    }
    pub fn content(&self) -> &str {
        &self.content
    }
    pub fn last_modified(&self) -> DateTime<Utc> {
        self.last_modified
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}, {}, {}, {}",
            self.street, self.zip, self.city, self.country
        )
    }
}

#[derive(Debug)]
pub enum AddressParseError {
    InvalidFormat,
    ParseError(ParseIntError),
}

impl fmt::Display for AddressParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            AddressParseError::InvalidFormat => {
                write!(f, "Invalid format. Expected Street, Zip, City, Country")
            }
            AddressParseError::ParseError(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for AddressParseError {}

impl From<ParseIntError> for AddressParseError {
    fn from(err: ParseIntError) -> AddressParseError {
        AddressParseError::ParseError(err)
    }
}

impl FromStr for Address {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(',').collect();
        if parts.len() != 4 {
            return Err(AddressParseError::InvalidFormat);
        }
        let street = parts[0].trim().to_string();
        let zip = parts[1].trim().to_string();
        let city = parts[2].trim().to_string();
        let country = parts[3].trim().to_string();
        Ok(Address {
            id: Uuid::new_v4(),
            street,
            city,
            country,
            state: None,
            zip,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_card(number: &str) -> PaymentCard {
        PaymentCard::new(
            None,
            "Test Card",
            "John Doe",
            number,
            "123",
            Expiry { month: 12, year: 2025 },
            None,
            None,
            None,
        )
    }

    #[test]
    fn test_last4_normal_16_digit() {
        let card = make_card("4111111111111234");
        assert_eq!(card.last4(), "•••• 1234");
    }

    #[test]
    fn test_last4_short_number() {
        let card = make_card("12");
        assert_eq!(card.last4(), "•••• 12");
    }

    #[test]
    fn test_last4_exactly_4_digits() {
        let card = make_card("5678");
        assert_eq!(card.last4(), "•••• 5678");
    }

    #[test]
    fn test_credential_with_note() {
        let cred = Credential::new(None, "pass", "google.com", "user", Some("work account"), None);
        assert_eq!(cred.note(), Some("work account"));
    }

    #[test]
    fn test_credential_without_note() {
        let cred = Credential::new(None, "pass", "google.com", "user", None, None);
        assert_eq!(cred.note(), None);
    }

    #[test]
    fn test_credential_with_empty_note_becomes_none() {
        let cred = Credential::new(None, "pass", "google.com", "user", Some(""), None);
        assert_eq!(cred.note(), None);
    }

    #[test]
    fn test_credential_json_serialization_with_note() {
        let cred = Credential::new(None, "pass", "google.com", "user", Some("admin access"), None);
        let json = serde_json::to_string(&cred).unwrap();
        assert!(json.contains("\"note\":\"admin access\""));
    }

    #[test]
    fn test_credential_json_serialization_without_note() {
        let cred = Credential::new(None, "pass", "google.com", "user", None, None);
        let json = serde_json::to_string(&cred).unwrap();
        assert!(json.contains("\"note\":null"));
    }

    #[test]
    fn test_credential_deserialization_without_note_field() {
        let json = r#"{"uuid":"00000000-0000-0000-0000-000000000000","password":"pass","service":"google.com","username":"user","last_modified":"2024-01-01T00:00:00Z"}"#;
        let cred: Credential = serde_json::from_str(json).unwrap();
        assert_eq!(cred.note(), None);
    }
}
