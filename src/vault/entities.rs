use chrono::{DateTime, Utc};
use keepass_ng::db::TOTP;
use log::debug;
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

#[derive(Clone)]
pub struct Credential {
    uuid: Uuid,
    password: String,
    service: String,
    username: String,
    notes: Option<String>,
    last_modified: DateTime<Utc>,
}

impl Credential {
    pub fn new(
        uuid: Option<&Uuid>,
        password: &str,
        service: &str,
        username: &str,
        notes: Option<&str>,
        last_modified: Option<DateTime<Utc>>,
    ) -> Self {
        Credential {
            uuid: uuid.map(|id| id.clone()).unwrap_or_else(|| Uuid::new_v4()),
            password: password.to_string(),
            service: sanitize(service),
            username: sanitize(username),
            notes: notes.map(sanitize),
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

    pub fn notes(&self) -> Option<&String> {
        self.notes.as_ref()
    }

    pub fn last_modified(&self) -> &DateTime<Utc> {
        &self.last_modified
    }
}

#[derive(Clone)]
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
}

#[derive(Clone)]
pub struct Totp {
    id: Uuid,
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
            "label: {}, issuer: {}, secret: {}, algo: {}, digits: {}",
            self.label, self.issuer, self.secret, self.algorithm, self.digits
        )
    }
}

pub struct TotpCode {
    pub value: String,
    pub valid_for_seconds: u64,
}

impl Totp {
    pub fn get_code(&self) -> Result<TotpCode, Error> {
        let totp = TOTP::from_str(&self.url)?;

        debug!("Getting code for totp: {}", totp);
        let code = totp.value_now()?;
        Ok(TotpCode {
            value: code.code,
            valid_for_seconds: code.valid_for.as_secs(),
        })
    }
}

impl PaymentCard {
    pub fn last_four(&self) -> String {
        self.number
            .chars()
            .skip(self.number.len() - 4)
            .take(4)
            .collect::<String>()
    }
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

#[derive(Clone)]
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

#[derive(Clone)]
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

#[derive(Clone)]
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
