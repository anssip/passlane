use std::fmt::{Display, Formatter};
use uuid::Uuid;
use std::num::ParseIntError;
use std::fmt;
use std::str::FromStr;

#[derive(Clone)]
pub struct Date(pub String);

impl Display for Date {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug)]
pub struct Error {
    pub message: String,
}

#[derive(Clone)]
pub struct Credential {
    pub uuid: Uuid,
    pub password: String,
    pub service: String,
    pub username: String,
    pub notes: Option<String>,
}

pub struct PaymentCard {
    pub id: Uuid,
    pub name: String,
    pub name_on_card: String,
    pub number: String,
    pub cvv: String,
    pub expiry: Expiry,
    pub color: Option<String>,
    pub billing_address: Option<Address>,
}

pub struct Totp {
    pub id: Uuid,
    pub label: String,
    pub issuer: String,
    pub secret: String,
    pub algorithm: String,
    pub period: u32,
    pub digits: u32,
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

pub struct Expiry {
    pub month: i32,
    pub year: i32,
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
        let month = parts[0].parse::<i32>().map_err(ExpiryParseError::ParseError)?;
        let year = parts[1].parse::<i32>().map_err(ExpiryParseError::ParseError)?;
        Ok(Expiry { month, year })
    }
}

pub struct Address {
    pub id: Uuid,
    pub street: String,
    pub city: String,
    pub country: String,
    pub state: Option<String>,
    pub zip: String,
}

pub struct Note {
    pub id: Uuid,
    pub title: String,
    pub content: String,
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
            AddressParseError::InvalidFormat => write!(f, "Invalid format. Expected Street, Zip, City, Country"),
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
        Ok(Address { id: Uuid::new_v4(), street, city, country, state: None, zip })
    }
}