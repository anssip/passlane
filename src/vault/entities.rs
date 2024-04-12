use std::fmt::{Display, Formatter};

pub struct Date(pub String);

impl Display for Date {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub struct Credential {
    pub created: Date,
    pub modified: Option<Date>,
    pub password: String,
    pub service: String,
    pub username: String,
    pub notes: Option<String>,
}

pub struct PaymentCard {
    pub id: i32,
    pub iv: String,
    pub name: String,
    pub name_on_card: String,
    pub number: String,
    pub cvv: String,
    pub expiry: Expiry,
    pub color: Option<String>,
    pub billing_address: Option<Address>,
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

pub struct Address {
    pub id: i32,
    pub street: String,
    pub city: String,
    pub country: String,
    pub state: Option<String>,
    pub zip: String,
}

pub struct Note {
    pub id: i32,
    pub iv: String,
    pub title: String,
    pub content: String,
    pub created: Date,
    pub modified: Option<Date>,
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
