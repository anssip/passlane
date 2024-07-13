use crate::vault::entities::{Credential, Error, Note, PaymentCard, Totp};
use uuid::Uuid;

pub trait PasswordVault {
    fn get_master_password(&self) -> String;

    fn grep(&self, grep: Option<&str>) -> Vec<Credential>;

    fn save_credentials(&mut self, credentials: &Vec<Credential>) -> Result<i8, Error>;

    fn save_one_credential(&mut self, credential: Credential) -> Result<(), Error>;

    fn update_credential(&mut self, credential: Credential) -> Result<(), Error>;

    fn delete_credentials(&mut self, uuid: &Uuid) -> Result<(), Error>;

    fn delete_matching(&mut self, grep: &str) -> Result<i8, Error>;
}

pub trait PaymentVault {
    fn find_payments(&self) -> Vec<PaymentCard>;

    fn save_payment(&mut self, payment: PaymentCard) -> Result<(), Error>;

    fn delete_payment(&mut self, uuid: &Uuid) -> Result<(), Error>;
}

pub trait NoteVault {
    fn find_notes(&self) -> Vec<Note>;

    fn save_note(&mut self, note: &Note) -> Result<(), Error>;

    fn delete_note(&mut self, uuid: &Uuid) -> Result<(), Error>;
}

pub trait TotpVault {
    fn find_totp(&self, grep: Option<&str>) -> Vec<Totp>;

    fn save_totp(&mut self, totp: &Totp) -> Result<(), Error>;

    fn delete_totp(&mut self, uuid: &Uuid) -> Result<(), Error>;
}

pub trait Vault: PasswordVault + PaymentVault + NoteVault + TotpVault {}
