use uuid::Uuid;
use crate::vault::entities::{Credential, Note, PaymentCard, Totp};

pub trait PasswordVault {
    fn get_master_password(&self) -> String;

    fn grep(&self, grep: Option<&str>) -> Vec<Credential>;

    fn save_credentials(
        &mut self,
        credentials: &Vec<Credential>,
    ) -> i8;

    fn save_one_credential(
        &mut self,
        credential: Credential,
    ) -> i8;

    fn delete_credentials(
        &mut self,
        uuid: &Uuid,
    ) -> i8;

    fn delete_matching(
        &mut self,
        grep: &str,
    ) -> i8;
}

pub trait PaymentVault {
    fn find_payments(&self) -> Vec<PaymentCard>;

    fn save_payment(
        &mut self,
        payment: PaymentCard,
    ) -> i8;

    fn delete_payment(&mut self, uuid: &Uuid) -> i8;
}

pub trait NoteVault {
    fn find_notes(&self) -> Vec<Note>;

    fn save_note(&mut self, note: &Note) -> i8;

    fn delete_note(&mut self, uuid: &Uuid) -> i8;
}

pub trait TotpVault {
    fn find_totp(&self, grep: Option<&str>) -> Vec<Totp>;

    fn save_totp(&mut self, totp: &Totp) -> i8;

    fn delete_totp(&mut self, uuid: &Uuid) -> i8;
}

pub trait Vault: PasswordVault + PaymentVault + NoteVault + TotpVault {}