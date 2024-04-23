use anyhow::bail;
use csv::{ReaderBuilder, Writer};
use serde::Deserialize;
use serde::Serialize;
use std::fs::create_dir;
use std::fs::remove_file;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::path::Path;
use std::path::PathBuf;
use uuid::Uuid;
use crate::vault::entities::{Credential, Date, Note, PaymentCard};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CSVInputCredentials {
    pub service: String,
    pub username: String,
    pub password: String,
}

impl CSVInputCredentials {
    pub fn to_credential(&self) -> Credential {
        Credential {
            uuid: Uuid::new_v4(),
            service: self.service.clone(),
            username: self.username.clone(),
            password: self.password.clone(),
            notes: None,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CSVPaymentCard {
    pub name: String,
    pub name_on_card: String,
    pub number: String,
    pub cvv: String,
    pub expiry: String,
    pub color: String,
    pub billing_address: String,

}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CSVSecureNote {
    pub title: String,
    pub note: String,
}

fn home_dir() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("~"))
}

fn dir_path() -> PathBuf {
    let dir_path = PathBuf::from(home_dir()).join(".passlane");
    let exists = Path::new(&dir_path).exists();
    if !exists {
        create_dir(&dir_path).expect("Unable to create .passlane dir");
    }
    dir_path
}

fn master_password_file_path() -> PathBuf {
    PathBuf::from(dir_path()).join(".master_pwd")
}

fn vault_file_path() -> PathBuf {
    // TODO: implement possibility to change the vault file path. Store location in a config file.
    PathBuf::from(dir_path()).join("store.kdbx")
}

pub fn save_master_password(master_pwd: &str) {
    let file_path = master_password_file_path();
    let mut file = File::create(file_path).expect("Cannot create master password file");
    file.write_all(master_pwd.as_bytes())
        .expect("Unable write to master password file");
}

pub fn read_from_csv(file_path: &str) -> anyhow::Result<Vec<CSVInputCredentials>> {
    let path = PathBuf::from(file_path);
    let in_file = OpenOptions::new().read(true).open(path)?;
    let mut reader = ReaderBuilder::new().has_headers(true).from_reader(in_file);
    let credentials = &mut Vec::new();
    for result in reader.deserialize() {
        credentials.push(result?);
    }
    Ok(credentials.clone())
}

fn read_from_file(path: &PathBuf) -> Option<String> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(false)
        .create_new(false)
        .open(&path).unwrap();

    let mut file_content = String::new();
    file.read_to_string(&mut file_content).expect("Unable to read master password file");
    Some(file_content.trim().parse().unwrap())
}

pub fn get_keyfile_path() -> Option<String> {
    let path = dir_path().join(".keyfile_path");
    if !path.exists() {
        return None;
    }
    read_from_file(&path)
}

pub(crate) fn write_credentials_to_csv(file_path: &str, creds: &Vec<Credential>) -> anyhow::Result<i64> {
    let mut wtr = Writer::from_path(file_path)?;
    for cred in creds {
        wtr.serialize(CSVInputCredentials {
            service: String::from(&cred.service),
            username: String::from(&cred.username),
            password: String::from(&cred.password),
        })?;
    }
    wtr.flush()?;
    Ok(creds.len() as i64)
}

pub(crate) fn write_payment_cards_to_csv(file_path: &str, cards: &Vec<PaymentCard>) -> anyhow::Result<i64> {
    let mut wtr = Writer::from_path(file_path)?;
    for card in cards {
        wtr.serialize(CSVPaymentCard {
            name: String::from(&card.name),
            name_on_card: String::from(&card.name_on_card),
            number: String::from(&card.number),
            cvv: String::from(&card.cvv),
            expiry: format!("{}", card.expiry),
            color: match &card.color {
                Some(color) => String::from(color),
                None => String::from("")
            },
            billing_address: match &card.billing_address {
                Some(address) => format!("{}", address),
                None => String::from("")
            },
        })?;
    }
    wtr.flush()?;
    Ok(cards.len() as i64)
}

pub(crate) fn write_secure_notes_to_csv(file_path: &str, notes: &Vec<Note>) -> anyhow::Result<i64> {
    let mut wtr = Writer::from_path(file_path)?;
    for note in notes {
        wtr.serialize(CSVSecureNote {
            title: String::from(&note.title),
            note: String::from(&note.content),
        })?;
    }
    wtr.flush()?;
    Ok(notes.len() as i64)
}

pub(crate) fn is_unlocked() -> bool {
    master_password_file_path().exists()
}

pub(crate) fn get_vault_path() -> String {
    vault_file_path().to_str().unwrap().to_string()
}