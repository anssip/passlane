use crate::vault::entities::{Credential, Error, Note, PaymentCard};
use csv::{ReaderBuilder, Writer};
use serde::Serialize;
use std::fs::create_dir;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::path::Path;
use std::path::PathBuf;

impl From<csv::Error> for Error {
    fn from(e: csv::Error) -> Self {
        Error {
            message: e.to_string(),
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error {
            message: e.to_string(),
        }
    }
}

#[derive(Debug, Serialize, Clone)]
pub struct CSVPaymentCard {
    pub name: String,
    pub name_on_card: String,
    pub number: String,
    pub cvv: String,
    pub expiry: String,
    pub color: String,
    pub billing_address: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct CSVSecureNote {
    pub title: String,
    pub note: String,
}

fn home_dir() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("~"))
}

fn dir_path() -> PathBuf {
    let dir_path = home_dir().join(".passlane");
    let exists = Path::new(&dir_path).exists();
    if !exists {
        create_dir(&dir_path).expect("Unable to create .passlane dir");
    }
    dir_path
}

pub fn read_from_csv(file_path: &str) -> anyhow::Result<Vec<Credential>> {
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
        .open(&path)
        .unwrap();

    let mut file_content = String::new();
    file.read_to_string(&mut file_content)
        .expect("Unable to read master password file");
    Some(file_content.trim().parse().unwrap())
}

fn resolve_keyfile_path(path_config_file: &str) -> Option<String> {
    let path = dir_path().join(path_config_file);
    if !path.exists() {
        None
    } else {
        read_from_file(&path)
    }
}

pub fn get_keyfile_path() -> Option<String> {
    resolve_keyfile_path(".keyfile_path")
}

pub(crate) fn get_totp_keyfile_path() -> Option<String> {
    resolve_keyfile_path(".totp_keyfile_path")
}

fn resolve_vault_path(default_filename: &str, path_config_filename: &str) -> String {
    let default_path = dir_path()
        .join(default_filename)
        .to_str()
        .unwrap()
        .to_string();
    let path = dir_path().join(path_config_filename);
    if path.exists() {
        return read_from_file(&path)
            .unwrap_or(default_path)
            .trim()
            .to_string();
    }
    default_path
}

pub(crate) fn get_vault_path() -> String {
    resolve_vault_path("store.kdbx", ".vault_path")
}

pub(crate) fn get_totp_vault_path() -> String {
    resolve_vault_path("totp.kdbx", ".totp_vault_path")
}

pub(crate) fn write_credentials_to_csv(
    file_path: &str,
    creds: &Vec<Credential>,
) -> Result<i64, Error> {
    let mut wtr = Writer::from_path(file_path)?;
    for cred in creds {
        wtr.serialize(cred)?;
    }
    wtr.flush()?;
    Ok(creds.len() as i64)
}

pub(crate) fn write_payment_cards_to_csv(
    file_path: &str,
    cards: &Vec<PaymentCard>,
) -> Result<i64, Error> {
    let mut wtr = Writer::from_path(file_path)?;
    for card in cards {
        wtr.serialize(CSVPaymentCard {
            name: String::from(card.name()),
            name_on_card: String::from(card.name_on_card()),
            number: String::from(card.number()),
            cvv: String::from(card.cvv()),
            expiry: format!("{}", card.expiry()),
            color: match card.color() {
                Some(color) => String::from(color),
                None => String::from(""),
            },
            billing_address: match card.billing_address() {
                Some(address) => format!("{}", address),
                None => String::from(""),
            },
        })?;
    }
    wtr.flush()?;
    Ok(cards.len() as i64)
}

pub(crate) fn write_secure_notes_to_csv(file_path: &str, notes: &Vec<Note>) -> Result<i64, Error> {
    let mut wtr = Writer::from_path(file_path)?;
    for note in notes {
        wtr.serialize(CSVSecureNote {
            title: note.title().to_string(),
            note: note.content().to_string(),
        })?;
    }
    wtr.flush()?;
    Ok(notes.len() as i64)
}
