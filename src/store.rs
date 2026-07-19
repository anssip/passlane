use crate::vault::entities::{Credential, Error, Note, PaymentCard};
use chrono::{DateTime, Utc};
use csv::{ReaderBuilder, Writer};
use serde::{Deserialize, Serialize};
use std::fs::create_dir;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::path::Path;
use std::path::PathBuf;
use uuid::Uuid;

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

#[derive(Debug, Deserialize)]
struct CsvImportRow {
    #[serde(alias = "url")]
    service: String,
    username: String,
    password: String,
    #[serde(default, alias = "guid")]
    uuid: Option<String>,
    #[serde(default)]
    note: Option<String>,
    #[serde(default)]
    last_modified: Option<DateTime<Utc>>,
}

pub fn read_from_csv(file_path: &str) -> anyhow::Result<Vec<Credential>> {
    let path = PathBuf::from(file_path);
    let in_file = OpenOptions::new().read(true).open(path)?;
    let mut reader = ReaderBuilder::new().has_headers(true).from_reader(in_file);
    let mut credentials = Vec::new();
    for result in reader.deserialize::<CsvImportRow>() {
        let row = result?;
        if row.service.is_empty() && row.username.is_empty() && row.password.is_empty() {
            continue;
        }
        let parsed_uuid = row
            .uuid
            .as_deref()
            .filter(|s| !s.is_empty())
            .and_then(|s| Uuid::parse_str(s).ok());
        credentials.push(Credential::new(
            parsed_uuid.as_ref(),
            &row.password,
            &row.service,
            &row.username,
            row.note.as_deref(),
            row.last_modified,
        ));
    }
    Ok(credentials)
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

fn config_file_exists(path_config_filename: &str) -> bool {
    dir_path().join(path_config_filename).exists()
}

pub(crate) fn get_vault_path() -> String {
    resolve_vault_path("store.kdbx", ".vault_path")
}

pub(crate) fn get_totp_vault_path() -> String {
    resolve_vault_path("totp.kdbx", ".totp_vault_path")
}

/// Create (or truncate) a file that will hold sensitive data. On Unix the file
/// is restricted to owner-only access (0o600), and existing files get their
/// permissions tightened too, since they are about to receive fresh sensitive
/// content. On other platforms the platform default ACLs apply.
pub(crate) fn create_private_file(path: impl AsRef<Path>) -> std::io::Result<std::fs::File> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

pub(crate) fn write_credentials_to_csv(
    file_path: &str,
    creds: &Vec<Credential>,
) -> Result<i64, Error> {
    let mut wtr = Writer::from_writer(create_private_file(file_path)?);
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
    let mut wtr = Writer::from_writer(create_private_file(file_path)?);
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
    let mut wtr = Writer::from_writer(create_private_file(file_path)?);
    for note in notes {
        wtr.serialize(CSVSecureNote {
            title: note.title().to_string(),
            note: note.content().to_string(),
        })?;
    }
    wtr.flush()?;
    Ok(notes.len() as i64)
}

pub fn save_config_path(config_file: &str, path: &str) -> Result<(), Error> {
    let config_path = dir_path().join(config_file);
    let exists = config_path.exists();
    let mut file = OpenOptions::new()
        .create(!exists)
        .write(true)
        .truncate(true)
        .open(config_path)?;
    file.write_all(String::from(path).as_bytes())?;
    Ok(())
}

pub(crate) fn save_vault_path(path: &str) -> Result<(), Error> {
    save_config_path(".vault_path", path)
}

pub(crate) fn save_totp_vault_path(path: &str) -> Result<(), Error> {
    save_config_path(".totp_vault_path", path)
}

pub(crate) fn save_keyfile_path(path: &str) -> Result<(), Error> {
    save_config_path(".keyfile_path", path)
}

pub(crate) fn save_totp_keyfile_path(path: &str) -> Result<(), Error> {
    save_config_path(".totp_keyfile_path", path)
}

pub fn has_vault_path() -> bool {
    config_file_exists(".vault_path")
}

pub fn has_totp_vault_path() -> bool {
    config_file_exists(".totp_vault_path")
}

pub fn has_keyfile_path() -> bool {
    config_file_exists(".keyfile_path")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::entities::Credential;
    use tempfile::NamedTempFile;

    #[cfg(unix)]
    #[test]
    fn test_csv_export_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let cred = Credential::new(None, "pass123", "google.com", "user@gmail.com", None, None);
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        // Pre-existing file with loose permissions must be tightened on export
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_credentials_to_csv(&path, &vec![cred]).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn test_create_private_file_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.csv");
        create_private_file(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn test_csv_export_includes_note() {
        let cred = Credential::new(None, "pass123", "google.com", "user@gmail.com", Some("work account"), None);
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        write_credentials_to_csv(&path, &vec![cred]).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("work account"), "CSV should contain the note value");
        assert!(content.contains("note"), "CSV header should contain 'note'");
    }

    #[test]
    fn test_csv_roundtrip_without_note() {
        let cred = Credential::new(None, "pass123", "google.com", "user@gmail.com", None, None);
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        write_credentials_to_csv(&path, &vec![cred]).unwrap();
        let imported = read_from_csv(&path).unwrap();
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].note(), None);
        assert_eq!(imported[0].service(), "google.com");
    }

    #[test]
    fn test_csv_roundtrip_with_note() {
        let cred = Credential::new(None, "pass123", "google.com", "user@gmail.com", Some("shared login"), None);
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        write_credentials_to_csv(&path, &vec![cred]).unwrap();
        let imported = read_from_csv(&path).unwrap();
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].note(), Some("shared login"));
    }

    #[test]
    fn test_csv_import_firefox_format() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        std::fs::write(
            &path,
            "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\",\"timeLastUsed\",\"timePasswordChanged\"\n\
             \"https://example.com\",\"alice\",\"hunter2\",\"\",\"https://example.com\",\"d3f3c5b2-1234-4abc-9def-0123456789ab\",\"1700000000000\",\"1700000000000\",\"1700000000000\"\n",
        )
        .unwrap();
        let imported = read_from_csv(&path).unwrap();
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].service(), "https://example.com");
        assert_eq!(imported[0].username(), "alice");
        assert_eq!(imported[0].password(), "hunter2");
    }

    #[test]
    fn test_csv_import_firefox_non_uuid_guid() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        std::fs::write(
            &path,
            "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\",\"timeLastUsed\",\"timePasswordChanged\"\n\
             \"https://example.com\",\"bob\",\"s3cret\",\"\",\"https://example.com\",\"{not-a-real-uuid}\",\"1700000000000\",\"1700000000000\",\"1700000000000\"\n",
        )
        .unwrap();
        let imported = read_from_csv(&path).unwrap();
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].service(), "https://example.com");
        assert_eq!(imported[0].username(), "bob");
        // A fresh uuid should have been generated since the guid was unparseable.
        assert_eq!(imported[0].uuid().get_version_num(), 4);
    }
}
