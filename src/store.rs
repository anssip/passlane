use crate::vault::entities::{parse_tags, Credential, Error, Note, PaymentCard};
use chrono::{DateTime, Utc};
use csv::{ReaderBuilder, Writer};
use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
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
pub struct CSVCredential {
    pub uuid: String,
    pub password: String,
    pub title: String,
    pub url: String,
    pub username: String,
    pub note: String,
    /// Semicolon-separated tags
    pub tags: String,
    pub expires: bool,
    /// RFC 3339 timestamp, empty when the credential does not expire
    pub expiry_time: String,
    /// Custom attributes encoded as "key=value" pairs joined with ";"
    pub custom_attributes: String,
    pub last_modified: String,
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

/// The passlane config directory (~/.passlane), created on first use. Vault
/// locations live in the registry (see vault_registry.rs); this module keeps
/// the low-level file helpers and the CSV import/export.
pub(crate) fn dir_path() -> PathBuf {
    let dir_path = home_dir().join(".passlane");
    if !dir_path.exists() {
        if let Err(e) = create_private_dir(&dir_path) {
            // A concurrent passlane may have created the directory between
            // the exists() check and the create; that race is benign.
            if e.kind() != std::io::ErrorKind::AlreadyExists {
                panic!("Unable to create .passlane dir: {}", e);
            }
        }
    }
    tighten_dir_permissions(&dir_path);
    dir_path
}

/// Create the config directory owner-only. It holds sensitive metadata (the
/// vault registry, the active-vault pointer, per-vault completion caches):
/// other local users must not even see the filenames.
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    tighten_dir_permissions(path);
    Ok(())
}

/// Pre-existing directories get their permissions tightened too, since they
/// are about to receive fresh sensitive content — mirroring what
/// create_private_file does for files. Non-Unix platforms keep the platform
/// default ACLs.
#[cfg(unix)]
fn tighten_dir_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)) {
        eprintln!(
            "Warning: could not restrict permissions on '{}': {}",
            path.display(),
            e
        );
    }
}

#[cfg(not(unix))]
fn tighten_dir_permissions(_path: &Path) {}

#[derive(Debug, Deserialize)]
struct CsvImportRow {
    /// "service" is accepted for exports written by older passlane versions;
    /// Firefox exports only have a "url" column, handled below.
    #[serde(default, alias = "service")]
    title: Option<String>,
    #[serde(default)]
    url: Option<String>,
    username: String,
    password: String,
    #[serde(default, alias = "guid")]
    uuid: Option<String>,
    #[serde(default)]
    note: Option<String>,
    #[serde(default)]
    tags: Option<String>,
    #[serde(default)]
    expires: bool,
    #[serde(default)]
    expiry_time: Option<DateTime<Utc>>,
    #[serde(default)]
    custom_attributes: Option<String>,
    #[serde(default)]
    last_modified: Option<DateTime<Utc>>,
}

/// Characters that would break the "key=value;key=value" CSV encoding of
/// custom attributes; percent-encoded in keys and values on export and
/// decoded on import so attributes containing them roundtrip.
const CSV_ATTRIBUTE_ESCAPE: &AsciiSet = &AsciiSet::EMPTY.add(b';').add(b'=').add(b'%');

fn parse_custom_attributes(encoded: &str) -> Vec<(String, String)> {
    encoded
        .split(';')
        .filter_map(|pair| pair.split_once('='))
        .map(|(key, value)| {
            // Only the key is trimmed: trimming values would irreversibly
            // drop leading/trailing whitespace the user stored.
            (
                percent_decode_str(key.trim()).decode_utf8_lossy().to_string(),
                percent_decode_str(value).decode_utf8_lossy().to_string(),
            )
        })
        .filter(|(key, _)| !key.is_empty())
        .collect()
}

fn encode_custom_attributes(attributes: &[(String, String)]) -> String {
    attributes
        .iter()
        .map(|(key, value)| {
            format!(
                "{}={}",
                utf8_percent_encode(key, CSV_ATTRIBUTE_ESCAPE),
                utf8_percent_encode(value, CSV_ATTRIBUTE_ESCAPE)
            )
        })
        .collect::<Vec<String>>()
        .join(";")
}

pub fn read_from_csv(file_path: &str) -> anyhow::Result<Vec<Credential>> {
    let path = PathBuf::from(file_path);
    let in_file = OpenOptions::new().read(true).open(path)?;
    let mut reader = ReaderBuilder::new().has_headers(true).from_reader(in_file);
    // The csv crate deserializes an empty field into None for Option<String>,
    // so a blank title cell is indistinguishable from a missing column at the
    // value level — check the header row instead.
    let has_title_column = reader
        .headers()?
        .iter()
        .any(|header| matches!(header.trim().to_lowercase().as_str(), "title" | "service"));
    let mut credentials = Vec::new();
    for result in reader.deserialize::<CsvImportRow>() {
        let row = result?;
        // Firefox-style exports have no title column at all; their url is
        // the best available title. A blank title cell also falls back to
        // the url so the credential always gets a displayable title.
        let title = row
            .title
            .clone()
            .filter(|title| !title.is_empty())
            .or_else(|| row.url.clone().filter(|url| !url.is_empty()))
            .unwrap_or_default();
        if title.is_empty() && row.username.is_empty() && row.password.is_empty() {
            continue;
        }
        // When the URL became the title (no title column in the file), don't
        // also store it as the URL: that duplicate remains ambiguous with
        // legacy passlane entries. A title column that is merely empty still
        // counts as present, so its url value is kept as provided.
        let url = if has_title_column {
            row.url.clone()
        } else {
            None
        };
        let parsed_uuid = row
            .uuid
            .as_deref()
            .filter(|s| !s.is_empty())
            .and_then(|s| Uuid::parse_str(s).ok());
        credentials.push(
            Credential::new(
                parsed_uuid.as_ref(),
                &row.password,
                &title,
                &row.username,
                row.note.as_deref(),
                row.last_modified,
            )
            .with_url(url.as_deref())
            .with_tags(&parse_tags(row.tags.as_deref().unwrap_or("")))
            .with_expiry(row.expires, row.expiry_time)
            .with_custom_attributes(&parse_custom_attributes(
                row.custom_attributes.as_deref().unwrap_or(""),
            )),
        );
    }
    Ok(credentials)
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
        wtr.serialize(CSVCredential {
            uuid: cred.uuid().to_string(),
            password: cred.password().to_string(),
            title: cred.title().to_string(),
            url: cred.url().unwrap_or("").to_string(),
            username: cred.username().to_string(),
            note: cred.note().unwrap_or("").to_string(),
            tags: cred.tags().join(";"),
            expires: cred.expires(),
            expiry_time: cred
                .expiry_time()
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_default(),
            custom_attributes: encode_custom_attributes(cred.custom_attributes()),
            last_modified: cred.last_modified().to_rfc3339(),
        })?;
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

    #[cfg(unix)]
    #[test]
    fn test_config_dir_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("passlane-home");
        // A pre-existing directory with loose permissions gets tightened...
        std::fs::create_dir(&config).unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o755)).unwrap();
        tighten_dir_permissions(&config);
        let mode = std::fs::metadata(&config).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        // ...and a fresh one is created owner-only from the start.
        let fresh = dir.path().join("passlane-home2");
        create_private_dir(&fresh).unwrap();
        let mode = std::fs::metadata(&fresh).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
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
        assert_eq!(imported[0].title(), "google.com");
        assert_eq!(imported[0].url(), None);
    }

    #[test]
    fn test_csv_roundtrip_with_new_fields() {
        let expiry = DateTime::parse_from_rfc3339("2027-01-31T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let cred = Credential::new(None, "pass123", "github.com", "user", Some("note"), None)
            .with_url(Some("https://github.com/login"))
            .with_tags(&["work".to_string(), "dev".to_string()])
            .with_expiry(true, Some(expiry))
            .with_custom_attributes(&[("Recovery code".to_string(), "12345".to_string())]);
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        write_credentials_to_csv(&path, &vec![cred]).unwrap();
        let imported = read_from_csv(&path).unwrap();
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].title(), "github.com");
        assert_eq!(imported[0].url(), Some("https://github.com/login"));
        assert_eq!(imported[0].tags(), ["work".to_string(), "dev".to_string()]);
        assert!(imported[0].expires());
        assert_eq!(imported[0].expiry_time(), Some(expiry));
        assert_eq!(
            imported[0].custom_attributes(),
            &[("Recovery code".to_string(), "12345".to_string())]
        );
    }

    #[test]
    fn test_csv_roundtrip_escapes_custom_attribute_delimiters() {
        let cred = Credential::new(None, "secret", "github.com", "user", None, None)
            .with_custom_attributes(&[(
                "Rate limit=high;strict".to_string(),
                "a=b;c %100".to_string(),
            )]);
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        write_credentials_to_csv(&path, &vec![cred]).unwrap();
        let imported = read_from_csv(&path).unwrap();
        assert_eq!(
            imported[0].custom_attributes(),
            &[("Rate limit=high;strict".to_string(), "a=b;c %100".to_string())]
        );
    }

    #[test]
    fn test_csv_import_empty_title_column_keeps_url() {
        // A title column that exists but is blank must not be treated like a
        // Firefox export (which has no title column): the provided url value
        // is kept instead of being folded away, and the blank title still
        // falls back to the url for display.
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        std::fs::write(
            &path,
            "title,url,username,password\n\
             \"\",\"https://example.com\",\"alice\",\"hunter2\"\n",
        )
        .unwrap();
        let imported = read_from_csv(&path).unwrap();
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].title(), "https://example.com");
        assert_eq!(imported[0].url(), Some("https://example.com"));
    }

    #[test]
    fn test_csv_roundtrip_preserves_custom_attribute_whitespace() {
        let cred = Credential::new(None, "secret", "example.com", "user", None, None)
            .with_custom_attributes(&[("key".to_string(), "  padded value  ".to_string())]);
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        write_credentials_to_csv(&path, &vec![cred]).unwrap();
        let imported = read_from_csv(&path).unwrap();
        assert_eq!(
            imported[0].custom_attributes(),
            &[("key".to_string(), "  padded value  ".to_string())]
        );
    }

    #[test]
    fn test_csv_import_legacy_service_column() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        std::fs::write(
            &path,
            "uuid,password,service,username,note,last_modified\n\
             \"00000000-0000-0000-0000-000000000001\",\"pass123\",\"google.com\",\"user\",\"\",\"2024-01-01T00:00:00Z\"\n",
        )
        .unwrap();
        let imported = read_from_csv(&path).unwrap();
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].title(), "google.com");
        assert_eq!(imported[0].url(), None);
        assert!(!imported[0].expires());
        assert!(imported[0].tags().is_empty());
        assert!(imported[0].custom_attributes().is_empty());
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
        assert_eq!(imported[0].title(), "https://example.com");
        // The URL became the title and is not stored twice: URL == Title is
        // treated as the legacy duplicate on vault reads, so storing both
        // would lose the URL field.
        assert_eq!(imported[0].url(), None);
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
        assert_eq!(imported[0].title(), "https://example.com");
        assert_eq!(imported[0].username(), "bob");
        // A fresh uuid should have been generated since the guid was unparseable.
        assert_eq!(imported[0].uuid().get_version_num(), 4);
    }
}
