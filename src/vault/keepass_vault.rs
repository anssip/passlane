use crate::vault::entities::{Address, Credential, Error, Expiry, Note, PaymentCard, Totp};
use crate::vault::vault_trait::{NoteVault, PasswordVault, PaymentVault, TotpVault, Vault};
use chrono::{DateTime, NaiveDateTime, Utc};
use keepass_ng::db::{
    group_get_children, node_is_entry, node_is_group, Database, Entry, Group,
    Node, NodeIterator, NodePtr, SerializableNodePtr, TOTP,
};
use keepass_ng::db::DatabaseSaveError;
use keepass_ng::{
    ChallengeResponseKey, DatabaseConfig, DatabaseKey, DatabaseOpenError, DatabaseVersion,
};

use log::debug;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::str::FromStr;
use uuid::Uuid;
use zeroize::Zeroize;

pub struct KeepassVault {
    password: String,
    db: Database,
    filepath: String,
    keyfile: Option<String>,
    challenge_response: Option<ChallengeResponseKey>,
}

impl Drop for KeepassVault {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

impl From<DatabaseOpenError> for Error {
    fn from(e: DatabaseOpenError) -> Self {
        Error {
            message: e.to_string(),
        }
    }
}

impl From<DatabaseSaveError> for Error {
    fn from(e: DatabaseSaveError) -> Self {
        Error {
            message: e.to_string(),
        }
    }
}

impl From<keepass_ng::Error> for Error {
    fn from(e: keepass_ng::Error) -> Self {
        Error {
            message: e.to_string(),
        }
    }
}

/// Normalize an `otpauth://` URL so its `secret=` value passes strict RFC 4648
/// base32 decoding: uppercase letters, strip whitespace, and pad with `=` to the
/// next multiple of 8 characters. Other parts of the URL are left untouched.
fn normalize_otp_url(url: &str) -> String {
    let secret_start = if let Some(pos) = url.find("?secret=") {
        pos + "?secret=".len()
    } else if let Some(pos) = url.find("&secret=") {
        pos + "&secret=".len()
    } else {
        return url.to_string();
    };
    let after = &url[secret_start..];
    let end_offset = after.find('&').unwrap_or(after.len());
    let raw_secret = &after[..end_offset];

    let cleaned: String = raw_secret
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_uppercase();
    let unpadded = cleaned.trim_end_matches('=');
    let pad_len = (8 - (unpadded.len() % 8)) % 8;
    let normalized = format!("{}{}", unpadded, "=".repeat(pad_len));

    let secret_end = secret_start + end_offset;
    format!(
        "{}{}{}",
        &url[..secret_start],
        normalized,
        &url[secret_end..]
    )
}

fn node_has_totp(node: &NodePtr) -> bool {
    let node = node.borrow();
    let e = node.downcast_ref::<Entry>().unwrap();
    let raw = e.get_raw_otp_value();
    debug!(
        "Checking node for TOTP: {:?} has_otp={}",
        e.get_title(),
        raw.is_some()
    );
    match raw {
        Some(url) => TOTP::from_str(&normalize_otp_url(url)).is_ok(),
        None => false,
    }
}

/// Custom attribute keys that carry the payment card fields. Older passlane
/// versions stored these as "Key: value" lines in the notes field; reads
/// still accept that format, but all writes go to custom attributes. Values
/// are stored unprotected: keepass-ng 0.11 has no API for protected custom
/// fields.
const PAYMENT_FIELD_NAME_ON_CARD: &str = "Name on card";
const PAYMENT_FIELD_NUMBER: &str = "Number";
const PAYMENT_FIELD_CVV: &str = "CVV";
const PAYMENT_FIELD_EXPIRY: &str = "Expiry";
const PAYMENT_FIELD_COLOR: &str = "Color";
const PAYMENT_FIELD_ADDRESS_STREET: &str = "Billing Address Street";
const PAYMENT_FIELD_ADDRESS_ZIP: &str = "Billing Address Zip";
const PAYMENT_FIELD_ADDRESS_CITY: &str = "Billing Address City";
const PAYMENT_FIELD_ADDRESS_STATE: &str = "Billing Address State";
const PAYMENT_FIELD_ADDRESS_COUNTRY: &str = "Billing Address Country";

fn node_looks_like_payment(node: &NodePtr) -> bool {
    let node = node.borrow();
    let e = match node.downcast_ref::<Entry>() {
        Some(e) => e,
        None => return false,
    };
    // Legacy format written by older passlane versions.
    if let Some(notes) = e.get_notes() {
        let has_number = notes.lines().any(|l| l.starts_with("Number: "));
        let has_expiry = notes.lines().any(|l| l.starts_with("Expiry: "));
        if has_number && has_expiry {
            return true;
        }
    }
    // Current format. An entry with username/password/URL set is a
    // credential that happens to carry "Number"/"Expiry" attributes, not a
    // card.
    let has_credential_fields = e.get_username().is_some_and(|u| !u.is_empty())
        || e.get_password().is_some_and(|p| !p.is_empty())
        || e.get_url().is_some_and(|u| !u.is_empty());
    !has_credential_fields && node_has_payment_custom_fields(e)
}

/// True when the entry carries its payment card data in custom attributes:
/// a non-empty "Number" plus an "Expiry" that parses as MM/YYYY.
fn node_has_payment_custom_fields(e: &Entry) -> bool {
    let has_number = e
        .get(PAYMENT_FIELD_NUMBER)
        .is_some_and(|number| !number.is_empty());
    let has_expiry = e
        .get(PAYMENT_FIELD_EXPIRY)
        .is_some_and(|expiry| Expiry::from_str(expiry).is_ok());
    has_number && has_expiry
}

fn node_looks_like_note(node: &NodePtr) -> bool {
    if node_has_totp(node) {
        return false;
    }
    if node_looks_like_payment(node) {
        return false;
    }
    let node = node.borrow();
    let e = match node.downcast_ref::<Entry>() {
        Some(e) => e,
        None => return false,
    };
    let has_notes = e.get_notes().map(|n| !n.is_empty()).unwrap_or(false);
    if !has_notes {
        return false;
    }
    let has_username = e.get_username().map(|u| !u.is_empty()).unwrap_or(false);
    let has_password = e.get_password().map(|p| !p.is_empty()).unwrap_or(false);
    let has_url = e.get_url().map(|u| !u.is_empty()).unwrap_or(false);
    !has_username && !has_password && !has_url
}

fn node_looks_like_credential(node: &NodePtr) -> bool {
    if node_looks_like_payment(node) {
        return false;
    }
    if node_looks_like_note(node) {
        return false;
    }
    let node_ref = node.borrow();
    let e = match node_ref.downcast_ref::<Entry>() {
        Some(e) => e,
        None => return false,
    };
    let has_username = e.get_username().map(|u| !u.is_empty()).unwrap_or(false);
    let has_password = e.get_password().map(|p| !p.is_empty()).unwrap_or(false);
    let has_url = e.get_url().map(|u| !u.is_empty()).unwrap_or(false);
    has_username || has_password || has_url
}

/// The KeePass entry fields of a credential entry, as read from the vault.
struct NodeCredentialValues {
    username: String,
    title: String,
    url: Option<String>,
    password: String,
    note: Option<String>,
    tags: Vec<String>,
    expires: bool,
    expiry_time: Option<DateTime<Utc>>,
    custom_attributes: Vec<(String, String)>,
    uuid: Uuid,
    last_modified: Option<NaiveDateTime>,
}

/// Only the hardware-key variant blocks on a physical touch; a
/// `LocalChallenge` key (recovery via backed-up secret, tests) computes the
/// response locally, so no "touch" prompt should be shown for it.
fn requires_touch(challenge_response: Option<&ChallengeResponseKey>) -> bool {
    matches!(
        challenge_response,
        Some(ChallengeResponseKey::YubikeyChallenge(..))
    )
}

impl KeepassVault {
    pub fn open(
        password: &str,
        filepath: &str,
        keyfile_path: Option<String>,
        challenge_response: Option<&ChallengeResponseKey>,
    ) -> Result<KeepassVault, Error> {
        debug!("Opening database '{}'", filepath);
        let db = Self::open_database(filepath, password, &keyfile_path, challenge_response)?;
        Ok(Self {
            password: String::from(password),
            db,
            filepath: filepath.to_string(),
            keyfile: keyfile_path,
            challenge_response: challenge_response.cloned(),
        })
    }

    pub fn new(
        filepath: &str,
        password: &str,
        keyfile: Option<&str>,
        challenge_response: Option<&ChallengeResponseKey>,
    ) -> Result<KeepassVault, Error> {
        let mut db = Database::new(DatabaseConfig::default());
        db.meta.database_name = Some("Passlane database".to_string());

        if let Some(keyfile_path) = keyfile {
            println!("Using keyfile '{}'", keyfile_path);
        }
        let vault = KeepassVault {
            db,
            password: password.to_string(),
            filepath: filepath.to_string(),
            keyfile: keyfile.map(ToString::to_string),
            challenge_response: challenge_response.cloned(),
        };
        let key = Self::build_key(password, &vault.keyfile, challenge_response)?;
        // The challenge happens during the save below; print only once the
        // keyfile opened fine, mirroring the open path.
        if requires_touch(challenge_response) {
            eprintln!("Touch your hardware key to encrypt the vault...");
        }
        vault.save_atomically(key)?;

        Ok(vault)
    }

    fn get_root(&self) -> SerializableNodePtr {
        self.db.root.clone()
    }

    fn get_root_uuid(&self) -> Uuid {
        self.get_root().borrow().get_uuid()
    }

    fn save_database(&self) -> Result<(), Error> {
        // Every save issues a fresh challenge to the hardware key, so tell the
        // user why passlane is waiting. Stderr keeps stdout parseable for
        // commands with JSON output.
        if requires_touch(self.challenge_response.as_ref()) {
            eprintln!("Touch your hardware key to authorize saving...");
        }
        let key = Self::build_key(&self.password, &self.keyfile, self.challenge_response.as_ref())?;
        debug!("Saving database to file '{}'", &self.filepath);
        self.save_atomically(key)
    }

    pub fn change_master_password(&mut self, mut new_password: String) -> Result<(), Error> {
        let result =
            Self::build_key(&new_password, &self.keyfile, self.challenge_response.as_ref()).and_then(
                |key| {
                    debug!("Re-encrypting database '{}' with new master password", &self.filepath);
                    self.save_atomically(key)
                },
            );
        if let Err(e) = result {
            new_password.zeroize();
            return Err(e);
        }
        let mut old_password = std::mem::replace(&mut self.password, new_password);
        old_password.zeroize();
        Ok(())
    }

    /// Enroll or remove the hardware-key challenge-response factor and re-save
    /// the vault. The save itself challenges the *new* key, so a successful
    /// return proves the enrollment works before any config is persisted.
    /// Removing the factor (`None`) needs the current key only to open the
    /// vault, which the caller has already done. If the save fails, the
    /// previous factor is restored so the in-memory state keeps matching the
    /// file on disk.
    pub fn update_challenge_response(
        &mut self,
        challenge_response: Option<ChallengeResponseKey>,
    ) -> Result<(), Error> {
        let previous = std::mem::replace(&mut self.challenge_response, challenge_response);
        if let Err(e) = self.save_database() {
            self.challenge_response = previous;
            return Err(e);
        }
        Ok(())
    }

    /// Serialize the database to a temporary file in the same directory, fsync
    /// it, and rename it over the vault file. The rename is atomic on POSIX, so
    /// a crash mid-save leaves either the old vault or the new one — never a
    /// truncated or partially written file.
    fn save_atomically(&self, key: DatabaseKey) -> Result<(), Error> {
        let path = Path::new(&self.filepath);
        let dir = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => PathBuf::from("."),
        };
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("vault.kdbx");
        let (mut tmp, tmp_path) = Self::create_temp_file(&dir, file_name)?;

        let result = (|| -> Result<(), Error> {
            if let Ok(meta) = std::fs::metadata(path) {
                std::fs::set_permissions(&tmp_path, meta.permissions())?;
            }
            self.db.save(&mut tmp, key)?;
            tmp.sync_all()?;
            drop(tmp);
            std::fs::rename(&tmp_path, path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp_path);
            return result;
        }

        // Best effort: persist the rename itself across a power loss.
        if let Ok(dir_handle) = File::open(&dir) {
            let _ = dir_handle.sync_all();
        }
        Ok(())
    }

    /// Create a temp file for the atomic save with `create_new` (O_EXCL), so an
    /// existing file or symlink at the path is never followed or clobbered. The
    /// pid + counter suffix keeps concurrent saves from colliding; owner-only
    /// permissions apply until the original vault's permissions are copied over.
    fn create_temp_file(dir: &Path, file_name: &str) -> Result<(File, PathBuf), Error> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        for _ in 0..100 {
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let tmp_path = dir.join(format!(".{}.{}.{}.tmp", file_name, std::process::id(), n));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&tmp_path) {
                Ok(f) => return Ok((f, tmp_path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Err(Error {
            message: format!("could not create temporary file for '{}'", file_name),
        })
    }

    fn build_key(
        password: &str,
        keyfile: &Option<String>,
        challenge_response: Option<&ChallengeResponseKey>,
    ) -> Result<DatabaseKey, Error> {
        let mut key = match keyfile {
            Some(kf) => {
                debug!("Using keyfile '{}' and password", kf);
                let mut file = File::open(kf)?;
                DatabaseKey::new().with_password(password).with_keyfile(&mut file)?
            }
            None => DatabaseKey::new().with_password(password),
        };
        if let Some(cr) = challenge_response {
            key = key.with_challenge_response_key(cr.clone());
        }
        Ok(key)
    }

    fn open_database(
        filepath: &str,
        password: &str,
        keyfile: &Option<String>,
        challenge_response: Option<&ChallengeResponseKey>,
    ) -> Result<Database, Error> {
        match std::fs::metadata(filepath) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::new(&format!(
                    "Vault file '{}' does not exist. If the vault is on a synced or mounted drive, make sure it is available. To create a new vault, run 'passlane init'.",
                    filepath
                )));
            }
            Err(e) => return Err(e.into()),
            Ok(meta) if !meta.is_file() => {
                return Err(Error::new(&format!(
                    "Vault path '{}' is not a regular file.",
                    filepath
                )));
            }
            Ok(_) => {}
        }
        let (mut db_file, key) =
            Self::get_database_key(filepath, password, keyfile, challenge_response)?;
        // Printed only once the vault file and keyfile opened fine, so the
        // user is never told to touch the key for an operation that is about
        // to fail before any challenge happens.
        if requires_touch(challenge_response) {
            eprintln!("Touch your hardware key to open the vault...");
        }
        let mut db = Database::open(&mut db_file, key)?;
        db.set_recycle_bin_enabled(false);
        // keepass-ng 0.11 only writes KDBX 4.1, while vaults created with
        // earlier passlane versions (keepass-ng 0.9) are KDBX 4.0. Upgrade
        // the version in memory so the next save succeeds; KDBX 4.1 is a
        // superset of 4.0 that all current KeePass clients can read.
        if db.config.version == DatabaseVersion::KDB4(0) {
            db.config.version = DatabaseVersion::KDB4(1);
        }
        Ok(db)
    }

    fn create_group(&self, parent_uuid: Uuid, group_name: &str) -> Option<Uuid> {
        self.db
            .create_new_group(parent_uuid, 0)
            .map(|node| {
                node.borrow_mut().downcast_mut::<Group>().map(|group| {
                    group.set_title(Some(group_name));
                    group.get_uuid()
                })
            })
            .unwrap()
    }

    fn get_database_key(
        filepath: &str,
        password: &str,
        keyfile: &Option<String>,
        challenge_response: Option<&ChallengeResponseKey>,
    ) -> Result<(File, DatabaseKey), DatabaseOpenError> {
        let db_file = File::open(filepath)?;
        let mut key = match keyfile {
            Some(kf) => {
                debug!("Using keyfile '{}' and password", kf);
                let mut file = File::open(kf)?;
                DatabaseKey::new()
                    .with_password(password)
                    .with_keyfile(&mut file)?
            }
            None => DatabaseKey::new().with_password(password),
        };
        if let Some(cr) = challenge_response {
            key = key.with_challenge_response_key(cr.clone());
        }
        Ok((db_file, key))
    }

    fn load_credentials(&self, grep: Option<&str>) -> Vec<Credential> {
        let grep_lower = grep.map(|g| g.to_lowercase());
        NodeIterator::new(&self.get_root())
            .filter(node_is_entry)
            .filter(node_looks_like_credential)
            .filter(|node| {
                let Some(grep_lower) = &grep_lower else {
                    return true;
                };
                let node = node.borrow();
                let e = node.downcast_ref::<Entry>().unwrap();
                let title = e.get_title().unwrap_or("").to_lowercase();
                let url = e.get_url().unwrap_or("").to_lowercase();
                let username = e.get_username().unwrap_or("").to_lowercase();
                let tags = e.get_tags().join(" ").to_lowercase();
                let combined = format!("{}:{}", title, username);
                title.contains(grep_lower)
                    || url.contains(grep_lower)
                    || username.contains(grep_lower)
                    || tags.contains(grep_lower)
                    || combined.contains(grep_lower)
            })
            .map(Self::node_to_credential)
            .collect()
    }

    fn load_totps(&self, grep: Option<&str>) -> Vec<Totp> {
        NodeIterator::new(&self.get_root())
            // .map(|node| {debug!("Node: {:?}", node); node})
            .filter(node_is_entry)
            .filter(node_has_totp)
            .map(Self::node_to_totp)
            .filter(|totp| {
                if let Some(grep) = &grep {
                    if !totp.label().to_lowercase().contains(&grep.to_lowercase())
                        && !totp.issuer().to_lowercase().contains(&grep.to_lowercase())
                    {
                        return false;
                    }
                }
                true
            })
            .collect()
    }

    fn load_payments(&self) -> Vec<PaymentCard> {
        NodeIterator::new(&self.get_root())
            .filter(node_is_entry)
            .filter(node_looks_like_payment)
            .filter_map(Self::node_to_payment)
            .collect()
    }

    fn load_notes(&self) -> Vec<Note> {
        NodeIterator::new(&self.get_root())
            .filter(node_is_entry)
            .filter(node_looks_like_note)
            .map(Self::node_to_note)
            .collect()
    }

    fn node_to_credential(node: NodePtr) -> Credential {
        let values = Self::get_node_values(node);
        Credential::new(
            Some(&values.uuid),
            &values.password,
            &values.title,
            &values.username,
            values.note.as_deref(),
            values
                .last_modified
                .map(|dt| DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc)),
        )
        .with_url(values.url.as_deref())
        .with_tags(&values.tags)
        .with_expiry(values.expires, values.expiry_time)
        .with_custom_attributes(&values.custom_attributes)
    }

    fn node_to_totp(node: NodePtr) -> Totp {
        let totp = Self::get_node_totp_values(node);
        match totp {
            Err(e) => {
                panic!("Failed to convert node to TOTP: {}", e.message);
            }
            Ok(totp) => {
                let (url, label, issuer, secret, algorithm, period, digits, id, last_modified) =
                    totp;
                Totp::new(
                    Some(&id),
                    &url,
                    &label,
                    &issuer,
                    &secret,
                    &algorithm,
                    period,
                    digits,
                    last_modified.map(|dt| DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc)),
                )
            }
        }
    }

    fn get_node_values(node: NodePtr) -> NodeCredentialValues {
        let node = node.borrow();
        let e = node.downcast_ref::<Entry>().unwrap();
        let username = e.get_username().unwrap_or("(no username)").to_string();
        let title = e.get_title().unwrap_or("(no title)").to_string();
        // Older passlane versions stored the service value in both Title and
        // URL; a URL identical to the Title is that legacy duplicate, not a
        // real URL, so drop it on read.
        let url = e
            .get_url()
            .map(|u| u.to_string())
            .filter(|u| !u.is_empty() && u != &title);
        let password = e.get_password().unwrap_or("(no password)").to_string();
        let note = e
            .get_notes()
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty());
        let tags = e.get_tags().clone();
        let times = e.get_times();
        let expires = times.get_expires();
        let expiry_time = times
            .get_expiry_time()
            .map(|dt| DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc));
        let custom_attributes = e.additional_attributes();
        let uuid = e.get_uuid();
        let last_modified = times.get_last_modification();
        NodeCredentialValues {
            username,
            title,
            url,
            password,
            note,
            tags,
            expires,
            expiry_time,
            custom_attributes,
            uuid,
            last_modified,
        }
    }

    fn node_to_payment(node: NodePtr) -> Option<PaymentCard> {
        let (name, name_on_card, number, cvv, expiry, color, billing_address, id) =
            Self::get_node_payment_values(node)?;
        Some(PaymentCard::new(
            Some(&id),
            &name,
            &name_on_card,
            &number,
            &cvv,
            expiry,
            color.as_deref(),
            billing_address.as_ref(),
            None,
        ))
    }

    fn node_to_note(node: NodePtr) -> Note {
        let (title, content, id, last_modified) = Self::get_node_note_values(node);
        Note::new(
            Some(&id),
            &title,
            &content,
            last_modified.map(|dt| DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc)),
        )
    }

    fn get_node_payment_values(
        node: NodePtr,
    ) -> Option<(
        String,
        String,
        String,
        String,
        Expiry,
        Option<String>,
        Option<Address>,
        Uuid,
    )> {
        let node = node.borrow();
        let e = node.downcast_ref::<Entry>().unwrap();
        let name = e.get_title().unwrap_or("(no name)");
        // The custom-fields format written since payments moved off the
        // notes field takes precedence...
        if let Some((name_on_card, number, cvv, expiry, color, billing_address)) =
            Self::payment_values_from_custom_fields(e)
        {
            return Some((
                name.to_string(),
                name_on_card,
                number,
                cvv,
                expiry,
                color,
                billing_address,
                e.get_uuid(),
            ));
        }
        // ...followed by the legacy "Key: value" notes lines written by
        // older passlane versions. Fields are matched by their "Name: "
        // prefix rather than by line position, so notes edited in another
        // KeePass client (reordered lines) still load. A missing or
        // unparseable expiry means the entry is not treated as a payment
        // card.
        let note = e.get_notes()?;
        let name_on_card = Self::extract_value_from_note(note, "Name on card");
        let number = Self::extract_value_from_note(note, "Number");
        let cvv = Self::extract_value_from_note(note, "CVV");
        let expiry = Self::extract_value_from_note_opt(note, "Expiry")
            .and_then(|value| Expiry::from_str(&value).ok())?;
        let color = Self::extract_value_from_note_opt(note, "Color");
        // Cards saved without a billing address store an empty line in their
        // notes; treat an empty or malformed address as "no address" instead
        // of failing to load the card.
        let billing_address =
            Address::from_str(&Self::extract_value_from_note(note, "Billing Address")).ok();

        Some((
            name.to_string(),
            name_on_card,
            number,
            cvv,
            expiry,
            color,
            billing_address,
            e.get_uuid(),
        ))
    }

    /// Read a card from custom attributes. Returns None unless the entry has
    /// a non-empty "Number" and a parseable "Expiry" attribute.
    fn payment_values_from_custom_fields(
        e: &Entry,
    ) -> Option<(
        String,
        String,
        String,
        Expiry,
        Option<String>,
        Option<Address>,
    )> {
        let number = e.get(PAYMENT_FIELD_NUMBER)?;
        if number.is_empty() {
            return None;
        }
        let expiry = Expiry::from_str(e.get(PAYMENT_FIELD_EXPIRY)?).ok()?;
        let name_on_card = e.get(PAYMENT_FIELD_NAME_ON_CARD).unwrap_or("").to_string();
        let cvv = e.get(PAYMENT_FIELD_CVV).unwrap_or("").to_string();
        let color = e
            .get(PAYMENT_FIELD_COLOR)
            .filter(|color| !color.is_empty())
            .map(String::from);
        let street = e.get(PAYMENT_FIELD_ADDRESS_STREET);
        let zip = e.get(PAYMENT_FIELD_ADDRESS_ZIP);
        let city = e.get(PAYMENT_FIELD_ADDRESS_CITY);
        let state = e.get(PAYMENT_FIELD_ADDRESS_STATE);
        let country = e.get(PAYMENT_FIELD_ADDRESS_COUNTRY);
        // An address is present when any of its parts is; entries without
        // one store none of the address attributes.
        let has_address = street.is_some() || zip.is_some() || city.is_some() || country.is_some();
        let billing_address = if has_address {
            Some(Address::new(
                None,
                street.unwrap_or(""),
                city.unwrap_or(""),
                country.unwrap_or(""),
                state,
                zip.unwrap_or(""),
            ))
        } else {
            None
        };
        Some((
            name_on_card,
            number.to_string(),
            cvv,
            expiry,
            color,
            billing_address,
        ))
    }

    fn get_node_note_values(node: NodePtr) -> (String, String, Uuid, Option<NaiveDateTime>) {
        let node = node.borrow();
        let e = node.downcast_ref::<Entry>().unwrap();
        let content = e.get_notes().unwrap_or("");
        let title = e.get_title().unwrap_or("(no title)");
        let last_modified = e.get_times().get_last_modification();

        (
            title.to_string(),
            content.to_string(),
            e.get_uuid(),
            last_modified,
        )
    }

    fn extract_value_from_note_opt(note: &str, name: &str) -> Option<String> {
        let prefix = format!("{name}: ");
        note.lines()
            .find_map(|line| line.strip_prefix(&prefix))
            .map(String::from)
    }

    fn extract_value_from_note(note: &str, name: &str) -> String {
        let no_value = String::from(&format!("(no {name} on card)"));
        Self::extract_value_from_note_opt(note, name).unwrap_or(no_value)
    }

    fn get_node_totp_values(
        node: NodePtr,
    ) -> Result<
        (
            String,
            String,
            String,
            String,
            String,
            u64,
            u32,
            Uuid,
            Option<NaiveDateTime>,
        ),
        Error,
    > {
        let node = node.borrow();
        let e = node
            .downcast_ref::<Entry>()
            .ok_or(Error::new("Failed to downcast keepass node"))?;
        let raw_url = e
            .get_raw_otp_value()
            .ok_or(Error::new("Failed to get URL from keepass node"))?;
        let normalized_url = normalize_otp_url(raw_url);
        let otp: TOTP = normalized_url.parse().map_err(|e| {
            Error::new(&format!("Failed to parse OTP URL: {:?}", e))
        })?;
        let last_modified = e.get_times().get_last_modification();
        Ok((
            normalized_url,
            otp.label.to_string(),
            otp.issuer.clone().unwrap_or_default(),
            otp.get_secret(),
            otp.algorithm.to_string(),
            otp.period,
            otp.digits,
            e.get_uuid(),
            last_modified,
        ))
    }

    fn get_groups(&self) -> Vec<NodePtr> {
        let root = self.get_root();
        group_get_children(&root)
            .unwrap()
            .iter()
            .filter(|node| node_is_group(node))
            .cloned()
            .collect()
    }

    fn find_group(&self, group_name: &str) -> Option<Uuid> {
        let groups = self.get_groups();
        let group: Vec<&NodePtr> = groups
            .iter()
            .filter(|node| node_is_group(node))
            .filter(|node| {
                if let Some(entry) = node.borrow().downcast_ref::<Group>() {
                    entry.get_title().unwrap() == group_name
                } else {
                    false
                }
            })
            .collect();
        if !group.is_empty() {
            Some(group[0].borrow().get_uuid())
        } else {
            None
        }
    }

    /// Write all credential fields onto a KeePass entry. Custom attributes
    /// that exist on the entry but are absent from the credential are
    /// removed, so edits can delete attributes.
    fn apply_credential_fields(
        entry: &mut Entry,
        credentials: &Credential,
    ) -> keepass_ng::Result<()> {
        entry.set_title(Some(credentials.title()));
        entry.set_url(credentials.url());
        entry.set_username(Some(credentials.username()));
        entry.set_password(Some(credentials.password()));
        entry.set_notes(credentials.note());
        *entry.get_tags_mut() = credentials.tags().to_vec();
        let times = entry.get_times_mut();
        times.set_expires(credentials.expires());
        times.set_expiry_time(credentials.expiry_time().map(|dt| dt.naive_utc()));
        for (key, value) in credentials.custom_attributes() {
            entry.set_additional_attribute(key, Some(value))?;
        }
        let kept_keys = credentials
            .custom_attributes()
            .iter()
            .map(|(key, _)| key.to_string())
            .collect::<Vec<String>>();
        for key in entry
            .additional_attributes()
            .into_iter()
            .map(|(key, _)| key)
        {
            if !kept_keys.contains(&key) {
                entry.set_additional_attribute(&key, None)?;
            }
        }
        Ok(())
    }

    /// Write all payment card fields onto a KeePass entry as custom
    /// attributes. Absent optional fields (color, billing address) have
    /// their attributes removed, so edits can clear them. Unlike
    /// credentials, unknown custom attributes are left untouched: a card
    /// cannot round-trip them, and they may have been added by the user in
    /// another KeePass client.
    fn apply_payment_fields(entry: &mut Entry, payment: &PaymentCard) -> keepass_ng::Result<()> {
        entry.set_title(Some(payment.name()));
        // Older passlane versions stored the card as "Key: value" lines in
        // the notes field; clear them so they don't linger next to the
        // custom attributes.
        entry.set_notes(None);
        entry.set_additional_attribute(PAYMENT_FIELD_NAME_ON_CARD, Some(payment.name_on_card()))?;
        entry.set_additional_attribute(PAYMENT_FIELD_NUMBER, Some(payment.number()))?;
        entry.set_additional_attribute(PAYMENT_FIELD_CVV, Some(payment.cvv()))?;
        entry.set_additional_attribute(PAYMENT_FIELD_EXPIRY, Some(&payment.expiry_str()))?;
        entry.set_additional_attribute(
            PAYMENT_FIELD_COLOR,
            payment.color().map(|color| color.as_str()),
        )?;
        let address = payment.billing_address();
        entry
            .set_additional_attribute(PAYMENT_FIELD_ADDRESS_STREET, address.map(|a| a.street()))?;
        entry.set_additional_attribute(PAYMENT_FIELD_ADDRESS_ZIP, address.map(|a| a.zip()))?;
        entry.set_additional_attribute(PAYMENT_FIELD_ADDRESS_CITY, address.map(|a| a.city()))?;
        entry.set_additional_attribute(
            PAYMENT_FIELD_ADDRESS_STATE,
            address.and_then(|a| a.state()).map(|state| state.as_str()),
        )?;
        entry.set_additional_attribute(
            PAYMENT_FIELD_ADDRESS_COUNTRY,
            address.map(|a| a.country()),
        )?;
        Ok(())
    }

    fn create_password_entry(
        &mut self,
        parent_uuid: &Uuid,
        credentials: &Credential,
    ) -> keepass_ng::Result<Option<Uuid>> {
        let node = self.db.create_new_entry(parent_uuid.clone(), 0)?;
        let mut node_ref = node.borrow_mut();
        match node_ref.downcast_mut::<Entry>() {
            Some(entry) => {
                Self::apply_credential_fields(entry, credentials)?;
                Ok(Some(entry.get_uuid()))
            }
            None => Ok(None),
        }
    }

    fn create_totp_entry(
        &mut self,
        parent_uuid: &Uuid,
        totp: &Totp,
    ) -> Result<Option<Uuid>, Error> {
        Ok(self.db.create_new_entry(*parent_uuid, 0).map(|node| {
            node.borrow_mut()
                .downcast_mut::<Entry>()
                .map(|entry| {
                    entry.set_title(Some(totp.label()));
                    entry.set_raw_otp_value(Some(totp.url()));
                    entry.get_uuid()
                })
        })?)
    }

    fn create_payment_entry(
        &mut self,
        parent_uuid: &Uuid,
        payment: &PaymentCard,
    ) -> keepass_ng::Result<Option<Uuid>> {
        let node = self.db.create_new_entry(parent_uuid.clone(), 0)?;
        let mut node_ref = node.borrow_mut();
        match node_ref.downcast_mut::<Entry>() {
            Some(entry) => {
                Self::apply_payment_fields(entry, payment)?;
                Ok(Some(entry.get_uuid()))
            }
            None => Ok(None),
        }
    }

    fn create_note_entry(
        &mut self,
        parent_uuid: &Uuid,
        note: &Note,
    ) -> keepass_ng::Result<Option<Uuid>> {
        self.db
            .create_new_entry(parent_uuid.clone(), 0)
            .map(|node| {
                node.borrow_mut()
                    .downcast_mut::<Entry>()
                    .map(|entry| {
                        entry.set_title(Some(note.title()));
                        entry.set_notes(Some(note.content()));
                        entry.get_uuid()
                    })
            })
    }

    fn do_delete(&mut self, uuid: &Uuid, save: bool) -> Result<(), Error> {
        debug!("Deleting with uuid '{}'", uuid);
        self.db.remove_node_by_uuid(*uuid)?;
        if save {
            self.save_database()?;
        }
        Ok(())
    }
    fn find_or_create_group(&mut self, group_name: &str) -> Uuid {
        self.find_group(group_name)
            .unwrap_or_else(|| self.create_group(self.get_root_uuid(), group_name).unwrap())
    }

    fn update_entry<F>(&mut self, uuid: Uuid, update_fn: F) -> Result<(), Error>
    where
        F: FnOnce(&mut Entry),
    {
        let node = self.db.search_node_by_uuid(uuid);

        if let Some(node_ref) = node {
            {
                let mut node = node_ref.borrow_mut();
                if let Some(entry) = node.downcast_mut::<Entry>() {
                    update_fn(entry);
                    entry.update_history();
                } else {
                    return Err(Error {
                        message: "Node is not an Entry".to_string(),
                    });
                }
            }
            self.save_database()?;
            Ok(())
        } else {
            Err(Error {
                message: format!("Entry with uuid '{}' not found", uuid),
            })
        }
    }
}

impl PasswordVault for KeepassVault {
    fn get_master_password(&self) -> String {
        self.password.clone()
    }

    fn grep(&self, grep: Option<&str>) -> Vec<Credential> {
        self.load_credentials(grep)
    }

    fn save_credentials(&mut self, credentials: &Vec<Credential>) -> Result<i8, Error> {
        let group = self.find_or_create_group("Passwords");
        for c in credentials {
            self.create_password_entry(&group, c)?;
        }
        self.save_database()?;
        Ok(credentials.len() as i8)
    }

    fn save_one_credential(&mut self, credentials: Credential) -> Result<(), Error> {
        self.save_credentials(&vec![credentials])?;
        Ok(())
    }

    fn update_credential(&mut self, credential: Credential) -> Result<(), Error> {
        let uuid = *credential.uuid();
        let node = match self.db.search_node_by_uuid(uuid) {
            Some(node) => node,
            None => {
                return Err(Error {
                    message: format!("Entry with uuid '{}' not found", uuid),
                })
            }
        };
        {
            let mut node = node.borrow_mut();
            let entry = match node.downcast_mut::<Entry>() {
                Some(entry) => entry,
                None => {
                    return Err(Error {
                        message: "Node is not an Entry".to_string(),
                    })
                }
            };
            // Apply before saving: set_additional_attribute only fails for
            // KeePass-reserved field names, and a failed apply must not
            // persist a partially-updated entry.
            Self::apply_credential_fields(entry, &credential)?;
            entry.update_history();
        }
        self.save_database()?;
        Ok(())
    }

    fn delete_credentials(&mut self, uuid: &Uuid) -> Result<(), Error> {
        self.do_delete(uuid, true)?;
        Ok(())
    }

    fn delete_matching(&mut self, grep: &str) -> Result<i8, Error> {
        let root = self.get_root();
        let matching: Vec<NodePtr> = NodeIterator::new(&root)
            .filter(node_is_entry)
            .filter(|node| {
                let node = node.borrow();
                let e = node.downcast_ref::<Entry>().unwrap();
                let username = e.get_username().unwrap_or("(no username)");
                let title = e.get_title().unwrap_or("(no title)");
                let url = e.get_url().unwrap_or("");
                username.contains(grep) || title.contains(grep) || url.contains(grep)
            })
            .collect();
        // delete
        for node in &matching {
            self.do_delete(&node.borrow().get_uuid(), false)?;
        }
        self.save_database()?;
        Ok(matching.len() as i8)
    }
}

impl PaymentVault for KeepassVault {
    fn find_payments(&self) -> Vec<PaymentCard> {
        self.load_payments()
    }

    fn save_payment(&mut self, payment: PaymentCard) -> Result<(), Error> {
        let group = self.find_or_create_group("Payments");
        self.create_payment_entry(&group, &payment)?;
        self.save_database()?;
        Ok(())
    }

    fn delete_payment(&mut self, id: &Uuid) -> Result<(), Error> {
        self.do_delete(id, true)?;
        Ok(())
    }

    fn update_payment(&mut self, payment: PaymentCard) -> Result<(), Error> {
        let uuid = *payment.id();
        let node = match self.db.search_node_by_uuid(uuid) {
            Some(node) => node,
            None => {
                return Err(Error {
                    message: format!("Entry with uuid '{}' not found", uuid),
                })
            }
        };
        {
            let mut node = node.borrow_mut();
            let entry = match node.downcast_mut::<Entry>() {
                Some(entry) => entry,
                None => {
                    return Err(Error {
                        message: "Node is not an Entry".to_string(),
                    })
                }
            };
            // Apply before saving: set_additional_attribute only fails for
            // KeePass-reserved field names, and a failed apply must not
            // persist a partially-updated entry.
            Self::apply_payment_fields(entry, &payment)?;
            entry.update_history();
        }
        self.save_database()?;
        Ok(())
    }
}

impl NoteVault for KeepassVault {
    fn find_notes(&self) -> Vec<Note> {
        self.load_notes()
    }

    fn save_note(&mut self, note: &Note) -> Result<(), Error> {
        let group = self.find_or_create_group("Notes");
        self.create_note_entry(&group, &note)
            .expect("Failed to save note");
        self.save_database()?;
        Ok(())
    }

    fn delete_note(&mut self, id: &Uuid) -> Result<(), Error> {
        self.do_delete(id, true)
    }

    fn update_note(&mut self, note: Note) -> Result<(), Error> {
        let uuid = note.id();
        self.update_entry(uuid, |entry| {
            entry.set_title(Some(note.title()));
            entry.set_notes(Some(note.content()));
        })
    }
}

impl TotpVault for KeepassVault {
    fn find_totp(&self, grep: Option<&str>) -> Vec<Totp> {
        self.load_totps(grep)
    }

    fn save_totp(&mut self, totp: &Totp) -> Result<(), Error> {
        let group = self.db.root.borrow().get_uuid();
        self.create_totp_entry(&group, &totp)
            .expect("Failed to save TOTP");
        self.save_database()?;
        Ok(())
    }

    fn delete_totp(&mut self, uuid: &Uuid) -> Result<(), Error> {
        self.do_delete(uuid, true)
    }

    fn update_totp(&mut self, totp: Totp) -> Result<(), Error> {
        let uuid = totp.id();
        self.update_entry(*uuid, |entry| {
            entry.set_title(Some(totp.label()));
            entry.set_raw_otp_value(Some(totp.url()));
        })
    }
}

impl Vault for KeepassVault {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_database_config_is_kdbx4_with_argon2_kdf() {
        use keepass_ng::{DatabaseVersion, KdfConfig};

        // KeepassVault::new relies on DatabaseConfig::default(); pin that it
        // stays KDBX 4.1 + Argon2 rather than legacy AES-KDF. keepass-ng 0.11
        // refuses to write anything but KDBX 4.1.
        let config = DatabaseConfig::default();
        assert_eq!(config.version, DatabaseVersion::KDB4(1));
        assert!(matches!(config.kdf_config, KdfConfig::Argon2 { .. }));
    }

    #[test]
    fn normalize_lowercase_secret() {
        let input = "otpauth://totp/braintree:api@iki.fi?secret=ue5u4t4fzitipzo2&issuer=braintree&period=30&digits=6";
        let expected = "otpauth://totp/braintree:api@iki.fi?secret=UE5U4T4FZITIPZO2&issuer=braintree&period=30&digits=6";
        assert_eq!(normalize_otp_url(input), expected);
    }

    #[test]
    fn normalize_already_canonical() {
        let input = "otpauth://totp/x:y?secret=JBSWY3DPEHPK3PXP&issuer=x&period=30&digits=6";
        assert_eq!(normalize_otp_url(input), input);
    }

    #[test]
    fn normalize_strips_whitespace_in_secret() {
        let input = "otpauth://totp/x?secret=jbsw y3dp ehpk 3pxp&issuer=x";
        let expected = "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&issuer=x";
        assert_eq!(normalize_otp_url(input), expected);
    }

    #[test]
    fn normalize_adds_padding() {
        // 10 chars unpadded -> needs 6 '=' to reach 16
        let input = "otpauth://totp/x?secret=JBSWY3DPEH&issuer=x";
        let expected = "otpauth://totp/x?secret=JBSWY3DPEH======&issuer=x";
        assert_eq!(normalize_otp_url(input), expected);
    }

    #[test]
    fn normalize_secret_at_end_of_url() {
        let input = "otpauth://totp/x?issuer=x&secret=ue5u4t4fzitipzo2";
        let expected = "otpauth://totp/x?issuer=x&secret=UE5U4T4FZITIPZO2";
        assert_eq!(normalize_otp_url(input), expected);
    }

    #[test]
    fn normalize_no_secret_param_is_noop() {
        let input = "otpauth://totp/x?issuer=x";
        assert_eq!(normalize_otp_url(input), input);
    }

    #[test]
    fn normalized_braintree_url_parses_as_totp() {
        let url = "otpauth://totp/braintree:api@iki.fi?secret=ue5u4t4fzitipzo2&issuer=braintree&period=30&alorithm=SHA1&digits=6";
        let parsed: Result<TOTP, _> = normalize_otp_url(url).parse();
        assert!(parsed.is_ok(), "expected parse to succeed, got {:?}", parsed.err());
    }

    #[test]
    fn open_missing_vault_file_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.kdbx");
        let path_str = path.to_str().unwrap();

        let result = KeepassVault::open("any-password", path_str, None, None);
        let err = result.err().expect("opening a missing vault file must fail");
        assert!(
            err.message.contains("does not exist"),
            "unexpected error message: {}",
            err.message
        );
    }

    #[test]
    fn save_replaces_vault_atomically_and_truncates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let path_str = path.to_str().unwrap();

        let vault = KeepassVault::new(path_str, "master-pw", None, None).unwrap();

        // Simulate stale trailing bytes left by a previously larger version.
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&[0xAB; 4096]).unwrap();
        drop(f);

        vault.save_database().unwrap();

        let bytes = std::fs::read(&path).unwrap();
        assert!(!bytes.ends_with(&[0xAB; 4096]), "stale bytes survived the save");
        KeepassVault::open("master-pw", path_str, None, None).unwrap();

        let leftover_tmp = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().ends_with(".tmp"));
        assert!(!leftover_tmp, "temp file left behind after save");
    }

    #[test]
    fn change_master_password_reencrypts_vault() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let path_str = path.to_str().unwrap();

        let mut vault = KeepassVault::new(path_str, "old-pw", None, None).unwrap();
        vault.change_master_password("new-pw".to_string()).unwrap();

        assert!(KeepassVault::open("new-pw", path_str, None, None).is_ok());
        assert!(KeepassVault::open("old-pw", path_str, None, None).is_err());
    }

    #[test]
    fn credential_fields_roundtrip_through_kdbx() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let path_str = path.to_str().unwrap();

        let expiry = DateTime::parse_from_rfc3339("2027-01-31T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let credential = Credential::new(None, "secret", "GitHub", "user", Some("note"), None)
            .with_url(Some("https://github.com/login"))
            .with_tags(&["work".to_string(), "dev".to_string()])
            .with_expiry(true, Some(expiry))
            .with_custom_attributes(&[("Recovery code".to_string(), "12345".to_string())]);

        let mut vault = KeepassVault::new(path_str, "master-pw", None, None).unwrap();
        vault.save_one_credential(credential).unwrap();
        drop(vault);

        let vault = KeepassVault::open("master-pw", path_str, None, None).unwrap();
        let found = &vault.grep(None)[0];
        assert_eq!(found.title(), "GitHub");
        assert_eq!(found.url(), Some("https://github.com/login"));
        assert_eq!(found.username(), "user");
        assert_eq!(found.password(), "secret");
        assert_eq!(found.note(), Some("note"));
        assert_eq!(found.tags(), ["work".to_string(), "dev".to_string()]);
        assert!(found.expires());
        assert_eq!(found.expiry_time(), Some(expiry));
        assert_eq!(
            found.custom_attributes(),
            &[("Recovery code".to_string(), "12345".to_string())]
        );

        // Editing must be able to drop custom attributes and disable expiry.
        let updated = found
            .clone()
            .with_expiry(false, None)
            .with_custom_attributes(&[]);
        let mut vault = KeepassVault::open("master-pw", path_str, None, None).unwrap();
        vault.update_credential(updated).unwrap();
        drop(vault);

        let vault = KeepassVault::open("master-pw", path_str, None, None).unwrap();
        let found = &vault.grep(None)[0];
        assert!(!found.expires());
        assert_eq!(found.expiry_time(), None);
        assert!(found.custom_attributes().is_empty());
    }

    #[test]
    fn legacy_entry_with_url_equal_to_title_reads_url_as_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let path_str = path.to_str().unwrap();

        // Write an entry the way old passlane did: service in both Title and URL.
        let mut vault = KeepassVault::new(path_str, "master-pw", None, None).unwrap();
        {
            let group_uuid = vault.find_or_create_group("Passwords");
            let node = vault.db.create_new_entry(group_uuid, 0).unwrap();
            let mut n = node.borrow_mut();
            let entry = n.downcast_mut::<Entry>().unwrap();
            entry.set_title(Some("legacy-service"));
            entry.set_url(Some("legacy-service"));
            entry.set_username(Some("user"));
            entry.set_password(Some("pass"));
        }
        vault.save_database().unwrap();
        drop(vault);

        let vault = KeepassVault::open("master-pw", path_str, None, None).unwrap();
        let found = &vault.grep(None)[0];
        assert_eq!(found.title(), "legacy-service");
        assert_eq!(found.url(), None);
    }

    #[test]
    fn update_with_reserved_attribute_name_fails_without_saving() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let path_str = path.to_str().unwrap();

        let credential = Credential::new(None, "secret", "GitHub", "user", None, None);
        let mut vault = KeepassVault::new(path_str, "master-pw", None, None).unwrap();
        vault.save_one_credential(credential).unwrap();
        drop(vault);

        // A reserved KeePass field name must be rejected before the database
        // is saved, so the stored entry stays untouched.
        let mut vault = KeepassVault::open("master-pw", path_str, None, None).unwrap();
        let stored = vault.grep(None)[0].clone();
        let rejected = stored
            .clone()
            .with_custom_attributes(&[("Title".to_string(), "hijack".to_string())]);
        let err = vault.update_credential(rejected).unwrap_err();
        assert!(err.message.contains("Title"), "unexpected error: {}", err.message);
        drop(vault);

        let vault = KeepassVault::open("master-pw", path_str, None, None).unwrap();
        let stored = &vault.grep(None)[0];
        assert_eq!(stored.title(), "GitHub");
        assert!(stored.custom_attributes().is_empty());
    }

    #[test]
    fn grep_matches_tags() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let path_str = path.to_str().unwrap();

        let credential = Credential::new(None, "secret", "GitHub", "user", None, None)
            .with_tags(&["infra".to_string()]);
        let mut vault = KeepassVault::new(path_str, "master-pw", None, None).unwrap();
        vault.save_one_credential(credential).unwrap();
        drop(vault);

        let vault = KeepassVault::open("master-pw", path_str, None, None).unwrap();
        assert_eq!(vault.grep(Some("infra")).len(), 1);
        assert_eq!(vault.grep(Some("no-such-tag")).len(), 0);
    }

    /// A stand-in for a hardware key: the 20-byte HMAC-SHA1 secret a
    /// challenge-response slot would hold, hex-encoded. LocalChallenge is also
    /// what the lost-key recovery path uses.
    fn local_challenge() -> ChallengeResponseKey {
        ChallengeResponseKey::LocalChallenge("0102030405060708090a0b0c0d0e0f1011121314".to_string())
    }

    #[test]
    fn hwkey_enrolled_vault_requires_challenge_response() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let path_str = path.to_str().unwrap();

        let cr = local_challenge();
        KeepassVault::new(path_str, "master-pw", None, Some(&cr)).unwrap();

        // Opening with the enrolled factor works; without it the key is wrong.
        assert!(KeepassVault::open("master-pw", path_str, None, Some(&cr)).is_ok());
        assert!(KeepassVault::open("master-pw", path_str, None, None).is_err());
    }

    #[test]
    fn update_challenge_response_enrolls_and_removes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let path_str = path.to_str().unwrap();

        let mut vault = KeepassVault::new(path_str, "master-pw", None, None).unwrap();
        let cr = local_challenge();
        vault.update_challenge_response(Some(cr.clone())).unwrap();
        drop(vault);
        // The enrollment is persisted: reopening needs the factor.
        assert!(KeepassVault::open("master-pw", path_str, None, Some(&cr)).is_ok());

        let mut vault = KeepassVault::open("master-pw", path_str, None, Some(&cr)).unwrap();
        vault.update_challenge_response(None).unwrap();
        drop(vault);
        assert!(KeepassVault::open("master-pw", path_str, None, None).is_ok());
        assert!(KeepassVault::open("master-pw", path_str, None, Some(&cr)).is_err());
    }

    #[test]
    fn change_master_password_preserves_challenge_response() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let path_str = path.to_str().unwrap();

        let cr = local_challenge();
        let mut vault = KeepassVault::new(path_str, "old-pw", None, Some(&cr)).unwrap();
        vault.change_master_password("new-pw".to_string()).unwrap();
        drop(vault);

        assert!(KeepassVault::open("new-pw", path_str, None, Some(&cr)).is_ok());
        assert!(KeepassVault::open("new-pw", path_str, None, None).is_err());
    }

    #[test]
    fn opens_and_resaves_vault_written_by_keepass_ng_0_9() {
        // Vault written by passlane 3.2.0 (keepass-ng 0.9, KDBX 4.0) with one
        // credential, one payment card, and one TOTP entry. keepass-ng 0.11
        // only writes KDBX 4.1, so opening must upgrade the version in memory
        // or the first save after the upgrade would fail.
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/resources/legacy-passlane3.2-kdbx4.0.kdbx");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        std::fs::copy(&fixture, &path).unwrap();
        let path_str = path.to_str().unwrap().to_string();

        let vault = KeepassVault::open("fixture-password", &path_str, None, None).unwrap();
        assert_eq!(vault.grep(None).len(), 1);
        assert_eq!(vault.find_payments().len(), 1);
        assert_eq!(vault.find_totp(None).len(), 1);
        assert_eq!(vault.db.config.version, DatabaseVersion::KDB4(1));
        drop(vault);

        // The upgraded vault must save and reload with all entries intact.
        let mut vault = KeepassVault::open("fixture-password", &path_str, None, None).unwrap();
        vault.save_database().unwrap();
        let vault = KeepassVault::open("fixture-password", &path_str, None, None).unwrap();
        assert_eq!(vault.grep(None).len(), 1);
        assert_eq!(vault.find_payments().len(), 1);
        assert_eq!(vault.find_totp(None).len(), 1);

        let totp = &vault.find_totp(None)[0];
        assert_eq!(totp.label(), "Fixture:demo");
        assert_eq!(totp.issuer(), "Fixture");
        let credential = &vault.grep(None)[0];
        assert_eq!(credential.username(), "fixture-user");
        assert_eq!(credential.password(), "fixture-password-1");
    }

    fn payment_entry_node(title: &str, notes: &str) -> NodePtr {
        let mut db = Database::new(DatabaseConfig::default());
        let root_uuid = db.root.borrow().get_uuid();
        let node = db.create_new_entry(root_uuid, 0).unwrap();
        {
            let mut n = node.borrow_mut();
            let entry = n.downcast_mut::<Entry>().unwrap();
            entry.set_title(Some(title));
            entry.set_notes(Some(notes));
        }
        node
    }

    #[test]
    fn payment_note_with_reordered_lines_loads() {
        // Field detection is order-independent ("any Number: and Expiry:
        // line"), so parsing must not assume the line layout written by
        // create_payment_entry either.
        let node = payment_entry_node(
            "Reordered Card",
            "Expiry: 12/30\nName on card: Reordered User\nNumber: 4111111111111111\nCVV: 123\nColor: \nBilling Address: ",
        );
        let payment = KeepassVault::node_to_payment(node).unwrap();
        assert_eq!(payment.number(), "4111111111111111");
        assert_eq!(payment.expiry_str(), "12/30");
        assert_eq!(payment.name_on_card(), "Reordered User");
    }

    #[test]
    fn payment_note_with_unparseable_expiry_is_skipped() {
        // A "Number:"/"Expiry:" note whose expiry does not parse is not a
        // payment card; it must be skipped, not panic.
        let node = payment_entry_node(
            "Broken Card",
            "Name on card: X\nNumber: 4111\nCVV: 1\nExpiry: never\nColor: \nBilling Address: ",
        );
        assert!(KeepassVault::node_to_payment(node).is_none());
    }

    fn custom_field_entry_node(title: &str, attrs: &[(&str, &str)]) -> NodePtr {
        let db = Database::new(DatabaseConfig::default());
        let root_uuid = db.root.borrow().get_uuid();
        let node = db.create_new_entry(root_uuid, 0).unwrap();
        {
            let mut n = node.borrow_mut();
            let entry = n.downcast_mut::<Entry>().unwrap();
            entry.set_title(Some(title));
            for (key, value) in attrs {
                entry.set_additional_attribute(key, Some(value)).unwrap();
            }
        }
        node
    }

    #[test]
    fn payment_custom_fields_are_detected_and_parsed() {
        let node = custom_field_entry_node(
            "Visa",
            &[
                ("Name on card", "Jane Doe"),
                ("Number", "4111111111111111"),
                ("CVV", "123"),
                ("Expiry", "12/30"),
                ("Color", "silver"),
                ("Billing Address Street", "Main St 1"),
                ("Billing Address Zip", "00100"),
                ("Billing Address City", "Helsinki"),
                ("Billing Address State", "Uusimaa"),
                ("Billing Address Country", "Finland"),
            ],
        );
        assert!(node_looks_like_payment(&node));
        let payment = KeepassVault::node_to_payment(node).unwrap();
        assert_eq!(payment.name(), "Visa");
        assert_eq!(payment.name_on_card(), "Jane Doe");
        assert_eq!(payment.number(), "4111111111111111");
        assert_eq!(payment.cvv(), "123");
        assert_eq!(payment.expiry_str(), "12/30");
        assert_eq!(payment.color(), Some(&"silver".to_string()));
        let address = payment.billing_address().unwrap();
        assert_eq!(address.street(), "Main St 1");
        assert_eq!(address.zip(), "00100");
        assert_eq!(address.city(), "Helsinki");
        // Unlike the legacy comma-joined notes format, the structured
        // address attributes keep the state.
        assert_eq!(address.state(), Some(&"Uusimaa".to_string()));
        assert_eq!(address.country(), "Finland");
    }

    #[test]
    fn credential_with_number_and_expiry_attributes_is_not_a_payment() {
        let db = Database::new(DatabaseConfig::default());
        let root_uuid = db.root.borrow().get_uuid();
        let node = db.create_new_entry(root_uuid, 0).unwrap();
        {
            let mut n = node.borrow_mut();
            let entry = n.downcast_mut::<Entry>().unwrap();
            entry.set_title(Some("Server"));
            entry.set_username(Some("admin"));
            entry.set_password(Some("hunter2"));
            entry
                .set_additional_attribute("Number", Some("42"))
                .unwrap();
            entry
                .set_additional_attribute("Expiry", Some("12/30"))
                .unwrap();
        }
        assert!(!node_looks_like_payment(&node));
        assert!(node_looks_like_credential(&node));
    }

    #[test]
    fn payment_custom_fields_roundtrip_through_kdbx() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let path_str = path.to_str().unwrap();

        let address = Address::new(
            None,
            "Main St 1",
            "Helsinki",
            "Finland",
            Some("Uusimaa"),
            "00100",
        );
        let card = PaymentCard::new(
            None,
            "Visa",
            "Jane Doe",
            "4111111111111111",
            "123",
            Expiry {
                month: 12,
                year: 30,
            },
            Some("silver"),
            Some(&address),
            None,
        );
        let mut vault = KeepassVault::new(path_str, "master-pw", None, None).unwrap();
        vault.save_payment(card).unwrap();
        drop(vault);

        let vault = KeepassVault::open("master-pw", path_str, None, None).unwrap();
        assert_eq!(vault.find_payments().len(), 1);
        let found = &vault.find_payments()[0];
        assert_eq!(found.name(), "Visa");
        assert_eq!(found.name_on_card(), "Jane Doe");
        assert_eq!(found.number(), "4111111111111111");
        assert_eq!(found.cvv(), "123");
        assert_eq!(found.expiry_str(), "12/30");
        assert_eq!(found.color(), Some(&"silver".to_string()));
        let address = found.billing_address().unwrap();
        assert_eq!(address.street(), "Main St 1");
        assert_eq!(address.state(), Some(&"Uusimaa".to_string()));
        assert_eq!(address.country(), "Finland");
        // The card must not leak into the other item types.
        assert_eq!(vault.grep(None).len(), 0);
        assert_eq!(vault.find_notes().len(), 0);
    }

    #[test]
    fn payment_update_rewrites_legacy_notes_entry_to_custom_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let path_str = path.to_str().unwrap();

        // Write a card the way old passlane did: "Key: value" lines in notes.
        let mut vault = KeepassVault::new(path_str, "master-pw", None, None).unwrap();
        {
            let group_uuid = vault.find_or_create_group("Payments");
            let node = vault.db.create_new_entry(group_uuid, 0).unwrap();
            let mut n = node.borrow_mut();
            let entry = n.downcast_mut::<Entry>().unwrap();
            entry.set_title(Some("Legacy Card"));
            entry.set_notes(Some(
                "Name on card: Jane\nNumber: 4111111111111111\nCVV: 123\nExpiry: 11/29\nColor: \nBilling Address: Main St 1, 00100, Helsinki, Finland",
            ));
        }
        vault.save_database().unwrap();
        drop(vault);

        // The legacy entry reads transparently...
        let mut vault = KeepassVault::open("master-pw", path_str, None, None).unwrap();
        let legacy = vault.find_payments()[0].clone();
        assert_eq!(legacy.number(), "4111111111111111");
        assert_eq!(legacy.name_on_card(), "Jane");

        // ...and an edit rewrites it into custom fields.
        let updated = PaymentCard::new(
            Some(legacy.id()),
            legacy.name(),
            legacy.name_on_card(),
            "5555444433332222",
            "999",
            Expiry { month: 1, year: 31 },
            None,
            None,
            None,
        );
        vault.update_payment(updated).unwrap();
        drop(vault);

        let vault = KeepassVault::open("master-pw", path_str, None, None).unwrap();
        assert_eq!(vault.find_payments().len(), 1);
        let card = &vault.find_payments()[0];
        assert_eq!(card.number(), "5555444433332222");
        assert_eq!(card.cvv(), "999");
        assert_eq!(card.expiry_str(), "1/31");
        assert_eq!(card.color(), None);
        assert!(card.billing_address().is_none());
        // The cleared notes left no note or credential behind.
        assert_eq!(vault.grep(None).len(), 0);
        assert_eq!(vault.find_notes().len(), 0);

        // The notes are gone and the card data lives in custom attributes.
        let node = vault.db.search_node_by_uuid(*card.id()).unwrap();
        let n = node.borrow();
        let entry = n.downcast_ref::<Entry>().unwrap();
        assert!(entry.get_notes().map_or(true, |notes| notes.is_empty()));
        assert_eq!(entry.get("Number"), Some("5555444433332222"));
        assert_eq!(entry.get("Expiry"), Some("1/31"));
    }

    #[test]
    fn payment_update_preserves_unknown_custom_attributes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let path_str = path.to_str().unwrap();

        let address = Address::new(None, "Main St 1", "Helsinki", "Finland", None, "00100");
        let card = PaymentCard::new(
            None,
            "Visa",
            "Jane",
            "4111111111111111",
            "123",
            Expiry {
                month: 12,
                year: 30,
            },
            Some("silver"),
            Some(&address),
            None,
        );
        let mut vault = KeepassVault::new(path_str, "master-pw", None, None).unwrap();
        vault.save_payment(card).unwrap();

        // A user adds an attribute in another KeePass client.
        let id = *vault.find_payments()[0].id();
        let node = vault.db.search_node_by_uuid(id).unwrap();
        {
            let mut n = node.borrow_mut();
            n.downcast_mut::<Entry>()
                .unwrap()
                .set_additional_attribute("PIN", Some("4321"))
                .unwrap();
        }
        vault.save_database().unwrap();
        drop(vault);

        // Editing the card clears its color and address but must keep the
        // user's own attribute.
        let mut vault = KeepassVault::open("master-pw", path_str, None, None).unwrap();
        let stored = vault.find_payments()[0].clone();
        let updated = PaymentCard::new(
            Some(stored.id()),
            stored.name(),
            stored.name_on_card(),
            stored.number(),
            stored.cvv(),
            Expiry {
                month: 12,
                year: 30,
            },
            None,
            None,
            None,
        );
        vault.update_payment(updated).unwrap();
        drop(vault);

        let vault = KeepassVault::open("master-pw", path_str, None, None).unwrap();
        assert_eq!(vault.find_payments().len(), 1);
        let card = &vault.find_payments()[0];
        assert_eq!(card.color(), None);
        assert!(card.billing_address().is_none());
        let node = vault.db.search_node_by_uuid(id).unwrap();
        let n = node.borrow();
        let entry = n.downcast_ref::<Entry>().unwrap();
        assert_eq!(entry.get("PIN"), Some("4321"));
        assert_eq!(entry.get("Number"), Some("4111111111111111"));
        assert_eq!(entry.get("Color"), None);
        assert_eq!(entry.get("Billing Address Street"), None);
        assert_eq!(entry.get("Billing Address State"), None);
    }
}
