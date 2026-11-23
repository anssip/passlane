use crate::challenge::{ChallengeFactor, validate_for_enrollment};
use crate::vault::entities::{Address, Credential, Error, Expiry, Note, PaymentCard, Totp};
use crate::vault::vault_trait::{NoteVault, PasswordVault, PaymentVault, TotpVault, Vault};
use chrono::{DateTime, NaiveDateTime, Utc};
use keepass_ng::db::DatabaseSaveError;
use keepass_ng::db::{
    Database, Entry, Group, Node, NodeIterator, NodePtr, SerializableNodePtr, TOTP,
    group_get_children, node_is_entry, node_is_group,
};
// Only used by the usb-gated "Wrong CRC" explanation in explain_open_error.
use keepass_ng::{
    ChallengeResponseKey, DatabaseConfig, DatabaseKey, DatabaseOpenError, DatabaseVersion,
};
#[cfg(feature = "usb")]
use keepass_ng::{ChallengeResponseKeyError, DatabaseKeyError};

use log::debug;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use uuid::Uuid;
use zeroize::Zeroize;

pub struct KeepassVault {
    password: String,
    db: Database,
    filepath: String,
    keyfile: Option<String>,
    challenge_factor: Option<ChallengeFactor>,
}

impl Drop for KeepassVault {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

impl From<DatabaseOpenError> for Error {
    fn from(e: DatabaseOpenError) -> Self {
        Error {
            message: explain_open_error(&e),
        }
    }
}

/// Map keepass-ng's open errors to user-facing messages. "Wrong CRC" from
/// the challenge-response exchange is what a *missed* YubiKey touch looks
/// like: the key times out and answers with an error status, which fails
/// the response CRC check. Name the likely causes instead of the raw
/// protocol error. The string match is on the inner error's Display
/// because the challenge_response crate is not a direct dependency.
fn explain_open_error(e: &DatabaseOpenError) -> String {
    // The Api variant (and thus the "Wrong CRC" string match) only exists
    // with the `usb` feature; without hardware keys there is no touch to
    // miss, so the raw error message is already the right answer.
    #[cfg(feature = "usb")]
    if let DatabaseOpenError::Key(DatabaseKeyError::ChallengeResponse(
        ChallengeResponseKeyError::Api(inner),
    )) = e
    {
        if inner.to_string() == "Wrong CRC" {
            return "The hardware key did not return a valid response. Either no touch was \
                    detected within the key's timeout (touch the key when it blinks), or its \
                    slot is not programmed for HMAC-SHA1 challenge-response."
                .to_string();
        }
    }
    e.to_string()
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
    // An entry with username/password/URL set is a credential that happens
    // to carry card-like data, whether in "Number"/"Expiry" custom
    // attributes or in "Number: "/"Expiry: " note lines. passlane card
    // entries never set those fields, in either format.
    let has_credential_fields = e.get_username().is_some_and(|u| !u.is_empty())
        || e.get_password().is_some_and(|p| !p.is_empty())
        || e.get_url().is_some_and(|u| !u.is_empty());
    if has_credential_fields {
        return false;
    }
    // Legacy format written by older passlane versions. The expiry line
    // must parse: node_to_payment drops entries whose expiry does not, so
    // claiming them here would make them invisible to every loader. With
    // the parse required, a malformed entry falls through to the note
    // loaders instead.
    if let Some(notes) = e.get_notes() {
        let has_number = notes
            .lines()
            .find_map(|l| l.strip_prefix("Number: "))
            .is_some_and(|value| !value.trim().is_empty());
        let expiry = notes
            .lines()
            .find_map(|l| l.strip_prefix("Expiry: "))
            .and_then(|value| Expiry::from_str(value.trim()).ok());
        if has_number && expiry.is_some() {
            return true;
        }
    }
    // Current format.
    node_has_payment_custom_fields(e)
}

/// True when the entry carries its payment card data in custom attributes:
/// a non-empty "Number" plus an "Expiry" that parses as a month/year pair
/// (see `Expiry::from_str`).
fn node_has_payment_custom_fields(e: &Entry) -> bool {
    let has_number = e
        .get(PAYMENT_FIELD_NUMBER)
        .is_some_and(|number| !number.trim().is_empty());
    let has_expiry = e
        .get(PAYMENT_FIELD_EXPIRY)
        .is_some_and(|expiry| Expiry::from_str(expiry.trim()).is_ok());
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

/// True for absolute URIs like `https://…`, `mailto:…`, `tel:…` or `urn:…`
/// (an RFC 3986 `scheme:` prefix), false for bare names like `github.com`
/// that legacy passlane duplicated into the URL field.
fn is_absolute_uri(value: &str) -> bool {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() => {}
        _ => return false,
    }
    for c in chars {
        match c {
            ':' => return true,
            c if c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.') => {}
            _ => return false,
        }
    }
    false
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

/// What to tell the user before an operation challenges the enrolled factor.
/// Every open and save issues a fresh challenge, but only a physical key
/// makes that wait for a touch; a virtual key answers instantly and
/// silently, so it gets no notice.
fn touch_notice(challenge_factor: Option<&ChallengeFactor>) -> Option<&'static str> {
    challenge_factor
        .is_some_and(ChallengeFactor::requires_touch)
        .then_some("Touch your hardware key")
}

/// Errors a File Provider can emit while it is busy, updating or wedged.
/// macOS: EDEADLK=11 (the "Resource deadlock avoided" seen when a synced
/// folder's provider is unresponsive), EBUSY=16, EAGAIN=35; on Linux
/// EAGAIN=11 and EDEADLK=35. Covering all three on both platforms is
/// harmless — no regular-disk read produces them.
fn is_transient_read_error(e: &std::io::Error) -> bool {
    matches!(e.raw_os_error(), Some(11) | Some(16) | Some(35))
}

/// Extra guidance appended to vault read errors when the file lives in a
/// known synced folder, where the usual culprit is the sync client's file
/// provider rather than the disk.
fn sync_folder_hint(filepath: &str) -> &'static str {
    // Normalize separators and case so native Windows paths
    // (C:\Users\x\OneDrive\...) match too. Registry paths are absolute in
    // practice, so matching on "/<folder>/" is enough.
    let normalized = filepath.replace('\\', "/").to_lowercase();
    const SYNCED_MARKERS: [&str; 8] = [
        "/dropbox/",
        "/dropbox (", // Windows business: Dropbox (Contoso)
        "/onedrive/",
        "/onedrive - ", // Windows work/school: OneDrive - Contoso
        "/google drive/",
        "/googledrive/", // ~/Library/CloudStorage/GoogleDrive-<account>
        "/mobile documents/",
        "/cloudstorage/", // macOS File Provider mounts: Dropbox-, OneDrive-, ...
    ];
    if SYNCED_MARKERS.iter().any(|m| normalized.contains(m)) {
        " The vault is in a synced folder; the sync client may be busy, updating or \
         unresponsive. Retry in a moment or restart the sync client. Opening the \
         vault once in another app (Finder preview or KeePassXC) forces the sync \
         client to finish fetching the file and has been known to restore reads."
    } else {
        ""
    }
}

impl KeepassVault {
    /// Open a vault whose challenge-response factor is given as keepass-ng's
    /// own `ChallengeResponseKey` — or that has none.
    ///
    /// This is [`Self::open_with_challenge_factor`] with the key converted
    /// by [`ChallengeFactor::try_from`]; new callers should build a
    /// [`ChallengeFactor`] instead.
    pub fn open(
        password: &str,
        filepath: &str,
        keyfile_path: Option<String>,
        challenge_response: Option<&ChallengeResponseKey>,
    ) -> Result<KeepassVault, Error> {
        let challenge_factor = challenge_response
            .map(ChallengeFactor::try_from)
            .transpose()?;
        Self::open_with_challenge_factor(
            password,
            filepath,
            keyfile_path,
            challenge_factor.as_ref(),
        )
    }

    /// Open the vault at `filepath` with its master password, an optional
    /// keyfile and an optional challenge-response factor. The factor answers
    /// the vault's challenges itself, and does so again on every save. A
    /// YubiKey factor that names no key is pinned to the one it opened with.
    pub fn open_with_challenge_factor(
        password: &str,
        filepath: &str,
        keyfile_path: Option<String>,
        challenge_factor: Option<&ChallengeFactor>,
    ) -> Result<KeepassVault, Error> {
        debug!("Opening database '{}'", filepath);
        // Pinned before opening, so the vault keeps the very key that
        // answered the open's challenge — not whichever key is connected
        // by the time parsing finishes.
        let challenge_factor = Self::pinned(challenge_factor)?;
        let db = Self::open_database(filepath, password, &keyfile_path, challenge_factor.as_ref())?;
        Ok(Self {
            password: String::from(password),
            db,
            filepath: filepath.to_string(),
            keyfile: keyfile_path,
            challenge_factor,
        })
    }

    /// Create a vault protected by keepass-ng's own `ChallengeResponseKey`
    /// — or by no challenge-response factor.
    ///
    /// This is [`Self::new_with_challenge_factor`] with the key converted
    /// by [`ChallengeFactor::try_from`]; new callers should build a
    /// [`ChallengeFactor`] instead.
    pub fn new(
        filepath: &str,
        password: &str,
        keyfile: Option<&str>,
        challenge_response: Option<&ChallengeResponseKey>,
    ) -> Result<KeepassVault, Error> {
        let challenge_factor = challenge_response
            .map(ChallengeFactor::try_from)
            .transpose()?;
        Self::new_with_challenge_factor(filepath, password, keyfile, challenge_factor.as_ref())
    }

    /// Create the vault at `filepath` with its master password, an optional
    /// keyfile and an optional challenge-response factor. The first save
    /// already challenges the factor, so a factor that cannot answer — a
    /// YubiKey that is not connected — fails here and leaves no vault file.
    /// So does one that may not be enrolled: a virtual factor whose secret
    /// is not a 20-byte key in hex. It may open a vault, but not protect a
    /// new one. A YubiKey factor that names no key is pinned to the one
    /// connected now.
    pub fn new_with_challenge_factor(
        filepath: &str,
        password: &str,
        keyfile: Option<&str>,
        challenge_factor: Option<&ChallengeFactor>,
    ) -> Result<KeepassVault, Error> {
        if let Some(factor) = challenge_factor {
            validate_for_enrollment(factor)?;
        }
        let challenge_factor = Self::pinned(challenge_factor)?;
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
            challenge_factor: challenge_factor.clone(),
        };
        let key = Self::build_key(password, &vault.keyfile, challenge_factor.as_ref())?;
        // The challenge happens during the save below; print only once the
        // keyfile opened fine, mirroring the open path.
        if let Some(notice) = touch_notice(challenge_factor.as_ref()) {
            eprintln!("{notice} to encrypt the vault...");
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
        // Every save issues a fresh challenge to the enrolled factor, so
        // tell the user why passlane is waiting when that is a touch on a
        // hardware key. Stderr keeps stdout parseable for commands with
        // JSON output.
        if let Some(notice) = touch_notice(self.challenge_factor.as_ref()) {
            eprintln!("{notice} to authorize saving...");
        }
        let key = Self::build_key(
            &self.password,
            &self.keyfile,
            self.challenge_factor.as_ref(),
        )?;
        debug!("Saving database to file '{}'", &self.filepath);
        self.save_atomically(key)
    }

    pub fn change_master_password(&mut self, mut new_password: String) -> Result<(), Error> {
        let result = Self::build_key(&new_password, &self.keyfile, self.challenge_factor.as_ref())
            .and_then(|key| {
                debug!(
                    "Re-encrypting database '{}' with new master password",
                    &self.filepath
                );
                self.save_atomically(key)
            });
        if let Err(e) = result {
            new_password.zeroize();
            return Err(e);
        }
        let mut old_password = std::mem::replace(&mut self.password, new_password);
        old_password.zeroize();
        Ok(())
    }

    /// Enroll or remove the challenge-response factor and re-save the vault.
    /// The save itself challenges the *new* factor, so a successful return
    /// proves the enrollment works before any config is persisted.
    /// Removing the factor (`None`) needs the current factor only to open
    /// the vault, which the caller has already done. If the save fails, the
    /// previous factor is restored so the in-memory state keeps matching the
    /// file on disk.
    ///
    /// The new factor has to be fit to enroll: a virtual factor whose
    /// secret is not a 20-byte key in hex is refused before anything
    /// changes, although such a factor may well have opened the vault.
    /// A YubiKey factor that names no key is pinned to the one connected
    /// now, and kept pinned for the saves that follow.
    pub fn update_challenge_factor(
        &mut self,
        challenge_factor: Option<ChallengeFactor>,
    ) -> Result<(), Error> {
        if let Some(factor) = &challenge_factor {
            validate_for_enrollment(factor)?;
        }
        let challenge_factor = Self::pinned(challenge_factor.as_ref())?;
        let previous = std::mem::replace(&mut self.challenge_factor, challenge_factor);
        if let Err(e) = self.save_database() {
            self.challenge_factor = previous;
            return Err(e);
        }
        Ok(())
    }

    /// The factor to keep for the saves that follow an open, a creation or
    /// an enrollment: the given one, except that a YubiKey factor naming no
    /// key is pinned to the key connected right now (see
    /// [`ChallengeFactor::pinned_to_connected`]).
    fn pinned(
        challenge_factor: Option<&ChallengeFactor>,
    ) -> Result<Option<ChallengeFactor>, Error> {
        let factor = challenge_factor.cloned();
        #[cfg(feature = "usb")]
        let factor = factor
            .map(|factor| factor.pinned_to_connected(|slot| ChallengeFactor::yubikey(slot, None)))
            .transpose()?;
        Ok(factor)
    }

    /// [`Self::update_challenge_factor`] with the new factor given as
    /// keepass-ng's own `ChallengeResponseKey`.
    pub fn update_challenge_response(
        &mut self,
        challenge_response: Option<ChallengeResponseKey>,
    ) -> Result<(), Error> {
        // Converted first: an invalid key leaves the enrolled factor as it
        // was, like any other failed update.
        let challenge_factor = challenge_response
            .as_ref()
            .map(ChallengeFactor::try_from)
            .transpose()?;
        self.update_challenge_factor(challenge_factor)
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
        challenge_factor: Option<&ChallengeFactor>,
    ) -> Result<DatabaseKey, Error> {
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
        if let Some(factor) = challenge_factor {
            key = key.with_challenge_response_key(factor.challenge_response_key()?);
        }
        Ok(key)
    }

    fn open_database(
        filepath: &str,
        password: &str,
        keyfile: &Option<String>,
        challenge_factor: Option<&ChallengeFactor>,
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
        let (vault_bytes, key) =
            Self::get_database_key(filepath, password, keyfile, challenge_factor)?;
        // Printed only once the vault file and keyfile opened fine *and* the
        // vault bytes are in memory. The challenge itself happens inside
        // Database::parse, shortly after this point; reading the file first
        // means a vault on an unavailable synced drive fails before the user
        // is told to touch the key (the touch prompt otherwise misattributes
        // the failure to the hardware key).
        if let Some(notice) = touch_notice(challenge_factor) {
            eprintln!("{notice} to open the vault...");
        }
        let mut db = Database::parse(&vault_bytes, key)?;
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
        challenge_factor: Option<&ChallengeFactor>,
    ) -> Result<(Vec<u8>, DatabaseKey), Error> {
        let vault_bytes = Self::read_vault_file(filepath)?;
        let key = Self::build_key(password, keyfile, challenge_factor)?;
        Ok((vault_bytes, key))
    }

    /// Read the vault file into memory. File Provider-backed folders
    /// (Dropbox, OneDrive, iCloud Drive, Google Drive) can transiently
    /// refuse reads with EDEADLK/EAGAIN/EBUSY while the provider is busy,
    /// updating or restarting, so transient errors are retried briefly
    /// before giving up — they usually clear within seconds.
    fn read_vault_file(filepath: &str) -> Result<Vec<u8>, Error> {
        Self::read_vault_file_with(filepath, |p| std::fs::read(p), std::thread::sleep)
    }

    /// `read_vault_file` with the filesystem reader and the sleep injected,
    /// so the retry behavior is deterministically testable.
    fn read_vault_file_with(
        filepath: &str,
        mut read: impl FnMut(&str) -> std::io::Result<Vec<u8>>,
        mut sleep: impl FnMut(std::time::Duration),
    ) -> Result<Vec<u8>, Error> {
        const MAX_ATTEMPTS: u32 = 5;
        const RETRY_DELAY_MS: u64 = 500;
        for attempt in 1..=MAX_ATTEMPTS {
            match read(filepath) {
                Ok(bytes) => return Ok(bytes),
                Err(e) if is_transient_read_error(&e) && attempt < MAX_ATTEMPTS => {
                    eprintln!(
                        "Vault file '{}' is not readable yet ({}), retrying ({}/{})...",
                        filepath,
                        e,
                        attempt,
                        MAX_ATTEMPTS - 1
                    );
                    sleep(std::time::Duration::from_millis(RETRY_DELAY_MS));
                }
                Err(e) => {
                    return Err(Error::new(&format!(
                        "Failed to read vault file '{}': {}.{}",
                        filepath,
                        e,
                        sync_folder_hint(filepath)
                    )));
                }
            }
        }
        unreachable!("read_vault_file loop must return on its last attempt")
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
        let agent_policy = Self::node_agent_policy(&node);
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
                .with_agent_policy(agent_policy)
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
        // real URL, so drop it on read — unless it is an absolute URI, which
        // no legacy service name ever was.
        let url = e
            .get_url()
            .map(|u| u.to_string())
            .filter(|u| !u.is_empty() && (u != &title || is_absolute_uri(u)));
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
            Self::get_node_payment_values(node.clone())?;
        Some(
            PaymentCard::new(
                Some(&id),
                &name,
                &name_on_card,
                &number,
                &cvv,
                expiry,
                color.as_deref(),
                billing_address.as_ref(),
                None,
            )
            .with_agent_policy(Self::node_agent_policy(&node)),
        )
    }

    fn node_to_note(node: NodePtr) -> Note {
        let (title, content, id, last_modified) = Self::get_node_note_values(node.clone());
        Note::new(
            Some(&id),
            &title,
            &content,
            last_modified.map(|dt| DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc)),
        )
        .with_agent_policy(Self::node_agent_policy(&node))
    }

    /// The entry's agent access policy, read from the `agent` custom
    /// attribute. Credentials carry their custom attributes in the entity
    /// itself; the other entry types only surface this one.
    fn node_agent_policy(node: &NodePtr) -> crate::vault::entities::AgentPolicy {
        let node = node.borrow();
        node.downcast_ref::<Entry>()
            .map(|e| {
                crate::vault::entities::AgentPolicy::parse(
                    e.get(crate::vault::entities::AGENT_ATTRIBUTE),
                )
            })
            .unwrap_or_default()
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
        let number = Self::extract_value_from_note_opt(note, "Number")
            .and_then(|value| Self::non_empty_str(Some(&value)).map(String::from))?;
        let cvv = Self::extract_value_from_note(note, "CVV");
        let expiry = Self::extract_value_from_note_opt(note, "Expiry")
            .and_then(|value| Expiry::from_str(value.trim()).ok())?;
        // The legacy format always wrote a "Color: " line, empty when no
        // color was set; an empty value is no color, matching the
        // custom-fields read path.
        let color_note = Self::extract_value_from_note_opt(note, "Color");
        let color = Self::non_empty_str(color_note.as_deref()).map(String::from);
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
        let number = Self::non_empty_str(e.get(PAYMENT_FIELD_NUMBER))?;
        let expiry = Expiry::from_str(e.get(PAYMENT_FIELD_EXPIRY)?.trim()).ok()?;
        let name_on_card = e.get(PAYMENT_FIELD_NAME_ON_CARD).unwrap_or("").to_string();
        let cvv = e.get(PAYMENT_FIELD_CVV).unwrap_or("").to_string();
        let color = Self::non_empty_str(e.get(PAYMENT_FIELD_COLOR)).map(String::from);
        let street = Self::non_empty_str(e.get(PAYMENT_FIELD_ADDRESS_STREET));
        let zip = Self::non_empty_str(e.get(PAYMENT_FIELD_ADDRESS_ZIP));
        let city = Self::non_empty_str(e.get(PAYMENT_FIELD_ADDRESS_CITY));
        let state = Self::non_empty_str(e.get(PAYMENT_FIELD_ADDRESS_STATE));
        let country = Self::non_empty_str(e.get(PAYMENT_FIELD_ADDRESS_COUNTRY));
        // An address is present when any of its parts is, the state
        // included; entries without one store none of the address
        // attributes.
        let has_address = [street, zip, city, state, country]
            .iter()
            .any(|p| p.is_some());
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

    fn non_empty_str(value: Option<&str>) -> Option<&str> {
        match value.map(str::trim) {
            Some(value) if !value.is_empty() => Some(value),
            _ => None,
        }
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
        let otp: TOTP = normalized_url
            .parse()
            .map_err(|e| Error::new(&format!("Failed to parse OTP URL: {:?}", e)))?;
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
            .collect::<std::collections::HashSet<String>>();
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
            Self::non_empty_str(payment.color().map(|color| color.as_str())),
        )?;
        let address = payment.billing_address();
        entry.set_additional_attribute(
            PAYMENT_FIELD_ADDRESS_STREET,
            Self::non_empty_str(address.map(|a| a.street())),
        )?;
        entry.set_additional_attribute(
            PAYMENT_FIELD_ADDRESS_ZIP,
            Self::non_empty_str(address.map(|a| a.zip())),
        )?;
        entry.set_additional_attribute(
            PAYMENT_FIELD_ADDRESS_CITY,
            Self::non_empty_str(address.map(|a| a.city())),
        )?;
        entry.set_additional_attribute(
            PAYMENT_FIELD_ADDRESS_STATE,
            Self::non_empty_str(address.and_then(|a| a.state()).map(|state| state.as_str())),
        )?;
        entry.set_additional_attribute(
            PAYMENT_FIELD_ADDRESS_COUNTRY,
            Self::non_empty_str(address.map(|a| a.country())),
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
            node.borrow_mut().downcast_mut::<Entry>().map(|entry| {
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
                node.borrow_mut().downcast_mut::<Entry>().map(|entry| {
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
                });
            }
        };
        {
            let mut node = node.borrow_mut();
            let entry = match node.downcast_mut::<Entry>() {
                Some(entry) => entry,
                None => {
                    return Err(Error {
                        message: "Node is not an Entry".to_string(),
                    });
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
                });
            }
        };
        {
            let mut node = node.borrow_mut();
            let entry = match node.downcast_mut::<Entry>() {
                Some(entry) => entry,
                None => {
                    return Err(Error {
                        message: "Node is not an Entry".to_string(),
                    });
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
    use crate::vault::entities::AgentPolicy;

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
        assert!(
            parsed.is_ok(),
            "expected parse to succeed, got {:?}",
            parsed.err()
        );
    }

    #[test]
    fn open_missing_vault_file_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.kdbx");
        let path_str = path.to_str().unwrap();

        let result = KeepassVault::open("any-password", path_str, None, None);
        let err = result
            .err()
            .expect("opening a missing vault file must fail");
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
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.write_all(&[0xAB; 4096]).unwrap();
        drop(f);

        vault.save_database().unwrap();

        let bytes = std::fs::read(&path).unwrap();
        assert!(
            !bytes.ends_with(&[0xAB; 4096]),
            "stale bytes survived the save"
        );
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
    fn agent_policy_attribute_roundtrips_through_kdbx() {
        // The `agent` attribute is a standard KeePass custom attribute, so
        // it must survive save/open for every entry type — including
        // entries the attribute was added to in another KeePass client.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let path_str = path.to_str().unwrap();

        let mut vault = KeepassVault::new(path_str, "master-pw", None, None).unwrap();
        // Credential: the attribute travels with the custom attributes.
        vault
            .save_one_credential(
                Credential::new(None, "secret", "GitHub", "user", None, None)
                    .with_custom_attributes(&[("agent".to_string(), "allow".to_string())]),
            )
            .unwrap();
        // Card, note and TOTP: the attribute is set directly on the entry,
        // the way another KeePass client would.
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
            None,
            None,
            None,
        );
        vault.save_payment(card).unwrap();
        {
            let id = *vault.find_payments()[0].id();
            let node = vault.db.search_node_by_uuid(id).unwrap();
            node.borrow_mut()
                .downcast_mut::<Entry>()
                .unwrap()
                .set_additional_attribute("agent", Some("ask"))
                .unwrap();
        }
        vault
            .save_note(&Note::new(None, "wifi", "wpa-key", None))
            .unwrap();
        {
            let note_id = vault.find_notes()[0].id();
            let node = vault.db.search_node_by_uuid(note_id).unwrap();
            node.borrow_mut()
                .downcast_mut::<Entry>()
                .unwrap()
                .set_additional_attribute("agent", Some("never"))
                .unwrap();
        }
        vault
            .save_totp(&Totp::new(
                None,
                "otpauth://totp/GitHub:user?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
                "GitHub:user",
                "GitHub",
                "JBSWY3DPEHPK3PXP",
                "SHA1",
                30,
                6,
                None,
            ))
            .unwrap();
        {
            let totp_id = *vault.find_totp(None)[0].id();
            let node = vault.db.search_node_by_uuid(totp_id).unwrap();
            node.borrow_mut()
                .downcast_mut::<Entry>()
                .unwrap()
                .set_additional_attribute("agent", Some("allow"))
                .unwrap();
        }
        vault.save_database().unwrap();
        drop(vault);

        let vault = KeepassVault::open("master-pw", path_str, None, None).unwrap();
        assert_eq!(vault.grep(None)[0].agent_policy(), AgentPolicy::Allow);
        assert_eq!(vault.find_payments()[0].agent_policy(), AgentPolicy::Ask);
        assert_eq!(vault.find_notes()[0].agent_policy(), AgentPolicy::Never);
        assert_eq!(vault.find_totp(None)[0].agent_policy(), AgentPolicy::Allow);
    }

    #[test]
    fn payment_edit_preserves_the_agent_attribute() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let path_str = path.to_str().unwrap();

        let mut vault = KeepassVault::new(path_str, "master-pw", None, None).unwrap();
        vault
            .save_payment(PaymentCard::new(
                None,
                "Visa",
                "Jane",
                "4111111111111111",
                "123",
                Expiry {
                    month: 12,
                    year: 30,
                },
                None,
                None,
                None,
            ))
            .unwrap();
        {
            let id = *vault.find_payments()[0].id();
            let node = vault.db.search_node_by_uuid(id).unwrap();
            node.borrow_mut()
                .downcast_mut::<Entry>()
                .unwrap()
                .set_additional_attribute("agent", Some("ask"))
                .unwrap();
        }
        vault.save_database().unwrap();

        // A passlane edit rewrites the card's own fields but must leave the
        // user's agent attribute (like any unknown attribute) untouched.
        let stored = vault.find_payments()[0].clone();
        vault
            .update_payment(PaymentCard::new(
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
            ))
            .unwrap();
        drop(vault);

        let vault = KeepassVault::open("master-pw", path_str, None, None).unwrap();
        assert_eq!(vault.find_payments()[0].agent_policy(), AgentPolicy::Ask);
    }

    #[test]
    fn credential_agent_policy_defaults_to_never_without_attribute() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let path_str = path.to_str().unwrap();

        let mut vault = KeepassVault::new(path_str, "master-pw", None, None).unwrap();
        // An unrecognized value must read as `never`, never widen access.
        vault
            .save_one_credential(
                Credential::new(None, "secret", "GitHub", "user", None, None)
                    .with_custom_attributes(&[("agent".to_string(), "sometimes".to_string())]),
            )
            .unwrap();
        drop(vault);

        let vault = KeepassVault::open("master-pw", path_str, None, None).unwrap();
        assert_eq!(vault.grep(None)[0].agent_policy(), AgentPolicy::Never);
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
    fn entry_with_absolute_url_equal_to_title_keeps_url() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let path_str = path.to_str().unwrap();

        let mut vault = KeepassVault::new(path_str, "master-pw", None, None).unwrap();
        {
            let group_uuid = vault.find_or_create_group("Passwords");
            let node = vault.db.create_new_entry(group_uuid, 0).unwrap();
            let mut n = node.borrow_mut();
            let entry = n.downcast_mut::<Entry>().unwrap();
            entry.set_title(Some("https://example.com"));
            entry.set_url(Some("https://example.com"));
            entry.set_username(Some("user"));
            entry.set_password(Some("pass"));
        }
        vault.save_database().unwrap();
        drop(vault);

        let vault = KeepassVault::open("master-pw", path_str, None, None).unwrap();
        let found = &vault.grep(None)[0];
        assert_eq!(found.title(), "https://example.com");
        assert_eq!(found.url(), Some("https://example.com"));
    }

    #[test]
    fn entry_with_scheme_only_url_equal_to_title_keeps_url() {
        // mailto:/tel:/urn: URIs carry no "//", but are still absolute URIs
        // and must not be mistaken for the legacy Title == URL duplicate.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let path_str = path.to_str().unwrap();

        let mut vault = KeepassVault::new(path_str, "master-pw", None, None).unwrap();
        {
            let group_uuid = vault.find_or_create_group("Passwords");
            let node = vault.db.create_new_entry(group_uuid, 0).unwrap();
            let mut n = node.borrow_mut();
            let entry = n.downcast_mut::<Entry>().unwrap();
            entry.set_title(Some("mailto:support@example.com"));
            entry.set_url(Some("mailto:support@example.com"));
            entry.set_username(Some("user"));
            entry.set_password(Some("pass"));
        }
        vault.save_database().unwrap();
        drop(vault);

        let vault = KeepassVault::open("master-pw", path_str, None, None).unwrap();
        let found = &vault.grep(None)[0];
        assert_eq!(found.title(), "mailto:support@example.com");
        assert_eq!(found.url(), Some("mailto:support@example.com"));
    }

    #[test]
    fn is_absolute_uri_recognizes_schemes() {
        assert!(is_absolute_uri("https://example.com"));
        assert!(is_absolute_uri("mailto:user@example.com"));
        assert!(is_absolute_uri("tel:+3581234567"));
        assert!(is_absolute_uri("urn:isbn:0451450523"));
        assert!(is_absolute_uri("otpauth://totp/x"));
        // Bare service names and paths are not absolute URIs
        assert!(!is_absolute_uri("github.com"));
        assert!(!is_absolute_uri("example.com/login"));
        assert!(!is_absolute_uri("/var/tmp"));
        assert!(!is_absolute_uri("1password://x"));
        assert!(!is_absolute_uri("no scheme here"));
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
        assert!(
            err.message.contains("Title"),
            "unexpected error: {}",
            err.message
        );
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

    #[test]
    fn transient_read_errors_are_classified() {
        // EDEADLK (macOS) / EAGAIN (Linux), EBUSY, EAGAIN (macOS) /
        // EDEADLK (Linux): the errors a File Provider emits when busy.
        for errno in [11, 16, 35] {
            let e = std::io::Error::from_raw_os_error(errno);
            assert!(
                is_transient_read_error(&e),
                "errno {} must be transient",
                errno
            );
        }
        for errno in [2, 13, 21, 5] {
            let e = std::io::Error::from_raw_os_error(errno);
            assert!(
                !is_transient_read_error(&e),
                "errno {} must not be transient",
                errno
            );
        }
        assert!(!is_transient_read_error(&std::io::Error::from(
            std::io::ErrorKind::UnexpectedEof
        )));
    }

    #[test]
    fn sync_folder_hint_matches_known_providers() {
        assert!(sync_folder_hint("/Users/x/vaults/store.kdbx").is_empty());
        assert!(!sync_folder_hint("/Users/x/Dropbox/Documents/store.kdbx").is_empty());
        assert!(!sync_folder_hint("/Users/x/OneDrive/store.kdbx").is_empty());
        assert!(!sync_folder_hint("/Users/x/Library/Mobile Documents/store.kdbx").is_empty());
        // macOS File Provider mounts under ~/Library/CloudStorage.
        assert!(
            !sync_folder_hint("/Users/x/Library/CloudStorage/OneDrive-Personal/store.kdbx")
                .is_empty()
        );
        assert!(
            !sync_folder_hint(
                "/Users/x/Library/CloudStorage/GoogleDrive-user@example.com/My Drive/store.kdbx"
            )
            .is_empty()
        );
        assert!(
            !sync_folder_hint("/Users/x/Library/CloudStorage/Dropbox-personal/store.kdbx")
                .is_empty()
        );
        // Native Windows paths, separators and case.
        assert!(!sync_folder_hint(r"C:\Users\x\OneDrive\store.kdbx").is_empty());
        assert!(!sync_folder_hint(r"C:\Users\X\Dropbox\Documents\store.kdbx").is_empty());
        // Work/school and business folders carry an organization suffix.
        assert!(!sync_folder_hint(r"C:\Users\Alice\OneDrive - Contoso\store.kdbx").is_empty());
        assert!(!sync_folder_hint(r"C:\Users\Alice\Dropbox (Contoso)\store.kdbx").is_empty());
        // A path merely containing the word is not enough...
        assert!(sync_folder_hint("/Users/x/my-dropbox-backups/store.kdbx").is_empty());
        assert!(sync_folder_hint(r"C:\Users\x\dropbox-backups\store.kdbx").is_empty());
    }

    #[test]
    fn read_vault_file_recovers_after_transient_errors() {
        let reads = std::cell::RefCell::new(0);
        let mut sleeps = Vec::new();
        let result = KeepassVault::read_vault_file_with(
            "/Users/x/Dropbox/store.kdbx",
            |path| {
                let n = {
                    let mut r = reads.borrow_mut();
                    *r += 1;
                    *r
                };
                if n < 3 {
                    Err(std::io::Error::from_raw_os_error(11))
                } else {
                    assert_eq!(path, "/Users/x/Dropbox/store.kdbx");
                    Ok(vec![1, 2, 3])
                }
            },
            |d| sleeps.push(d),
        );
        assert_eq!(result.unwrap(), vec![1, 2, 3]);
        assert_eq!(*reads.borrow(), 3, "success on the third read");
        assert_eq!(sleeps.len(), 2, "one sleep per retry");
        assert!(sleeps.iter().all(|d| d.as_millis() == 500));
    }

    #[test]
    fn read_vault_file_gives_up_after_five_attempts() {
        let reads = std::cell::RefCell::new(0);
        let mut sleeps = Vec::new();
        let err = KeepassVault::read_vault_file_with(
            "/Users/x/Dropbox/store.kdbx",
            |_| {
                *reads.borrow_mut() += 1;
                Err(std::io::Error::from_raw_os_error(11))
            },
            |d| sleeps.push(d),
        )
        .unwrap_err();
        assert_eq!(*reads.borrow(), 5, "the attempt limit is five reads");
        assert_eq!(sleeps.len(), 4, "no sleep after the final attempt");
        assert!(
            err.message
                .contains("Failed to read vault file '/Users/x/Dropbox/store.kdbx'"),
            "unexpected message: {}",
            err.message
        );
        // The OS message for the injected errno differs per platform
        // (EDEADLK on macOS, EAGAIN on Linux); derive it, don't hard-code.
        assert!(
            err.message
                .contains(&std::io::Error::from_raw_os_error(11).to_string()),
            "unexpected message: {}",
            err.message
        );
        assert!(
            err.message.contains("synced folder"),
            "unexpected message: {}",
            err.message
        );
    }

    #[test]
    fn read_vault_file_fails_immediately_on_permanent_error() {
        let reads = std::cell::RefCell::new(0);
        let mut sleeps = Vec::new();
        let err = KeepassVault::read_vault_file_with(
            "/vaults/store.kdbx",
            |_| {
                *reads.borrow_mut() += 1;
                Err(std::io::Error::from_raw_os_error(13)) // EACCES
            },
            |d| sleeps.push(d),
        )
        .unwrap_err();
        assert_eq!(*reads.borrow(), 1, "no retries for a permanent error");
        assert!(sleeps.is_empty());
        assert!(
            err.message
                .contains("Failed to read vault file '/vaults/store.kdbx'"),
            "unexpected message: {}",
            err.message
        );
    }

    #[test]
    fn open_unreadable_vault_reports_file_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");

        // A valid vault, so environments that can still read the file
        // (Windows skips the permission change; privileged Unix ignores
        // it) take the successful-open path and skip the assertions
        // below instead of failing on an unparseable fixture.
        KeepassVault::new(path.to_str().unwrap(), "fixture-pw", None, None).unwrap();

        // Make the vault unreadable (EACCES) for anyone but root.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        }
        let result = KeepassVault::open("fixture-pw", path.to_str().unwrap(), None, None);
        if let Err(err) = result {
            assert!(
                err.message.contains("Failed to read vault file"),
                "unexpected error message: {}",
                err.message
            );
            assert!(
                err.message.contains(path.to_str().unwrap()),
                "error message must name the vault file: {}",
                err.message
            );
        }
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

    /// A virtual key: the 20-byte HMAC-SHA1 secret a vault would be
    /// enrolled with on a phone, or that backs up a hardware key's slot.
    fn virtual_factor() -> ChallengeFactor {
        ChallengeFactor::from_secret_hex("0102030405060708090a0b0c0d0e0f1011121314").unwrap()
    }

    fn another_virtual_factor() -> ChallengeFactor {
        ChallengeFactor::from_secret_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap()
    }

    #[test]
    fn virtual_factor_create_lock_open_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let path_str = path.to_str().unwrap();
        let factor = virtual_factor();

        // Create: the very first save is already challenged with the key.
        let mut vault =
            KeepassVault::new_with_challenge_factor(path_str, "master-pw", None, Some(&factor))
                .unwrap();
        vault
            .save_one_credential(Credential::new(
                None, "secret", "GitHub", "user", None, None,
            ))
            .unwrap();
        // Lock: drop the open vault, leaving nothing but the file.
        drop(vault);

        // Unlock with the virtual key it was enrolled with.
        let vault =
            KeepassVault::open_with_challenge_factor("master-pw", path_str, None, Some(&factor))
                .unwrap();
        assert_eq!(vault.grep(None).len(), 1);
        assert_eq!(vault.grep(None)[0].password(), "secret");

        // The factor is really part of the key: the password alone does not
        // open the vault, and neither does a different virtual key.
        assert!(
            KeepassVault::open_with_challenge_factor("master-pw", path_str, None, None).is_err()
        );
        let other = another_virtual_factor();
        assert!(
            KeepassVault::open_with_challenge_factor("master-pw", path_str, None, Some(&other))
                .is_err()
        );
    }

    #[test]
    fn virtual_factor_resaves_without_a_touch_notice() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let path_str = path.to_str().unwrap();
        let factor = virtual_factor();
        KeepassVault::new_with_challenge_factor(path_str, "master-pw", None, Some(&factor))
            .unwrap();

        // Every save re-challenges the factor. A virtual key answers on the
        // spot, so the user is never told to touch anything — unlike with a
        // hardware key, which blocks on the touch.
        assert!(touch_notice(Some(&factor)).is_none());
        assert!(touch_notice(None).is_none());

        let mut vault =
            KeepassVault::open_with_challenge_factor("master-pw", path_str, None, Some(&factor))
                .unwrap();
        vault
            .save_one_credential(Credential::new(
                None, "secret", "GitHub", "user", None, None,
            ))
            .unwrap();
        drop(vault);
        let vault =
            KeepassVault::open_with_challenge_factor("master-pw", path_str, None, Some(&factor))
                .unwrap();
        assert_eq!(vault.grep(None).len(), 1);
    }

    #[test]
    fn virtual_factor_and_keepass_local_challenge_are_interchangeable() {
        // The virtual factor is not a new vault-format type: it is the same
        // HMAC-SHA1 challenge-response as keepass-ng's LocalChallenge, so a
        // vault enrolled through either API opens through the other.
        let dir = tempfile::tempdir().unwrap();
        let legacy = local_challenge();

        let legacy_path = dir.path().join("legacy.kdbx");
        let legacy_path = legacy_path.to_str().unwrap();
        KeepassVault::new(legacy_path, "master-pw", None, Some(&legacy)).unwrap();
        KeepassVault::open_with_challenge_factor(
            "master-pw",
            legacy_path,
            None,
            Some(&virtual_factor()),
        )
        .unwrap();

        let virtual_path = dir.path().join("virtual.kdbx");
        let virtual_path = virtual_path.to_str().unwrap();
        KeepassVault::new_with_challenge_factor(
            virtual_path,
            "master-pw",
            None,
            Some(&virtual_factor()),
        )
        .unwrap();
        KeepassVault::open("master-pw", virtual_path, None, Some(&legacy)).unwrap();
    }

    #[test]
    fn update_challenge_factor_enrolls_and_removes_a_virtual_factor() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let path_str = path.to_str().unwrap();

        let mut vault =
            KeepassVault::new_with_challenge_factor(path_str, "master-pw", None, None).unwrap();
        vault
            .update_challenge_factor(Some(virtual_factor()))
            .unwrap();
        drop(vault);
        // The enrollment is persisted: reopening needs the factor.
        assert!(
            KeepassVault::open_with_challenge_factor("master-pw", path_str, None, None).is_err()
        );

        let mut vault = KeepassVault::open_with_challenge_factor(
            "master-pw",
            path_str,
            None,
            Some(&virtual_factor()),
        )
        .unwrap();
        vault.update_challenge_factor(None).unwrap();
        drop(vault);
        assert!(
            KeepassVault::open_with_challenge_factor("master-pw", path_str, None, None).is_ok()
        );
        assert!(
            KeepassVault::open_with_challenge_factor(
                "master-pw",
                path_str,
                None,
                Some(&virtual_factor())
            )
            .is_err()
        );
    }

    #[test]
    fn change_master_password_preserves_a_virtual_factor() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let path_str = path.to_str().unwrap();

        let factor = virtual_factor();
        let mut vault =
            KeepassVault::new_with_challenge_factor(path_str, "old-pw", None, Some(&factor))
                .unwrap();
        vault
            .save_one_credential(Credential::new(
                None, "secret", "GitHub", "user", None, None,
            ))
            .unwrap();
        vault.change_master_password("new-pw".to_string()).unwrap();
        drop(vault);

        let vault =
            KeepassVault::open_with_challenge_factor("new-pw", path_str, None, Some(&factor))
                .unwrap();
        assert_eq!(vault.grep(None).len(), 1);
        assert!(KeepassVault::open_with_challenge_factor("new-pw", path_str, None, None).is_err());
        assert!(
            KeepassVault::open_with_challenge_factor("old-pw", path_str, None, Some(&factor))
                .is_err()
        );
    }

    #[test]
    fn a_malformed_virtual_factor_fails_to_open_and_leaves_the_vault_intact() {
        // A factor built by hand can bypass the constructors. Opening does
        // not second-guess its secret — that is keepass-ng's job, and the
        // file format's rule — so the attempt simply fails to open: no
        // panic, and nothing weakened.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let path_str = path.to_str().unwrap();
        let factor = virtual_factor();
        KeepassVault::new_with_challenge_factor(path_str, "master-pw", None, Some(&factor))
            .unwrap();

        let malformed = ChallengeFactor::Virtual {
            secret_hex: "not hex".to_string(),
        };
        let err =
            KeepassVault::open_with_challenge_factor("master-pw", path_str, None, Some(&malformed))
                .err()
                .expect("a malformed secret must not open the vault");
        assert!(
            err.message
                .contains("Error decoding local challenge secret"),
            "unexpected message: {}",
            err.message
        );
        // To keepass-ng an empty secret is a valid, merely different key.
        let empty = ChallengeFactor::Virtual {
            secret_hex: String::new(),
        };
        let err =
            KeepassVault::open_with_challenge_factor("master-pw", path_str, None, Some(&empty))
                .err()
                .expect("an empty secret must not open this vault");
        assert!(
            err.message.contains("Incorrect key"),
            "unexpected message: {}",
            err.message
        );
        // The failed attempts left the vault intact.
        KeepassVault::open_with_challenge_factor("master-pw", path_str, None, Some(&factor))
            .unwrap();
    }

    /// Write a vault with keepass-ng alone, protected by a local challenge
    /// secret that is not 20 bytes. Nothing in passlane writes one — the
    /// enrollment refuses it — but nothing stops another tool from doing so.
    fn keepass_ng_vault_with_short_secret(path: &str, password: &str, secret_hex: &str) {
        let db = Database::new(DatabaseConfig::default());
        let key = DatabaseKey::new()
            .with_password(password)
            .with_challenge_response_key(ChallengeResponseKey::LocalChallenge(
                secret_hex.to_string(),
            ));
        let mut file = std::fs::File::create(path).unwrap();
        db.save(&mut file, key).unwrap();
    }

    #[test]
    fn a_vault_written_by_keepass_ng_with_a_shorter_secret_still_opens_and_resaves() {
        // Opening must never be stricter than the file format. keepass-ng
        // accepts a challenge secret of any length, so one of its own vaults
        // with a 16-byte secret keeps opening here, through either API, and
        // keeps its factor across a re-save.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let path_str = path.to_str().unwrap();
        // 16 bytes: a fifth short of a YubiKey slot's key.
        let secret_hex = "000102030405060708090a0b0c0d0e0f";
        keepass_ng_vault_with_short_secret(path_str, "master-pw", secret_hex);

        let legacy = ChallengeResponseKey::LocalChallenge(secret_hex.to_string());
        let mut vault = KeepassVault::open("master-pw", path_str, None, Some(&legacy)).unwrap();
        vault
            .save_one_credential(Credential::new(
                None, "secret", "GitHub", "user", None, None,
            ))
            .unwrap();
        drop(vault);

        let existing = ChallengeFactor::from_existing_secret_hex(secret_hex).unwrap();
        let vault =
            KeepassVault::open_with_challenge_factor("master-pw", path_str, None, Some(&existing))
                .unwrap();
        assert_eq!(vault.grep(None).len(), 1);
        // It is still this secret that protects the vault.
        assert!(
            KeepassVault::open_with_challenge_factor("master-pw", path_str, None, None).is_err()
        );
        assert!(
            KeepassVault::open_with_challenge_factor(
                "master-pw",
                path_str,
                None,
                Some(&virtual_factor())
            )
            .is_err()
        );

        // The short secret is not fit to be enrolled, though: not afresh...
        let fresh = dir.path().join("fresh.kdbx");
        assert!(
            KeepassVault::new(fresh.to_str().unwrap(), "master-pw", None, Some(&legacy)).is_err()
        );
        assert!(!fresh.exists());
        // ...and not on the very vault it protects. The refusal leaves the
        // vault as it was, in memory as on disk.
        let mut vault =
            KeepassVault::open_with_challenge_factor("master-pw", path_str, None, Some(&existing))
                .unwrap();
        let err = vault
            .update_challenge_factor(Some(existing.clone()))
            .expect_err("a short secret must not be enrolled");
        assert!(
            err.message.contains("40 hex characters"),
            "unexpected message: {}",
            err.message
        );
        vault
            .save_one_credential(Credential::new(
                None, "another", "GitLab", "user", None, None,
            ))
            .unwrap();
        drop(vault);
        let vault =
            KeepassVault::open_with_challenge_factor("master-pw", path_str, None, Some(&existing))
                .unwrap();
        assert_eq!(vault.grep(None).len(), 2);
    }

    #[test]
    fn an_empty_virtual_factor_cannot_be_enrolled() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let path_str = path.to_str().unwrap();
        let empty = ChallengeFactor::Virtual {
            secret_hex: String::new(),
        };

        // Creating a vault with it fails and leaves no vault file.
        let err =
            KeepassVault::new_with_challenge_factor(path_str, "master-pw", None, Some(&empty))
                .err()
                .expect("an empty secret must not protect a vault");
        assert!(
            err.message.contains("but has 0 characters"),
            "unexpected message: {}",
            err.message
        );
        assert!(!path.exists(), "no vault file must be left behind");

        // Enrolling it on an existing vault fails and keeps the enrolled
        // factor, in memory as on disk.
        let factor = virtual_factor();
        let mut vault =
            KeepassVault::new_with_challenge_factor(path_str, "master-pw", None, Some(&factor))
                .unwrap();
        vault
            .update_challenge_factor(Some(ChallengeFactor::Virtual {
                secret_hex: String::new(),
            }))
            .expect_err("an empty secret must not be enrolled");
        vault
            .save_one_credential(Credential::new(
                None, "secret", "GitHub", "user", None, None,
            ))
            .unwrap();
        drop(vault);
        assert!(
            KeepassVault::open_with_challenge_factor("master-pw", path_str, None, None).is_err()
        );
        KeepassVault::open_with_challenge_factor("master-pw", path_str, None, Some(&factor))
            .unwrap();
    }

    #[test]
    fn a_legacy_local_challenge_with_a_short_secret_cannot_protect_a_vault() {
        // keepass-ng alone would accept this; through the vault it meets
        // the virtual-factor rule and is refused with a clear message.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let path_str = path.to_str().unwrap();
        let short = ChallengeResponseKey::LocalChallenge("ab".to_string());

        let err = KeepassVault::new(path_str, "master-pw", None, Some(&short))
            .err()
            .expect("a two-character secret must not protect a vault");
        assert!(
            err.message.contains("40 hex characters"),
            "unexpected message: {}",
            err.message
        );
        assert!(!path.exists(), "no vault file must be left behind");
    }

    #[test]
    fn a_failed_factor_update_keeps_the_enrolled_factor() {
        // A replacement that is fit to enroll, but whose save fails: the
        // keyfile disappeared after the vault was opened. The vault must
        // keep the factor it was enrolled with, in memory as on disk.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let path_str = path.to_str().unwrap();
        let keyfile_path = dir.path().join("vault.key");
        let keyfile = b"passlane test keyfile".to_vec();
        std::fs::write(&keyfile_path, &keyfile).unwrap();
        let keyfile_str = keyfile_path.to_str().unwrap();
        let factor = virtual_factor();

        let mut vault = KeepassVault::new_with_challenge_factor(
            path_str,
            "master-pw",
            Some(keyfile_str),
            Some(&factor),
        )
        .unwrap();

        std::fs::remove_file(&keyfile_path).unwrap();
        let err = vault
            .update_challenge_factor(Some(another_virtual_factor()))
            .expect_err("the save must fail without the keyfile");
        // The save failed; the enrollment check did not reject the factor.
        assert!(
            !err.message.contains("40 hex characters"),
            "unexpected message: {}",
            err.message
        );
        std::fs::write(&keyfile_path, &keyfile).unwrap();

        // In memory the original key is still the enrolled factor: the next
        // save is challenged with it and goes through.
        vault
            .save_one_credential(Credential::new(
                None, "secret", "GitHub", "user", None, None,
            ))
            .unwrap();
        drop(vault);

        // So it is on disk: the replacement never took.
        let keyfile = Some(keyfile_str.to_string());
        assert!(
            KeepassVault::open_with_challenge_factor("master-pw", path_str, keyfile.clone(), None)
                .is_err()
        );
        assert!(
            KeepassVault::open_with_challenge_factor(
                "master-pw",
                path_str,
                keyfile.clone(),
                Some(&another_virtual_factor())
            )
            .is_err()
        );
        let vault =
            KeepassVault::open_with_challenge_factor("master-pw", path_str, keyfile, Some(&factor))
                .unwrap();
        assert_eq!(vault.grep(None).len(), 1);
    }

    #[test]
    fn a_kept_factor_is_the_one_given() {
        // No factor, or one that already names what answers for it, is
        // kept exactly as given.
        assert!(KeepassVault::pinned(None).unwrap().is_none());
        let factor = virtual_factor();
        let kept = KeepassVault::pinned(Some(&factor)).unwrap().unwrap();
        assert_eq!(
            kept.challenge_response_key().unwrap(),
            factor.challenge_response_key().unwrap()
        );
    }

    #[cfg(feature = "usb")]
    #[test]
    fn a_kept_yubikey_factor_is_kept_named_or_refused_before_any_key_is_looked_for() {
        let named = ChallengeFactor::Yubikey {
            slot: 1,
            serial: Some(42),
        };
        let kept = KeepassVault::pinned(Some(&named)).unwrap().unwrap();
        assert!(matches!(
            kept,
            ChallengeFactor::Yubikey {
                slot: 1,
                serial: Some(42)
            }
        ));
        // An invalid slot is refused before the lookup, so this needs no key.
        let nameless = ChallengeFactor::Yubikey {
            slot: 7,
            serial: None,
        };
        let err = KeepassVault::pinned(Some(&nameless)).expect_err("must be refused");
        assert!(
            err.message.contains("must be 1 or 2"),
            "unexpected message: {}",
            err.message
        );
    }

    #[cfg(feature = "usb")]
    #[test]
    fn only_a_yubikey_factor_gets_the_touch_notice() {
        let yubikey = ChallengeFactor::Yubikey {
            slot: 2,
            serial: Some(12345678),
        };
        assert!(yubikey.requires_touch());
        assert_eq!(
            touch_notice(Some(&yubikey)),
            Some("Touch your hardware key")
        );
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
    fn payment_note_with_empty_color_is_treated_as_absent() {
        let node = payment_entry_node(
            "No Color Card",
            "Name on card: User\nNumber: 4111111111111111\nCVV: 123\nExpiry: 12/30\nColor: \nBilling Address: ",
        );
        let payment = KeepassVault::node_to_payment(node).unwrap();
        assert!(payment.color().is_none());
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

    #[test]
    fn payment_note_with_unparseable_expiry_is_visible_as_note() {
        // Detection must not claim the malformed entry either: load_payments
        // drops it in filter_map, and the note/credential loaders exclude
        // payment-looking nodes, so claiming it would make the entry
        // invisible to every loader.
        let node = payment_entry_node(
            "Broken Card",
            "Name on card: X\nNumber: 4111\nCVV: 1\nExpiry: never\nColor: \nBilling Address: ",
        );
        assert!(!node_looks_like_payment(&node));
        assert!(node_looks_like_note(&node));
    }

    #[test]
    fn payment_note_with_blank_number_is_visible_as_note() {
        let node = payment_entry_node(
            "Broken Card",
            "Name on card: X\nNumber:   \nCVV: 1\nExpiry: 12/30\nColor: \nBilling Address: ",
        );
        assert!(!node_looks_like_payment(&node));
        assert!(node_looks_like_note(&node));
        assert!(KeepassVault::node_to_payment(node).is_none());
    }

    #[test]
    fn payment_note_detection_trims_expiry() {
        let node = payment_entry_node(
            "Visa",
            "Name on card: X\nNumber: 4111\nCVV: 1\nExpiry:  12/30  \nColor: \nBilling Address: ",
        );
        assert!(node_looks_like_payment(&node));
        let payment = KeepassVault::node_to_payment(node).unwrap();
        assert_eq!(payment.expiry_str(), "12/30");
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
    fn payment_address_state_only_is_not_dropped() {
        // An address edited in another KeePass client can consist of just
        // the state attribute; the read must keep it instead of dropping
        // the address (and the next write deleting the attribute).
        let node = custom_field_entry_node(
            "Visa",
            &[
                ("Number", "4111111111111111"),
                ("Expiry", "12/30"),
                ("Billing Address State", "CA"),
            ],
        );
        let payment = KeepassVault::node_to_payment(node).unwrap();
        let address = payment
            .billing_address()
            .expect("state-only address must survive the read");
        assert_eq!(address.state(), Some(&"CA".to_string()));
    }

    #[test]
    fn payment_empty_address_attributes_do_not_create_address() {
        let node = custom_field_entry_node(
            "Visa",
            &[
                ("Number", "4111111111111111"),
                ("Expiry", "12/30"),
                ("Billing Address Street", ""),
                ("Billing Address State", ""),
            ],
        );
        let payment = KeepassVault::node_to_payment(node).unwrap();
        assert!(payment.billing_address().is_none());
    }

    #[test]
    fn payment_custom_fields_trim_whitespace() {
        let node = custom_field_entry_node(
            "Visa",
            &[
                ("Number", " 4111111111111111 "),
                ("Expiry", " 12/30 "),
                ("Color", "   "),
            ],
        );
        assert!(node_looks_like_payment(&node));
        let payment = KeepassVault::node_to_payment(node).unwrap();
        assert_eq!(payment.number(), "4111111111111111");
        assert_eq!(payment.expiry_str(), "12/30");
        assert!(payment.color().is_none());
    }

    #[test]
    fn credential_with_card_like_fields_is_not_a_payment() {
        // A credential carrying card-like data — "Number"/"Expiry" custom
        // attributes or legacy "Key: value" note lines — must stay a
        // credential, in both the custom-fields and the legacy-notes
        // detection path.
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
            entry.set_notes(Some("Number: 4111111111111111\nExpiry: 12/30"));
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

    #[test]
    fn payment_save_state_only_address_does_not_write_blank_address_attributes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let path_str = path.to_str().unwrap();

        let address = Address::new(None, "", "", "", Some("CA"), "");
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
            None,
            Some(&address),
            None,
        );
        let mut vault = KeepassVault::new(path_str, "master-pw", None, None).unwrap();
        vault.save_payment(card).unwrap();
        let id = *vault.find_payments()[0].id();

        let node = vault.db.search_node_by_uuid(id).unwrap();
        let n = node.borrow();
        let entry = n.downcast_ref::<Entry>().unwrap();
        assert_eq!(entry.get("Billing Address State"), Some("CA"));
        assert_eq!(entry.get("Billing Address Street"), None);
        assert_eq!(entry.get("Billing Address Zip"), None);
        assert_eq!(entry.get("Billing Address City"), None);
        assert_eq!(entry.get("Billing Address Country"), None);
    }

    #[test]
    fn payment_save_empty_color_does_not_write_color_attribute() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let path_str = path.to_str().unwrap();

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
            Some(""),
            None,
            None,
        );
        let master_password = Uuid::new_v4().to_string();
        let mut vault = KeepassVault::new(path_str, &master_password, None, None).unwrap();
        vault.save_payment(card).unwrap();
        let id = *vault.find_payments()[0].id();

        let node = vault.db.search_node_by_uuid(id).unwrap();
        let n = node.borrow();
        let entry = n.downcast_ref::<Entry>().unwrap();
        assert_eq!(entry.get("Color"), None);
    }
}
