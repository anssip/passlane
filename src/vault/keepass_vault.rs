use crate::vault::entities::{Address, Credential, Error, Expiry, Note, PaymentCard, Totp};
use crate::vault::vault_trait::{NoteVault, PasswordVault, PaymentVault, TotpVault, Vault};
use chrono::{DateTime, NaiveDateTime, Utc};
use keepass_ng::db::{
    group_get_children, node_is_entry, node_is_group, Database, Entry, Group,
    Node, NodeIterator, NodePtr, SerializableNodePtr, TOTP,
};
use keepass_ng::error::DatabaseSaveError;
use keepass_ng::{error::DatabaseOpenError, DatabaseConfig, DatabaseKey};

use log::debug;
use std::fs::{File, OpenOptions};
use std::path::Path;
use std::str::FromStr;
use uuid::Uuid;

pub struct KeepassVault {
    password: String,
    db: Database,
    filepath: String,
    keyfile: Option<String>,
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

impl From<keepass_ng::error::Error> for Error {
    fn from(e: keepass_ng::error::Error) -> Self {
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
    let e = node.as_any().downcast_ref::<Entry>().unwrap();
    let raw = e.get_raw_otp_value();
    debug!("Checking node for TOTP: {:?} raw={:?}", e.get_title(), raw);
    match raw {
        Some(url) => TOTP::from_str(&normalize_otp_url(url)).is_ok(),
        None => false,
    }
}

fn node_looks_like_payment(node: &NodePtr) -> bool {
    let node = node.borrow();
    let e = match node.as_any().downcast_ref::<Entry>() {
        Some(e) => e,
        None => return false,
    };
    let notes = match e.get_notes() {
        Some(n) if !n.is_empty() => n,
        _ => return false,
    };
    let has_number = notes.lines().any(|l| l.starts_with("Number: "));
    let has_expiry = notes.lines().any(|l| l.starts_with("Expiry: "));
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
    let e = match node.as_any().downcast_ref::<Entry>() {
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
    let e = match node_ref.as_any().downcast_ref::<Entry>() {
        Some(e) => e,
        None => return false,
    };
    let has_username = e.get_username().map(|u| !u.is_empty()).unwrap_or(false);
    let has_password = e.get_password().map(|p| !p.is_empty()).unwrap_or(false);
    let has_url = e.get_url().map(|u| !u.is_empty()).unwrap_or(false);
    has_username || has_password || has_url
}

impl KeepassVault {
    pub fn open(
        password: &str,
        filepath: &str,
        keyfile_path: Option<String>,
    ) -> Result<KeepassVault, Error> {
        debug!("Opening database '{}'", filepath);
        let db = Self::open_database(filepath, password, &keyfile_path)?;
        Ok(Self {
            password: String::from(password),
            db,
            filepath: filepath.to_string(),
            keyfile: keyfile_path,
        })
    }

    pub fn new(
        filepath: &str,
        password: &str,
        keyfile: Option<&str>,
    ) -> Result<KeepassVault, Error> {
        let mut db = Database::new(DatabaseConfig::default());
        db.meta.database_name = Some("Passlane database".to_string());

        let mut key = DatabaseKey::new().with_password(password);

        if let Some(keyfile_path) = keyfile {
            println!("Using keyfile '{}'", keyfile_path);
            let mut file = File::open(keyfile_path)?;
            key = key.with_keyfile(&mut file)?;
        }
        db.save(&mut File::create(filepath)?, key)?;

        Ok(KeepassVault {
            db,
            password: password.to_string(),
            filepath: filepath.to_string(),
            keyfile: keyfile.map(ToString::to_string),
        })
    }

    fn get_root(&self) -> SerializableNodePtr {
        self.db.root.clone()
    }

    fn get_root_uuid(&self) -> Uuid {
        self.get_root().borrow().get_uuid()
    }

    fn save_database(&self) -> Result<(), DatabaseSaveError> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(!Path::new(&self.filepath).exists())
            .open(&self.filepath)
            .unwrap();

        let (_, key) =
            Self::get_database_key(&self.filepath, &self.password, &self.keyfile).unwrap();
        debug!("Saving database to file '{}'", &self.filepath);

        self.db.save(&mut file, key)
    }

    pub fn change_master_password(&mut self, new_password: String) -> Result<(), Error> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.filepath)?;
        let (_, key) = Self::get_database_key(&self.filepath, &new_password, &self.keyfile)?;
        debug!("Re-encrypting database '{}' with new master password", &self.filepath);
        self.db.save(&mut file, key)?;
        self.password = new_password;
        Ok(())
    }

    fn open_database(
        filepath: &str,
        password: &str,
        keyfile: &Option<String>,
    ) -> Result<Database, Error> {
        if !Path::new(filepath).exists() {
            debug!(
                "Database file '{}' does not exist, creating new database",
                filepath
            );
            return Ok(Database::new(DatabaseConfig::default()));
        }
        let (mut db_file, key) = Self::get_database_key(filepath, password, keyfile)?;
        let mut db = Database::open(&mut db_file, key)?;
        db.set_recycle_bin_enabled(false);
        Ok(db)
    }

    fn create_group(&self, parent_uuid: Uuid, group_name: &str) -> Option<Uuid> {
        self.db
            .create_new_group(parent_uuid, 0)
            .map(|node| {
                node.borrow_mut()
                    .as_any_mut()
                    .downcast_mut::<Group>()
                    .map(|group| {
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
    ) -> Result<(File, DatabaseKey), DatabaseOpenError> {
        let db_file = File::open(filepath)?;
        let key = match keyfile {
            Some(kf) => {
                debug!("Using keyfile '{}' and password", kf);
                let file = &mut File::open(kf).expect("Failed to open keyfile");
                DatabaseKey::new()
                    .with_password(password)
                    .with_keyfile(file)
                    .unwrap()
            }
            None => DatabaseKey::new().with_password(password),
        };
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
                let e = node.as_any().downcast_ref::<Entry>().unwrap();
                let title = e.get_title().unwrap_or("").to_lowercase();
                let url = e.get_url().unwrap_or("").to_lowercase();
                let username = e.get_username().unwrap_or("").to_lowercase();
                let combined = format!("{}:{}", url, username);
                title.contains(grep_lower)
                    || url.contains(grep_lower)
                    || username.contains(grep_lower)
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
            .map(Self::node_to_payment)
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
        let (username, service, password, note, uuid, modified_date_time) = Self::get_node_values(node);
        Credential::new(
            Some(&uuid),
            &password,
            &service,
            &username,
            note.as_deref(),
            modified_date_time.map(|dt| DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc)),
        )
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

    fn get_node_values(node: NodePtr) -> (String, String, String, Option<String>, Uuid, Option<NaiveDateTime>) {
        let node = node.borrow();
        let e = node.as_any().downcast_ref::<Entry>().unwrap();
        let username = e.get_username().unwrap_or("(no username)");
        let service = match e.get_url() {
            Some(url) if !url.is_empty() => url,
            _ => e.get_title().unwrap_or("(no service)"),
        };
        let password = e.get_password().unwrap_or("(no password)");
        let note = e.get_notes()
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty());
        let uuid = e.get_uuid();
        let last_modified = e.get_times().get_last_modification();
        (
            username.to_string(),
            service.to_string(),
            password.to_string(),
            note,
            uuid,
            last_modified,
        )
    }

    fn node_to_payment(node: NodePtr) -> PaymentCard {
        let (name, name_on_card, number, cvv, expiry, color, billing_address, id) =
            Self::get_node_payment_values(node).unwrap();
        PaymentCard::new(
            Some(&id),
            &name,
            &name_on_card,
            &number,
            &cvv,
            Expiry::from_str(&expiry).unwrap(),
            color.as_deref(),
            Some(&Address::from_str(&billing_address).unwrap()),
            None,
        )
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
        String,
        Option<String>,
        String,
        Uuid,
    )> {
        let node = node.borrow();
        let e = node.as_any().downcast_ref::<Entry>().unwrap();
        let note = e.get_notes()?;
        let name = e.get_title().unwrap_or("(no name)");
        let name_on_card = Self::extract_value_from_note(note, 0, "Name on card");
        let number = Self::extract_value_from_note(note, 1, "Number");
        let cvv = Self::extract_value_from_note(note, 2, "CVV");
        let expiry = Self::extract_value_from_note(note, 3, "Expiry");
        let color = Self::extract_value_from_note_opt(note, 4, "Color");
        let billing_address = Self::extract_value_from_note(note, 5, "Billing Address");

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

    fn get_node_note_values(node: NodePtr) -> (String, String, Uuid, Option<NaiveDateTime>) {
        let node = node.borrow();
        let e = node.as_any().downcast_ref::<Entry>().unwrap();
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

    fn extract_value_from_note_opt(note: &str, line: usize, name: &str) -> Option<String> {
        let no_value = &format!("(no {name} on card)");
        note.lines()
            .nth(line)
            .unwrap_or(no_value)
            .split(&format!("{name}: "))
            .nth(1)
            .map(|v| String::from(v))
    }

    fn extract_value_from_note(note: &str, line: usize, name: &str) -> String {
        let no_value = String::from(&format!("(no {name} on card)"));
        Self::extract_value_from_note_opt(note, line, name).unwrap_or(no_value)
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
            .as_any()
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
            String::from(&otp.issuer),
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
                if let Some(entry) = node.borrow().as_any().downcast_ref::<Group>() {
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

    fn create_password_entry(
        &mut self,
        parent_uuid: &Uuid,
        credentials: &Credential,
    ) -> keepass_ng::Result<Option<Uuid>> {
        self.db
            .create_new_entry(parent_uuid.clone(), 0)
            .map(|node| {
                node.borrow_mut()
                    .as_any_mut()
                    .downcast_mut::<Entry>()
                    .map(|entry| {
                        entry.set_title(Some(credentials.service()));
                        entry.set_username(Some(credentials.username()));
                        entry.set_password(Some(credentials.password()));
                        entry.set_url(Some(&credentials.service()));
                        entry.set_notes(credentials.note());
                        entry.get_uuid()
                    })
            })
    }

    fn create_totp_entry(
        &mut self,
        parent_uuid: &Uuid,
        totp: &Totp,
    ) -> Result<Option<Uuid>, Error> {
        Ok(self.db.create_new_entry(*parent_uuid, 0).map(|node| {
            node.borrow_mut()
                .as_any_mut()
                .downcast_mut::<Entry>()
                .map(|entry| {
                    entry.set_title(Some(totp.label()));
                    entry.set_otp(totp.url());
                    entry.get_uuid()
                })
        })?)
    }

    fn create_payment_entry(
        &mut self,
        parent_uuid: &Uuid,
        payment: &PaymentCard,
    ) -> keepass_ng::Result<Option<Uuid>> {
        self.db.create_new_entry(parent_uuid.clone(), 0).map(|node| {
            let note = format!("Name on card: {}\nNumber: {}\nCVV: {}\nExpiry: {}\nColor: {}\nBilling Address: {}",
                               payment.name_on_card(),
                               payment.number(),
                               payment.cvv(),
                               payment.expiry_str(),
                               payment.color_str(),
                               payment.billing_address().as_ref().map(|a| a.to_string()).unwrap_or("".to_string())
            );
            node.borrow_mut().as_any_mut().downcast_mut::<Entry>().map(|entry| {
                entry.set_title(Some(payment.name()));
                entry.set_notes(Some(&note));
                entry.get_uuid()
            })
        })
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
                    .as_any_mut()
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
                if let Some(entry) = node.as_any_mut().downcast_mut::<Entry>() {
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
        let uuid = credential.uuid();
        self.update_entry(*uuid, |entry| {
            entry.set_title(Some(credential.service()));
            entry.set_username(Some(credential.username()));
            entry.set_password(Some(credential.password()));
            entry.set_url(Some(credential.service()));
            entry.set_notes(credential.note());
        })
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
                let e = node.as_any().downcast_ref::<Entry>().unwrap();
                let username = e.get_username().unwrap_or("(no username)");
                let service = e.get_url().unwrap_or("(no service)");
                username.contains(grep) || service.contains(grep)
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
        self.create_payment_entry(&group, &payment)
            .expect("Failed to save payment");
        self.save_database()?;
        Ok(())
    }

    fn delete_payment(&mut self, id: &Uuid) -> Result<(), Error> {
        self.do_delete(id, true)?;
        Ok(())
    }

    fn update_payment(&mut self, payment: PaymentCard) -> Result<(), Error> {
        let uuid = payment.id();
        self.update_entry(*uuid, |entry| {
            let note = format!(
                "Name on card: {}\nNumber: {}\nCVV: {}\nExpiry: {}\nColor: {}\nBilling Address: {}",
                payment.name_on_card(),
                payment.number(),
                payment.cvv(),
                payment.expiry_str(),
                payment.color_str(),
                payment
                    .billing_address()
                    .as_ref()
                    .map(|a| a.to_string())
                    .unwrap_or("".to_string())
            );

            entry.set_title(Some(payment.name()));
            entry.set_notes(Some(&note));
        })
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
            entry.set_otp(totp.url());
        })
    }
}

impl Vault for KeepassVault {}

#[cfg(test)]
mod tests {
    use super::*;

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
}
