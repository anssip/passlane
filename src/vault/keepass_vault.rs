use crate::vault::entities::{Address, Credential, Error, Expiry, Note, PaymentCard, Totp};
use crate::vault::vault_trait::{NoteVault, PasswordVault, PaymentVault, TotpVault, Vault};
use chrono::{DateTime, NaiveDateTime, Utc};
use keepass_ng::db::{
    group_get_children, node_is_entry, node_is_group, search_node_by_uuid, Database, Entry, Group,
    Node, NodeIterator, NodePtr, SerializableNodePtr,
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

fn node_has_totp(node: &NodePtr) -> bool {
    let node = node.borrow();
    let e = node.as_any().downcast_ref::<Entry>().unwrap();
    debug!(
        "Checking node for TOTP: {:?} {:?}",
        e.get_title(),
        e.get_otp()
    );
    e.get_otp().is_ok()
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
        NodeIterator::new(&self.get_root())
            .filter(node_is_entry)
            .map(Self::node_to_credential)
            .filter(|cred| {
                if let Some(grep) = &grep {
                    if !cred
                        .username()
                        .to_lowercase()
                        .contains(&grep.to_lowercase())
                        && !cred.service().to_lowercase().contains(&grep.to_lowercase())
                    {
                        return false;
                    }
                }
                true
            })
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
        let payments_group_uuid = self.find_group("Payments").unwrap();
        let payments_group = search_node_by_uuid(&self.get_root(), payments_group_uuid).unwrap();
        NodeIterator::new(&payments_group)
            .filter(node_is_entry)
            .map(Self::node_to_payment)
            .collect()
    }

    fn load_notes(&self) -> Vec<Note> {
        let payments_group_uuid = self.find_group("Notes").unwrap();
        let payments_group = search_node_by_uuid(&self.get_root(), payments_group_uuid).unwrap();
        NodeIterator::new(&payments_group)
            .filter(node_is_entry)
            .map(Self::node_to_note)
            .collect()
    }

    fn node_to_credential(node: NodePtr) -> Credential {
        let (username, service, password, uuid, modified_date_time) = Self::get_node_values(node);
        Credential::new(
            Some(&uuid),
            &password,
            &service,
            &username,
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

    fn get_node_values(node: NodePtr) -> (String, String, String, Uuid, Option<NaiveDateTime>) {
        let node = node.borrow();
        let e = node.as_any().downcast_ref::<Entry>().unwrap();
        let username = e.get_username().unwrap_or("(no username)");
        let service = e.get_url().unwrap_or("(no service)");
        let password = e.get_password().unwrap_or("(no password)");
        let uuid = e.get_uuid();
        let last_modified = e.get_times().get_last_modification();
        (
            username.to_string(),
            service.to_string(),
            password.to_string(),
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
        let otp = e
            .get_otp()
            .map_err(|e| Error::new(&format!("Failed to get OTP from keepass node: {:?}", e)))?;
        let url = e
            .get_raw_otp_value()
            .ok_or(Error::new("Failed to get URL from keepass node"))?;
        let last_modified = e.get_times().get_last_modification();
        Ok((
            String::from(url),
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
