use crate::vault::entities::{Address, Credential, Expiry, Note, PaymentCard, Error};
use crate::vault::vault_trait::{NoteVault, PasswordVault, PaymentVault, Vault};
use keepass_ng::{db::Entry, db::Node, Database, DatabaseKey, error::DatabaseOpenError, group_get_children, NodeIterator, node_is_group, NodePtr, node_is_entry, search_node_by_uuid, DatabaseConfig, Group};
use std::fs::{File, OpenOptions};
use std::path::Path;
use std::str::FromStr;
use log::{debug, error};
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

impl KeepassVault {
    pub fn new(password: &str, filepath: &str, keyfile_path: Option<String>) -> Result<KeepassVault, Error> {
        debug!("Opening database '{}'", filepath);
        let db = Self::open_database(filepath, password, &keyfile_path)?;
        Ok(Self {
            password: String::from(password),
            db,
            filepath: filepath.to_string(),
            keyfile: keyfile_path,
        })
    }
    fn get_root(&self) -> NodePtr {
        self.db.root.clone()
    }

    fn get_root_uuid(&self) -> Uuid {
        self.get_root().borrow().get_uuid()
    }

    fn save_database(&self) {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(!Path::new(&self.filepath).exists())
            .open(&self.filepath).unwrap();

        let (_, key) = Self::get_database_key(&self.filepath, &self.password, &self.keyfile).unwrap();
        debug!("Saving database to file '{}'", &self.filepath);

        self.db.save(&mut file, key).unwrap();
    }


    fn open_database(filepath: &str, password: &str, keyfile: &Option<String>) -> Result<Database, Error> {
        if !Path::new(filepath).exists() {
            debug!("Database file '{}' does not exist, creating new database", filepath);
            return Ok(Database::new(DatabaseConfig::default()));
        }
        let (mut db_file, key) = Self::get_database_key(filepath, password, keyfile)?;
        let mut db = Database::open(&mut db_file, key)?;
        db.set_recycle_bin_enabled(false);
        Ok(db)
    }

    fn create_group(&self, parent_uuid: Uuid, group_name: &str) -> Option<Uuid> {
        self.db.create_new_group(parent_uuid, 0).map(|node| {
            node.borrow_mut().as_any_mut().downcast_mut::<Group>().map(|group| {
                group.set_title(Some(group_name));
                group.get_uuid()
            })
        }).unwrap()
    }

    fn get_database_key(filepath: &str, password: &str, keyfile: &Option<String>) -> Result<(File, DatabaseKey), DatabaseOpenError> {
        let db_file = File::open(filepath)?;
        let key = match keyfile {
            Some(kf) => {
                debug!("Using keyfile '{}' and password", kf);
                let file = &mut File::open(kf).expect("Failed to open keyfile");
                DatabaseKey::new().with_password(password).with_keyfile(file).unwrap()
            }
            None => {
                DatabaseKey::new().with_password(password)
            }
        };
        Ok((db_file, key))
    }

    fn load_credentials(&self, grep: &Option<String>) -> Vec<Credential> {
        NodeIterator::new(&self.get_root())
            .filter(node_is_entry)
            .map(Self::node_to_credential)
            .filter(|cred| {
                if let Some(grep) = &grep {
                    if !cred.username.contains(grep) && !cred.service.contains(grep) {
                        return false;
                    }
                }
                true
            }).collect()
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
        let (username, service, password, uuid) = Self::get_node_values(node);
        Credential {
            uuid,
            password: password.to_string(),
            service: service.to_string(),
            username: username.to_string(),
            notes: None,
        }
    }

    fn get_node_values(node: NodePtr) -> (String, String, String, Uuid) {
        let node = node.borrow();
        let e = node.as_any().downcast_ref::<Entry>().unwrap();
        let username = e.get_username().unwrap_or("(no username)");
        let service = e.get_url().unwrap_or("(no service)");
        let password = e.get_password().unwrap_or("(no password)");
        let uuid = e.get_uuid();
        (username.to_string(), service.to_string(), password.to_string(), uuid)
    }

    fn node_to_payment(node: NodePtr) -> PaymentCard {
        let (name, name_on_card, number, cvv, expiry, color, billing_address, id) = Self::get_node_payment_values(node).unwrap();
        PaymentCard {
            id,
            name,
            name_on_card,
            number,
            cvv,
            expiry: Expiry::from_str(&expiry).unwrap(),
            color,
            billing_address: Some(Address::from_str(&billing_address).unwrap()),
        }
    }

    fn node_to_note(node: NodePtr) -> Note {
        let (title, content, id) = Self::get_node_note_values(node).unwrap();
        Note {
            id,
            title,
            content,
        }
    }

    fn get_node_payment_values(node: NodePtr) -> Option<(String, String, String, String, String, Option<String>, String, Uuid)> {
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

        Some((name.to_string(), name_on_card, number, cvv, expiry, color, billing_address, e.get_uuid()))
    }

    fn get_node_note_values(node: NodePtr) -> Option<(String, String, Uuid)> {
        let node = node.borrow();
        let e = node.as_any().downcast_ref::<Entry>().unwrap();
        let content = e.get_notes()?;
        let title = e.get_title().unwrap_or("(no title)");

        Some((title.to_string(), content.to_string(), e.get_uuid()))
    }

    fn extract_value_from_note_opt(note: &str, line: usize, name: &str) -> Option<String> {
        let no_value = &format!("(no {name} on card)");
        note.lines().nth(line).unwrap_or(no_value).split(&format!("{name}: ")).nth(1).map(|v| String::from(v))
    }

    fn extract_value_from_note(note: &str, line: usize, name: &str) -> String {
        let no_value = String::from(&format!("(no {name} on card)"));
        String::from(Self::extract_value_from_note_opt(note, line, name).unwrap_or(no_value))
    }

    fn get_groups(&self) -> Vec<NodePtr> {
        let root = self.get_root();
        group_get_children(&root).unwrap().iter()
            .filter(|node| node_is_group(node))
            .cloned()
            .collect()
    }

    fn find_group(&self, group_name: &str) -> Option<Uuid> {
        let groups = self.get_groups();
        let group: Vec<&NodePtr> = groups.iter()
            .filter(|node| node_is_group(node))
            .filter(|node| {
                if let Some(entry) = node.borrow().as_any().downcast_ref::<Group>() {
                    entry.get_title().unwrap() == group_name
                } else {
                    false
                }
            }).collect();
        if !group.is_empty() {
            Some(group[0].borrow().get_uuid())
        } else {
            None
        }
    }

    fn create_password_entry(&mut self, parent_uuid: &Uuid, credentials: &Credential) -> keepass_ng::Result<Option<Uuid>> {
        self.db.create_new_entry(parent_uuid.clone(), 0).map(|node| {
            node.borrow_mut().as_any_mut().downcast_mut::<Entry>().map(|entry| {
                entry.set_title(Some(&credentials.service));
                entry.set_username(Some(&credentials.username));
                entry.set_password(Some(&credentials.password));
                entry.set_url(Some(&credentials.service));
                entry.get_uuid()
            })
        })
    }

    fn create_payment_entry(&mut self, parent_uuid: &Uuid, payment: &PaymentCard) -> keepass_ng::Result<Option<Uuid>> {
        self.db.create_new_entry(parent_uuid.clone(), 0).map(|node| {
            let note = format!("Name on card: {}\nNumber: {}\nCVV: {}\nExpiry: {}\nColor: {}\nBilling Address: {}",
                               payment.name_on_card,
                               payment.number,
                               payment.cvv,
                               payment.expiry_str(),
                               payment.color_str(),
                               payment.billing_address.as_ref().map(|a| a.to_string()).unwrap_or("".to_string())
            );
            node.borrow_mut().as_any_mut().downcast_mut::<Entry>().map(|entry| {
                entry.set_title(Some(&payment.name));
                entry.set_notes(Some(&note));
                entry.get_uuid()
            })
        })
    }

    fn create_note_entry(&mut self, parent_uuid: &Uuid, note: &Note) -> keepass_ng::Result<Option<Uuid>> {
        self.db.create_new_entry(parent_uuid.clone(), 0).map(|node| {
            node.borrow_mut().as_any_mut().downcast_mut::<Entry>().map(|entry| {
                entry.set_title(Some(&note.title));
                entry.set_notes(Some(&note.content));
                entry.get_uuid()
            })
        })
    }

    fn do_delete(&mut self, uuid: &Uuid, save: bool) -> i8 {
        debug!("Deleting with uuid '{}'", uuid);
        match self.db.remove_node_by_uuid(*uuid) {
            Ok(_) => {
                if save {
                    self.save_database();
                }
                1
            }
            Err(e) => {
                error!("Failed to delete: {}", e);
                0
            }
        }
    }

    fn find_or_create_group(&mut self, group_name: &str) -> Uuid {
        self.find_group(group_name).unwrap_or_else(|| {
            self.create_group(self.get_root_uuid(), group_name).unwrap()
        })
    }
}

impl PasswordVault for KeepassVault {
    fn get_master_password(&self) -> String {
        self.password.clone()
    }

    fn grep(&self, grep: &Option<String>) -> Vec<Credential> {
        self.load_credentials(grep)
    }

    fn save_credentials(&mut self, credentials: &Vec<Credential>) -> i8 {
        let group = self.find_or_create_group("Passwords");
        credentials.iter().for_each(|c| {
            self.create_password_entry(&group, c).expect("Failed to save credential");
        });
        self.save_database();
        credentials.len() as i8
    }

    fn save_one_credential(&mut self, credentials: Credential) -> i8 {
        self.save_credentials(&vec![credentials])
    }

    fn delete_credentials(&mut self, uuid: &Uuid) -> i8 {
        self.do_delete(uuid, true)
    }

    fn delete_matching(&mut self, grep: &str) -> i8 {
        let root = self.get_root();
        let matching: Vec<NodePtr> = NodeIterator::new(&root)
            .filter(node_is_entry)
            .filter(|node| {
                let node = node.borrow();
                let e = node.as_any().downcast_ref::<Entry>().unwrap();
                let username = e.get_username().unwrap_or("(no username)");
                let service = e.get_url().unwrap_or("(no service)");
                username.contains(grep) || service.contains(grep)
            }).collect();
        // delete
        let count = matching.iter().map(|node| self.do_delete(&node.borrow().get_uuid(), false)).sum();
        self.save_database();
        count
    }
}

impl PaymentVault for KeepassVault {
    fn find_payments(&self) -> Vec<PaymentCard> {
        self.load_payments()
    }

    fn save_payment(&mut self, payment: PaymentCard) -> i8 {
        let group = self.find_or_create_group("Payments");
        self.create_payment_entry(&group, &payment).expect("Failed to save payment");
        self.save_database();
        1
    }

    fn delete_payment(&mut self, id: &Uuid) -> i8 {
        self.do_delete(id, true)
    }
}

impl NoteVault for KeepassVault {
    fn find_notes(&self) -> Vec<Note> {
        self.load_notes()
    }

    fn save_note(&mut self, note: &Note) -> i8 {
        let group = self.find_or_create_group("Notes");
        self.create_note_entry(&group, &note).expect("Failed to save note");
        self.save_database();
        1
    }

    fn delete_note(&mut self, id: &Uuid) -> i8 {
        self.do_delete(id, true)
    }
}

impl Vault for KeepassVault {}