use crate::vault::entities::{Credential, Date, Note, PaymentCard};
use crate::vault::vault_trait::Vault;
use keepass::{db::Entry, db::Value, db::Node, Database, DatabaseKey, error::DatabaseOpenError, group_get_children, NodeIterator, node_is_group, NodePtr, node_is_entry};
use std::fs::{File, OpenOptions};
use std::ops::Deref;
use keepass::db::Group;
use log::{debug, error};
use uuid::Uuid;

pub struct KeepassVault {
    password: String,
    db: Database,
    filepath: String,
    keyfile: Option<String>,
}

impl KeepassVault {
    pub fn new(password: &str, filepath: &str, keyfile_path: Option<String>) -> Option<Self> {
        debug!("Opening database '{}'", filepath);
        let db = Self::open_database(filepath, password, &keyfile_path);

        match db {
            Some(db) => {
                debug!("Opened database successfully");
                Some(Self {
                    password: String::from(password),
                    db,
                    filepath: filepath.to_string(),
                    keyfile: keyfile_path,
                })
            }
            None => {
                error!("Failed to open database. Incorrect password or keyfile not provided?");
                None
            }
        }
    }
    pub fn get_root(&self) -> NodePtr {
        self.db.root.clone()
    }

    pub fn save_database(&self) {
        let (_, key) = Self::get_database_key(&self.filepath, &self.password, &self.keyfile).unwrap();
        debug!("Saving database to file '{}'", &self.filepath);

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(false)
            .open(&self.filepath).unwrap();

        self.db.save(&mut file, key).unwrap();
    }


    fn open_database(filepath: &str, password: &str, keyfile: &Option<String>) -> Option<Database> {
        let (mut db_file, key) = Self::get_database_key(filepath, password, keyfile).unwrap();
        let mut db = Database::open(&mut db_file, key).unwrap();
        db.set_recycle_bin_enabled(false);
        Some(db)
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

    fn node_to_credential(node: NodePtr) -> Credential {
        let (username, service, password, uuid) = Self::get_node_values(node);
        Credential {
            uuid,
            created: Date("".to_string()), // TODO: get created date from the NodePtr
            modified: None,
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

    pub fn get_groups(&self) -> Vec<NodePtr> {
        let root = self.get_root();
        group_get_children(&root).unwrap().iter()
            .filter(|node| node_is_group(node))
            .cloned()
            .collect()
    }

    fn find_group(&mut self, group_name: &str) -> Option<Uuid> {
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

    fn create_password_entry(&mut self, parent_uuid: &Uuid, credentials: &Credential) -> keepass::Result<Option<Uuid>> {
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

    fn do_delete(&mut self, uuid: &Uuid, save: bool) -> i8 {
        debug!("Deleting credential with uuid '{}'", uuid);
        match self.db.remove_node_by_uuid(*uuid) {
            Ok(_) => {
                if save {
                    self.save_database();
                }
                1
            }
            Err(e) => {
                error!("Failed to delete credential: {}", e);
                0
            }
        }
    }
}

impl Vault for KeepassVault {
    fn get_master_password(&self) -> String {
        self.password.clone()
    }

    fn grep(&self, grep: &Option<String>) -> Vec<Credential> {
        let root = &self.db.root;
        self.load_credentials(grep)
    }

    fn save_credentials(&mut self, credentials: &Vec<Credential>) -> i8 {
        let group = match self.find_group("Passwords") {
            Some(uuid) => uuid,
            None => {
                let root_uuid = self.get_root().borrow().get_uuid();
                self.create_group(root_uuid, "Passwords").unwrap()
            }
        };
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

    fn find_payment_cards(&self) -> Vec<PaymentCard> {
        todo!()
    }

    fn save_payment(&self, payment: PaymentCard) -> i8 {
        todo!()
    }

    fn delete_payment(&self, id: &Uuid) -> i8 {
        todo!()
    }

    fn delete_note(&self, id: &Uuid) -> i8 {
        todo!()
    }

    fn save_note(&self, note: &Note) -> i8 {
        todo!()
    }

    fn find_notes(&self) -> Vec<Note> {
        todo!()
    }
}