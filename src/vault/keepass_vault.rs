use std::error::Error;
use crate::vault::entities::{Credential, Date, Note, PaymentCard};
use crate::vault::vault_trait::Vault;
use keepass::{
    db::NodeRef,
    db::Entry,
    db::Value,
    db::Node,
    Database,
    DatabaseKey,
    error::DatabaseOpenError,
};
use std::fs::{File, OpenOptions};
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
    pub fn new(password: &str, filepath: &str, keyfile_path: Option<String>) -> Result<Self, DatabaseOpenError> {
        let db = Self::open_database(filepath, password, &keyfile_path);
        match db {
            Ok(db) => {
                debug!("Opened database successfully");
                Ok(Self {
                    password: String::from(password),
                    db,
                    filepath: filepath.to_string(),
                    keyfile: keyfile_path,
                })
            }
            Err(e) => {
                error!("Failed to open database. Incorrect password or keyfile not provided? {}", e.to_string());
                Err(e)
            }
        }
    }

    pub fn save_database(&self, db: &Database) {
        let (_, key) = Self::get_database_key(&self.filepath, &self.password, &self.keyfile).unwrap();
        debug!("Saving database to file '{}'", &self.filepath);

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(false)
            .open(&self.filepath).unwrap();

        db.save(&mut file, key).unwrap();
    }


    fn open_database(filepath: &str, password: &str, keyfile: &Option<String>) -> Result<Database, DatabaseOpenError> {
        let (mut db_file, key) = Self::get_database_key(filepath, password, keyfile)?;
        Database::open(&mut db_file, key)

        // TODO: make sure we have the necessary Groups present
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

    fn load_credentials(&self, root: &Group, grep: &Option<String>) -> Vec<Credential> {
        let mut credentials = vec![];

        for node in root {
            match node {
                NodeRef::Group(g) => {
                    println!("Saw group '{0}'", g.name);
                }
                NodeRef::Entry(e) => {
                    let username = e.get_username().unwrap_or("(no username)");
                    let service = e.get_url().unwrap_or("(no service)");

                    if let Some(grep) = &grep {
                        if !username.contains(grep) && !service.contains(grep) {
                            continue;
                        }
                    }

                    let password = e.get_password().unwrap_or("(no password)");
                    let uuid = e.get_uuid();
                    credentials.push(Credential {
                        uuid: *uuid,
                        created: Date("".to_string()),
                        modified: None,
                        password: password.to_string(),
                        service: service.to_string(),
                        username: username.to_string(),
                        notes: None,
                    });
                }
            }
        }
        credentials
    }

    fn find_group(&mut self, group_name: &str) -> Option<&mut Group> {
        for node in self.db.root.children.iter_mut() {
            if let Node::Group(g) = node {
                if g.name == group_name {
                    return Some(g);
                }
            }
        }
        None
    }

    fn replace_group_entries(&mut self, mut db: &mut Database, root: &Group, group_name: &str, entries: &[Entry]) {
        let group = self.find_group(group_name).expect("Group should exist in the Keepass store");

        // remove nodes from group.children that are not in entries.
        for node in root {
            match node {
                NodeRef::Group(g) => {
                    println!("Preserving group '{0}'", g.name);
                    group.add_child(Node::Group(g.clone()));
                }
                NodeRef::Entry(e) => {
                    if entries.iter().any(|entry| entry.uuid == e.uuid) {
                        group.add_child(Node::Entry(e.clone()));
                    } else {
                        println!("Removing entry with uuid '{0}'", e.uuid);
                    }
                }
            }
            db.root.add_child(Node::Group(group.clone()));
        }
    }

    fn create_password_entry(credentials: &Credential) -> Entry {
        let mut entry = Entry::new();
        entry.fields.insert("Title".to_string(), Value::Unprotected(credentials.service.clone()));
        entry.fields.insert("UserName".to_string(), Value::Unprotected(credentials.username.clone()));
        entry.fields.insert("Password".to_string(), Value::Protected(credentials.password.as_bytes().into()));
        entry.fields.insert("URL".to_string(), Value::Unprotected(credentials.service.clone()));
        entry
    }

    // fn add_to_passwords(&self, mut db: &mut Database, mut entry: Entry) {
    //     let mut group = self.find_group("Passwords").unwrap_or_else(|| {
    //         let group = Group::new("Passwords");
    //         db.root.add_child(group.clone());
    //         group
    //     });
    //     group.add_child(Node::Entry(entry));
    //     db.root.add_child(group);
    // }

    fn delete(&mut self, match_test: Box<dyn Fn(&Entry) -> bool>, group_name: &str) {
        let mut db = self.db.clone();
        let group = self.find_group(group_name).expect(format!("{} group should exist in the Keepass store", group_name).as_str());
        for node in &db.root {
            match node {
                NodeRef::Group(g) => {
                    println!("Keeping group '{0}'", g.name);
                    group.add_child(Node::Group(g.clone()));
                }
                NodeRef::Entry(e) => {
                    if match_test(e) {
                        debug!("Removing entry with uuid '{0}'", e.uuid);
                        // delete from group.children
                        group.children.retain(|n| {
                            if let Node::Entry(entry) = n {
                                entry.uuid != e.uuid
                            } else {
                                true
                            }
                        });
                    } else {
                        debug!("Keeping entry with uuid '{0}'", e.uuid);
                        // group.add_child(Node::Entry(e.clone()));
                    }
                }
            }
        }
        db.root.add_child(Node::Group(group.clone()));
        self.save_database(&db);
    }
}

impl Vault for KeepassVault {
    fn get_master_password(&self) -> String {
        self.password.clone()
    }

    fn grep(&self, grep: &Option<String>) -> Vec<Credential> {
        let root = &self.db.root;
        self.load_credentials(root, grep)
    }

    fn find_payment_cards(&self) -> Vec<PaymentCard> {
        todo!()
    }

    fn save_credentials(&mut self, credentials: &Vec<Credential>) -> i8 {
        let mut db = self.db.clone();
        let group = self.find_group("Passwords").expect("Passwords group should exist in the Keepass store");

        for credential in credentials {
            let entry = Self::create_password_entry(credential);
            group.add_child(Node::Entry(entry));
        }
        db.root.add_child(Node::Group(group.clone()));
        self.save_database(&db);
        credentials.len() as i8
    }


    fn save_one_credential(&mut self, credentials: &Credential) -> i8 {
        let entry = Self::create_password_entry(credentials);
        let mut db = self.db.clone();
        let group = self.find_group("Passwords").expect("Passwords group should exist in the Keepass store");

        let node = Node::Entry(entry);
        group.add_child(node.clone());
        db.root.add_child(Node::Group(group.clone()));

        self.save_database(&db);
        1
    }

    fn delete_credentials(&mut self, uuid: &Uuid) -> i8 {
        // create a copy of all entries and filter out the one with
        debug!("Deleting credential with uuid '{}'", uuid);
        let uuid = *uuid;
        let match_test = Box::new(move |e: &Entry| e.uuid == uuid);
        let group_name = "Passwords";

        self.delete(match_test, group_name);
        1
    }

    fn delete_matching(&mut self, grep: &str) -> i8 {
        // create a copy of all entries and filter out the ones matching grep
        let mut db = self.db.clone();
        let mut credentials = vec![];
        for node in &self.db.root {
            if let NodeRef::Entry(e) = node {
                let username = e.get_username().unwrap_or("(no username)");
                let service = e.get_url().unwrap_or("(no service)");
                if !username.contains(grep) && !service.contains(grep) {
                    credentials.push(e.clone());
                }
            }
        }
        // self.replace_group_entries(&mut db, "Passwords", &credentials);
        self.save_database(&db);
        credentials.len() as i8
    }

    fn save_payment(&self, payment: &PaymentCard) -> i8 {
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