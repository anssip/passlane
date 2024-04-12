use std::error::Error;
use crate::vault::entities::{Credential, Date, Note, PaymentCard};
use crate::vault::vault_trait::Vault;
use keepass::{
    db::NodeRef,
    Database,
    DatabaseKey,
    error::DatabaseOpenError,
};
use std::fs::File;
use keepass::db::Group;
use log::{debug};

pub struct KeepassVault {
    password: String,
    db: Database,
}

impl KeepassVault {
    pub fn new(password: &str, filepath: &str, keyfile_path: Option<String>) -> Result<Self, String> {
        let db = Self::open_database(filepath, password, keyfile_path);
        match db {
            Ok(db) => {
                debug!("Opened database successfully");
                Ok(Self {
                    password: String::from(password),
                    db,
                })
            }
            Err(e) => {
                Err(format!("Failed to open database. Incorrect password or keyfile not provided? {}", e.to_string()))
            }
        }
    }

    fn open_database(filepath: &str, password: &str, keyfile: Option<String>) -> Result<Database, DatabaseOpenError> {
        let mut db_file = File::open(filepath)?;

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
        Database::open(&mut db_file, key)
    }

    fn load_credentials(root: &Group, grep: Option<String>) -> Vec<Credential> {
        let mut credentials = vec![];

        for node in root {
            match node {
                NodeRef::Group(g) => {
                    println!("Saw group '{0}'", g.name);
                    // credentials.append(&mut Self::load_credentials(g));
                }
                NodeRef::Entry(e) => {
                    // let title = e.get_title().unwrap_or("(no title)");
                    let username = e.get_username().unwrap_or("(no username)");
                    let password = e.get_password().unwrap_or("(no password)");
                    let service = e.get_url().unwrap_or("(no password)");

                    if let Some(grep) = &grep {
                        if !username.contains(grep) && !service.contains(grep) {
                            continue;
                        }
                    }

                    credentials.push(Credential {
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
}

impl Vault for KeepassVault {
    fn get_master_password(&self) -> String {
        self.password.clone()
    }

    fn grep(&self, grep: Option<String>) -> Vec<Credential> {
        let root = &self.db.root;
        Self::load_credentials(root, grep)
    }

    fn find_payment_cards(&self) -> Vec<PaymentCard> {
        todo!()
    }

    fn push_credentials(&self, credentials: &Vec<Credential>) -> Option<i32> {
        todo!()
    }

    fn push_one_credential(&self, credentials: &Credential) -> Option<i32> {
        todo!()
    }

    fn delete_credentials(&self, grep: &str, index: Option<i32>) -> Option<i32> {
        todo!()
    }

    fn save_payment(&self, payment: PaymentCard) -> Option<PaymentCard> {
        todo!()
    }

    fn delete_payment(&self, id: i32) -> Option<i32> {
        todo!()
    }

    fn delete_note(&self, id: i32) -> Option<i32> {
        todo!()
    }

    fn save_note(&self, note: &Note) -> Option<Note> {
        todo!()
    }

    fn find_notes(&self) -> Vec<Note> {
        todo!()
    }
}