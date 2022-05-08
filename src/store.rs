use crate::password::Credentials;
use crate::password::{decrypt, encrypt};
use crate::ui::ask;
use csv::WriterBuilder;
use pwhash::bcrypt;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::path::Path;
use std::path::PathBuf;

fn home_dir() -> PathBuf {
    match dirs::home_dir() {
        Some(path) => path,
        None => PathBuf::from("~"),
    }
}

pub fn save(master_password: &String, creds: &Credentials) {
    let file_path = PathBuf::from(home_dir()).join(".genpass");
    println!("path {:?}", file_path);
    let exists = Path::new(&file_path).exists();
    println!("exists? {}", exists);

    let file = OpenOptions::new()
        .create_new(!exists)
        .write(true)
        .append(true)
        .open(file_path)
        .unwrap();

    let mut wtr = WriterBuilder::new().has_headers(false).from_writer(file);
    wtr.serialize(creds.encrypt(master_password))
        .expect("Unable to store credentials");
}

pub fn verify_master_password(master_pwd: &String) -> bool {
    let file_path = PathBuf::from(home_dir()).join(".genpass_pwd");
    let exists = Path::new(&file_path).exists();
    if exists {
        verify_with_saved(file_path, master_pwd)
    } else {
        save_master_password(file_path, master_pwd)
    }
}

fn save_master_password(file_path: PathBuf, master_pwd: &String) -> bool {
    let retyped = ask("Re-enter master password:");
    if master_pwd.eq(&retyped) {
        let mut file = File::create(file_path).expect("Cannot create master password file");
        let content = bcrypt::hash(master_pwd).unwrap();
        file.write_all(content.as_bytes())
            .expect("Unable write to master password file");
        true
    } else {
        false
    }
}

fn verify_with_saved(file_path: PathBuf, master_pwd: &String) -> bool {
    let mut file = File::open(file_path).expect("Cannot open master password file");
    let mut file_content = String::new();
    file.read_to_string(&mut file_content)
        .expect("Unable to read master password file");
    bcrypt::verify(master_pwd, &file_content)
}

pub fn grep(search: &String) -> Vec<String> {
    return Vec::new();
}
