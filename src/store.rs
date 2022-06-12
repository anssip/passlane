use crate::password::Credentials;
use crate::ui::ask_password;
use csv::ReaderBuilder;
use csv::WriterBuilder;
use pwhash::bcrypt;
use regex::Regex;
use std::fs::create_dir;
use std::fs::rename;
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

fn dir_path() -> PathBuf {
    let dir_path = PathBuf::from(home_dir()).join(".passlane");
    let exists = Path::new(&dir_path).exists();
    if !exists {
        create_dir(&dir_path).expect("Unable to create .passlane dir");
    }
    dir_path
}

pub fn save(master_password: &String, creds: &Credentials) {
    let file_path = PathBuf::from(dir_path()).join(".store");
    println!("path {:?}", file_path);
    let exists = Path::new(&file_path).exists();
    println!("exists? {}", exists);

    let file = OpenOptions::new()
        .create_new(!exists)
        .write(true)
        .append(true)
        .open(file_path)
        .unwrap();

    let mut wtr = WriterBuilder::new().has_headers(!exists).from_writer(file);
    wtr.serialize(creds.encrypt(master_password))
        .expect("Unable to store credentials");
}

fn master_password_file_path() -> PathBuf {
    PathBuf::from(dir_path()).join(".master_pwd")
}

pub fn verify_master_password(master_pwd: &String, store_if_new: bool) -> Result<bool, String> {
    let file_path = master_password_file_path();
    let exists = Path::new(&file_path).exists();
    if exists {
        return verify_with_saved(file_path, master_pwd);
    }
    if store_if_new {
        let retyped = ask_password("Re-enter master password: ");
        if master_pwd.eq(&retyped) {
            save_master_password(file_path, master_pwd)
        } else {
            Err(String::from("Passwords did not match"))
        }
    } else {
        Result::Ok(true)
    }
}

fn save_master_password(file_path: PathBuf, master_pwd: &String) -> Result<bool, String> {
    let mut file = File::create(file_path).expect("Cannot create master password file");
    let content = bcrypt::hash(master_pwd).unwrap();
    file.write_all(content.as_bytes())
        .expect("Unable write to master password file");
    Result::Ok(true)
}

fn verify_with_saved(file_path: PathBuf, master_pwd: &String) -> Result<bool, String> {
    let mut file = File::open(file_path).expect("Cannot open master password file");
    let mut file_content = String::new();
    file.read_to_string(&mut file_content)
        .expect("Unable to read master password file");
    if bcrypt::verify(master_pwd, &file_content) {
        Result::Ok(true)
    } else {
        Err(String::from("Incorrect password"))
    }
}

fn open_password_file(writable: bool) -> (File, PathBuf, bool) {
    let path = PathBuf::from(dir_path()).join(".store");
    let exists = path.exists();
    let file = OpenOptions::new()
        .read(true)
        .write(writable)
        .append(writable)
        .create_new(!exists)
        .open(&path)
        .expect("Unable to open password file");
    (file, path, exists)
}

pub fn update_master_password(old_password: &String, new_password: &String) -> bool {
    let file;
    (file, ..) = open_password_file(false);
    let path = PathBuf::from(dir_path()).join(".store_new");
    let mut reader = ReaderBuilder::new().has_headers(true).from_reader(file);
    let mut wtr = csv::Writer::from_path(path).expect("Unable to open output file");

    for result in reader.deserialize() {
        let creds: Credentials = result.expect("unable to deserialize passwords CSV file");
        wtr.serialize(creds.decrypt(old_password).encrypt(new_password))
            .expect("Unable to store credentials to temp file");
    }
    save_master_password(master_password_file_path(), new_password)
        .expect("Failed to save master password");
    rename(dir_path().join(".store_new"), dir_path().join(".store"))
        .expect("Unable to rename password file");
    true
}

pub fn import_csv(file_path: &String, master_password: &String) -> Result<i64, String> {
    let path = PathBuf::from(file_path);
    let in_file = OpenOptions::new()
        .read(true)
        .open(path)
        .expect("Unable to open input file");

    let out_file;
    let exists;
    (out_file, _, exists) = open_password_file(true);
    let mut wtr = WriterBuilder::new()
        .has_headers(!exists)
        .from_writer(out_file);

    let mut reader = ReaderBuilder::new().has_headers(true).from_reader(in_file);
    let mut count = 0;
    for result in reader.deserialize() {
        let creds: Credentials = result.expect("unable to deserialize passwords CSV file");
        wtr.serialize(creds.encrypt(master_password))
            .expect("Unable to store credentials");
        count += 1;
    }
    Result::Ok(count)
}

pub fn get_all_credentials() -> Vec<Credentials> {
    let file;
    (file, ..) = open_password_file(false);
    let mut reader = ReaderBuilder::new().has_headers(true).from_reader(file);
    let mut credentials = Vec::new();
    for result in reader.deserialize() {
        credentials.push(result.unwrap())
    }
    credentials
}

pub fn grep(master_password: &String, search: &String) -> Vec<Credentials> {
    let creds = get_all_credentials();
    let mut matches = Vec::new();
    for credential in creds {
        let re = Regex::new(search).unwrap();
        if re.is_match(&credential.service) {
            matches.push(credential.decrypt(master_password));
        }
    }
    matches
}
