use crate::auth::AccessTokens;
use crate::password::Credentials;
use anyhow;
use anyhow::bail;
use chrono::Duration;
use csv::ReaderBuilder;
use log::debug;
use pwhash::bcrypt;
use std::fs::create_dir;
use std::fs::rename;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;

fn home_dir() -> PathBuf {
    match dirs::home_dir() {
        Some(path) => path,
        None => PathBuf::from("~"),
    }
}

fn dir_path() -> PathBuf {
    let dir_path = PathBuf::from(home_dir()).join(".passlane_dev");
    let exists = Path::new(&dir_path).exists();
    if !exists {
        create_dir(&dir_path).expect("Unable to create .passlane dir");
    }
    dir_path
}

fn access_token_path() -> PathBuf {
    let path = dir_path();
    let path = path.join(".access_token");
    path
}

fn master_password_file_path() -> PathBuf {
    PathBuf::from(dir_path()).join(".master_pwd")
}

pub fn save_master_password(master_pwd: &str) {
    let file_path = master_password_file_path();
    let mut file = File::create(file_path).expect("Cannot create master password file");
    let content = bcrypt::hash(master_pwd).unwrap();
    file.write_all(content.as_bytes())
        .expect("Unable write to master password file");
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

pub fn update_master_password(old_password: &str, new_password: &str) -> bool {
    let file;
    (file, ..) = open_password_file(false);
    let mut reader = ReaderBuilder::new().has_headers(true).from_reader(file);
    let path = PathBuf::from(dir_path()).join(".store_new");
    let mut wtr = csv::Writer::from_path(path).expect("Unable to open output file");

    for result in reader.deserialize() {
        let creds: Credentials = result.expect("unable to deserialize passwords CSV file");
        wtr.serialize(creds.decrypt(old_password).encrypt(new_password))
            .expect("Unable to store credentials to temp file");
    }
    save_master_password(new_password);
    rename(dir_path().join(".store_new"), dir_path().join(".store"))
        .expect("Unable to rename password file");
    true
}

pub fn read_from_csv(file_path: &str) -> anyhow::Result<Vec<Credentials>> {
    let path = PathBuf::from(file_path);
    let in_file = OpenOptions::new().read(true).open(path)?;
    let mut reader = ReaderBuilder::new().has_headers(true).from_reader(in_file);
    let credentials = &mut Vec::new();
    for result in reader.deserialize() {
        credentials.push(result?);
    }
    Ok(credentials.clone())
}

pub fn store_access_token(token: &AccessTokens) -> anyhow::Result<bool> {
    let path = access_token_path();

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .append(false)
        .create_new(!path.exists())
        .open(&path)
        .expect("Unable to open access token file");

    debug!("storing token with timestamp {}", token.created_timestamp);
    let empty = String::from("");
    let contents = format!(
        "{},{},{},{},",
        token.access_token,
        if let Some(value) = &token.refresh_token {
            value
        } else {
            &empty
        },
        if let Some(duration) = token.expires_in {
            duration.num_seconds()
        } else {
            0
        },
        token.created_timestamp
    );
    file.write_all(contents.as_bytes())?;
    Ok(true)
}

pub fn has_logged_in() -> bool {
    access_token_path().exists()
}

pub fn get_access_token() -> anyhow::Result<AccessTokens> {
    let path = access_token_path();
    if !path.exists() {
        bail!("Please login first with: passlane -l");
    }
    let mut file = OpenOptions::new()
        .read(true)
        .write(false)
        .create_new(false)
        .open(&path)?;

    let mut file_content = String::new();
    file.read_to_string(&mut file_content)?;

    let parts: Vec<&str> = file_content.split(",").collect();
    let expires = i64::from_str(parts[2])?;
    debug!("created_timestamp: {}", parts[3]);
    Ok(AccessTokens {
        access_token: String::from(parts[0]),
        refresh_token: if parts[1] != "" {
            Some(String::from(parts[1]))
        } else {
            None
        },
        expires_in: if expires > 0 {
            Some(Duration::seconds(expires))
        } else {
            None
        },
        created_timestamp: parts[3].into(),
    })
}
