extern crate keyring;

use crate::password::Credentials;
use keyring::Entry;
use std::error::Error;

pub fn save(creds: &Credentials) -> Result<(), Box<dyn Error>> {
    let username: &str = &creds.username;
    let service: &str = &creds.service;
    let target = format!("{} ({})", service, username);
    let entry = keyring::Entry::new_with_target(&target, &creds.service, &creds.username);
    entry.set_password(&creds.password)?;
    Ok(())
}

pub fn save_all(
    creds: &Vec<Credentials>,
    master_password: &String,
) -> Result<usize, Box<dyn Error>> {
    for c in creds {
        match save(&c.decrypt(master_password)) {
            Err(message) => println!("Failed to save {}: {}", c.service, message),
            Ok(()) => print!("."),
        }
    }
    println!("");
    Ok(creds.len())
}

pub fn delete(creds: &Credentials) -> () {
    let entry = Entry::new(&creds.service, &creds.username);
    match entry.delete_password() {
        Ok(()) => println!("(Keychain: Password for user '{}' deleted)", creds.username),
        Err(keyring::Error::NoEntry) => (),
        Err(err) => {
            eprintln!(
                "Keycain: Couldn't delete password for user '{}': {}",
                creds.username, err
            );
        }
    }
}

pub fn delete_all(credentials: &Vec<Credentials>) {
    credentials.iter().for_each(|c| delete(c));
}
