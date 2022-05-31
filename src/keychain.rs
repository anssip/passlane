extern crate keyring;

use crate::password::Credentials;
use std::error::Error;

pub fn save(creds: &Credentials) -> Result<(), Box<dyn Error>> {
    let entry = keyring::Entry::new(&creds.service, &creds.username);
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
