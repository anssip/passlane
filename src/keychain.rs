extern crate keyring;

use crate::password::Credentials;
use std::error::Error;

pub fn save(creds: &Credentials) -> Result<(), Box<dyn Error>> {
    let entry = keyring::Entry::new(&creds.service, &creds.username);
    entry.set_password(&creds.password)?;
    Ok(())
}
