use keyring::{Entry};
use log::{debug};
use crate::vault::entities::Error;

const SERVICE_NAME: &str = "passlane_master_pwd";
const SERVICE_NAME_TOTP: &str = "passlane_totp_master_pwd";
const USERNAME: &str = "passlane";

impl From<keyring::Error> for Error {
    fn from(e: keyring::Error) -> Self {
        Error {
            message: e.to_string(),
        }
    }
}

pub fn save_master_password(pwd: &str) -> Result<(), Error> {
    let entry = Entry::new(SERVICE_NAME, USERNAME)?;
    Ok(entry.set_password(pwd)?)
}
pub fn save_totp_master_password(pwd: &str) -> Result<(), Error> {
    let entry = Entry::new(SERVICE_NAME_TOTP, USERNAME)?;
    Ok(entry.set_password(pwd)?)
}

pub fn get_master_password() -> Result<String, Error> {
    debug!("Getting master password from keychain");
    let entry = Entry::new(SERVICE_NAME, USERNAME)?;
    Ok(entry.get_password()?)
}

pub fn delete_master_password() -> Result<(), Error> {
    let entry = Entry::new(SERVICE_NAME, USERNAME)?;
    Ok(entry.delete_password()?)
}

pub(crate) fn get_totp_master_password() -> Result<String, Error> {
    let entry = Entry::new(SERVICE_NAME_TOTP, USERNAME)?;
    Ok(entry.get_password()?)
}

pub(crate) fn delete_totp_master_password() -> Result<(), Error>{
    let entry = Entry::new(SERVICE_NAME_TOTP, USERNAME)?;
    Ok(entry.delete_password()?)
}