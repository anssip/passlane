use keyring::{Entry, Result};

const SERVICE_NAME: &str = "passlane_master_pwd";
const USERNAME: &str = "passlane";

pub fn save_master_password(pwd: &str) -> Result<()> {
    let entry = Entry::new(SERVICE_NAME, USERNAME)?;
    entry.set_password(pwd)?;
    Ok(())
}

pub fn get_master_password() -> Result<String> {
    let entry = Entry::new(SERVICE_NAME, USERNAME)?;
    Ok(entry.get_password()?)
}

pub fn delete_master_password() -> Result<()> {
    let entry = Entry::new(SERVICE_NAME, USERNAME)?;
    entry.delete_password()?;
    Ok(())
}