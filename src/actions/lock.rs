use crate::actions::Action;
use crate::keychain;
use crate::vault::entities::Error;

pub struct LockAction {}

impl Action for LockAction {
    fn run(&self) -> Result<String, Error> {
        let credential_vault_response = match keychain::delete_master_password() {
            Ok(_) => {
                "Vault locked"
            }
            Err(_) => {
                "Vault was already locked"
            }
        };
        let totp_vault_response = match keychain::delete_totp_master_password() {
            Ok(_) => {
                "TOTP vault locked"
            }
            Err(_) => {
                "TOTP vault was already locked"
            }
        };
        Ok(format!("{}\n{}", credential_vault_response, totp_vault_response))
    }
}