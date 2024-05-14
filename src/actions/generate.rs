use crate::actions::{Action, copy_to_clipboard};
use crate::crypto;
use crate::vault::entities::Error;

pub struct GeneratePasswordAction;

impl Action for GeneratePasswordAction {
    fn run(&self) -> Result<String, Error> {
        let password = crypto::generate();
        copy_to_clipboard(&password);
        Ok(format!("Password - also copied to clipboard: {}", password))
    }
}
