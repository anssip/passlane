use crate::actions::{copy_to_clipboard, Action};
use crate::crypto;
use crate::vault::entities::Error;

pub struct GeneratePasswordAction;

impl Action for GeneratePasswordAction {
    fn run(&self) -> Result<String, Error> {
        let password = crypto::generate();
        copy_to_clipboard(&password);
        Ok("Password - also copied to clipboard".to_string())
    }
}
