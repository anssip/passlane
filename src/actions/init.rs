use crate::actions::vault::setup_vault;
use crate::actions::Action;
use crate::vault::entities::Error;
use crate::vault_registry;

pub struct InitAction {}

impl Action for InitAction {
    fn run(&self) -> Result<String, Error> {
        let vaults = vault_registry::load()?;
        if !vaults.is_empty() {
            let names = vaults
                .iter()
                .map(|v| v.name.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            return Ok(format!(
                "Passlane is already initialized with vault(s): {}. Use 'passlane vault add' to register another vault.",
                names
            ));
        }
        setup_vault(None)
    }
}
