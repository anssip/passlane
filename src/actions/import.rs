use clap::ArgMatches;
use crate::actions::UnlockingAction;
use crate::store;
use crate::vault::entities::Error;
use crate::vault::vault_trait::Vault;

pub struct ImportCsvAction {
    pub file_path: String,
}

impl ImportCsvAction {
    pub fn new(matches: &ArgMatches) -> ImportCsvAction {
        ImportCsvAction {
            file_path: matches.get_one::<String>("FILE_PATH").expect("required").to_string(),
        }
    }
}

fn push_from_csv(vault: &mut Box<dyn Vault>, file_path: &str) -> Result<i64, Error> {
    let input = store::read_from_csv(file_path)?;
    let creds = input.into_iter().map(|c| c.to_credential()).collect();

    vault.save_credentials(&creds)?;
    let num_imported = creds.len();
    Ok(num_imported.try_into().unwrap())
}

impl UnlockingAction for ImportCsvAction {
    fn run_with_vault(&self, vault: &mut Box<dyn Vault>) -> Result<Option<String>, Error> {
        push_from_csv(vault, &self.file_path)
            .map(|count| format!("Imported {} entries", count)).map(Some)
    }
}