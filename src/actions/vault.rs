use clap::ArgMatches;
use comfy_table::presets::ASCII_MARKDOWN;
use comfy_table::Table;

use crate::actions::Action;
use crate::completion_cache;
use crate::keychain;
use crate::ui::input::{
    ask_existing_path, ask_existing_vault_uses_hwkey, ask_keyfile_path, ask_make_vault_active,
    ask_master_password, ask_new_master_password, ask_open_existing_vault, ask_remove_vault,
    ask_store_hwkey, ask_store_master_password, ask_vault_name, ask_vault_path, newline,
};
use crate::vault::entities::Error;
use crate::vault::keepass_vault::KeepassVault;
use crate::vault_registry::{self, VaultConfig};

pub struct VaultAction {
    pub command: VaultCommand,
}

pub enum VaultCommand {
    List,
    Add {
        name: Option<String>,
    },
    Use {
        name: String,
    },
    Remove {
        name: String,
    },
    Rename {
        old_name: String,
        new_name: String,
    },
    Info {
        name: Option<String>,
    },
}

impl VaultAction {
    pub fn new(matches: &ArgMatches) -> VaultAction {
        match matches.subcommand() {
            Some(("add", sub)) => VaultAction {
                command: VaultCommand::Add {
                    name: sub.get_one::<String>("NAME").cloned(),
                },
            },
            Some(("use", sub)) | Some(("switch", sub)) => VaultAction {
                command: VaultCommand::Use {
                    name: sub.get_one::<String>("NAME").cloned().unwrap_or_default(),
                },
            },
            Some(("remove", sub)) => VaultAction {
                command: VaultCommand::Remove {
                    name: sub.get_one::<String>("NAME").cloned().unwrap_or_default(),
                },
            },
            Some(("rename", sub)) => VaultAction {
                command: VaultCommand::Rename {
                    old_name: sub.get_one::<String>("OLD_NAME").cloned().unwrap_or_default(),
                    new_name: sub.get_one::<String>("NEW_NAME").cloned().unwrap_or_default(),
                },
            },
            Some(("info", sub)) => VaultAction {
                command: VaultCommand::Info {
                    name: sub.get_one::<String>("NAME").cloned(),
                },
            },
            _ => VaultAction {
                command: VaultCommand::List,
            },
        }
    }
}

impl Action for VaultAction {
    fn run(&self) -> Result<String, Error> {
        match &self.command {
            VaultCommand::List => self.list(),
            VaultCommand::Add { name } => setup_vault(name.clone()),
            VaultCommand::Use { name } => self.use_vault(name),
            VaultCommand::Remove { name } => self.remove(name),
            VaultCommand::Rename { old_name, new_name } => self.rename(old_name, new_name),
            VaultCommand::Info { name } => self.info(name.as_deref()),
        }
    }
}

impl VaultAction {
    fn list(&self) -> Result<String, Error> {
        let vaults = vault_registry::load()?;
        if vaults.is_empty() {
            return Ok("No vaults configured. Run 'passlane init' to create one.".to_string());
        }
        let active = vault_registry::get_active();
        let mut table = Table::new();
        table.load_preset(ASCII_MARKDOWN);
        table.set_header(vec![
            "Active",
            "Name",
            "Location",
            "Keyfile",
            "Hardware key",
            "State",
        ]);
        for vault in &vaults {
            table.add_row(vec![
                if active.as_deref() == Some(vault.name.as_str()) {
                    "*".to_string()
                } else {
                    String::new()
                },
                vault.name.clone(),
                vault.path.clone(),
                yes_no(vault.keyfile.is_some()),
                yes_no(vault.hwkey.is_some()),
                lock_state(&vault.name),
            ]);
        }
        Ok(table.to_string())
    }

    fn use_vault(&self, name: &str) -> Result<String, Error> {
        vault_registry::set_active(name)?;
        Ok(format!(
            "Vault '{}' is now the active vault. Unlock it with 'passlane unlock'.",
            name
        ))
    }

    fn remove(&self, name: &str) -> Result<String, Error> {
        let vaults = vault_registry::load()?;
        if vault_registry::find(&vaults, name).is_none() {
            return Err(vault_registry::unknown_vault_error(name, &vaults));
        }
        if !ask_remove_vault(name) {
            return Ok("Aborted".to_string());
        }
        let removed = vault_registry::remove_vault(name)?;
        // Lock it too: a stored master password for an unregistered vault
        // would linger in the keychain forever.
        if let Err(e) = keychain::delete_master_password_if_stored(name) {
            eprintln!(
                "Warning: could not remove the stored master password of vault '{}': {}",
                name, e
            );
        }
        completion_cache::clear_cache_for(name);
        Ok(format!(
            "Vault '{}' removed. The vault file {} was NOT deleted.",
            removed.name, removed.path
        ))
    }

    fn rename(&self, old_name: &str, new_name: &str) -> Result<String, Error> {
        // Everything that can fail must fail before any mutation happens, so
        // the keychain entry is never left filed under a name no vault has.
        vault_registry::check_rename(old_name, new_name)?;

        // Rename the registry entry first. If moving the keychain entry
        // fails afterwards, the worst case is the password staying filed
        // under the old name — the user is re-prompted once at the next
        // unlock and it gets re-stored. The reverse order could orphan it.
        let password = keychain::get_master_password(old_name).ok();
        vault_registry::rename_vault(old_name, new_name)?;
        completion_cache::clear_cache_for(old_name);

        let mut warning = String::new();
        if let Some(password) = &password {
            let result = keychain::save_master_password(new_name, password).and_then(|()| {
                keychain::delete_master_password_if_stored(old_name).map(|_| ())
            });
            if let Err(e) = result {
                eprintln!(
                    "Warning: could not move the stored master password of vault '{}' to its new name ({}). \
                     You will be asked for the password at the next unlock.",
                    new_name, e
                );
                warning = "\n(The stored master password could not be moved and will be re-requested at the next unlock.)".to_string();
            }
        }
        Ok(format!(
            "Vault '{}' renamed to '{}'{}",
            old_name, new_name, warning
        ))
    }

    fn info(&self, name: Option<&str>) -> Result<String, Error> {
        let config = match name {
            Some(name) => {
                let vaults = vault_registry::load()?;
                vault_registry::find(&vaults, name)
                    .cloned()
                    .ok_or_else(|| vault_registry::unknown_vault_error(name, &vaults))?
            }
            None => vault_registry::current()?,
        };
        let active = vault_registry::get_active();
        let lines = vec![
            format!("Name:         {}", config.name),
            format!("Location:     {}", config.path),
            format!(
                "Keyfile:      {}",
                config.keyfile.as_deref().unwrap_or("none")
            ),
            match &config.hwkey {
                Some(hwkey) => match hwkey.serial {
                    Some(serial) => {
                        format!("Hardware key: slot {} (key serial {})", hwkey.slot, serial)
                    }
                    None => format!("Hardware key: slot {}", hwkey.slot),
                },
                None => "Hardware key: none".to_string(),
            },
            format!("State:        {}", lock_state(&config.name)),
            format!(
                "Active vault: {}",
                if active.as_deref() == Some(config.name.as_str()) {
                    "yes"
                } else {
                    "no"
                }
            ),
        ];
        Ok(lines.join("\n"))
    }
}

fn vault_names(vaults: &[VaultConfig]) -> String {
    vaults
        .iter()
        .map(|v| v.name.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

fn yes_no(flag: bool) -> String {
    if flag { "yes" } else { "no" }.to_string()
}

fn lock_state(name: &str) -> String {
    if keychain::get_master_password(name).is_ok() {
        "unlocked".to_string()
    } else {
        "locked".to_string()
    }
}

/// Interactively register and set up a vault. Shared by 'passlane init'
/// (first vault) and 'passlane vault add'. Returns a summary message.
pub fn setup_vault(name_arg: Option<String>) -> Result<String, Error> {
    let existing = vault_registry::load()?;
    let name = match name_arg {
        Some(name) => {
            vault_registry::validate_name(&name)?;
            if vault_registry::find(&existing, &name).is_some() {
                return Err(Error::new(&format!(
                    "A vault named '{}' already exists. Configured vaults: {}",
                    name,
                    vault_names(&existing)
                )));
            }
            name
        }
        None => loop {
            let name = ask_vault_name();
            if let Err(e) = vault_registry::validate_name(&name) {
                println!("{}", e.message);
                continue;
            }
            if vault_registry::find(&existing, &name).is_some() {
                println!(
                    "A vault named '{}' already exists. Configured vaults: {}",
                    name,
                    vault_names(&existing)
                );
                continue;
            }
            break name;
        },
    };

    let open_existing = ask_open_existing_vault();
    let default_path = crate::store::dir_path()
        .join(format!("{}.kdbx", name))
        .to_string_lossy()
        .to_string();
    let path = if open_existing {
        ask_existing_path()
    } else {
        ask_vault_path(&default_path)
    };
    let keyfile = ask_keyfile_path(None).filter(|k| !k.is_empty());

    let password;
    let mut hwkey_config = None;
    // Set for a vault created in this run: only then may a failed registry
    // write need to strip an enrolled hardware-key factor again.
    let mut created_vault: Option<KeepassVault> = None;

    if open_existing {
        password = ask_master_password(Some(&format!(
            "Please enter master password of the vault at {}",
            path
        )));
        // The vault may already be protected by a hardware key (e.g.
        // registered on another machine): record the factor and verify all
        // unlock factors together — opening without the challenge-response
        // would fail with a misleading wrong-password error.
        let mut challenge_response = None;
        if ask_existing_vault_uses_hwkey() {
            let (cr, config) = crate::hwkey::resolve_new_key(None, None)?;
            challenge_response = Some(cr);
            hwkey_config = Some(config);
        }
        println!("Verifying that the vault opens with the given password and factors...");
        KeepassVault::open(&password, &path, keyfile.clone(), challenge_response.as_ref())?;
    } else {
        let (hwkey_key, config) = if ask_store_hwkey() {
            let (key, config) = crate::hwkey::resolve_new_key(None, None)?;
            (Some(key), Some(config))
        } else {
            (None, None)
        };
        hwkey_config = config;
        println!("Initializing new vault '{}' at {}...", name, path);
        password = ask_new_master_password();
        created_vault = Some(KeepassVault::new(
            &path,
            &password,
            keyfile.as_deref(),
            hwkey_key.as_ref(),
        )?);
    }

    if let Err(e) = vault_registry::add_vault(VaultConfig {
        name: name.clone(),
        path: path.clone(),
        keyfile: keyfile.clone(),
        hwkey: hwkey_config.clone(),
    }) {
        // When the just-created vault already demands the hardware key but
        // the enrollment could not be persisted, strip the factor again —
        // otherwise nothing would tell passlane to use the key on open and
        // the vault would be unreachable.
        if let Some(mut vault) = created_vault {
            if hwkey_config.is_some() {
                if let Err(rollback) = vault.update_challenge_response(None) {
                    eprintln!(
                        "Warning: failed to roll back the hardware key enrollment: {}",
                        rollback
                    );
                }
            }
        }
        return Err(e);
    }
    if hwkey_config.is_some() {
        crate::hwkey::print_backup_reminder();
    }

    if ask_make_vault_active(&name) {
        vault_registry::set_active(&name)?;
    }
    if ask_store_master_password() {
        keychain::save_master_password(&name, &password)?;
    }
    newline();
    Ok(format!(
        "Vault '{}' added. Use 'passlane --vault {} <command>' or 'passlane vault use {}' to work with it.",
        name, name, name
    ))
}
