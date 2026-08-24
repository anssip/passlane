use clap::ArgMatches;
use keepass_ng::ChallengeResponseKey;

use crate::actions::{get_vault_password, Action};
use crate::hwkey;
use crate::vault::entities::Error;
use crate::vault::keepass_vault::KeepassVault;
use crate::vault_registry::{self, VaultConfig};
use zeroize::Zeroize;

pub struct HwKeyAction {
    pub command: HwKeyCommand,
}

pub enum HwKeyCommand {
    Add {
        slot: Option<u8>,
        serial: Option<u32>,
    },
    Remove {
        secret: bool,
    },
    Status,
}

impl HwKeyAction {
    pub fn new(matches: &ArgMatches) -> HwKeyAction {
        match matches.subcommand() {
            Some(("add", sub)) => HwKeyAction {
                command: HwKeyCommand::Add {
                    slot: sub
                        .get_one::<String>("slot")
                        .and_then(|s| s.parse::<u8>().ok()),
                    serial: sub.get_one::<u32>("serial").copied(),
                },
            },
            Some(("remove", sub)) => HwKeyAction {
                command: HwKeyCommand::Remove {
                    secret: sub.get_one::<bool>("secret").map_or(false, |v| *v),
                },
            },
            _ => HwKeyAction {
                command: HwKeyCommand::Status,
            },
        }
    }
}

impl Action for HwKeyAction {
    fn run(&self) -> Result<String, Error> {
        match &self.command {
            HwKeyCommand::Add { slot, serial } => self.run_add(*slot, *serial),
            HwKeyCommand::Remove { secret } => self.run_remove(*secret),
            HwKeyCommand::Status => self.run_status(),
        }
    }
}

impl HwKeyAction {
    fn run_add(&self, slot: Option<u8>, serial: Option<u32>) -> Result<String, Error> {
        let config = vault_registry::current()?;
        if config.hwkey.is_some() {
            return Err(Error::new(&format!(
                "A hardware key is already enrolled for vault '{}'. Remove it first with 'passlane hwkey remove'.",
                config.name
            )));
        }
        // Fail fast if no key is connected, before asking for the password.
        let (challenge_response, hwkey_config) = hwkey::resolve_new_key(slot, serial)?;

        let mut password = get_vault_password(&config.name);
        let result = (|| {
            println!("Unlocking vault '{}'...", config.name);
            let mut vault =
                KeepassVault::open(&password, &config.path, config.keyfile.clone(), None)?;
            // The re-save challenges the new key, proving the enrollment
            // before the config is persisted.
            vault.update_challenge_response(Some(challenge_response))?;
            if let Err(e) = vault_registry::set_hwkey(&config.name, Some(hwkey_config.clone())) {
                // The vault now requires the key but passlane would not know
                // to use it (no persisted config): roll the factor back or
                // the vault can no longer be opened via passlane.
                if let Err(rollback) = vault.update_challenge_response(None) {
                    eprintln!(
                        "Warning: failed to roll back the hardware key enrollment: {}",
                        rollback
                    );
                }
                return Err(e);
            }
            Ok::<(), Error>(())
        })();
        password.zeroize();
        result?;

        hwkey::print_backup_reminder();
        Ok(format!(
            "Hardware key enrolled for vault '{}'",
            config.name
        ))
    }

    fn run_remove(&self, secret: bool) -> Result<String, Error> {
        let config = vault_registry::current()?;
        let enrolled = config.hwkey.clone().ok_or_else(|| {
            Error::new(&format!(
                "No hardware key is enrolled for vault '{}'.",
                config.name
            ))
        })?;
        let challenge_response = if secret {
            hwkey::recovery_key_from_prompt()
        } else {
            hwkey::configured_challenge_response_key(&enrolled)?
        };

        let mut password = get_vault_password(&config.name);
        let result = (|| {
            println!("Unlocking vault '{}'...", config.name);
            let mut vault = KeepassVault::open(
                &password,
                &config.path,
                config.keyfile.clone(),
                Some(&challenge_response),
            )?;
            // Delete the config before touching the vault: if deletion
            // fails, abort with the vault still protected by the key,
            // rather than stripping the factor first and leaving passlane
            // demanding a key the vault no longer requires.
            vault_registry::set_hwkey(&config.name, None)?;
            if let Err(e) = vault.update_challenge_response(None) {
                // The vault on disk still requires the key; put the config
                // back so passlane keeps using it.
                if let Err(restore_err) = vault_registry::set_hwkey(&config.name, Some(enrolled.clone())) {
                    return Err(Error::new(&format!(
                        "Removing the hardware key from the vault failed: {}. Restoring the \
                         enrollment also failed: {}. The vault still requires the hardware key — \
                         re-add slot {} (serial {:?}) to vault '{}' in {} and retry.",
                        e,
                        restore_err,
                        enrolled.slot,
                        enrolled.serial,
                        config.name,
                        vault_registry::registry_file_display(),
                    )));
                }
                return Err(e);
            }
            Ok::<(), Error>(())
        })();
        password.zeroize();
        result?;

        Ok(format!(
            "Hardware key removed from vault '{}'. It now opens with the master password (and keyfile) only.",
            config.name
        ))
    }

    fn run_status(&self) -> Result<String, Error> {
        let VaultConfig {
            name, path, hwkey, ..
        } = vault_registry::current()?;
        let mut lines = Vec::new();
        match hwkey {
            Some(config) => {
                let serial = config
                    .serial
                    .map(|s| format!(" (key serial {})", s))
                    .unwrap_or_default();
                lines.push(format!(
                    "Hardware key enrolled for vault '{}': challenge-response slot {}{}",
                    name, config.slot, serial
                ));
            }
            None => lines.push(format!("No hardware key enrolled for vault '{}'.", name)),
        }
        lines.push(format!("Vault '{}': {}", name, path));
        match ChallengeResponseKey::get_available_yubikeys() {
            Ok(keys) if keys.is_empty() => lines.push(String::from("No hardware keys detected.")),
            Ok(keys) => {
                lines.push(String::from("Connected hardware keys:"));
                for key in keys {
                    let name = key
                        .name
                        .as_deref()
                        .map(|n| format!(" ({})", n))
                        .unwrap_or_default();
                    lines.push(format!("  serial {}{}", key.serial_number, name));
                }
            }
            Err(e) => lines.push(format!("Could not list hardware keys: {}", e)),
        }
        Ok(lines.join("\n"))
    }
}
