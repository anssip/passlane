use clap::ArgMatches;
use keepass_ng::ChallengeResponseKey;

use crate::actions::{get_vault_password, Action};
use crate::hwkey;
use crate::store;
use crate::vault::entities::Error;
use crate::vault::keepass_vault::KeepassVault;
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
        if hwkey::load_config()?.is_some() {
            return Err(Error::new(
                "A hardware key is already enrolled. Remove it first with 'passlane hwkey remove'.",
            ));
        }
        // Fail fast if no key is connected, before asking for the password.
        let (challenge_response, config) = hwkey::resolve_new_key(slot, serial)?;

        let mut password = get_vault_password();
        let result = (|| {
            println!("Unlocking vault...");
            let mut vault = KeepassVault::open(
                &password,
                &store::get_vault_path(),
                store::get_keyfile_path(),
                None,
            )?;
            // The re-save challenges the new key, proving the enrollment
            // before the config is persisted.
            vault.update_challenge_response(Some(challenge_response))?;
            if let Err(e) = hwkey::save_config(&config) {
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
        Ok(String::from("Hardware key enrolled"))
    }

    fn run_remove(&self, secret: bool) -> Result<String, Error> {
        if hwkey::load_config()?.is_none() {
            return Err(Error::new("No hardware key is enrolled."));
        }
        let challenge_response = if secret {
            hwkey::recovery_key_from_prompt()
        } else {
            hwkey::configured_challenge_response_key()?
                .ok_or_else(|| Error::new("No hardware key is enrolled."))?
        };

        let mut password = get_vault_password();
        let result = (|| {
            println!("Unlocking vault...");
            let mut vault = KeepassVault::open(
                &password,
                &store::get_vault_path(),
                store::get_keyfile_path(),
                Some(&challenge_response),
            )?;
            vault.update_challenge_response(None)?;
            hwkey::clear_config();
            Ok::<(), Error>(())
        })();
        password.zeroize();
        result?;

        Ok(String::from(
            "Hardware key removed. The vault now opens with the master password (and keyfile) only.",
        ))
    }

    fn run_status(&self) -> Result<String, Error> {
        let mut lines = Vec::new();
        match hwkey::load_config()? {
            Some(config) => {
                let serial = config
                    .serial
                    .map(|s| format!(" (key serial {})", s))
                    .unwrap_or_default();
                lines.push(format!(
                    "Hardware key enrolled: challenge-response slot {}{}",
                    config.slot, serial
                ));
            }
            None => lines.push(String::from("No hardware key enrolled for the main vault.")),
        }
        lines.push(format!("Vault: {}", store::get_vault_path()));
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
