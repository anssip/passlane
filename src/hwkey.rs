use keepass_ng::{ChallengeResponseKey, ChallengeResponseKeyError, DatabaseKeyError};

use crate::store;
use crate::ui::input::{ask_password, ask_with_options};
use crate::vault::entities::Error;

/// Enrolled hardware-key configuration for the main vault: which HMAC-SHA1
/// challenge-response slot to use, plus the serial number of the enrolled key
/// (stored only to disambiguate when several keys are connected).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HwKeyConfig {
    pub slot: u8,
    pub serial: Option<u32>,
}

impl HwKeyConfig {
    /// Parse the `~/.passlane/.hwkey` content: a `slot=` line (required, 1 or
    /// 2) and an optional `serial=` line.
    pub fn parse(content: &str) -> Result<HwKeyConfig, Error> {
        let mut slot: Option<u8> = None;
        let mut serial: Option<u32> = None;
        for line in content.lines().map(str::trim).filter(|l| !l.is_empty()) {
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| Error::new(&format!("invalid hardware key config line: '{}'", line)))?;
            match key.trim() {
                "slot" => {
                    let parsed = value
                        .trim()
                        .parse::<u8>()
                        .map_err(|_| Error::new(&format!("invalid slot '{}': must be 1 or 2", value.trim())))?;
                    if parsed != 1 && parsed != 2 {
                        return Err(Error::new(&format!("invalid slot '{}': must be 1 or 2", parsed)));
                    }
                    slot = Some(parsed);
                }
                "serial" => {
                    serial = Some(value.trim().parse::<u32>().map_err(|_| {
                        Error::new(&format!("invalid serial number '{}'", value.trim()))
                    })?);
                }
                other => {
                    return Err(Error::new(&format!(
                        "unknown key '{}' in hardware key config",
                        other
                    )));
                }
            }
        }
        Ok(HwKeyConfig {
            slot: slot.ok_or_else(|| Error::new("hardware key config is missing the 'slot' line"))?,
            serial,
        })
    }

    fn to_file_content(&self) -> String {
        match self.serial {
            Some(serial) => format!("slot={}\nserial={}", self.slot, serial),
            None => format!("slot={}", self.slot),
        }
    }
}

/// Load the enrolled config. `Ok(None)` when no hardware key is enrolled.
pub fn load_config() -> Result<Option<HwKeyConfig>, Error> {
    match store::read_hwkey_config() {
        None => Ok(None),
        Some(content) => Ok(Some(HwKeyConfig::parse(&content)?)),
    }
}

pub fn save_config(config: &HwKeyConfig) -> Result<(), Error> {
    store::save_hwkey_config(&config.to_file_content())
}

pub fn clear_config() {
    store::clear_hwkey_config();
}

/// Build the challenge-response key from the stored config, resolving the
/// connected device. `Ok(None)` when no hardware key is enrolled.
pub fn configured_challenge_response_key() -> Result<Option<ChallengeResponseKey>, Error> {
    let Some(config) = load_config()? else {
        return Ok(None);
    };
    let device =
        ChallengeResponseKey::get_yubikey(config.serial).map_err(friendly_device_error)?;
    Ok(Some(ChallengeResponseKey::YubikeyChallenge(
        device,
        config.slot.to_string(),
    )))
}

/// List connected hardware keys and ask which slot to enroll (unless `slot`
/// was given on the command line). Returns the key to enroll with plus the
/// config to persist once the vault has been re-saved.
pub fn resolve_new_key(slot: Option<u8>, serial: Option<u32>) -> Result<(ChallengeResponseKey, HwKeyConfig), Error> {
    let device =
        ChallengeResponseKey::get_yubikey(serial).map_err(friendly_device_error)?;
    let config = HwKeyConfig {
        slot: match slot {
            Some(s) => s,
            None => ask_slot()?,
        },
        serial: Some(device.serial_number),
    };
    println!(
        "Enrolling hardware key with serial {} (slot {})",
        device.serial_number, config.slot
    );
    Ok((
        ChallengeResponseKey::YubikeyChallenge(device, config.slot.to_string()),
        config,
    ))
}

fn ask_slot() -> Result<u8, Error> {
    let answer = ask_with_options(
        "Which challenge-response slot does the key use?",
        vec!["1", "2"],
    );
    answer
        .parse::<u8>()
        .map_err(|_| Error::new("slot must be 1 or 2"))
}

/// Prompt for the backed-up HMAC-SHA1 secret (hex) of an enrolled slot, for
/// recovering a vault whose hardware key has been lost. The secret is what
/// `ykman otp chalresp` was programmed with (or exported from).
pub fn recovery_key_from_prompt() -> ChallengeResponseKey {
    let secret = ask_password(
        "Enter the backed-up HMAC-SHA1 secret (hex) of the enrolled slot",
        Some("The 40-character hex secret saved when the key's slot was programmed, e.g. with 'ykman otp chalresp'"),
    );
    ChallengeResponseKey::LocalChallenge(secret)
}

/// Warn that without the hardware key or a backup of the slot secret, an
/// enrolled vault cannot be opened.
pub fn print_backup_reminder() {
    println!(
        "Make sure you have a backup of the slot's HMAC-SHA1 secret (e.g. printed when \
         programming the slot with 'ykman otp chalresp'). Without the key or the secret \
         the vault cannot be opened; the secret can be used to recover with \
         'passlane hwkey remove --secret'."
    );
}

fn friendly_device_error(e: DatabaseKeyError) -> Error {
    let message = match e {
        DatabaseKeyError::ChallengeResponse(ChallengeResponseKeyError::NoKeys) => {
            "No hardware key detected. Insert the key and try again.".to_string()
        }
        DatabaseKeyError::ChallengeResponse(ChallengeResponseKeyError::AmbiguousKeys) => {
            "Multiple hardware keys detected. Re-enroll with 'passlane hwkey add --serial <serial>' to pick one.".to_string()
        }
        DatabaseKeyError::ChallengeResponse(ChallengeResponseKeyError::KeyNotFound(serial)) => {
            format!(
                "The enrolled hardware key (serial {}) is not connected. Insert the key and try again.",
                serial
            )
        }
        DatabaseKeyError::ChallengeResponse(ChallengeResponseKeyError::InvalidSlot(slot)) => {
            format!("Invalid hardware key slot '{}': must be 1 or 2", slot)
        }
        DatabaseKeyError::ChallengeResponse(ChallengeResponseKeyError::Hex(_)) => {
            "The recovery secret is not valid hex (expected 40 hex characters).".to_string()
        }
        other => format!("{}", other),
    };
    Error::new(&message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_slot_only() {
        let config = HwKeyConfig::parse("slot=2").unwrap();
        assert_eq!(config, HwKeyConfig { slot: 2, serial: None });
    }

    #[test]
    fn parse_slot_and_serial() {
        let config = HwKeyConfig::parse("slot=1\nserial=12345678\n").unwrap();
        assert_eq!(
            config,
            HwKeyConfig {
                slot: 1,
                serial: Some(12345678)
            }
        );
    }

    #[test]
    fn parse_rejects_invalid_slot() {
        assert!(HwKeyConfig::parse("slot=3").is_err());
        assert!(HwKeyConfig::parse("slot=x").is_err());
    }

    #[test]
    fn parse_rejects_missing_slot() {
        assert!(HwKeyConfig::parse("serial=1").is_err());
        assert!(HwKeyConfig::parse("").is_err());
    }

    #[test]
    fn parse_rejects_unknown_keys() {
        assert!(HwKeyConfig::parse("slot=1\nfoo=bar").is_err());
    }

    #[test]
    fn file_content_roundtrip() {
        let config = HwKeyConfig {
            slot: 2,
            serial: Some(42),
        };
        let parsed = HwKeyConfig::parse(&config.to_file_content()).unwrap();
        assert_eq!(config, parsed);
    }
}
