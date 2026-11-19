//! Hardware-key logic that does not touch the terminal: the enrolled-key
//! configuration ([`HwKeyConfig`]) persisted per vault, and resolution of an
//! enrolled config into a challenge-response key. Interactive flows — slot
//! prompts, enrollment, recovery-secret entry — live in the CLI crate.

#[cfg(feature = "usb")]
use keepass_ng::ChallengeResponseKey;
use keepass_ng::{ChallengeResponseKeyError, DatabaseKeyError};
use serde::{Deserialize, Serialize};

use crate::vault::entities::Error;

/// Enrolled hardware-key configuration for a vault: which HMAC-SHA1
/// challenge-response slot to use, plus the serial number of the enrolled key
/// (stored only to disambiguate when several keys are connected).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HwKeyConfig {
    pub slot: u8,
    pub serial: Option<u32>,
}

impl HwKeyConfig {
    /// Parse the legacy `~/.passlane/.hwkey` content, used when migrating an
    /// existing installation to the vault registry: a `slot=` line (required,
    /// 1 or 2) and an optional `serial=` line.
    pub fn parse(content: &str) -> Result<HwKeyConfig, Error> {
        let mut slot: Option<u8> = None;
        let mut serial: Option<u32> = None;
        for line in content.lines().map(str::trim).filter(|l| !l.is_empty()) {
            let (key, value) = line.split_once('=').ok_or_else(|| {
                Error::new(&format!("invalid hardware key config line: '{}'", line))
            })?;
            match key.trim() {
                "slot" => {
                    let parsed = value.trim().parse::<u8>().map_err(|_| {
                        Error::new(&format!("invalid slot '{}': must be 1 or 2", value.trim()))
                    })?;
                    if parsed != 1 && parsed != 2 {
                        return Err(Error::new(&format!(
                            "invalid slot '{}': must be 1 or 2",
                            parsed
                        )));
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
            slot: slot
                .ok_or_else(|| Error::new("hardware key config is missing the 'slot' line"))?,
            serial,
        })
    }
}

/// Build the challenge-response key from an enrolled config, resolving the
/// connected device.
#[cfg(feature = "usb")]
pub fn configured_challenge_response_key(
    config: &HwKeyConfig,
) -> Result<ChallengeResponseKey, Error> {
    let device = ChallengeResponseKey::get_yubikey(config.serial).map_err(friendly_device_error)?;
    Ok(ChallengeResponseKey::YubikeyChallenge(
        device,
        config.slot.to_string(),
    ))
}

/// Map keepass-ng's device errors to user-facing messages. Shared by
/// [`configured_challenge_response_key`] and the CLI's enrollment flow.
pub fn friendly_device_error(e: DatabaseKeyError) -> Error {
    let message = match e {
        DatabaseKeyError::ChallengeResponse(ChallengeResponseKeyError::NoKeys) => {
            "No hardware key detected. Insert the key and try again.".to_string()
        }
        DatabaseKeyError::ChallengeResponse(ChallengeResponseKeyError::AmbiguousKeys) => {
            // Wording must fit both enrollment ('hwkey add') and unlocking:
            // either way the fix is naming the key via --serial.
            "Multiple hardware keys detected. Specify which one to use with '--serial <serial>' (see 'passlane hwkey status' for connected serials).".to_string()
        }
        DatabaseKeyError::ChallengeResponse(ChallengeResponseKeyError::KeyNotFound(serial)) => {
            format!(
                "Hardware key (serial {}) is not connected. Insert the key and try again.",
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
        assert_eq!(
            config,
            HwKeyConfig {
                slot: 2,
                serial: None
            }
        );
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
}
