//! Hardware-key logic that does not touch the terminal: the enrolled-key
//! configuration ([`HwKeyConfig`]) persisted per vault, and the user-facing
//! messages for keys that are missing or ambiguous. The factor that answers
//! a vault's challenges is [`crate::challenge::ChallengeFactor`], which an
//! enrolled config resolves into. Interactive flows — slot prompts,
//! enrollment, recovery-secret entry — live in the CLI crate.

#[cfg(feature = "usb")]
use keepass_ng::ChallengeResponseKey;
use keepass_ng::{ChallengeResponseKeyError, DatabaseKeyError};
use serde::{Deserialize, Serialize};

#[cfg(feature = "usb")]
use crate::challenge::ChallengeFactor;
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
/// connected device. This is the keepass-ng key form of
/// `ChallengeFactor::yubikey(config.slot, config.serial)`, for callers
/// that want to hand keepass-ng's own key type to the vault.
#[cfg(feature = "usb")]
pub fn configured_challenge_response_key(
    config: &HwKeyConfig,
) -> Result<ChallengeResponseKey, Error> {
    ChallengeFactor::yubikey(config.slot, config.serial)?.challenge_response_key()
}

/// Map keepass-ng's device errors to user-facing messages. Shared by
/// [`crate::challenge::ChallengeFactor`] and the CLI's enrollment flow.
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

    fn device_message(e: ChallengeResponseKeyError) -> String {
        friendly_device_error(DatabaseKeyError::ChallengeResponse(e)).message
    }

    #[test]
    fn missing_and_ambiguous_keys_get_actionable_messages() {
        assert_eq!(
            device_message(ChallengeResponseKeyError::NoKeys),
            "No hardware key detected. Insert the key and try again."
        );
        assert_eq!(
            device_message(ChallengeResponseKeyError::KeyNotFound(42)),
            "Hardware key (serial 42) is not connected. Insert the key and try again."
        );
        let ambiguous = device_message(ChallengeResponseKeyError::AmbiguousKeys);
        assert!(
            ambiguous.contains("'--serial <serial>'"),
            "the fix must be named: {}",
            ambiguous
        );
    }

    #[test]
    fn an_invalid_slot_names_the_slot_and_the_valid_ones() {
        assert_eq!(
            device_message(ChallengeResponseKeyError::InvalidSlot("7".to_string())),
            "Invalid hardware key slot '7': must be 1 or 2"
        );
    }

    #[test]
    fn other_key_errors_keep_their_own_message() {
        let message = device_message(ChallengeResponseKeyError::NotPerformed);
        assert_eq!(message, ChallengeResponseKeyError::NotPerformed.to_string());
    }

    #[cfg(feature = "usb")]
    #[test]
    fn an_enrolled_config_with_an_invalid_slot_is_rejected_up_front() {
        // Before any USB device is looked for, so this needs no key.
        let err = configured_challenge_response_key(&HwKeyConfig {
            slot: 7,
            serial: Some(1),
        })
        .expect_err("the slot must be rejected");
        assert_eq!(err.message, "Invalid hardware key slot '7': must be 1 or 2");
    }
}
