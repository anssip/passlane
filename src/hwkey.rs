//! Interactive hardware-key flows: enrollment prompts, the recovery-secret
//! prompt and the backup reminder. The pure parts — `HwKeyConfig`, its
//! parsing, the challenge-response factor and the device-error messages —
//! live in `passlane_core` (`hwkey` and `challenge`).

use keepass_ng::ChallengeResponseKey;
use passlane_core::challenge::ChallengeFactor;
use passlane_core::hwkey::{HwKeyConfig, friendly_device_error};

use crate::ui::input::{ask_password, ask_with_options};
use passlane_core::vault::entities::Error;

/// List connected hardware keys and ask which slot to enroll (unless `slot`
/// was given on the command line). Returns the factor to enroll the vault
/// with plus the config to persist once the vault has been re-saved.
pub fn resolve_new_key(
    slot: Option<u8>,
    serial: Option<u32>,
) -> Result<(ChallengeFactor, HwKeyConfig), Error> {
    let device = ChallengeResponseKey::get_yubikey(serial).map_err(friendly_device_error)?;
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
        ChallengeFactor::Yubikey {
            slot: config.slot,
            serial: config.serial,
        },
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
/// `ykman otp chalresp` was programmed with (or exported from). It becomes
/// the virtual challenge factor, which answers challenges with the same key
/// material the lost key holds. See [`recovery_factor`] for what is accepted.
pub fn recovery_key_from_prompt() -> Result<ChallengeFactor, Error> {
    let secret = ask_password(
        "Enter the backed-up HMAC-SHA1 secret (hex) of the enrolled slot",
        Some(
            "The 40-character hex secret saved when the key's slot was programmed, e.g. with 'ykman otp chalresp'",
        ),
    );
    let (factor, note) = recovery_factor(&secret)?;
    if let Some(note) = note {
        println!("{note}");
    }
    Ok(factor)
}

/// The recovery factor for a secret as entered, plus a note to show when
/// the secret is unusual. A hardware key's secret is 40 hex characters, in
/// either case, and whitespace is ignored since pasted secrets carry line
/// breaks. A secret of another length is still used, with a note: usually
/// it is a typo, which the vault then rejects — but a vault protected by
/// another tool may have a secret of another length, and recovery must not
/// lock it out. A secret that is not hex at all is rejected here, before
/// the master password is asked for.
fn recovery_factor(secret: &str) -> Result<(ChallengeFactor, Option<String>), Error> {
    match ChallengeFactor::from_secret_hex(secret) {
        Ok(factor) => Ok((factor, None)),
        Err(not_a_key) => match ChallengeFactor::from_existing_secret_hex(secret) {
            Ok(factor) => {
                let note = match &factor {
                    ChallengeFactor::Virtual { secret_hex } => Some(format!(
                        "Note: the secret has {} characters, not the 40 of a hardware key's slot \
                         secret. It is used anyway: a vault protected by another tool may have a \
                         secret of another length.",
                        secret_hex.len()
                    )),
                    // Cannot happen today; keeps working if it ever could.
                    _ => None,
                };
                Ok((factor, note))
            }
            // Not usable at all: report why, precisely.
            Err(_) => Err(not_a_key),
        },
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "0102030405060708090a0b0c0d0e0f1011121314";

    fn answers_with(factor: &ChallengeFactor) -> keepass_ng::ChallengeResponseKey {
        factor.challenge_response_key().unwrap()
    }

    #[test]
    fn a_slot_secret_recovers_without_a_note() {
        // Pasted, with a trailing newline.
        let (factor, note) = recovery_factor(&format!(" {SECRET}\n")).unwrap();
        assert!(note.is_none());
        assert_eq!(
            answers_with(&factor),
            keepass_ng::ChallengeResponseKey::LocalChallenge(SECRET.to_string())
        );
    }

    #[test]
    fn a_secret_of_another_length_is_used_with_a_note() {
        // A vault protected by another tool with a 16-byte secret must stay
        // recoverable; the user is told what is unusual about the secret.
        let short = "000102030405060708090a0b0c0d0e0f";
        let (factor, note) = recovery_factor(short).unwrap();
        let note = note.expect("the unusual length is reported");
        assert!(note.contains("32 characters"), "{note}");
        assert_eq!(
            answers_with(&factor),
            keepass_ng::ChallengeResponseKey::LocalChallenge(short.to_string())
        );
    }

    #[test]
    fn a_typo_in_the_length_gets_the_same_note() {
        // Nothing tells a typo apart from such a vault, so both are used
        // and the vault decides: a typo fails there.
        let (_, note) = recovery_factor(&SECRET[..39]).unwrap();
        let note = note.expect("the unusual length is reported");
        assert!(note.contains("39 characters"), "{note}");
    }

    #[test]
    fn a_secret_that_is_not_hex_is_rejected_at_once() {
        let err = recovery_factor(" \n").unwrap_err();
        assert!(
            err.message.contains("has 0 characters"),
            "unexpected message: {}",
            err.message
        );
        let err = recovery_factor(&SECRET.replacen("01", "0z", 1)).unwrap_err();
        assert!(
            err.message.contains("not a hex digit"),
            "unexpected message: {}",
            err.message
        );
    }
}
