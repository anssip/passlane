//! Interactive hardware-key flows: enrollment prompts, the recovery-secret
//! prompt and the backup reminder. The pure parts — `HwKeyConfig`, its
//! parsing and challenge-response key resolution — live in
//! `passlane_core::hwkey`.

use keepass_ng::ChallengeResponseKey;
use passlane_core::hwkey::{HwKeyConfig, friendly_device_error};

use crate::ui::input::{ask_password, ask_with_options};
use passlane_core::vault::entities::Error;

/// List connected hardware keys and ask which slot to enroll (unless `slot`
/// was given on the command line). Returns the key to enroll with plus the
/// config to persist once the vault has been re-saved.
pub fn resolve_new_key(
    slot: Option<u8>,
    serial: Option<u32>,
) -> Result<(ChallengeResponseKey, HwKeyConfig), Error> {
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

/// Prompt for the backed-up HMAC-SHA1 secret (hex) of the enrolled factor,
/// for recovering a vault whose hardware key or phone has been lost. For a
/// hardware key it is what `ykman otp chalresp` was programmed with (or
/// exported from); for a phone-held key it is the secret printed on the
/// recovery sheet. Whitespace and the grouping spaces of the sheet are
/// stripped: pasted secrets often carry trailing newlines too, which would
/// otherwise fail hex decoding.
pub fn recovery_key_from_prompt() -> ChallengeResponseKey {
    let secret = ask_password(
        "Enter the backed-up HMAC-SHA1 secret (hex) of the enrolled factor",
        Some(
            "A hardware key: the 40 hex characters its slot was programmed with. A phone-held \
             key: the secret printed on its recovery sheet.",
        ),
    );
    let secret = secret.chars().filter(|c| !c.is_whitespace()).collect();
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
