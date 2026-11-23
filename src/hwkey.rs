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
/// material the lost key holds. Whitespace is stripped (pasted secrets often
/// carry trailing newlines or spaces), and anything but a 40-character hex
/// secret is rejected on the spot, before the master password is asked for.
pub fn recovery_key_from_prompt() -> Result<ChallengeFactor, Error> {
    let secret = ask_password(
        "Enter the backed-up HMAC-SHA1 secret (hex) of the enrolled slot",
        Some(
            "The 40-character hex secret saved when the key's slot was programmed, e.g. with 'ykman otp chalresp'",
        ),
    );
    ChallengeFactor::from_secret_hex(&secret)
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
