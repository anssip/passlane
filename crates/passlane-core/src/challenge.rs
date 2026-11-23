//! Challenge-response factors of a vault's composite key, whatever answers
//! the challenge.
//!
//! A KeePass challenge-response factor adds HMAC-SHA1(challenge, secret) to
//! the composite key. [`ChallengeFactor::Virtual`] holds that secret (as
//! hex) and answers locally: the virtual keys that are the mobile path, and
//! the backed-up slot secret that recovers a vault whose hardware key is
//! lost. [`ChallengeFactor::Yubikey`] — behind the `usb` cargo feature,
//! since its backend is libusb — delegates to a connected YubiKey, at the
//! cost of a physical touch per challenge. Both map onto keepass-ng's
//! `ChallengeResponseKey`, so they protect the same vault format.

use std::fmt;

use keepass_ng::ChallengeResponseKey;
// Only the YubiKey factor resolves a device and can have an invalid slot.
#[cfg(feature = "usb")]
use keepass_ng::{ChallengeResponseKeyError, DatabaseKeyError};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "usb")]
use crate::hwkey::friendly_device_error;
use crate::vault::entities::Error;

/// An HMAC-SHA1 challenge-response secret in hex: the 20-byte key a YubiKey
/// slot holds, as `ykman otp chalresp` prints it.
const SECRET_HEX_LEN: usize = 20 * 2;

/// A challenge-response factor of a vault's composite key.
///
/// The factor answers the vault's challenges itself, so callers never see a
/// challenge or a response; [`Self::requires_touch`] is the one property
/// that changes what to tell the user. A secret never appears in the
/// [`Debug`](fmt::Debug) output and is zeroed when the factor is dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub enum ChallengeFactor {
    /// A virtual key: the HMAC-SHA1 secret as 40 hex characters, answered
    /// locally with no device and no touch. This is also how a recovery
    /// secret is used — the backed-up slot secret of a lost hardware key
    /// is the same key material. Build a new one with
    /// [`Self::from_secret_hex`], and one for a secret that already
    /// protects a vault with [`Self::from_existing_secret_hex`]. A secret
    /// that is not a 20-byte key in hex can still open a vault, but it
    /// cannot be enrolled on one.
    Virtual { secret_hex: String },
    /// A YubiKey's HMAC-SHA1 challenge-response `slot` (1 or 2). `serial`
    /// identifies the key, or is `None` for whichever single key is
    /// connected. Build it with [`Self::yubikey`].
    #[cfg(feature = "usb")]
    Yubikey { slot: u8, serial: Option<u32> },
}

impl ChallengeFactor {
    /// A new [`Self::Virtual`] key from its secret: the 20-byte HMAC-SHA1
    /// key as 40 hex characters, in either case. Whitespace is ignored,
    /// since pasted secrets carry line breaks. Anything else is rejected
    /// here, so a mistyped secret fails with a clear message instead of as
    /// a wrong-key error after the key derivation. Enrolling a virtual
    /// factor on a vault applies the same rule, however it was built.
    pub fn from_secret_hex(secret_hex: &str) -> Result<Self, Error> {
        let mut secret_hex = normalize_secret_hex(secret_hex);
        if let Err(e) = validate_secret_hex(&secret_hex) {
            secret_hex.zeroize();
            return Err(e);
        }
        Ok(Self::Virtual { secret_hex })
    }

    /// A [`Self::Virtual`] factor for a secret that already protects a
    /// vault — a backed-up slot secret used to recover one. Whitespace and
    /// case are handled as by [`Self::from_secret_hex`] and the secret must
    /// be non-empty hex, but it need not be 20 bytes: keepass-ng accepts a
    /// secret of any length, so a vault written by another tool may rely on
    /// one, and opening a vault must not be stricter than its file format.
    /// Such a factor opens a vault, but it cannot be enrolled on one.
    pub fn from_existing_secret_hex(secret_hex: &str) -> Result<Self, Error> {
        let secret_hex = normalize_secret_hex(secret_hex);
        let is_hex = secret_hex.bytes().all(|b| b.is_ascii_hexdigit());
        if !secret_hex.is_empty() && is_hex {
            Ok(Self::Virtual { secret_hex })
        } else if secret_hex.is_empty() {
            Err(Error::new(
                "The challenge-response secret must be hex, but nothing was entered.",
            ))
        } else {
            Err(Error::new(
                "The challenge-response secret must be hex, but it contains a character that \
                 is not a hex digit.",
            ))
        }
    }

    /// A connected YubiKey as the factor: its challenge-response `slot`
    /// (1 or 2), and `serial` to pick the key when several are connected
    /// (`None` accepts a single connected key). Fails with a user-facing
    /// message when the slot is invalid or the key is not connected, so
    /// callers can check before asking for the master password.
    #[cfg(feature = "usb")]
    pub fn yubikey(slot: u8, serial: Option<u32>) -> Result<Self, Error> {
        validate_slot(slot)?;
        let device = ChallengeResponseKey::get_yubikey(serial).map_err(friendly_device_error)?;
        Ok(Self::Yubikey {
            slot,
            serial: Some(device.serial_number),
        })
    }

    /// Whether answering a challenge waits for the user to touch a physical
    /// key. Only a YubiKey does. A virtual key answers instantly and
    /// silently, on every open and save.
    pub fn requires_touch(&self) -> bool {
        match self {
            Self::Virtual { .. } => false,
            #[cfg(feature = "usb")]
            Self::Yubikey { .. } => true,
        }
    }

    /// The keepass-ng key that answers the vault's challenges with this
    /// factor. For a YubiKey the connected device is resolved here, so a
    /// key that is not connected — or an invalid slot — fails before the
    /// key derivation runs. A virtual factor is taken as it is and
    /// keepass-ng checks the secret itself: opening a vault has to accept
    /// whatever the file was protected with. Whether a secret is fit to be
    /// *enrolled* is a separate question, decided by
    /// [`KeepassVault::new_with_challenge_factor`] and
    /// [`KeepassVault::update_challenge_factor`].
    ///
    /// [`KeepassVault::new_with_challenge_factor`]: crate::vault::keepass_vault::KeepassVault::new_with_challenge_factor
    /// [`KeepassVault::update_challenge_factor`]: crate::vault::keepass_vault::KeepassVault::update_challenge_factor
    pub fn challenge_response_key(&self) -> Result<ChallengeResponseKey, Error> {
        match self {
            Self::Virtual { secret_hex } => {
                Ok(ChallengeResponseKey::LocalChallenge(secret_hex.clone()))
            }
            #[cfg(feature = "usb")]
            Self::Yubikey { slot, serial } => {
                validate_slot(*slot)?;
                let device =
                    ChallengeResponseKey::get_yubikey(*serial).map_err(friendly_device_error)?;
                Ok(ChallengeResponseKey::YubikeyChallenge(
                    device,
                    slot.to_string(),
                ))
            }
        }
    }
}

impl TryFrom<&ChallengeResponseKey> for ChallengeFactor {
    type Error = Error;

    /// The factor that answers challenges the way `key` does: a
    /// `LocalChallenge` secret becomes [`ChallengeFactor::Virtual`], a
    /// YubiKey key becomes [`ChallengeFactor::Yubikey`]. A YubiKey key
    /// whose slot is not 1 or 2 is rejected, and so is a YubiKey key when
    /// this crate was built without its `usb` feature. The secret of a
    /// `LocalChallenge` key is taken as it is, so that any vault keepass-ng
    /// can open opens; whether it may be *enrolled* is checked separately.
    fn try_from(key: &ChallengeResponseKey) -> Result<Self, Error> {
        // The fallback arm is what keeps this compiling in every
        // configuration. keepass-ng's YubiKey variant exists whenever any
        // crate in the build enables its USB feature — Cargo unifies
        // features — which need not be this crate's `usb` feature. An
        // exhaustive match with a cfg-gated arm would not compile there,
        // and an `if let` on `LocalChallenge` is irrefutable without it.
        match key {
            ChallengeResponseKey::LocalChallenge(secret_hex) => Ok(Self::Virtual {
                secret_hex: secret_hex.clone(),
            }),
            #[cfg(feature = "usb")]
            ChallengeResponseKey::YubikeyChallenge(device, slot) => {
                // The same two labels keepass-ng accepts for a slot.
                if !matches!(slot.as_str(), "1" | "2") {
                    return Err(invalid_slot_error(slot));
                }
                Ok(Self::Yubikey {
                    slot: slot.parse().expect("a validated slot is 1 or 2"),
                    serial: Some(device.serial_number),
                })
            }
            // Unreachable unless keepass-ng's USB feature is on and this
            // crate's `usb` feature is off.
            #[allow(unreachable_patterns)]
            _ => Err(Error::new(
                "YubiKey challenge-response needs a build of passlane-core with its `usb` feature",
            )),
        }
    }
}

impl fmt::Debug for ChallengeFactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Virtual { secret_hex } => f
                .debug_struct("Virtual")
                .field(
                    "secret_hex",
                    &format_args!("<redacted: {} hex characters>", secret_hex.len()),
                )
                .finish(),
            #[cfg(feature = "usb")]
            Self::Yubikey { slot, serial } => f
                .debug_struct("Yubikey")
                .field("slot", slot)
                .field("serial", serial)
                .finish(),
        }
    }
}

/// Whether `factor` may be **enrolled** on a vault — the bar a new factor
/// has to clear, unlike one that merely opens a vault already requiring it.
/// A virtual key must be a real 20-byte key in hex: the variant's fields
/// are public, and keepass-ng derives the factor from any hex string, an
/// empty one included, so without this check a hand-built factor could
/// protect a vault with a zero- or few-bit secret.
pub(crate) fn validate_for_enrollment(factor: &ChallengeFactor) -> Result<(), Error> {
    match factor {
        ChallengeFactor::Virtual { secret_hex } => validate_secret_hex(secret_hex),
        #[cfg(feature = "usb")]
        ChallengeFactor::Yubikey { slot, .. } => validate_slot(*slot),
    }
}

/// A secret as entered: whitespace dropped (pasted secrets carry line
/// breaks) and lower-cased, since either case is the same key.
fn normalize_secret_hex(secret_hex: &str) -> String {
    secret_hex
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Check that `secret_hex` is a well-formed virtual key: exactly the 20-byte
/// HMAC-SHA1 secret, in hex. This is the rule for a secret that is
/// *enrolled*, applied by [`ChallengeFactor::from_secret_hex`] and by
/// [`validate_for_enrollment`]; opening a vault accepts any secret.
fn validate_secret_hex(secret_hex: &str) -> Result<(), Error> {
    let is_hex = secret_hex.bytes().all(|b| b.is_ascii_hexdigit());
    if secret_hex.len() == SECRET_HEX_LEN && is_hex {
        Ok(())
    } else {
        Err(invalid_secret_error(secret_hex.len(), is_hex))
    }
}

/// The shared rejection of a secret that is not a well-formed virtual key.
/// It describes the input by its flaws only: the input is secret material.
fn invalid_secret_error(length: usize, is_hex: bool) -> Error {
    let flaw = if !is_hex {
        "but it contains a character that is not a hex digit".to_string()
    } else {
        format!("but has {length} characters")
    };
    Error::new(&format!(
        "The challenge-response secret must be {} hex characters (a 20-byte HMAC-SHA1 \
         key), {flaw}.",
        SECRET_HEX_LEN
    ))
}

#[cfg(feature = "usb")]
fn validate_slot(slot: u8) -> Result<(), Error> {
    if matches!(slot, 1 | 2) {
        Ok(())
    } else {
        Err(invalid_slot_error(slot))
    }
}

/// The shared "must be 1 or 2" error for `slot`, however the slot was
/// spelled.
#[cfg(feature = "usb")]
fn invalid_slot_error(slot: impl fmt::Display) -> Error {
    friendly_device_error(DatabaseKeyError::ChallengeResponse(
        ChallengeResponseKeyError::InvalidSlot(slot.to_string()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "0102030405060708090a0b0c0d0e0f1011121314";

    fn virtual_factor() -> ChallengeFactor {
        ChallengeFactor::from_secret_hex(SECRET).unwrap()
    }

    fn secret_of(factor: &ChallengeFactor) -> &str {
        match factor {
            // The enum is only non_exhaustive for other crates.
            ChallengeFactor::Virtual { secret_hex } => secret_hex,
            #[cfg(feature = "usb")]
            ChallengeFactor::Yubikey { .. } => panic!("expected a virtual factor"),
        }
    }

    fn assert_invalid_secret(input: &str) -> Error {
        let err = ChallengeFactor::from_secret_hex(input).expect_err("the secret must be rejected");
        assert!(
            err.message.contains("40 hex characters"),
            "unexpected message: {}",
            err.message
        );
        // The rejected input is secret material too: never echo it (checked
        // for secret-sized inputs, so the message's own words cannot match).
        if input.len() >= 12 {
            assert!(!err.message.contains(input), "{}", err.message);
        }
        err
    }

    #[test]
    fn from_secret_hex_strips_whitespace_and_lowercases() {
        // A secret pasted from a terminal or a printed backup: upper case,
        // padded with spaces and a trailing newline.
        let pasted = format!("  {}  \n", SECRET.to_uppercase());
        let factor = ChallengeFactor::from_secret_hex(&pasted).unwrap();
        assert_eq!(secret_of(&factor), SECRET);
    }

    #[test]
    fn from_secret_hex_accepts_the_secret_verbatim() {
        assert_eq!(secret_of(&virtual_factor()), SECRET);
    }

    #[test]
    fn from_secret_hex_rejects_every_other_length() {
        for len in [0, 2, 38, 42, 80] {
            let err = assert_invalid_secret(&"ab".repeat(len / 2));
            assert!(
                err.message.contains(&format!("but has {len}")),
                "the length is reported: {}",
                err.message
            );
        }
    }

    #[test]
    fn from_secret_hex_rejects_non_hex_characters() {
        assert_invalid_secret(&SECRET.replacen("01", "0g", 1));
        assert_invalid_secret(&SECRET.replacen("01", "0z", 1));
        // Not even inside a full-length candidate.
        assert_invalid_secret(&format!("0x{}", &SECRET[..38]));
    }

    #[test]
    fn a_rejected_secret_is_reported_by_its_flaw() {
        let err = assert_invalid_secret("ab");
        assert!(
            err.message.contains("but has 2 characters"),
            "unexpected message: {}",
            err.message
        );
        let err = assert_invalid_secret(&SECRET.replacen("01", "0g", 1));
        assert!(
            err.message.contains("not a hex digit"),
            "unexpected message: {}",
            err.message
        );
    }

    #[test]
    fn from_secret_hex_rejects_a_non_ascii_lookalike() {
        // A fullwidth digit survives the case folding and must still fail.
        assert_invalid_secret(&format!("{}\u{FF11}", &SECRET[..39]));
    }

    #[test]
    fn a_virtual_factor_maps_to_a_local_challenge() {
        let key = virtual_factor().challenge_response_key().unwrap();
        assert_eq!(
            key,
            ChallengeResponseKey::LocalChallenge(SECRET.to_string())
        );
    }

    #[test]
    fn a_virtual_factor_never_requires_a_touch() {
        assert!(!virtual_factor().requires_touch());
    }

    #[test]
    fn a_local_challenge_key_converts_to_a_virtual_factor() {
        let key = ChallengeResponseKey::LocalChallenge(SECRET.to_string());
        let factor = ChallengeFactor::try_from(&key).unwrap();
        assert_eq!(secret_of(&factor), SECRET);
    }

    #[test]
    fn a_hand_built_virtual_factor_answers_with_whatever_secret_it_holds() {
        // Opening a vault must never be stricter than its file format:
        // keepass-ng derives the factor from any secret and checks the hex
        // itself, so the factor passes the secret through untouched, even
        // for a factor built by hand. Whether it may be *enrolled* is a
        // separate question (see `only_a_real_virtual_key_may_be_enrolled`).
        for secret_hex in [
            String::new(),
            "ab".to_string(),
            SECRET[..39].to_string(),
            "zz".repeat(20),
            String::from(" \n"),
        ] {
            let factor = ChallengeFactor::Virtual {
                secret_hex: secret_hex.clone(),
            };
            assert_eq!(
                factor.challenge_response_key().unwrap(),
                ChallengeResponseKey::LocalChallenge(secret_hex)
            );
        }
    }

    #[test]
    fn from_existing_secret_hex_accepts_any_non_empty_hex_secret() {
        // A 16-byte secret: nothing in passlane writes one, but a vault made
        // with another tool may be protected by it, and recovery must not
        // lock it out.
        let short = "000102030405060708090a0b0c0d0e0f";
        let factor = ChallengeFactor::from_existing_secret_hex(short).unwrap();
        assert_eq!(secret_of(&factor), short);
        // Whitespace and case are normalized, exactly as for a new key.
        let pasted = format!("  {}\n", SECRET.to_uppercase());
        let factor = ChallengeFactor::from_existing_secret_hex(&pasted).unwrap();
        assert_eq!(secret_of(&factor), SECRET);
        // A single byte is still a secret keepass-ng accepts.
        ChallengeFactor::from_existing_secret_hex("ab").unwrap();
    }

    #[test]
    fn from_existing_secret_hex_rejects_nothing_and_non_hex() {
        let err = ChallengeFactor::from_existing_secret_hex(" \n")
            .expect_err("an empty secret is no secret");
        assert!(
            err.message.contains("nothing was entered"),
            "unexpected message: {}",
            err.message
        );
        let not_hex = format!("{}z", &SECRET[..39]);
        let err = ChallengeFactor::from_existing_secret_hex(&not_hex)
            .expect_err("a non-hex secret is no secret");
        assert!(
            err.message.contains("not a hex digit"),
            "unexpected message: {}",
            err.message
        );
        // The rejected input is secret material too: never echo it.
        assert!(!err.message.contains(&not_hex[..20]), "{}", err.message);
    }

    #[test]
    fn only_a_real_virtual_key_may_be_enrolled() {
        // The enrollment bar, however the factor was built. The variant's
        // fields are public and keepass-ng derives the factor from any hex
        // string, an empty one included.
        for secret_hex in [
            String::new(),
            "ab".to_string(),
            SECRET[..39].to_string(),
            "zz".repeat(20),
        ] {
            let factor = ChallengeFactor::Virtual {
                secret_hex: secret_hex.clone(),
            };
            let err = validate_for_enrollment(&factor).expect_err("must not be enrolled");
            assert!(
                err.message.contains("40 hex characters"),
                "unexpected message: {}",
                err.message
            );
        }
        validate_for_enrollment(&virtual_factor()).unwrap();
        // A secret that already protects a vault opens it, but is not fit
        // to be enrolled.
        let existing =
            ChallengeFactor::from_existing_secret_hex("000102030405060708090a0b0c0d0e0f").unwrap();
        assert!(validate_for_enrollment(&existing).is_err());
    }

    #[test]
    fn a_hand_built_virtual_factor_in_upper_case_is_the_same_key() {
        // Either case is the same 20-byte key; the constructor merely
        // normalizes it.
        let factor = ChallengeFactor::Virtual {
            secret_hex: SECRET.to_uppercase(),
        };
        let key = factor.challenge_response_key().unwrap();
        assert_eq!(
            key,
            ChallengeResponseKey::LocalChallenge(SECRET.to_uppercase())
        );
    }

    #[test]
    fn a_legacy_local_challenge_opens_with_its_secret_as_given() {
        // keepass-ng's LocalChallenge accepts any secret. One that is not a
        // 20-byte key still opens the vault it protects — that is the file
        // format's rule, not passlane's to tighten.
        for secret_hex in ["ab", "not hex"] {
            let key = ChallengeResponseKey::LocalChallenge(secret_hex.to_string());
            let factor = ChallengeFactor::try_from(&key).unwrap();
            assert_eq!(factor.challenge_response_key().unwrap(), key);
        }
    }

    #[test]
    fn debug_output_never_shows_the_secret() {
        let factor = virtual_factor();
        let rendered = format!("{factor:?}");
        assert!(rendered.contains("Virtual"), "{}", rendered);
        assert!(rendered.contains("redacted"), "{}", rendered);
        // Neither the whole secret nor any stretch of it.
        assert!(!rendered.contains(SECRET), "{}", rendered);
        assert!(!rendered.contains(&SECRET[..6]), "{}", rendered);
        assert!(
            !rendered.contains(&SECRET[SECRET.len() - 6..]),
            "{}",
            rendered
        );
    }

    #[test]
    fn cloning_leaves_the_original_usable() {
        let factor = virtual_factor();
        let clone = factor.clone();
        assert_eq!(secret_of(&clone), SECRET);
        assert_eq!(secret_of(&factor), SECRET);
    }

    #[test]
    fn zeroizing_scrubs_the_secret_and_keeps_the_factor_a_virtual_one() {
        // ZeroizeOnDrop calls this for every factor when it is dropped.
        // The bytes are gone after `zeroize`, so assert on what remains
        // observable: the string is emptied and the variant is unchanged.
        let mut factor = virtual_factor();
        factor.zeroize();
        assert_eq!(secret_of(&factor), "");
        assert!(!factor.requires_touch());
    }

    #[test]
    fn a_dropped_factor_does_not_panic_or_leak_through_a_clone() {
        // Dropping one handle must not take the secret away from the other:
        // each clone owns its own copy.
        let factor = virtual_factor();
        let clone = factor.clone();
        drop(factor);
        assert_eq!(secret_of(&clone), SECRET);
    }

    #[cfg(feature = "usb")]
    mod yubikey {
        use super::*;

        fn yubikey_factor(slot: u8) -> ChallengeFactor {
            ChallengeFactor::Yubikey {
                slot,
                serial: Some(12345678),
            }
        }

        #[test]
        fn a_yubikey_requires_a_touch() {
            assert!(yubikey_factor(1).requires_touch());
        }

        #[test]
        fn an_invalid_slot_may_not_be_enrolled() {
            // Before any USB device is looked for, so this needs no key.
            for slot in [0u8, 3, 255] {
                let err = validate_for_enrollment(&yubikey_factor(slot))
                    .expect_err("the slot must be rejected");
                assert!(
                    err.message.contains("must be 1 or 2"),
                    "unexpected message: {}",
                    err.message
                );
            }
            validate_for_enrollment(&yubikey_factor(2)).unwrap();
        }

        #[test]
        fn an_invalid_slot_is_rejected_without_looking_for_a_key() {
            // Both ways of building the factor, so a hand-built one cannot
            // slip an invalid slot through to the USB device.
            for slot in [0u8, 3, 255] {
                let err =
                    ChallengeFactor::yubikey(slot, None).expect_err("the slot must be rejected");
                assert!(
                    err.message.contains(&format!("slot '{slot}'")),
                    "unexpected message: {}",
                    err.message
                );
                let err = yubikey_factor(slot)
                    .challenge_response_key()
                    .expect_err("the slot must be rejected");
                assert!(
                    err.message.contains("must be 1 or 2"),
                    "unexpected message: {}",
                    err.message
                );
            }
        }
    }
}
