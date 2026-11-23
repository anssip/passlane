//! Enrolling a phone-held key: the holder creates the key and its
//! recovery sheet, then the vault is re-keyed to it.
//!
//! The order is the one the issue requires (SPEC §7):
//!
//! 1. Open the vault with the factors it has today.
//! 2. Ask the holder to create a key for the vault (`EnrollKey`). The
//!    holder answers only once the recovery sheet has been scanned back, so
//!    this step returning *is* the scan-back confirmation the CLI waits
//!    for. Nothing has been re-keyed while it was pending.
//! 3. Re-key: save with the challenge-response factor. The save asks the
//!    holder for the new seed's answer.
//! 4. Open the saved file with that answer. This is the proof that the
//!    enrollment works — the holder's key is the one the vault now needs —
//!    and it runs before anything is persisted.
//!
//! The caller records the factor in the registry, and rolls it back
//! ([`Enrollment::rollback`]) if that fails.

use std::sync::{Arc, Mutex};

use passlane_core::vault::entities::Error;
use passlane_core::vault::keepass_vault::KeepassVault;
use zeroize::Zeroizing;

use super::{
    ANSWER_LEN, Answer, CHALLENGE_LEN, FixedAnswer, PhoneRequest, ResponseError, ResponseSource,
    fixed_key, kdf_seed, save_only_key,
};
use crate::vault_registry::VaultConfig;

/// A successful enrollment. Holds the open vault so the caller can undo
/// the re-key if the registry cannot be written.
pub(crate) struct Enrollment {
    /// Unix time the vault was re-keyed to the holder's key.
    pub enrolled_at: u64,
    /// The vault, still open. A rollback re-saves its database without the
    /// challenge-response factor.
    vault: KeepassVault,
}

impl std::fmt::Debug for Enrollment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The vault holds decrypted entries and is never printed.
        f.debug_struct("Enrollment")
            .field("enrolled_at", &self.enrolled_at)
            .finish()
    }
}

impl Enrollment {
    /// Strip the challenge-response factor again. For when the enrollment
    /// cannot be recorded: passlane would otherwise not know to ask the
    /// phone, and the vault would be unreachable through it.
    pub(crate) fn rollback(mut self) -> Result<(), Error> {
        self.vault.update_challenge_response(None)
    }
}

/// The holder's answer to the re-key, kept for the open that proves it.
struct RecordingSource {
    inner: Arc<dyn ResponseSource>,
    last_save: Mutex<Option<([u8; CHALLENGE_LEN], Zeroizing<Vec<u8>>)>>,
}

impl ResponseSource for RecordingSource {
    fn respond(&self, request: &PhoneRequest) -> Result<Answer, ResponseError> {
        let answer = self.inner.respond(request)?;
        if request.operation == passlane_approval::message::Operation::Save {
            *self.last_save.lock().unwrap() = Some((request.challenge, answer.response.clone()));
        }
        Ok(answer)
    }
}

/// Enrol `config`'s vault with the key `source`'s holder creates on
/// request. `password` must open the vault with its current factors.
pub(crate) fn enroll(
    config: &VaultConfig,
    password: &str,
    source: Arc<dyn ResponseSource>,
) -> Result<Enrollment, Error> {
    if config.hwkey.is_some() || config.phone_key.is_some() {
        return Err(Error::new(&format!(
            "Vault '{}' already has a challenge-response factor. Remove it first with \
             'passlane hwkey remove'.",
            config.name
        )));
    }

    // 1. The vault as it is today.
    let mut vault = KeepassVault::open(password, &config.path, config.keyfile.clone(), None)?;

    // 2. Create the key, and wait for the recovery sheet to be scanned
    //    back. The challenge is a proof value; the CLI cannot check the
    //    answer itself (it never learns the secret) — step 4 is the check.
    let proof = fresh_challenge()?;
    let request = PhoneRequest {
        vault_id: config.name.clone(),
        vault_name: config.name.clone(),
        operation: passlane_approval::message::Operation::EnrollKey,
        challenge: proof,
    };
    let created = source
        .respond(&request)
        .map_err(|e| Error::new(&e.to_string()))?;
    if created.response.len() != ANSWER_LEN {
        return Err(Error::new(&format!(
            "the holder returned a {}-byte answer, not {ANSWER_LEN}",
            created.response.len()
        )));
    }

    // 3. Re-key. If the save fails the vault type restores its previous
    //    factor in memory and the file on disk is untouched.
    let recording = Arc::new(RecordingSource {
        inner: source,
        last_save: Mutex::new(None),
    });
    vault.update_challenge_response(Some(save_only_key(config, recording.clone())))?;

    // 4. Prove it: open the file as it is on disk with the one answer the
    //    save obtained. Anything wrong here is undone before returning.
    let proved = prove_enrollment(config, password, &recording);
    if let Err(e) = proved {
        return match vault.update_challenge_response(None) {
            Ok(()) => Err(Error::new(&format!(
                "{} The phone-held key was not enrolled; the vault is as it was.",
                e.message
            ))),
            Err(rollback) => Err(Error::new(&format!(
                "{} Rolling the phone-held key back also failed: {}. The vault file now needs \
                 the phone-held key, but passlane does not know that yet — retry 'passlane \
                 hwkey add --phone', or recover with the recovery sheet ('passlane hwkey \
                 remove --secret').",
                e.message, rollback
            ))),
        };
    }

    Ok(Enrollment {
        enrolled_at: crate::approvals::now_secs(),
        vault,
    })
}

fn prove_enrollment(
    config: &VaultConfig,
    password: &str,
    recording: &RecordingSource,
) -> Result<(), Error> {
    let (seed, answer) = recording
        .last_save
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| Error::new("the save did not ask the holder for an answer"))?;
    let on_disk = kdf_seed::read_kdf_seed(&config.path)?;
    if on_disk != seed {
        return Err(Error::new(
            "the vault file changed while it was being re-keyed (a sync client may have \
             replaced it); the file on disk was not written by this enrollment",
        ));
    }
    let key = fixed_key(config, FixedAnswer::new(seed, answer));
    match KeepassVault::open(password, &config.path, config.keyfile.clone(), Some(&key)) {
        Ok(_) => Ok(()),
        Err(e) => Err(Error::new(&format!(
            "the re-keyed vault did not open with the holder's answer: {}",
            e.message
        ))),
    }
}

/// A fresh 32-byte proof challenge.
fn fresh_challenge() -> Result<[u8; CHALLENGE_LEN], Error> {
    use rand::RngCore;
    let mut challenge = [0u8; CHALLENGE_LEN];
    rand::rngs::OsRng
        .try_fill_bytes(&mut challenge)
        .map_err(|e| Error::new(&format!("could not generate a proof challenge: {e}")))?;
    Ok(challenge)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::phone_key::open_key;
    use crate::phone_key::tests::{MockPhone, config_for};
    use passlane_approval::message::Operation;
    use passlane_core::vault::vault_trait::PasswordVault;

    const SECRET: [u8; 20] = [0x5a; 20];

    /// A registered vault with no second factor, and its file bytes.
    fn plain_vault(dir: &std::path::Path) -> (VaultConfig, Vec<u8>) {
        let path = dir.join("vault.kdbx");
        let path = path.to_str().unwrap();
        KeepassVault::new(path, "master-pw", None, None).unwrap();
        let config = config_for(std::path::Path::new(path));
        let bytes = std::fs::read(&config.path).unwrap();
        (config, bytes)
    }

    #[test]
    fn enrollment_creates_the_key_then_re_keys_and_proves_it() {
        let dir = tempfile::tempdir().unwrap();
        let (config, before) = plain_vault(dir.path());
        let phone = Arc::new(MockPhone::new(&SECRET));

        let enrollment = enroll(&config, "master-pw", phone.clone()).unwrap();
        assert!(enrollment.enrolled_at > 0);

        // Exactly two asks: create the key (with the scan-back gating its
        // answer), then the answer to the new seed. The proof open reuses
        // that answer instead of asking a third time.
        let asked = phone.asked();
        assert_eq!(
            asked
                .iter()
                .map(|r| r.operation.clone())
                .collect::<Vec<_>>(),
            [Operation::EnrollKey, Operation::Save]
        );
        assert_ne!(asked[0].challenge, asked[1].challenge);
        assert_eq!(
            asked[1].challenge,
            kdf_seed::read_kdf_seed(&config.path).unwrap()
        );

        // The vault now needs the phone, and opens with it.
        let bytes = std::fs::read(&config.path).unwrap();
        assert_ne!(bytes, before, "the vault was re-keyed");
        assert!(KeepassVault::open("master-pw", &config.path, None, None).is_err());
        let key = open_key(&config, phone.clone()).unwrap();
        assert!(KeepassVault::open("master-pw", &config.path, None, Some(&key)).is_ok());
    }

    #[test]
    fn a_holder_that_never_confirms_the_sheet_enrolls_nothing() {
        // The holder refuses at the key-creation step — which is exactly
        // what a recovery sheet that was never scanned back amounts to.
        let dir = tempfile::tempdir().unwrap();
        let (config, before) = plain_vault(dir.path());
        let phone = Arc::new(MockPhone::new(&SECRET));
        phone.refuse(ResponseError::Unavailable(
            "the recovery sheet was not scanned back".into(),
        ));

        let err = enroll(&config, "master-pw", phone.clone()).unwrap_err();
        assert!(
            err.message
                .contains("the recovery sheet was not scanned back"),
            "{}",
            err.message
        );
        // The vault was never re-keyed: byte for byte as it was.
        assert_eq!(std::fs::read(&config.path).unwrap(), before);
        assert_eq!(phone.asked().len(), 1, "it never got as far as a save");
    }

    #[test]
    fn a_refused_re_key_leaves_the_vault_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let (config, before) = plain_vault(dir.path());
        let phone = Arc::new(MockPhone::new(&SECRET));
        // Answer the key creation, refuse the save.
        let refuse_save = RefusingSave {
            inner: phone.clone(),
        };
        let err = enroll(&config, "master-pw", Arc::new(refuse_save)).unwrap_err();
        assert!(
            err.message
                .contains("refused by the approver: not this save"),
            "{}",
            err.message
        );
        assert_eq!(std::fs::read(&config.path).unwrap(), before);
        assert!(KeepassVault::open("master-pw", &config.path, None, None).is_ok());
    }

    /// Answers everything but the re-key.
    struct RefusingSave {
        inner: Arc<MockPhone>,
    }

    impl ResponseSource for RefusingSave {
        fn respond(&self, request: &PhoneRequest) -> Result<Answer, ResponseError> {
            if request.operation == Operation::Save {
                self.inner.respond(request)?;
                return Err(ResponseError::Denied("not this save".into()));
            }
            self.inner.respond(request)
        }
    }

    #[test]
    fn rollback_strips_the_factor_again() {
        let dir = tempfile::tempdir().unwrap();
        let (config, before) = plain_vault(dir.path());
        let phone = Arc::new(MockPhone::new(&SECRET));
        let enrollment = enroll(&config, "master-pw", phone).unwrap();
        assert!(KeepassVault::open("master-pw", &config.path, None, None).is_err());

        enrollment.rollback().unwrap();
        let vault = KeepassVault::open("master-pw", &config.path, None, None).unwrap();
        assert!(vault.grep(None).is_empty());
        // Not byte-identical (a save picks fresh seeds) but factor-free.
        assert_ne!(std::fs::read(&config.path).unwrap(), before);
    }

    #[test]
    fn an_enrolled_vault_is_not_enrolled_again() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = plain_vault(dir.path()).0;
        config.phone_key = Some(crate::vault_registry::PhoneKeyConfig {
            holder_kid: "0123456789abcdef".into(),
            enrolled_at: 1,
        });
        let phone = Arc::new(MockPhone::new(&SECRET));
        let err = enroll(&config, "master-pw", phone.clone()).unwrap_err();
        assert!(
            err.message
                .contains("already has a challenge-response factor")
        );
        assert!(phone.asked().is_empty());
    }

    #[test]
    fn an_enrolled_vault_opens_with_the_secret_itself() {
        // The factor is ordinary KeePass challenge-response: a YubiKey
        // programmed with the sheet secret — here `LocalChallenge`, which
        // computes exactly what such a slot does — opens the vault the
        // phone enrolled. That is the fallback the recovery sheet buys.
        let dir = tempfile::tempdir().unwrap();
        let (config, _) = plain_vault(dir.path());
        let phone = Arc::new(MockPhone::new(&SECRET));
        enroll(&config, "master-pw", phone).unwrap();

        let secret_hex = passlane_approval::encoding::hex_encode(&SECRET);
        let as_a_yubikey_slot =
            keepass_ng::ChallengeResponseKey::LocalChallenge(secret_hex.clone());
        let vault = KeepassVault::open("master-pw", &config.path, None, Some(&as_a_yubikey_slot))
            .expect("the sheet secret opens the phone-enrolled vault");
        assert!(vault.grep(None).is_empty());

        // A different secret does not, and neither does no second factor.
        let wrong = keepass_ng::ChallengeResponseKey::LocalChallenge("00".repeat(20));
        assert!(KeepassVault::open("master-pw", &config.path, None, Some(&wrong)).is_err());
        assert!(KeepassVault::open("master-pw", &config.path, None, None).is_err());
    }
}
