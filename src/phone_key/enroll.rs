//! Enrolling a phone-held key: the holder creates the key and its
//! recovery sheet, then the vault is re-keyed to it.
//!
//! The order is the one the issue requires (SPEC §7):
//!
//! 1. The vault arrives open, with the factors it has today (the caller
//!    opens it through the unlock chain).
//! 2. Ask the holder to create a key for the vault (`EnrollKey`). The
//!    holder answers only once the recovery sheet has been scanned back, so
//!    this step returning *is* the scan-back confirmation the CLI waits
//!    for. Nothing has been re-keyed while it was pending. The challenge
//!    is the vault file's current KDF seed, so an enrollment that exited
//!    with the link resumes on the answer approved elsewhere.
//! 3. Re-key: save with the challenge-response factor. The save asks the
//!    holder for the new seed's answer.
//! 4. Open the saved file with that answer. This is the proof that the
//!    enrollment works — the holder's key is the one the vault now needs —
//!    and it runs before anything is persisted.
//!
//! The caller records the factor in the registry, and rolls it back
//! (see [`rollback_enrollment`]) if that fails.

use std::sync::{Arc, Mutex};

use passlane_core::vault::entities::Error;
use passlane_core::vault::keepass_vault::KeepassVault;
use zeroize::Zeroizing;

use super::{
    ANSWER_LEN, Answer, CHALLENGE_LEN, FixedAnswer, PhoneRequest, ResponseError, ResponseSource,
    fixed_key, kdf_seed, save_only_key,
};
use crate::vault_registry::VaultConfig;

/// A successful enrollment: the metadata to record. The vault itself
/// stays with the caller, who re-saves it without the factor when the
/// enrollment cannot be recorded (see [`rollback_enrollment`]).
pub(crate) struct Enrollment {
    /// Unix time the vault was re-keyed to the holder's key.
    pub enrolled_at: u64,
}

impl std::fmt::Debug for Enrollment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Enrollment")
            .field("enrolled_at", &self.enrolled_at)
            .finish()
    }
}

/// Strip a just-enrolled phone-held key again: for when the factor cannot
/// be recorded — passlane would otherwise not know to ask the holder, and
/// the vault would be unreachable through it.
pub(crate) fn rollback_enrollment(vault: &mut KeepassVault) -> Result<(), Error> {
    vault.update_challenge_response(None)
}

/// The holder's answer to the re-key, kept for the open that proves it.
struct RecordingSource {
    inner: Arc<dyn ResponseSource>,
    last_save: Mutex<Option<SaveAnswer>>,
}

/// A save's answer: the seed it was for, and the answer itself.
type SaveAnswer = ([u8; CHALLENGE_LEN], Zeroizing<Vec<u8>>);

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
/// request. The vault must be open on the factors it has today (no
/// challenge-response), and `password` is the master password it was
/// opened with — the proving open of the re-keyed file uses it again.
pub(crate) fn enroll(
    config: &VaultConfig,
    vault: &mut KeepassVault,
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

    // 2. Create the key, and wait for the recovery sheet to be scanned
    //    back. The challenge is the vault file's current KDF seed: a
    //    proof value the CLI cannot check itself (it never learns the
    //    secret — step 4 is the check) that is stable for as long as the
    //    file is. That stability is what lets an enrollment resume: run
    //    without a terminal, the command exits with the link, the owner
    //    approves elsewhere, and the re-run finds the approved answer
    //    by this same challenge. A save in between changes the seed, and
    //    with it the challenge, so a stale approval is simply not found.
    let proof = kdf_seed::read_kdf_seed(&config.path)?;
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
    vault.update_challenge_factor(Some(save_only_key(config, recording.clone())))?;

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
    match KeepassVault::open_with_challenge_factor(
        password,
        &config.path,
        config.keyfile.clone(),
        Some(&key),
    ) {
        Ok(_) => Ok(()),
        Err(e) => Err(Error::new(&format!(
            "the re-keyed vault did not open with the holder's answer: {}",
            e.message
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::phone_key::tests::{MockPhone, config_for, hmac_sha1};
    use crate::phone_key::{AnswerOrigin, open_key};
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

    /// Open the vault with `key`; the error message if it does not open.
    fn open_failure(path: &str, key: Option<&keepass_ng::ChallengeResponseKey>) -> String {
        match KeepassVault::open("master-pw", path, None, key) {
            Ok(_) => panic!("the vault opened without the right factor"),
            Err(e) => e.message,
        }
    }

    #[test]
    fn enrollment_creates_the_key_then_re_keys_and_proves_it() {
        let dir = tempfile::tempdir().unwrap();
        let (config, _) = plain_vault(dir.path());
        let seed_before = kdf_seed::read_kdf_seed(&config.path).unwrap();
        let mut vault = KeepassVault::open("master-pw", &config.path, None, None).unwrap();
        let phone = Arc::new(MockPhone::new(&SECRET));

        let enrollment = enroll(&config, &mut vault, "master-pw", phone.clone()).unwrap();
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
        // The proof challenge is the file's seed as it was; the save's is
        // the seed it wrote.
        assert_eq!(asked[0].challenge, seed_before);
        assert_eq!(
            asked[1].challenge,
            kdf_seed::read_kdf_seed(&config.path).unwrap()
        );
        assert_ne!(asked[0].challenge, asked[1].challenge);

        // The vault now needs the phone, and opens with it.
        assert!(open_failure(&config.path, None).contains("Incorrect key"));
        let key = open_key(&config, phone.clone()).unwrap();
        assert!(
            KeepassVault::open_with_challenge_factor("master-pw", &config.path, None, Some(&key))
                .is_ok()
        );
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

        let mut vault = KeepassVault::open("master-pw", &config.path, None, None).unwrap();
        let err = enroll(&config, &mut vault, "master-pw", phone.clone()).unwrap_err();
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
        let mut vault = KeepassVault::open("master-pw", &config.path, None, None).unwrap();
        let err = enroll(&config, &mut vault, "master-pw", Arc::new(refuse_save)).unwrap_err();
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
        let (config, _) = plain_vault(dir.path());
        let phone = Arc::new(MockPhone::new(&SECRET));
        let mut vault = KeepassVault::open("master-pw", &config.path, None, None).unwrap();
        enroll(&config, &mut vault, "master-pw", phone).unwrap();
        assert!(open_failure(&config.path, None).contains("Incorrect key"));

        rollback_enrollment(&mut vault).unwrap();
        let vault = KeepassVault::open("master-pw", &config.path, None, None).unwrap();
        assert!(vault.grep(None).is_empty());
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
        let mut vault = KeepassVault::open("master-pw", &config.path, None, None).unwrap();
        let err = enroll(&config, &mut vault, "master-pw", phone.clone()).unwrap_err();
        assert!(
            err.message
                .contains("already has a challenge-response factor")
        );
        assert!(phone.asked().is_empty());
    }

    #[test]
    fn an_exited_enrollment_resumes_on_the_answer_approved_elsewhere() {
        let dir = tempfile::tempdir().unwrap();
        let (config, before) = plain_vault(dir.path());
        let phone = Arc::new(MockPhone::new(&SECRET));

        // Run 1: the answer is "nowhere to be kept" — as when no session
        // agent is running — so nothing is enrolled.
        phone.refuse(ResponseError::Unavailable("no terminal, no agent".into()));
        let mut vault = KeepassVault::open("master-pw", &config.path, None, None).unwrap();
        enroll(&config, &mut vault, "master-pw", phone.clone()).unwrap_err();
        assert_eq!(std::fs::read(&config.path).unwrap(), before);
        let asked_run_1 = phone.asked();
        assert_eq!(asked_run_1.len(), 1);
        assert_eq!(asked_run_1[0].operation, Operation::EnrollKey);

        // The owner approves run 1's request from elsewhere; the agent
        // holds that answer for its challenge.
        phone.allow();
        let kept = HeldAnswers::new(&asked_run_1[0].challenge, &SECRET);

        // Run 2 finds it without asking again, then goes on to re-key.
        let answering = Resuming {
            kept,
            inner: phone.clone(),
        };
        let mut vault = KeepassVault::open("master-pw", &config.path, None, None).unwrap();
        enroll(&config, &mut vault, "master-pw", Arc::new(answering)).unwrap();
        assert_eq!(
            phone.asked()[1..]
                .iter()
                .map(|r| r.operation.clone())
                .collect::<Vec<_>>(),
            [Operation::Save],
            "run 2 asked only for the re-key"
        );
        assert!(open_failure(&config.path, None).contains("Incorrect key"));
    }

    /// What the session agent holds after `passlane approve --response`:
    /// one answer, for one challenge.
    struct HeldAnswers {
        challenge: [u8; CHALLENGE_LEN],
        answer: Zeroizing<Vec<u8>>,
    }

    impl HeldAnswers {
        fn new(challenge: &[u8; CHALLENGE_LEN], secret: &[u8]) -> Self {
            Self {
                challenge: *challenge,
                answer: Zeroizing::new(hmac_sha1(secret, challenge).to_vec()),
            }
        }
    }

    /// A source like the link transport with a session agent: an answer
    /// already held is returned without asking; anything else is asked.
    struct Resuming {
        kept: HeldAnswers,
        inner: Arc<MockPhone>,
    }

    impl ResponseSource for Resuming {
        fn respond(&self, request: &PhoneRequest) -> Result<Answer, ResponseError> {
            if request.challenge == self.kept.challenge {
                return Ok(Answer {
                    response: self.kept.answer.clone(),
                    origin: AnswerOrigin::SessionAgent,
                });
            }
            self.inner.respond(request)
        }
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
        let mut vault = KeepassVault::open("master-pw", &config.path, None, None).unwrap();
        enroll(&config, &mut vault, "master-pw", phone).unwrap();

        let secret_hex = passlane_approval::encoding::hex_encode(&SECRET);
        let as_a_yubikey_slot =
            keepass_ng::ChallengeResponseKey::LocalChallenge(secret_hex.clone());
        let vault = KeepassVault::open("master-pw", &config.path, None, Some(&as_a_yubikey_slot))
            .expect("the sheet secret opens the phone-enrolled vault");
        assert!(vault.grep(None).is_empty());

        // A different secret does not, and neither does no second factor.
        let wrong = keepass_ng::ChallengeResponseKey::LocalChallenge("00".repeat(20));
        assert!(open_failure(&config.path, Some(&wrong)).contains("Incorrect key"));
        assert!(open_failure(&config.path, None).contains("Incorrect key"));
    }
}
