//! The phone-held key (passlane#53, SPEC §7): a vault whose
//! challenge-response secret lives on another device.
//!
//! The vault factor is exactly KeePass's HMAC-SHA1 challenge-response —
//! the same one a YubiKey slot or `ChallengeResponseKey::LocalChallenge`
//! provides — with custody elsewhere. This machine never holds the secret.
//! keepass-ng asks for each answer through the
//! `ChallengeResponseKey::External` responder built here, which obtains a
//! 20-byte answer over the active transport (the link transport today) and
//! returns it:
//!
//! ```text
//! keepass-ng          this module                       the holder
//! -----------          -----------                       ----------
//! open:  seed ───────▶ PhoneResponder ── Unlock{seed} ─▶ approve
//!                      ◀──────── 20-byte answer ────────
//!        ◀── answer
//! save:  new seed ───▶ PhoneResponder ── Save{seed} ──▶ approve
//!                      ◀──────── 20-byte answer ────────
//!        ◀── answer
//! ```
//!
//! The answer is a vault unlock factor. It lives in zeroized memory and is
//! never written anywhere: the CLI proves the vault opens, and drops it. A
//! save always needs a fresh answer, because the KDF seed rotates each
//! time — which is also what makes an old answer useless after a save.

pub(crate) mod enroll;
pub(crate) mod kdf_seed;
pub(crate) mod transport;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use keepass_ng::ChallengeResponseKeyError;
use passlane_approval::message::Operation;
use passlane_core::challenge::ChallengeFactor;
use passlane_core::vault::entities::Error;
use zeroize::Zeroizing;

use crate::vault_registry::VaultConfig;

/// The HMAC-SHA1 answer a phone-held key gives: 20 bytes.
pub(crate) const ANSWER_LEN: usize = passlane_approval::message::CHALLENGE_RESPONSE_LEN;
/// The challenge a phone-held key answers: the 32-byte KDF seed.
pub(crate) const CHALLENGE_LEN: usize = passlane_approval::message::CHALLENGE_LEN;

/// What the CLI asks the holder of a vault's key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PhoneRequest {
    /// Registry id of the vault — the holder keys its secrets by it.
    pub vault_id: String,
    /// Display name of the vault.
    pub vault_name: String,
    /// What the answer is for.
    pub operation: Operation,
    /// The 32-byte challenge: the file's KDF seed for `Unlock`, the new
    /// seed for `Save`, a proof value for `EnrollKey`.
    pub challenge: [u8; CHALLENGE_LEN],
}

impl PhoneRequest {
    /// The challenge as lower-case hex, the form the pending store and the
    /// session agent key answers by.
    pub(crate) fn challenge_hex(&self) -> String {
        passlane_approval::encoding::hex_encode(&self.challenge)
    }

    /// One line for a person: what is being asked, for which vault.
    pub(crate) fn describe(&self) -> String {
        match self.operation {
            Operation::Unlock => format!("opening vault '{}'", self.vault_name),
            Operation::Save => format!("saving vault '{}'", self.vault_name),
            Operation::EnrollKey => {
                format!("creating a phone-held key for vault '{}'", self.vault_name)
            }
            Operation::Reveal { .. } => format!("vault '{}'", self.vault_name),
        }
    }
}

/// Why there is no answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ResponseError {
    /// The holder, or the person at the terminal, refused.
    Denied(String),
    /// Nothing could ask or answer here: no holder is pinned, there is no
    /// terminal to prompt at and no session agent to wait on, the request
    /// expired, ...
    Unavailable(String),
}

impl std::fmt::Display for ResponseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Denied(reason) => write!(f, "refused by the approver: {reason}"),
            Self::Unavailable(reason) => write!(f, "{reason}"),
        }
    }
}

/// How an answer reached this process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AnswerOrigin {
    /// A live session-agent session held it (`unlock --session`, or
    /// `passlane approve --response` run from elsewhere).
    SessionAgent,
    /// The link transport, answered in this process: a QR, a link, and a
    /// response pasted at the terminal.
    LinkTransport,
}

/// An answer, and how it got here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Answer {
    pub response: Zeroizing<Vec<u8>>,
    pub origin: AnswerOrigin,
}

/// How answers reach this process. The real one is the link transport
/// ([`transport::LinkTransport`]); tests supply a mocked phone.
pub(crate) trait ResponseSource: Send + Sync {
    /// The holder's 20-byte answer to `request`.
    fn respond(&self, request: &PhoneRequest) -> Result<Answer, ResponseError>;
}

/// A source that already knows the answer to one challenge: the CLI opens
/// the vault it has just re-keyed with the answer that re-keyed it, to
/// prove the enrollment, without asking again.
pub(crate) struct FixedAnswer {
    challenge: [u8; CHALLENGE_LEN],
    answer: Zeroizing<Vec<u8>>,
}

impl FixedAnswer {
    pub(crate) fn new(challenge: [u8; CHALLENGE_LEN], answer: Zeroizing<Vec<u8>>) -> Self {
        Self { challenge, answer }
    }
}

impl ResponseSource for FixedAnswer {
    fn respond(&self, request: &PhoneRequest) -> Result<Answer, ResponseError> {
        if request.operation == Operation::Unlock && request.challenge == self.challenge {
            Ok(Answer {
                response: self.answer.clone(),
                origin: AnswerOrigin::LinkTransport,
            })
        } else {
            Err(ResponseError::Unavailable(format!(
                "this answer is for one challenge only, not {}",
                request.describe()
            )))
        }
    }
}

// The answer that opened the current vault on this thread, if a
// phone-held key was used to open one. keepass-ng calls the responder on
// the thread that opens the vault, which is the thread the command runs
// on — so the answer is scoped to that command, not to the process.
// Written by the responder, read once by `unlock --session` so it can
// hand the answer to the session agent.
thread_local! {
    static LAST_OPEN_ANSWER: std::cell::RefCell<Option<(PhoneRequest, Answer)>> =
        const { std::cell::RefCell::new(None) };
}

/// Take the answer that last opened a phone-gated vault on this thread.
pub(crate) fn take_last_open_answer() -> Option<(PhoneRequest, Answer)> {
    LAST_OPEN_ANSWER.with(|slot| slot.borrow_mut().take())
}

/// The challenge-response key for opening `config`'s vault with its
/// phone-held key, and for saving it afterwards.
///
/// The vault's KDF seed is read here, before keepass-ng opens the file, so
/// a request can be emitted while the vault is still locked. keepass-ng's
/// first challenge must then be that same seed; a different one means the
/// file changed underneath the request (a sync client replaced it), and
/// an answer to the old seed would be silently wrong.
/// The vault's holder-side identity: the uid assigned at enrollment if
/// there is one, else the registry name. This is what a request body's
/// `vault_id` carries and the approver keys its held key under — stable
/// across 'passlane vault rename', which changes the name but must not
/// orphan the holder's key.
pub(crate) fn vault_identity(config: &VaultConfig) -> String {
    config
        .phone_key
        .as_ref()
        .and_then(|key| key.vault_uid.clone())
        .unwrap_or_else(|| config.name.clone())
}

pub(crate) fn open_key(
    config: &VaultConfig,
    source: Arc<dyn ResponseSource>,
) -> Result<ChallengeFactor, Error> {
    let seed = kdf_seed::read_kdf_seed(&config.path)?;
    Ok(responder_key(
        &vault_identity(config),
        &config.name,
        source,
        Opening::ExpectSeed(seed),
    ))
}

/// The challenge-response key for a vault that is already open and is
/// about to be re-keyed (enrollment): every challenge is a new seed.
pub(crate) fn save_only_key(
    vault_id: &str,
    vault_name: &str,
    source: Arc<dyn ResponseSource>,
) -> ChallengeFactor {
    responder_key(vault_id, vault_name, source, Opening::AlreadyOpen)
}

/// A session-held answer, wrapped for the unlock chain: it answers the
/// challenge it was approved for (the file's current seed) and hands
/// every other challenge — the fresh seed a save issues — to the link
/// transport, so a save after a session-backed open still asks the
/// holder instead of failing on a stale answer.
pub(crate) struct HeldAnswer {
    seed: [u8; CHALLENGE_LEN],
    answer: Zeroizing<Vec<u8>>,
    transport: Arc<dyn ResponseSource>,
}

// HeldAnswer is constructed where its pieces come together
// (`held_answer_key`); no `new` needed.

impl ResponseSource for HeldAnswer {
    fn respond(&self, request: &PhoneRequest) -> Result<Answer, ResponseError> {
        if request.challenge == self.seed {
            return Ok(Answer {
                response: self.answer.clone(),
                origin: AnswerOrigin::SessionAgent,
            });
        }
        self.transport.respond(request)
    }
}

/// The phone-held key of a vault as the link transport: answers come from
/// the pinned holder — pasted at this terminal, or held by the session
/// agent after the owner approved from elsewhere. Building the key asks
/// nothing; it resolves the holder and the vault's challenge here, and
/// answers (or refuses with guidance) only when keepass-ng issues the
/// challenge.
pub(crate) fn transport_key(config: &VaultConfig) -> Result<ChallengeFactor, Error> {
    let source = transport_source(config)?;
    open_key(config, source)
}

/// The vault's link transport as a response source: the one place the
/// holder, the approvals state and the agent's held answers come
/// together.
pub(crate) fn transport_source(config: &VaultConfig) -> Result<Arc<dyn ResponseSource>, Error> {
    let dir = crate::approvals::state_dir();
    let holder = crate::phone_key::transport::holder_pin(
        &dir,
        &config
            .phone_key
            .as_ref()
            .expect("transport_source is for a phone-gated vault")
            .holder_kid,
    )?;
    Ok(Arc::new(crate::phone_key::transport::LinkTransport::new(
        &dir,
        holder,
        crate::agent::requester(),
        Arc::new(crate::session_agent::AgentAnswerStore),
    )))
}

/// The challenge-response key for opening a vault with a session-held
/// answer: the answer serves its own challenge, and every other
/// challenge — the fresh seed a save issues — goes to the transport, so a
/// session-backed open still asks the holder before saving.
pub(crate) fn held_answer_key(
    config: &VaultConfig,
    seed: [u8; CHALLENGE_LEN],
    answer: Zeroizing<Vec<u8>>,
) -> ChallengeFactor {
    responder_key(
        &vault_identity(config),
        &config.name,
        Arc::new(HeldAnswer {
            seed,
            answer,
            transport: Arc::new(LazyTransport {
                config: config.clone(),
            }),
        }),
        Opening::ExpectSeed(seed),
    )
}

/// The link transport, resolved when a challenge first needs it: a
/// session-backed open must not fail because the holder is not pinned
/// (or the approvals state cannot be read) — only the *next save* needs
/// the holder, and that is where the refusal belongs.
struct LazyTransport {
    config: VaultConfig,
}

impl ResponseSource for LazyTransport {
    fn respond(&self, request: &PhoneRequest) -> Result<Answer, ResponseError> {
        let transport =
            transport_source(&self.config).map_err(|e| ResponseError::Unavailable(e.message))?;
        transport.respond(request)
    }
}

/// The challenge-response key for opening a vault with one known answer.
pub(crate) fn fixed_key(config: &VaultConfig, fixed: FixedAnswer) -> ChallengeFactor {
    let challenge = fixed.challenge;
    responder_key(
        &vault_identity(config),
        &config.name,
        Arc::new(fixed),
        Opening::ExpectSeed(challenge),
    )
}

/// Whether the vault's first challenge should be a known seed.
enum Opening {
    ExpectSeed([u8; CHALLENGE_LEN]),
    AlreadyOpen,
}

fn responder_key(
    vault_id: &str,
    vault_name: &str,
    source: Arc<dyn ResponseSource>,
    opening: Opening,
) -> ChallengeFactor {
    let responder = PhoneResponder {
        vault_id: vault_id.to_string(),
        vault_name: vault_name.to_string(),
        source,
        opening,
        opened: AtomicBool::new(false),
    };
    ChallengeFactor::External {
        responder: Arc::new(move |seed| responder.respond(seed)),
    }
}

struct PhoneResponder {
    /// The holder-side identity the request body carries.
    vault_id: String,
    /// The registry name, for display on the approval screen.
    vault_name: String,
    source: Arc<dyn ResponseSource>,
    opening: Opening,
    /// Set once the opening challenge has been answered.
    opened: AtomicBool,
}

impl PhoneResponder {
    fn respond(&self, seed: &[u8]) -> Result<Vec<u8>, ChallengeResponseKeyError> {
        let challenge: [u8; CHALLENGE_LEN] = seed.try_into().map_err(|_| {
            ChallengeResponseKeyError::External(format!(
                "the vault's challenge is {} bytes, not {CHALLENGE_LEN}",
                seed.len()
            ))
        })?;

        // keepass-ng challenges the key once to open, then once per save.
        // The opening challenge is the seed read before the file was
        // opened; anything else is a save's fresh seed.
        let opening = match &self.opening {
            Opening::AlreadyOpen => false,
            Opening::ExpectSeed(expected) => {
                if !self.opened.swap(true, Ordering::SeqCst) {
                    if *expected != challenge {
                        return Err(ChallengeResponseKeyError::External(
                            "the vault file changed while its challenge response was being \
                             obtained (a sync client may have replaced it); nothing was \
                             opened — re-run the command"
                                .into(),
                        ));
                    }
                    true
                } else {
                    false
                }
            }
        };

        let request = PhoneRequest {
            vault_id: self.vault_id.clone(),
            vault_name: self.vault_name.clone(),
            operation: if opening {
                Operation::Unlock
            } else {
                Operation::Save
            },
            challenge,
        };
        let answer = self
            .source
            .respond(&request)
            .map_err(|e| ChallengeResponseKeyError::External(e.to_string()))?;
        if answer.response.len() != ANSWER_LEN {
            return Err(ChallengeResponseKeyError::External(format!(
                "the approver returned a {}-byte answer, not {ANSWER_LEN}",
                answer.response.len()
            )));
        }
        if opening {
            // The latest open wins: one command may open a vault more than
            // once (the REPL), and what matters is the file as it is now.
            LAST_OPEN_ANSWER.with(|slot| *slot.borrow_mut() = Some((request, answer.clone())));
        }
        Ok(answer.response.to_vec())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use passlane_core::vault::entities::Credential;
    use passlane_core::vault::keepass_vault::KeepassVault;
    use passlane_core::vault::vault_trait::PasswordVault;
    use std::sync::Mutex;

    /// A mocked phone: holds a 20-byte secret only it knows and answers
    /// every challenge the way keepass-ng's `LocalChallenge` would — the
    /// same HMAC-SHA1 a YubiKey slot computes. It records what it was asked.
    pub(crate) struct MockPhone {
        secret: Zeroizing<Vec<u8>>,
        asked: Mutex<Vec<PhoneRequest>>,
        origin: AnswerOrigin,
        refusal: Mutex<Option<ResponseError>>,
    }

    impl MockPhone {
        pub(crate) fn new(secret: &[u8]) -> Self {
            Self {
                secret: Zeroizing::new(secret.to_vec()),
                asked: Mutex::new(Vec::new()),
                origin: AnswerOrigin::LinkTransport,
                refusal: Mutex::new(None),
            }
        }

        pub(crate) fn with_origin(mut self, origin: AnswerOrigin) -> Self {
            self.origin = origin;
            self
        }

        pub(crate) fn refuse(&self, error: ResponseError) {
            *self.refusal.lock().unwrap() = Some(error);
        }

        /// Answer normally again after [`Self::refuse`].
        pub(crate) fn allow(&self) {
            *self.refusal.lock().unwrap() = None;
        }

        pub(crate) fn asked(&self) -> Vec<PhoneRequest> {
            self.asked.lock().unwrap().clone()
        }

        /// A point in the request log, to look only at what a later step
        /// asks (`asked_since`).
        pub(crate) fn mark(&self) -> usize {
            self.asked.lock().unwrap().len()
        }

        /// What was asked after `mark`.
        pub(crate) fn asked_since(&self, mark: usize) -> Vec<PhoneRequest> {
            self.asked.lock().unwrap()[mark..].to_vec()
        }
    }

    impl ResponseSource for MockPhone {
        fn respond(&self, request: &PhoneRequest) -> Result<Answer, ResponseError> {
            self.asked.lock().unwrap().push(request.clone());
            if let Some(error) = self.refusal.lock().unwrap().clone() {
                return Err(error);
            }
            Ok(Answer {
                response: Zeroizing::new(hmac_sha1(&self.secret, &request.challenge).to_vec()),
                origin: self.origin,
            })
        }
    }

    /// HMAC-SHA1, as keepass-ng's `LocalChallenge` computes a response.
    /// The shared construction lives in the protocol crate now
    /// (`answer_challenge`, exposed to the iOS app through the FFI);
    /// this helper keeps its test-only call sites and their fixed valid
    /// shapes.
    pub(crate) fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; ANSWER_LEN] {
        passlane_approval::message::answer_challenge(key, message)
            .expect("phone-key tests use 20-byte secrets and 32-byte challenges")
    }

    /// The registry entry for the vault *file* at `path`, with no second
    /// factor recorded.
    pub(crate) fn config_for(path: &std::path::Path) -> VaultConfig {
        assert!(
            !path.is_dir(),
            "config_for takes the vault file, not its directory: {path:?}"
        );
        VaultConfig {
            name: "work".to_string(),
            path: path.to_str().unwrap().to_string(),
            keyfile: None,
            hwkey: None,
            phone_key: None,
        }
    }

    fn operations(phone: &MockPhone) -> Vec<Operation> {
        phone
            .asked()
            .into_iter()
            .map(|r| r.operation.clone())
            .collect()
    }

    const SECRET: [u8; 20] = [0xa1; 20];

    /// Open the vault with `key`; the error message if it does not open.
    fn open_failure(path: &str, key: Option<&ChallengeFactor>) -> String {
        match KeepassVault::open_with_challenge_factor("master-pw", path, None, key) {
            Ok(_) => panic!("the vault opened without the right factor"),
            Err(e) => e.message,
        }
    }

    /// Save an entry through the vault's public API: every save asks the
    /// phone for a fresh answer.
    fn add_entry(vault: &mut KeepassVault) -> Result<(), Error> {
        vault.save_one_credential(Credential::new(None, "pw", "Example", "user", None, None))
    }

    #[test]
    fn the_request_identity_is_the_assigned_id_and_survives_a_rename() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        KeepassVault::new(path.to_str().unwrap(), "pw", None, None).unwrap();

        // No phone key: the name, as ever.
        let mut config = config_for(&path);
        assert_eq!(vault_identity(&config), "work");

        // Enrolled: the assigned id — and still it after the registry's
        // name changes, which is the whole point of the field.
        config.phone_key = Some(crate::vault_registry::PhoneKeyConfig {
            holder_kid: "0123456789abcdef".to_string(),
            vault_uid: Some("a1b2c3d4e5f60718293a4b5c6d7e8f90".to_string()),
            enrolled_at: 1,
        });
        assert_eq!(vault_identity(&config), "a1b2c3d4e5f60718293a4b5c6d7e8f90");
        config.name = "renamed".to_string();
        assert_eq!(
            vault_identity(&config),
            "a1b2c3d4e5f60718293a4b5c6d7e8f90",
            "a rename does not change what the holder is asked by"
        );

        // A pre-field enrollment (no uid recorded): the name remains the
        // identity, exactly as when it was enrolled.
        config.phone_key.as_mut().unwrap().vault_uid = None;
        assert_eq!(vault_identity(&config), "renamed");
    }

    #[test]
    fn vault_enrolled_by_phone_answers_opens_and_saves() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("vault.kdbx");
        let vault_path = vault_path.to_str().unwrap();
        KeepassVault::new(vault_path, "master-pw", None, None).unwrap();
        let config = config_for(std::path::Path::new(vault_path));
        let phone = Arc::new(MockPhone::new(&SECRET));

        // -- re-key: the save asks the phone for the new seed's answer --
        let mut vault = KeepassVault::open("master-pw", vault_path, None, None).unwrap();
        vault
            .update_challenge_factor(Some(save_only_key("work", "work", phone.clone())))
            .unwrap();
        drop(vault);
        assert_eq!(operations(&phone), [Operation::Save]);

        // -- open: without the factor the key is wrong; with it, it opens --
        assert!(open_failure(vault_path, None).contains("Incorrect key"));
        let key = open_key(&config, phone.clone()).unwrap();
        let mut vault =
            KeepassVault::open_with_challenge_factor("master-pw", vault_path, None, Some(&key))
                .unwrap();
        assert_eq!(
            operations(&phone),
            [Operation::Save, Operation::Unlock],
            "the open asks once, for the file's seed"
        );

        // -- a save needs a second, fresh answer --
        let before = kdf_seed::read_kdf_seed(vault_path).unwrap();
        add_entry(&mut vault).unwrap();
        drop(vault);
        let after = kdf_seed::read_kdf_seed(vault_path).unwrap();
        assert_ne!(before, after, "the seed rotated");
        assert_eq!(
            operations(&phone),
            [Operation::Save, Operation::Unlock, Operation::Save]
        );
        assert_eq!(
            phone.asked()[2].challenge,
            after,
            "the save asked for the seed it wrote"
        );
        assert_eq!(phone.asked()[1].challenge, before);

        // -- and the saved file opens again, by phone --
        let key = open_key(&config, phone.clone()).unwrap();
        let vault =
            KeepassVault::open_with_challenge_factor("master-pw", vault_path, None, Some(&key))
                .unwrap();
        assert_eq!(vault.grep(None).len(), 1, "the saved entry is there");
    }

    #[test]
    fn only_the_phone_with_the_secret_opens_the_vault() {
        // A lost phone is exactly this: the holder is gone, and no other
        // holder's answer fits.
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("vault.kdbx");
        let vault_path = vault_path.to_str().unwrap();
        let config = config_for(&dir.path().join("vault.kdbx"));
        let phone = Arc::new(MockPhone::new(&SECRET));
        let mut vault = KeepassVault::new(vault_path, "master-pw", None, None).unwrap();
        vault
            .update_challenge_factor(Some(save_only_key("work", "work", phone)))
            .unwrap();
        drop(vault);

        let other_phone = Arc::new(MockPhone::new(&[0xb2; 20]));
        let key = open_key(&config, other_phone.clone()).unwrap();
        let err = open_failure(vault_path, Some(&key));
        assert!(err.contains("Incorrect key"), "{}", err);
        assert_eq!(
            other_phone.asked().len(),
            1,
            "it was asked, and answered wrongly"
        );

        let right_phone = Arc::new(MockPhone::new(&SECRET));
        let key = open_key(&config, right_phone).unwrap();
        assert!(
            KeepassVault::open_with_challenge_factor("master-pw", vault_path, None, Some(&key))
                .is_ok()
        );
    }

    #[test]
    fn a_refusal_is_reported_with_its_reason_and_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("vault.kdbx");
        let vault_path = vault_path.to_str().unwrap();
        let config = config_for(&dir.path().join("vault.kdbx"));
        let phone = Arc::new(MockPhone::new(&SECRET));
        let mut vault = KeepassVault::new(vault_path, "master-pw", None, None).unwrap();
        vault
            .update_challenge_factor(Some(save_only_key("work", "work", phone.clone())))
            .unwrap();
        drop(vault);

        phone.refuse(ResponseError::Denied("not from this device".into()));
        let key = open_key(&config, phone.clone()).unwrap();
        let err = open_failure(vault_path, Some(&key));
        assert!(
            err.contains("refused by the approver: not from this device"),
            "{}",
            err
        );

        // A refused save leaves the file as it was.
        let mut vault = {
            *phone.refusal.lock().unwrap() = None;
            let key = open_key(&config, phone.clone()).unwrap();
            KeepassVault::open_with_challenge_factor("master-pw", vault_path, None, Some(&key))
                .unwrap()
        };
        let before = std::fs::read(vault_path).unwrap();
        phone.refuse(ResponseError::Unavailable("nobody can answer".into()));
        let err = add_entry(&mut vault).unwrap_err();
        assert!(err.message.contains("nobody can answer"), "{}", err.message);
        assert_eq!(std::fs::read(vault_path).unwrap(), before);
    }

    #[test]
    fn a_file_replaced_while_waiting_is_not_opened_with_the_old_answer() {
        // The seed is read before keepass-ng opens the file. If a sync
        // client swaps the file in between, keepass-ng challenges with the
        // new file's seed; answering that with an answer meant for the
        // old one would just be "Incorrect key" — or worse, a `Save`
        // request for a file the user never unlocked.
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("vault.kdbx");
        let vault_path = vault_path.to_str().unwrap();
        let config = config_for(&dir.path().join("vault.kdbx"));
        let phone = Arc::new(MockPhone::new(&SECRET));
        let mut vault = KeepassVault::new(vault_path, "master-pw", None, None).unwrap();
        vault
            .update_challenge_factor(Some(save_only_key("work", "work", phone.clone())))
            .unwrap();
        drop(vault);

        let key = open_key(&config, phone.clone()).unwrap();
        let other = dir.path().join("other.kdbx");
        KeepassVault::new_with_challenge_factor(
            other.to_str().unwrap(),
            "master-pw",
            None,
            Some(&save_only_key("work", "work", phone.clone())),
        )
        .unwrap();
        std::fs::copy(&other, vault_path).unwrap();

        // The key was built for the old file's seed; keepass-ng now
        // challenges with the new one. Nothing may go out for that:
        // answering it with an answer meant for the old file is the trap.
        let asked_before = phone.asked().len();
        let err = open_failure(vault_path, Some(&key));
        assert!(err.contains("the vault file changed"), "{}", err);
        assert_eq!(
            phone.asked().len(),
            asked_before,
            "nobody is asked to unlock a file that changed"
        );
    }

    #[test]
    fn answers_of_the_wrong_length_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("vault.kdbx");
        let vault_path = vault_path.to_str().unwrap();
        KeepassVault::new(vault_path, "master-pw", None, None).unwrap();
        let config = config_for(&dir.path().join("vault.kdbx"));
        let short = Arc::new(FixedAnswer::new(
            kdf_seed::read_kdf_seed(vault_path).unwrap(),
            Zeroizing::new(vec![1, 2, 3]),
        ));
        let key = open_key(&config, short).unwrap();
        let err = open_failure(vault_path, Some(&key));
        assert!(err.contains("3-byte answer, not 20"), "{}", err);
    }

    #[test]
    fn the_opening_answer_is_recorded_for_unlock_session() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("vault.kdbx");
        let vault_path = vault_path.to_str().unwrap();
        let config = config_for(&dir.path().join("vault.kdbx"));
        let phone = Arc::new(MockPhone::new(&SECRET).with_origin(AnswerOrigin::SessionAgent));
        let mut vault = KeepassVault::new(vault_path, "master-pw", None, None).unwrap();
        vault
            .update_challenge_factor(Some(save_only_key("work", "work", phone.clone())))
            .unwrap();
        drop(vault);

        assert!(take_last_open_answer().is_none());
        let seed = kdf_seed::read_kdf_seed(vault_path).unwrap();
        let key = open_key(&config, phone).unwrap();
        drop(
            KeepassVault::open_with_challenge_factor("master-pw", vault_path, None, Some(&key))
                .unwrap(),
        );

        let (request, answer) = take_last_open_answer().expect("the open is recorded");
        assert_eq!(request.operation, Operation::Unlock);
        assert_eq!(request.challenge, seed);
        assert_eq!(answer.origin, AnswerOrigin::SessionAgent);
        assert_eq!(answer.response.as_slice(), hmac_sha1(&SECRET, &seed));
        // Taken, not copied: a second command in this process finds nothing.
        assert!(take_last_open_answer().is_none());
    }

    #[test]
    fn fixed_answer_answers_only_its_own_challenge() {
        let fixed = FixedAnswer::new([7u8; CHALLENGE_LEN], Zeroizing::new(vec![9u8; ANSWER_LEN]));
        let request = |operation: Operation, challenge: [u8; CHALLENGE_LEN]| PhoneRequest {
            vault_id: "work".into(),
            vault_name: "work".into(),
            operation,
            challenge,
        };
        assert!(
            fixed
                .respond(&request(Operation::Unlock, [7u8; 32]))
                .is_ok()
        );
        assert!(
            fixed
                .respond(&request(Operation::Unlock, [8u8; 32]))
                .is_err()
        );
        assert!(fixed.respond(&request(Operation::Save, [7u8; 32])).is_err());
    }

    #[test]
    fn requests_describe_themselves_and_hex_their_challenge() {
        let mut request = PhoneRequest {
            vault_id: "work".into(),
            vault_name: "work".into(),
            operation: Operation::Save,
            challenge: [0xab; 32],
        };
        assert_eq!(request.challenge_hex(), "ab".repeat(32));
        assert_eq!(request.describe(), "saving vault 'work'");
        request.operation = Operation::Unlock;
        assert_eq!(request.describe(), "opening vault 'work'");
        request.operation = Operation::EnrollKey;
        assert_eq!(
            request.describe(),
            "creating a phone-held key for vault 'work'"
        );
        request.operation = Operation::Reveal {
            entry: String::new(),
            field: String::new(),
        };
        assert_eq!(request.describe(), "vault 'work'");
        assert_eq!(
            ResponseError::Denied("no".into()).to_string(),
            "refused by the approver: no"
        );
        assert_eq!(
            ResponseError::Unavailable("nowhere".into()).to_string(),
            "nowhere"
        );
    }
}
