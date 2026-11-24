//! Smoke tests for the FFI surface (passlane#44): a real scratch kdbx
//! built through core, then the exact flows the phone will drive — open
//! (plain, keyfile, virtual challenge), search with metadata-only
//! results, field-at-a-time secret fetches, and totp_now's current+next
//! code pair.
//!
//! The fixtures write through core's save APIs; the FFI surface itself is
//! read-only in v1, and no test ever calls a write through it.

use passlane_core::challenge::ChallengeFactor as CoreChallengeFactor;
use passlane_core::vault::entities::{Credential, Expiry, Note, PaymentCard, Totp};
use passlane_core::vault::keepass_vault::KeepassVault;
use passlane_core::vault::vault_trait::{NoteVault, PasswordVault, PaymentVault, TotpVault};
use passlane_ffi::{
    ChallengeFactor, CoreError, EntrySummary, ItemType, PasslaneVault, SecretField, TotpCode,
};

const PASSWORD: &str = "ffi-test-master-password";
/// A 20-byte HMAC-SHA1 secret as hex, like `ykman otp chalresp` prints one.
const SLOT_SECRET: &str = "0102030405060708090a0b0c0d0e0f1011121314";
const OTP_SECRET: &str = "JBSWY3DPEHPK3PXP";
const OTP_URL: &str =
    "otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=6";

/// A scratch vault with one entry of each kind. The temp dirs (the
/// vault's, and the keyfile's when there is one) live as long as the
/// fixture.
struct Fixture {
    _dir: tempfile::TempDir,
    _keyfile_dir: Option<tempfile::TempDir>,
    vault_path: String,
    keyfile_path: Option<String>,
    challenge: Option<CoreChallengeFactor>,
}

impl Fixture {
    fn plain(tag: &str) -> Self {
        Self::create(tag, None, None)
    }

    fn with_keyfile(tag: &str) -> Self {
        let keyfile_dir = tempfile::tempdir().unwrap();
        let keyfile = keyfile_dir.path().join("keyfile");
        // A bare keyfile: keepass-ng hashes whatever bytes it reads.
        std::fs::write(&keyfile, b"a bare keyfile keepass-ng hashes").unwrap();
        let mut fixture = Self::create(tag, Some(keyfile.to_str().unwrap().to_string()), None);
        fixture._keyfile_dir = Some(keyfile_dir);
        fixture
    }

    fn with_challenge(tag: &str) -> Self {
        let factor = CoreChallengeFactor::from_secret_hex(SLOT_SECRET).unwrap();
        Self::create(tag, None, Some(factor))
    }

    fn create(
        tag: &str,
        keyfile_path: Option<String>,
        challenge: Option<CoreChallengeFactor>,
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join(format!("{tag}.kdbx"));
        let vault_path = vault_path.to_str().unwrap().to_string();
        let mut vault = KeepassVault::new_with_challenge_factor(
            &vault_path,
            PASSWORD,
            keyfile_path.as_deref(),
            challenge.as_ref(),
        )
        .unwrap();
        vault
            .save_credentials(&vec![
                Credential::new(
                    None,
                    "hunter2",
                    "GitHub",
                    "user@example.com",
                    Some("the work account"),
                    None,
                )
                .with_url(Some("https://github.com")),
            ])
            .unwrap();
        vault
            .save_totp(&Totp::new(
                None,
                OTP_URL,
                "user@example.com",
                "GitHub",
                OTP_SECRET,
                "SHA1",
                30,
                6,
                None,
            ))
            .unwrap();
        vault
            .save_note(&Note::new(
                None,
                "Wifi password",
                "wpa-passphrase-at-home",
                None,
            ))
            .unwrap();
        vault
            .save_payment(PaymentCard::new(
                None,
                "Personal",
                "John Doe",
                "4111111111111111",
                "123",
                Expiry {
                    month: 12,
                    year: 2030,
                },
                None,
                None,
                None,
            ))
            .unwrap();
        Fixture {
            _dir: dir,
            _keyfile_dir: None,
            vault_path,
            keyfile_path,
            challenge,
        }
    }

    /// Open with the fixture's own factors (password, keyfile, virtual
    /// challenge as created).
    fn open(&self) -> PasslaneVault {
        PasslaneVault::open(
            self.vault_path.clone(),
            PASSWORD.to_string(),
            self.keyfile_path.clone(),
            self.challenge.is_some().then(|| ChallengeFactor::Virtual {
                secret_hex: SLOT_SECRET.to_string(),
            }),
        )
        .expect("the fixture vault opens")
    }
}

/// The message of an error result, failing the test if there is none.
fn err_message(result: Result<(), CoreError>) -> String {
    match result {
        Ok(()) => panic!("expected an error"),
        Err(CoreError::Vault { message }) => message,
    }
}

#[test]
fn a_plain_vault_opens_and_searches() {
    let fixture = Fixture::plain("plain");
    let vault = fixture.open();

    let credentials = vault
        .search("github".to_string(), ItemType::Credential)
        .unwrap();
    assert_eq!(credentials.len(), 1);
    let summary = &credentials[0];
    assert_eq!(summary.title, "GitHub");
    assert_eq!(summary.item_type, ItemType::Credential);
    // The summary is metadata only, in the issue's exact shape: id, title,
    // username, url, item type — there is no secret field to leak.
    assert_eq!(
        *summary,
        EntrySummary {
            id: summary.id.clone(),
            title: "GitHub".to_string(),
            username: Some("user@example.com".to_string()),
            url: Some("https://github.com".to_string()),
            item_type: ItemType::Credential,
        }
    );

    // Every entry kind is searchable, with the CLI's semantics.
    assert_eq!(
        vault
            .search("wifi".to_string(), ItemType::Note)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        vault
            .search("personal".to_string(), ItemType::Payment)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        vault
            .search("github".to_string(), ItemType::Totp)
            .unwrap()
            .len(),
        1
    );
    // Case-insensitive substring, like the CLI.
    assert_eq!(
        vault
            .search("GITHUB".to_string(), ItemType::Credential)
            .unwrap()
            .len(),
        1
    );
    assert!(
        vault
            .search("no-such-entry".to_string(), ItemType::Credential)
            .unwrap()
            .is_empty()
    );
    // An empty query lists everything, like the CLI's list commands.
    assert_eq!(
        vault
            .search(String::new(), ItemType::Credential)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn a_keyfile_vault_needs_its_keyfile() {
    let fixture = Fixture::with_keyfile("keyfile");
    let vault = fixture.open();
    assert_eq!(
        vault
            .search("github".to_string(), ItemType::Credential)
            .unwrap()
            .len(),
        1
    );

    // The same password without the keyfile must not open it.
    let without_keyfile =
        PasslaneVault::open(fixture.vault_path.clone(), PASSWORD.to_string(), None, None);
    assert!(!err_message(without_keyfile.map(|_| ())).is_empty());
}

#[test]
fn a_virtual_challenge_vault_opens_with_the_secret() {
    let fixture = Fixture::with_challenge("challenge");
    let vault = fixture.open();
    assert_eq!(
        vault
            .search("github".to_string(), ItemType::Credential)
            .unwrap()
            .len(),
        1
    );

    // A wrong secret must not open the vault...
    let wrong_secret = PasslaneVault::open(
        fixture.vault_path.clone(),
        PASSWORD.to_string(),
        None,
        Some(ChallengeFactor::Virtual {
            secret_hex: "ffffffffffffffffffffffffffffffffffffffff".to_string(),
        }),
    );
    assert!(!err_message(wrong_secret.map(|_| ())).is_empty());
    // ...nor the right password without the factor.
    let bare = PasslaneVault::open(fixture.vault_path.clone(), PASSWORD.to_string(), None, None);
    assert!(!err_message(bare.map(|_| ())).is_empty());
}

#[test]
fn a_wrong_password_is_an_error() {
    let fixture = Fixture::plain("wrong-password");
    let result = PasslaneVault::open(
        fixture.vault_path.clone(),
        "not-the-password".to_string(),
        None,
        None,
    );
    let message = err_message(result.map(|_| ()));
    assert!(!message.is_empty());
    // And it never echoes the password back.
    assert!(!message.contains("not-the-password"));
}

#[test]
fn secrets_are_fetched_one_field_at_a_time() {
    let fixture = Fixture::plain("secrets");
    let vault = fixture.open();

    let credential = &vault
        .search("github".to_string(), ItemType::Credential)
        .unwrap()[0];
    let password = vault
        .secret(credential.id.clone(), SecretField::Password)
        .unwrap();
    assert_eq!(password.as_bytes(), b"hunter2".to_vec());

    // A field fetched from the wrong kind of entry finds nothing.
    let other_kind = err_message(
        vault
            .secret(credential.id.clone(), SecretField::NoteBody)
            .map(|_| ()),
    );
    assert!(other_kind.contains("No note with id"), "{other_kind}");

    // Unknown ids and malformed ids are distinct errors.
    let missing = err_message(
        vault
            .secret(
                "00000000-0000-0000-0000-000000000000".to_string(),
                SecretField::Password,
            )
            .map(|_| ()),
    );
    assert!(missing.contains("No credential with id"), "{missing}");
    let malformed = err_message(
        vault
            .secret("not-a-uuid".to_string(), SecretField::Password)
            .map(|_| ()),
    );
    assert!(malformed.contains("not a valid entry id"), "{malformed}");
}

#[test]
fn every_secret_field_round_trips() {
    let fixture = Fixture::plain("fields");
    let vault = fixture.open();

    let note = &vault.search("wifi".to_string(), ItemType::Note).unwrap()[0];
    let body = vault
        .secret(note.id.clone(), SecretField::NoteBody)
        .unwrap();
    assert_eq!(body.as_bytes(), b"wpa-passphrase-at-home".to_vec());

    let totp = &vault.search("github".to_string(), ItemType::Totp).unwrap()[0];
    let seed = vault
        .secret(totp.id.clone(), SecretField::TotpSeed)
        .unwrap();
    assert_eq!(seed.as_bytes(), OTP_SECRET.as_bytes().to_vec());

    let card = &vault
        .search("personal".to_string(), ItemType::Payment)
        .unwrap()[0];
    let number = vault
        .secret(card.id.clone(), SecretField::CardNumber)
        .unwrap();
    assert_eq!(number.as_bytes(), b"4111111111111111".to_vec());
    let cvv = vault.secret(card.id.clone(), SecretField::CardCvv).unwrap();
    assert_eq!(cvv.as_bytes(), b"123".to_vec());
}

#[test]
fn totp_now_returns_the_current_and_next_code() {
    let fixture = Fixture::plain("totp");
    let vault = fixture.open();

    let totp = &vault.search("github".to_string(), ItemType::Totp).unwrap()[0];
    let code: TotpCode = vault.totp_now(totp.id.clone()).unwrap();
    assert_eq!(code.code.len(), 6);
    assert!(code.code.chars().all(|c| c.is_ascii_digit()));
    assert_eq!(code.next_code.len(), 6);
    assert!(code.next_code.chars().all(|c| c.is_ascii_digit()));
    assert!((1..=30).contains(&code.seconds_remaining));

    // An id that is no TOTP entry is an error, not an empty code.
    let credential = &vault
        .search("github".to_string(), ItemType::Credential)
        .unwrap()[0];
    let message = err_message(vault.totp_now(credential.id.clone()).map(|_| ()));
    assert!(message.contains("No TOTP entry with id"), "{message}");
}

#[test]
fn the_scaffolding_exports_the_documented_ffi_symbols() {
    // The UniFFI scaffolding (what the Swift module calls through) exists
    // under the documented symbol names — a cheap roundtrip check that the
    // proc-macro setup really generated the externs, without linking a
    // foreign language into this test.
    let symbols = [
        passlane_ffi::uniffi_passlane_ffi_fn_constructor_passlanevault_open as *const (),
        passlane_ffi::uniffi_passlane_ffi_fn_method_passlanevault_search as *const (),
        passlane_ffi::uniffi_passlane_ffi_fn_method_passlanevault_secret as *const (),
        passlane_ffi::uniffi_passlane_ffi_fn_method_passlanevault_totp_now as *const (),
        passlane_ffi::uniffi_passlane_ffi_fn_method_secretbytes_as_bytes as *const (),
    ];
    assert!(symbols.iter().all(|s| !s.is_null()));
}
