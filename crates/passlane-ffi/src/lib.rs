//! UniFFI bindings for the passlane vault API — the read-only v1 surface
//! the iOS app consumes (passlane#44).
//!
//! The surface is a thin, one-directional image of [`passlane_core`]:
//! Swift calls Rust, never the reverse, and there are no callbacks. One
//! object, [`PasslaneVault`], opens a vault and serves the v1 wedge —
//! search, copy, AutoFill — with the phone strictly read-only: there is no
//! save, because the phone does not write the vault in v1 (capture lands
//! later, behind the `inbox.kdbx` open question).
//!
//! # Secrets cross on demand, one field at a time
//!
//! Lists carry metadata only ([`EntrySummary`]): no method returns a
//! secret inside a list or DTO. A password, a TOTP seed, a note body or a
//! card field is fetched through [`PasslaneVault::secret`] — one field per
//! call — as [`SecretBytes`], whose buffer is zeroized when the foreign
//! side releases it. The master password and the challenge secret are
//! zeroized at this boundary too, on every path including failure: core
//! zeroizes its own copies on drop, and this crate scrubs the copies the
//! foreign side handed over.
//!
//! # Known limitation: UniFFI's transport buffers are not wiped
//!
//! Every value that crosses the boundary rides a `RustBuffer` that
//! UniFFI's generic machinery allocates and frees — for a secret going
//! out (`as_bytes`) or coming in (the password, the challenge secret)
//! alike, that transport allocation is freed without zeroization, and
//! there is no per-type hook to change that (a secret-holding object
//! constructed from a string param would cross the very same buffer).
//! Every copy this crate and core own *is* scrubbed: the decoded inputs,
//! the fetch intermediates, the `SecretBytes` buffer, the worker's
//! opening credentials. What remains is one unwiped transport copy per
//! crossing, freed back to the allocator — the same residual exposure
//! UniFFI gives every secret-bearing consumer, accepted here explicitly
//! rather than papered over.
//!
//! # Threading
//!
//! keepass-ng's node graph is `Rc`-based, so core's [`KeepassVault`] is
//! `!Send` — while every UniFFI object must be `Send + Sync`. The vault
//! therefore lives on one dedicated worker thread where it is opened,
//! served and dropped; [`PasslaneVault`] itself only holds a channel to
//! that thread. Nothing about the threading is visible in the surface.
//!
//! # Scope guard
//!
//! Approval-protocol types (the phone-key service) join this surface in a
//! later revision once the protocol crate stabilizes. Until then the
//! surface contains no UI concepts, no callbacks and no keepass-ng types.

uniffi::setup_scaffolding!();

use std::fmt;
use std::panic::{AssertUnwindSafe, UnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex, mpsc};

use passlane_core::challenge::ChallengeFactor as CoreChallengeFactor;
use passlane_core::vault::entities;
use passlane_core::vault::entities::SecretField as CoreSecretField;
use passlane_core::vault::keepass_vault::KeepassVault;
use passlane_core::vault::vault_trait::{NoteVault, PasswordVault, PaymentVault, TotpVault};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

/// The FFI image of the CLI's `ItemType`: which kind of entry a command
/// addresses. Entries of every kind live in whatever vault is open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ItemType {
    Credential,
    Payment,
    Note,
    Totp,
}

/// One secret field of an entry, fetched on demand via
/// [`PasslaneVault::secret`]. The field implies the entry kind it belongs
/// to: `Password` is looked up among credentials, `CardNumber` among
/// payment cards, and so on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SecretField {
    /// A credential's password.
    Password,
    /// A TOTP entry's seed, as its base32 text from the `otpauth://` URL.
    TotpSeed,
    /// A secure note's body.
    NoteBody,
    /// A payment card's number.
    CardNumber,
    /// A payment card's verification code.
    CardCvv,
}

impl From<SecretField> for CoreSecretField {
    fn from(field: SecretField) -> Self {
        match field {
            SecretField::Password => CoreSecretField::Password,
            SecretField::TotpSeed => CoreSecretField::TotpSeed,
            SecretField::NoteBody => CoreSecretField::NoteBody,
            SecretField::CardNumber => CoreSecretField::CardNumber,
            SecretField::CardCvv => CoreSecretField::CardCvv,
        }
    }
}

/// A challenge-response factor of the vault's composite key, as the phone
/// can supply one. v1 carries only [`ChallengeFactor::Virtual`]: the
/// 20-byte HMAC-SHA1 secret as 40 hex characters, covering both virtual
/// keys (convenience mode) and recovery secrets — the same key material.
/// A hardware-key variant would need USB, which the phone does not have.
///
/// The secret never appears in `Debug` output, and is scrubbed in place
/// the moment the factor is converted to core's own
/// [`CoreChallengeFactor`] — the only thing this crate ever does with it.
#[derive(uniffi::Enum)]
pub enum ChallengeFactor {
    /// The HMAC-SHA1 secret as hex (40 characters for a 20-byte key;
    /// whitespace and either case accepted, as by core's
    /// `ChallengeFactor::from_existing_secret_hex`).
    Virtual { secret_hex: String },
}

impl fmt::Debug for ChallengeFactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChallengeFactor::Virtual { secret_hex } => f
                .debug_struct("Virtual")
                .field(
                    "secret_hex",
                    &format_args!("<redacted: {} hex characters>", secret_hex.len()),
                )
                .finish(),
        }
    }
}

impl ChallengeFactor {
    /// The core factor that answers challenges the way this one does,
    /// scrubbing the secret this crate was handed. Opening is never
    /// stricter than the vault's file format, so the existing-secret rule
    /// applies: any non-empty hex secret opens a vault that requires it.
    fn into_core(mut self) -> Result<CoreChallengeFactor, CoreError> {
        // Matched by reference and scrubbed in place: with no `Drop` impl
        // of its own the enum's field could be moved out, but this way
        // the buffer is zeroed before it is freed either way.
        match &mut self {
            ChallengeFactor::Virtual { secret_hex } => {
                let converted = CoreChallengeFactor::from_existing_secret_hex(secret_hex)
                    .map_err(CoreError::from);
                secret_hex.zeroize();
                converted
            }
        }
    }
}

/// A list result carrying **metadata only**: no password, seed, note body
/// or card field ever appears here. Secrets are fetched one field at a
/// time through [`PasslaneVault::secret`].
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct EntrySummary {
    /// The entry's stable UUID, as text — the id `secret`/`totp_now`
    /// fetch it by.
    pub id: String,
    pub title: String,
    /// The credential's username; `None` for the other entry kinds (or
    /// when it is empty).
    pub username: Option<String>,
    /// The credential's URL; `None` for the other entry kinds.
    pub url: Option<String>,
    pub item_type: ItemType,
}

/// A TOTP code pair for rendering the countdown ring and the two-window
/// view: the code that is current right now, the one that follows it, and
/// how many seconds the current one is still valid for.
///
/// The codes themselves are display values — the phone shows them in
/// cleartext — so unlike every other secret they cross as plain record
/// fields rather than [`SecretBytes`].
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct TotpCode {
    pub code: String,
    pub next_code: String,
    pub seconds_remaining: u64,
}

/// The FFI image of core's `entities::Error`, which is a message and
/// nothing else — core classifies nothing further, so neither does this
/// surface. `Result<T, CoreError>` becomes `throws` in Swift.
#[derive(Debug, uniffi::Error)]
pub enum CoreError {
    /// A vault operation failed; `message` is the user-presentable reason
    /// (core's messages are written for users already) and never contains
    /// secret material.
    Vault { message: String },
}

impl From<entities::Error> for CoreError {
    fn from(e: entities::Error) -> Self {
        CoreError::Vault { message: e.message }
    }
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoreError::Vault { message } => write!(f, "{message}"),
        }
    }
}

/// A secret fetched one field at a time. The buffer is zeroized when the
/// object is released — the foreign side's own copies of the bytes are
/// its business, and `as_bytes` says so.
#[derive(uniffi::Object)]
pub struct SecretBytes {
    bytes: Zeroizing<Vec<u8>>,
}

#[uniffi::export]
impl SecretBytes {
    /// The secret as raw bytes. This is a copy: whatever the foreign side
    /// builds from it (`String`, `Data`, …) outlives this object and is
    /// *not* zeroized with it, so the caller should wipe it when done.
    pub fn as_bytes(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never render the bytes; even the length is only shown, not the
        // contents.
        write!(f, "SecretBytes(<redacted: {} bytes>)", self.bytes.len())
    }
}

/// An open, read-only view of one vault. Built by [`PasslaneVault::open`],
/// which runs the key derivation and fails on a wrong password, a missing
/// keyfile or a challenge factor that does not answer.
///
/// The keepass-ng database behind it lives on a dedicated worker thread
/// (see the module docs); each method call is served there in order.
#[derive(uniffi::Object)]
pub struct PasslaneVault {
    /// Requests to the worker thread that owns the vault. Behind a
    /// `Mutex` only because UniFFI objects must be `Send + Sync` and a
    /// bare `Sender` is not `Sync`; the lock is held just long enough to
    /// queue one request.
    requests: Mutex<mpsc::Sender<Request>>,
}

/// One method call queued to the worker thread that owns the vault.
enum Request {
    Search {
        query: String,
        item_type: ItemType,
        reply: Reply<Vec<EntrySummary>>,
    },
    Secret {
        id: String,
        field: SecretField,
        reply: Reply<Zeroizing<Vec<u8>>>,
    },
    TotpNow {
        id: String,
        reply: Reply<TotpCode>,
    },
}

type Reply<T> = mpsc::Sender<Result<T, CoreError>>;

#[uniffi::export]
impl PasslaneVault {
    /// Open the vault at `path` with its master password, an optional
    /// keyfile and an optional challenge-response factor. The password and
    /// the challenge secret are zeroized on this side once the open has
    /// used them, whether it succeeded or failed.
    #[uniffi::constructor]
    pub fn open(
        path: String,
        password: String,
        keyfile_path: Option<String>,
        challenge: Option<ChallengeFactor>,
    ) -> Result<Self, CoreError> {
        // Zeroizing from the moment it arrives: the param is the copy the
        // foreign side handed over; core makes (and zeroizes on drop) its
        // own copies.
        let password = Zeroizing::new(password);
        // Converted (and the FFI copy of the secret scrubbed) before the
        // thread exists, so a conversion error or a failed spawn leaves
        // nothing behind either.
        let challenge = challenge.map(ChallengeFactor::into_core).transpose()?;
        let (requests_tx, requests_rx) = mpsc::channel();
        let (opened_tx, opened_rx) = mpsc::channel();
        // The vault is opened on the worker thread, not here: keepass-ng's
        // `Rc`-based database must never cross a thread boundary, so it is
        // created, served and dropped on one and the same thread.
        std::thread::Builder::new()
            .name("passlane-vault".to_string())
            .spawn(move || {
                let vault = KeepassVault::open_with_challenge_factor(
                    &password,
                    &path,
                    keyfile_path,
                    challenge.as_ref(),
                );
                // Core has copied both into the vault it returned, so the
                // boundary copies have nothing left to protect — scrub
                // them now (Zeroizing/ZeroizeOnDrop on drop) instead of
                // holding them for the whole session the request loop
                // runs.
                drop(password);
                drop(challenge);
                match vault {
                    Ok(vault) => {
                        // Dropping `opened_tx` on the error paths below is
                        // what tells the constructor the thread is gone.
                        if opened_tx.send(Ok(())).is_err() {
                            return;
                        }
                        serve_requests(vault, requests_rx);
                    }
                    Err(e) => {
                        let _ = opened_tx.send(Err(e.into()));
                    }
                }
            })
            .map_err(|e| CoreError::Vault {
                message: format!("Could not start the vault thread: {e}"),
            })?;
        match opened_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                requests: Mutex::new(requests_tx),
            }),
            Ok(Err(e)) => Err(e),
            // Unreachable while the thread is alive: it sends exactly one
            // result before touching the request channel.
            Err(_) => Err(worker_gone()),
        }
    }

    /// Search the vault, with the CLI's matching semantics: a
    /// case-insensitive substring match — credentials over title, URL,
    /// username and tags, TOTP entries over label and issuer, notes over
    /// title, payment cards over name. An empty query matches everything,
    /// like the CLI's list commands.
    ///
    /// The results carry metadata only; fetch secrets field by field with
    /// [`Self::secret`]. (The issue's v1 signature returns the list
    /// directly; this returns a `Result` all the same so that a vault
    /// whose worker thread has died surfaces as an error instead of a
    /// silently empty list.)
    pub fn search(
        &self,
        query: String,
        item_type: ItemType,
    ) -> Result<Vec<EntrySummary>, CoreError> {
        self.call(|reply| Request::Search {
            query,
            item_type,
            reply,
        })
    }

    /// Fetch one secret field of the entry with the UUID `id`. The buffer
    /// is zeroized when the returned [`SecretBytes`] is released; see its
    /// docs for what that means for the caller's own copy.
    pub fn secret(&self, id: String, field: SecretField) -> Result<Arc<SecretBytes>, CoreError> {
        Ok(Arc::new(SecretBytes {
            bytes: self.call(|reply| Request::Secret { id, field, reply })?,
        }))
    }

    /// The current and next TOTP code of the entry with the UUID `id`,
    /// plus the seconds the current one is still valid for.
    pub fn totp_now(&self, id: String) -> Result<TotpCode, CoreError> {
        self.call(|reply| Request::TotpNow { id, reply })
    }
}

impl PasslaneVault {
    /// Queue one request to the worker and wait for its reply.
    fn call<T>(&self, build: impl FnOnce(Reply<T>) -> Request) -> Result<T, CoreError> {
        let (tx, rx) = mpsc::channel();
        // The lock is only ever held for the duration of a `send`, so a
        // panic while holding it is not a state to recover from.
        let requests = self
            .requests
            .lock()
            .expect("the vault request channel is only locked to send");
        requests.send(build(tx)).map_err(|_| worker_gone())?;
        rx.recv().map_err(|_| worker_gone())?
    }
}

/// Serve the vault's requests until the `PasslaneVault` side drops its
/// sender — then drop the vault, zeroizing the master password core keeps.
fn serve_requests(vault: KeepassVault, requests: mpsc::Receiver<Request>) {
    for request in requests {
        match request {
            Request::Search {
                query,
                item_type,
                reply,
            } => {
                let _ = reply.send(guard_panic(
                    "search",
                    AssertUnwindSafe(|| search_entries(&vault, &query, item_type)),
                ));
            }
            Request::Secret { id, field, reply } => {
                let _ = reply.send(guard_panic(
                    "secret",
                    AssertUnwindSafe(|| fetch_secret(&vault, &id, field)),
                ));
            }
            Request::TotpNow { id, reply } => {
                let _ = reply.send(guard_panic(
                    "totp_now",
                    AssertUnwindSafe(|| current_totp_code(&vault, &id)),
                ));
            }
        }
    }
}

/// Run one request, turning a panic into an error instead of tearing the
/// worker thread down with the channel still connected. The panic payload
/// is dropped unread: it is not this surface's business to repeat what a
/// panicked library chose to say.
fn guard_panic<T, F>(what: &str, request: F) -> Result<T, CoreError>
where
    F: FnOnce() -> Result<T, CoreError> + UnwindSafe,
{
    catch_unwind(request).unwrap_or_else(|_| {
        Err(CoreError::Vault {
            message: format!("The vault operation '{what}' failed unexpectedly."),
        })
    })
}

fn worker_gone() -> CoreError {
    CoreError::Vault {
        message: "The vault worker thread is no longer running; open the vault again.".to_string(),
    }
}

/// The metadata-only summaries one search returns. Core loads whole
/// entities (the decrypted database is in memory anyway); the secrets in
/// them stay on this side of the boundary and are dropped with the
/// entities here.
fn search_entries(
    vault: &KeepassVault,
    query: &str,
    item_type: ItemType,
) -> Result<Vec<EntrySummary>, CoreError> {
    let summaries = match item_type {
        ItemType::Credential => vault
            .grep(Some(query))
            .into_iter()
            .map(|c| EntrySummary {
                id: c.uuid().to_string(),
                title: c.title().to_string(),
                username: summary_username(c.username()),
                url: c.url().map(str::to_string),
                item_type,
            })
            .collect(),
        ItemType::Payment => vault
            .find_payments()
            .into_iter()
            .filter(|p| matches_query(query, &[p.name()]))
            .map(|p| EntrySummary {
                id: p.id().to_string(),
                title: p.name().to_string(),
                username: None,
                url: None,
                item_type,
            })
            .collect(),
        ItemType::Note => vault
            .find_notes()
            .into_iter()
            .filter(|n| matches_query(query, &[n.title()]))
            .map(|n| EntrySummary {
                id: n.id().to_string(),
                title: n.title().to_string(),
                username: None,
                url: None,
                item_type,
            })
            .collect(),
        ItemType::Totp => vault
            .find_totp(Some(query))
            .into_iter()
            .map(|t| EntrySummary {
                id: t.id().to_string(),
                title: t.label().to_string(),
                username: None,
                url: None,
                item_type,
            })
            .collect(),
    };
    Ok(summaries)
}

/// The CLI's matching rule for the kinds core takes no query for (the CLI
/// simply lists all notes and cards): a case-insensitive substring match
/// over the fields a list row shows. An empty query matches everything.
fn matches_query(query: &str, fields: &[&str]) -> bool {
    let needle = query.to_lowercase();
    query.is_empty() || fields.iter().any(|f| f.to_lowercase().contains(&needle))
}

/// The username of an [`EntrySummary`]: `None` when absent. Core's loader
/// fills a missing `UserName` field with its `"(no username)"` display
/// placeholder, which is not account metadata — AutoFill matches on this
/// value — so the placeholder maps to `None`. That costs a corner: a user
/// who literally stores `"(no username)"` as their username is
/// indistinguishable at this boundary, because the entity has already
/// lost the field's absence. Preserving it would mean changing core's
/// entity semantics for every CLI display; the mapping keeps the loss
/// here, documented, instead.
fn summary_username(value: &str) -> Option<String> {
    match value {
        "" | "(no username)" => None,
        stored => Some(stored.to_string()),
    }
}

/// One entry's one secret field, as zeroized bytes. The fetch goes
/// through core's field-at-a-time read (`get_secret_field`), which
/// materializes only the asked-for field of the one named entry — no
/// whole-category entity lists — and scrubs what it cannot avoid
/// materializing; see the module docs for the one copy UniFFI's
/// transport adds on top.
fn fetch_secret(
    vault: &KeepassVault,
    id: &str,
    field: SecretField,
) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    vault
        .get_secret_field(&parse_id(id)?, field.into())
        .map_err(CoreError::from)
}

/// The current and next TOTP code of one entry, read by id through core's
/// single-entry accessor.
fn current_totp_code(vault: &KeepassVault, id: &str) -> Result<TotpCode, CoreError> {
    let code = vault
        .get_totp_code(&parse_id(id)?)
        .map_err(CoreError::from)?;
    Ok(TotpCode {
        code: code.value,
        next_code: code.next_value,
        seconds_remaining: code.valid_for_seconds,
    })
}

/// Parse an entry id the foreign side held from an [`EntrySummary`]. A
/// malformed id is reported as such rather than as a missing entry, so a
/// caller bug and an absent entry stay distinguishable.
fn parse_id(id: &str) -> Result<Uuid, CoreError> {
    Uuid::parse_str(id).map_err(|_| CoreError::Vault {
        message: format!("'{id}' is not a valid entry id (a UUID)."),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_username_treats_the_display_placeholder_as_absent() {
        // Core's loader fills a missing UserName with "(no username)"; a
        // summary must not hand that placeholder to Swift as metadata.
        assert_eq!(summary_username("(no username)"), None);
        assert_eq!(summary_username(""), None);
        assert_eq!(
            summary_username("user@example.com"),
            Some("user@example.com".to_string())
        );
        // Near-misses of the placeholder stay real usernames.
        assert_eq!(
            summary_username("(no username!)"),
            Some("(no username!)".to_string())
        );
        assert_eq!(
            summary_username(" (no username) "),
            Some(" (no username) ".to_string())
        );
    }
}
