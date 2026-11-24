//! The CLI side of the approval link transport (passlane#51, SPEC §1/§6).
//!
//! This module owns everything around the protocol envelopes that
//! [`passlane_approval`] defines:
//!
//! - **Emission** — when the ask flow needs an approval, seal the request
//!   to a pinned approver and present it as a terminal QR plus a copyable
//!   link. The envelope rides the URL **fragment** (never sent to the
//!   page's domain) and is recorded as a pending request.
//! - **Verification** — `passlane approve --response` opens the pasted
//!   response envelope against the pinned keys (WebAuthn assertions for
//!   Phase 0 pages), the file-backed replay store, and the pending
//!   request's `rid`; a verified `Allow` becomes a grant the ask flow
//!   consumes to release the entry.
//! - **Enrollment** — `passlane approvals enroll` runs the SPEC §6
//!   ceremony: the page enrolls a WebCrypto ECDH key (the encryption
//!   identity) and a WebAuthn passkey (the signing identity), and the
//!   passkey's assertion over `SHA-256(enrollment_nonce ‖ ECDH_public)`
//!   binds the two before anything is pinned.
//!
//! State lives under the approvals directory (default `~/.passlane`,
//! overridable with `PASSLANE_APPROVALS_DIR` for tests and scripted
//! verification):
//!
//! - `approval_identity.json` / `approval_peers.json` (protocol crate)
//! - `.approval_nonces` — the replay store
//! - `approval_pending.json` — pending requests and grants

pub mod cose;
pub mod pending;

use std::path::PathBuf;

use rand::rngs::OsRng;

use passlane_approval::envelope::Envelope;
use passlane_approval::keys::{IdentityKeys, PeerPin, PublicKey};
use passlane_approval::message::{Body, Decision, MessageType, Operation, Scope};
use passlane_approval::policy::Policy;
use passlane_approval::replay::FileNonceStore;
use passlane_approval::store::{load_or_generate_identity, load_peers, save_peers};
use passlane_approval::webauthn::WebauthnAssertion;

use pending::{PendingRequest, PendingStore, RequestKind, RequestState};

/// Default home of the static approval page. The domain later serves the
/// app's `apple-app-site-association` so universal links route to the app
/// instead (SPEC §6); the envelope always stays in the fragment.
pub const DEFAULT_PAGE: &str = "https://approve.passlane.app";

/// Directory holding all approval state. Overridable for CLI-level tests
/// and scripted verification with `PASSLANE_APPROVALS_DIR`; default
/// `~/.passlane`. All stateful functions take the directory explicitly;
/// this is the default the actions pass.
pub fn state_dir() -> PathBuf {
    std::env::var("PASSLANE_APPROVALS_DIR")
        .ok()
        .filter(|d| !d.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(crate::store::dir_path)
}

/// File mapping a pinned approver's encryption key id to the exact page
/// base URL it was enrolled under (`approval_pages.json`). The WebAuthn
/// origin cannot carry a deployment path (e.g. `https://example.com/passlane`),
/// so the full base is remembered beside the pin.
const PAGES_FILENAME: &str = "approval_pages.json";

fn load_page_bases(dir: &std::path::Path) -> std::collections::HashMap<String, String> {
    let path = dir.join(PAGES_FILENAME);
    std::fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

/// Remember (or replace) the page base URL for the approver keyed by
/// `enc_kid`. Best-effort persistence: a missing map never blocks
/// approvals — the link falls back to the pinned origin.
pub fn remember_page_base(
    dir: &std::path::Path,
    enc_kid: &str,
    base_url: &str,
) -> Result<(), String> {
    let mut map = load_page_bases(dir);
    map.insert(
        enc_kid.to_string(),
        base_url.trim_end_matches('/').to_string(),
    );
    std::fs::create_dir_all(dir)
        .and_then(|()| {
            let bytes =
                serde_json::to_vec(&map).map_err(|e| std::io::Error::other(e.to_string()))?;
            let tmp = dir.join(format!("{PAGES_FILENAME}.tmp"));
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            use std::io::Write;
            let mut file = options.open(&tmp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            std::fs::rename(&tmp, dir.join(PAGES_FILENAME))
        })
        .map_err(|e| format!("could not persist the page base URL: {e}"))
}

/// The replay store path (`<dir>/.approval_nonces`).
fn nonce_store_path(dir: &std::path::Path) -> PathBuf {
    dir.join(".approval_nonces")
}

/// This device's protocol identity, generating on first use.
pub fn load_identity(dir: &std::path::Path) -> Result<IdentityKeys, String> {
    load_or_generate_identity(dir, &mut OsRng)
        .map_err(|e| format!("could not load the approval identity: {e}"))
}

/// The pinned approvers.
pub fn load_peers_pinned(dir: &std::path::Path) -> Result<Vec<PeerPin>, String> {
    load_peers(dir).map_err(|e| format!("could not load pinned approvers: {e}"))
}

/// Persist the pinned approvers.
pub fn store_peers(dir: &std::path::Path, peers: &[PeerPin]) -> Result<(), String> {
    save_peers(dir, peers).map_err(|e| format!("could not save pinned approvers: {e}"))
}

/// The pinned approver requests are sealed to: the most recently paired.
fn preferred_peer(peers: &[PeerPin]) -> Option<&PeerPin> {
    peers.iter().max_by_key(|p| p.paired_at)
}

/// Unix seconds now (never negative on a sane clock).
pub fn now_secs() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Link building and QR rendering
// ---------------------------------------------------------------------------

/// The approval page base URL: the `--page` flag, `$PASSLANE_APPROVAL_PAGE`,
/// or the default domain.
pub fn page_url(explicit: Option<&str>) -> String {
    explicit
        .map(str::to_string)
        .or_else(|| {
            std::env::var("PASSLANE_APPROVAL_PAGE")
                .ok()
                .filter(|u| !u.is_empty())
        })
        .unwrap_or_else(|| DEFAULT_PAGE.to_string())
}

/// `https://…/approve.html#<envelope>` — the envelope rides the fragment,
/// which browsers never send to the domain. The `.html` suffix works on
/// any plain static file server; a real deployment may add a clean-URL
/// rewrite later (the page is the same bytes).
pub fn approve_link(base: &str, envelope_b64url: &str) -> String {
    format!("{base}/approve.html#{envelope_b64url}")
}

/// `https://…/enroll.html#n=<nonce hex>&c=<CLI encryption public key hex>&s=<CLI verifying key hex>`
/// — the enrollment link (SPEC §6). The nonce drives the binding ceremony;
/// the CLI's public keys are what the page later seals its approval
/// responses to (`c`) and verifies request signatures against (`s`).
/// Everything stays in the fragment.
pub fn enroll_link(
    page: &str,
    nonce_hex: &str,
    cli_enc_pub_hex: &str,
    cli_sig_pub_hex: &str,
) -> String {
    format!(
        "{}/enroll.html#n={nonce_hex}&c={cli_enc_pub_hex}&s={cli_sig_pub_hex}",
        page.trim_end_matches('/')
    )
}

/// The link base requests to `peer` should use: the exact deployment base
/// recorded at its enrollment (which may carry a path, e.g.
/// `https://example.com/passlane`), else the pinned WebAuthn origin, else
/// the configured default.
fn link_base_for(dir: &std::path::Path, peer: &PeerPin) -> String {
    if let Ok(kid) = peer.enc_kid()
        && let Some(base) = load_page_bases(dir).get(&kid)
    {
        return base.trim_end_matches('/').to_string();
    }
    peer.webauthn
        .as_ref()
        .map(|w| w.origin.trim_end_matches('/').to_string())
        .unwrap_or_else(|| page_url(None))
}

/// Render a QR as terminal text: two module rows per line via half-block
/// characters, so modules come out square at typical terminal font
/// geometry (one cell is roughly twice as tall as wide). A quiet zone of
/// four modules is included on every side.
pub fn render_qr(data: &str) -> Result<String, String> {
    let code = qrcode::QrCode::with_error_correction_level(data.as_bytes(), qrcode::EcLevel::L)
        .map_err(|e| format!("could not encode the QR code: {e}"))?;
    let width = code.width();
    let quiet = 4usize;
    let total = width + 2 * quiet;
    let dark = |x: usize, y: usize| -> bool {
        let mx = x as i64 - quiet as i64;
        let my = y as i64 - quiet as i64;
        (0..width as i64).contains(&mx)
            && (0..width as i64).contains(&my)
            && code[(mx as usize, my as usize)] == qrcode::Color::Dark
    };
    let mut out = String::with_capacity(total * (total + 1) / 2);
    let mut y = 0;
    while y < total {
        let mut line = String::with_capacity(total);
        for x in 0..total {
            let top = dark(x, y);
            let bottom = y + 1 < total && dark(x, y + 1);
            line.push(match (top, bottom) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        out.push_str(&line);
        out.push('\n');
        y += 2;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Emission
// ---------------------------------------------------------------------------

/// A request envelope handed to the transport.
#[derive(Debug, Clone)]
pub struct EmittedRequest {
    /// The request id the response must echo.
    pub rid: String,
    /// The full `https://…/approve.html#…` link.
    pub link: String,
    /// The envelope, unpadded base64url (the link's fragment).
    #[cfg_attr(not(test), allow(dead_code))]
    pub envelope: String,
    /// Unix seconds after which the request can no longer be approved.
    pub exp: u64,
}

/// What a request is about, as the pending store records it.
#[derive(Debug, Clone, Copy)]
pub struct RequestTarget<'a> {
    /// Vault the request targets (registry name).
    pub vault: &'a str,
    /// The entry's stable UUID — grants are matched on this, never on the
    /// display title. Empty for challenge-bearing requests.
    pub entry_id: &'a str,
    /// Entry title or match string, for display only.
    pub entry: &'a str,
    /// The field being revealed (`password`, `code`, ...); empty for
    /// challenge-bearing requests.
    pub field: &'a str,
    /// What the request asks for.
    pub kind: RequestKind,
    /// The challenge (lower-case hex) of an `Unlock`, `Save` or `EnrollKey`
    /// request.
    pub challenge: Option<&'a str>,
}

impl<'a> RequestTarget<'a> {
    /// A challenge-bearing request (SPEC §7): no entry, a challenge.
    pub fn challenge(vault: &'a str, kind: RequestKind, challenge: &'a str) -> Self {
        debug_assert!(kind.carries_challenge(), "{:?} carries no challenge", kind);
        Self {
            vault,
            entry_id: "",
            entry: "",
            field: "",
            kind,
            challenge: Some(challenge),
        }
    }
}

/// Seal an approval request for `peer` and record it as pending.
///
/// `entry_id` is the entry's stable UUID — grants match on it, never on
/// the display title. `requested_timed` is the widest reuse a response may
/// offer (`None`: single use only).
pub fn emit_to(
    dir: &std::path::Path,
    peer: &PeerPin,
    target: RequestTarget<'_>,
    body: Body,
    requested_timed: Option<u32>,
) -> Result<EmittedRequest, String> {
    let identity = load_identity(dir)?;
    let now = now_secs();
    let envelope = passlane_approval::envelope::seal(
        &mut OsRng,
        &identity,
        peer,
        body,
        now,
        &Policy::default(),
    )
    .map_err(|e| format!("could not seal the approval request: {e}"))?;
    let rid = envelope.header().rid.clone();
    let exp = envelope.header().exp;
    let encoded = envelope.to_base64url();
    let link = approve_link(&link_base_for(dir, peer), &encoded);
    // The request was sealed to this approver; only its response may
    // answer it (checked at verification, against the response's sender).
    let holder_kid = peer.enc_kid().ok();

    // Recording runs under the store's exclusive lock (and persists the
    // pruning of dead records) — a concurrent consume/approve can never
    // be overwritten by this stale view.
    PendingStore::transaction(dir, |pending| {
        pending.upsert(PendingRequest {
            rid: rid.clone(),
            vault: target.vault.to_string(),
            entry_id: target.entry_id.to_string(),
            entry: target.entry.to_string(),
            field: target.field.to_string(),
            created: now,
            exp,
            requested_timed,
            kind: target.kind,
            challenge: target.challenge.map(str::to_string),
            link: Some(link.clone()),
            holder_kid,
            state: RequestState::Pending,
        });
    })
    .map_err(|e| format!("could not record the pending request: {e}"))?;
    Ok(EmittedRequest {
        rid,
        link,
        envelope: encoded,
        exp,
    })
}

/// Seal a reveal request to the pinned approver and record it as
/// pending. Fails when no approver is pinned yet.
pub fn emit_approval_request(
    dir: &std::path::Path,
    vault: &str,
    entry: &str,
    entry_id: &str,
    field: &str,
    requester: &str,
) -> Result<EmittedRequest, String> {
    let peers = load_peers_pinned(dir)?;
    let peer = preferred_peer(&peers).ok_or_else(|| {
        "no approver is pinned; run 'passlane approvals enroll' first".to_string()
    })?;
    let body = Body::ApprovalRequest {
        vault_id: vault.to_string(),
        vault_name: vault.to_string(),
        operation: Operation::Reveal {
            entry: entry.to_string(),
            field: field.to_string(),
        },
        requester: requester.to_string(),
        scope: Scope::Once,
        challenge: None,
    };
    emit_to(
        dir,
        peer,
        RequestTarget {
            vault,
            entry_id,
            entry,
            field,
            kind: RequestKind::Reveal,
            challenge: None,
        },
        body,
        None,
    )
}

/// The body of a challenge-bearing request (SPEC §7): the operation, the
/// 32-byte challenge it is answered for, and who is asking.
pub fn challenge_request_body(
    vault_id: &str,
    vault_name: &str,
    operation: Operation,
    challenge: &[u8],
    requester: &str,
) -> Result<Body, String> {
    if !RequestKind::from_operation(&operation).carries_challenge() {
        return Err(
            "internal: only unlock, save and enroll_key requests carry a challenge".to_string(),
        );
    }
    if challenge.len() != passlane_approval::message::CHALLENGE_LEN {
        return Err(format!(
            "internal: a challenge is {} bytes, not {}",
            challenge.len(),
            passlane_approval::message::CHALLENGE_LEN
        ));
    }
    // `vault_id` is the holder-side identity the approver keys its key
    // under (stable across 'passlane vault rename'); `vault_name` is what
    // the approval card shows.
    Ok(Body::ApprovalRequest {
        vault_id: vault_id.to_string(),
        vault_name: vault_name.to_string(),
        operation,
        requester: requester.to_string(),
        scope: Scope::Once,
        challenge: Some(passlane_approval::message::SecretHex::from_bytes(challenge)),
    })
}

// ---------------------------------------------------------------------------
// Grants
// ---------------------------------------------------------------------------

/// Consume a live grant for this exact reveal, best-effort: returns the
/// approving request's rid, or None when nothing grants it. The whole
/// load-consume-save span runs under the store's exclusive lock, so two
/// concurrent reveals can never both consume a once-grant.
pub fn consume_grant(
    dir: &std::path::Path,
    vault: &str,
    entry_id: &str,
    field: &str,
) -> Option<String> {
    // The clock is read inside the lock: a `now` captured earlier could
    // consume a grant that expired while this process waited for another
    // transaction to finish.
    PendingStore::transaction(dir, |pending| {
        let now = now_secs();
        pending.take_grant(vault, entry_id, field, now)
    })
    .ok()
    .flatten()
}

// ---------------------------------------------------------------------------
// Response verification (`passlane approve --response`)
// ---------------------------------------------------------------------------

/// What a verified response did.
#[derive(Debug, Clone, PartialEq)]
pub enum ApproveOutcome {
    /// The approver allowed the request; the grant is live.
    Allowed {
        /// The request id that was released.
        rid: String,
        vault: String,
        entry: String,
        field: String,
        /// Single-use grant.
        once: bool,
        /// Unix seconds until which the grant is reusable.
        until: u64,
        /// The response carries a challenge response (unlock, save,
        /// enrollment — phone-held keys, passlane#53).
        has_unlock_response: bool,
    },
    /// The approver refused the request.
    Denied {
        rid: String,
        vault: String,
        entry: String,
        field: String,
        reason: Option<String>,
    },
}

/// What a verified response did, and what it answered.
///
/// Deliberately carries no answer bytes: a challenge response reaches
/// its caller only through [`verify_response`]'s handoff, so there is
/// exactly one place an unlock factor can be taken from.
#[derive(Debug)]
pub struct VerifiedResponse {
    /// What the response did.
    pub outcome: ApproveOutcome,
    /// What the answered request asked for.
    pub kind: RequestKind,
}

/// What happens to a request once its answer is verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Leave it granted: the command that asked consumes it (the ask
    /// flow's re-run), or a session holds the answer.
    Grant,
    /// The caller uses the answer right now; the request ends as consumed,
    /// so the same blob presented again is recognised as spent.
    ConsumeNow,
}

/// A challenge response, handed to the caller *before* anything is
/// recorded — if the handoff fails, the response can be presented again.
pub struct ResponseHandoff<'a> {
    /// The request being answered.
    pub rid: &'a str,
    /// The vault the answer is for.
    pub vault: &'a str,
    /// What was asked.
    pub kind: RequestKind,
    /// The challenge the answer is for (lower-case hex).
    pub challenge: Option<&'a str>,
    /// The 20-byte HMAC-SHA1 answer.
    pub response: &'a [u8],
    /// The scope the approver granted.
    pub scope: Scope,
}

/// Verify a pasted response blob and release (or refuse) the pending
/// request it answers.
///
/// Order (SPEC §10): parse → rid must match a still-pending request →
/// open() (freshness, sender pinning, WebAuthn assertion, AEAD, replay
/// recording) → hand a challenge response to `handoff` → grant, consume
/// or deny. The replay store is persisted only after full verification
/// and — for a challenge response — only once `handoff` has accepted it,
/// so a handoff that fails leaves the response presentable again. The
/// pending record only changes state for a verified decision. Everything
/// that reads or writes the pending store runs inside one exclusive-locked
/// transaction (load through atomic save), so concurrent approvals and
/// reveals serialize on the same view.
pub fn verify_response(
    dir: &std::path::Path,
    blob: &str,
    disposition: Disposition,
    handoff: &dyn Fn(&ResponseHandoff<'_>) -> Result<(), String>,
) -> Result<VerifiedResponse, String> {
    let cleaned: String = blob.chars().filter(|c| !c.is_whitespace()).collect();
    let envelope = Envelope::from_base64url(&cleaned)
        .map_err(|e| format!("the response is not a valid envelope: {e}"))?;
    let header = envelope.header();
    if header.t != MessageType::ApprovalResponse as u8 {
        return Err("the envelope is not an approval response (wrong message type)".to_string());
    }
    let rid = header.rid.clone();

    let identity = load_identity(dir)?;
    let peers = load_peers_pinned(dir)?;
    let mut nonces =
        FileNonceStore::load(&nonce_store_path(dir)).map_err(|e| format!("replay store: {e}"))?;

    PendingStore::transaction(dir, |pending| -> Result<VerifiedResponse, String> {
        // The clock is read here, after both the pending-store and
        // replay-store locks are held: a timestamp captured before
        // waiting on a lock could pass a response that expired in the
        // meantime.
        let now = now_secs();
        let record = pending
            .find(&rid)
            .ok_or_else(|| {
                "no pending approval request matches this response (it may have expired)"
                    .to_string()
            })?
            .clone();
        match record.state {
            RequestState::Pending => {}
            RequestState::Granted { .. } => {
                return Err(format!(
                    "request {rid} was already approved; it cannot be approved twice"
                ))
            }
            RequestState::Consumed => {
                return Err(format!(
                    "request {rid} was already approved and used; emit a new one by re-running the command"
                ))
            }
            RequestState::Denied => {
                return Err(format!("request {rid} was already denied"))
            }
        }
        if now >= record.exp {
            return Err(format!(
                "the request expired at {}; emit a new one by re-running the command",
                record.exp
            ));
        }
        // The approver the request was sealed to is the only one who may
        // answer it. The response's sender key id says who did; with
        // several approvers pinned, another one holding the link could
        // otherwise answer in the holder's place — for a challenge
        // request, with Save/Unlock material of its own choosing.
        if let Some(expected) = &record.holder_kid
            && header.skid != *expected
        {
            return Err(format!(
                "request {rid} was addressed to approver {expected}, but this response comes \
                 from '{}'. Only the device a request was sealed to may answer it.",
                header.skid
            ));
        }

        // Full verification (the replay nonce is recorded in memory by
        // open() only once everything above it passed). Pruning the
        // replay store here — under its own lock, before the rewrite —
        // keeps `.approval_nonces` bounded by the replay window.
        use passlane_approval::replay::NonceStore;
        nonces.prune(now);

        let body = passlane_approval::envelope::open(
            &identity,
            &peers,
            &envelope,
            now,
            &Policy::default(),
            &mut nonces,
        )
        .map_err(|e| format!("the approval response failed verification: {e}"))?;

        let Body::ApprovalResponse {
            decision,
            scope,
            response,
        } = &*body
        else {
            return Err("the envelope does not carry an approval response body".to_string());
        };

        let (vault, entry, field) =
            (record.vault.clone(), record.entry.clone(), record.field.clone());
        match decision {
            Decision::Allow => {
                // The response may not grant more than the request asked
                // for (SPEC §4): every request this CLI emits is
                // `Scope::Once`, so a reusable scope is refused — a single
                // approval must release exactly one reveal.
                let once = matches!(scope, Scope::Once);
                if !once && record.requested_timed.is_none() {
                    return Err(format!(
                        "request {rid} asked for a single-use approval; the response offered a \
                         reusable scope, which is refused"
                    ));
                }
                if let Scope::Timed { seconds } = scope
                    && record.requested_timed.is_some_and(|asked| seconds > &asked)
                {
                    return Err(format!(
                        "request {rid} asked for at most {}s of reuse; the response offered {seconds}s",
                        record.requested_timed.unwrap()
                    ));
                }
                // A once-grant is bounded by the request envelope's own expiry
                // (it lives only to be consumed); a timed grant by its window.
                let until = if once {
                    record.exp
                } else {
                    now + scope.seconds()
                };

                let answer = match record.kind.carries_challenge() {
                    true => {
                        // Decode and validate before anything is recorded.
                        let answer = response.as_ref().ok_or_else(|| {
                            format!(
                                "request {rid} was approved, but the response carries no \
                                 challenge response; re-run the command to ask again"
                            )
                        })?;
                        let bytes = answer.as_bytes().map_err(|e| {
                            format!("the challenge response in the response is not valid hex: {e}")
                        })?;
                        if bytes.len() != passlane_approval::message::CHALLENGE_RESPONSE_LEN {
                            return Err(format!(
                                "request {rid} was approved, but the challenge response is {} \
                                 bytes, not {}; re-run the command to ask again",
                                bytes.len(),
                                passlane_approval::message::CHALLENGE_RESPONSE_LEN
                            ));
                        }
                        Some(bytes)
                    }
                    false => None,
                };

                if let Some(bytes) = &answer {
                    // The answer is the caller's before anything is
                    // recorded: a handoff that fails (nowhere to keep it)
                    // leaves the blob presentable again.
                    handoff(&ResponseHandoff {
                        rid: &rid,
                        vault: &vault,
                        kind: record.kind,
                        challenge: record.challenge.as_deref(),
                        response: bytes,
                        scope: *scope,
                    })?;
                }
                nonces
                    .save()
                    .map_err(|e| format!("could not persist the replay store: {e}"))?;
                match disposition {
                    Disposition::Grant => {
                        if !pending.grant(&rid, once, until) {
                            return Err(format!("request {rid} disappeared from the pending store"));
                        }
                    }
                    Disposition::ConsumeNow => {
                        if !pending.consume(&rid) {
                            return Err(format!("request {rid} disappeared from the pending store"));
                        }
                    }
                }
                Ok(VerifiedResponse {
                    outcome: ApproveOutcome::Allowed {
                        rid,
                        vault,
                        entry,
                        field,
                        once,
                        until,
                        has_unlock_response: answer.is_some(),
                    },
                    kind: record.kind,
                })
            }
            Decision::Deny { reason } => {
                nonces
                    .save()
                    .map_err(|e| format!("could not persist the replay store: {e}"))?;
                pending.deny(&rid);
                Ok(VerifiedResponse {
                    outcome: ApproveOutcome::Denied {
                        rid,
                        vault,
                        entry,
                        field,
                        reason: reason.clone(),
                    },
                    kind: record.kind,
                })
            }
        }
    })
    .map_err(|e| format!("could not update the pending-request store: {e}"))?
}

/// [`verify_response`] leaving the request granted and ignoring any
/// answer. The binary's one caller — `passlane approve --response` —
/// hands the answer to the session agent instead; this is the shape the
/// tests use for a plain approval.
#[cfg(test)]
pub fn approve_response(dir: &std::path::Path, blob: &str) -> Result<ApproveOutcome, String> {
    verify_response(dir, blob, Disposition::Grant, &|_| Ok(())).map(|verified| verified.outcome)
}

// ---------------------------------------------------------------------------
// Enrollment (`passlane approvals enroll`, SPEC §6)
// ---------------------------------------------------------------------------

/// The page's WebAuthn coordinates derived from its base URL: the origin
/// the client data must carry and the RP id whose hash the authenticator
/// data must contain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageOrigin {
    pub rp_id: String,
    pub origin: String,
}

/// Derive [`PageOrigin`] from a page base URL. Only `https` pages can host
/// WebAuthn, so anything else is rejected before any ceremony starts. The
/// host is lower-cased and an explicit `:443` dropped, matching how
/// browsers normalize `clientDataJSON.origin` — a verbatim pin of
/// `https://Host:443` would never match the assertion origin.
pub fn page_origin(page: &str) -> Result<PageOrigin, String> {
    let rest = page
        .strip_prefix("https://")
        .ok_or_else(|| format!("the approval page must be an https URL: {page}"))?;
    let host_port = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .trim_end_matches('/');
    if host_port.is_empty() || host_port.contains('@') {
        return Err(format!("the approval page URL has no usable host: {page}"));
    }
    // Canonicalize: lower-case host, drop the default https port (origins
    // keep non-standard ports; the RP id is the registrable host alone).
    let host = host_port.to_ascii_lowercase();
    let (host, port) = match host.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => (h, Some(p)),
        _ => (host.as_str(), None),
    };
    if host.is_empty() || host.contains('[') {
        return Err(format!("the approval page URL has no usable host: {page}"));
    }
    let origin = match port {
        Some(p) if p != "443" => format!("https://{host}:{p}"),
        _ => format!("https://{host}"),
    };
    Ok(PageOrigin {
        rp_id: host.to_string(),
        origin,
    })
}

/// A fresh 16-byte enrollment nonce, hex.
pub fn generate_enrollment_nonce() -> String {
    use rand::RngCore;
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    passlane_approval::encoding::hex_encode(&nonce)
}

/// The enrollment blob the page pastes back (all strings exactly as the
/// page produces them; the assertion field names match the crate's wire
/// representation, SPEC §3).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct EnrollmentBlob {
    /// Blob format version; must be 1.
    pub v: u8,
    /// The page's ECDH public key, 65-byte hex SEC1.
    pub enc_pub: String,
    /// The passkey's credential public key, base64url CBOR COSE_Key
    /// (verbatim from `attestedCredentialData`).
    pub cose_key: String,
    /// The binding assertion over `SHA-256(nonce ‖ enc_pub)`.
    pub assertion: WebauthnAssertion,
}

/// Verify an enrollment blob against the ceremony nonce, the page origin
/// and **this CLI's own identity keys**, returning the two keys to pin
/// (`enc_pub`, `sig_pub`, both hex SEC1).
///
/// Verification is the SPEC §6 binding ceremony: the passkey must have
/// signed (with user presence) the challenge
/// `SHA-256(enrollment_nonce ‖ ECDH_public_key ‖ cli_enc_pub ‖
/// cli_sig_pub)` on the page's origin — the signature vouches that this
/// exact ECDH key belongs to this passkey's owner, and covering this
/// CLI's keys means a relay that swapped the link's key material cannot
/// elicit an assertion the genuine CLI will accept (the challenge is
/// recomputed from `cli_identity`, never from the link).
pub fn verify_enrollment(
    blob_json: &str,
    enrollment_nonce: &str,
    origin: &PageOrigin,
    cli_identity: &IdentityKeys,
) -> Result<(String, String), String> {
    let blob: EnrollmentBlob = serde_json::from_str(blob_json)
        .map_err(|e| format!("the enrollment blob is not valid JSON: {e}"))?;
    if blob.v != 1 {
        return Err(format!(
            "unsupported enrollment blob version {}; expected 1",
            blob.v
        ));
    }
    let nonce = passlane_approval::encoding::hex_decode(enrollment_nonce)
        .map_err(|e| format!("internal: the enrollment nonce is invalid: {e}"))?;
    let enc_bytes = passlane_approval::encoding::hex_decode(&blob.enc_pub)
        .map_err(|e| format!("the ECDH public key is not valid hex: {e}"))?;
    let enc_key = PublicKey::from_bytes(&enc_bytes)
        .map_err(|e| format!("the ECDH public key is not a valid P-256 point: {e}"))?;

    let cose_bytes = passlane_approval::encoding::base64url_decode(&blob.cose_key)
        .map_err(|e| format!("the COSE key is not valid base64url: {e}"))?;
    let cose = cose::parse_cose_ec2_p256(&cose_bytes)
        .map_err(|e| format!("the passkey public key is not a valid ES256 COSE key: {e}"))?;
    let sig_sec1 = cose.to_sec1();
    let sig_key = PublicKey::from_bytes(&sig_sec1)
        .map_err(|e| format!("the passkey public key is not a valid P-256 point: {e}"))?;

    let challenge = passlane_approval::webauthn::enrollment_challenge(
        &nonce,
        &enc_key.0,
        &cli_identity.encryption_public(),
        &cli_identity.verifying_key().to_sec1_bytes(),
    );
    let verifying = sig_key
        .verifying_key()
        .map_err(|e| format!("the passkey public key is unusable: {e}"))?;
    passlane_approval::webauthn::verify_assertion(
        &verifying,
        &origin.rp_id,
        &origin.origin,
        &blob.assertion,
        &challenge,
    )
    .map_err(|e| {
        // The challenge covers the nonce, the page's ECDH key, and both
        // CLI keys, so a mismatch does not by itself establish *which*
        // input differed: a stale link/tab is the common benign cause,
        // but substituted key material lands here too (the relay-swap
        // test reaches this branch with matching link ids). Describe the
        // failure, list the causes, and give a recovery path that works:
        // this process exits on error and its nonce dies with it, so the
        // old link can never produce an acceptable blob again.
        if e.to_string().contains("challenge mismatch") {
            format!(
                "the passkey binding assertion failed: the page's signature does not \
                 match this enrollment (challenge mismatch). This terminal's link id is \
                 '{}' — the page must have shown the same id, opened from THIS run's \
                 link. Likely causes: the page tab was from an earlier 'passlane \
                 approvals enroll' run (or the blob was pasted into a different \
                 invocation), or the enrollment used different key material than this \
                 link carried (a substituted link). Recover by starting fresh: re-run \
                 the same command (keeping any --page option), open the newly printed \
                 link, and paste the new blob into that invocation.",
                &enrollment_nonce.chars().take(8).collect::<String>()
            )
        } else {
            format!("the passkey binding assertion failed: {e}")
        }
    })?;

    Ok((
        passlane_approval::encoding::hex_encode(&enc_key.0),
        passlane_approval::encoding::hex_encode(&sig_key.0),
    ))
}

/// Pin an enrolled approver (idempotent per label: re-enrolling a label
/// replaces its pin). The whole load-mutate-save span holds a stable
/// sidecar lock (`approval_peers.json.lock`), so concurrent enrollment
/// and removal cannot lose each other's writes.
pub fn pin_approver(
    dir: &std::path::Path,
    pin: PeerPin,
    page_base: Option<&str>,
) -> Result<(), String> {
    let _guard = PeersLock::take(dir)?;
    let mut peers = load_peers_pinned(dir)?;
    peers.retain(|p| p.label != pin.label);
    if let Some(base) = page_base
        && let Ok(kid) = pin.enc_kid()
    {
        let _ = remember_page_base(dir, &kid, base);
    }
    peers.push(pin);
    store_peers(dir, &peers)
}

/// Remove a pinned approver by label (same locked transaction as
/// [`pin_approver`]).
pub fn unpin_approver(dir: &std::path::Path, label: &str) -> Result<bool, String> {
    let _guard = PeersLock::take(dir)?;
    let mut peers = load_peers_pinned(dir)?;
    let before = peers.len();
    let removed: Vec<PeerPin> = peers.iter().filter(|p| p.label == label).cloned().collect();
    peers.retain(|p| p.label != label);
    if peers.len() == before {
        return Ok(false);
    }
    // Forget the remembered page base alongside the pin.
    if !removed.is_empty() {
        let mut map = load_page_bases(dir);
        let changed = removed
            .iter()
            .filter_map(|p| p.enc_kid().ok())
            .any(|kid| map.remove(&kid).is_some());
        if changed {
            let _ = remember_page_map(dir, &map);
        }
    }
    store_peers(dir, &peers)?;
    Ok(true)
}

fn remember_page_map(
    dir: &std::path::Path,
    map: &std::collections::HashMap<String, String>,
) -> Result<(), String> {
    std::fs::create_dir_all(dir)
        .and_then(|()| {
            let bytes =
                serde_json::to_vec(map).map_err(|e| std::io::Error::other(e.to_string()))?;
            let tmp = dir.join(format!("{PAGES_FILENAME}.tmp"));
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            use std::io::Write;
            let mut file = options.open(&tmp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            std::fs::rename(&tmp, dir.join(PAGES_FILENAME))
        })
        .map_err(|e| format!("could not persist the page base URL: {e}"))
}

/// Exclusive cross-process lock over the pinned-peers file, held for the
/// guard's lifetime. The lock sits on a stable sidecar file because the
/// data file is rewritten in place.
struct PeersLock(#[allow(dead_code)] std::fs::File);

impl PeersLock {
    fn take(dir: &std::path::Path) -> Result<Self, String> {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("could not access the approvals directory: {e}"))?;
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .read(true)
            .open(dir.join("approval_peers.json.lock"))
            .map_err(|e| format!("could not lock the peers store: {e}"))?;
        fs4::FileExt::lock(&lock).map_err(|e| format!("could not lock the peers store: {e}"))?;
        Ok(Self(lock))
    }
}

// -- test seams: a mocked Phase 0 approver shared by the ask-flow tests --

/// A mocked approval page: an ECDH identity for encryption plus a local
/// ECDSA key standing in for the WebAuthn passkey. Returns the pin to
/// trust it with and the keys to act it with.
#[cfg(test)]
pub(crate) fn mock_page() -> (PeerPin, IdentityKeys, p256::ecdsa::SigningKey) {
    let page = IdentityKeys::generate(&mut OsRng).unwrap();
    let passkey = {
        use rand::RngCore;
        let mut scalar = zeroize::Zeroizing::new([0u8; 32]);
        loop {
            OsRng.fill_bytes(&mut scalar[..]);
            if let Ok(k) = p256::ecdsa::SigningKey::from_slice(scalar.as_slice()) {
                break k;
            }
        }
    };
    let pin = PeerPin {
        label: "approval-page".into(),
        enc_pub: passlane_approval::encoding::hex_encode(&page.encryption_public()),
        sig_pub: passlane_approval::encoding::hex_encode(&passkey.verifying_key().to_sec1_bytes()),
        paired_at: now_secs(),
        webauthn: Some(passlane_approval::keys::WebauthnPin {
            rp_id: crate::approvals::MOCK_PAGE_RP_ID.into(),
            origin: format!("https://{}", crate::approvals::MOCK_PAGE_RP_ID),
        }),
    };
    (pin, page, passkey)
}

/// The mock page's WebAuthn coordinates (kept in sync with
/// [`mock_page_response`]).
#[cfg(test)]
pub(crate) const MOCK_PAGE_RP_ID: &str = "page.test";

/// Build the mocked page's WebAuthn-signed Allow response for a request
/// rid, exactly the way the static page does (SPEC §3/§6): seal_webauthn →
/// passkey assertion over the transcript challenge → attach.
#[cfg(test)]
pub(crate) fn mock_page_response(
    cli: &IdentityKeys,
    page: &IdentityKeys,
    passkey: &p256::ecdsa::SigningKey,
    request_rid: &str,
    decision: Decision,
) -> Envelope {
    mock_page_answer(cli, page, passkey, request_rid, decision, None, Scope::Once)
}

/// [`mock_page_response`] answering a challenge-bearing request: the
/// Allow carries the 20-byte HMAC-SHA1 `answer`, with the given scope.
#[cfg(test)]
pub(crate) fn mock_page_answer(
    cli: &IdentityKeys,
    page: &IdentityKeys,
    passkey: &p256::ecdsa::SigningKey,
    request_rid: &str,
    decision: Decision,
    answer: Option<[u8; 20]>,
    scope: Scope,
) -> Envelope {
    mock_page_answer_at(
        cli,
        page,
        passkey,
        request_rid,
        decision,
        answer,
        scope,
        now_secs(),
    )
}

/// [`mock_page_answer`] sealed at an explicit time — a blob whose
/// envelope is already expired, for the rejected-paste paths.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn mock_page_answer_at(
    cli: &IdentityKeys,
    page: &IdentityKeys,
    passkey: &p256::ecdsa::SigningKey,
    request_rid: &str,
    decision: Decision,
    answer: Option<[u8; 20]>,
    scope: Scope,
    now: u64,
) -> Envelope {
    let cli_pin = PeerPin::new(
        "cli",
        PublicKey(cli.encryption_public()),
        PublicKey::from_bytes(&cli.verifying_key().to_sec1_bytes()).unwrap(),
        0,
    );
    let (pending, challenge) = passlane_approval::envelope::seal_webauthn(
        &mut OsRng,
        page,
        &cli_pin,
        Body::ApprovalResponse {
            decision,
            scope,
            response: answer.map(|bytes| passlane_approval::message::SecretHex::from_bytes(&bytes)),
        },
        request_rid,
        now,
        &Policy::default(),
    )
    .unwrap();

    // The passkey (a local ECDSA key stands in for the authenticator)
    // signs the assertion over the transcript challenge.
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use sha2::{Digest, Sha256};
    let rp_hash = Sha256::digest(MOCK_PAGE_RP_ID.as_bytes());
    let mut auth_data = Vec::with_capacity(37);
    auth_data.extend_from_slice(&rp_hash);
    auth_data.push(0x01); // UP flag
    auth_data.extend_from_slice(&0u32.to_be_bytes());
    let client_data_json = format!(
        r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"https://{MOCK_PAGE_RP_ID}"}}"#
    );
    let mut digest = Sha256::new();
    digest.update(&auth_data);
    digest.update(Sha256::digest(client_data_json.as_bytes()));
    let sig: p256::ecdsa::Signature = passkey.sign_prehash(&digest.finalize()).unwrap();
    let assertion = WebauthnAssertion::from_raw(
        &auth_data,
        client_data_json.as_bytes(),
        sig.to_der().as_bytes(),
    );
    passlane_approval::envelope::attach_webauthn_assertion(pending, assertion).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use passlane_approval::keys::PeerPin;

    #[test]
    fn approve_link_carries_the_envelope_in_the_fragment_only() {
        let link = approve_link("https://page.example", "UExBUA");
        assert_eq!(link, "https://page.example/approve.html#UExBUA");
        // Fragment-only transport: nothing before the '#'.
        let (before, fragment) = link.split_once('#').unwrap();
        assert_eq!(fragment, "UExBUA");
        assert!(!before.contains("UExBUA"));
    }

    #[test]
    fn enroll_link_carries_the_nonce_and_cli_keys() {
        assert_eq!(
            enroll_link("https://page.example", "aabb", "04cd", "05ef"),
            "https://page.example/enroll.html#n=aabb&c=04cd&s=05ef"
        );
    }

    #[test]
    fn page_origin_parsing() {
        let o = page_origin("https://approve.passlane.app").unwrap();
        assert_eq!(o.rp_id, "approve.passlane.app");
        assert_eq!(o.origin, "https://approve.passlane.app");

        // Paths/ports: rp id is the registrable host, origin keeps the port.
        let o = page_origin("https://local.test:8443/enroll").unwrap();
        assert_eq!(o.rp_id, "local.test");
        assert_eq!(o.origin, "https://local.test:8443");

        // Browsers normalize clientDataJSON origins: the default https
        // port is dropped and hosts are lower-cased, so the pin must be
        // canonical or assertion origin checks would never match.
        let o = page_origin("https://APPROVE.Passlane.APP:443").unwrap();
        assert_eq!(o.origin, "https://approve.passlane.app");
        assert_eq!(o.rp_id, "approve.passlane.app");

        // WebAuthn needs https.
        assert!(page_origin("http://insecure.example").is_err());
        assert!(page_origin("https://").is_err());
        assert!(page_origin("https://user@host/").is_err());
    }

    #[test]
    fn qr_renders_quiet_zoned_square_text() {
        let qr = render_qr("https://approve.passlane.app/approve.html#UExBUA").unwrap();
        let lines: Vec<&str> = qr.lines().collect();
        // Quiet zone of 4 modules = 2 leading/trailing space-only lines.
        assert!(lines.len() > 8, "a QR with quiet zone has padding rows");
        assert!(lines.iter().all(|l| !l.is_empty()));
        // All lines same width (square modules).
        let width = lines[0].chars().count();
        assert!(lines.iter().all(|l| l.chars().count() == width));
        // Contains dark modules.
        assert!(qr.contains('█') || qr.contains('▀') || qr.contains('▄'));
        // Not encodable input is an error, not a panic.
        assert!(render_qr(&"x".repeat(10_000)).is_err());
    }

    #[test]
    fn generate_enrollment_nonce_is_fresh_hex() {
        let a = generate_enrollment_nonce();
        let b = generate_enrollment_nonce();
        assert_eq!(a.len(), 32, "16 bytes as hex");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    /// The full Phase 0 ask loop against a mocked page/approver:
    /// enroll → emit → (approver decrypts and answers) → approve → grant →
    /// the ask flow's grant consumption releases the entry, exactly once.
    #[test]
    fn emission_to_grant_roundtrip_with_mocked_approver() {
        let state = tempfile::tempdir().unwrap();
        let dir = state.path();
        {
            // -- enroll: pin a page with an ECDH key and a passkey stand-in --
            let (pin, page, passkey) = mock_page();
            pin_approver(dir, pin, None).unwrap();

            // -- emit: the ask flow seals a request to the pinned page --
            let emitted = emit_approval_request(
                dir,
                "default",
                "GitHub",
                "uuid-github",
                "password",
                "test-user",
            )
            .expect("emission succeeds with a pinned approver");
            assert_eq!(emitted.rid.len(), 32);
            assert!(emitted.link.contains("/approve.html#"));
            assert!(emitted.link.ends_with(&emitted.envelope));

            // The link's fragment IS the envelope, and the page can parse
            // and open it with the CLI's pinned keys.
            let fragment = emitted.link.split('#').nth(1).unwrap();
            assert_eq!(fragment, emitted.envelope);
            let envelope = Envelope::from_base64url(fragment).unwrap();
            let cli = load_identity(dir).unwrap();
            let cli_pin = PeerPin::new(
                "cli",
                PublicKey(cli.encryption_public()),
                PublicKey::from_bytes(&cli.verifying_key().to_sec1_bytes()).unwrap(),
                0,
            );
            let mut nonces = passlane_approval::replay::InMemoryNonceStore::default();
            let opened = passlane_approval::envelope::open(
                &page,
                &[cli_pin],
                &envelope,
                now_secs() + 1,
                &Policy::default(),
                &mut nonces,
            )
            .unwrap();
            let Body::ApprovalRequest { operation, .. } = &*opened else {
                panic!("expected approval request");
            };
            assert!(matches!(
                operation,
                Operation::Reveal {
                    entry,
                    field
                } if entry == "GitHub" && field == "password"
            ));

            // -- the page answers: seal_webauthn + passkey assertion --
            let answer = mock_page_response(&cli, &page, &passkey, &emitted.rid, Decision::Allow);

            // -- approve: verification turns it into a grant --
            let outcome = approve_response(dir, &answer.to_base64url()).unwrap();
            let ApproveOutcome::Allowed {
                rid,
                vault,
                entry,
                field,
                once,
                ..
            } = outcome
            else {
                panic!("expected Allow");
            };
            assert_eq!(rid, emitted.rid);
            assert_eq!(
                (vault.as_str(), entry.as_str(), field.as_str()),
                ("default", "GitHub", "password")
            );
            assert!(once, "a Scope::Once request grants a single reveal");

            // -- the ask flow consumes the grant, exactly once --
            assert_eq!(
                consume_grant(dir, "default", "uuid-github", "password"),
                Some(rid.clone())
            );
            assert_eq!(
                consume_grant(dir, "default", "uuid-github", "password"),
                None
            );

            // -- presenting the same blob again is refused: the request
            //    was granted and used --
            let err = approve_response(dir, &answer.to_base64url()).unwrap_err();
            assert!(err.contains("already approved"), "{err}");
        }
    }

    #[test]
    fn replayed_response_is_rejected_across_invocations() {
        let state = tempfile::tempdir().unwrap();
        let dir = state.path();
        {
            let (pin, page, passkey) = mock_page();
            pin_approver(dir, pin, None).unwrap();
            let cli = load_identity(dir).unwrap();
            let emitted = emit_approval_request(
                dir,
                "default",
                "GitHub",
                "uuid-github",
                "password",
                "test-user",
            )
            .unwrap();
            let answer = mock_page_response(&cli, &page, &passkey, &emitted.rid, Decision::Allow);

            // The response was already consumed by another process (the
            // session agent relayed it once): its nonce is in the shared
            // file-backed store before approve runs.
            {
                let mut nonces =
                    passlane_approval::replay::FileNonceStore::load(&nonce_store_path(dir))
                        .unwrap();
                let peers = load_peers_pinned(dir).unwrap();
                passlane_approval::envelope::open(
                    &load_identity(dir).unwrap(),
                    &peers,
                    &answer,
                    now_secs(),
                    &Policy::default(),
                    &mut nonces,
                )
                .unwrap();
                nonces.save().unwrap();
            }

            // approve sees the replay and refuses — "the CLI proceeds
            // exactly once" (issue acceptance criteria).
            let err = approve_response(dir, &answer.to_base64url()).unwrap_err();
            assert!(
                err.contains("replayed") || err.contains("failed verification"),
                "{err}"
            );

            // And the request is still pending: nothing was released.
            let pending = PendingStore::load(dir).unwrap();
            assert_eq!(pending.records()[0].state, RequestState::Pending);
        }
    }

    #[test]
    fn second_presentation_of_the_same_response_is_refused() {
        let state = tempfile::tempdir().unwrap();
        let dir = state.path();
        {
            let (pin, page, passkey) = mock_page();
            pin_approver(dir, pin, None).unwrap();
            let cli = load_identity(dir).unwrap();
            let emitted = emit_approval_request(
                dir,
                "default",
                "GitHub",
                "uuid-github",
                "password",
                "test-user",
            )
            .unwrap();
            let answer = mock_page_response(&cli, &page, &passkey, &emitted.rid, Decision::Allow);

            assert!(approve_response(dir, &answer.to_base64url()).is_ok());
            // The same blob pasted again: the request is already resolved.
            let err = approve_response(dir, &answer.to_base64url()).unwrap_err();
            assert!(err.contains("already approved"), "{err}");
        }
    }

    #[test]
    fn deny_records_refusal_and_never_grants() {
        let state = tempfile::tempdir().unwrap();
        let dir = state.path();
        {
            let (pin, page, passkey) = mock_page();
            pin_approver(dir, pin, None).unwrap();
            let cli = load_identity(dir).unwrap();
            let emitted = emit_approval_request(
                dir,
                "default",
                "prod-db",
                "uuid-prod",
                "password",
                "test-user",
            )
            .unwrap();
            let answer = mock_page_response(
                &cli,
                &page,
                &passkey,
                &emitted.rid,
                Decision::Deny {
                    reason: Some("not now".into()),
                },
            );

            let outcome = approve_response(dir, &answer.to_base64url()).unwrap();
            assert!(matches!(outcome, ApproveOutcome::Denied { .. }));
            assert_eq!(consume_grant(dir, "default", "uuid-prod", "password"), None);

            // A later Allow for the same rid cannot resurrect it.
            let allow = mock_page_response(&cli, &page, &passkey, &emitted.rid, Decision::Allow);
            let err = approve_response(dir, &allow.to_base64url()).unwrap_err();
            assert!(err.contains("already denied"), "{err}");
        }
    }

    #[test]
    fn response_for_unknown_rid_is_refused() {
        let state = tempfile::tempdir().unwrap();
        let dir = state.path();
        {
            let (pin, page, _passkey) = mock_page();
            pin_approver(dir, pin, None).unwrap();
            let cli = load_identity(dir).unwrap();
            let cli_pin = PeerPin::new(
                "cli",
                PublicKey(cli.encryption_public()),
                PublicKey::from_bytes(&cli.verifying_key().to_sec1_bytes()).unwrap(),
                0,
            );
            // A response echoing a rid nothing requested.
            let foreign = passlane_approval::envelope::seal_reply(
                &mut OsRng,
                &page,
                &cli_pin,
                Body::ApprovalResponse {
                    decision: Decision::Allow,
                    scope: Scope::Once,
                    response: None,
                },
                &"f".repeat(32),
                now_secs(),
                &Policy::default(),
            )
            .unwrap();
            let err = approve_response(dir, &foreign.to_base64url()).unwrap_err();
            assert!(err.contains("no pending approval request"), "{err}");
        }
    }

    #[test]
    fn emission_without_a_pinned_approver_fails_with_guidance() {
        let state = tempfile::tempdir().unwrap();
        let dir = state.path();
        {
            let err =
                emit_approval_request(dir, "default", "GitHub", "uuid-github", "password", "t")
                    .unwrap_err();
            assert!(err.contains("approvals enroll"), "{err}");
        }
    }

    #[test]
    fn reusable_response_cannot_widen_a_once_request() {
        // The page answers a Scope::Once request with Scope::Timed: the
        // response verifies cryptographically, but the grant must be
        // refused — one approval releases exactly one reveal.
        let state = tempfile::tempdir().unwrap();
        let dir = state.path();
        {
            let (pin, page, passkey) = mock_page();
            pin_approver(dir, pin, None).unwrap();
            let cli = load_identity(dir).unwrap();
            let emitted = emit_approval_request(
                dir,
                "default",
                "GitHub",
                "uuid-github",
                "password",
                "test-user",
            )
            .unwrap();

            // Build the Allow{Timed} response the way a hostile or buggy
            // responder would.
            let cli_pin = PeerPin::new(
                "cli",
                PublicKey(cli.encryption_public()),
                PublicKey::from_bytes(&cli.verifying_key().to_sec1_bytes()).unwrap(),
                0,
            );
            let (pending, challenge) = passlane_approval::envelope::seal_webauthn(
                &mut OsRng,
                &page,
                &cli_pin,
                Body::ApprovalResponse {
                    decision: Decision::Allow,
                    scope: Scope::Timed { seconds: 900 },
                    response: None,
                },
                &emitted.rid,
                now_secs(),
                &Policy::default(),
            )
            .unwrap();
            use p256::ecdsa::signature::hazmat::PrehashSigner;
            use sha2::{Digest, Sha256};
            let rp_hash = Sha256::digest(MOCK_PAGE_RP_ID.as_bytes());
            let mut auth_data = Vec::with_capacity(37);
            auth_data.extend_from_slice(&rp_hash);
            auth_data.push(0x01);
            auth_data.extend_from_slice(&0u32.to_be_bytes());
            let client_data_json = format!(
                r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"https://{MOCK_PAGE_RP_ID}"}}"#
            );
            let mut digest = Sha256::new();
            digest.update(&auth_data);
            digest.update(Sha256::digest(client_data_json.as_bytes()));
            let sig: p256::ecdsa::Signature = passkey.sign_prehash(&digest.finalize()).unwrap();
            let env = passlane_approval::envelope::attach_webauthn_assertion(
                pending,
                WebauthnAssertion::from_raw(
                    &auth_data,
                    client_data_json.as_bytes(),
                    sig.to_der().as_bytes(),
                ),
            )
            .unwrap();

            let err = approve_response(dir, &env.to_base64url()).unwrap_err();
            assert!(
                err.contains("single-use approval") && err.contains("reusable scope"),
                "{err}"
            );
            // Nothing was released.
            assert_eq!(
                consume_grant(dir, "default", "uuid-github", "password"),
                None
            );
        }
    }

    #[test]
    fn path_prefixed_page_base_is_remembered_for_links() {
        // A page deployed under a path: enroll pins it, and emission
        // builds links under that exact base (the WebAuthn origin cannot
        // carry the path).
        let state = tempfile::tempdir().unwrap();
        let dir = state.path();
        {
            let (pin, _page, _passkey) = mock_page();
            pin_approver(dir, pin, Some("https://example.com/passlane/")).unwrap();
            let emitted =
                emit_approval_request(dir, "default", "GitHub", "uuid-github", "password", "t")
                    .unwrap();
            assert!(
                emitted
                    .link
                    .starts_with("https://example.com/passlane/approve.html#"),
                "{}",
                emitted.link
            );

            // Forgetting the approver forgets the base too.
            unpin_approver(dir, "approval-page").unwrap();
            assert!(load_page_bases(dir).is_empty());
        }
    }

    #[test]
    fn unpin_and_repin_by_label() {
        let state = tempfile::tempdir().unwrap();
        let dir = state.path();
        {
            let (pin, _page, _passkey) = mock_page();
            pin_approver(dir, pin.clone(), None).unwrap();
            assert_eq!(load_peers_pinned(dir).unwrap(), vec![pin.clone()]);
            // Re-enrolling the same label replaces, not duplicates.
            pin_approver(dir, pin.clone(), None).unwrap();
            assert_eq!(load_peers_pinned(dir).unwrap().len(), 1);
            assert!(unpin_approver(dir, "approval-page").unwrap());
            assert!(!unpin_approver(dir, "approval-page").unwrap());
            assert!(load_peers_pinned(dir).unwrap().is_empty());
        }
    }

    /// Emit a challenge-bearing request to the pinned page, the way the
    /// phone-held-key transport does.
    fn emit_challenge(
        dir: &std::path::Path,
        kind: RequestKind,
        challenge: &[u8; 32],
    ) -> EmittedRequest {
        let peer = load_peers_pinned(dir).unwrap().remove(0);
        let hex = passlane_approval::encoding::hex_encode(challenge);
        let operation = match kind {
            RequestKind::Unlock => Operation::Unlock,
            RequestKind::Save => Operation::Save,
            RequestKind::EnrollKey => Operation::EnrollKey,
            RequestKind::Reveal => panic!("a reveal carries no challenge"),
        };
        let body = challenge_request_body("default", "default", operation, challenge, "test-user")
            .unwrap();
        emit_to(
            dir,
            &peer,
            RequestTarget::challenge("default", kind, &hex),
            body,
            None,
        )
        .unwrap()
    }

    #[test]
    fn challenge_request_carries_the_challenge_encrypted() {
        let state = tempfile::tempdir().unwrap();
        let dir = state.path();
        {
            let (pin, page, _passkey) = mock_page();
            pin_approver(dir, pin, None).unwrap();
            let cli = load_identity(dir).unwrap();
            let challenge = [0x5fu8; 32];
            let emitted = emit_challenge(dir, RequestKind::Save, &challenge);

            // The link's fragment IS the envelope, and the page can parse
            // and open it with the CLI's pinned keys.
            let fragment = emitted.link.split('#').nth(1).unwrap();
            assert_eq!(fragment, emitted.envelope);
            let envelope = Envelope::from_base64url(fragment).unwrap();
            let mut nonces = passlane_approval::replay::InMemoryNonceStore::default();
            let opened = passlane_approval::envelope::open(
                &page,
                &[PeerPin::new(
                    "cli",
                    PublicKey(cli.encryption_public()),
                    PublicKey::from_bytes(&cli.verifying_key().to_sec1_bytes()).unwrap(),
                    0,
                )],
                &envelope,
                now_secs() + 1,
                &Policy::default(),
                &mut nonces,
            )
            .unwrap();
            let Body::ApprovalRequest {
                challenge: c,
                operation,
                ..
            } = &*opened
            else {
                panic!()
            };
            assert_eq!(
                c.as_ref().unwrap().as_bytes().unwrap().as_slice(),
                challenge
            );
            assert_eq!(*operation, Operation::Save);
            // The challenge never appears in the link bytes.
            assert!(!emitted.link.contains("5f5f"));

            // The pending record knows what it is asking and for which
            // challenge, and can show the link again.
            let pending = PendingStore::load(dir).unwrap();
            let record = &pending.records()[0];
            assert_eq!(record.kind, RequestKind::Save);
            assert_eq!(record.challenge.as_deref(), Some("5f".repeat(32).as_str()));
            assert_eq!(record.link.as_deref(), Some(emitted.link.as_str()));
            assert!(record.entry.is_empty() && record.field.is_empty());
        }
    }

    #[test]
    fn challenge_request_body_refuses_a_reveal_and_a_short_challenge() {
        assert!(
            challenge_request_body(
                "v",
                "v",
                Operation::Reveal {
                    entry: "e".into(),
                    field: "f".into()
                },
                &[0u8; 32],
                "r"
            )
            .is_err()
        );
        assert!(
            challenge_request_body("v", "v", Operation::Unlock, &[0u8; 20], "r").is_err(),
            "the challenge is the 32-byte KDF seed"
        );
        assert!(challenge_request_body("v", "v", Operation::EnrollKey, &[7u8; 32], "r").is_ok());
    }

    #[test]
    fn a_response_from_another_pinned_approver_is_refused() {
        // The request is sealed to one approver; with several pinned,
        // another one holding the link must not be able to answer in the
        // holder's place — with Save/Unlock material of its own choosing.
        let state = tempfile::tempdir().unwrap();
        let dir = state.path();
        {
            let (pin, _page, _passkey) = mock_page();
            let expected_kid = pin.enc_kid().unwrap();
            pin_approver(dir, pin, None).unwrap();
            // A second, different approver, also pinned (pinning replaces
            // by label, so it needs its own).
            let (mut other_pin, other_page, other_passkey) = mock_page();
            other_pin.label = "second-page".into();
            let other_kid = other_pin.enc_kid().unwrap();
            assert_ne!(other_kid, expected_kid);
            pin_approver(dir, other_pin, None).unwrap();
            let cli = load_identity(dir).unwrap();
            // Emit to the FIRST pin, explicitly — with two pinned, the
            // helper's "remove(0)" pick is whichever loads first.
            let challenge = [0xa1u8; 32];
            let body = challenge_request_body(
                "default",
                "default",
                Operation::Unlock,
                &challenge,
                "test-user",
            )
            .unwrap();
            let peers = load_peers_pinned(dir).unwrap();
            let holder = peers
                .iter()
                .find(|peer| peer.enc_kid().ok().as_deref() == Some(expected_kid.as_str()))
                .expect("the first pin is there")
                .clone();
            let emitted = emit_to(
                dir,
                &holder,
                crate::approvals::RequestTarget::challenge(
                    "default",
                    RequestKind::Unlock,
                    &passlane_approval::encoding::hex_encode(&challenge),
                ),
                body,
                None,
            )
            .unwrap();

            let blob = mock_page_answer(
                &cli,
                &other_page,
                &other_passkey,
                &emitted.rid,
                Decision::Allow,
                Some([0x99u8; 20]),
                Scope::Once,
            )
            .to_base64url();
            let err = verify_response(dir, &blob, Disposition::ConsumeNow, &|_| Ok(()))
                .expect_err("a response from the wrong approver is refused");
            assert!(err.contains("was addressed to approver"), "{err}");
            assert!(
                err.contains(&other_kid),
                "the refusal names who answered: {err}"
            );
            assert!(
                PendingStore::load(dir)
                    .unwrap()
                    .find(&emitted.rid)
                    .unwrap()
                    .state
                    == RequestState::Pending,
                "the request is still pending: nothing was consumed"
            );
            // And the request is still pending: nothing was consumed.
            assert_eq!(
                PendingStore::load(dir)
                    .unwrap()
                    .find(&emitted.rid)
                    .unwrap()
                    .state,
                RequestState::Pending
            );
        }
    }

    #[test]
    fn verified_challenge_response_is_handed_over_and_spent() {
        let state = tempfile::tempdir().unwrap();
        let dir = state.path();
        {
            let (pin, page, passkey) = mock_page();
            pin_approver(dir, pin, None).unwrap();
            let cli = load_identity(dir).unwrap();
            let challenge = [0xa1u8; 32];
            let emitted = emit_challenge(dir, RequestKind::Unlock, &challenge);
            let answer = [0x77u8; 20];
            let blob = mock_page_answer(
                &cli,
                &page,
                &passkey,
                &emitted.rid,
                Decision::Allow,
                Some(answer),
                Scope::Once,
            )
            .to_base64url();

            let handed = std::cell::RefCell::new(Vec::new());
            let verified = verify_response(dir, &blob, Disposition::ConsumeNow, &|handoff| {
                assert_eq!(handoff.rid, emitted.rid);
                assert_eq!(handoff.vault, "default");
                assert_eq!(handoff.kind, RequestKind::Unlock);
                assert_eq!(handoff.challenge, Some("a1".repeat(32).as_str()));
                assert_eq!(handoff.scope, Scope::Once);
                *handed.borrow_mut() = handoff.response.to_vec();
                Ok(())
            })
            .unwrap();
            assert_eq!(
                handed.into_inner(),
                answer,
                "the caller receives the answer through the handoff"
            );
            assert_eq!(verified.kind, RequestKind::Unlock);
            assert!(matches!(
                verified.outcome,
                ApproveOutcome::Allowed {
                    has_unlock_response: true,
                    once: true,
                    ..
                }
            ));

            // Used the moment it arrived: the record is spent, and the
            // same blob presented again says so.
            let pending = PendingStore::load(dir).unwrap();
            assert_eq!(pending.records()[0].state, RequestState::Consumed);
            let err = approve_response(dir, &blob).unwrap_err();
            assert!(err.contains("already approved and used"), "{err}");
        }
    }

    #[test]
    fn a_failed_handoff_leaves_the_response_presentable_again() {
        // `passlane approve --response` hands the answer to the session
        // agent. When the agent refuses it (or is not running), nothing
        // may be recorded: the same blob must still work once it is.
        let state = tempfile::tempdir().unwrap();
        let dir = state.path();
        {
            let (pin, page, passkey) = mock_page();
            pin_approver(dir, pin, None).unwrap();
            let cli = load_identity(dir).unwrap();
            let emitted = emit_challenge(dir, RequestKind::Unlock, &[0x01; 32]);
            let blob = mock_page_answer(
                &cli,
                &page,
                &passkey,
                &emitted.rid,
                Decision::Allow,
                Some([0x42; 20]),
                Scope::Once,
            )
            .to_base64url();

            let err = verify_response(dir, &blob, Disposition::Grant, &|_| {
                Err("nowhere to keep it".to_string())
            })
            .unwrap_err();
            assert!(err.contains("nowhere to keep it"), "{err}");

            // Still pending, and not yet replayed: the blob verifies and
            // hands the same answer over.
            let pending = PendingStore::load(dir).unwrap();
            assert_eq!(pending.records()[0].state, RequestState::Pending);
            let got = std::cell::RefCell::new(Vec::new());
            verify_response(dir, &blob, Disposition::Grant, &|handoff| {
                got.borrow_mut().clear();
                got.borrow_mut().extend_from_slice(handoff.response);
                Ok(())
            })
            .unwrap();
            assert_eq!(got.into_inner(), [0x42u8; 20]);
            let pending = PendingStore::load(dir).unwrap();
            assert!(matches!(
                pending.records()[0].state,
                RequestState::Granted { once: true, .. }
            ));
        }
    }

    #[test]
    fn an_approval_without_an_answer_satisfies_no_challenge_request() {
        let state = tempfile::tempdir().unwrap();
        let dir = state.path();
        {
            let (pin, page, passkey) = mock_page();
            pin_approver(dir, pin, None).unwrap();
            let cli = load_identity(dir).unwrap();
            let emitted = emit_challenge(dir, RequestKind::EnrollKey, &[0x0c; 32]);
            let empty = mock_page_response(&cli, &page, &passkey, &emitted.rid, Decision::Allow)
                .to_base64url();

            let err = approve_response(dir, &empty).unwrap_err();
            assert!(err.contains("carries no challenge response"), "{err}");
            // Nothing was released or spent.
            let pending = PendingStore::load(dir).unwrap();
            assert_eq!(pending.records()[0].state, RequestState::Pending);
            assert_eq!(
                consume_grant(dir, "default", "", ""),
                None,
                "a challenge request never becomes a reveal grant"
            );
        }
    }

    #[test]
    fn a_denied_challenge_request_is_refused_with_its_reason() {
        let state = tempfile::tempdir().unwrap();
        let dir = state.path();
        {
            let (pin, page, passkey) = mock_page();
            pin_approver(dir, pin, None).unwrap();
            let cli = load_identity(dir).unwrap();
            let emitted = emit_challenge(dir, RequestKind::Unlock, &[0x03; 32]);
            let deny = mock_page_response(
                &cli,
                &page,
                &passkey,
                &emitted.rid,
                Decision::Deny {
                    reason: Some("not this vault".into()),
                },
            )
            .to_base64url();
            let verified = verify_response(dir, &deny, Disposition::ConsumeNow, &|_| {
                panic!("a denial hands nothing over")
            })
            .unwrap();
            assert!(matches!(
                verified.outcome,
                ApproveOutcome::Denied {
                    ref reason,
                    ..
                } if reason.as_deref() == Some("not this vault")
            ));
            let pending = PendingStore::load(dir).unwrap();
            assert_eq!(pending.records()[0].state, RequestState::Denied);
        }
    }

    // -- enrollment (SPEC §6) -------------------------------------------------

    /// An enrollment blob with a real binding assertion, built the way the
    /// page builds it: ECDH pub + COSE passkey pub + a passkey signature
    /// over SHA-256(nonce ‖ ECDH pub).
    fn enrollment_blob(nonce_hex: &str, rp_id: &str, origin: &str, cli: &IdentityKeys) -> String {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        use sha2::{Digest, Sha256};

        let page = IdentityKeys::generate(&mut OsRng).unwrap();
        let passkey = {
            use rand::RngCore;
            let mut scalar = zeroize::Zeroizing::new([0u8; 32]);
            loop {
                OsRng.fill_bytes(&mut scalar[..]);
                if let Ok(k) = p256::ecdsa::SigningKey::from_slice(scalar.as_slice()) {
                    break k;
                }
            }
        };
        // COSE {1:2, 3:-7, -1:1, -2:x, -3:y} for the passkey key.
        let pub_bytes = passkey.verifying_key().to_sec1_bytes();
        let mut cose = vec![0xa5];
        cose.extend_from_slice(&[0x01, 0x02, 0x03, 0x26, 0x20, 0x01]);
        cose.extend_from_slice(&[0x21, 0x58, 0x20]);
        cose.extend_from_slice(&pub_bytes[1..33]);
        cose.extend_from_slice(&[0x22, 0x58, 0x20]);
        cose.extend_from_slice(&pub_bytes[33..65]);

        let nonce = passlane_approval::encoding::hex_decode(nonce_hex).unwrap();
        let page_pub = page.encryption_public();
        let challenge = passlane_approval::webauthn::enrollment_challenge(
            &nonce,
            &page_pub,
            &cli.encryption_public(),
            &cli.verifying_key().to_sec1_bytes(),
        );
        let rp_hash = Sha256::digest(rp_id.as_bytes());
        let mut auth_data = Vec::with_capacity(37);
        auth_data.extend_from_slice(&rp_hash);
        auth_data.push(0x01); // UP
        auth_data.extend_from_slice(&0u32.to_be_bytes());
        let client_data_json =
            format!(r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"{origin}"}}"#);
        let mut digest = Sha256::new();
        digest.update(&auth_data);
        digest.update(Sha256::digest(client_data_json.as_bytes()));
        let sig: p256::ecdsa::Signature = passkey.sign_prehash(&digest.finalize()).unwrap();
        let assertion = WebauthnAssertion::from_raw(
            &auth_data,
            client_data_json.as_bytes(),
            sig.to_der().as_bytes(),
        );
        serde_json::json!({
            "v": 1,
            "enc_pub": passlane_approval::encoding::hex_encode(&page_pub),
            "cose_key": passlane_approval::encoding::base64url_encode(&cose),
            "assertion": {
                "authenticator_data": assertion.authenticator_data,
                "client_data_json": assertion.client_data_json,
                "signature": assertion.signature,
            },
        })
        .to_string()
    }

    const ENROLL_NONCE: &str = "0a0b0c0d0e0f00112223334445556667";

    #[test]
    fn enrollment_ceremony_verifies_and_yields_the_pins() {
        let origin = PageOrigin {
            rp_id: "page.test".into(),
            origin: "https://page.test".into(),
        };
        let cli = IdentityKeys::generate(&mut OsRng).unwrap();
        let blob = enrollment_blob(ENROLL_NONCE, &origin.rp_id, &origin.origin, &cli);
        let (enc_pub, sig_pub) = verify_enrollment(&blob, ENROLL_NONCE, &origin, &cli)
            .expect("a genuine ceremony passes");
        assert_eq!(enc_pub.len(), 130, "65 bytes hex");
        assert_eq!(sig_pub.len(), 130);
        // Both keys are valid P-256 points.
        assert!(PublicKey::from_hex(&enc_pub).is_ok());
        assert!(PublicKey::from_hex(&sig_pub).is_ok());
    }

    #[test]
    fn enrollment_rejects_wrong_nonce_origin_and_garbage() {
        let origin = PageOrigin {
            rp_id: "page.test".into(),
            origin: "https://page.test".into(),
        };
        let cli = IdentityKeys::generate(&mut OsRng).unwrap();
        let blob = enrollment_blob(ENROLL_NONCE, &origin.rp_id, &origin.origin, &cli);

        // A different ceremony nonce (the page answered a stale request).
        let err = verify_enrollment(&blob, &"f".repeat(32), &origin, &cli).unwrap_err();
        assert!(
            err.contains("challenge mismatch") && err.contains("Recover by starting fresh"),
            "the mismatch failure must describe the failure and a working recovery: {err}"
        );
        // ...and it must carry this run's link id so the mismatch is
        // diagnosable from the terminal alone.
        assert!(err.contains(&"f".repeat(8)), "{err}");

        // A different origin than the page's real one.
        let other = PageOrigin {
            rp_id: "other.test".into(),
            origin: "https://other.test".into(),
        };
        assert!(verify_enrollment(&blob, ENROLL_NONCE, &other, &cli).is_err());

        // A relay-swapped link: the page bound the ATTACKER's keys into
        // the challenge, so this genuine CLI must refuse the blob.
        let attacker = IdentityKeys::generate(&mut OsRng).unwrap();
        let swapped = enrollment_blob(ENROLL_NONCE, &origin.rp_id, &origin.origin, &attacker);
        let err = verify_enrollment(&swapped, ENROLL_NONCE, &origin, &cli).unwrap_err();
        assert!(err.contains("assertion"), "{err}");

        // Garbage JSON and shape errors.
        assert!(verify_enrollment("not json", ENROLL_NONCE, &origin, &cli).is_err());
        assert!(
            verify_enrollment(
                &blob.replace("\"v\":1", "\"v\":2"),
                ENROLL_NONCE,
                &origin,
                &cli
            )
            .is_err()
        );
        let bad_cose = blob.replace("cose_key", "coseKey"); // missing field
        assert!(verify_enrollment(&bad_cose, ENROLL_NONCE, &origin, &cli).is_err());
    }

    #[test]
    fn page_enrollment_fixture_verifies_in_rust() {
        // A blob produced by the page's real ceremony code (run.mjs drives
        // page/js/enroll.js under node's WebCrypto, committed as a
        // fixture). Verifying it here — recomputing the binding challenge
        // from the CLI's own identity keys — proves both sides derive the
        // identical SHA-256(nonce ‖ ECDH pub ‖ cli_enc ‖ cli_sig).
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("page")
            .join("tests")
            .join("fixtures")
            .join("page-enrollment-v1.json");
        let doc: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("enrollment fixture committed"))
                .expect("fixture is valid JSON");
        let cli = {
            let c = &doc["cli"];
            IdentityKeys::from_bytes(
                &passlane_approval::encoding::hex_decode(c["enc_secret"].as_str().unwrap())
                    .unwrap(),
                &passlane_approval::encoding::hex_decode(c["sig_secret"].as_str().unwrap())
                    .unwrap(),
            )
            .unwrap()
        };
        let origin = PageOrigin {
            rp_id: doc["origin"]["rp_id"].as_str().unwrap().to_string(),
            origin: doc["origin"]["origin"].as_str().unwrap().to_string(),
        };
        let nonce = doc["nonce_hex"].as_str().unwrap();
        let blob = serde_json::to_string(&doc["blob"]).unwrap();

        let (enc_pub, _sig_pub) = verify_enrollment(&blob, nonce, &origin, &cli)
            .expect("the page's enrollment blob verifies with the CLI ceremony");
        assert_eq!(enc_pub, doc["expected"]["enc_pub"].as_str().unwrap());
    }
}
