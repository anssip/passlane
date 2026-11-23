//! `passlane approvals …` (passlane#51): manage the approvers that can
//! answer requests over the link transport.
//!
//! - `enroll` — the SPEC §6 Phase 0 ceremony: print the enrollment link,
//!   the page enrolls its ECDH key + passkey, and the pasted blob is
//!   verified (passkey binding assertion) before the keys are pinned.
//! - `list` / `remove` — pin bookkeeping.
//! - `pending` — the pending-request store, for the owner to see what is
//!   awaiting an answer.

use clap::ArgMatches;

use passlane_approval::keys::{PeerPin, WebauthnPin};
use passlane_core::vault::entities::Error;

use crate::actions::Action;
use crate::approvals::pending::{PendingRequest, RequestKind, RequestState};
use crate::approvals::{self, pending::PendingStore};

pub struct ApprovalsAction {
    subcommand: Subcommand,
}

enum Subcommand {
    Enroll { page: Option<String> },
    List,
    Pending,
    Link { rid: String },
    Remove { label: String },
}

impl ApprovalsAction {
    pub fn new(matches: &ArgMatches) -> Self {
        let subcommand = match matches.subcommand() {
            Some(("enroll", sub)) => Subcommand::Enroll {
                page: sub.get_one::<String>("page").cloned(),
            },
            Some(("list", _)) => Subcommand::List,
            Some(("pending", _)) => Subcommand::Pending,
            Some(("link", sub)) => Subcommand::Link {
                rid: sub.get_one::<String>("RID").cloned().unwrap_or_default(),
            },
            Some(("remove", sub)) => Subcommand::Remove {
                label: sub.get_one::<String>("LABEL").cloned().unwrap_or_default(),
            },
            _ => Subcommand::List,
        };
        Self { subcommand }
    }

    fn run_enroll(page_explicit: Option<String>) -> Result<String, Error> {
        let (pin, _page, enc_kid) = enroll_approver(page_explicit.as_deref())?;
        Ok(format!(
            "Pinned approver '{}' ({}). Approval requests will now be sealed to it; run 'passlane approvals list' to see the pin.",
            pin.label,
            &enc_kid[..enc_kid.len().min(8)],
        ))
    }
    fn run_list() -> Result<String, Error> {
        let peers =
            approvals::load_peers_pinned(&approvals::state_dir()).map_err(|e| Error::new(&e))?;
        if peers.is_empty() {
            return Ok(
                "No approvers pinned. Run 'passlane approvals enroll' to pin the approval page."
                    .to_string(),
            );
        }
        let mut out = String::from("Pinned approvers:\n");
        for peer in &peers {
            let webauthn = peer
                .webauthn
                .as_ref()
                .map(|w| format!(" passkey on {}", w.rp_id))
                .unwrap_or_default();
            let paired =
                chrono::DateTime::from_timestamp(i64::try_from(peer.paired_at).unwrap_or(0), 0)
                    .map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string())
                    .unwrap_or_else(|| peer.paired_at.to_string());
            out.push_str(&format!("  {} (paired {paired},{webauthn})\n", peer.label));
        }
        Ok(out.trim_end().to_string())
    }

    fn run_pending() -> Result<String, Error> {
        // The transaction holds the lock and persists the pruning of dead
        // records; pruning inside the closure means the displayed snapshot
        // is already pruned on the *first* invocation after expiry.
        let store = PendingStore::transaction(&approvals::state_dir(), |store| {
            store.prune(approvals::now_secs());
            store.records().to_vec()
        })
        .map_err(|e| Error::new(&format!("could not load the pending-request store: {e}")))?;
        if store.is_empty() {
            return Ok("No pending approval requests.".to_string());
        }
        let mut out = String::from("Pending approval requests:\n");
        for record in &store {
            let state = match &record.state {
                RequestState::Pending => "awaiting the approver".to_string(),
                RequestState::Granted { once, until } => {
                    if *once {
                        "granted (single use, unconsumed)".to_string()
                    } else {
                        format!("granted (reusable until {until})")
                    }
                }
                RequestState::Consumed => "granted and used".to_string(),
                RequestState::Denied => "denied".to_string(),
            };
            out.push_str(&format!(
                "  {} … {} — {state}\n",
                &record.rid[..record.rid.len().min(8)],
                describe_request(record)
            ));
        }
        Ok(out.trim_end().to_string())
    }

    /// `approvals link <RID>`: the link of a still-pending request, to
    /// relay it again (for a command that is waiting on an answer, or
    /// one whose output was not captured).
    fn run_link(rid: &str) -> Result<String, Error> {
        let records = PendingStore::transaction(&approvals::state_dir(), |store| {
            store.prune(approvals::now_secs());
            store.records().to_vec()
        })
        .map_err(|e| Error::new(&format!("could not load the pending-request store: {e}")))?;
        let matches: Vec<_> = records
            .iter()
            .filter(|record| record.rid.starts_with(rid))
            .collect();
        let [record] = matches.as_slice() else {
            return Err(Error::new(&format!(
                "'{rid}' matches {} pending requests (see 'passlane approvals pending')",
                matches.len()
            )));
        };
        match (&record.state, &record.link) {
            (RequestState::Pending, Some(link)) => Ok(link.clone()),
            (state, _) => Err(Error::new(&format!(
                "request {} is {} — there is nothing left to approve; re-run the command that                  asked to emit a fresh request",
                &record.rid[..record.rid.len().min(8)],
                state_label(state)
            ))),
        }
    }

    fn run_remove(label: &str) -> Result<String, Error> {
        match approvals::unpin_approver(&approvals::state_dir(), label)
            .map_err(|e| Error::new(&e))?
        {
            true => Ok(format!("Removed approver '{label}'.")),
            false => Err(Error::new(&format!(
                "No pinned approver labeled '{label}' (see 'passlane approvals list')"
            ))),
        }
    }
}

/// One line saying what a recorded request asks for.
pub(crate) fn describe_request(record: &PendingRequest) -> String {
    match record.kind {
        RequestKind::Reveal => format!(
            "reveal '{}' of '{}' (vault {})",
            record.field, record.entry, record.vault
        ),
        RequestKind::Unlock => {
            format!("open vault '{}' with its phone-held key", record.vault)
        }
        RequestKind::Save => {
            format!("save vault '{}' with its phone-held key", record.vault)
        }
        RequestKind::EnrollKey => {
            format!("create a phone-held key for vault '{}'", record.vault)
        }
    }
}

/// How a request's state reads in a message.
fn state_label(state: &RequestState) -> &'static str {
    match state {
        RequestState::Pending => "awaiting the approver",
        RequestState::Granted { .. } => "already approved",
        RequestState::Consumed => "already approved and used",
        RequestState::Denied => "denied",
    }
}

/// The enrollment ceremony (SPEC §6): print the link, wait for the page's
/// blob, verify the passkey binding against this CLI's own keys, and pin
/// only once the human confirms both devices show the same code.
///
/// Returns the pin, the page base it was enrolled under, and the pin's
/// encryption key id. Interactive: it prompts. Other commands that need a
/// pinned approver — `hwkey add --phone`, when nothing is pinned yet — run
/// this instead of making the user run `approvals enroll` first.
pub(crate) fn enroll_approver(
    page_explicit: Option<&str>,
) -> Result<(PeerPin, String, String), Error> {
    let page = approvals::page_url(page_explicit);
    let origin = approvals::page_origin(&page).map_err(|e| Error::new(&e))?;

    // 1. Fresh nonce + link + QR. The nonce is single-use and lives
    //    only in this process (SPEC §6); the link also carries this
    //    CLI's public keys — its encryption key (`c`) so the page
    //    knows who to seal approvals to, and its verifying key (`s`)
    //    so the page can check request signatures (fragment-only,
    //    like every link).
    let nonce = approvals::generate_enrollment_nonce();
    let identity = approvals::load_identity(&approvals::state_dir()).map_err(|e| Error::new(&e))?;
    let cli_pub = passlane_approval::encoding::hex_encode(&identity.encryption_public());
    let cli_sig =
        passlane_approval::encoding::hex_encode(&identity.verifying_key().to_sec1_bytes());
    let link = approvals::enroll_link(&page, &nonce, &cli_pub, &cli_sig);
    println!("Open this link on the approval page (scan or paste it):");
    println!("{link}");
    println!(
        "Link id: {} — the page must show the same id before you confirm anything.",
        &nonce[..8]
    );
    print_qr(&link);

    // 2. The page enrolls: ECDH key + passkey, then the binding
    //    assertion over SHA-256(nonce ‖ ECDH public key).
    let blob =
        inquire::Text::new("Paste the enrollment blob the page produced (one line of JSON):")
            .prompt()
            .map_err(|_| Error::new("enrollment aborted: no enrollment blob was pasted"))?;

    let label = inquire::Text::new("Label for this approver:")
        .with_default(&origin.rp_id)
        .prompt()
        .map_err(|_| Error::new("enrollment aborted: no label given"))?;

    // 3. Verify the ceremony before pinning anything. The challenge is
    //    recomputed from THIS CLI's identity keys — never from the
    //    link — so relay-swapped key material cannot pass.
    let (enc_pub, sig_pub) = approvals::verify_enrollment(&blob, &nonce, &origin, &identity)
        .map_err(|e| Error::new(&e))?;

    // 4. The human check (SPEC §5 adapted): both sides display a code
    //    over BOTH parties' keys; the pin is persisted only when the
    //    human confirms they match. A substituted responder (someone
    //    who read the link and raced their own blob in) shows a
    //    different code on the terminal than the genuine page does.
    let page_enc = passlane_approval::encoding::hex_decode(&enc_pub)
        .map_err(|e| Error::new(&format!("the ECDH public key is not valid hex: {e}")))?;
    let page_sig = passlane_approval::encoding::hex_decode(&sig_pub)
        .map_err(|e| Error::new(&format!("the passkey public key is not valid hex: {e}")))?;
    let code = passlane_approval::webauthn::enrollment_confirmation_code(
        &identity.encryption_public(),
        &identity.verifying_key().to_sec1_bytes(),
        &page_enc,
        &page_sig,
    );
    let confirmed = inquire::Confirm::new(&format!(
        "Confirmation code: {code} — does the approval page show the same code?"
    ))
    .with_default(false)
    .prompt()
    .unwrap_or(false);
    if !confirmed {
        return Err(Error::new(
            "Enrollment aborted: the codes did not match, so nothing was pinned. If you \
             suspect a substituted link or blob, compare full key fingerprints instead \
             (see crates/passlane-approval/SPEC.md §5).",
        ));
    }

    let pin = PeerPin {
        label: label.clone(),
        enc_pub,
        sig_pub,
        paired_at: approvals::now_secs(),
        webauthn: Some(WebauthnPin {
            rp_id: origin.rp_id.clone(),
            origin: origin.origin.clone(),
        }),
    };
    let enc_kid = passlane_approval::keys::kid(
        b"enc",
        &pin.enc_pub_bytes()
            .map_err(|e| Error::new(&e.to_string()))?,
    );
    approvals::pin_approver(&approvals::state_dir(), pin.clone(), Some(&page))
        .map_err(|e| Error::new(&e))?;

    Ok((pin, page, enc_kid))
}

/// One line about a phone-held key's holder: its label if it is still
/// pinned, and when it was enrolled. A pinned-approvers file that cannot
/// be read is reported as such, not mistaken for "not pinned".
pub(crate) fn describe_holder(
    phone_key: &crate::vault_registry::PhoneKeyConfig,
    peers: Result<Vec<PeerPin>, String>,
) -> String {
    let who = match peers {
        Ok(peers) => peers
            .iter()
            .find(|peer| peer.enc_kid().ok().as_deref() == Some(phone_key.holder_kid.as_str()))
            .map(|peer| format!("held by '{}'", peer.label))
            .unwrap_or_else(|| {
                format!(
                    "holder {} is NOT pinned (re-pair with 'passlane approvals enroll')",
                    phone_key.holder_kid
                )
            }),
        Err(e) => format!(
            "holder {} (pinned approvers unreadable: {e})",
            phone_key.holder_kid
        ),
    };
    format!(
        "{who}, since {}",
        chrono::DateTime::from_timestamp(phone_key.enrolled_at as i64, 0)
            .map(|t| t.format("%Y-%m-%d").to_string())
            .unwrap_or_else(|| phone_key.enrolled_at.to_string())
    )
}

/// The QR goes to stderr: it is for the human at the terminal, while the
/// link on stdout may be captured and relayed by an agent.
fn print_qr(data: &str) {
    match approvals::render_qr(data) {
        Ok(qr) => eprintln!("{qr}"),
        Err(e) => eprintln!("(no QR: {e})"),
    }
}

impl Action for ApprovalsAction {
    fn run(&self) -> Result<String, Error> {
        match &self.subcommand {
            Subcommand::Enroll { page } => Self::run_enroll(page.clone()),
            Subcommand::List => Self::run_list(),
            Subcommand::Pending => Self::run_pending(),
            Subcommand::Link { rid } => Self::run_link(rid),
            Subcommand::Remove { label } => Self::run_remove(label),
        }
    }
}
