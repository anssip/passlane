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
use crate::approvals;

pub struct ApprovalsAction {
    subcommand: Subcommand,
}

enum Subcommand {
    Enroll { page: Option<String> },
    List,
    Pending,
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
            Some(("remove", sub)) => Subcommand::Remove {
                label: sub
                    .get_one::<String>("LABEL")
                    .cloned()
                    .unwrap_or_default(),
            },
            _ => Subcommand::List,
        };
        Self { subcommand }
    }

    fn run_enroll(page_explicit: Option<String>) -> Result<String, Error> {
        let page = approvals::page_url(page_explicit.as_deref());
        let origin = approvals::page_origin(&page).map_err(|e| Error::new(&e))?;

        // 1. Fresh nonce + link + QR. The nonce is single-use and lives
        //    only in this process (SPEC §6); the link also carries this
        //    CLI's encryption public key so the page knows who to seal
        //    its approvals to (fragment-only, like every link).
        let nonce = approvals::generate_enrollment_nonce();
        let identity = approvals::load_identity(&approvals::state_dir())
            .map_err(|e| Error::new(&e))?;
        let cli_pub = passlane_approval::encoding::hex_encode(&identity.encryption_public());
        let link = approvals::enroll_link(&page, &nonce, &cli_pub);
        println!("Open this link on the approval page (scan or paste it):");
        println!("{link}");
        print_qr(&link);

        // 2. The page enrolls: ECDH key + passkey, then the binding
        //    assertion over SHA-256(nonce ‖ ECDH public key).
        let blob = inquire::Text::new(
            "Paste the enrollment blob the page produced (one line of JSON):",
        )
        .prompt()
        .map_err(|_| Error::new("enrollment aborted: no enrollment blob was pasted"))?;

        let label = inquire::Text::new("Label for this approver:")
            .with_default(&origin.rp_id)
            .prompt()
            .map_err(|_| Error::new("enrollment aborted: no label given"))?;

        // 3. Verify the ceremony before pinning anything.
        let (enc_pub, sig_pub) =
            approvals::verify_enrollment(&blob, &nonce, &origin).map_err(|e| Error::new(&e))?;
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
        let enc_kid = passlane_approval::keys::kid(b"enc", &pin.enc_pub_bytes().map_err(|e| Error::new(&e.to_string()))?);
        approvals::pin_approver(&approvals::state_dir(), pin).map_err(|e| Error::new(&e))?;

        Ok(format!(
            "Pinned approver '{label}' ({}). Approval requests will now be sealed to it; run 'passlane approvals list' to see the pin.",
            &enc_kid[..8.min(enc_kid.len())],
        ))
    }

    fn run_list() -> Result<String, Error> {
        let peers = approvals::load_peers_pinned(&approvals::state_dir()).map_err(|e| Error::new(&e))?;
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
            let paired = chrono::DateTime::from_timestamp(
                i64::try_from(peer.paired_at).unwrap_or(0),
                0,
            )
            .map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string())
            .unwrap_or_else(|| peer.paired_at.to_string());
            out.push_str(&format!(
                "  {} (paired {paired},{webauthn})\n",
                peer.label
            ));
        }
        Ok(out.trim_end().to_string())
    }

    fn run_pending() -> Result<String, Error> {
        let mut store =
            approvals::pending::PendingStore::load(&approvals::state_dir()).map_err(|e| {
                Error::new(&format!("could not load the pending-request store: {e}"))
            })?;
        store.prune(approvals::now_secs());
        if store.records().is_empty() {
            return Ok("No pending approval requests.".to_string());
        }
        let mut out = String::from("Pending approval requests:\n");
        for record in store.records() {
            let state = match &record.state {
                approvals::pending::RequestState::Pending => "awaiting the approver".to_string(),
                approvals::pending::RequestState::Granted { once, until } => {
                    if *once {
                        "granted (single use, unconsumed)".to_string()
                    } else {
                        format!("granted (reusable until {until})")
                    }
                }
                approvals::pending::RequestState::Consumed => "granted and used".to_string(),
                approvals::pending::RequestState::Denied => "denied".to_string(),
            };
            let target = if record.entry.is_empty() {
                format!("unlock vault '{}'", record.vault)
            } else {
                format!("reveal '{}' of '{}' (vault {})", record.field, record.entry, record.vault)
            };
            out.push_str(&format!("  {} … {target} — {state}\n", &record.rid[..8]));
        }
        Ok(out.trim_end().to_string())
    }

    fn run_remove(label: &str) -> Result<String, Error> {
        match approvals::unpin_approver(&approvals::state_dir(), label).map_err(|e| Error::new(&e))? {
            true => Ok(format!("Removed approver '{label}'.")),
            false => Err(Error::new(&format!(
                "No pinned approver labeled '{label}' (see 'passlane approvals list')"
            ))),
        }
    }
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
            Subcommand::Remove { label } => Self::run_remove(label),
        }
    }
}
