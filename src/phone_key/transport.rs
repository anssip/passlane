//! The link transport for phone-held keys.
//!
//! A request is sealed to the holder (the pinned approver that keeps the
//! vault's secret) and shown as a terminal QR plus a link; the answer comes
//! back as a signed response. How it returns depends on the context:
//!
//! - **Interactive terminal** — the response is pasted into this process,
//!   verified, and used at once.
//! - **Opening a vault without a terminal** — the link is printed (stdout,
//!   for an agent to relay) and the command exits with guidance. The owner
//!   approves; `passlane approve --response` hands the answer to the session
//!   agent; re-running the command finds it there.
//! - **Saving without a terminal** — the new seed only exists inside the
//!   save, so the command cannot exit and resume. It prints the link and
//!   waits for `passlane approve --response` to deposit the answer with the
//!   session agent, until the request expires.
//!
//! In every case the answer exists only in memory: here, or in the agent.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use passlane_approval::keys::PeerPin;
use passlane_approval::message::Operation;
use passlane_core::vault::entities::Error;
use zeroize::Zeroizing;

use super::{Answer, AnswerOrigin, PhoneRequest, ResponseError, ResponseSource};
use crate::approvals::pending::{PendingStore, RequestKind, RequestState};
use crate::approvals::{self, ApproveOutcome, Disposition, EmittedRequest, RequestTarget};

/// How often a waiting command looks for its answer.
const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Answers already held in memory elsewhere in this login session — the
/// session agent in production, a map in tests.
pub(crate) trait AnswerStore: Send + Sync {
    /// The answer held for exactly this vault and challenge (lower-case
    /// hex), if any. A single-use one is consumed by this call.
    fn take(&self, vault: &str, challenge_hex: &str) -> Option<Zeroizing<Vec<u8>>>;

    /// Whether anything is running that could hold an answer at all.
    fn is_running(&self) -> bool;

    /// Hold an answer for later commands (the deposit-offer,
    /// passlane#77): starts an agent when none is running and that is
    /// allowed. Returns the held session's expiry (unix seconds); `Err`
    /// explains why nothing was held and never affects the command that
    /// already has its answer.
    fn deposit(&self, vault: &str, challenge_hex: &str, answer_hex: &str) -> Result<u64, String>;
}

/// What the human at the terminal is shown for one request.
pub(crate) struct Shown<'a> {
    /// What is being asked, and for which vault.
    pub request: &'a PhoneRequest,
    /// The `https://…/approve.html#…` link.
    pub link: &'a str,
    /// Request id (the response must answer it).
    pub rid: &'a str,
    /// Unix seconds after which the request can no longer be approved.
    pub exp: u64,
    /// Unix seconds until a response to this request can still be
    /// redeemed (SPEC §4's total-lifetime bound): the approver decides
    /// inside the window, the relay round trip may take longer.
    pub redeem_until: u64,
    /// The link belongs on stdout (an agent relays it) rather than stderr.
    pub link_on_stdout: bool,
}

/// The terminal, as the transport uses it. Injected so the flow is
/// testable without one.
pub(crate) trait Terminal: Send + Sync {
    /// Show the request: the link, a QR to scan, and what to do.
    fn show(&self, shown: &Shown<'_>);
    /// The response pasted at the prompt. `None` cancels.
    fn read_response(&self, prompt: &str) -> Option<String>;
    /// One yes/no question (the deposit-offer). A terminal that cannot
    /// ask answers no.
    fn confirm(&self, question: &str) -> bool;
}

/// The real terminal: the link on stdout or stderr, the QR and the
/// instructions on stderr (stdout stays parseable for agents), the
/// response through a prompt.
struct RealTerminal;

impl Terminal for RealTerminal {
    fn show(&self, shown: &Shown<'_>) {
        let request = shown.request;
        let link_line = format!(
            "Approval needed to {} (request {}…): {}",
            request.describe(),
            short(shown.rid),
            shown.link
        );
        if shown.link_on_stdout {
            println!("{link_line}");
        } else {
            eprintln!("{link_line}");
        }
        match approvals::render_qr(shown.link) {
            Ok(qr) => eprintln!("{qr}"),
            Err(e) => eprintln!("(no QR: {e})"),
        }
        eprintln!(
            "Scan the QR code with the device that holds the key for vault '{}' (or open the \
             link there), approve the request, and paste the response below.",
            request.vault_name
        );
        // How long the person has, in the terms they think in: the
        // approver must decide by the expiry, the pasted answer is
        // accepted until the redemption bound.
        let left = shown.exp.saturating_sub(crate::approvals::now_secs());
        if let Some(at) = chrono::DateTime::from_timestamp(shown.exp as i64, 0) {
            eprintln!(
                "The request expires at {} (in about {} minute(s)).",
                at.with_timezone(&chrono::Local).format("%H:%M:%S"),
                left.div_ceil(60)
            );
        }
        if let Some(at) = chrono::DateTime::from_timestamp(shown.redeem_until as i64, 0) {
            eprintln!(
                "An answer approved in time is accepted until {} even if it arrives later.",
                at.with_timezone(&chrono::Local).format("%H:%M:%S")
            );
        }
    }

    fn read_response(&self, prompt: &str) -> Option<String> {
        match inquire::Text::new(prompt).prompt() {
            Ok(text) if !text.trim().is_empty() => Some(text),
            _ => None,
        }
    }

    fn confirm(&self, question: &str) -> bool {
        // Default no: extending an approval's reach past the command that
        // asked for it is an affirmative act (passlane#77). A prompt that
        // fails — no terminal after all — declines rather than blocks.
        inquire::Confirm::new(question)
            .with_default(false)
            .prompt()
            .unwrap_or(false)
    }
}

fn short(rid: &str) -> &str {
    &rid[..rid.len().min(8)]
}

/// The message that ends the command after one rejected paste
/// (passlane#72): the verifier's precise reason, and — when the blob is
/// an envelope at all — that it does answer this command's request even
/// though the response itself did not verify. (A blob answering a
/// *different* request never reaches verification: it is refused
/// beforehand, without spending anything, by the caller's rid
/// pre-check.) Nothing here re-prompts.
fn rejected_paste_message(
    reason: &str,
    blob: &str,
    request: &PhoneRequest,
    expected_rid: &str,
) -> String {
    let mut message = format!("The pasted response was not accepted: {reason}");
    match answered_request(blob) {
        Some(answered) => {
            message.push_str(&format!(
                " It does answer this command's request {}… ({}), but the response itself did \
                 not verify.",
                short(&answered),
                request.describe()
            ));
        }
        None => message.push_str(&format!(
            " This prompt waits for request {}… ({}).",
            short(expected_rid),
            request.describe()
        )),
    }
    message.push_str(" Re-run the command to ask again.");
    message
}

/// The request id a pasted response blob says it answers: the `rid`
/// echoed in the response envelope's cleartext header, decodable even
/// when the blob is rejected (already used, expired, sealed by another
/// sender). `None` when the blob is not an approval-response envelope
/// or its header does not carry a well-formed id — an unverified
/// header is attacker-controlled, so anything that does not look like
/// a request id is refused a place in an error message.
fn answered_request(blob: &str) -> Option<String> {
    let cleaned: String = blob.chars().filter(|c| !c.is_whitespace()).collect();
    let envelope = passlane_approval::envelope::Envelope::from_base64url(&cleaned).ok()?;
    let header = envelope.header();
    let looks_like_rid = header.rid.len() == 32
        && header
            .rid
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, 'a'..='f'));
    (header.t == passlane_approval::message::MessageType::ApprovalResponse as u8 && looks_like_rid)
        .then(|| header.rid.clone())
}

/// The link transport.
pub(crate) struct LinkTransport {
    /// The approvals state directory (identity, pins, pending requests).
    dir: PathBuf,
    /// The pinned approver that holds the vault's secret.
    holder: PeerPin,
    /// Who is asking, shown on the approval screen.
    requester: String,
    /// Whether a person can be prompted.
    interactive: bool,
    store: Arc<dyn AnswerStore>,
    terminal: Arc<dyn Terminal>,
    /// Whether an agent could be auto-started (passlane#77) — asked
    /// before offering to hold a pasted answer: an offer that could not
    /// be accepted even by saying yes is noise.
    could_autostart: bool,
    /// How long to wait for an answer deposited from elsewhere. `None`
    /// waits until the request expires.
    max_wait: Option<Duration>,
    poll_interval: Duration,
    /// The approval log, for the audit trail.
    log: crate::agent::ApprovalLog,
}

impl LinkTransport {
    /// The transport for a vault's holder. Whether a person can be prompted
    /// follows stdin.
    pub(crate) fn new(
        dir: &Path,
        holder: PeerPin,
        requester: impl Into<String>,
        store: Arc<dyn AnswerStore>,
    ) -> Self {
        Self {
            dir: dir.to_path_buf(),
            holder,
            requester: requester.into(),
            interactive: std::io::stdin().is_terminal(),
            store,
            terminal: Arc::new(RealTerminal),
            could_autostart: crate::session_agent::autostart_ready(),
            max_wait: None,
            poll_interval: POLL_INTERVAL,
            log: crate::agent::ApprovalLog::default_path(),
        }
    }
}

impl ResponseSource for LinkTransport {
    fn respond(&self, request: &PhoneRequest) -> Result<Answer, ResponseError> {
        let challenge_hex = request.challenge_hex();

        // An answer granted earlier — `unlock --session`, or an approval
        // deposited from another terminal — is used without asking again.
        if let Some(response) = self.store.take(&request.vault_name, &challenge_hex) {
            return Ok(Answer {
                response,
                origin: AnswerOrigin::SessionAgent,
            });
        }

        let kind = RequestKind::from_operation(&request.operation);
        let body = approvals::challenge_request_body(
            &request.vault_id,
            &request.vault_name,
            request.operation.clone(),
            &request.challenge,
            &self.requester,
        )
        .map_err(ResponseError::Unavailable)?;
        let emitted = approvals::emit_to(
            &self.dir,
            &self.holder,
            RequestTarget::challenge(&request.vault_name, kind, &challenge_hex),
            body.clone(),
            None,
        )
        .map_err(|e| {
            ResponseError::Unavailable(format!(
                "could not ask the holder of vault '{}': {e}",
                request.vault_name
            ))
        })?;
        self.log
            .log_challenge_request(&emitted.rid, &request.vault_name, kind.label(), &body);

        self.terminal.show(&Shown {
            request,
            link: &emitted.link,
            rid: &emitted.rid,
            exp: emitted.exp,
            redeem_until: emitted.redeem_until,
            link_on_stdout: !self.interactive,
        });

        let outcome = if self.interactive {
            match self.answered_at_the_terminal(request, &emitted) {
                Ok(answer) => {
                    // The paste verified: offer to let it outlive this
                    // process (passlane#77) before handing it back.
                    self.offer_to_hold(request, &answer);
                    Ok(answer)
                }
                Err(e) => Err(e),
            }
        } else {
            match request.operation {
                // A save cannot exit and resume: the seed it needs only
                // exists inside the save.
                Operation::Save => self.answered_from_elsewhere(request, &emitted),
                _ => Err(ResponseError::Unavailable(
                    self.relay_guidance(request, &emitted),
                )),
            }
        };

        let approved = outcome.is_ok();
        self.log
            .log_challenge_decision(&emitted.rid, &request.vault_name, kind.label(), approved);
        outcome
    }
}

impl LinkTransport {
    /// The deposit-offer (passlane#77): after an interactive approval is
    /// pasted and verified, offer to hold the answer in the session agent
    /// so it outlives this process — the "one approval per command"
    /// degradation of a missing agent becomes "one approval per sitting"
    /// without anyone running a daemon by hand.
    ///
    /// Boundaries:
    ///
    /// - **Interactive approvals only** — we are in the interactive arm
    ///   of `respond`, and the terminal's own confirm declines (never
    ///   blocks) when there is nobody to ask.
    /// - **Unlock approvals only**: the answer that opened the vault
    ///   serves the next command too (the seed stands until a save). A
    ///   save's answer belongs to the save that asked for it, and an
    ///   enrollment's proves the holder, not a vault file.
    /// - **Only when holding could work**: an agent is running, or one
    ///   would be auto-started on acceptance. Nothing is asked when
    ///   neither holds.
    /// - **Declining — or a refused deposit — changes nothing**: the
    ///   command proceeds with the answer it already has; the agent's
    ///   cap rules are obeyed, never bent.
    fn offer_to_hold(&self, request: &PhoneRequest, answer: &Answer) {
        if request.operation != Operation::Unlock {
            return;
        }
        if !self.store.is_running() && !self.could_autostart {
            return;
        }
        let question = format!(
            "Hold this approval in the session agent for {} minutes, so commands until then \
             do not ask the phone again?",
            crate::session_agent::DEPOSIT_SESSION_SECS / 60,
        );
        if !self.terminal.confirm(&question) {
            return;
        }
        // Zeroized: this is the phone's unlock factor in the clear — the
        // agent copies it into its own zeroizing buffers, and this copy
        // must not linger in freed heap memory after the deposit.
        let answer_hex = Zeroizing::new(passlane_approval::encoding::hex_encode(&answer.response));
        match self
            .store
            .deposit(&request.vault_name, &request.challenge_hex(), &answer_hex)
        {
            Ok(until) => {
                let when = chrono::DateTime::from_timestamp(i64::try_from(until).unwrap_or(0), 0)
                    .map(|t| t.to_rfc3339())
                    .unwrap_or_else(|| format!("+{}s", crate::session_agent::DEPOSIT_SESSION_SECS));
                eprintln!(
                    "Held until {when} (memory only): until then, commands on vault '{}' do not \
                     ask the phone again. 'passlane lock' or 'passlane sessions revoke' drops it \
                     early.",
                    request.vault_name
                );
            }
            Err(why) => {
                eprintln!("Warning: the approval was not held: {why}");
            }
        }
    }

    /// The response is pasted here and used at once. One paste, one
    /// verdict (passlane#72): a rejected paste ends the command with the
    /// reason and the re-run guidance instead of re-prompting — a second
    /// prompt for the same request invites pasting the same dead blob
    /// again, which is exactly what the retry loop used to produce.
    fn answered_at_the_terminal(
        &self,
        request: &PhoneRequest,
        emitted: &EmittedRequest,
    ) -> Result<Answer, ResponseError> {
        // No prompt once the request's answers can no longer be redeemed:
        // there is nothing a paste could still land in. That is the
        // total-lifetime bound, not the request's expiry — an in-time
        // decision stays redeemable past it (SPEC §4, passlane#73).
        if crate::approvals::now_secs() >= emitted.redeem_until {
            return Err(ResponseError::Unavailable(format!(
                "request {}… ({}) expired before a response was pasted; re-run the command to \
                 ask again",
                short(&emitted.rid),
                request.describe()
            )));
        }
        let prompt = format!(
            "Paste the approval response for {} (leave empty to cancel)",
            request.describe()
        );
        let Some(blob) = self.terminal.read_response(&prompt) else {
            return Err(ResponseError::Unavailable(
                "cancelled at the terminal: no response was given".into(),
            ));
        };
        // The response must answer the request this command emitted, not
        // any other pending one — and that is checked from the
        // envelope's cleartext header BEFORE verification, because a
        // verified response spends the request it answers (replay
        // nonce, consumed/denied state): a blob belonging to another
        // command must not burn that command's approval.
        if let Some(answered) = answered_request(&blob)
            && answered != emitted.rid
        {
            return Err(ResponseError::Unavailable(
                self.wrong_request_message(&answered, request, emitted),
            ));
        }
        // The verifier hands the answer over before recording anything;
        // here it is used immediately, so the request ends as consumed.
        let handed = std::cell::RefCell::new(None);
        let verified =
            approvals::verify_response(&self.dir, &blob, Disposition::ConsumeNow, &|handoff| {
                *handed.borrow_mut() = Some(Zeroizing::new(handoff.response.to_vec()));
                Ok(())
            });
        match verified {
            Ok(verified) => match verified.outcome {
                ApproveOutcome::Allowed { .. } => {
                    // verify_response refuses a challenge request
                    // approved without an answer, so this is Some.
                    Ok(Answer {
                        response: handed.into_inner().ok_or_else(|| {
                            ResponseError::Unavailable(
                                "the approved response carried no answer".into(),
                            )
                        })?,
                        origin: AnswerOrigin::LinkTransport,
                    })
                }
                ApproveOutcome::Denied { reason, .. } => Err(ResponseError::Denied(
                    reason.unwrap_or_else(|| "no reason given".into()),
                )),
            },
            Err(e) => Err(ResponseError::Unavailable(rejected_paste_message(
                &e,
                &blob,
                request,
                &emitted.rid,
            ))),
        }
    }

    /// Why a pasted blob answering request `answered` does not satisfy
    /// this command's prompt: what that request's state is (already
    /// used, denied, still waiting on its own command — read from the
    /// pending store, without touching anything), next to the request
    /// this prompt waits for. Nothing was spent in producing it.
    fn wrong_request_message(
        &self,
        answered: &str,
        request: &PhoneRequest,
        emitted: &EmittedRequest,
    ) -> String {
        let state = PendingStore::load(&self.dir)
            .ok()
            .and_then(|pending| pending.find(answered).cloned());
        let why = match state {
            Some(record) => match record.state {
                RequestState::Consumed => " (already approved and used)".to_string(),
                RequestState::Granted { .. } => " (already approved)".to_string(),
                RequestState::Denied => " (already denied)".to_string(),
                RequestState::Pending => {
                    // Pending past its expiry is not necessarily dead: an
                    // in-time decision may still be redeemed until the
                    // total-lifetime bound (SPEC §4, passlane#73), and the
                    // other command may be waiting on exactly that.
                    let policy = passlane_approval::policy::Policy::default();
                    let decision_deadline = (record.exp + 2 * policy.max_clock_skew_secs)
                        .min(policy.redemption_deadline(record.created, record.exp));
                    if crate::approvals::now_secs() >= decision_deadline {
                        " (expired)".to_string()
                    } else {
                        " (another command's live request)".to_string()
                    }
                }
            },
            None => " (no pending request with that id — it may have expired and been pruned)"
                .to_string(),
        };
        format!(
            "That response answers request {}{}{}; this prompt waits for request {}… ({}). It \
             was not used, and nothing was spent. Re-run the command to ask again.",
            short(answered),
            "…",
            why,
            short(&emitted.rid),
            request.describe()
        )
    }

    /// Someone elsewhere approves and runs `passlane approve --response`;
    /// the answer is deposited with the session agent. Wait for it.
    fn answered_from_elsewhere(
        &self,
        request: &PhoneRequest,
        emitted: &EmittedRequest,
    ) -> Result<Answer, ResponseError> {
        if !self.store.is_running() {
            return Err(ResponseError::Unavailable(format!(
                "{} Saving needs a response to a seed that only exists during the save, so \
                 this command cannot exit and be re-run: start 'passlane-agent' (see \
                 docs/features/session-agent.md) so 'passlane approve --response' can hand the \
                 answer over, then run the command again — or run it in an interactive \
                 terminal.",
                self.relay_guidance(request, emitted)
            )));
        }
        // Wait as long as an answer can still be redeemed: the approver
        // decides inside the request window, but the relay round trip —
        // and `passlane approve --response` — may land after it, until
        // the request's total-lifetime bound (SPEC §4, passlane#73).
        let left = emitted
            .redeem_until
            .saturating_sub(crate::approvals::now_secs())
            .max(1);
        let deadline = Instant::now() + self.max_wait.unwrap_or(Duration::from_secs(left));
        loop {
            if let Some(response) = self
                .store
                .take(&request.vault_name, &request.challenge_hex())
            {
                return Ok(Answer {
                    response,
                    origin: AnswerOrigin::SessionAgent,
                });
            }
            // A refusal recorded by `passlane approve --response` ends the
            // wait; without this the command would sit until expiry.
            if let Ok(pending) = PendingStore::load(&self.dir)
                && let Some(record) = pending.find(&emitted.rid)
                && record.state == RequestState::Denied
            {
                return Err(ResponseError::Denied(
                    "the approver denied the request".into(),
                ));
            }
            if Instant::now() >= deadline {
                return Err(ResponseError::Unavailable(format!(
                    "no response arrived for request {}… in time; re-run the command to ask \
                     again",
                    short(&emitted.rid)
                )));
            }
            std::thread::sleep(self.poll_interval);
        }
    }

    /// What to do when the link is out and this command cannot take the
    /// answer itself.
    fn relay_guidance(&self, request: &PhoneRequest, emitted: &EmittedRequest) -> String {
        let verb = match request.operation {
            Operation::Unlock => "open",
            Operation::Save => "save",
            Operation::EnrollKey => "enroll the phone-held key for",
            Operation::Reveal { .. } => "proceed with",
        };
        let mut text = format!(
            "Vault '{}' needs its phone-held key to {verb} it (request {}…). The approval \
             request has been emitted: scan the QR code or relay the link to the holder, \
             approve it there, then run 'passlane approve --response <blob-from-the-holder>' \
             and re-run this command.",
            request.vault_name,
            short(&emitted.rid)
        );
        if !self.store.is_running() {
            text.push_str(
                " The session agent is not running, so there is nowhere to keep that answer: \
                 start 'passlane-agent', or run this command in an interactive terminal and \
                 paste the response at its prompt.",
            );
        }
        text
    }
}

/// The pinned approver that holds a vault's key, by the encryption key id
/// the registry records.
pub(crate) fn holder_pin(dir: &Path, holder_kid: &str) -> Result<PeerPin, Error> {
    let peers = approvals::load_peers_pinned(dir).map_err(|e| Error::new(&e))?;
    peers
        .iter()
        .find(|peer| peer.enc_kid().ok().as_deref() == Some(holder_kid))
        .cloned()
        .ok_or_else(|| {
            let mut message = format!(
                "The device that holds the key for this vault (approver {holder_kid}) is no \
                 longer pinned, so it cannot be asked for the challenge response."
            );
            if peers.is_empty() {
                message.push_str(
                    " Recovering needs the recovery sheet: 'passlane hwkey remove --secret' \
                     opens the vault without the holder and removes its key. Pairing again \
                     creates a new device identity that does not hold this vault's key, so \
                     after recovering, pair ('passlane approvals enroll') and enroll the \
                     key again ('passlane hwkey add --phone').",
                );
            } else {
                let pinned: Vec<String> = peers
                    .iter()
                    .map(|peer| match peer.enc_kid() {
                        Ok(kid) => format!("'{}' ({kid})", peer.label),
                        Err(_) => format!("'{}'", peer.label),
                    })
                    .collect();
                message.push_str(&format!(
                    " Pinned approvers: {}. Pairing again creates a new device identity \
                     that does not hold this vault's key, so recovering needs the recovery \
                     sheet: 'passlane hwkey remove --secret', then pair ('passlane approvals \
                     enroll') and enroll again ('passlane hwkey add --phone').",
                    pinned.join(", ")
                ));
            }
            message.push_str(
                " If that device is lost, recover with the recovery sheet: 'passlane hwkey \
                 remove --secret'.",
            );
            Error::new(&message)
        })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::approvals::{
        load_identity, mock_page, mock_page_answer, mock_page_answer_at, pin_approver,
    };
    use passlane_approval::keys::IdentityKeys;
    use passlane_approval::message::Decision;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// An in-memory stand-in for the session agent's held answers.
    #[derive(Default)]
    pub(crate) struct MemoryStore {
        answers: Mutex<HashMap<(String, String), Vec<u8>>>,
        takes: AtomicUsize,
        deposits: AtomicUsize,
    }

    impl MemoryStore {
        pub(crate) fn deposit(&self, vault: &str, challenge_hex: &str, answer: [u8; 20]) {
            self.answers.lock().unwrap().insert(
                (vault.to_string(), challenge_hex.to_string()),
                answer.to_vec(),
            );
        }

        pub(crate) fn takes(&self) -> usize {
            self.takes.load(Ordering::SeqCst)
        }

        /// How many times the deposit-offer's acceptance reached the store.
        pub(crate) fn deposits(&self) -> usize {
            self.deposits.load(Ordering::SeqCst)
        }

        /// Whether an answer is held for exactly this vault and challenge.
        pub(crate) fn holds(&self, vault: &str, challenge_hex: &str) -> bool {
            self.answers
                .lock()
                .unwrap()
                .contains_key(&(vault.to_string(), challenge_hex.to_string()))
        }
    }

    impl AnswerStore for MemoryStore {
        fn take(&self, vault: &str, challenge_hex: &str) -> Option<Zeroizing<Vec<u8>>> {
            self.takes.fetch_add(1, Ordering::SeqCst);
            self.answers
                .lock()
                .unwrap()
                .remove(&(vault.to_string(), challenge_hex.to_string()))
                .map(Zeroizing::new)
        }

        fn is_running(&self) -> bool {
            true
        }

        fn deposit(
            &self,
            vault: &str,
            challenge_hex: &str,
            answer_hex: &str,
        ) -> Result<u64, String> {
            self.deposits.fetch_add(1, Ordering::SeqCst);
            let answer = passlane_approval::encoding::hex_decode(answer_hex)
                .map_err(|e| format!("malformed answer: {e}"))?;
            self.answers
                .lock()
                .unwrap()
                .insert((vault.to_string(), challenge_hex.to_string()), answer);
            Ok(crate::approvals::now_secs() + 900)
        }
    }

    /// A session agent that is not running.
    pub(crate) struct NoAgent;

    impl AnswerStore for NoAgent {
        fn take(&self, _vault: &str, _challenge_hex: &str) -> Option<Zeroizing<Vec<u8>>> {
            None
        }

        fn is_running(&self) -> bool {
            false
        }

        fn deposit(
            &self,
            _vault: &str,
            _challenge_hex: &str,
            _answer_hex: &str,
        ) -> Result<u64, String> {
            Err("the session agent is not running".into())
        }
    }

    /// What a scripted terminal was shown, without borrows.
    #[derive(Debug, Clone)]
    struct ShownRecord {
        describe: String,
        link: String,
        rid: String,
        link_on_stdout: bool,
    }

    /// A scripted terminal. `on_show` runs when the request appears — it
    /// stands in for whoever approves while the command waits — and
    /// `on_read` produces each paste, given what was shown last.
    /// `confirm_answers` supplies the person's yes/no answers to the
    /// deposit-offer (empty = always decline), and `confirmations` counts
    /// how often the offer was made at all.
    struct ScriptedTerminal {
        shown: Mutex<Vec<ShownRecord>>,
        prompts: AtomicUsize,
        confirmations: AtomicUsize,
        confirm_answers: Mutex<std::collections::VecDeque<bool>>,
        on_show: Mutex<Option<OnShow>>,
        on_read: OnRead,
    }

    /// What a scripted terminal does when a request appears.
    type OnShow = Box<dyn FnOnce(&ShownRecord) + Send>;
    /// What it pastes for one, given what was shown last.
    type OnRead = Box<dyn Fn(&ShownRecord) -> Option<String> + Send + Sync>;

    impl ScriptedTerminal {
        fn new(on_show: Option<OnShow>, on_read: OnRead) -> Self {
            Self {
                shown: Mutex::new(Vec::new()),
                prompts: AtomicUsize::new(0),
                confirmations: AtomicUsize::new(0),
                confirm_answers: Mutex::new(std::collections::VecDeque::new()),
                on_show: Mutex::new(on_show),
                on_read,
            }
        }

        fn with_confirm_answers(self, answers: Vec<bool>) -> Self {
            *self.confirm_answers.lock().unwrap() = answers.into();
            self
        }

        fn shown(&self) -> Vec<ShownRecord> {
            self.shown.lock().unwrap().clone()
        }

        /// How many times a paste was asked for — the one-paste rule
        /// (passlane#72) is asserted against this.
        fn prompts(&self) -> usize {
            self.prompts.load(Ordering::SeqCst)
        }

        /// How many times the deposit-offer was made (passlane#77).
        fn confirmations(&self) -> usize {
            self.confirmations.load(Ordering::SeqCst)
        }
    }

    impl Terminal for ScriptedTerminal {
        fn show(&self, shown: &Shown<'_>) {
            let record = ShownRecord {
                describe: shown.request.describe().to_string(),
                link: shown.link.to_string(),
                rid: shown.rid.to_string(),
                link_on_stdout: shown.link_on_stdout,
            };
            self.shown.lock().unwrap().push(record.clone());
            if let Some(on_show) = self.on_show.lock().unwrap().take() {
                on_show(&record);
            }
        }

        fn read_response(&self, _prompt: &str) -> Option<String> {
            self.prompts.fetch_add(1, Ordering::SeqCst);
            let shown = self.shown.lock().unwrap();
            (self.on_read)(
                shown
                    .last()
                    .expect("a paste is read only after a request is shown"),
            )
        }

        fn confirm(&self, _question: &str) -> bool {
            self.confirmations.fetch_add(1, Ordering::SeqCst);
            self.confirm_answers
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(false)
        }
    }

    type PageKeys = (IdentityKeys, IdentityKeys, p256::ecdsa::SigningKey);

    /// The pinned page's signed answer to a shown request.
    fn page_answer(keys: &PageKeys, shown: &ShownRecord, answer: Option<[u8; 20]>) -> String {
        let (cli, page, passkey) = keys;
        mock_page_answer(
            cli,
            page,
            passkey,
            &shown.rid,
            Decision::Allow,
            answer,
            passlane_approval::message::Scope::Once,
        )
        .to_base64url()
    }

    fn page_denial(keys: &PageKeys, shown: &ShownRecord, reason: &str) -> String {
        let (cli, page, passkey) = keys;
        mock_page_answer(
            cli,
            page,
            passkey,
            &shown.rid,
            Decision::Deny {
                reason: Some(reason.into()),
            },
            None,
            passlane_approval::message::Scope::Once,
        )
        .to_base64url()
    }

    /// What a test's terminal needs to act as the page or as
    /// `passlane approve --response`: the page's keys, the approvals
    /// directory, and the session agent's store (when one is running).
    struct Env {
        keys: Arc<Mutex<PageKeys>>,
        dir: PathBuf,
        agent: Option<Arc<MemoryStore>>,
    }

    type TerminalFactory = Box<dyn FnOnce(Env) -> Arc<ScriptedTerminal>>;

    /// A scratch approvals state with a pinned page and a transport
    /// against it.
    struct Rig {
        /// Keeps the scratch directories alive; the field is never read.
        #[allow(dead_code)]
        state: tempfile::TempDir,
        dir: PathBuf,
        log_path: PathBuf,
        transport: LinkTransport,
        /// The scripted terminal, to inspect what the person was shown.
        terminal: Arc<ScriptedTerminal>,
        /// The session agent's store, when one is running.
        agent: Option<Arc<MemoryStore>>,
    }

    impl Rig {
        /// `interactive`: a person can be prompted. `agent_running`: a
        /// session agent can hold answers. `terminal` builds what the
        /// person (or the approving owner) does. The rig never claims an
        /// agent could be auto-started — tests must not spawn daemons.
        fn new(interactive: bool, agent_running: bool, terminal: TerminalFactory) -> Self {
            let state = tempfile::tempdir().unwrap();
            let dir = state.path().join("approvals");
            std::fs::create_dir_all(&dir).unwrap();
            let (pin, page, passkey) = mock_page();
            pin_approver(&dir, pin.clone(), None).unwrap();
            let keys = Arc::new(Mutex::new((load_identity(&dir).unwrap(), page, passkey)));
            let agent = agent_running.then(|| Arc::new(MemoryStore::default()));
            let store: Arc<dyn AnswerStore> = match &agent {
                Some(agent) => agent.clone(),
                None => Arc::new(NoAgent),
            };
            let terminal = terminal(Env {
                keys,
                dir: dir.clone(),
                agent: agent.clone(),
            });
            let shown_terminal = terminal.clone();
            let log_path = state.path().join("approvals.log");
            let transport = LinkTransport {
                dir: dir.clone(),
                holder: pin,
                requester: "tester".into(),
                interactive,
                store,
                terminal,
                could_autostart: false,
                // Generous: no test should ever be able to wait this long,
                // so a wait that ends does so because of what it found.
                max_wait: Some(Duration::from_secs(30)),
                poll_interval: Duration::from_millis(5),
                log: crate::agent::ApprovalLog::at(&log_path),
            };
            Self {
                state,
                dir,
                log_path,
                transport,
                terminal: shown_terminal,
                agent,
            }
        }

        fn ask(&self, operation: Operation) -> Result<Answer, ResponseError> {
            self.transport.respond(&PhoneRequest {
                vault_id: "work".into(),
                vault_name: "work".into(),
                operation,
                challenge: [0x5a; 32],
            })
        }

        fn terminal(&self) -> &ScriptedTerminal {
            &self.terminal
        }

        fn agent(&self) -> &MemoryStore {
            self.agent.as_ref().expect("this rig has a running agent")
        }

        fn pending(&self) -> Vec<crate::approvals::pending::PendingRequest> {
            PendingStore::load(&self.dir).unwrap().records().to_vec()
        }

        fn log_lines(&self) -> Vec<serde_json::Value> {
            // No log file means nothing was ever logged.
            let Ok(text) = std::fs::read_to_string(&self.log_path) else {
                return Vec::new();
            };
            text.lines()
                .filter(|l| !l.is_empty())
                .map(|l| serde_json::from_str(l).unwrap())
                .collect()
        }
    }

    const ANSWER: [u8; 20] = [0x77; 20];

    /// A terminal that pastes whatever `paste` decides, as the page would.
    fn pasting(
        paste: impl Fn(&PageKeys, &ShownRecord) -> Option<String> + Send + Sync + 'static,
    ) -> TerminalFactory {
        Box::new(move |env: Env| {
            Arc::new(ScriptedTerminal::new(
                None,
                Box::new(move |shown| paste(&env.keys.lock().unwrap(), shown)),
            ))
        })
    }

    /// A terminal whose person does as told while the command waits.
    fn reacting(
        react: impl FnOnce(&PageKeys, &Path, &MemoryStore, &ShownRecord) + Send + 'static,
    ) -> TerminalFactory {
        Box::new(move |env: Env| {
            let on_show = {
                let keys = env.keys.clone();
                let dir = env.dir.clone();
                let agent = env.agent.clone();
                move |shown: &ShownRecord| {
                    let agent = agent.expect("reacting needs a running agent");
                    react(&keys.lock().unwrap(), &dir, &agent, shown)
                }
            };
            Arc::new(ScriptedTerminal::new(
                Some(Box::new(on_show)),
                Box::new(|_| None),
            ))
        })
    }

    #[test]
    fn interactive_answer_is_pasted_verified_and_used_at_once() {
        let rig = Rig::new(
            true,
            false,
            pasting(|keys, shown| Some(page_answer(keys, shown, Some(ANSWER)))),
        );
        let answer = rig.ask(Operation::Unlock).unwrap();
        assert_eq!(answer.response.as_slice(), ANSWER);
        assert_eq!(answer.origin, AnswerOrigin::LinkTransport);

        // The person was told what for, given the link and the QR target.
        let shown = rig.terminal().shown();
        assert_eq!(shown.len(), 1);
        assert_eq!(shown[0].describe, "opening vault 'work'");
        assert!(shown[0].link.contains("/approve.html#"));
        assert!(
            !shown[0].link_on_stdout,
            "interactive: the link stays on stderr"
        );

        // Used the moment it arrived: the request is spent, not left as a
        // grant, so the same response cannot be presented again.
        let pending = rig.pending();
        assert_eq!(pending[0].state, RequestState::Consumed);
        assert_eq!(pending[0].link.as_deref(), Some(shown[0].link.as_str()));
    }

    #[test]
    fn interactive_denial_is_reported_with_its_reason() {
        let rig = Rig::new(
            true,
            false,
            pasting(|keys, shown| Some(page_denial(keys, shown, "not while I am away"))),
        );
        let err = rig.ask(Operation::Unlock).unwrap_err();
        assert_eq!(err, ResponseError::Denied("not while I am away".into()));
        assert_eq!(rig.pending()[0].state, RequestState::Denied);
    }

    #[test]
    fn interactive_a_bad_paste_ends_the_command_after_one_prompt() {
        // passlane#72: one paste, one verdict. A malformed blob is not a
        // reason to re-prompt — re-prompting invites pasting the same
        // dead thing again — so the command ends, saying what was
        // expected and what to do.
        let rig = Rig::new(true, false, pasting(|_, _| Some("not an envelope".into())));
        let err = rig.ask(Operation::Save).unwrap_err();
        let ResponseError::Unavailable(message) = &err else {
            panic!("{err:?}")
        };
        assert!(message.contains("not accepted"), "{message}");
        assert!(
            message.contains("is not a valid envelope"),
            "the verifier's reason is carried through: {message}"
        );
        assert!(
            message.contains("Re-run the command to ask again"),
            "{message}"
        );
        // One prompt, no second chance: a malformed paste is not a reason
        // to re-prompt — re-prompting invites pasting the same dead thing
        // again.
        assert_eq!(rig.terminal().prompts(), 1);
        // Nothing was released: a bad paste is not a decision, so the
        // request is still only pending until it expires.
        assert_eq!(rig.pending()[0].state, RequestState::Pending);
    }

    #[test]
    fn interactive_giving_up_ends_the_request_without_an_answer() {
        // An empty paste cancels at once.
        let rig = Rig::new(true, false, pasting(|_, _| None));
        let err = rig.ask(Operation::Unlock).unwrap_err();
        assert!(
            matches!(err, ResponseError::Unavailable(ref m) if m.contains("cancelled")),
            "{err:?}"
        );
        assert_eq!(rig.terminal().shown().len(), 1, "no second request");
    }

    #[test]
    fn interactive_a_wrong_blob_is_rejected_once_and_names_both_requests() {
        // The blob answers an earlier, still-pending request (a different
        // command's). It is refused BEFORE verification — so the other
        // command's approval is not spent — with both request ids in the
        // message so the mixup explains itself.
        let pasted: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let keys_slot: Arc<Mutex<Option<Arc<Mutex<PageKeys>>>>> = Arc::new(Mutex::new(None));
        let rig = Rig::new(true, false, {
            let pasted = pasted.clone();
            let keys_slot = keys_slot.clone();
            Box::new(move |env: Env| {
                *keys_slot.lock().unwrap() = Some(env.keys.clone());
                Arc::new(ScriptedTerminal::new(
                    None,
                    Box::new(move |_| pasted.lock().unwrap().clone()),
                ))
            })
        });
        // Command one abandons its request at the prompt (nothing pasted
        // yet), leaving it pending; its response blob is then built from
        // that request and pasted into command two's prompt.
        let _ = rig.ask(Operation::Unlock).unwrap_err();
        let shown = rig.terminal().shown();
        let keys = keys_slot.lock().unwrap().clone().unwrap();
        let blob = page_answer(&keys.lock().unwrap(), &shown[0], Some(ANSWER));
        *pasted.lock().unwrap() = Some(blob.clone());
        let err = rig.ask(Operation::Save).unwrap_err();
        let ResponseError::Unavailable(message) = &err else {
            panic!("{err:?}")
        };
        let pending = rig.pending();
        let wrong = &pending[0].rid; // the abandoned request's
        let expected = &pending[1].rid; // the save's own
        assert!(
            message.contains(&wrong[..8]),
            "names the answered one: {message}"
        );
        assert!(
            message.contains(&expected[..8]),
            "names the expected one: {message}"
        );
        assert!(
            message.contains("another command's live request"),
            "says what state the answered request is in: {message}"
        );
        assert!(
            message.contains(&format!("saving vault '{}'", pending[1].vault)),
            "says what the prompt waits for: {message}"
        );
        assert!(
            message.contains("Re-run the command to ask again"),
            "{message}"
        );
        assert_eq!(
            rig.terminal().prompts(),
            2,
            "one prompt per command, no retry"
        );
        // The refusal happened before verification, so it spent nothing:
        // the abandoned request is still pending, and its response still
        // verifies for whoever asks under that rid again.
        assert_eq!(pending[0].state, RequestState::Pending, "{message}");
        let redeemed = approvals::verify_response(&rig.dir, &blob, Disposition::Grant, &|_| Ok(()));
        assert!(
            redeemed.is_ok(),
            "the wrong-pasted blob is still redeemable: {redeemed:?}"
        );
    }

    #[test]
    fn interactive_a_byte_identical_re_paste_of_a_used_blob_is_self_diagnosing() {
        // The real-world trap (passlane#72 evidence): the response that
        // already served its command, pasted again at the next one. One
        // prompt, then a message that names the spent request against
        // the fresh one.
        let spent: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let rig = Rig::new(true, false, {
            let spent = spent.clone();
            pasting(move |keys, shown| {
                let mut slot = spent.lock().unwrap();
                if slot.is_none() {
                    // Command one's own response, remembered verbatim.
                    *slot = Some(page_answer(keys, shown, Some(ANSWER)));
                }
                slot.clone()
            })
        });
        // Command one consumes its request with the paste it asked for.
        rig.ask(Operation::Unlock).unwrap();
        // Command two gets the very same bytes pasted at its own prompt.
        let err = rig.ask(Operation::Unlock).unwrap_err();
        let ResponseError::Unavailable(message) = &err else {
            panic!("{err:?}")
        };
        let pending = rig.pending();
        assert!(
            message.contains("already approved and used"),
            "names the spent request's state: {message}"
        );
        assert!(
            message.contains(&pending[0].rid[..8]),
            "names the spent request: {message}"
        );
        assert!(
            message.contains(&pending[1].rid[..8]),
            "names the request the prompt waits for: {message}"
        );
        assert!(
            message.contains("Re-run the command to ask again"),
            "{message}"
        );
        assert_eq!(
            rig.terminal().prompts(),
            2,
            "one prompt per command, no retry"
        );
    }

    #[test]
    fn interactive_an_expired_blob_is_rejected_once_and_explains_itself() {
        // A blob sealed in the past: its envelope has lapsed even though
        // it answers the request this prompt waits for. The message says
        // both — right request, dead blob — and how to recover.
        let rig = Rig::new(
            true,
            false,
            pasting(|keys: &PageKeys, shown| {
                let (cli, page, passkey) = keys;
                Some(
                    mock_page_answer_at(
                        cli,
                        page,
                        passkey,
                        &shown.rid,
                        Decision::Allow,
                        Some(ANSWER),
                        passlane_approval::message::Scope::Once,
                        crate::approvals::now_secs() - 400,
                    )
                    .to_base64url(),
                )
            }),
        );
        let err = rig.ask(Operation::Unlock).unwrap_err();
        let ResponseError::Unavailable(message) = &err else {
            panic!("{err:?}")
        };
        assert!(
            message.contains("failed verification"),
            "the verifier's reason is carried through: {message}"
        );
        assert!(
            message.contains("does answer this command's request"),
            "right request, dead blob: {message}"
        );
        assert!(
            message.contains("Re-run the command to ask again"),
            "{message}"
        );
        assert_eq!(rig.terminal().prompts(), 1);
    }

    #[test]
    fn non_interactive_open_prints_the_link_and_explains_the_relay() {
        let rig = Rig::new(false, false, pasting(|_, _| None));
        let err = rig.ask(Operation::Unlock).unwrap_err();
        let ResponseError::Unavailable(message) = &err else {
            panic!("{err:?}")
        };
        let pending = rig.pending();
        assert!(message.contains(&pending[0].rid[..8]), "{message}");
        assert!(
            message.contains("'passlane approve --response <blob-from-the-holder>'"),
            "{message}"
        );
        assert!(message.contains("re-run this command"), "{message}");
        assert!(
            message.contains("session agent is not running"),
            "no agent: the owner is told what that means: {message}"
        );

        // The link is on stdout for an agent to relay, and nothing is
        // consumed: the request simply waits for the approval.
        let shown = rig.terminal().shown();
        assert!(shown[0].link_on_stdout);
        assert_eq!(shown[0].rid, pending[0].rid);
        assert_eq!(pending[0].kind, RequestKind::Unlock);
        assert_eq!(pending[0].state, RequestState::Pending);
        assert_eq!(
            pending[0].challenge.as_deref(),
            Some("5a".repeat(32).as_str())
        );
    }

    #[test]
    fn non_interactive_save_waits_for_an_answer_deposited_from_elsewhere() {
        // While the command waits, the owner approves from another
        // terminal: `passlane approve --response` verifies the blob and
        // hands the answer to the session agent.
        let rig = Rig::new(
            false,
            true,
            reacting(|keys, dir, agent, shown| {
                let blob = page_answer(keys, shown, Some(ANSWER));
                let verified =
                    approvals::verify_response(dir, &blob, Disposition::Grant, &|handoff| {
                        assert_eq!(handoff.kind, RequestKind::Save);
                        assert_eq!(handoff.response, ANSWER);
                        agent.deposit("work", handoff.challenge.unwrap(), ANSWER);
                        Ok(())
                    })
                    .unwrap();
                assert_eq!(verified.kind, RequestKind::Save);
            }),
        );
        let answer = rig.ask(Operation::Save).unwrap();
        assert_eq!(answer.response.as_slice(), ANSWER);
        assert_eq!(answer.origin, AnswerOrigin::SessionAgent);
        assert!(rig.terminal().shown()[0].link_on_stdout);
        // The approval left the request granted (the depositor's doing).
        assert!(matches!(
            rig.pending()[0].state,
            RequestState::Granted { once: true, .. }
        ));
    }

    #[test]
    fn non_interactive_save_stops_as_soon_as_the_request_is_denied() {
        let rig = Rig::new(
            false,
            true,
            reacting(|keys, dir, _agent, shown| {
                approvals::approve_response(dir, &page_denial(keys, shown, "no")).unwrap();
            }),
        );
        let started = Instant::now();
        let err = rig.ask(Operation::Save).unwrap_err();
        assert!(matches!(err, ResponseError::Denied(_)), "{err:?}");
        // The refusal was seen on the very first look, not after a wait:
        // one check before the request went out, one after.
        assert_eq!(
            rig.agent().takes(),
            2,
            "a denial ends the wait on the first look"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "a denial ends the wait instead of letting it time out"
        );
    }

    #[test]
    fn non_interactive_save_without_an_agent_says_why_it_cannot_wait() {
        let rig = Rig::new(false, false, pasting(|_, _| None));
        let err = rig.ask(Operation::Save).unwrap_err();
        let ResponseError::Unavailable(message) = &err else {
            panic!("{err:?}")
        };
        assert!(message.contains("only exists during the save"), "{message}");
        assert!(message.contains("'passlane-agent'"), "{message}");
        assert!(message.contains("interactive terminal"), "{message}");
        assert_eq!(rig.terminal().shown().len(), 1, "the link is still shown");
    }

    #[test]
    fn non_interactive_save_gives_up_when_nothing_arrives() {
        let store = Arc::new(MemoryStore::default());
        let takes = Arc::new(AtomicUsize::new(0));
        let counting = CountingStore {
            inner: store.clone(),
            takes: takes.clone(),
        };
        let state = tempfile::tempdir().unwrap();
        let dir = state.path().join("approvals");
        std::fs::create_dir_all(&dir).unwrap();
        let (pin, _page, _passkey) = mock_page();
        pin_approver(&dir, pin.clone(), None).unwrap();
        let transport = LinkTransport {
            dir,
            holder: pin,
            requester: "tester".into(),
            interactive: false,
            store: Arc::new(counting),
            terminal: Arc::new(ScriptedTerminal::new(None, Box::new(|_| None))),
            could_autostart: false,
            max_wait: Some(Duration::from_millis(60)),
            poll_interval: Duration::from_millis(5),
            log: crate::agent::ApprovalLog::at(state.path().join("approvals.log")),
        };
        let err = transport
            .respond(&PhoneRequest {
                vault_id: "work".into(),
                vault_name: "work".into(),
                operation: Operation::Save,
                challenge: [0x5a; 32],
            })
            .unwrap_err();
        assert!(
            matches!(err, ResponseError::Unavailable(ref m) if m.contains("in time")),
            "{err:?}"
        );
        // It waited and kept looking — more than the one check an answer
        // already held would have needed.
        assert!(
            takes.load(Ordering::SeqCst) >= 3,
            "polled {} times",
            takes.load(Ordering::SeqCst)
        );
    }

    struct CountingStore {
        inner: Arc<MemoryStore>,
        takes: Arc<AtomicUsize>,
    }

    impl AnswerStore for CountingStore {
        fn take(&self, vault: &str, challenge_hex: &str) -> Option<Zeroizing<Vec<u8>>> {
            self.takes.fetch_add(1, Ordering::SeqCst);
            self.inner.take(vault, challenge_hex)
        }

        fn is_running(&self) -> bool {
            true
        }

        fn deposit(
            &self,
            vault: &str,
            challenge_hex: &str,
            answer_hex: &str,
        ) -> Result<u64, String> {
            AnswerStore::deposit(&*self.inner, vault, challenge_hex, answer_hex)
        }
    }

    #[test]
    fn an_answer_held_by_the_agent_is_used_without_asking() {
        // From `unlock --session` earlier, or an approval deposited while
        // this command was not running: no QR, no prompt, no new request.
        let prompts = Arc::new(AtomicUsize::new(0));
        let observed = prompts.clone();
        let rig = Rig::new(
            true,
            true,
            Box::new(move |env: Env| {
                env.agent
                    .as_ref()
                    .expect("agent")
                    .deposit("work", &"5a".repeat(32), ANSWER);
                Arc::new(ScriptedTerminal::new(
                    None,
                    Box::new(move |_| {
                        prompts.fetch_add(1, Ordering::SeqCst);
                        None // a person who walks away from the prompt
                    }),
                ))
            }),
        );
        let answer = rig.ask(Operation::Unlock).unwrap();
        assert_eq!(answer.response.as_slice(), ANSWER);
        assert_eq!(answer.origin, AnswerOrigin::SessionAgent);
        assert_eq!(observed.load(Ordering::SeqCst), 0, "no prompt");
        assert!(rig.terminal().shown().is_empty(), "no QR, no link");
        assert!(rig.pending().is_empty());
        assert!(
            rig.log_lines().is_empty(),
            "nothing was asked, nothing to audit"
        );

        // A single-use answer: it is gone, so the second command asks.
        let err = rig.ask(Operation::Unlock).unwrap_err();
        assert!(
            matches!(err, ResponseError::Unavailable(ref m) if m.contains("cancelled")),
            "{err:?}"
        );
        assert_eq!(observed.load(Ordering::SeqCst), 1);
        assert_eq!(rig.terminal().shown().len(), 1);
    }

    #[test]
    fn the_audit_log_records_the_request_and_how_it_ended() {
        let rig = Rig::new(
            true,
            false,
            pasting(|keys, shown| Some(page_answer(keys, shown, Some(ANSWER)))),
        );
        rig.ask(Operation::EnrollKey).unwrap();
        let events = rig.log_lines();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["event"], "request");
        assert_eq!(events[0]["vault"], "work");
        assert_eq!(events[0]["field"], "enroll_key");
        assert_eq!(events[0]["policy"], "phone-key");
        assert_eq!(events[0]["request"]["operation"]["kind"], "enroll_key");
        assert_eq!(events[0]["request"]["challenge"], "5a".repeat(32));
        assert_eq!(events[1]["event"], "decision");
        assert_eq!(events[1]["id"], events[0]["id"]);
        assert_eq!(events[1]["decision"], "approved");

        // A refusal is audited as denied, correlated the same way.
        let rig = Rig::new(
            true,
            false,
            pasting(|keys, shown| Some(page_denial(keys, shown, "no"))),
        );
        rig.ask(Operation::Unlock).unwrap_err();
        let events = rig.log_lines();
        assert_eq!(events[1]["decision"], "denied");
    }

    /// A terminal that pastes a valid unlock answer and then answers the
    /// deposit-offer (passlane#77) with `hold`.
    fn holding(hold: bool) -> TerminalFactory {
        Box::new(move |env: Env| {
            let terminal =
                pasting(move |keys, shown| Some(page_answer(keys, shown, Some(ANSWER))))(env);
            *terminal.confirm_answers.lock().unwrap() = vec![hold].into();
            terminal
        })
    }

    /// The deposit-offer, accepted: the pasted answer is held and the
    /// next command opens without asking the phone again (passlane#77).
    #[test]
    fn an_accepted_offer_holds_the_answer_for_later_commands() {
        let rig = Rig::new(true, true, holding(true));
        let answer = rig.ask(Operation::Unlock).unwrap();
        assert_eq!(answer.response.as_slice(), ANSWER);
        assert_eq!(answer.origin, AnswerOrigin::LinkTransport);
        assert!(
            rig.agent().holds("work", &"5a".repeat(32)),
            "the pasted answer was deposited"
        );
        assert_eq!(rig.agent().deposits(), 1);

        // The held answer serves the next command: no new request, no
        // paste prompt.
        let second = rig.ask(Operation::Unlock).unwrap();
        assert_eq!(second.response.as_slice(), ANSWER);
        assert_eq!(second.origin, AnswerOrigin::SessionAgent);
        assert_eq!(rig.terminal().shown().len(), 1, "no second QR");
        assert_eq!(rig.terminal().prompts(), 1, "no second paste prompt");
    }

    /// The offer, declined: exactly today's behavior — the answer serves
    /// this command and dies with it, so the next command dances again.
    #[test]
    fn a_declined_offer_keeps_the_answer_process_local() {
        let rig = Rig::new(true, true, holding(false));
        let answer = rig.ask(Operation::Unlock).unwrap();
        assert_eq!(answer.origin, AnswerOrigin::LinkTransport);
        assert_eq!(rig.terminal().confirmations(), 1, "the offer was made");
        assert!(!rig.agent().holds("work", &"5a".repeat(32)));
        assert_eq!(rig.agent().deposits(), 0);

        // The next command needs its own approval again: a fresh
        // request, a fresh paste, and an answer that likewise dies with
        // the command that asked for it.
        let second = rig.ask(Operation::Unlock).unwrap();
        assert_eq!(second.origin, AnswerOrigin::LinkTransport);
        assert_eq!(rig.terminal().shown().len(), 2, "a fresh request");
        assert_eq!(rig.terminal().prompts(), 2, "a fresh paste prompt");
        assert_eq!(rig.agent().deposits(), 0, "still nothing held");
    }

    /// A save's answer is never offered: it belongs to the save that
    /// asked for it, not to the commands that follow.
    #[test]
    fn save_answers_are_not_offered_for_deposit() {
        let rig = Rig::new(true, true, holding(true));
        rig.ask(Operation::Save).unwrap();
        assert_eq!(rig.terminal().confirmations(), 0, "no offer for a save");
        assert_eq!(rig.agent().deposits(), 0);
    }

    /// No agent running and none that could be started: the offer is
    /// never made — an unanswerable question is noise, and non-terminal
    /// contexts (the non-interactive arm) never see it at all.
    #[test]
    fn no_offer_when_nothing_could_hold_the_answer() {
        let rig = Rig::new(true, false, holding(true));
        rig.ask(Operation::Unlock).unwrap();
        assert_eq!(
            rig.terminal().confirmations(),
            0,
            "nothing could hold it: nothing is asked"
        );
    }

    /// An offer accepted but refused by the agent (its cap is below the
    /// offer's duration): a warning, never a failure — the command
    /// already has its answer.
    #[test]
    fn a_refused_deposit_is_a_warning_not_a_failure() {
        let refusing = RefusingDeposit {
            inner: Arc::new(MemoryStore::default()),
        };
        let state = tempfile::tempdir().unwrap();
        let dir = state.path().join("approvals");
        std::fs::create_dir_all(&dir).unwrap();
        let (pin, page, passkey) = mock_page();
        pin_approver(&dir, pin.clone(), None).unwrap();
        let keys = Arc::new(Mutex::new((load_identity(&dir).unwrap(), page, passkey)));
        let keys_for_paste = keys.clone();
        let terminal = ScriptedTerminal::new(
            None,
            Box::new(move |shown| {
                Some(page_answer(
                    &keys_for_paste.lock().unwrap(),
                    shown,
                    Some(ANSWER),
                ))
            }),
        )
        .with_confirm_answers(vec![true]);
        let transport = LinkTransport {
            dir: dir.clone(),
            holder: pin,
            requester: "tester".into(),
            interactive: true,
            store: Arc::new(refusing),
            terminal: Arc::new(terminal),
            could_autostart: false,
            max_wait: Some(Duration::from_secs(30)),
            poll_interval: Duration::from_millis(5),
            log: crate::agent::ApprovalLog::at(state.path().join("approvals.log")),
        };
        let answer = transport
            .respond(&PhoneRequest {
                vault_id: "work".into(),
                vault_name: "work".into(),
                operation: Operation::Unlock,
                challenge: [0x5a; 32],
            })
            .unwrap();
        assert_eq!(answer.response.as_slice(), ANSWER);
        assert_eq!(answer.origin, AnswerOrigin::LinkTransport);
    }

    /// A store that cannot hold what it is offered.
    struct RefusingDeposit {
        inner: Arc<MemoryStore>,
    }

    impl AnswerStore for RefusingDeposit {
        fn take(&self, vault: &str, challenge_hex: &str) -> Option<Zeroizing<Vec<u8>>> {
            self.inner.take(vault, challenge_hex)
        }
        fn is_running(&self) -> bool {
            true
        }
        fn deposit(
            &self,
            _vault: &str,
            _challenge_hex: &str,
            _answer_hex: &str,
        ) -> Result<u64, String> {
            Err("session of 900s exceeds this agent's cap of 300s".into())
        }
    }

    #[test]
    fn holder_pin_is_found_by_key_id() {
        let state = tempfile::tempdir().unwrap();
        let (pin, _page, _passkey) = mock_page();
        let kid = pin.enc_kid().unwrap();
        pin_approver(state.path(), pin.clone(), None).unwrap();
        assert_eq!(holder_pin(state.path(), &kid).unwrap(), pin);

        let err = holder_pin(state.path(), "0000000000000000").unwrap_err();
        assert!(err.message.contains("no longer pinned"), "{}", err.message);
        assert!(err.message.contains("'approval-page' ("), "{}", err.message);
        assert!(
            err.message.contains("'passlane hwkey remove --secret'"),
            "{}",
            err.message
        );

        let empty = tempfile::tempdir().unwrap();
        let err = holder_pin(empty.path(), "0000000000000000").unwrap_err();
        assert!(
            err.message.contains("'passlane approvals enroll'"),
            "{}",
            err.message
        );
        assert!(!err.message.contains("Pinned approvers"), "{}", err.message);
    }
}
