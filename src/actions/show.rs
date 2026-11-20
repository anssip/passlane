use crate::actions::{
    ItemType, MatchHandlerTemplate, UnlockingAction, copy_to_clipboard, copy_to_clipboard_timed,
    handle_matches,
};

use crate::agent::{self, RevealContext, RevealDecision, decide};
use crate::ui::input::{ask_index, ask_with_options};
use crate::ui::output::{
    show_card, show_credential, show_credentials_table, show_note, show_notes_table,
    show_payment_cards_table, show_totp_table,
};
use clap::ArgMatches;
use log::debug;
use passlane_core::vault::entities::{AgentPolicy, Credential, Error, Note, PaymentCard, Totp};
use passlane_core::vault::vault_trait::Vault;
use std::io::{self, Read, Write};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// Enforce the entry's agent policy for one reveal in this command's
/// context (see docs/features/agent-approvals.md). `stdout_reveal` marks
/// the scripting paths that print the secret to stdout; those, and any
/// reveal without an interactive terminal, are agent-facing.
/// `entry_id` is the entry's stable UUID (what reveal sessions are keyed
/// by); `entry` is the display title.
fn gate_reveal(
    policy: AgentPolicy,
    stdout_reveal: bool,
    entry_id: &str,
    entry: &str,
    field: &str,
) -> Result<(), Error> {
    agent::enforce_reveal(
        policy,
        RevealContext::for_reveal(stdout_reveal),
        entry_id,
        entry,
        field,
    )
}

/// A verbose (cleartext) table would reveal every matched entry at once,
/// so in an agent-facing context it is only allowed when every entry's
/// policy allows it. Returns the number of restricted entries.
fn restricted_count(policies: impl Iterator<Item = AgentPolicy>) -> usize {
    policies
        .filter(|p| decide(*p, RevealContext::Agent) != RevealDecision::Reveal)
        .count()
}

/// Refuse a cleartext table that would include policy-restricted entries.
fn require_cleartext_allowed(gated: usize) -> Result<(), Error> {
    if gated > 0 {
        Err(Error::new(&format!(
            "{} of the matched entries are restricted by their agent policy, so their secrets \
             stay withheld. Narrow the pattern to agent-allowed entries, or reveal a specific \
             entry with 'passlane show <pattern> --out' (agent=allow) or interactively \
             (agent=ask)",
            gated
        )))
    } else {
        Ok(())
    }
}

/// Verbose (cleartext) multi-match tables reveal every matched entry at
/// once. At the owner's terminal that is the owner's own view and stays
/// untouched; in an agent-facing context the table must not include
/// restricted entries, so it is refused instead of partially redacted.
fn guard_cleartext_table(
    show_cleartext: bool,
    context: RevealContext,
    policies: impl Iterator<Item = AgentPolicy>,
) -> Result<(), Error> {
    if show_cleartext && context == RevealContext::Agent {
        require_cleartext_allowed(restricted_count(policies))
    } else {
        Ok(())
    }
}

struct ShowCredentialsTemplate {
    verbose: bool,
    stdout_only: bool,
    plain: bool,
}

impl MatchHandlerTemplate for ShowCredentialsTemplate {
    type ItemType = Credential;

    fn pre_handle_matches(&self, matches: &Vec<Self::ItemType>) {
        println!("Found {} credentials:", matches.len());
    }

    fn handle_one_match(&mut self, the_match: Self::ItemType) -> Result<Option<String>, Error> {
        gate_reveal(
            the_match.agent_policy(),
            self.stdout_only,
            &the_match.uuid().to_string(),
            the_match.title(),
            "password",
        )?;
        if self.stdout_only {
            println!("{}", the_match.password());
            return Ok(None);
        }
        show_credential(&the_match, self.verbose, self.plain);
        println!("Password copied to clipboard! Clipboard will be cleared in 20 seconds.");
        copy_to_clipboard_timed(the_match.password(), 20);
        Ok(None)
    }

    fn handle_many_matches(
        &mut self,
        matches: Vec<Self::ItemType>,
    ) -> Result<Option<String>, Error> {
        // A verbose table reveals every matched password up front. That is
        // the owner's own view at a terminal; in an agent-facing context it
        // must not include restricted entries.
        let agent_ctx = agent::in_agent_context(self.stdout_only);
        if let Err(e) = guard_cleartext_table(
            self.verbose,
            RevealContext::for_reveal(self.stdout_only),
            matches.iter().map(|c| c.agent_policy()),
        ) {
            // The refused table's ask entries still enter the ask flow.
            agent::log_bulk_ask_requests(
                matches
                    .iter()
                    .map(|c| (c.title().to_string(), c.agent_policy())),
                "password",
                false,
            );
            return Err(e);
        }
        show_credentials_table(&matches, self.verbose, self.plain, agent_ctx);

        let prompt = if self.stdout_only {
            "To print one of these passwords, please enter a row number from the table above"
        } else {
            "To show one of these credentials, please enter a row number from the table above"
        };

        match ask_index(
            prompt,
            matches.len() as i16 - 1,
            Some("Press q to exit without showing the credential"),
        ) {
            Ok(index) => {
                gate_reveal(
                    matches[index].agent_policy(),
                    self.stdout_only,
                    &matches[index].uuid().to_string(),
                    matches[index].title(),
                    "password",
                )?;
                if self.stdout_only {
                    println!("{}", matches[index].password());
                    Ok(None)
                } else {
                    show_credential(&matches[index], self.verbose, self.plain);
                    println!(
                        "Password copied to clipboard! Clipboard will be cleared in 20 seconds."
                    );
                    copy_to_clipboard_timed(matches[index].password(), 20);
                    Ok(None)
                }
            }
            Err(message) => Err(Error { message }),
        }
    }
}

struct ShowPaymentsTemplate {
    show_cleartext: bool,
    plain: bool,
}

impl MatchHandlerTemplate for ShowPaymentsTemplate {
    type ItemType = PaymentCard;

    fn pre_handle_matches(&self, matches: &Vec<Self::ItemType>) {
        println!("Found {} payment cards:", matches.len());
    }

    fn handle_one_match(&mut self, the_match: Self::ItemType) -> Result<Option<String>, Error> {
        gate_reveal(
            the_match.agent_policy(),
            false,
            &the_match.id().to_string(),
            the_match.name(),
            "number",
        )?;
        // The gate above passed (allow, owner's own reveal, or an approved
        // ask), so the table renders a display copy with the policy
        // cleared — otherwise ask cells would stay redacted after the
        // owner just approved them.
        let display = the_match.clone().with_agent_policy(AgentPolicy::Allow);
        show_payment_cards_table(&vec![display], self.show_cleartext, self.plain);
        if ask_with_options(
            "Do you want to see the full card details? (yes/no)",
            vec!["yes", "no"],
        ) == "yes"
        {
            show_card(&the_match);
        }
        println!("Card number copied to clipboard! Clipboard will be cleared in 20 seconds.");
        copy_to_clipboard_timed(the_match.number(), 20);
        Ok(None)
    }

    fn handle_many_matches(
        &mut self,
        matches: Vec<Self::ItemType>,
    ) -> Result<Option<String>, Error> {
        // A cleartext table reveals every matched card number up front —
        // the owner's own view at a terminal, gated in agent contexts.
        if let Err(e) = guard_cleartext_table(
            self.show_cleartext,
            RevealContext::for_reveal(false),
            matches.iter().map(|c| c.agent_policy()),
        ) {
            agent::log_bulk_ask_requests(
                matches
                    .iter()
                    .map(|c| (c.name().to_string(), c.agent_policy())),
                "number",
                false,
            );
            return Err(e);
        }
        show_payment_cards_table(&matches, self.show_cleartext, self.plain);

        match ask_index(
            "To see card details, enter a row number from the table above",
            matches.len() as i16 - 1,
            Some("Press q to exit without showing"),
        ) {
            Ok(index) => {
                gate_reveal(
                    matches[index].agent_policy(),
                    false,
                    &matches[index].id().to_string(),
                    matches[index].name(),
                    "number",
                )?;
                show_card(&matches[index]);
                println!(
                    "Card number copied to clipboard! Clipboard will be cleared in 20 seconds."
                );
                copy_to_clipboard_timed(matches[index].number(), 20);
                Ok(None)
            }
            Err(message) => Err(Error { message }),
        }
    }
}

struct ShowNotesTemplate {
    verbose: bool,
    plain: bool,
}

impl MatchHandlerTemplate for ShowNotesTemplate {
    type ItemType = Note;

    fn pre_handle_matches(&self, matches: &Vec<Self::ItemType>) {
        println!("Found {} notes:", matches.len());
    }

    fn handle_one_match(&mut self, the_match: Self::ItemType) -> Result<Option<String>, Error> {
        gate_reveal(
            the_match.agent_policy(),
            false,
            &the_match.id().to_string(),
            the_match.title(),
            "content",
        )?;
        // As with payment cards: the reveal is approved, so the verbose
        // table renders a display copy instead of redacted ask cells.
        let display = the_match.clone().with_agent_policy(AgentPolicy::Allow);
        show_notes_table(&vec![display], self.verbose, self.plain);
        let response = ask_with_options(
            "Do you want to see the full note? (yes/no)",
            vec!["yes", "no"],
        );
        if response == "yes" {
            show_note(&the_match);
        }
        Ok(None)
    }

    fn handle_many_matches(
        &mut self,
        matches: Vec<Self::ItemType>,
    ) -> Result<Option<String>, Error> {
        // A cleartext table reveals every matched note up front — the
        // owner's own view at a terminal, gated in agent contexts.
        if let Err(e) = guard_cleartext_table(
            self.verbose,
            RevealContext::for_reveal(false),
            matches.iter().map(|n| n.agent_policy()),
        ) {
            agent::log_bulk_ask_requests(
                matches
                    .iter()
                    .map(|n| (n.title().to_string(), n.agent_policy())),
                "content",
                false,
            );
            return Err(e);
        }
        show_notes_table(&matches, self.verbose, self.plain);

        match ask_index(
            "To see the full note, please enter a row number from the table above",
            matches.len() as i16 - 1,
            Some("Press q to exit without showing the note"),
        ) {
            Ok(index) => {
                gate_reveal(
                    matches[index].agent_policy(),
                    false,
                    &matches[index].id().to_string(),
                    matches[index].title(),
                    "content",
                )?;
                show_note(&matches[index]);
                Ok(None)
            }
            Err(message) => Err(Error { message }),
        }
    }
}

struct ShowTotpTemplate {
    plain: bool,
}

impl MatchHandlerTemplate for ShowTotpTemplate {
    type ItemType = Totp;

    fn pre_handle_matches(&self, matches: &Vec<Self::ItemType>) {
        println!("Found {} matching OTP authorizers:", matches.len());
        show_totp_table(matches, self.plain);
    }

    fn handle_one_match(&mut self, the_match: Self::ItemType) -> Result<Option<String>, Error> {
        debug!("found totp: {}", the_match);
        Self::show_code(the_match)
    }

    fn handle_many_matches(
        &mut self,
        matches: Vec<Self::ItemType>,
    ) -> Result<Option<String>, Error> {
        match ask_index(
            "To see the code for one of these OTP authorizers, please enter a row number from the table above",
            matches.len() as i16 - 1,
            Some("Press q to exit without showing the code"),
        ) {
            Ok(index) => Self::show_code(matches[index].clone()),
            Err(message) => Err(Error { message }),
        }
    }
}

impl ShowTotpTemplate {
    fn show_code(the_match: Totp) -> Result<Option<String>, Error> {
        // The interactive code view is an owner reveal; an `ask` entry
        // prompts for its approval before the first code appears.
        gate_reveal(
            the_match.agent_policy(),
            false,
            &the_match.id().to_string(),
            the_match.label(),
            "code",
        )?;
        let (tx, rx) = mpsc::channel();
        let (tx_counter, rx_counter) = mpsc::channel();
        let session_ended = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        // When this vault was unlocked through the session agent, the
        // continuous code view is session-backed: subscribe and stop
        // refreshing (and copying) the moment the agent drops the
        // session (revocation, expiry, `passlane lock`).
        if crate::actions::last_unlock_source() == crate::actions::PasswordSource::SessionAgent
            && let Some(mut events) = crate::session_agent::subscribe_to_events()
        {
            let vault = crate::agent::current_vault_name();
            let quit = tx.clone();
            let ended = std::sync::Arc::clone(&session_ended);
            thread::spawn(move || {
                while let Ok(event) = events.next_event() {
                    if crate::session_agent::event_ends_access(&event, &vault) {
                        ended.store(true, std::sync::atomic::Ordering::SeqCst);
                        let _ = quit.send(());
                        break;
                    }
                }
            });
        }

        // Spawn a thread to listen for keyboard input
        thread::spawn(move || {
            let mut buffer = [0; 1];
            let stdin = io::stdin();
            let mut handle = stdin.lock();

            loop {
                if handle.read_exact(&mut buffer).is_ok() {
                    let input = buffer[0];
                    if input == b'q' || input == 4 {
                        // 'q' or Ctrl+D (EOF)
                        tx.send(()).expect("Failed to send termination signal");
                        break;
                    }
                }
            }
        });

        // Spawn a thread to handle the countdown timer
        thread::spawn(move || {
            loop {
                let duration = rx_counter.recv().expect("Failed to receive duration");
                println!("Next code in {} seconds", duration);
                println!("{}", ".".repeat(duration as usize));
                io::stdout().flush().unwrap();

                for _ in (1..=duration).rev() {
                    print!(".");
                    io::stdout().flush().unwrap();
                    thread::sleep(Duration::from_secs(1));
                }
            }
        });

        loop {
            let code = the_match.get_code();

            match code {
                Ok(code) => {
                    copy_to_clipboard(&code.value);
                    println!(
                        "\nCode {} (also copied to clipboard). Press q to exit.",
                        code.value
                    );

                    // Send the duration to the countdown timer thread
                    tx_counter
                        .send(code.valid_for_seconds)
                        .expect("Failed to send duration");

                    // Wait for the specified duration or a keyboard interrupt
                    let duration = Duration::from_secs(code.valid_for_seconds);
                    if rx.recv_timeout(duration).is_ok() {
                        if session_ended.load(std::sync::atomic::Ordering::SeqCst) {
                            println!("Session ended (revoked, expired or locked); exiting.");
                        } else {
                            println!("Exiting as requested.");
                        }
                        break;
                    }
                }
                Err(e) => {
                    return Err(Error { message: e.message });
                }
            }
        }
        Ok(None)
    }
}

pub struct ShowAction {
    pub grep: Option<String>,
    pub verbose: bool,
    pub item_type: ItemType,
    pub stdout_only: bool,
    pub plain: bool,
    pub once: bool,
}

impl ShowAction {
    pub fn new(matches: &ArgMatches) -> ShowAction {
        ShowAction {
            grep: matches.get_one::<String>("REGEXP").cloned(),
            verbose: matches.get_one::<bool>("verbose").map_or(false, |v| *v),
            item_type: ItemType::new_from_args(matches),
            stdout_only: matches.get_one::<bool>("out").map_or(false, |v| *v),
            plain: matches.get_one::<bool>("plain").map_or(false, |v| *v),
            once: matches.get_one::<bool>("once").map_or(false, |v| *v),
        }
    }

    /// One-shot TOTP code retrieval: print the single matching code to stdout
    /// and return. Errors (non-zero exit) on zero or multiple matches. No
    /// clipboard, no countdown, no keyboard wait. The stdout reveal is
    /// agent-facing, so the entry's agent policy applies.
    fn show_totp_once(&self, matches: Vec<Totp>) -> Result<Option<String>, Error> {
        match matches.len() {
            1 => {
                let totp = &matches[0];
                gate_reveal(
                    totp.agent_policy(),
                    true,
                    &totp.id().to_string(),
                    totp.label(),
                    "code",
                )?;
                let code = totp.get_code()?;
                Ok(Some(code.value))
            }
            0 => Err(Error {
                message: "No matching OTP authorizer found.".to_string(),
            }),
            _ => {
                let labels = matches
                    .iter()
                    .map(|t| t.label())
                    .collect::<Vec<_>>()
                    .join(", ");
                Err(Error {
                    message: format!(
                        "Multiple OTP authorizers match: {}. Refine the search pattern to match exactly one.",
                        labels
                    ),
                })
            }
        }
    }
}

impl UnlockingAction for ShowAction {
    fn run_with_vault(&self, vault: &mut Box<dyn Vault>) -> Result<Option<String>, Error> {
        match self.item_type {
            ItemType::Credential => {
                let grep = match &self.grep {
                    Some(grep) => grep.as_str(),
                    None => {
                        return Err(Error {
                            message: "No search term REGEXP provided".to_string(),
                        });
                    }
                };
                handle_matches(
                    vault.grep(Some(grep)),
                    &mut Box::new(ShowCredentialsTemplate {
                        verbose: self.verbose,
                        stdout_only: self.stdout_only,
                        plain: self.plain,
                    }),
                )
            }
            ItemType::Payment => handle_matches(
                vault.find_payments(),
                &mut Box::new(ShowPaymentsTemplate {
                    show_cleartext: self.verbose,
                    plain: self.plain,
                }),
            ),
            ItemType::Note => handle_matches(
                vault.find_notes(),
                &mut Box::new(ShowNotesTemplate {
                    verbose: self.verbose,
                    plain: self.plain,
                }),
            ),
            ItemType::Totp => {
                let matches = vault.find_totp(self.grep.as_deref());
                if self.once {
                    self.show_totp_once(matches)
                } else {
                    handle_matches(
                        matches,
                        &mut Box::new(ShowTotpTemplate { plain: self.plain }),
                    )
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn totp(label: &str) -> Totp {
        Totp::new(
            Some(&Uuid::nil()),
            "otpauth://totp/GitHub:user?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
            label,
            "GitHub",
            "JBSWY3DPEHPK3PXP",
            "SHA1",
            30,
            6,
            None,
        )
        .with_agent_policy(AgentPolicy::Allow)
    }

    fn once_action() -> ShowAction {
        ShowAction {
            grep: None,
            verbose: false,
            item_type: ItemType::Totp,
            stdout_only: false,
            plain: false,
            once: true,
        }
    }

    #[test]
    fn test_show_totp_once_single_match_prints_code() {
        let result = once_action().show_totp_once(vec![totp("a@test.com")]);
        let code = result
            .expect("expected a code")
            .expect("expected Some(code)");
        // A current TOTP code is a non-empty numeric string.
        assert!(!code.is_empty());
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_show_totp_once_no_match_errors() {
        let result = once_action().show_totp_once(vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn test_show_totp_once_multiple_matches_errors_with_labels() {
        let result = once_action().show_totp_once(vec![totp("a@test.com"), totp("b@test.com")]);
        let err = result.expect_err("expected an error on multiple matches");
        assert!(err.message.contains("a@test.com"));
        assert!(err.message.contains("b@test.com"));
    }

    #[test]
    fn restricted_count_counts_never_and_ask() {
        let policies = [
            AgentPolicy::Allow,
            AgentPolicy::Never,
            AgentPolicy::Ask,
            AgentPolicy::Allow,
        ];
        assert_eq!(restricted_count(policies.into_iter()), 2);
        assert_eq!(restricted_count([AgentPolicy::Allow].into_iter()), 0);
    }

    #[test]
    fn require_cleartext_allowed_passes_without_restricted_entries() {
        assert!(require_cleartext_allowed(0).is_ok());
    }

    #[test]
    fn require_cleartext_allowed_refuses_restricted_entries() {
        let err = require_cleartext_allowed(2).expect_err("restricted entries must block");
        assert!(
            err.message
                .contains("2 of the matched entries are restricted"),
            "unexpected message: {}",
            err.message
        );
        assert!(err.message.contains("agent=allow"));
    }

    #[test]
    fn cleartext_table_guard_uses_the_reveal_context() {
        let policies = [AgentPolicy::Never, AgentPolicy::Allow];
        // At the owner's terminal the verbose table is the owner's own view.
        assert!(guard_cleartext_table(true, RevealContext::Owner, policies.into_iter()).is_ok());
        // In agent-facing contexts a table containing restricted entries is refused...
        assert!(guard_cleartext_table(true, RevealContext::Agent, policies.into_iter()).is_err());
        // ...but non-cleartext tables never carry secrets, and all-allowed
        // sets pass anywhere.
        assert!(guard_cleartext_table(false, RevealContext::Agent, policies.into_iter()).is_ok());
        assert!(
            guard_cleartext_table(true, RevealContext::Agent, [AgentPolicy::Allow].into_iter())
                .is_ok()
        );
    }
}
