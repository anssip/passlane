use crate::actions::{
    copy_to_clipboard, copy_to_clipboard_timed, handle_matches, ItemType, MatchHandlerTemplate,
    UnlockingAction,
};

use crate::ui::input::{ask_index, ask_with_options};
use crate::ui::output::{
    show_card, show_credentials_table, show_note, show_notes_table, show_payment_cards_table,
    show_totp_table,
};
use crate::vault::entities::{Credential, Error, Note, PaymentCard, Totp};
use crate::vault::vault_trait::Vault;
use clap::ArgMatches;
use log::debug;
use std::io::{self, Read, Write};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

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
        show_credentials_table(&vec![the_match.clone()], self.verbose, self.plain);
        if self.stdout_only {
            println!("{}", the_match.password());
            Ok(None)
        } else {
            println!("Password copied to clipboard! Clipboard will be cleared in 20 seconds.");
            copy_to_clipboard_timed(the_match.password(), 20);
            Ok(None)
        }
    }

    fn handle_many_matches(
        &mut self,
        matches: Vec<Self::ItemType>,
    ) -> Result<Option<String>, Error> {
        show_credentials_table(&matches, self.verbose, self.plain);

        let prompt = if self.stdout_only {
            "To print one of these passwords, please enter a row number from the table above"
        } else {
            "To copy one of these passwords to clipboard, please enter a row number from the table above"
        };

        match ask_index(
            prompt,
            matches.len() as i16 - 1,
            Some("Press q to exit without copying the password"),
        ) {
            Ok(index) => {
                if self.stdout_only {
                    println!("{}", matches[index].password());
                    Ok(None)
                } else {
                    println!("Password copied to clipboard! Clipboard will be cleared in 20 seconds.");
                    copy_to_clipboard_timed(matches[index].password(), 20);
                    Ok(None)
                }
            }
            Err(message) => {
                Err(Error { message })
            }
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
        show_payment_cards_table(&vec![the_match.clone()], self.show_cleartext, self.plain);
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
        show_payment_cards_table(&matches, self.show_cleartext, self.plain);

        match ask_index(
            "To see card details, enter a row number from the table above",
            matches.len() as i16 - 1,
            Some("Press q to exit without showing"),
        ) {
            Ok(index) => {
                show_card(&matches[index]);
                println!("Card number copied to clipboard! Clipboard will be cleared in 20 seconds.");
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
        show_notes_table(&vec![the_match.clone()], self.verbose, self.plain);
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
        show_notes_table(&matches, self.verbose, self.plain);

        match ask_index(
            "To see the full note, please enter a row number from the table above",
            matches.len() as i16 - 1,
            Some("Press q to exit without showing the note"),
        ) {
            Ok(index) => {
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
            Ok(index) => {
                Self::show_code(matches[index].clone())
            }
            Err(message) => {
                Err(Error { message })
            }
        }
    }
}

impl ShowTotpTemplate {
    fn show_code(the_match: Totp) -> Result<Option<String>, Error> {
        let (tx, rx) = mpsc::channel();
        let (tx_counter, rx_counter) = mpsc::channel();

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
        thread::spawn(move || loop {
            let duration = rx_counter.recv().expect("Failed to receive duration");
            println!("Next code in {} seconds", duration);
            println!("{}", ".".repeat(duration as usize));
            io::stdout().flush().unwrap();

            for _ in (1..=duration).rev() {
                print!(".");
                io::stdout().flush().unwrap();
                thread::sleep(Duration::from_secs(1));
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
                        println!("Exiting as requested.");
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
    pub is_totp: bool,
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
            is_totp: matches.get_one::<bool>("otp").map_or(false, |v| *v),
            stdout_only: matches.get_one::<bool>("out").map_or(false, |v| *v),
            plain: matches.get_one::<bool>("plain").map_or(false, |v| *v),
            once: matches.get_one::<bool>("once").map_or(false, |v| *v),
        }
    }

    /// One-shot TOTP code retrieval: print the single matching code to stdout
    /// and return. Errors (non-zero exit) on zero or multiple matches. No
    /// clipboard, no countdown, no keyboard wait.
    fn show_totp_once(&self, matches: Vec<Totp>) -> Result<Option<String>, Error> {
        match matches.len() {
            1 => {
                let code = matches[0].get_code()?;
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
    fn is_totp_vault(&self) -> bool {
        self.is_totp
    }

    fn run_with_vault(&self, vault: &mut Box<dyn Vault>) -> Result<Option<String>, Error> {
        match self.item_type {
            ItemType::Credential => {
                let grep = match &self.grep {
                    Some(grep) => grep.as_str(),
                    None => {
                        return Err(Error {
                            message: "No search term REGEXP provided".to_string(),
                        })
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
                    handle_matches(matches, &mut Box::new(ShowTotpTemplate { plain: self.plain }))
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
    }

    fn once_action() -> ShowAction {
        ShowAction {
            grep: None,
            verbose: false,
            item_type: ItemType::Totp,
            is_totp: true,
            stdout_only: false,
            plain: false,
            once: true,
        }
    }

    #[test]
    fn test_show_totp_once_single_match_prints_code() {
        let result = once_action().show_totp_once(vec![totp("a@test.com")]);
        let code = result.expect("expected a code").expect("expected Some(code)");
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
        let result =
            once_action().show_totp_once(vec![totp("a@test.com"), totp("b@test.com")]);
        let err = result.expect_err("expected an error on multiple matches");
        assert!(err.message.contains("a@test.com"));
        assert!(err.message.contains("b@test.com"));
    }
}
