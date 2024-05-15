use clap::ArgMatches;
use log::debug;
use crate::actions::{copy_to_clipboard, handle_matches, ItemType, MatchHandlerTemplate, UnlockingAction};
use crate::ui;
use crate::vault::entities::{Credential, Error, Note, PaymentCard, Totp};
use crate::vault::vault_trait::Vault;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use std::io::{self, Read, Write};

struct ShowCredentialsTemplate {
    verbose: bool,
}

impl MatchHandlerTemplate for ShowCredentialsTemplate {
    type ItemType = Credential;

    fn pre_handle_matches(&self, matches: &Vec<Self::ItemType>) {
        println!("Found {} credentials:", matches.len());
    }

    fn handle_one_match(&mut self, the_match: Self::ItemType) -> Result<Option<String>, Error> {
        ui::show_credentials_table(&vec![the_match.clone()], self.verbose);
        copy_to_clipboard(&the_match.password);
        Ok(Some("Password copied to clipboard!".to_string()))
    }

    fn handle_many_matches(&mut self, matches: Vec<Self::ItemType>) -> Result<Option<String>, Error> {
        ui::show_credentials_table(&matches, self.verbose);

        match ui::ask_index(
            "To copy one of these passwords to clipboard, please enter a row number from the table above, or press q to exit:",
            matches.len() as i16 - 1,
        ) {
            Ok(index) => {
                copy_to_clipboard(&matches[index].password);
                Ok(Some("Password copied to clipboard!".to_string()))
            }
            Err(message) => {
                Err(Error { message })
            }
        }
    }
}

struct ShowPaymentsTemplate {
    show_cleartext: bool,
}

impl MatchHandlerTemplate for ShowPaymentsTemplate {
    type ItemType = PaymentCard;

    fn pre_handle_matches(&self, matches: &Vec<Self::ItemType>) {
        println!("Found {} payment cards:", matches.len());
    }

    fn handle_one_match(&mut self, the_match: Self::ItemType) -> Result<Option<String>, Error> {
        ui::show_payment_cards_table(&vec![the_match.clone()], self.show_cleartext);
        copy_to_clipboard(&the_match.number);
        match ui::ask("Do you want to see the full card details? (y/n)").as_str() {
            "y" => {
                ui::show_card(&the_match);
                Ok(Some("Card number copied to clipboard!".to_string()))
            }
            _ => {
                Ok(Some("Card number copied to clipboard!".to_string()))
            }
        }
        
    }

    fn handle_many_matches(&mut self, matches: Vec<Self::ItemType>) -> Result<Option<String>, Error> {
        ui::show_payment_cards_table(&matches, self.show_cleartext);

        match ui::ask_index(
            "To see card details, enter a row number from the table above, or press q to exit:",
            matches.len() as i16 - 1,
        ) {
            Ok(index) => {
                ui::show_card(&matches[index]);
                copy_to_clipboard(&matches[index].number);
                Ok(Some("Card number copied to clipboard!".to_string()))
            }
            Err(message) => {
                Err(Error { message })
            }
        }
    }
}

struct ShowNotesTemplate {
    verbose: bool,
}

impl MatchHandlerTemplate for ShowNotesTemplate {
    type ItemType = Note;

    fn pre_handle_matches(&self, matches: &Vec<Self::ItemType>) {
        println!("Found {} notes:", matches.len());
    }

    fn handle_one_match(&mut self, the_match: Self::ItemType) -> Result<Option<String>, Error> {
        ui::show_notes_table(&vec![the_match.clone()], self.verbose);
        let response = ui::ask("Do you want to see the full note? (y/n)");
        if response == "y" {
            ui::show_note(&the_match);
        }
        Ok(None)
    }

    fn handle_many_matches(&mut self, matches: Vec<Self::ItemType>) -> Result<Option<String>, Error> {
        ui::show_notes_table(&matches, self.verbose);

        match ui::ask_index(
            "To see the full note, please enter a row number from the table above, or press q to exit:",
            matches.len() as i16 - 1,
        ) {
            Ok(index) => {
                ui::show_note(&matches[index]);
                Ok(None)
            }
            Err(message) => {
                Err(Error { message })
            }
        }
    }
}

struct ShowTotpTemplate;

impl MatchHandlerTemplate for ShowTotpTemplate {
    type ItemType = Totp;

    fn pre_handle_matches(&self, matches: &Vec<Self::ItemType>) {
        println!("Found {} matching OTP authorizers:", matches.len());
        ui::show_totp_table(matches);
    }

    fn handle_one_match(&mut self, the_match: Self::ItemType) -> Result<Option<String>, Error> {
        debug!("found totp: {}", the_match);
        Self::show_code(the_match)
    }

    fn handle_many_matches(&mut self, matches: Vec<Self::ItemType>) -> Result<Option<String>, Error> {

        match ui::ask_index(
            "To see the code for one of these OTP authorizers, please enter a row number from the table above, or press q to exit:",
            matches.len() as i16 - 1,
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
                    if input == b'q' || input == 4 { // 'q' or Ctrl+D (EOF)
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
                    println!("\nCode {} (also copied to clipboard). Press q to exit.", code.value);

                    // Send the duration to the countdown timer thread
                    tx_counter.send(code.valid_for_seconds).expect("Failed to send duration");

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
}

impl ShowAction {
    pub fn new(matches: &ArgMatches) -> ShowAction {
        ShowAction {
            grep: matches.get_one::<String>("REGEXP").cloned(),
            verbose: matches
                .get_one::<bool>("verbose")
                .map_or(false, |v| *v),
            item_type: ItemType::new_from_args(matches),
            is_totp: matches.get_one::<bool>("otp").map_or(false, |v| *v),
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
                    None => return Err(Error { message: "No search term REGEXP provided".to_string() }),
                };
                handle_matches(vault.grep(Some(grep)), &mut Box::new(ShowCredentialsTemplate { verbose: self.verbose }))
            }
            ItemType::Payment => {
                handle_matches(vault.find_payments(), &mut Box::new(ShowPaymentsTemplate { show_cleartext: self.verbose }))
            }
            ItemType::Note => {
                handle_matches(vault.find_notes(), &mut Box::new(ShowNotesTemplate { verbose: self.verbose }))
            }
            ItemType::Totp => {
                handle_matches(vault.find_totp(self.grep.as_deref()), &mut Box::new(ShowTotpTemplate))
            }
        }
    }
}