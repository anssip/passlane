use comfy_table::*;

use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::{Hinter, HistoryHinter};
use rustyline::validate::{MatchingBracketValidator, Validator};
use rustyline::{Config, DefaultEditor, Editor, Result as RustylineResult};
use rustyline_derive::Helper;

use std::io::{self};

use crate::vault::entities::{Address, Credential, Expiry, Note, PaymentCard, Totp};
use std::cmp::min;

#[derive(Helper)]
struct MultilineHelper {
    validator: MatchingBracketValidator,
    hinter: HistoryHinter,
}

impl Validator for MultilineHelper {}
impl Highlighter for MultilineHelper {}

impl Hinter for MultilineHelper {
    type Hint = String;

    fn hint(&self, line: &str, pos: usize, ctx: &rustyline::Context<'_>) -> Option<String> {
        self.hinter.hint(line, pos, ctx)
    }
}

impl Completer for MultilineHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        _: &str,
        pos: usize,
        _: &rustyline::Context<'_>,
    ) -> RustylineResult<(usize, Vec<Self::Candidate>)> {
        Ok((pos, vec![])) // No completion, just return an empty vector
    }
}

pub fn ask_multiline_with_initial(question: &str, default_answer: Option<&str>) -> String {
    let config = Config::builder()
        .edit_mode(rustyline::EditMode::Emacs)
        .auto_add_history(true)
        .build();
    let mut rl = Editor::with_config(config).unwrap();
    let helper = MultilineHelper {
        validator: MatchingBracketValidator::new(),
        hinter: HistoryHinter {},
    };
    rl.set_helper(Some(helper));

    let initial_prompt = format!(
        "{}\n(Press Enter on an empty line to finish, Ctrl+C to cancel, use \\\\n for newlines)\n> ",
        question
    );
    let continuation_prompt = "| ";

    let default = default_answer.unwrap_or("");

    let mut full_input = String::new();
    let mut is_first_line = true;

    loop {
        let prompt = if is_first_line {
            &initial_prompt
        } else {
            continuation_prompt
        };
        let readline = if is_first_line && !default.is_empty() {
            rl.readline_with_initial(prompt, (default, ""))
        } else {
            rl.readline(prompt)
        };

        match readline {
            Ok(line) => {
                if line.trim().is_empty() {
                    if full_input.trim().is_empty() && default_answer.is_none() {
                        println!("Please enter a value");
                        continue;
                    }
                    break;
                }
                let processed_line = line.replace("\\\\n", "\n");

                if !full_input.is_empty() {
                    full_input.push('\n');
                }
                full_input.push_str(&processed_line);
                is_first_line = false;
            }
            Err(ReadlineError::Interrupted) => {
                println!("Interrupted");
                return String::new();
            }
            Err(ReadlineError::Eof) => {
                if !full_input.trim().is_empty() {
                    break;
                } else if default_answer.is_some() {
                    return default_answer.unwrap().to_string();
                } else {
                    println!("Cancelled");
                    return String::new();
                }
            }
            Err(err) => {
                println!("Error: {:?}", err);
                return String::new();
            }
        }
    }
    full_input.trim_end().to_string()
}

pub fn ask(question: &str) -> String {
    ask_with_initial(question, None)
}

pub fn ask_with_initial(question: &str, default_answer: Option<&str>) -> String {
    let mut rl = DefaultEditor::new().unwrap();
    let prompt = format!("{}: ", question);
    let default = default_answer.unwrap_or("");

    loop {
        let readline = rl.readline_with_initial(&prompt, (default, ""));
        match readline {
            Ok(line) => {
                if line.trim().is_empty() {
                    if let Some(answer) = default_answer {
                        return answer.to_string();
                    } else {
                        println!("Please enter a value");
                        continue;
                    }
                }
                return line;
            }
            Err(ReadlineError::Interrupted) => {
                break;
            }
            Err(ReadlineError::Eof) => {
                break;
            }
            Err(err) => {
                println!("Error: {:?}", err);
                break;
            }
        }
    }
    return "".to_string();
}

pub fn ask_multiline(question: &str) -> String {
    // read multiple lines from stdin
    println!("{} (press Ctrl+D when done)", question);
    let mut buffer = String::new();
    loop {
        let mut line = String::new();
        match io::stdin().read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => buffer.push_str(&line),
            Err(error) => {
                println!("error: {}", error);
                break;
            }
        }
    }
    buffer.trim().to_string()
}

pub fn ask_password(question: &str) -> String {
    match rpassword::prompt_password(format!("{}: ", question)) {
        Ok(password) => password,
        Err(_) => ask_password(question),
    }
}

pub fn ask_number(question: &str) -> i32 {
    match ask(question).parse() {
        Ok(n) => n,
        Err(_) => {
            println!("Please enter a number: ");
            ask_number(question)
        }
    }
}

pub fn ask_credentials(password: &str) -> Credential {
    let service = ask("Enter URL or service");
    let username = ask("Enter username");
    Credential::new(None, password, &service, &username, None, None)
}

pub(crate) fn ask_modified_credential<'a>(the_match: &'a Credential) -> Credential {
    let service = ask_with_initial("Enter URL or service", Some(the_match.service()));
    let username = ask_with_initial("Enter username", Some(the_match.username()));
    let password = ask_password("Enter password, or leave empty to keep the current value");

    Credential::new(
        Some(the_match.uuid()),
        if password == "" {
            the_match.password()
        } else {
            &password
        },
        &service,
        &username,
        None,
        None,
    )
}

pub(crate) fn ask_modified_note<'a>(the_match: &'a Note) -> Note {
    let title = ask_with_initial("Enter title", Some(the_match.title()));
    let content = ask_multiline_with_initial("Enter content", Some(the_match.content()));

    Note::new(
        Some(&the_match.id()),
        &title,
        &content,
        Some(the_match.last_modified()),
    )
}

pub fn ask_master_password(question: Option<&str>) -> String {
    if let Some(q) = question {
        ask_password(q)
    } else {
        ask_password("Please enter master password")
    }
}

pub(crate) fn ask_totp_master_password() -> String {
    ask_password("Please enter master password of the One Time Passwords vault")
}

pub fn show_credentials_table(credentials: &[Credential], show_password: bool) {
    let mut table = Table::new();
    let header_cell = |label: String| -> Cell { Cell::new(label).fg(Color::Green) };
    let headers = if show_password {
        vec!["", "Service", "Username/email", "Password", "Modified"]
    } else {
        vec!["", "Service", "Username/email", "Modified"]
    };
    table.set_header(
        headers
            .iter()
            .map(|&h| header_cell(String::from(h)))
            .collect::<Vec<Cell>>(),
    );
    for (index, creds) in (0_i16..).zip(credentials.iter()) {
        let service = creds.service().to_string();
        let columns = if show_password {
            vec![
                Cell::new(index.to_string()).fg(Color::Yellow),
                Cell::new(service[..min(service.len(), 60)].to_string()),
                Cell::new(String::from(creds.username())),
                Cell::new(String::from(creds.password())),
                Cell::new(creds.last_modified().format("%d.%m.%Y %H:%M").to_string()),
            ]
        } else {
            vec![
                Cell::new(index.to_string()).fg(Color::Yellow),
                Cell::new(service[..min(service.len(), 60)].to_string()),
                Cell::new(String::from(creds.username())),
                Cell::new(creds.last_modified().format("%d.%m.%Y %H:%M").to_string()),
            ]
        };
        table.add_row(columns);
    }
    println!("{table}");
}

fn header_cell(label: String) -> Cell {
    Cell::new(label).fg(Color::Green)
}

pub fn show_payment_cards_table(cards: &Vec<PaymentCard>, show_cleartext: bool) {
    let mut table = Table::new();
    let headers = if show_cleartext {
        vec![
            "",
            "Name",
            "Color",
            "Number",
            "Expiry",
            "CVV",
            "Name on card",
            "Modified",
        ]
    } else {
        vec!["", "Name", "Color", "Expiry", "Modified"]
    };
    table.set_header(
        headers
            .iter()
            .map(|&h| header_cell(String::from(h)))
            .collect::<Vec<Cell>>(),
    );
    for (index, card) in (0_i16..).zip(cards.iter()) {
        let columns = if show_cleartext {
            vec![
                Cell::new(index.to_string()).fg(Color::Yellow),
                Cell::new(String::from(card.name())),
                Cell::new(String::from(if let Some(color) = card.color() {
                    &color
                } else {
                    ""
                })),
                Cell::new(String::from(card.number())),
                Cell::new(String::from(format!("{}", card.expiry()))),
                Cell::new(String::from(card.cvv())),
                Cell::new(String::from(card.name_on_card())),
                Cell::new(card.last_modified().format("%d.%m.%Y %H:%M").to_string()),
            ]
        } else {
            vec![
                Cell::new(index.to_string()).fg(Color::Yellow),
                Cell::new(String::from(card.name())),
                Cell::new(card.color_str()),
                Cell::new(card.expiry_str()),
                Cell::new(card.last_modified().format("%d.%m.%Y %H:%M").to_string()),
            ]
        };
        table.add_row(columns);
    }
    println!("{table}");
}

pub fn show_card(card: &PaymentCard) {
    let mut table = Table::new();
    let mut add_row = |label: &str, value: &str, color: Option<comfy_table::Color>| {
        table.add_row(vec![
            Cell::new(label).fg(if let Some(col) = color {
                col
            } else {
                Color::Yellow
            }),
            Cell::new(value),
        ]);
    };
    add_row("Name", card.name(), None);
    add_row("Color", &card.color_str(), None);
    add_row("Number", card.number(), None);
    add_row("Expiry", &card.expiry_str(), None);
    add_row("CVV", card.cvv(), None);
    add_row("Name on card", card.name_on_card(), None);
    if let Some(address) = card.billing_address() {
        add_row("Billing address", "", Some(comfy_table::Color::Cyan));
        add_row("Street", address.street(), Some(comfy_table::Color::Cyan));
        add_row("Zip", address.zip(), Some(comfy_table::Color::Cyan));
        add_row("City", address.city(), Some(comfy_table::Color::Cyan));
        if let Some(state) = address.state() {
            add_row("State", &state, Some(comfy_table::Color::Cyan));
        }
        add_row("Country", address.country(), Some(comfy_table::Color::Cyan));
    }
    println!("{table}");
}

pub fn ask_index(question: &str, max_index: i16) -> Result<usize, String> {
    let answer = ask_with_initial(question, None);
    if answer == "q" {
        return Err(String::from("Quitting"));
    }
    if answer == "a" {
        return Ok(usize::MAX);
    }
    match answer.parse::<i16>() {
        Ok(num) => {
            if num >= 0 && num <= max_index as i16 {
                Ok(num.try_into().unwrap())
            } else {
                Err(String::from("Invalid index"))
            }
        }
        Err(_) => Err(String::from("Invalid index")),
    }
}

fn ask_address() -> Address {
    println!("Enter billing address:");
    let street = ask("Enter street address:");
    let city = ask("Enter city:");
    let state = ask("Enter state:");
    let zip = ask("Enter postal code:");
    let country = ask("Enter country:");

    Address::new(
        None,
        &street,
        &city,
        &country,
        if !state.is_empty() {
            Some(&state)
        } else {
            None
        },
        &zip,
    )
}

pub fn ask_payment_info() -> PaymentCard {
    let name = ask_with_initial("Enter card name:", None);
    let color = ask("Enter card color (optional):");
    let number = ask_with_initial("Enter card number:", None);
    let name_on_card = ask_with_initial("Enter card holder name:", None);
    let card_expiration_month = ask_number("Enter card expiration month:");
    let card_expiration_year = ask_number("Enter card expiration year:");
    let cvv = ask_with_initial("Enter card cvv:", None);
    let address = ask_address();

    PaymentCard::new(
        None,
        &name,
        &name_on_card,
        &number,
        &cvv,
        Expiry {
            month: card_expiration_month,
            year: card_expiration_year,
        },
        if !color.is_empty() {
            Some(&color)
        } else {
            None
        },
        Some(&address),
        None,
    )
}

pub(crate) fn ask_note_info() -> Note {
    let title = ask_with_initial("Enter note title:", None);
    let content = ask_multiline_with_initial("Enter note content:", Some("Default\nline1\nline2"));

    Note::new(None, &title, &content, None)
}

pub(crate) fn ask_totp_info() -> Totp {
    let label = ask_with_initial(
        "Enter label, typically formatted like <issuer:username>:",
        None,
    );

    let issuer = ask_with_initial("Enter issuer:", None);
    let secret = ask_with_initial(
        "Enter secret, or leave empty to keep the current secret:",
        None,
    );

    println!("Add TOTP using settings settings (number of digits: 6, algo: SHA1, period: 30 seconds), or proceed to specify algorithm and other details (y/n)?");
    let proceed = ask_with_initial(
        "Press y (yes) to add with defaults, n (no) to specify details.",
        Some("y"),
    );

    if proceed.to_lowercase() == "n" || proceed.to_lowercase() == "no" {
        let digits = ask_number("Enter number of digits:");
        let period = ask_number("Enter period:");
        let algorithm = ask_algorithm();

        Totp::new(
            None,
            &format!(
                "otpauth://totp/{}?secret={}&issuer={}&period={}&alorithm={}&digits={}",
                label, secret, &issuer, period, algorithm, digits
            ),
            &label,
            &issuer,
            &secret,
            &algorithm,
            period as u64,
            digits as u32,
            None,
        )
    } else {
        Totp::new(
            None,
            &format!(
                "otpauth://totp/{}?secret={}&issuer={}&period=30&alorithm=sha1&digits=6",
                label, secret, issuer
            ),
            &label,
            &issuer,
            &secret,
            "SHA1",
            30,
            6,
            None,
        )
    }
}

fn ask_algorithm() -> String {
    let valid_algos = vec!["SHA1", "SHA256", "SHA512"];
    let mut algo = ask_with_initial(
        "Enter algorithm; SHA1 (default), SHA256, SHA512:",
        Some("SHA1"),
    );

    while !valid_algos.contains(&algo.to_uppercase().as_str()) {
        println!("Invalid algorithm");
        algo = ask_with_initial(
            "Enter algorithm; SHA1 (default), SHA256, SHA512:",
            Some("SHA1"),
        );
    }
    algo
}

pub(crate) fn show_notes_table(notes: &[Note], show_cleartext: bool) {
    let mut table = Table::new();
    let headers = if show_cleartext {
        vec!["", "Title", "Note", "Modified"]
    } else {
        vec!["", "Title", "Modified"]
    };
    table.set_header(
        headers
            .iter()
            .map(|&h| header_cell(String::from(h)))
            .collect::<Vec<Cell>>(),
    );
    for (index, note) in notes.iter().enumerate() {
        let columns = if show_cleartext {
            vec![
                Cell::new(index.to_string()).fg(Color::Yellow),
                Cell::new(note.title()),
                Cell::new(note.content()),
                Cell::new(&note.last_modified().format("%Y-%m-%d %H:%M:%S").to_string()),
            ]
        } else {
            vec![
                Cell::new(index.to_string()).fg(Color::Yellow),
                Cell::new(&note.title()),
                Cell::new(&note.last_modified().format("%Y-%m-%d %H:%M:%S").to_string()),
            ]
        };
        table.add_row(columns);
    }
    println!("{table}");
}

pub(crate) fn show_note(note: &Note) {
    println!("---------------------------");
    println!("{}\n", note.title());
    println!("{}", note.content());
    println!("---------------------------");
}

pub(crate) fn show_totp_table(totps: &[Totp]) {
    let mut table = Table::new();
    table.set_header(
        vec![
            header_cell("".to_string()),
            header_cell("Label".to_string()),
            header_cell("Issuer".to_string()),
            header_cell("Modified".to_string()),
        ]
        .into_iter()
        .collect::<Vec<Cell>>(),
    );
    for (index, totp) in totps.iter().enumerate() {
        table.add_row(vec![
            Cell::new(index.to_string()).fg(Color::Yellow),
            Cell::new(totp.label().to_string()),
            Cell::new(totp.issuer().to_string()),
            Cell::new(totp.last_modified().format("%d.%m.%Y %H:%M").to_string()),
        ]);
    }
    println!("{table}");
}
