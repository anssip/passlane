use std::path::Path;

use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::{Hinter, HistoryHinter};
use rustyline::validate::Validator;
use rustyline::{Config, DefaultEditor, Editor, Result as RustylineResult};
use rustyline_derive::Helper;

use crate::vault::entities::{Address, Credential, Expiry, Note, PaymentCard, Totp};

#[derive(Helper)]
struct MultilineHelper {
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
        hinter: HistoryHinter {},
    };
    rl.set_helper(Some(helper));

    let initial_prompt = format!(
        "{}\n(Press Enter on an empty line to finish, Ctrl+D to finish editing, use \\\\n for newlines)\n> ",
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
                if !full_input.is_empty() {
                    full_input.push('\n');
                }
                full_input.push_str(&line.replace("\\\\n", "\n"));
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
    loop {
        let answer = ask_with_initial_optional(question, default_answer, false);
        if let Some(answer) = answer {
            return answer;
        }
    }
}

pub fn ask_with_initial_optional(
    question: &str,
    default_answer: Option<&str>,
    optional: bool,
) -> Option<String> {
    let mut rl = DefaultEditor::new().unwrap();
    let prompt = format!(
        "{}{}: ",
        question,
        if optional { " (optional)" } else { "" }
    );
    let default = default_answer.unwrap_or("");

    loop {
        let readline = rl.readline_with_initial(&prompt, (default, ""));
        match readline {
            Ok(line) => {
                if line.trim().is_empty() {
                    if let Some(answer) = default_answer {
                        return Some(answer.to_string());
                    } else if !optional {
                        println!("Please enter a value");
                        continue;
                    } else {
                        return None;
                    }
                }
                return Some(line);
            }
            Err(ReadlineError::Interrupted) => {
                panic!("interrupted");
            }
            Err(ReadlineError::Eof) => {
                panic!("interrupted");
            }
            Err(err) => {
                println!("Error: {:?}", err);
                break;
            }
        }
    }
    return None;
}

pub fn ask_password(question: &str) -> String {
    match rpassword::prompt_password(format!("{}: ", question)) {
        Ok(password) => password,
        Err(_) => ask_password(question),
    }
}

pub fn ask_number(question: &str) -> u64 {
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
    Credential::new(None, password, &service, &username, None)
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
    )
}

pub(crate) fn ask_modified_address(address: &Address) -> Address {
    let street = ask_with_initial("Enter street", Some(address.street()));
    let city = ask_with_initial("Enter city", Some(address.city()));
    let zip = ask_with_initial("Enter ZIP code", Some(address.zip()));
    let country = ask_with_initial("Enter country", Some(address.country()));
    let state = ask_with_initial_optional("Enter state", address.state().map(|s| s.as_str()), true);

    Address::new(
        Some(address.id()),
        &street,
        &city,
        &country,
        state.as_deref(),
        &zip,
    )
}

pub(crate) fn ask_modified_payment_info<'a>(payment_card: &'a PaymentCard) -> PaymentCard {
    let name = ask_with_initial("Enter card name", Some(payment_card.name()));
    let color = ask_with_initial_optional(
        "Enter color",
        payment_card.color().map(|s| s.as_str()),
        true,
    );
    let cardholder_name =
        ask_with_initial("Enter card holder name", Some(payment_card.name_on_card()));
    let card_number = ask_with_initial("Enter card number", Some(payment_card.number()));
    let expiration_month = ask_with_initial(
        "Enter card expiration month",
        Some(&payment_card.expiry().month.to_string()),
    );
    let expiration_year = ask_with_initial(
        "Enter card expiration year",
        Some(&payment_card.expiry().year.to_string()),
    );
    let security_code = ask_with_initial("Enter card cvv", Some(payment_card.cvv()));
    println!("Billing address:");
    let address = match payment_card.billing_address() {
        Some(address) => ask_modified_address(&address),
        None => ask_address(),
    };

    PaymentCard::new(
        Some(payment_card.id()),
        &name,
        &cardholder_name,
        &card_number,
        &security_code,
        Expiry {
            year: expiration_year.parse().unwrap(),
            month: expiration_month.parse().unwrap(),
        },
        color.as_deref(),
        Some(&address),
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

pub(crate) fn ask_modified_totp<'a>(the_match: &'a Totp) -> Totp {
    let label = ask_with_initial("Enter label", Some(the_match.label()));
    let issuer = ask_with_initial("Enter issuer", Some(the_match.issuer()));
    let secret = ask_with_initial("Secret", Some(the_match.secret()));
    let digits = ask_with_initial("Digits", Some(&the_match.digits().to_string()))
        .parse::<u32>()
        .unwrap();
    let period = ask_with_initial("Period", Some(&the_match.period().to_string()))
        .parse::<u64>()
        .unwrap();
    let algorithm = ask_with_initial("Algorithm", Some(the_match.algorithm()));

    Totp::new(
        Some(the_match.id()),
        &format_totp_url(&label, &secret, &issuer, period, &algorithm, digits),
        &label,
        &issuer,
        &secret,
        &algorithm,
        period as u64,
        digits,
        None,
    )
}

pub fn ask_master_password(question: Option<&str>) -> String {
    if let Some(q) = question {
        ask_password(q)
    } else {
        ask_password("Please enter master password")
    }
}

pub fn ask_new_master_password() -> String {
    let pwd1 = ask_password("Please enter new master password");
    let pwd2 = ask_password("Retype new master password");
    if pwd1 != pwd2 {
        println!("Passwords do not match, please try again");
        ask_new_master_password()
    } else {
        pwd1
    }
}

pub(crate) fn ask_totp_master_password() -> String {
    ask_password("Please enter master password of the One Time Passwords vault")
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
    println!("Enter billing address");
    let street = ask("Enter street address");
    let city = ask("Enter city");
    let state = ask_with_initial_optional("Enter state", None, true);
    let zip = ask("Enter postal code");
    let country = ask("Enter country");

    Address::new(None, &street, &city, &country, state.as_deref(), &zip)
}

pub fn ask_payment_info() -> PaymentCard {
    let name = ask_with_initial("Enter card name", None);
    let color = ask_with_initial_optional("Enter card color", None, true);
    let number = ask_with_initial("Enter card number", None);
    let name_on_card = ask_with_initial("Enter card holder name", None);
    let card_expiration_month = ask_number("Enter card expiration month");
    let card_expiration_year = ask_number("Enter card expiration year");
    let cvv = ask_with_initial("Enter card cvv", None);
    let address = ask_address();

    PaymentCard::new(
        None,
        &name,
        &name_on_card,
        &number,
        &cvv,
        Expiry {
            month: card_expiration_month as u32,
            year: card_expiration_year as u32,
        },
        color.as_deref(),
        Some(&address),
        None,
    )
}

pub(crate) fn ask_note_info() -> Note {
    let title = ask_with_initial("Enter note title", None);
    let content = ask_multiline_with_initial("Enter note content", None);

    Note::new(None, &title, &content, None)
}

fn format_totp_url(
    label: &str,
    secret: &str,
    issuer: &str,
    period: u64,
    algo: &str,
    digits: u32,
) -> String {
    format!(
        "otpauth://totp/{}?secret={}&issuer={}&period={}&alorithm={}&digits={}",
        label, secret, &issuer, period, algo, digits
    )
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
            &format_totp_url(
                &label,
                &secret,
                &issuer,
                period as u64,
                &algorithm,
                digits as u32,
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
            &format_totp_url(&label, &secret, &issuer, 30, "SHA1", 6),
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

pub fn ask_vault_path(current_path: &str) -> String {
    ask_path("Enter vault location", current_path, "store.kdbx")
}

pub fn ask_totp_vault_path(current_path: &str) -> String {
    ask_path(
        "Enter vault location for Timed One Time Passwords, a.k.a. TOTPs",
        current_path,
        "totp.kdbx",
    )
}

pub fn ask_path(question: &str, default_answer: &str, default_filename: &str) -> String {
    let location = ask_with_initial(question, Some(default_answer));
    if !parent_path_exists(&location) {
        println!("Directory '{}' does not exist, please try again", &location);
        ask_path(question, default_answer, default_filename)
    } else {
        verify_file_path(&location, default_filename)
    }
}

pub fn ask_existing_path() -> String {
    let location = ask_with_initial("Enter path to existing vault file", None);
    if !Path::new(&location).is_file() {
        println!("File '{}' does not exist, please try again", &location);
        ask_existing_path()
    } else {
        location
    }
}

fn verify_file_path(location: &str, default_filename: &str) -> String {
    let file_path = Path::new(location);
    if file_path.is_file() {
        println!("File '{}' already exists, please try again", location);
        ask_path("Enter vault location", location, default_filename)
    } else {
        let path = Path::new(location);
        if path.is_dir() {
            let location_with_filename = path.join(default_filename);
            location_with_filename.to_str().unwrap().to_string()
        } else {
            location.to_string()
        }
    }
}

fn parent_path_exists(location: &str) -> bool {
    let file_path = Path::new(location);
    if file_path.is_dir() {
        return true;
    }
    if location.ends_with(".kdbx") {
        return file_path.parent().unwrap().exists();
    }
    file_path.exists()
}

pub fn ask_keyfile_path(current_path: Option<&str>) -> Option<String> {
    println!("The keyfile should be created with KeepassXC.");
    println!(
        ">> To learn more about keyfiles, visit: https://keepass.info/help/base/keys.html#keyfiles"
    );

    ask_with_initial_optional(
        "Enter location for the Keyfile to encrypt the vaults with, or leave empty to not use a keyfile",
        current_path,
        true
    )
}

pub fn newline() {
    println!();
}

pub fn ask_store_master_password() -> bool {
    ask_with_initial(
        "Store master password in keychain? You can also save it later using the 'unlock' command.",
        Some("y"),
    )
    .to_lowercase()
        == "y"
}

pub fn ask_open_existing_vault() -> bool {
    ask_with_initial(
        "Do you want to create a new vault or open an existing one? n=new, e=existing",
        Some("n"),
    )
    .to_lowercase()
        == "e"
}

pub fn ask_open_existing_totp_vault() -> bool {
    ask_with_initial(
        "Do you want to create a new TOTP vault or open an existing one? n=new, e=existing",
        Some("n"),
    )
    .to_lowercase()
        == "e"
}
