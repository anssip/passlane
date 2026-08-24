use std::path::Path;

use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::{Hinter, HistoryHinter};
use rustyline::validate::Validator;
use rustyline::{Config, Editor, Result as RustylineResult};
use rustyline_derive::Helper;

use crate::vault::entities::{
    parse_tags, Address, Credential, Expiry, Note, PaymentCard, RESERVED_CUSTOM_ATTRIBUTE_KEYS,
    Totp,
};
use chrono::{DateTime, NaiveDate, Utc};
use inquire::{Confirm, CustomType, Password, Select, Text};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};

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
    Text::new(question).prompt().unwrap()
}

pub fn ask_with_initial(
    question: &str,
    default_answer: Option<&str>,
    help_message: Option<&str>,
) -> String {
    let mut prompt = Text::new(question);
    if let Some(default) = default_answer {
        prompt = prompt.with_default(default);
    }
    if let Some(message) = help_message {
        prompt = prompt.with_help_message(message);
    }
    prompt.prompt().unwrap()
}

pub fn ask_with_initial_optional(
    question: &str,
    default_answer: Option<&str>,
    help_message: Option<&str>,
    optional: bool,
) -> Option<String> {
    let mut prompt = Text::new(question);
    if let Some(default) = default_answer {
        prompt = prompt.with_default(default);
    }
    if let Some(message) = help_message {
        prompt = prompt.with_help_message(message);
    }
    let result = prompt.prompt().unwrap();
    if !optional && result.is_empty() {
        ask_with_initial_optional(question, default_answer, help_message, optional)
    } else {
        if result == "" {
            None
        } else {
            Some(result)
        }
    }
}

pub fn ask_password(question: &str, help_message: Option<&str>) -> String {
    let mut prompt = Password::new(question).without_confirmation();
    if let Some(message) = help_message {
        prompt = prompt.with_help_message(message);
    }
    prompt.prompt().unwrap()
}

pub fn ask_new_password(question: &str) -> Option<String> {
    if ask_with_options("Do you want to change the password?", vec!["y", "n"]) == "n" {
        return None;
    }
    let prompt = Password::new(question);
    Some(prompt.prompt().unwrap())
}

pub fn ask_number(question: &str) -> u64 {
    CustomType::<u64>::new(question)
        .with_error_message("Please enter a valid number")
        .prompt()
        .unwrap()
}

pub fn ask_credentials(password: &str) -> Credential {
    let title = ask("Enter title");
    let url = ask_with_initial_optional(
        "Enter URL (optional)",
        None,
        Some("Press enter to skip"),
        true,
    );
    let username = ask("Enter username");
    let note = ask_with_initial_optional(
        "Enter note (optional)",
        None,
        Some("Press enter to skip"),
        true,
    );
    let credential = Credential::new(None, password, &title, &username, note.as_deref(), None)
        .with_url(url.as_deref());
    ask_advanced_fields(credential)
}

pub(crate) fn ask_modified_credential(the_match: &Credential) -> Credential {
    let title = ask_with_initial(
        "Enter title",
        Some(the_match.title()),
        Some("Press enter and leave empty to keep the current value shown in parentheses"),
    );
    let url = ask_with_initial_optional(
        "Enter URL (optional)",
        the_match.url(),
        Some("Press enter to keep current value, or type clear to remove"),
        true,
    );
    let username = ask_with_initial(
        "Enter username",
        Some(the_match.username()),
        Some("Press enter and leave empty to keep the current value shown in parentheses"),
    );
    let password = ask_new_password("Enter new password");
    let note = ask_with_initial_optional(
        "Enter note (optional)",
        the_match.note(),
        Some("Press enter to keep current value, or type clear to remove"),
        true,
    );

    let credential = Credential::new(
        Some(the_match.uuid()),
        password.as_deref().unwrap_or(the_match.password()),
        &title,
        &username,
        edited_optional_field(note, the_match.note()).as_deref(),
        None,
    )
    .with_url(edited_optional_field(url, the_match.url()).as_deref())
    // Carry the advanced fields over so skipping the advanced step below
    // preserves them; opting in re-prompts with these as the defaults.
    .with_tags(the_match.tags())
    .with_expiry(the_match.expires(), the_match.expiry_time())
    .with_custom_attributes(the_match.custom_attributes());
    ask_advanced_fields(credential)
}

/// Interpret optional-field input during edit: an unchanged prompt keeps the
/// current value, the literal word "clear" removes it, anything else is the
/// new value.
fn edited_optional_field(input: Option<String>, current: Option<&str>) -> Option<String> {
    match input {
        None => current.map(|value| value.to_string()),
        Some(value) if value.eq_ignore_ascii_case("clear") => None,
        Some(value) => Some(value),
    }
}

/// Offer the advanced credential fields (tags, expiry date, custom
/// attributes). Skipped unless the user opts in; fields the user never sees
/// keep the values already stored on the credential.
fn ask_advanced_fields(credential: Credential) -> Credential {
    let configure =
        Confirm::new("Configure advanced fields (tags, expiry date, custom attributes)?")
            .with_default(false)
            .prompt()
            .unwrap_or(false);
    if !configure {
        return credential;
    }
    let tags = ask_tags(Some(credential.tags()));
    let (expires, expiry_time) = ask_expiry(credential.expires(), credential.expiry_time());
    let attributes = ask_custom_attributes(Some(credential.custom_attributes()));
    credential
        .with_tags(&tags)
        .with_expiry(expires, expiry_time)
        .with_custom_attributes(&attributes)
}

fn ask_tags(current: Option<&[String]>) -> Vec<String> {
    let default = current.map(|tags| tags.join(";"));
    let input = ask_with_initial_optional(
        "Enter tags, separated by semicolons",
        default.as_deref(),
        Some("Press enter to keep current value, or type clear to remove all tags"),
        true,
    );
    match input {
        Some(text) if text.eq_ignore_ascii_case("clear") => Vec::new(),
        Some(text) => parse_tags(&text),
        None => Vec::new(),
    }
}

fn ask_expiry(
    current_expires: bool,
    current_expiry: Option<DateTime<Utc>>,
) -> (bool, Option<DateTime<Utc>>) {
    let expires = Confirm::new("Does this credential expire?")
        .with_default(current_expires)
        .prompt()
        .unwrap_or(false);
    if !expires {
        return (false, None);
    }
    let default = current_expiry.map(|dt| dt.format("%Y-%m-%d").to_string());
    loop {
        // optional=false re-prompts on empty input when there is no default
        let input = ask_with_initial_optional(
            "Enter expiry date (YYYY-MM-DD)",
            default.as_deref(),
            Some("Press enter to keep the current value"),
            default.is_none(),
        );
        let Some(raw) = input else {
            continue;
        };
        match NaiveDate::parse_from_str(&raw, "%Y-%m-%d") {
            Ok(date) => return (true, Some(date.and_hms_opt(0, 0, 0).unwrap().and_utc())),
            Err(_) => println!("Invalid date '{}', please use the YYYY-MM-DD format", raw),
        }
    }
}

fn ask_custom_attributes(current: Option<&[(String, String)]>) -> Vec<(String, String)> {
    let mut attributes: Vec<(String, String)> =
        current.map(|attrs| attrs.to_vec()).unwrap_or_default();
    loop {
        if !attributes.is_empty() {
            println!("Custom attributes:");
            for (key, value) in &attributes {
                println!("  {} = {}", key, value);
            }
        }
        let mut options = vec!["Add attribute"];
        if !attributes.is_empty() {
            options.push("Remove attribute");
        }
        options.push("Done");
        match ask_with_options("Custom attributes", options).as_str() {
            "Add attribute" => {
                let key = ask_attribute_name(&attributes);
                let value = ask("Enter attribute value");
                attributes.push((key, value));
            }
            "Remove attribute" => {
                let keys: Vec<String> =
                    attributes.iter().map(|(key, _)| key.clone()).collect();
                match Select::new("Which attribute should be removed?", keys).prompt() {
                    Ok(key) => attributes.retain(|(k, _)| k != &key),
                    Err(_) => println!("No attribute removed"),
                }
            }
            _ => return attributes,
        }
    }
}

fn ask_attribute_name(existing: &[(String, String)]) -> String {
    loop {
        let name = ask("Enter attribute name");
        let name = name.trim().to_string();
        if name.is_empty() {
            continue;
        }
        if RESERVED_CUSTOM_ATTRIBUTE_KEYS.contains(&name.as_str()) {
            println!(
                "'{}' is a reserved KeePass field name, please choose another",
                name
            );
            continue;
        }
        if existing.iter().any(|(key, _)| key == &name) {
            println!("An attribute named '{}' already exists", name);
            continue;
        }
        return name;
    }
}

pub(crate) fn ask_modified_address(address: &Address) -> Address {
    let street = ask_with_initial("Enter street", Some(address.street()), None);
    let city = ask_with_initial("Enter city", Some(address.city()), None);
    let zip = ask_with_initial("Enter ZIP code", Some(address.zip()), None);
    let country = ask_with_initial("Enter country", Some(address.country()), None);
    let state = ask_with_initial_optional(
        "Enter state",
        address.state().map(|s| s.as_str()),
        None,
        true,
    );

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
    let name = ask_with_initial("Enter card name", Some(payment_card.name()), None);
    let color = ask_with_initial_optional(
        "Enter color",
        payment_card.color().map(|s| s.as_str()),
        None,
        true,
    );
    let cardholder_name = ask_with_initial(
        "Enter card holder name",
        Some(payment_card.name_on_card()),
        None,
    );
    let card_number = ask_with_initial("Enter card number", Some(payment_card.number()), None);
    let expiration_month = ask_with_initial(
        "Enter card expiration month",
        Some(&payment_card.expiry().month.to_string()),
        None,
    );
    let expiration_year = ask_with_initial(
        "Enter card expiration year",
        Some(&payment_card.expiry().year.to_string()),
        None,
    );
    let security_code = ask_with_initial("Enter card cvv", Some(payment_card.cvv()), None);
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
    let title = ask_with_initial("Enter title", Some(the_match.title()), None);
    let content = ask_multiline_with_initial("Enter content", Some(the_match.content()));

    Note::new(
        Some(&the_match.id()),
        &title,
        &content,
        Some(the_match.last_modified()),
    )
}

pub(crate) fn ask_modified_totp<'a>(the_match: &'a Totp) -> Totp {
    let label = ask_with_initial("Enter label", Some(the_match.label()), None);
    let issuer = ask_with_initial("Enter issuer", Some(the_match.issuer()), None);
    let secret = ask_with_initial("Secret", Some(the_match.secret()), None);
    let digits = ask_with_initial("Digits", Some(&the_match.digits().to_string()), None)
        .parse::<u32>()
        .unwrap();
    let period = ask_with_initial("Period", Some(&the_match.period().to_string()), None)
        .parse::<u64>()
        .unwrap();
    let algorithm = ask_with_initial("Algorithm", Some(the_match.algorithm()), None);

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

fn ask_master_password_with<F: Fn(&str) -> String>(question: Option<&str>, reader: F) -> String {
    let q = question.unwrap_or("Please enter master password");
    reader(q)
}

pub fn ask_master_password(question: Option<&str>) -> String {
    ask_master_password_with(question, |q| ask_password(q, None))
}

fn ask_new_master_password_with<F: FnMut(&str) -> String>(mut reader: F) -> String {
    let pwd1 = reader("Please enter new master password");
    let pwd2 = reader("Retype new master password");
    if pwd1 != pwd2 {
        println!("Passwords do not match, please try again");
        ask_new_master_password_with(reader)
    } else {
        pwd1
    }
}

pub fn ask_new_master_password() -> String {
    ask_new_master_password_with(|q| ask_password(q, None))
}

pub fn ask_index(
    question: &str,
    max_index: i16,
    help_message: Option<&str>,
) -> Result<usize, String> {
    let answer = ask_with_initial(question, None, help_message);
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
    let state = ask_with_initial_optional(
        "Enter state",
        None,
        Some("leave empty if not applicable"),
        true,
    );
    let zip = ask("Enter postal code");
    let country = ask("Enter country");

    Address::new(None, &street, &city, &country, state.as_deref(), &zip)
}

pub fn ask_payment_info() -> PaymentCard {
    let name = ask_with_initial("Enter card name", None, None);
    let color = ask_with_initial_optional("Enter card color", None, None, true);
    let number = ask_with_initial("Enter card number", None, None);
    let name_on_card = ask_with_initial("Enter card holder name", None, None);
    let card_expiration_month = ask_number("Enter card expiration month");
    let card_expiration_year = ask_number("Enter card expiration year");
    let cvv = ask_with_initial(
        "Enter card cvv",
        None,
        Some("Card Verification Value: 3 or 4 digits that are usually located on the back of the card in the signature panel"),
    );
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
    let title = ask_with_initial("Enter note title", None, None);
    let content = ask_multiline_with_initial("Enter note content", None);

    Note::new(None, &title, &content, None)
}

/// Query values are percent-decoded by otpauth parsers; the label is a URL
/// path segment where ':' and '@' are legal, so those stay readable.
const TOTP_URL_QUERY: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');
/// The secret keeps '=' literal: it is base32 padding, and the vault-side
/// normalize_otp_url re-pads the raw secret substring, so encoding it as
/// %3D would make that normalization append bogus padding.
const TOTP_URL_SECRET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~')
    .remove(b'=');
const TOTP_URL_LABEL: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~')
    .remove(b':')
    .remove(b'@');

fn format_totp_url(
    label: &str,
    secret: &str,
    issuer: &str,
    period: u64,
    algo: &str,
    digits: u32,
) -> String {
    format!(
        "otpauth://totp/{}?secret={}&issuer={}&period={}&algorithm={}&digits={}",
        utf8_percent_encode(label, TOTP_URL_LABEL),
        utf8_percent_encode(secret, TOTP_URL_SECRET),
        utf8_percent_encode(issuer, TOTP_URL_QUERY),
        period,
        algo,
        digits
    )
}

pub(crate) fn ask_totp_info() -> Totp {
    let label = ask_with_initial(
        "Enter label, typically formatted like <issuer:username>:",
        None,
        None,
    );

    let issuer = ask_with_initial("Enter issuer:", None, None);
    let secret = ask_with_initial(
        "Enter secret, or leave empty to keep the current secret:",
        None,
        None,
    );

    println!("Add TOTP using settings settings (number of digits: 6, algo: SHA1, period: 30 seconds), or proceed to specify algorithm and other details (y/n)?");
    let proceed = ask_with_initial(
        "Press y (yes) to add with defaults, n (no) to specify details.",
        Some("y"),
        None,
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
        None,
    );

    while !valid_algos.contains(&algo.to_uppercase().as_str()) {
        println!("Invalid algorithm");
        algo = ask_with_initial(
            "Enter algorithm; SHA1 (default), SHA256, SHA512:",
            Some("SHA1"),
            None,
        );
    }
    algo
}

const VAULT_HELP_MESSAGE: &str = "You can specify your Dropbox folder here to make it easier to sync the vault between devices, or any other folder you want to store the vault in.";

pub fn ask_vault_path(current_path: &str) -> String {
    ask_path(
        "Enter vault location",
        current_path,
        "store.kdbx",
        Some(VAULT_HELP_MESSAGE),
    )
}

pub fn ask_path(
    question: &str,
    default_answer: &str,
    default_filename: &str,
    help_message: Option<&str>,
) -> String {
    // Expand ~ and make the answer absolute: the registry stores absolute
    // paths, and Path-based validation below cannot resolve a raw "~".
    let location = crate::vault_registry::absolutize(&ask_with_initial(
        question,
        Some(default_answer),
        help_message,
    ));
    if !parent_path_exists(&location) {
        println!("'{}' does not exist, please try again", &location);
        ask_path(question, default_answer, default_filename, help_message)
    } else {
        verify_file_path(&location, default_filename)
    }
}

pub fn ask_existing_path() -> String {
    let location = crate::vault_registry::absolutize(&ask_with_initial(
        "Enter path to existing vault file",
        None,
        None,
    ));
    if !Path::new(&location).is_file() {
        println!("File '{}' does not exist, please try again", location);
        ask_existing_path()
    } else {
        location
    }
}

fn verify_file_path(location: &str, default_filename: &str) -> String {
    let file_path = Path::new(location);
    if file_path.is_file() {
        println!("File '{}' already exists, please try again", location);
        ask_path("Enter vault location", location, default_filename, None)
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
    ask_with_initial_optional(
        "Enter location for the Keyfile to encrypt the vaults with, or leave empty to not use a keyfile",
        current_path,
        Some("The keyfile should be created with KeepassXC. To learn more about keyfiles, visit: https://keepass.info/help/base/keys.html#keyfiles"),
        true,
    )
    .map(|path| crate::vault_registry::absolutize(&path))
}

pub fn newline() {
    println!();
}

pub fn ask_store_master_password() -> bool {
    Confirm::new(
        "Store master password in keychain? You can also save it later using the 'unlock' command.",
    )
    .with_default(true)
    .prompt()
    .unwrap()
}

pub fn ask_vault_name() -> String {
    ask_with_initial(
        "Enter a name for the vault",
        Some("default"),
        Some("A short name like 'personal', 'work' or 'family'. Used to pick the vault: --vault <name>."),
    )
}

pub fn ask_make_vault_active(name: &str) -> bool {
    Confirm::new(&format!("Make '{}' the active vault?", name))
        .with_default(true)
        .prompt()
        .unwrap()
}

pub fn ask_remove_vault(name: &str) -> bool {
    Confirm::new(&format!(
        "Remove vault '{}' from passlane? The vault file itself is not deleted.",
        name
    ))
    .with_default(false)
    .prompt()
    .unwrap()
}

pub fn ask_store_hwkey() -> bool {
    Confirm::new(
        "Protect the vault with a hardware key (e.g. a YubiKey)? It becomes an additional unlock factor: the key must be connected and touched every time the vault is opened or saved.",
    )
    .with_default(false)
    .with_help_message("Requires a key with a programmed HMAC-SHA1 challenge-response slot. Program one with e.g. 'ykman otp chalresp --generate 2' and save the printed secret.")
    .prompt()
    .unwrap()
}

pub fn ask_open_existing_vault() -> bool {
    Select::new(
        "Do you want to create a new vault or open an existing one?",
        vec!["New", "Existing"],
    )
    .prompt()
    .unwrap()
        == "Existing"
}

pub fn ask_with_options(question: &str, options: Vec<&str>) -> String {
    Select::new(question, options).prompt().unwrap().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn totp_url_preserves_algorithm() {
        use keepass_ng::db::TOTP;
        use std::str::FromStr;

        let url = format_totp_url("GitHub:user", "JBSWY3DPEHPK3PXP", "GitHub", 30, "SHA256", 8);
        let totp = TOTP::from_str(&url).expect("generated otpauth URL must parse");
        assert_eq!(totp.algorithm.to_string(), "SHA256");
        assert_eq!(totp.issuer.as_deref(), Some("GitHub"));
        assert_eq!(totp.period, 30);
        assert_eq!(totp.digits, 8);
    }

    #[test]
    fn totp_url_percent_encodes_components() {
        use keepass_ng::db::TOTP;
        use std::str::FromStr;

        let url = format_totp_url(
            "My Service:user@example.com",
            "GEZDGNBVGY======",
            "Foo & Bar Inc",
            60,
            "SHA512",
            6,
        );
        // '&', '=' and spaces must not corrupt the query string.
        let totp = TOTP::from_str(&url).expect("generated otpauth URL must parse");
        assert_eq!(totp.issuer.as_deref(), Some("Foo & Bar Inc"));
        assert_eq!(totp.algorithm.to_string(), "SHA512");
        assert_eq!(totp.period, 60);
        assert!(url.starts_with("otpauth://totp/My%20Service:user@example.com?"));
        // Base32 padding must stay literal so vault-side secret
        // normalization sees real '=' characters, not %3D.
        assert!(url.contains("secret=GEZDGNBVGY======"));
    }

    #[test]
    fn test_ask_master_password_prompts_once() {
        let count = Cell::new(0u32);
        let result = ask_master_password_with(None, |_q| {
            count.set(count.get() + 1);
            "secret".to_string()
        });
        assert_eq!(count.get(), 1);
        assert_eq!(result, "secret");
    }

    #[test]
    fn test_ask_new_master_password_prompts_twice_on_match() {
        let count = Cell::new(0u32);
        let result = ask_new_master_password_with(|_q| {
            count.set(count.get() + 1);
            "matching".to_string()
        });
        assert_eq!(count.get(), 2);
        assert_eq!(result, "matching");
    }

    #[test]
    fn test_ask_new_master_password_retries_on_mismatch() {
        let count = Cell::new(0u32);
        let result = ask_new_master_password_with(|_q| {
            let n = count.get();
            count.set(n + 1);
            match n {
                0 => "first".to_string(),
                1 => "second".to_string(),
                _ => "correct".to_string(),
            }
        });
        assert_eq!(count.get(), 4);
        assert_eq!(result, "correct");
    }
}
