use comfy_table::*;
use std::io;
use std::io::Write;

use std::cmp::min;
use uuid::Uuid;
use crate::vault::entities::{Address, Credential, Expiry, Note, PaymentCard, Totp};
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};

pub fn ask(question: &str) -> String {
    print!("{} ", question);
    io::stdout().flush().unwrap();
    let mut buffer = String::new();
    io::stdin()
        .read_line(&mut buffer)
        .expect("failed to read line");
    buffer.trim().to_string()
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
    rpassword::prompt_password(question).unwrap()
}

pub fn ask_number(question: &str) -> i32 {
    match ask(question).parse() {
        Ok(n) => n,
        Err(_) => {
            println!("Please enter a number");
            ask_number(question)
        }
    }
}

pub fn ask_credentials(password: &str) -> Credential {
    let service = ask("Enter URL or service:");
    let username = ask("Enter username:");
    Credential {
        uuid: Uuid::new_v4(),
        service,
        username,
        password: String::from(password), // maybe rename the field because its not encrypted at this point
        notes: None,
    }
}

pub fn ask_master_password(question: Option<&str>) -> String {
    if let Some(q) = question {
        ask_password(q)
    } else {
        ask_password("Please enter master password: ")
    }
}


pub(crate) fn ask_totp_master_password() -> String {
    ask_password("Please enter master password of the One Time Passwords vault: ")
}

pub fn show_credentials_table(credentials: &[Credential], show_password: bool) {
    let mut table = Table::new();
    let header_cell = |label: String| -> Cell { Cell::new(label).fg(Color::Green) };
    let headers = if show_password {
        vec!["", "Service", "Username/email", "Password"]
    } else {
        vec!["", "Service", "Username/email"]
    };
    table.set_header(
        headers
            .iter()
            .map(|&h| header_cell(String::from(h)))
            .collect::<Vec<Cell>>(),
    );
    for (index, creds) in (0_i16..).zip(credentials.iter()) {
        let columns = if show_password {
            vec![
                Cell::new(index.to_string()).fg(Color::Yellow),
                Cell::new(String::from(&creds.service[..min(creds.service.len(), 60)])),
                Cell::new(String::from(&creds.username)),
                Cell::new(String::from(&creds.password)),
            ]
        } else {
            vec![
                Cell::new(index.to_string()).fg(Color::Yellow),
                Cell::new(String::from(&creds.service[..min(creds.service.len(), 60)])),
                Cell::new(String::from(&creds.username)),
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
        ]
    } else {
        vec!["", "Name", "Color", "Last 4", "Expiry"]
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
                Cell::new(String::from(&card.name)),
                Cell::new(String::from(if let Some(color) = &card.color {
                    &color
                } else {
                    ""
                })),
                Cell::new(String::from(&card.number)),
                Cell::new(String::from(format!("{}", &card.expiry))),
                Cell::new(String::from(&card.cvv)),
                Cell::new(String::from(&card.name_on_card)),
            ]
        } else {
            vec![
                Cell::new(index.to_string()).fg(Color::Yellow),
                Cell::new(String::from(&card.name)),
                Cell::new(card.color_str()),
                Cell::new(card.last_four()),
                Cell::new(card.expiry_str()),
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
    add_row("Name", &card.name, None);
    add_row("Color", &card.color_str(), None);
    add_row("Number", &card.number, None);
    add_row("Expiry", &card.expiry_str(), None);
    add_row("CVV", &card.cvv, None);
    add_row("Name on card", &card.name_on_card, None);
    if let Some(address) = &card.billing_address {
        add_row("Billing address", "", Some(comfy_table::Color::Cyan));
        add_row("Street", &address.street, Some(comfy_table::Color::Cyan));
        add_row("Zip", &address.zip, Some(comfy_table::Color::Cyan));
        add_row("City", &address.city, Some(comfy_table::Color::Cyan));
        if let Some(state) = &address.state {
            add_row("State", &state, Some(comfy_table::Color::Cyan));
        }
        add_row("Country", &address.country, Some(comfy_table::Color::Cyan));
    }
    println!("{table}");
}

pub fn ask_index(question: &str, max_index: i16) -> Result<usize, String> {
    let answer = ask(question);
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

    Address {
        id: Uuid::new_v4(),
        street,
        city,
        state: if state != "" { Some(state) } else { None },
        zip,
        country,
    }
}

pub fn ask_payment_info() -> PaymentCard {
    let name = ask("Enter card name:");
    let color = ask("Enter card color (optional):");
    let number = ask("Enter card number:");
    let name_on_card = ask("Enter card holder name:");
    let card_expiration_month = ask_number("Enter card expiration month:");
    let card_expiration_year = ask_number("Enter card expiration year:");
    let cvv = ask("Enter card cvv:");
    let address = ask_address();

    PaymentCard {
        id: Uuid::new_v4(),
        name,
        color: if !color.is_empty() { Some(color) } else { None },
        number,
        name_on_card,
        expiry: Expiry {
            month: card_expiration_month,
            year: card_expiration_year,
        },
        cvv,
        billing_address: Some(address),
    }
}

pub(crate) fn ask_note_info() -> Note {
    let title = ask("Enter note title:");
    let content = ask_multiline("Enter note content:");

    Note {
        id: Uuid::new_v4(),
        title,
        content,
    }
}

pub(crate) fn ask_totp_info() -> Totp {
    let label = ask("Enter label, typically formatted like <issuer:username>:");

    let issuer = ask("Enter issuer:");
    let secret = ask("Enter secret:");

    println!("Add TOTP using settings settings (number of digits: 6, algo: SHA1, period: 30 seconds), or proceed to specify algorithm and other details (y/n)?");
    let proceed = ask("Press y (yes) to add with defaults, n (no) to specify details:");

    if proceed.to_lowercase() == "n" || proceed.to_lowercase() == "no"{
        let digits = ask_number("Enter number of digits:");
        let period = ask_number("Enter period:");
        let algorithm = ask_algorithm();

        Totp {
            id: Uuid::new_v4(),
            url: format!("otpauth://totp/{}?secret={}&issuer={}&period={}&alorithm={}", label, secret, &issuer, period, algorithm),
            label: label.to_string(),
            issuer,
            secret,
            digits: digits as u32,
            algorithm,
            period: period as u64,
        }
    } else {

        Totp {
            id: Uuid::new_v4(),
            url: format!("otpauth://totp/{}?secret={}&issuer={}&period=30&alorithm=sha1", label, secret, issuer),
            label: label.to_string(),
            issuer: String::from(&issuer),
            secret,
            digits: 6u32,
            algorithm: String::from("SHA1"),
            period: 30u64,
        }
    }
}

fn ask_algorithm() -> String {
    let valid_algos = vec!["SHA1", "SHA256", "SHA512"];
    let mut algo = ask("Enter algorithm (SHA1, SHA256, SHA512):");

    while !valid_algos.contains(&algo.to_uppercase().as_str()) {
        println!("Invalid algorithm");
        algo = ask("Enter algorithm (SHA1, SHA256, SHA512):");
    }
    algo
}

pub(crate) fn show_notes_table(notes: &[Note], show_cleartext: bool) {
    let mut table = Table::new();
    let headers = if show_cleartext {
        vec!["", "Title", "Note"]
    } else {
        vec!["", "Title"]
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
                Cell::new(String::from(&note.title)),
                Cell::new(String::from(&note.content)),
            ]
        } else {
            vec![
                Cell::new(index.to_string()).fg(Color::Yellow),
                Cell::new(String::from(&note.title)),
            ]
        };
        table.add_row(columns);
    }
    println!("{table}");
}

pub(crate) fn show_note(note: &Note) {
    println!("---------------------------");
    println!("{}\n", note.title);
    println!("{}", note.content);
    println!("---------------------------");
}

pub(crate) fn show_totp_table(totps: &[Totp]) {
    let mut table = Table::new();
    table.set_header(
        vec![
            header_cell(String::from("")),
            header_cell(String::from("Label")),
            header_cell(String::from("Issuer")),
        ]
            .into_iter()
            .collect::<Vec<Cell>>(),
    );
    for (index, totp) in totps.iter().enumerate() {
        table.add_row(vec![
            Cell::new(index.to_string()).fg(Color::Yellow),
            Cell::new(String::from(&totp.label)),
            Cell::new(String::from(&totp.issuer)),
        ]);
    }
    println!("{table}");
}
