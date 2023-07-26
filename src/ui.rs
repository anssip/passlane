use comfy_table::*;
use std::io;
use std::io::Write;

use crate::crypto::get_random_key;
use crate::graphql::queries::types::*;
use crate::store;
use anyhow::bail;
use std::cmp::min;
use webbrowser;

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

pub fn ask_credentials(password: &str) -> CredentialsIn {
    let service = ask("Enter URL or service:");
    let username = ask("Enter username:");
    CredentialsIn {
        service,
        username,
        password_encrypted: String::from(password), // maybe rename the field because its not encrypted at this point
        iv: get_random_key(),
    }
}

pub fn ask_new_password() -> String {
    let pwd = ask_password("Enter new master password. Make sure to save the master password because if you forget it there is no way to recover it! : ");
    let pwd2 = ask_password("Re-enter new master password: ");
    if pwd.eq(&pwd2) {
        pwd
    } else {
        println!("Passwords did not match");
        std::process::exit(1);
    }
}

pub fn ask_master_password(question: Option<&str>) -> String {
    let master_pwd = if let Some(q) = question {
        ask_password(q)
    } else {
        ask_password("Please enter master password: ")
    };
    match store::verify_master_password(&master_pwd, true) {
        Ok(_) => master_pwd,
        Err(message) => {
            println!("{}", message);
            std::process::exit(1);
        }
    }
}

pub fn show_credentials_table(credentials: &Vec<Credentials>, show_password: bool) {
    let mut table = Table::new();
    let mut index: i16 = 0;
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
    for creds in credentials {
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
        index += 1;
    }
    println!("{table}");
}

fn header_cell(label: String) -> Cell {
    Cell::new(label).fg(Color::Green)
}

pub fn show_payment_cards_table(cards: &Vec<PaymentCard>, show_cleartext: bool) {
    let mut table = Table::new();
    let mut index: i16 = 0;
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
    for card in cards {
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
        index += 1;
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
    return match answer.parse::<i16>() {
        Ok(num) => {
            if num >= 0 && num <= max_index as i16 {
                Ok(num.try_into().unwrap())
            } else {
                Err(String::from("Invalid index"))
            }
        }
        Err(_) => Err(String::from("Invalid index")),
    };
}

pub fn open_browser(url: &str, prompt: &str) -> Result<bool, anyhow::Error> {
    if ask(prompt) == "q" {
        bail!("Aborted")
    } else {
        Ok(webbrowser::open(url).is_ok())
    }
}

fn ask_address() -> AddressIn {
    println!("Enter billing address:");
    let street = ask("Enter street address:");
    let city = ask("Enter city:");
    let state = ask("Enter state:");
    let zip = ask("Enter postal code:");
    let country = ask("Enter country:");

    AddressIn {
        street,
        city,
        state: if state != "" { Some(state) } else { None },
        zip,
        country,
    }
}

pub fn ask_payment_info() -> PaymentCardIn {
    let name = ask("Enter card name:");
    let color = ask("Enter card color (optional):");
    let number = ask("Enter card number:");
    let name_on_card = ask("Enter card holder name:");
    let card_expiration_month = ask_number("Enter card expiration month:");
    let card_expiration_year = ask_number("Enter card expiration year:");
    let cvv = ask("Enter card cvv:");
    let address = ask_address();
    let iv = get_random_key();

    PaymentCardIn {
        iv,
        name,
        color: if color != "" { Some(color) } else { None },
        number,
        name_on_card,
        expiry: ExpiryIn {
            month: card_expiration_month,
            year: card_expiration_year,
        },
        cvv,
        billing_address: Some(address),
    }
}

pub(crate) fn ask_note_info() -> NoteIn {
    let title = ask("Enter note title:");
    let content = ask_multiline("Enter note content:");
    let iv = get_random_key();

    NoteIn {
        iv,
        title,
        content,
        vault_id: None,
    }
}

pub(crate) fn show_notes_table(notes: &Vec<Note>, show_cleartext: bool) {
    let mut table = Table::new();
    let mut index: i16 = 0;
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
    for note in notes {
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
        index += 1;
    }
    println!("{table}");
}

pub(crate) fn show_note(note: &Note) {
    println!("---------------------------");
    println!("{}\n", note.title);
    println!("{}", note.content);
    println!("---------------------------");
}
