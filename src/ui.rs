use comfy_table::*;
use std::io;
use std::io::Write;

use crate::graphql::queries::{PaymentCardIn, ExpiryIn, AddressIn};
use crate::credentials::{Credentials, get_random_key};
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

pub fn ask_credentials(password: &str) -> Credentials {
    let service = ask("Enter URL or service:");
    let username = ask("Enter username:");
    Credentials {
        service,
        username,
        password: password.into(),
        iv: None,
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

pub fn show_as_table(credentials: &Vec<Credentials>, show_password: bool) {
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

pub fn ask_index(question: &str, credentials: &Vec<Credentials>) -> Result<usize, String> {
    let answer = ask(question);
    if answer == "q" {
        return Err(String::from("Quitting"));
    }
    if answer == "a" {
        return Ok(usize::MAX);
    }
    return match answer.parse::<i16>() {
        Ok(num) => {
            if num >= 0 && num < credentials.len().try_into().unwrap() {
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
        state: if state != "" {
            Some(state)
        } else {
            None
        },
        zip,
        country,
    }
}

pub fn ask_payment_info() -> PaymentCardIn {
    let name = ask("Enter card name:");
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
        number,
        name_on_card,
        expiry: ExpiryIn {
            month: card_expiration_month,
            year: card_expiration_year,
        },
        cvv,
        color: None,
        billing_address: Some(address),
    }
}
