use comfy_table::*;
use std::cmp::min;

use crate::vault::entities::{Credential, Note, PaymentCard, Totp};

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
                Cell::new(service[..min(service.len(), 30)].to_string()),
                Cell::new(String::from(creds.username())),
                Cell::new(String::from(creds.password())),
                Cell::new(creds.last_modified().format("%d.%m.%Y %H:%M").to_string()),
            ]
        } else {
            vec![
                Cell::new(index.to_string()).fg(Color::Yellow),
                Cell::new(service[..min(service.len(), 30)].to_string()),
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
