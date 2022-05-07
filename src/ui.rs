use std::io;
use std::io::Write;

use crate::password::Credentials;

pub fn ask(question: &str) -> String {
    print!("{} ", question);
    io::stdout().flush().unwrap();
    let mut buffer = String::new();
    io::stdin()
        .read_line(&mut buffer)
        .expect("failed to read line");
    buffer.trim().to_string()
}

pub fn ask_credentials() -> Credentials {
    let service = ask("Enter URL or service:");
    let username = ask("Enter username:");
    Credentials {
        service,
        username,
        password: String::from(""),
    }
}
