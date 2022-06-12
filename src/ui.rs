use std::io;
use std::io::Write;

use crate::password::Credentials;
use crate::store;

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

pub fn ask_credentials(password: String) -> Credentials {
    let service = ask("Enter URL or service:");
    let username = ask("Enter username:");
    Credentials {
        service,
        username,
        password,
    }
}

pub fn ask_new_password() -> String {
    let pwd = ask_password("Enter new master password: ");
    let pwd2 = ask_password("Re-enter new master password: ");
    if pwd.eq(&pwd2) {
        pwd
    } else {
        println!("Passwords did not match");
        std::process::exit(1);
    }
}

pub fn ask_master_password() -> String {
    let master_pwd = ask_password("Please enter master password: ");
    match store::verify_master_password(&master_pwd, true) {
        Ok(_) => master_pwd,
        Err(message) => {
            println!("{}", message);
            std::process::exit(1);
        }
    }
}
