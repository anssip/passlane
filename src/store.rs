use crate::password::Credentials;
use csv::WriterBuilder;
use std::env;
use std::fs::OpenOptions;
use std::path::Path;
use std::path::PathBuf;

pub fn save(_master_pwd: &String, creds: &Credentials) {
    let home = match env::home_dir() {
        Some(path) => path,
        None => PathBuf::from("~"),
    };

    let file_path = PathBuf::from(home).join(".genpass");
    println!("path {:?}", file_path);
    let exists = Path::new(&file_path).exists();
    println!("exists? {}", exists);

    let file = OpenOptions::new()
        .create_new(!exists)
        .write(true)
        .append(true)
        .open(file_path)
        .unwrap();

    let mut wtr = WriterBuilder::new().has_headers(false).from_writer(file);
    wtr.serialize(creds).expect("Unable to store credentials");
}
