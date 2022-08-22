use core::fmt::Display;
use core::fmt::Formatter;
use hex::{self};
use magic_crypt::MagicCryptTrait;
use rand::thread_rng;
use rand::Rng;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Deserialize, Serialize)]
pub struct Credentials {
    pub username: String,
    pub password: String,
    pub iv: Option<String>,
    pub service: String,
}

impl Credentials {
    fn clone_with_password(&self, password_and_iv: (&str, &str)) -> Credentials {
        Credentials {
            password: String::from(password_and_iv.0),
            iv: Some(String::from(password_and_iv.1)),
            username: String::from(&self.username),
            service: String::from(&self.service),
        }
    }
    pub fn encrypt(&self, key: &str) -> Credentials {
        let (password, iv) = encrypt(key, &self.password);
        self.clone_with_password((&password, &iv))
    }
    pub fn decrypt(&self, key: &str) -> Credentials {
        let iv = &self.iv.as_ref().expect("Cannot decrpt without iv");
        let decrypted_passwd = decrypt((key, iv), &self.password);
        self.clone_with_password((&decrypted_passwd, iv))
    }
    pub fn migrate(&self, key: &str) -> Credentials {
        let decrypted = Credentials {
            password: decrypt_old(key, &self.password),
            iv: None,
            username: String::from(&self.username),
            service: String::from(&self.service),
        };
        decrypted.encrypt(key)
    }
}

impl Display for Credentials {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{} - username: {}", self.service, self.username)
    }
}

impl PartialEq for Credentials {
    fn eq(&self, other: &Self) -> bool {
        self.username == other.username && self.service == other.service
    }
}

impl Clone for Credentials {
    fn clone(&self) -> Self {
        Credentials {
            password: String::from(&self.password),
            iv: match &self.iv {
                Some(iv) => Some(String::from(iv)),
                None => None,
            },
            username: String::from(&self.username),
            service: String::from(&self.service),
        }
    }
}

pub fn generate() -> String {
    let low_case = "abcdefghijklmnopqrstuvxyz".to_string();
    let up_case = "ABCDEFGHIJKLMNOPQRSTUVXYZ".to_string();
    let numbers = "0123456789".to_string();
    let special = "£$&()*+[]@#^-_!?".to_string();

    let mut password = "".to_string();

    for _ in 0..=14 {
        let char_group = random_index(4);
        password = match char_group {
            0 => append(&password, &low_case),
            1 => append(&password, &up_case),
            2 => append(&password, &numbers),
            3 => append(&password, &special),
            _ => password,
        }
    }
    password
}

pub fn validate_password(value: &String) -> bool {
    if value.len() != 15 {
        return false;
    }
    // TODO: improve to check that all character classes are present
    true
}

fn random_index(range: usize) -> usize {
    let mut rng = rand::thread_rng();
    rng.gen_range(0..range.try_into().unwrap())
}

fn append(to: &String, charset: &String) -> String {
    let character = charset
        .chars()
        .nth(random_index(charset.len() - 1))
        .unwrap();
    let mut result = String::from(to);
    result.push(character);
    result
}

fn get_random_key() -> String {
    let mut arr = [0u8; 8];
    thread_rng()
        .try_fill(&mut arr[..])
        .expect("Failed to generate ramdom key");
    return hex::encode(&arr);
}

pub fn encrypt(key: &str, value: &str) -> (String, String) {
    let iv = get_random_key();
    let mc = new_magic_crypt!(key, 256, &iv);
    let encrypted = mc.encrypt_str_to_base64(value);
    (String::from(encrypted), String::from(iv))
}

fn decrypt(key_and_iv: (&str, &str), value: &String) -> String {
    let mc = new_magic_crypt!(String::from(key_and_iv.0), 256, String::from(key_and_iv.1));
    mc.decrypt_base64_to_string(value)
        .expect("Unable to decrypt credentials. Invalid password?")
}

pub fn decrypt_old(key: &str, value: &String) -> String {
    let mc = new_magic_crypt!(String::from(key), 256);
    mc.decrypt_base64_to_string(value).expect(&format!(
        "Unable to decrypt value '{}'. Invalid password?",
        value
    ))
}

pub fn encrypt_all(key: &str, credentials: &Vec<Credentials>) -> Vec<Credentials> {
    credentials.into_iter().map(|c| c.encrypt(&key)).collect()
}
