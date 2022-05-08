use magic_crypt::MagicCryptTrait;
use rand::Rng;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Deserialize, Serialize)]
pub struct Credentials {
    pub username: String,
    pub password: String,
    pub service: String,
}

impl Credentials {
    pub fn encrypt(&self, key: &String) -> Credentials {
        Credentials {
            password: encrypt(key, &self.password),
            username: String::from(&self.username),
            service: String::from(&self.service),
        }
    }
    pub fn decrypt(&self, key: &String) -> Credentials {
        Credentials {
            password: decrypt(key, &self.password),
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

fn encrypt(key: &String, value: &String) -> String {
    let mc = new_magic_crypt!(key, 256);
    mc.encrypt_str_to_base64(value)
}

fn decrypt(key: &String, value: &String) -> String {
    let mc = new_magic_crypt!(key, 256);
    mc.decrypt_base64_to_string(value).unwrap()
}
