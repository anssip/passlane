use hex::{self};
use magic_crypt::MagicCryptTrait;

use pbkdf2::{
    password_hash::{PasswordHasher, Salt},
    Pbkdf2,
    Params,
};
use rand::thread_rng;
use rand::Rng;

use base64::{engine::general_purpose, Engine as _};

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
    let mut rng = thread_rng();
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

pub fn get_random_key() -> String {
    let mut arr = [0u8; 8];
    thread_rng()
        .try_fill(&mut arr[..])
        .expect("Failed to generate ramdom key");
    return hex::encode(&arr);
}

pub fn derive_encryption_key(salt: &str, master_password: &str) -> String {
    let params = Params {
        rounds: 4096,
        output_length: 32,
    };
    let sanitized = salt.replace("-", "").replace(":", "").replace(".", "");
    let salt_b64 = general_purpose::STANDARD.encode(sanitized.as_bytes());
    let salt = Salt::from_b64(&salt_b64).unwrap();

    let hash = Pbkdf2
        .hash_password_customized(master_password.as_bytes(), None, None, params, salt)
        .unwrap();

    hash.hash.unwrap().to_string()
}

pub fn encrypt(key: &str, iv: &str, value: &str) -> String {
    let mc = new_magic_crypt!(key, 256, iv);
    let encrypted = mc.encrypt_str_to_base64(value);
    String::from(encrypted)
}

pub fn decrypt(key_and_iv: (&str, &str), value: &String) -> anyhow::Result<String> {
    let mc = new_magic_crypt!(String::from(key_and_iv.0), 256, String::from(key_and_iv.1));
    Ok(mc.decrypt_base64_to_string(value)?)
}
