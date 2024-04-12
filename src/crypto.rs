use rand::thread_rng;
use rand::Rng;


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
