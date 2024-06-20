use rand::thread_rng;
use rand::Rng;

const LOW_CASE: &str = "abcdefghijklmnopqrstuvxyz";
const UP_CASE: &str = "ABCDEFGHIJKLMNOPQRSTUVXYZ";
const NUMBERS: &str = "0123456789";
pub const SPECIAL: &str = "£$&()*+[]@#^-_!?:;,.{}<>~%/\\|\"'`´^¨=§";

pub fn generate() -> String {
    let mut password = "".to_string();

    for _ in 0..=14 {
        let char_group = random_index(4);
        password = match char_group {
            0 => append(&password, &LOW_CASE.to_string()),
            1 => append(&password, &UP_CASE.to_string()),
            2 => append(&password, &NUMBERS.to_string()),
            3 => append(&password, &SPECIAL.to_string()),
            _ => password,
        }
    }
    password
}

pub fn validate_password(value: &String) -> bool {
    value.len() >= 15
        && value.chars().any(|c| LOW_CASE.contains(c))
        && value.chars().any(|c| UP_CASE.contains(c))
        && value.chars().any(|c| NUMBERS.contains(c))
        && value.chars().any(|c| SPECIAL.contains(c))
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
