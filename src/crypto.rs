use rand::seq::SliceRandom;
use rand::thread_rng;
use rand::Rng;

const LOW_CASE: &str = "abcdefghijklmnopqrstuvwxyz";
const UP_CASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const NUMBERS: &str = "0123456789";
pub const SPECIAL: &str = "£$&()*+[]@#^-_!?:;,.{}<>~%/\\|\"'`´^¨=§";

const PASSWORD_LENGTH: usize = 15;

pub fn generate() -> String {
    let mut rng = thread_rng();
    let classes = [LOW_CASE, UP_CASE, NUMBERS, SPECIAL];

    // Start with one character from each class so the result always passes
    // validate_password, then fill the rest from randomly chosen classes.
    let mut chars: Vec<char> = classes.iter().map(|c| random_char(&mut rng, c)).collect();
    while chars.len() < PASSWORD_LENGTH {
        let class = classes[rng.gen_range(0..classes.len())];
        chars.push(random_char(&mut rng, class));
    }
    // Shuffle so the guaranteed class characters don't sit at fixed positions.
    chars.shuffle(&mut rng);
    chars.into_iter().collect()
}

pub fn validate_password(value: &str) -> bool {
    value.chars().count() >= PASSWORD_LENGTH
        && value.chars().any(|c| LOW_CASE.contains(c))
        && value.chars().any(|c| UP_CASE.contains(c))
        && value.chars().any(|c| NUMBERS.contains(c))
        && value.chars().any(|c| SPECIAL.contains(c))
}

fn random_char(rng: &mut impl Rng, charset: &str) -> char {
    // Index over chars, not bytes — SPECIAL contains multi-byte characters.
    let count = charset.chars().count();
    charset
        .chars()
        .nth(rng.gen_range(0..count))
        .expect("index is within the charset's character count")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alphabets_are_complete() {
        assert_eq!(LOW_CASE, "abcdefghijklmnopqrstuvwxyz");
        assert_eq!(UP_CASE, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        assert_eq!(LOW_CASE.chars().count(), 26);
        assert_eq!(UP_CASE.chars().count(), 26);
    }

    #[test]
    fn generated_password_has_correct_length() {
        assert_eq!(generate().chars().count(), PASSWORD_LENGTH);
    }

    #[test]
    fn generated_password_always_validates() {
        for _ in 0..100 {
            let password = generate();
            assert!(
                validate_password(&password),
                "generated password failed validation: {}",
                password
            );
        }
    }

    #[test]
    fn random_char_reaches_last_character() {
        use rand::{rngs::StdRng, SeedableRng};
        // Seeded so the run is deterministic; 2000 draws cover all 26 chars.
        let mut rng = StdRng::seed_from_u64(42);
        assert!((0..2000).any(|_| random_char(&mut rng, LOW_CASE) == 'z'));
    }

    #[test]
    fn random_char_handles_multibyte_charsets() {
        use rand::{rngs::StdRng, SeedableRng};
        let mut rng = StdRng::seed_from_u64(42);
        for _ in 0..500 {
            let c = random_char(&mut rng, SPECIAL);
            assert!(SPECIAL.contains(c));
        }
    }
}
