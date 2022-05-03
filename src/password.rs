use rand::Rng;
extern crate clipboard;

use clipboard::ClipboardContext;
use clipboard::ClipboardProvider;

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
    copy_to_clipboard(&password);
    password
}

fn copy_to_clipboard(value: &String) {
    let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
    ctx.set_contents(String::from(value)).unwrap();
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
