use crate::actions::ItemType;

#[derive(Debug, PartialEq)]
pub enum ReplCommand {
    Show { item_type: ItemType, grep: Option<String> },
    Add { item_type: ItemType },
    Edit { item_type: ItemType, grep: Option<String> },
    Delete { item_type: ItemType, grep: Option<String> },
    Gen,
    Import { file_path: Option<String> },
    Export { item_type: ItemType, file_path: Option<String> },
    Lock,
    Unlock { totp: bool },
    Status,
    Completions,
    Help { command: Option<String> },
    Quit,
    Empty,
    Unknown(String),
}

/// Known command names for completion
pub const COMMAND_NAMES: &[&str] = &[
    "show", "add", "edit", "delete", "gen", "import", "export",
    "unlock", "lock", "status", "completions", "help", "quit", "exit",
];

/// Known type names for completion (second token)
pub const TYPE_NAMES: &[&str] = &[
    "creds", "cred", "credentials",
    "cards", "card", "payments",
    "notes", "note",
    "otp", "totp",
];

fn parse_item_type(token: &str) -> Option<ItemType> {
    match token {
        "creds" | "cred" | "credentials" => Some(ItemType::Credential),
        "cards" | "card" | "payments" => Some(ItemType::Payment),
        "notes" | "note" => Some(ItemType::Note),
        "otp" | "totp" => Some(ItemType::Totp),
        _ => None,
    }
}

pub fn parse_input(line: &str) -> ReplCommand {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return ReplCommand::Empty;
    }

    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    let command = tokens[0].to_lowercase();
    let rest = &tokens[1..];

    match command.as_str() {
        "show" => {
            let (item_type, grep) = parse_type_and_arg(rest, ItemType::Credential);
            // For credentials with no pattern, default to show all
            let grep = match (&item_type, &grep) {
                (ItemType::Credential, None) => Some(".*".to_string()),
                _ => grep,
            };
            ReplCommand::Show { item_type, grep }
        }
        "add" => {
            let item_type = if let Some(token) = rest.first() {
                parse_item_type(&token.to_lowercase()).unwrap_or(ItemType::Credential)
            } else {
                ItemType::Credential
            };
            ReplCommand::Add { item_type }
        }
        "edit" => {
            let (item_type, grep) = parse_type_and_arg(rest, ItemType::Credential);
            ReplCommand::Edit { item_type, grep }
        }
        "delete" => {
            let (item_type, grep) = parse_type_and_arg(rest, ItemType::Credential);
            ReplCommand::Delete { item_type, grep }
        }
        "gen" => ReplCommand::Gen,
        "import" => {
            let file_path = rest.first().map(|s| s.to_string());
            ReplCommand::Import { file_path }
        }
        "export" => {
            // export [type] <file>
            if rest.is_empty() {
                ReplCommand::Export { item_type: ItemType::Credential, file_path: None }
            } else if rest.len() == 1 {
                // Could be a type or a file path
                let token = rest[0].to_lowercase();
                if let Some(item_type) = parse_item_type(&token) {
                    ReplCommand::Export { item_type, file_path: None }
                } else {
                    ReplCommand::Export { item_type: ItemType::Credential, file_path: Some(rest[0].to_string()) }
                }
            } else {
                let token = rest[0].to_lowercase();
                if let Some(item_type) = parse_item_type(&token) {
                    ReplCommand::Export { item_type, file_path: Some(rest[1].to_string()) }
                } else {
                    ReplCommand::Export { item_type: ItemType::Credential, file_path: Some(rest[0].to_string()) }
                }
            }
        }
        "lock" => ReplCommand::Lock,
        "unlock" => {
            let totp = rest.first().map_or(false, |t| {
                let lower = t.to_lowercase();
                lower == "otp" || lower == "totp"
            });
            ReplCommand::Unlock { totp }
        }
        "status" => ReplCommand::Status,
        "completions" => ReplCommand::Completions,
        "help" => {
            let command = rest.first().map(|s| s.to_lowercase());
            ReplCommand::Help { command }
        }
        "quit" | "exit" => ReplCommand::Quit,
        _ => ReplCommand::Unknown(command),
    }
}

/// Parse an optional type token and an optional argument from the remaining tokens.
/// If the second token is a known type, use it; otherwise treat it as the argument
/// and default to the provided default_type.
fn parse_type_and_arg(tokens: &[&str], default_type: ItemType) -> (ItemType, Option<String>) {
    if tokens.is_empty() {
        return (default_type, None);
    }

    let first_lower = tokens[0].to_lowercase();
    if let Some(item_type) = parse_item_type(&first_lower) {
        // Second token was a type, rest is the argument
        let arg = if tokens.len() > 1 {
            Some(tokens[1..].join(" "))
        } else {
            None
        };
        (item_type, arg)
    } else {
        // Not a type — treat as argument, use default type
        (default_type, Some(tokens.join(" ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_input() {
        assert_eq!(parse_input(""), ReplCommand::Empty);
        assert_eq!(parse_input("   "), ReplCommand::Empty);
    }

    #[test]
    fn test_quit_variants() {
        assert_eq!(parse_input("quit"), ReplCommand::Quit);
        assert_eq!(parse_input("exit"), ReplCommand::Quit);
        assert_eq!(parse_input("QUIT"), ReplCommand::Quit);
    }

    #[test]
    fn test_gen() {
        assert_eq!(parse_input("gen"), ReplCommand::Gen);
        assert_eq!(parse_input("GEN"), ReplCommand::Gen);
    }

    #[test]
    fn test_show_defaults_to_all_credentials() {
        match parse_input("show") {
            ReplCommand::Show { item_type, grep } => {
                assert_eq!(item_type, ItemType::Credential);
                assert_eq!(grep, Some(".*".to_string()));
            }
            _ => panic!("Expected Show command"),
        }
    }

    #[test]
    fn test_show_with_pattern() {
        match parse_input("show github") {
            ReplCommand::Show { item_type, grep } => {
                assert_eq!(item_type, ItemType::Credential);
                assert_eq!(grep, Some("github".to_string()));
            }
            _ => panic!("Expected Show command"),
        }
    }

    #[test]
    fn test_show_with_type() {
        match parse_input("show cards") {
            ReplCommand::Show { item_type, grep } => {
                assert_eq!(item_type, ItemType::Payment);
                assert_eq!(grep, None);
            }
            _ => panic!("Expected Show command"),
        }
    }

    #[test]
    fn test_show_with_type_and_pattern() {
        match parse_input("show creds github") {
            ReplCommand::Show { item_type, grep } => {
                assert_eq!(item_type, ItemType::Credential);
                assert_eq!(grep, Some("github".to_string()));
            }
            _ => panic!("Expected Show command"),
        }
    }

    #[test]
    fn test_show_otp() {
        match parse_input("show otp") {
            ReplCommand::Show { item_type, grep } => {
                assert_eq!(item_type, ItemType::Totp);
                assert_eq!(grep, None);
            }
            _ => panic!("Expected Show command"),
        }
    }

    #[test]
    fn test_show_otp_with_pattern() {
        match parse_input("show otp github") {
            ReplCommand::Show { item_type, grep } => {
                assert_eq!(item_type, ItemType::Totp);
                assert_eq!(grep, Some("github".to_string()));
            }
            _ => panic!("Expected Show command"),
        }
    }

    #[test]
    fn test_add_default() {
        match parse_input("add") {
            ReplCommand::Add { item_type } => {
                assert_eq!(item_type, ItemType::Credential);
            }
            _ => panic!("Expected Add command"),
        }
    }

    #[test]
    fn test_add_card() {
        match parse_input("add card") {
            ReplCommand::Add { item_type } => {
                assert_eq!(item_type, ItemType::Payment);
            }
            _ => panic!("Expected Add command"),
        }
    }

    #[test]
    fn test_add_note() {
        match parse_input("add note") {
            ReplCommand::Add { item_type } => {
                assert_eq!(item_type, ItemType::Note);
            }
            _ => panic!("Expected Add command"),
        }
    }

    #[test]
    fn test_add_otp() {
        match parse_input("add otp") {
            ReplCommand::Add { item_type } => {
                assert_eq!(item_type, ItemType::Totp);
            }
            _ => panic!("Expected Add command"),
        }
    }

    #[test]
    fn test_edit_with_pattern() {
        match parse_input("edit github") {
            ReplCommand::Edit { item_type, grep } => {
                assert_eq!(item_type, ItemType::Credential);
                assert_eq!(grep, Some("github".to_string()));
            }
            _ => panic!("Expected Edit command"),
        }
    }

    #[test]
    fn test_edit_card() {
        match parse_input("edit card") {
            ReplCommand::Edit { item_type, grep } => {
                assert_eq!(item_type, ItemType::Payment);
                assert_eq!(grep, None);
            }
            _ => panic!("Expected Edit command"),
        }
    }

    #[test]
    fn test_delete_with_pattern() {
        match parse_input("delete github") {
            ReplCommand::Delete { item_type, grep } => {
                assert_eq!(item_type, ItemType::Credential);
                assert_eq!(grep, Some("github".to_string()));
            }
            _ => panic!("Expected Delete command"),
        }
    }

    #[test]
    fn test_import_with_path() {
        match parse_input("import /path/to/file.csv") {
            ReplCommand::Import { file_path } => {
                assert_eq!(file_path, Some("/path/to/file.csv".to_string()));
            }
            _ => panic!("Expected Import command"),
        }
    }

    #[test]
    fn test_import_without_path() {
        match parse_input("import") {
            ReplCommand::Import { file_path } => {
                assert_eq!(file_path, None);
            }
            _ => panic!("Expected Import command"),
        }
    }

    #[test]
    fn test_export_with_type_and_path() {
        match parse_input("export cards cards.csv") {
            ReplCommand::Export { item_type, file_path } => {
                assert_eq!(item_type, ItemType::Payment);
                assert_eq!(file_path, Some("cards.csv".to_string()));
            }
            _ => panic!("Expected Export command"),
        }
    }

    #[test]
    fn test_export_with_path_only() {
        match parse_input("export credentials.csv") {
            ReplCommand::Export { item_type, file_path } => {
                assert_eq!(item_type, ItemType::Credential);
                assert_eq!(file_path, Some("credentials.csv".to_string()));
            }
            _ => panic!("Expected Export command"),
        }
    }

    #[test]
    fn test_lock() {
        assert_eq!(parse_input("lock"), ReplCommand::Lock);
    }

    #[test]
    fn test_unlock() {
        match parse_input("unlock") {
            ReplCommand::Unlock { totp } => assert!(!totp),
            _ => panic!("Expected Unlock command"),
        }
    }

    #[test]
    fn test_unlock_otp() {
        match parse_input("unlock otp") {
            ReplCommand::Unlock { totp } => assert!(totp),
            _ => panic!("Expected Unlock command"),
        }
    }

    #[test]
    fn test_status() {
        assert_eq!(parse_input("status"), ReplCommand::Status);
    }

    #[test]
    fn test_help_general() {
        match parse_input("help") {
            ReplCommand::Help { command } => assert_eq!(command, None),
            _ => panic!("Expected Help command"),
        }
    }

    #[test]
    fn test_help_specific() {
        match parse_input("help show") {
            ReplCommand::Help { command } => assert_eq!(command, Some("show".to_string())),
            _ => panic!("Expected Help command"),
        }
    }

    #[test]
    fn test_unknown_command() {
        match parse_input("foobar") {
            ReplCommand::Unknown(cmd) => assert_eq!(cmd, "foobar"),
            _ => panic!("Expected Unknown command"),
        }
    }

    #[test]
    fn test_completions() {
        assert_eq!(parse_input("completions"), ReplCommand::Completions);
    }

    #[test]
    fn test_completions_case_insensitive() {
        assert_eq!(parse_input("COMPLETIONS"), ReplCommand::Completions);
    }

    #[test]
    fn test_case_insensitivity() {
        match parse_input("SHOW Cards") {
            ReplCommand::Show { item_type, grep } => {
                assert_eq!(item_type, ItemType::Payment);
                assert_eq!(grep, None);
            }
            _ => panic!("Expected Show command"),
        }
    }

    #[test]
    fn test_type_aliases() {
        // credentials aliases
        match parse_input("show creds") {
            ReplCommand::Show { item_type, .. } => assert_eq!(item_type, ItemType::Credential),
            _ => panic!("Expected Show"),
        }
        match parse_input("show cred") {
            ReplCommand::Show { item_type, .. } => assert_eq!(item_type, ItemType::Credential),
            _ => panic!("Expected Show"),
        }
        match parse_input("show credentials") {
            ReplCommand::Show { item_type, .. } => assert_eq!(item_type, ItemType::Credential),
            _ => panic!("Expected Show"),
        }
        // payment aliases
        match parse_input("show payments") {
            ReplCommand::Show { item_type, .. } => assert_eq!(item_type, ItemType::Payment),
            _ => panic!("Expected Show"),
        }
        match parse_input("add payments") {
            ReplCommand::Add { item_type } => assert_eq!(item_type, ItemType::Payment),
            _ => panic!("Expected Add"),
        }
        // totp aliases
        match parse_input("show totp") {
            ReplCommand::Show { item_type, .. } => assert_eq!(item_type, ItemType::Totp),
            _ => panic!("Expected Show"),
        }
    }

    #[test]
    fn test_ambiguous_type_vs_argument() {
        // "github" is not a type, so it's treated as a search argument
        match parse_input("show github") {
            ReplCommand::Show { item_type, grep } => {
                assert_eq!(item_type, ItemType::Credential);
                assert_eq!(grep, Some("github".to_string()));
            }
            _ => panic!("Expected Show command"),
        }
    }

    #[test]
    fn test_show_notes() {
        match parse_input("show notes") {
            ReplCommand::Show { item_type, grep } => {
                assert_eq!(item_type, ItemType::Note);
                assert_eq!(grep, None);
            }
            _ => panic!("Expected Show command"),
        }
    }

    #[test]
    fn test_delete_card() {
        match parse_input("delete card") {
            ReplCommand::Delete { item_type, grep } => {
                assert_eq!(item_type, ItemType::Payment);
                assert_eq!(grep, None);
            }
            _ => panic!("Expected Delete command"),
        }
    }

    #[test]
    fn test_edit_otp() {
        match parse_input("edit otp") {
            ReplCommand::Edit { item_type, grep } => {
                assert_eq!(item_type, ItemType::Totp);
                assert_eq!(grep, None);
            }
            _ => panic!("Expected Edit command"),
        }
    }
}
