use std::sync::{Arc, Mutex};

use rustyline::completion::{Completer, Pair};
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::Result as RustylineResult;
use rustyline_derive::Helper;

use super::commands::{COMMAND_NAMES, TYPE_NAMES};

/// Commands that accept a type as their second token
const COMMANDS_WITH_TYPES: &[&str] = &[
    "show", "add", "edit", "delete", "export",
];

/// Commands that accept entry name patterns (for dynamic completion)
const COMMANDS_WITH_ENTRIES: &[&str] = &[
    "show", "edit", "delete",
];

#[derive(Helper)]
pub struct ReplHelper {
    pub entry_names: Arc<Mutex<Vec<String>>>,
}

impl ReplHelper {
    pub fn new(entry_names: Arc<Mutex<Vec<String>>>) -> Self {
        ReplHelper { entry_names }
    }
}

impl Validator for ReplHelper {}
impl Highlighter for ReplHelper {}

impl Hinter for ReplHelper {
    type Hint = String;

    fn hint(&self, _line: &str, _pos: usize, _ctx: &rustyline::Context<'_>) -> Option<String> {
        None
    }
}

fn is_type_name(token: &str) -> bool {
    TYPE_NAMES.iter().any(|t| t.eq_ignore_ascii_case(token))
}

impl Completer for ReplHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &rustyline::Context<'_>,
    ) -> RustylineResult<(usize, Vec<Self::Candidate>)> {
        let line_up_to_cursor = &line[..pos];
        let tokens: Vec<&str> = line_up_to_cursor.split_whitespace().collect();

        // If the line ends with whitespace and we have tokens, we're starting a new token
        let trailing_space = line_up_to_cursor.ends_with(' ');

        if tokens.is_empty() || (tokens.len() == 1 && !trailing_space) {
            // Completing the first token (command name)
            let prefix = tokens.first().copied().unwrap_or("");
            let start = pos - prefix.len();
            let matches = complete_from_list(prefix, COMMAND_NAMES);
            Ok((start, matches))
        } else if (tokens.len() == 1 && trailing_space) || (tokens.len() == 2 && !trailing_space) {
            // Completing the second token — could be type name or entry name
            let command = tokens[0].to_lowercase();
            let prefix = if trailing_space { "" } else { tokens[1] };
            let start = pos - prefix.len();

            if COMMANDS_WITH_TYPES.contains(&command.as_str()) {
                let mut matches = complete_from_list(prefix, TYPE_NAMES);
                // For commands that accept entries, also suggest entry names
                // (when the prefix doesn't look like a type name)
                if COMMANDS_WITH_ENTRIES.contains(&command.as_str()) {
                    let entry_matches = self.complete_entry_names(prefix);
                    matches.extend(entry_matches);
                }
                Ok((start, matches))
            } else {
                Ok((pos, vec![]))
            }
        } else if (tokens.len() == 2 && trailing_space) || (tokens.len() == 3 && !trailing_space) {
            // Completing the third token — entry names for search commands
            let command = tokens[0].to_lowercase();
            if COMMANDS_WITH_ENTRIES.contains(&command.as_str()) {
                // Only complete entry names if the second token is a type name
                let second = tokens[1].to_lowercase();
                if is_type_name(&second) || !trailing_space && tokens.len() == 3 {
                    let prefix = if trailing_space { "" } else { tokens[2] };
                    let start = pos - prefix.len();
                    let matches = self.complete_entry_names(prefix);
                    Ok((start, matches))
                } else {
                    Ok((pos, vec![]))
                }
            } else {
                Ok((pos, vec![]))
            }
        } else {
            // Fourth token or beyond — no completion
            Ok((pos, vec![]))
        }
    }
}

impl ReplHelper {
    fn complete_entry_names(&self, prefix: &str) -> Vec<Pair> {
        let lower_prefix = prefix.to_lowercase();
        match self.entry_names.lock() {
            Ok(names) => names
                .iter()
                .filter(|n| {
                    if lower_prefix.is_empty() {
                        true
                    } else {
                        // Substring match (same as passlane's grep logic)
                        n.to_lowercase().contains(&lower_prefix)
                    }
                })
                .map(|n| Pair {
                    display: n.clone(),
                    replacement: n.clone(),
                })
                .collect(),
            Err(_) => vec![],
        }
    }
}

fn complete_from_list(prefix: &str, candidates: &[&str]) -> Vec<Pair> {
    let lower_prefix = prefix.to_lowercase();
    candidates
        .iter()
        .filter(|c| c.to_lowercase().starts_with(&lower_prefix))
        .map(|c| Pair {
            display: c.to_string(),
            replacement: c.to_string(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_complete_commands() {
        let matches = complete_from_list("sh", COMMAND_NAMES);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].replacement, "show");
    }

    #[test]
    fn test_complete_commands_multiple() {
        let matches = complete_from_list("e", COMMAND_NAMES);
        let names: Vec<&str> = matches.iter().map(|p| p.replacement.as_str()).collect();
        assert!(names.contains(&"edit"));
        assert!(names.contains(&"export"));
        assert!(names.contains(&"exit"));
    }

    #[test]
    fn test_complete_types() {
        let matches = complete_from_list("ca", TYPE_NAMES);
        let names: Vec<&str> = matches.iter().map(|p| p.replacement.as_str()).collect();
        assert!(names.contains(&"cards"));
        assert!(names.contains(&"card"));
    }

    #[test]
    fn test_complete_empty_prefix_commands() {
        let matches = complete_from_list("", COMMAND_NAMES);
        assert_eq!(matches.len(), COMMAND_NAMES.len());
    }

    #[test]
    fn test_complete_no_match() {
        let matches = complete_from_list("zzz", COMMAND_NAMES);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_complete_case_insensitive() {
        let matches = complete_from_list("SH", COMMAND_NAMES);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].replacement, "show");
    }

    #[test]
    fn test_complete_entry_names_prefix() {
        let names = Arc::new(Mutex::new(vec![
            "github:alice".to_string(),
            "google:bob".to_string(),
            "gitlab:alice".to_string(),
        ]));
        let helper = ReplHelper::new(names);
        let matches = helper.complete_entry_names("gi");
        let results: Vec<&str> = matches.iter().map(|p| p.replacement.as_str()).collect();
        assert!(results.contains(&"github:alice"));
        assert!(results.contains(&"gitlab:alice"));
        assert!(!results.contains(&"google:bob"));
    }

    #[test]
    fn test_complete_entry_names_substring() {
        let names = Arc::new(Mutex::new(vec![
            "github:alice".to_string(),
            "google:bob".to_string(),
            "gitlab:alice".to_string(),
        ]));
        let helper = ReplHelper::new(names);
        // "alice" matches github:alice and gitlab:alice (substring match)
        let matches = helper.complete_entry_names("alice");
        let results: Vec<&str> = matches.iter().map(|p| p.replacement.as_str()).collect();
        assert!(results.contains(&"github:alice"));
        assert!(results.contains(&"gitlab:alice"));
        assert!(!results.contains(&"google:bob"));
    }

    #[test]
    fn test_complete_entry_names_empty_prefix() {
        let names = Arc::new(Mutex::new(vec![
            "github:alice".to_string(),
            "google:bob".to_string(),
        ]));
        let helper = ReplHelper::new(names);
        let matches = helper.complete_entry_names("");
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_complete_entry_names_no_match() {
        let names = Arc::new(Mutex::new(vec!["github:alice".to_string()]));
        let helper = ReplHelper::new(names);
        let matches = helper.complete_entry_names("zzz");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_complete_entry_names_colon_pair() {
        let names = Arc::new(Mutex::new(vec![
            "github:alice".to_string(),
            "github:bob".to_string(),
        ]));
        let helper = ReplHelper::new(names);
        // "github:a" matches only github:alice
        let matches = helper.complete_entry_names("github:a");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].replacement, "github:alice");
    }

    #[test]
    fn test_is_type_name() {
        assert!(is_type_name("creds"));
        assert!(is_type_name("CREDS"));
        assert!(is_type_name("cards"));
        assert!(is_type_name("otp"));
        assert!(!is_type_name("github"));
    }
}
