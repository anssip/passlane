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

#[derive(Helper)]
pub struct ReplHelper;

impl Validator for ReplHelper {}
impl Highlighter for ReplHelper {}

impl Hinter for ReplHelper {
    type Hint = String;

    fn hint(&self, _line: &str, _pos: usize, _ctx: &rustyline::Context<'_>) -> Option<String> {
        None
    }
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
            // Completing the second token (type name) — only for commands that accept types
            let command = tokens[0].to_lowercase();
            if COMMANDS_WITH_TYPES.contains(&command.as_str()) {
                let prefix = if trailing_space { "" } else { tokens[1] };
                let start = pos - prefix.len();
                let matches = complete_from_list(prefix, TYPE_NAMES);
                Ok((start, matches))
            } else {
                Ok((pos, vec![]))
            }
        } else {
            // Third token or beyond — no completion
            Ok((pos, vec![]))
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
}
