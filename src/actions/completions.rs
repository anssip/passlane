use std::io::Write;
use std::path::PathBuf;

use clap::Command;
use clap_complete::{generate, Shell};

use crate::actions::Action;
use crate::completion_cache;
use crate::store;
use crate::vault::entities::Error;

pub struct CompletionsAction {
    pub shell: Option<String>,
    pub cmd: Command,
}

impl CompletionsAction {
    pub fn new(shell: Option<String>, cmd: Command) -> Self {
        CompletionsAction { shell, cmd }
    }

    fn resolve_shell(&self) -> Result<Shell, Error> {
        if let Some(ref shell_str) = self.shell {
            match shell_str.to_lowercase().as_str() {
                "bash" => Ok(Shell::Bash),
                "zsh" => Ok(Shell::Zsh),
                "fish" => Ok(Shell::Fish),
                other => Err(Error::new(&format!(
                    "Unsupported shell: '{}'. Supported shells: bash, zsh, fish",
                    other
                ))),
            }
        } else {
            Shell::from_env().ok_or_else(|| {
                Error::new(
                    "Could not detect your shell from $SHELL. \
                     Please specify one explicitly: passlane completions <bash|zsh|fish>",
                )
            })
        }
    }
}

fn completions_dir() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("~"));
    home.join(".passlane")
}

fn completions_filename(shell: Shell) -> &'static str {
    match shell {
        Shell::Bash => "completions.bash",
        Shell::Zsh => "completions.zsh",
        Shell::Fish => "completions.fish",
        _ => "completions.sh",
    }
}

fn source_command(shell: Shell, path: &str) -> String {
    match shell {
        Shell::Bash => format!("source \"{}\"", path),
        Shell::Zsh => format!("source \"{}\"", path),
        Shell::Fish => format!("source \"{}\"", path),
        _ => format!("source \"{}\"", path),
    }
}

fn rc_file(shell: Shell) -> &'static str {
    match shell {
        Shell::Bash => "~/.bashrc",
        Shell::Zsh => "~/.zshrc",
        Shell::Fish => "~/.config/fish/config.fish",
        _ => "your shell rc file",
    }
}

/// Try to open the vault and generate the completion cache.
/// Uses keychain password if available, otherwise prompts the user.
fn generate_cache() -> Result<usize, Error> {
    use crate::keychain;
    use crate::ui::input::ask_master_password;
    use crate::vault::keepass_vault::KeepassVault;
    use crate::vault::vault_trait::{PasswordVault, Vault};

    let master_pwd = match keychain::get_master_password() {
        Ok(pwd) => pwd,
        Err(_) => {
            println!("\nTo enable dynamic completions, enter your vault master password.");
            println!("(This is only used to read service names — the password is not stored.)\n");
            ask_master_password(None)
        }
    };

    let filepath = store::get_vault_path();
    let keyfile_path = store::get_keyfile_path();

    println!("Opening vault to build completion cache...");
    let vault = KeepassVault::open(&master_pwd, &filepath, keyfile_path)?;
    let count = vault.grep(None).len();
    let boxed: Box<dyn Vault> = Box::new(vault);
    completion_cache::update_cache(&boxed);
    Ok(count)
}

fn cache_file_path() -> String {
    let home = dirs::home_dir()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|| "~".to_string());
    format!("{}/.passlane/.completion_cache", home)
}

/// Post-process the generated completion script to replace default/file completions
/// with cache-based completions for REGEXP arguments in show/edit/delete/list.
fn patch_script(shell: Shell, script: &str) -> String {
    match shell {
        Shell::Zsh => patch_zsh(script),
        Shell::Bash => patch_bash(script),
        Shell::Fish => patch_fish(script),
        _ => script.to_string(),
    }
}

fn patch_zsh(script: &str) -> String {
    // In zsh completions, REGEXP args appear as:
    //   '::REGEXP -- description:_default'
    // Replace :_default with :_passlane_cache_entries for REGEXP args
    script
        .lines()
        .map(|line| {
            if line.contains("REGEXP") && line.contains(":_default") {
                line.replace(":_default", ":_passlane_cache_entries")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn patch_bash(script: &str) -> String {
    let cache_path = cache_file_path();
    // In bash completions, each subcommand case ends with:
    //   COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
    //   return 0
    //
    // For show/edit/delete/list, we insert cache-based completions before the
    // final return. We detect these sections by looking for case labels like
    // "passlane__show)" and inject a cache read block.
    let subcommands_with_cache = [
        "passlane__show)",
        "passlane__edit)",
        "passlane__delete)",
        "passlane__list)",
    ];

    let mut result = Vec::new();
    let mut in_target_subcommand = false;

    for line in script.lines() {
        let trimmed = line.trim();

        // Detect entry into a target subcommand section
        if subcommands_with_cache.iter().any(|s| trimmed == *s) {
            in_target_subcommand = true;
            result.push(line.to_string());
            continue;
        }

        // Detect exit from subcommand section
        if in_target_subcommand && trimmed == ";;" {
            in_target_subcommand = false;
            result.push(line.to_string());
            continue;
        }

        // Replace empty COMPREPLY in the default case with cache-based completion
        if in_target_subcommand && trimmed == "COMPREPLY=()" {
            // Substring match: use grep -i to filter cache entries containing the typed text
            result.push(format!(
                "                    if [[ -f \"{}\" ]] && [[ -s \"{}\" ]]; then local _entries; if [[ -n \"${{cur}}\" ]]; then _entries=$(grep -i \"${{cur}}\" \"{}\" 2>/dev/null); else _entries=$(cat \"{}\"); fi; if [[ -n \"$_entries\" ]]; then COMPREPLY=( $_entries ); else COMPREPLY=( $(compgen -W \"${{opts}}\" -- \"${{cur}}\") ); fi; else COMPREPLY=( $(compgen -W \"${{opts}}\" -- \"${{cur}}\") ); fi",
                cache_path, cache_path, cache_path, cache_path
            ));
            continue;
        }

        result.push(line.to_string());
    }

    result.join("\n")
}

fn patch_fish(script: &str) -> String {
    // Fish completions: clap generates lines like:
    //   complete -c passlane -n "__fish_seen_subcommand_from show" -l ... -d '...'
    // We don't need to patch the generated output — we just append our
    // dynamic complete commands (done in dynamic_completion_script).
    // But we should remove any -F (force file completion) flags for
    // subcommands that take REGEXP args.
    script
        .lines()
        .map(|line| {
            // Remove -F flag from show/edit/delete/list subcommand completions
            // that would force file completion for positional args
            if (line.contains("__fish_seen_subcommand_from show")
                || line.contains("__fish_seen_subcommand_from edit")
                || line.contains("__fish_seen_subcommand_from delete")
                || line.contains("__fish_seen_subcommand_from list"))
                && line.contains(" -F")
            {
                line.replace(" -F", "")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn dynamic_completion_script(shell: Shell) -> String {
    let cache_path = cache_file_path();
    match shell {
        Shell::Zsh => format!(
            r#"

# Dynamic completions from passlane completion cache (service:username pairs)
_passlane_cache_entries() {{
    local cache_file="{cache_path}"
    if [[ -f "$cache_file" ]]; then
        local -a entries
        local cur="${{words[CURRENT]}}"
        if [[ -n "$cur" ]]; then
            # Substring match: filter entries containing the typed text
            entries=(${{(f)"$(grep -i "$cur" "$cache_file" 2>/dev/null)"}})
        else
            entries=(${{(f)"$(< "$cache_file")"}})
        fi
        if (( $#entries )); then
            compadd -U -a entries
            return 0
        fi
    fi
}}
"#,
        ),
        Shell::Fish => format!(
            r#"
# Dynamic completions from passlane completion cache (service:username pairs)
function __passlane_cache_entries
    set -l cache_file "{cache_path}"
    if test -f $cache_file
        set -l tok (commandline -ct)
        if test -n "$tok"
            grep -i "$tok" $cache_file 2>/dev/null
        else
            cat $cache_file
        end
    end
end

# Add dynamic completions for commands that accept entry patterns
complete -c passlane -n "__fish_seen_subcommand_from show" -f -a "(__passlane_cache_entries)"
complete -c passlane -n "__fish_seen_subcommand_from edit" -f -a "(__passlane_cache_entries)"
complete -c passlane -n "__fish_seen_subcommand_from delete" -f -a "(__passlane_cache_entries)"
complete -c passlane -n "__fish_seen_subcommand_from list" -f -a "(__passlane_cache_entries)"
"#,
        ),
        // Bash: dynamic completions are patched inline (no append needed)
        _ => String::new(),
    }
}

impl Action for CompletionsAction {
    fn run(&self) -> Result<String, Error> {
        let shell = self.resolve_shell()?;
        let mut cmd = self.cmd.clone();

        // Generate base completions from clap
        let mut buf = Vec::new();
        generate(shell, &mut cmd, "passlane", &mut buf);

        // Post-process: replace file completions with cache-based completions
        let mut script = String::from_utf8(buf).unwrap_or_default();
        script = patch_script(shell, &script);

        // Append dynamic completion function definitions (zsh, fish)
        let dynamic = dynamic_completion_script(shell);
        if !dynamic.is_empty() {
            script.push_str(&dynamic);
        }

        // Write to file in ~/.passlane/
        let dir = completions_dir();
        std::fs::create_dir_all(&dir).map_err(|e| Error::new(&e.to_string()))?;
        let file_path = dir.join(completions_filename(shell));
        let mut file =
            std::fs::File::create(&file_path).map_err(|e| Error::new(&e.to_string()))?;
        file.write_all(script.as_bytes())
            .map_err(|e| Error::new(&e.to_string()))?;

        let path_str = file_path.to_string_lossy();
        let source_cmd = source_command(shell, &path_str);

        // Try to generate the completion cache so dynamic completions work immediately
        let cache_msg = if store::has_vault_path() {
            match generate_cache() {
                Ok(count) => format!("\nCompletion cache created with {} entries.", count),
                Err(e) => format!("\nNote: Could not create completion cache: {}", e),
            }
        } else {
            "\nNo vault configured yet — completion cache will be created when you first use the vault.".to_string()
        };

        Ok(format!(
            "Completions saved to {}\n\nAdd this line to {}:\n\n  {}\n\nThen restart your shell or run the command above.{}",
            path_str,
            rc_file(shell),
            source_cmd,
            cache_msg,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cmd() -> Command {
        Command::new("passlane")
            .subcommand(Command::new("show"))
            .subcommand(Command::new("add"))
            .subcommand(Command::new("completions"))
    }

    #[test]
    fn test_resolve_shell_explicit_bash() {
        let action = CompletionsAction::new(Some("bash".to_string()), test_cmd());
        assert_eq!(action.resolve_shell().unwrap(), Shell::Bash);
    }

    #[test]
    fn test_resolve_shell_explicit_zsh() {
        let action = CompletionsAction::new(Some("zsh".to_string()), test_cmd());
        assert_eq!(action.resolve_shell().unwrap(), Shell::Zsh);
    }

    #[test]
    fn test_resolve_shell_explicit_fish() {
        let action = CompletionsAction::new(Some("fish".to_string()), test_cmd());
        assert_eq!(action.resolve_shell().unwrap(), Shell::Fish);
    }

    #[test]
    fn test_resolve_shell_case_insensitive() {
        let action = CompletionsAction::new(Some("BASH".to_string()), test_cmd());
        assert_eq!(action.resolve_shell().unwrap(), Shell::Bash);
    }

    #[test]
    fn test_resolve_shell_unsupported() {
        let action = CompletionsAction::new(Some("powershell".to_string()), test_cmd());
        let result = action.resolve_shell();
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("Unsupported shell"));
    }

    #[test]
    fn test_patch_zsh_replaces_regexp_default() {
        let input = r#"'::REGEXP -- Regular expression:_default'
'::OTHER_ARG:_default'"#;
        let result = patch_zsh(input);
        assert!(result.contains(":_passlane_cache_entries'"));
        // Non-REGEXP args should keep _default
        assert!(result.contains("OTHER_ARG:_default"));
    }

    #[test]
    fn test_patch_zsh_preserves_non_regexp_lines() {
        let input = "'--verbose[Verbosely display]'";
        let result = patch_zsh(input);
        assert_eq!(result, input);
    }

    #[test]
    fn test_patch_bash_replaces_compreply_in_show() {
        let input = r#"        passlane__show)
            opts="-v -p"
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            ;;
        passlane__add)
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            ;;"#;
        let result = patch_bash(input);
        // show section should have cache-based COMPREPLY
        assert!(result.contains("completion_cache"));
        // add section should still have original COMPREPLY
        // (not a target subcommand, so not patched)
        let add_section: String = result.lines()
            .skip_while(|l| !l.contains("passlane__add)"))
            .take_while(|l| !l.trim().starts_with(";;"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!add_section.contains("completion_cache"));
    }

    #[test]
    fn test_patch_fish_removes_f_flag() {
        let input = r#"complete -c passlane -n "__fish_seen_subcommand_from show" -F
complete -c passlane -n "__fish_seen_subcommand_from add" -F"#;
        let result = patch_fish(input);
        // show should have -F removed
        assert!(!result.lines().next().unwrap().contains(" -F"));
        // add should keep -F
        assert!(result.lines().nth(1).unwrap().contains("-F"));
    }

    #[test]
    fn test_dynamic_completion_script_zsh_has_function() {
        let script = dynamic_completion_script(Shell::Zsh);
        assert!(script.contains("_passlane_cache_entries"));
        assert!(script.contains("compadd -U"));
        assert!(script.contains("grep -i"));
    }

    #[test]
    fn test_dynamic_completion_script_fish_has_function() {
        let script = dynamic_completion_script(Shell::Fish);
        assert!(script.contains("__passlane_cache_entries"));
        assert!(script.contains("__fish_seen_subcommand_from show"));
        assert!(script.contains("grep -i"));
    }

    #[test]
    fn test_dynamic_completion_script_bash_is_empty() {
        // Bash uses inline patching, no appended script needed
        let script = dynamic_completion_script(Shell::Bash);
        assert!(script.is_empty());
    }

    #[test]
    fn test_completions_filename() {
        assert_eq!(completions_filename(Shell::Bash), "completions.bash");
        assert_eq!(completions_filename(Shell::Zsh), "completions.zsh");
        assert_eq!(completions_filename(Shell::Fish), "completions.fish");
    }

    #[test]
    fn test_source_command_bash() {
        let cmd = source_command(Shell::Bash, "/home/user/.passlane/completions.bash");
        assert_eq!(cmd, "source \"/home/user/.passlane/completions.bash\"");
    }

    #[test]
    fn test_rc_file() {
        assert_eq!(rc_file(Shell::Bash), "~/.bashrc");
        assert_eq!(rc_file(Shell::Zsh), "~/.zshrc");
        assert_eq!(rc_file(Shell::Fish), "~/.config/fish/config.fish");
    }
}
