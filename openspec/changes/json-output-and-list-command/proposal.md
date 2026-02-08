## Why

Passlane is currently optimized for interactive terminal use — the `show` command copies passwords to clipboard, prompts for selection on multiple matches, and formats output as human-readable tables. This makes automation, scripting, and integration with other tools impossible. Users need machine-readable output to build workflows like password strength analysis, duplicate detection, export to other managers, and automated testing.

## What Changes

- Add a new `list` command that outputs vault entries to stdout without clipboard interaction or interactive prompts
- Support plain text and JSON output formats via a `--json` flag
- Support all entry types using existing flags: `-c` (credentials, default), `-p` (payments), `-n` (notes), `-o` (OTP)
- Support regex-based filtering via an optional positional argument (same as `show`)
- Add `-v/--verbose` flag for detailed plain text output
- Define structured JSON schemas for each entry type (credentials, payment cards, notes, TOTP) with envelope containing `type`, `count`, and `entries`
- Add serde serialization to vault entity types
- Passwords and secrets are included in output (both plain text and JSON) — this is intentional for scripting use cases

## Capabilities

### New Capabilities

- `list-command`: The `list` CLI command — argument parsing, entry type routing, regex filtering, and output formatting (plain text and JSON) for all vault entry types

### Modified Capabilities

_(none — no existing specs are affected)_

## Impact

- **Code — new action**: `src/actions/list.rs` implementing `UnlockingAction` for the new command
- **Code — CLI**: `src/main.rs` gets a new `list` subcommand definition with `--json`, `-p`, `-n`, `-o`, `-c`, `-v` flags and optional `<REGEXP>` argument
- **Code — entities**: `src/vault/entities.rs` needs `Serialize` derives and serde annotations for JSON output
- **Code — output helpers**: New JSON serialization helpers (envelope struct, `serde_json` formatting)
- **Dependencies**: `serde_json` added to `Cargo.toml` (serde with derive is already present)
- **Documentation**: README updated with `list` command usage, scripting examples, and security warnings about stdout password exposure
