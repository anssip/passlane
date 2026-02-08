## 1. Entity Serialization

- [ ] 1.1 Update `Credential` in `src/vault/entities.rs`: remove `#[serde(skip_serializing, skip_deserializing)]` from the `uuid` field so it is included in JSON output
- [ ] 1.2 Add `#[derive(Serialize)]` to `PaymentCard` in `src/vault/entities.rs` with serde field annotations for JSON naming
- [ ] 1.3 Add `#[derive(Serialize)]` to `Expiry` in `src/vault/entities.rs`
- [ ] 1.4 Add `#[derive(Serialize)]` to `Address` in `src/vault/entities.rs`
- [ ] 1.5 Add `#[derive(Serialize)]` to `Note` in `src/vault/entities.rs`
- [ ] 1.6 Add `#[derive(Serialize)]` to `Totp` in `src/vault/entities.rs` (exclude `url`, `period`, `digits`, `algorithm` fields only if they shouldn't be in output — per spec all are included)

## 2. JSON Output Helpers

- [ ] 2.1 Create a `ListOutput<T>` envelope struct with `type_name`, `count`, and `entries` fields, deriving `Serialize`, in a suitable location (e.g., within `src/actions/list.rs` or a new `src/json_output.rs`)
- [ ] 2.2 Implement a function to serialize `ListOutput<T>` to pretty-printed JSON string via `serde_json::to_string_pretty`

## 3. List Action Implementation

- [ ] 3.1 Create `src/actions/list.rs` with `ListAction` struct containing fields: `item_type: ItemType`, `search_pattern: Option<String>`, `json_output: bool`, `verbose: bool`, `is_totp: bool`
- [ ] 3.2 Implement `ListAction::new(matches: &ArgMatches) -> ListAction` constructor parsing CLI args
- [ ] 3.3 Implement `UnlockingAction` for `ListAction` with `is_totp_vault()` returning `self.is_totp`
- [ ] 3.4 Implement `run_with_vault` for credentials: call `vault.grep()` with optional regex, format as JSON or plain text
- [ ] 3.5 Implement `run_with_vault` for payment cards: call `vault.find_payments()`, format as JSON or plain text
- [ ] 3.6 Implement `run_with_vault` for notes: call `vault.find_notes()`, format as JSON or plain text
- [ ] 3.7 Implement `run_with_vault` for TOTP: call `vault.find_totp()` with optional regex, format as JSON or plain text
- [ ] 3.8 Implement plain text formatting: summary header line, per-entry labeled fields, verbose vs non-verbose for credentials

## 4. CLI Integration

- [ ] 4.1 Add `pub mod list;` to `src/actions/mod.rs`
- [ ] 4.2 Add `list` subcommand definition to `cli()` in `src/main.rs` with flags: `--json`, `-p`, `-n`, `-o`, `-c`, `-v`, and optional `<REGEXP>` positional argument
- [ ] 4.3 Add `list` match arm in `main()` that creates `ListAction` and wraps it as `VaultAction::UnlockingAction`

## 5. Testing

- [ ] 5.1 Add unit tests for JSON serialization of each entity type (`Credential`, `PaymentCard`, `Note`, `Totp`) verifying expected field names and values
- [ ] 5.2 Add unit tests for `ListOutput` envelope serialization verifying `type`, `count`, and `entries` structure
- [ ] 5.3 Add unit tests for plain text output formatting (verbose and non-verbose credentials, payment cards, notes, TOTP)
- [ ] 5.4 Verify `cargo test` passes with all new and existing tests

## 6. Documentation

- [ ] 6.1 Add `list` command usage section to README.md with examples for JSON and plain text output
- [ ] 6.2 Add security warning about passwords being printed to stdout in the README `list` section
- [ ] 6.3 Add scripting examples (pipe to `jq`, duplicate password detection, export) to README.md
