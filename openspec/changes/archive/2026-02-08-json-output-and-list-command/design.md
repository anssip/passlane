## Context

Passlane's current `show` command is interactive-only: it copies to clipboard, prompts for selection, and renders human-readable tables. There is no way to programmatically retrieve vault contents. The vault trait layer (`PasswordVault`, `PaymentVault`, `NoteVault`, `TotpVault`) already provides clean read access to all entry types via `grep()`, `find_payments()`, `find_notes()`, and `find_totp()`. The entity types (`Credential`, `PaymentCard`, `Note`, `Totp`) exist but only `Credential` has serde derives — and even those skip the UUID field. `serde_json` is already in `Cargo.toml`.

## Goals / Non-Goals

**Goals:**

- Add a `list` command that outputs vault entries to stdout without clipboard or interactive prompts
- Support JSON output (`--json` flag) and plain text output (default)
- Support all four entry types via existing flag convention (`-p`, `-n`, `-o`, default credentials)
- Support optional regex filtering (positional `<REGEXP>` argument)
- Produce structured JSON with an envelope (`type`, `count`, `entries`)
- Keep the implementation consistent with the existing action pattern (`UnlockingAction`)

**Non-Goals:**

- Modifying the existing `show` command behavior
- Adding `--json` to other commands (future work)
- Adding `--exclude-passwords` or `--format` options (future phases)
- Streaming output for large vaults

## Decisions

### 1. Separate `list` command vs `--json` on `show`

**Decision:** New `list` command.

**Rationale:** The `show` command has deeply embedded interactive behavior — clipboard copying, index prompts, TOTP countdown loops. Adding a non-interactive mode to `show` would require threading a `non_interactive` flag through every `MatchHandlerTemplate` implementation. A separate command is cleaner, avoids regressions, and makes intent explicit at the CLI level.

**Alternative considered:** Adding `--json` and `--no-interactive` flags to `show`. Rejected because it conflates two fundamentally different UX modes and risks breaking `show`'s well-tested interactive flow.

### 2. Action pattern: `UnlockingAction` without `MatchHandlerTemplate`

**Decision:** Implement `ListAction` as an `UnlockingAction` but **do not** use the `MatchHandlerTemplate` pattern.

**Rationale:** `MatchHandlerTemplate` is designed for interactive flows — it distinguishes single vs. multiple matches to decide clipboard vs. prompt behavior. `list` always dumps all matches to stdout regardless of count. Using the template would require no-op implementations for interactive methods that add complexity for no benefit. Instead, `ListAction::run_with_vault` will directly call vault query methods and format results.

**Alternative considered:** Creating a `NonInteractiveMatchHandler` implementation. Rejected as over-abstraction for a simple dump-all-results flow.

### 3. JSON envelope structure

**Decision:** Use a typed envelope: `{ "type": "<entry_type>", "count": N, "entries": [...] }`

The `type` field values are: `"credentials"`, `"payment_cards"`, `"notes"`, `"totp"`.

**Rationale:** A consistent envelope makes it easy for consumers to verify they're parsing the right data type and know entry count before iterating. This is a common pattern in JSON APIs.

### 4. Serde serialization approach

**Decision:** Add `Serialize` derives to all entity types (`PaymentCard`, `Note`, `Totp`, `Address`, `Expiry`) and fix `Credential`'s UUID skipping. Use `#[serde(rename = "...")]` annotations to produce the JSON field names from the feature spec.

**Key changes to entities:**
- `Credential`: Remove `skip_serializing` from `uuid`, add `#[serde(rename = "uuid")]` where needed
- `PaymentCard`: Add `Serialize` derive, annotate fields for JSON naming (e.g., `name_on_card`)
- `Note`: Add `Serialize` derive
- `Totp`: Add `Serialize` derive, include `issuer`, `account` (mapped from `label`), `secret`
- `Address`: Add `Serialize` derive
- `Expiry`: Add `Serialize` derive

**Rationale:** Deriving `Serialize` on the domain types is the simplest approach. The entities already use public getter methods, so serialization won't break encapsulation. Custom `#[serde(rename)]` attributes handle the gap between Rust field naming and the JSON spec.

**Alternative considered:** Creating separate DTO structs for JSON output. Rejected because the entities map closely enough to the JSON schema that separate types would be pure boilerplate. If the JSON schema diverges from internal representation in the future, DTOs can be introduced then.

### 5. Plain text output format

**Decision:** Print a summary header (`Found N <type>:`) followed by labeled fields for each entry, separated by blank lines. Passwords and secrets are always shown in output (both formats).

Without `-v/--verbose`, credentials show service and username only. With `-v`, all fields including password and last_modified are shown. Payment cards, notes, and TOTP entries show all fields regardless of verbose flag.

**Rationale:** Plain text should be parseable by simple tools (`grep`, `awk`) while remaining human-scannable. The verbose flag mirrors `show`'s existing `-v` flag semantics.

### 6. TOTP handling — secret only, no live code

**Decision:** For TOTP entries, output the stored secret and metadata fields. **Do not** generate and include the current TOTP code in `list` output.

**Rationale:** TOTP codes expire every 30 seconds, making them unreliable in piped/scripted output. Users who need a current code can derive it from the secret using standard TOTP libraries. Including a live code would also require calling `get_code()` which can fail, complicating the otherwise simple list operation. This differs from the feature doc's suggestion to include `current_code` — practical scripting is better served by stable output.

### 7. Exit codes and error output

**Decision:** Use exit code 0 for success (including empty results), exit code 1 for errors (vault unlock failure, invalid regex). Errors go to stderr, entry data goes to stdout.

**Rationale:** Standard Unix convention. Empty results are not errors — they produce `{ "type": "...", "count": 0, "entries": [] }` in JSON mode or `Found 0 <type>.` in plain text.

## Risks / Trade-offs

**[Passwords in stdout]** → The `list` command intentionally prints passwords to stdout. This is the core trade-off vs `show`. Mitigated by: clear `--help` text warning, documentation, and the fact that users explicitly choose `list` over `show`.

**[Serde derives on entities]** → Adding `Serialize` to domain types couples serialization format to internal representation. → Acceptable risk: field names are stable, and `#[serde(rename)]` / `#[serde(skip)]` provide escape hatches if divergence occurs.

**[No TOTP live code]** → Differs from feature doc spec. → Users can compute codes from the secret. A future `--with-code` flag could add this if needed.
