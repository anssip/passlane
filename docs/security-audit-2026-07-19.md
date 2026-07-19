# Security Audit — passlane

**Date:** 2026-07-19
**Performed with:** Claude Fable 5
**Scope:** full codebase (~7,100 lines of Rust) — crypto, secret handling,
vault I/O, file permissions, logging, and dependencies.
**Status:** ✅ All findings below have been fixed (PRs #17, #18, #27–#34,
released after v3.1.0). The text is preserved as originally written.

**Overall:** the fundamentals are sound — encryption is delegated to KeePass
(KDBX4), password generation uses a CSPRNG (`thread_rng`), master passwords go
to the OS keychain rather than a file, and `show` clears the clipboard after
20 seconds. The issues below are listed worst first.

---

## High impact

### 1. Vault saves are non-atomic and don't truncate — risk of permanent vault corruption

**Where:** `src/vault/keepass_vault.rs:196` (`save_database`) and `:211` (`change_master_password`)

Both open the existing `.kdbx` with `write(true)` but **no `truncate(true)`**,
and write in place:

- If the newly serialized database is smaller than the old file (entirely
  possible after deleting entries), stale trailing bytes remain in the file.
- A crash or Ctrl+C mid-write leaves a half-written vault with no backup —
  everything is lost.

**Fix:** write to a temp file in the same directory, fsync, then `rename()`
over the original (atomic on POSIX). Consider keeping a `.bak` of the previous
version.

### 2. TOTP secrets leak into debug logs

**Where:** `src/vault/keepass_vault.rs:85` and `src/actions/show.rs:186`

- `debug!("Checking node for TOTP: {:?} raw={:?}", ..., raw)` logs the full
  otpauth URL **including the secret**.
- `debug!("found totp: {}", the_match)` uses `Totp`'s `Display` impl, which
  explicitly formats `secret: {}` (`src/vault/entities.rs:277-284`).

Anyone running with `RUST_LOG=debug` (e.g. to report a bug, with output
captured to a file or pasted into a GitHub issue) exfiltrates their 2FA seeds.

**Fix:** remove secrets from `Display` and from all log lines.

### 3. A missing vault file silently "opens" as a new empty database

**Where:** `src/vault/keepass_vault.rs:228-234` (`open_database`)

If the path in `~/.passlane/.vault_path` doesn't resolve (typo, unmounted
Dropbox folder, moved file), `open_database` returns a fresh empty `Database`
instead of an error. Consequences:

- Any password appears to unlock the vault.
- `passlane unlock` then stores that unverified password in the keychain.
- The user sees an empty vault and may conclude their data is gone.
- The next save writes a brand-new vault at the wrong path.

**Fix:** opening should hard-fail when the file doesn't exist; creation belongs
only in `init`.

---

## Medium

### 4. Sensitive files created with default (typically world-readable) permissions

Nothing in the codebase sets file modes. Affected:

| File | Where | Contents |
|---|---|---|
| CSV exports | `src/store.rs:158-206` | Plaintext passwords, card numbers + CVVs, notes |
| `~/.passlane/.completion_cache` | `src/completion_cache.rs:139` | Every `service:username` pair in the vault (cleared on `lock`, but readable metadata on shared machines) |
| `~/.passlane/.repl_history` | `src/repl/mod.rs` | Search terms (which services you have accounts with) |
| New `.kdbx` files | `src/vault/keepass_vault.rs:178` | Encrypted, but 0600 is still the right default |

**Fix:** set `0o600` on all of these (`OpenOptions::mode` /
`std::fs::set_permissions`), and print a warning on export reminding the user
the file is plaintext.

### 5. `list -o` prints all TOTP secrets unconditionally

**Where:** `src/actions/list.rs:209`

Credentials gate the password behind `--verbose`, but the plain TOTP listing
dumps every seed with no flag at all. Inconsistent and easy to trigger by
accident (terminal scrollback, tmux logging).

**Fix:** gate secrets behind `--verbose` at minimum.

### 6. Password generator has an off-by-one and defective alphabets

**Where:** `src/crypto.rs`

- `append` calls `random_index(charset.len() - 1)`, and `random_index` uses
  `gen_range(0..range)` — the **last character of every charset can never be
  generated** (`z`, `Z`, `9`, and the final special char).
- `LOW_CASE`/`UP_CASE` are `"...tuvxyz"` — **the letter `w`/`W` is missing
  entirely**.
- Generated passwords aren't guaranteed to contain all four character classes
  (each of the 15 positions picks a random class), so `generate()` output can
  fail the tool's own `validate_password`.

Entropy is still roughly ~85 bits so this isn't exploitable, but for a password
manager the generator should be exactly what it claims.

**Fix:** correct the alphabets, use `gen_range(0..charset.len())`, and consider
guaranteeing one character per class.

---

## Low

### 7. Clipboard validation in `add --clipboard` is a no-op

**Where:** `src/actions/add.rs:30-32`

`Error::new(...)` is constructed and **discarded** — there is no
`return Err(...)`, so any clipboard content is accepted as the password.

### 8. Untimed clipboard copies

**Where:** `src/actions/add.rs:58`, `src/actions/show.rs:93,121`

`add` leaves the newly saved password in the clipboard forever, as does the
payment-card number path — while `show`/`generate` correctly use the 20-second
timed clear.

**Fix:** use `copy_to_clipboard_timed` consistently.

### 9. otpauth URL construction is broken for non-default algorithms

**Where:** `src/ui/input.rs:433` (`format_totp_url`)

- The parameter is spelled **`alorithm=`**, so a user who selects
  SHA256/SHA512 stores a URL whose algorithm parsers ignore — codes silently
  generate as SHA1 (wrong codes, locked out of accounts).
- label/secret/issuer are interpolated without percent-encoding (the
  `percent-encoding` crate is already a dependency), so an issuer containing
  `&` or spaces corrupts the URL.

---

## Informational

- **`magic-crypt` is a dead dependency** — declared in `Cargo.toml` and
  `extern crate`'d in `main.rs`, never used. Remove it (it's also a weak crypto
  crate you don't want in the dependency tree).
- The `clipboard` crate (0.5.0) is unmaintained; `arboard` is the maintained
  successor.
- Secrets (master password, entry passwords, TOTP seeds) live in ordinary
  `String`s, cloned freely, never zeroized. Consider the `zeroize`/`secrecy`
  crates for the master password at least.
- `KeepassVault::new` uses `DatabaseConfig::default()` — verify keepass-ng's
  default KDF is Argon2 (KDBX4), not legacy AES-KDF.
- Install `cargo-audit` (`cargo install cargo-audit`) and add it to CI to catch
  known advisories in the lockfile.

---

**Recommended priority:** fix items 1–3 before the next release — #1 can
destroy the vault, #2 leaks 2FA seeds, and #3 both masks configuration errors
and poisons the keychain with unverified passwords.
