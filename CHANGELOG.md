# Changelog

## [Unreleased]

- Add **virtual challenge-response keys** to `passlane-core` (passlane#43): a vault's challenge-response factor is now a single abstraction, `ChallengeFactor` — a *virtual key* (the 20-byte HMAC-SHA1 secret as hex, answered locally with no device and no touch; available without the `usb` cargo feature, which is the mobile path) or a YubiKey (behind `usb`). The vault opens and saves with either, and only a hardware key gets the "Touch your hardware key" prompt. A virtual key uses the same KeePass format as a hardware key, so the same backed-up slot secret recovers such a vault: `hwkey remove --secret` now rejects an empty or non-hex secret on the spot, and notes one that is not the 40 hex characters of a hardware key's slot secret while still trying it, so a vault protected elsewhere with a secret of another length stays recoverable. CI builds the no-USB configuration for iOS (`aarch64-apple-ios`, `aarch64-apple-ios-sim`) and runs the `passlane-core` tests without it
- Fix the session agent being bypassed when a command opens a vault without a terminal (passlane#65): a live `unlock` session supplied the master password but the CLI still went to the hardware key — and, with nobody to touch it, waited forever. The unlock chain now asks the session agent **first** (the only source guaranteed prompt-free), then the keychain, then the password prompt, falling through when a source's factors no longer open the vault. An unlock session can hold a vault's **hardware-key factor** beside its master password whenever the key is one whose secret passlane knows (a recovery secret; `ChallengeResponseMaterial` on the agent's protocol, now dialect 2), so such a vault opens — and saves — through the session with the key never touched. Commands without a terminal never wait: a hardware-key vault whose key the session does not hold fails at once, the keychain gets a bounded wait (the macOS permission dialog never closes by itself), the password is never prompted for, so are `hwkey add` and `hwkey remove --secret`, and a request to an agent that accepts connections but never answers is bounded too. A stale completion cache is refreshed from the vault a command opens instead of through a keychain read before it; `hwkey remove` goes through the same chain, so a session holding the key factor lets the key be removed with no key present. A socket named by `PASSLANE_AGENT_SOCK` that nothing serves, an untrusted socket, or an agent left running from an older binary (protocol dialect mismatch) is an error saying what to do instead of a quiet fall-through to a prompt. `passlane sessions list` shows `unlock + hwkey` for a session that holds the key factor. **Restart `passlane-agent` after upgrading** — the new CLI refuses an agent still speaking dialect 1, which would otherwise silently drop the factors it does not know. A physical (USB) hardware key still needs a touch for every command: its secret never leaves the device. See `docs/features/session-agent.md`
- Add the **approval link transport** (passlane#51): when the `ask` flow needs an approval, the CLI seals the request with the approval protocol (HPKE, pinned keys) and prints it as a terminal QR plus a copyable link — the envelope rides the URL **fragment**, so the page's domain never sees it. The new static approval page (`page/`, SPEC §6) enrolls a WebCrypto ECDH key (non-extractable, IndexedDB) plus a WebAuthn passkey via `passlane approvals enroll`, whose binding assertion (`SHA-256(nonce ‖ ECDH public key ‖ both CLI keys)`, strict COSE parsing included) the CLI verifies — recomputing the challenge from its own identity — before pinning. `passlane approve --response <blob>` verifies the page's reply — pinned keys, file-backed replay store, request id must match a pending request — and releases the entry as a single-use grant the original command consumes on re-run; a replayed response is refused, so the CLI proceeds exactly once. `passlane approvals list|pending|remove` manage the pins and open requests. Link emission prints the link to stdout (agents can relay it) and the QR to stderr (humans scan it); without a pinned approver the flow falls back to the interactive prompt
- Add per-entry **agent approvals** (passlane#50): every entry can carry `agent = never | ask | allow` (default `never`) as a standard KeePass custom attribute, round-tripping through other KeePass clients. Reveals that programs consume — `show --out`, `show -o --once`, `list --json`/`-v`/`--code`/`-p`/`-n`, `export`, and any reveal without an interactive terminal — now honor it: `never` is withheld, `allow` passes, and `ask` withholds while recording an approval request in the new append-only `~/.passlane/approvals.log` (until the approval link ships, the owner approves interactively and the decision is logged). `list` returns restricted entries with secret fields as `null` plus an `agent` field instead of failing. The owner's own interactive use (tables, prompts, clipboard, REPL) is unaffected apart from a one-time approval prompt for `ask` entries. See `docs/features/agent-approvals.md` for the semantics and the cooperative-enforcement caveat
- Fix a misleading hardware-key failure: the vault file is now read *before* the "Touch your hardware key to open the vault" prompt is shown, so an unreadable vault no longer appears to be a YubiKey problem. Transient File Provider errors (`Resource deadlock avoided`/EAGAIN/EBUSY from synced folders such as Dropbox while the sync client is busy or updating) are retried briefly, and a vault that stays unreadable fails with a clear message naming the file and pointing at the synced folder instead of a raw OS error. The message also suggests opening the vault once in another app (Finder/KeePassXC), which forces the sync client to materialize the file and has been observed to restore reads on a wedged Dropbox File Provider
- A missed YubiKey touch (the key times out waiting and the response fails its CRC check) now reports "The hardware key did not return a valid response..." with the two likely causes instead of the cryptic `Wrong CRC`

## [4.0.0]

- **Breaking:** Add multi-vault support: manage any number of named vaults (`vault add`, `vault list`, `vault use`, `vault remove`, `vault rename`, `vault info`), switch with the global `--vault <NAME>` flag or `PASSLANE_VAULT` env var, and track the active vault. All entry types (credentials, payment cards, notes, TOTP) can now live in any vault. The pre-multi-vault config is migrated automatically on first run (main vault → `default`, TOTP vault → `totp`); `unlock -o`/`passwd -o` remain as legacy aliases for `--vault totp`
- Add hardware key (YubiKey) challenge-response as an additional unlock factor for the main vault
- Align the stored entry format with the KeePass entry model: credentials and payment cards are stored in custom fields instead of notes, improving compatibility with other KeePass clients
- Upgrade keepass-ng from 0.9 to 0.11. Existing vaults are upgraded in memory from KDBX 4.0 to KDBX 4.1 on open, so the first save after upgrading works (keepass-ng 0.11 only writes KDBX 4.1; the format is a superset of 4.0 that all current KeePass clients read). Verified round-trip with KeePassXC, including TOTP entries
- Fix: payment cards saved without a billing address no longer fail to load ("InvalidFormat" panic); card fields in the notes are now matched by name instead of line position, so notes reordered in another KeePass client still load, and an unparseable expiry skips the entry instead of panicking

## [3.2.0]

Security release: fixes all findings from a full-codebase security audit (see `docs/security-audit-2026-07-19.md`).

- Save the vault atomically (temp file + rename) so a crash mid-save can no longer corrupt the vault file
- Fail with a clear error when the vault file is missing (e.g. unmounted sync folder) instead of silently opening an empty vault
- Stop logging TOTP secrets in debug output
- **Breaking:** `list -o` no longer prints stored TOTP secrets unless `--verbose` is passed; use `list -o --code` for codes
- Create sensitive files (CSV exports, completion cache, REPL history, vault files) with owner-only permissions, and warn that exports are plaintext
- Fix password generator: restore missing `w`/`W` in alphabets, fix an off-by-one that excluded the last character of each character set, and guarantee every generated password contains all four character classes
- Fix: `add --clipboard` now actually rejects clipboard content that fails password validation
- Use the timed 20-second clipboard clear in `add` and payment-card `show`
- Fix `otpauth://` URL construction: correct the misspelled `algorithm` parameter (SHA256/SHA512 authorizers no longer silently fall back to SHA1) and percent-encode label, secret, and issuer
- Zeroize master passwords in memory during password changes; replace the unmaintained clipboard dependency with `arboard`; remove unused `magic-crypt`; run `cargo audit` in CI

## [3.1.0]

- Add scriptable, non-interactive TOTP code retrieval: `passlane list -o --code` prints the current codes (with `valid_for_seconds` in `--json`) and `passlane show -o --once` prints a single matching code to stdout for use in scripts
- Add a Claude agent skill (`.claude/skills/passlane`) that teaches an AI agent how to use passlane in automations, such as programmatically logging into websites and APIs

## [3.0.2]

- Accept Firefox-exported CSV in `passlane csv` import
- Make `show` output narrower. Add `--plain` option for plain non-table output.
- Fix: Accept lenient TOTP secrets when reading from Keepass files
- Fix: `show` now finds entries stored anywhere in the Keepass file, including at the root and in groups created by other Keepass clients. Search also matches against the entry title, not just the URL.
- Added `passwd` command to change the master password of the vault file.

## [3.0.1]

- Fix completions from the cached completions file (dynamic completion of credentialsgit)

## [3.0.0]

- Add interactive REPL mode
- Add `list` command for JSON output and scripting
- Add optional note field to credentials
- Add shell completion support for bash/zsh/fish, with dynamic completions for commands and saved service/username completions
- Show last 4 digits of card number in non-verbose payment cards table
- Clipboard auto-clear after 10 seconds and `--out` flag for show/gen commands
- Fix to ask master password only once when unlocking vault
- Fix zsh completion clearing input when no exact match
- Fix table layout

## [2.5.1]

- Fix to not clear the password prompt when editing a credential and skipping the password change

## [2.5.0]

- Added the init command to easily start using this tool
- Made the UI prompts more user friendly and look better

## [2.4.3]

- Added the edit command to edit entries in the vault
- Fixed a panic that occurred when generating passwords with running passlane without any options

## [2.4.2]

- Fix to validate all input from the command line to be stored (to remove all characters not allowed in Keepass XML)
- Show last modified date for each entry in the results tables
- Fix to store OTPs as protected values in the Keepass file

## [2.4.1]

(skipped)

## [2.4.0]

- Added support for TOTP (Time-based One-Time Password) codes
- Refactor the code base significantly

## [2.3.2]

- Switch to keepass-ng dependency

## [2.3.1]

- Fix to show a proper error message when entering incorrect master password
- Fix to initial creation of the Keepass file

## [2.3.0]

- Switch to Keepass storage format
- Remove online vault

## [2.2.2]

- Fix login

## [2.2.1]

- Fix to allow multiline notes
- Export of vault contents (credentials, secure notes, payment cards)

## [2.2.0]

- Added secure notes

## [2.1.1]

- Fixed to allow null values in the user account first name and last name. [#4](https://github.com/anssip/passlane/issues/4)

## [2.1.0]

- Added possibility to manage payment cards.

## [2.0.0]

- Introduced encryption keys.
- Added the possibility to keep the vault open (with `passlane unlock`) so that the master password is not prompted with every password query.
- Encryption keys are kept on client device, only the end user can decrypt and access sensitive password info.

## [1.0.1]

- Add ability to update the master password in the online vault. Changing the master password updates every credential with newly encrypted passwords.

## [1.0.0]

- Online vault at https://passlanevault.com
- Switch to use commands instead of options in the command line
- Generate & save at the same time using `passlane add -g`
- Delete should not ask master password
- `migrate` command to migrate from old format without iv

## [0.1.4]

- New feature: Show results in table when querying for passwords using `--gerp`
- New feature: Add possibility to delete passwords using `--delete`
- Fixed: "Failed: Unable to retrieve value from clipboard" --> prompt for the password to be saved

## [0.1.3]

- Add ability to save passwords entered by the user - not just saving of the previously genereted one from clipboard.
- Added `--verbose` option to show passwords when grepping with the `--g` option.
- Passwords prompt input no longer shows the entered passwords.

# [0.1.0]

- Initial release
