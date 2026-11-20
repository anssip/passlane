---
name: passlane-cli-verify
description: Exercise the real passlane CLI against a scratch vault on this Mac — build the binary, register a uniquely-named test vault in the real config (never active, keychain-seeded), drive interactive prompts through a pty with script, and clean everything up afterwards. Use whenever a passlane change needs CLI-level verification (AGENTS.md requires it for every PR), when testing show/list/export/reveal behavior including the agent policy, or when a scripted passlane invocation hangs on an interactive prompt.
---

# Verifying the passlane CLI with a scratch vault

AGENTS.md requires exercising the real CLI (all affected options and commands), not just
`cargo test`. This is the working recipe on this Mac. Everything here is fire-and-forget
scriptable except where noted.

## Principles

- **Never touch the user's real vaults or active vault.** Register a uniquely named test
  vault (e.g. `cli-verify-<issue>`) whose *file* lives in the session temp dir, always
  address it with `--vault <name>`, and answer **No** to "make it the active vault".
- **Use the real `~/.passlane` config, not a scratch `$HOME`.** On macOS the keychain
  domain is resolved per-`HOME`; with `HOME=<scratch>` passlane fails with "A default
  keychain could not be found" and `security` commands hang. A scratch vault registered
  in the real config works and is fully removable.
- **`PASSLANE_APPROVAL_LOG=<tmp>/approvals.log`** on every verification run that can
  trigger the agent policy, or test events land in the user's real
  `~/.passlane/approvals.log`. Each shell block starts with a fresh environment — set the
  env var in the *same* command, not an earlier one.

## Setup

```bash
cargo build
T=$PWD/../agent-verify   # or a session temp dir; anywhere outside the repo
mkdir -p $T
P=$PWD/target/debug/passlane
NAME=clitest-<unique>
```

Create the vault (interactive, driven through a pty — see the pty section):

```bash
(printf '\n%s\n\n\n<pw>\n<pw>\n' "$T/$NAME.kdbx"; sleep 25; printf 'n'; sleep 3; printf '\n'; sleep 5) \
  | script -q /dev/null $P vault add $NAME
```

Answer order: New (Enter) → vault location (type the temp path) → keyfile (Enter) →
hardware key (Enter = No) → new master password ×2 → **Argon2 gap, in a debug build this
is 10–25 s — wait it out** → make active (**`n`**) → store master password in keychain
(Enter = Yes). Bytes that arrive while a prompt is not yet up are flushed, so get the
timing right or check afterwards; if the run dies before the keychain step, the item is
missing — fix it with `unlock` below, not with `security`.

### Keychain: never seed it with `security` — stay popup-free

A `security add-generic-password`-seeded item triggers a "passlane wants to access a key"
dialog on the first read, and **clicking Always Allow only lasts until the next rebuild**
(the debug binary is ad-hoc signed; every build gets a new signature). `-T "$P"` on the
item does not help, and keyring never sees items in custom keychains, so the
dedicated-keychain CI trick is out too.

The popup-free way is to let **passlane itself create the item** — the creating binary is
trusted for later reads, no dialogs at all (verified: reads return instantly; a dialog
blocks the process, so a hang *is* the symptom):

```bash
(printf '<pw>\n'; sleep 8) | script -q /dev/null $P --vault $NAME unlock
```

Rules:

- Build once per session (`cargo build`) and reuse that binary; a rebuild changes the
  signature, after which the old item prompts again. After a rebuild:
  `security delete-generic-password -s passlane_master_pwd -a $NAME`, then re-run the
  `unlock` line to re-create it popup-free.
- For the same reason the vault-add flow must complete the final "Store master password
  in keychain? (Y/n)" step with Yes (Enter).

### Seeding entries

- **Credentials (incl. custom attributes — the `agent` policy travels in the
  `custom_attributes` CSV column):**

  ```bash
  cat > $T/fixture.csv <<'EOF'
  username,password,title,custom_attributes
  alice,allow-pw,github.com,agent=allow
  bob,ask-pw,stripe-test,agent=ask
  carol,never-pw,root-server,
  EOF
  $P --vault $NAME csv $T/fixture.csv
  ```

  Do **not** add `expires`/`expiry_time` columns with empty values — an empty string fails
  bool/DateTime parsing; omit the columns entirely.

- **TOTP / payment cards:** interactive `add -o` / `add -p` through the pty (see below).
- **Notes via `add -n` don't work under the pty** — the multiline editor only ends on
  EOF, which `script` never forwards. Verify note behavior with unit tests, or add the
  note another way.

## Driving interactive prompts: the pty recipe

inquire/rustyline need a terminal; feeding a plain pipe hangs or panics. Wrap in
`script`:

```bash
(printf '<answers>'; sleep N; printf '\x03'; ...) \
  | script -q /dev/null env PASSLANE_APPROVAL_LOG=$T/approvals.log $P --vault $NAME <cmd>
```

- **Select** (arrow menus): Enter picks the highlighted first option; send `\x1b[B\n`
  (down + Enter) for the second.
- **Confirm (Y/n)**: Enter = default; typing `y`/`n` answers immediately — *do not* add
  a newline after it, the next prompt would eat it.
- **Text/Password**: value + `\n`.
- **`show` copies to the clipboard and blocks 20 s**: send `\x03` (Ctrl+C) once the
  output appears to skip the wait.
- **Keep the pipe open with sleeps** between answers — if printf's output ends and the
  pipe closes while passlane is still working (Argon2 unlock takes seconds), prompts see
  EOF and cancel/panic. Budget ~2 s per prompt plus ~4 s for the first unlock.
- **`script` never forwards EOF to the pty** — anything that ends on EOF (multiline note
  editor) hangs forever. Kill the stuck process and redesign the input.
- A stuck session: kill it **by the test vault's unique name**, never with a bare
  `pkill -f passlane` — that pattern also matches the *user's own* passlane processes and
  would terminate an unrelated vault operation mid-save or mid hardware-key challenge:
  ```bash
  pkill -f "passlane.*--vault $NAME"; pkill -f "passlane.*vault add $NAME"
  ```
- Remember: under `script`, passlane's stdin and stdout **are** TTYs, so non-stdout
  reveals run in the *owner* context (an `agent=ask` entry prompts "Approve revealing…?").
  To exercise the *agent* context (no prompts, refusals), run the binary with `</dev/null`
  stdin or a stdout-revealing flag (`--out`, `--once`, `list --json`), or redirect stdout.

## Gotchas

- **Never run the freshly built binary against the user's real vaults.** Any
  rebuild changes the ad-hoc signature, so the first keychain access to *real*
  items (`vault list` and `status` read the lock state of every configured
  vault!) triggers a permission popup per item — which also **blocks the run
  until a human answers**, so an unattended verification session wedges there.
  Scope every invocation to the test vault (`--vault $NAME`); check
  registration with
  `python3 -c "import json; print([v['name'] for v in json.load(open('$HOME/.passlane/vaults.json'))['vaults']])"`
  instead of `vault list`, and never use `vault list`/`status`/`vault info`
  with the debug binary outside the test vault.
- Unit tests (`cargo test`) are hermetic — no test reads the keychain. If a
  popup appears "during tests", it came from a stray binary invocation around
  them (often a sanity-check `vault list` after a rebuild).
- `Unlocking vault...` is printed to **stdout** (pre-existing). Filter it
  (`| grep -v '^Unlocking'`) before piping `list --json` into `jq`/`python`.
- Exit codes: capture them on an unpiped run (`$P ... ; echo $?`) — in a pipeline you get
  the last command's status (zsh: `$pipestatus[1]`, bash: `${PIPESTATUS[0]}`).
- The REPL works under `script`: `(printf 'show <pat>\n'; sleep 5; printf '\n'; ...;
  printf 'quit\n'; sleep 2) | script -q /dev/null $P --vault $NAME repl`.
- Verify file side effects directly: `ls -l ~/.passlane/.completion_cache.$NAME`
  (owner-only, `title:username` lines only), `~/.passlane/approvals.log` or your
  `PASSLANE_APPROVAL_LOG` (JSONL, 0600).

## Cleanup — always

```bash
security delete-generic-password -s passlane_master_pwd -a $NAME  # deterministic, never prompts
rm -f ~/.passlane/.completion_cache.$NAME
rm -rf $T
```

Prefer the direct `security` delete for the keychain item: `passlane --vault $NAME lock`
removes it too, but if the binary was rebuilt since the item was created, the delete
triggers a keychain permission prompt that **blocks the run until a human answers** —
fine interactively, a wedge in unattended cleanup. (`security` never prompts for its own
partition.) Run `lock` only when you know the binary is the one that created the item.

`vault remove <name>` asks a `(y/N)` confirm — under the pty, send `y` with a generous
delay (`sleep 3; printf 'y'`; a typed `y` answers immediately, no newline). If the pty
answer doesn't land, remove the registry entry directly instead of fighting the prompt
(safe equivalent for a non-active vault — `vault remove` only rewrites the registry,
clears the cache, and moves the active pointer when the removed vault was active):

```bash
python3 - <<EOF
import json
p = '$HOME/.passlane/vaults.json'
d = json.load(open(p))
d['vaults'] = [v for v in d['vaults'] if v['name'] != '$NAME']
json.dump(d, open(p, 'w'), indent=2)
EOF
```

Then confirm the user's world is intact **without running the debug binary**: read
`~/.passlane/.active_vault` (unchanged), and re-run the registry python check above (no
`$NAME` entry) — do **not** use `$P vault list` here, it reads the keychain lock state of
every real vault through the freshly built binary and blocks on permission dialogs (see
Gotchas). Also confirm no `approvals.log` test entries were left in `~/.passlane` (delete
the file if it only contains test events — check the `vault` field on each line first).
