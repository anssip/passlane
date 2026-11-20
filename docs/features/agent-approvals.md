# Agent approvals: the `agent` policy attribute

Every entry in a passlane vault carries an **agent access policy** as a
standard KeePass custom attribute:

```
agent = never | ask | allow      (default: never)
```

Because it is an ordinary custom attribute, it round-trips through other
KeePass clients (KeePassXC, KeePassium, StrongBox) and can be edited there.
In passlane, credentials can carry it via `edit` → *advanced fields* →
*custom attributes*; the other entry types get it from a KeePass client.
Missing or unrecognized values read as `never` — a typo never widens
access.

### Changing the policy

Setting or changing the attribute goes through the same gates as
revealing:

- For **credentials**, `passlane edit <pattern>` → *advanced fields* →
  *custom attributes* adds or updates `agent`. The edit prompts pre-fill
  the entry's current secret fields, so the edit itself runs the approval
  gate: restricted (`never`/`ask`) entries are refused outright in
  agent-facing contexts, and `ask` entries prompt the owner first. An
  agent cannot flip a restricted entry to `allow` for itself.
- For **cards, notes and TOTP entries** passlane's edit prompts do not
  offer custom attributes — set `agent` on those in another KeePass
  client. (Passlane's edits of those types leave the attribute untouched.)
- Any KeePass client can edit the attribute directly on the vault file —
  as with everything cooperative, a process with write access to the
  vault can always change it.
- `passlane csv` import accepts an `agent=…` value in the
  `custom_attributes` column (credentials).

Within the cooperative model an agent may still *edit* entries whose
policy is `allow` (the edit gate passes for them) — including changing
their other fields. Writes are out of scope for the reveal policy; keep
agent workflows on a dedicated vault if that matters.

The policy governs **agent-facing reveals**: passlane output that a program
(an AI agent, a script) consumes, as opposed to the owner's own interactive
use. It is the CLI half of the approvals feature (passlane#50,
[passlane-ios PLAN §3.3]); the phone/app side lands later.

## Semantics

| Policy | Owner, interactive terminal | Agent-facing reveal |
| --- | --- | --- |
| `allow` | reveal | reveal |
| `ask` | reveal after an approval prompt | **withheld**; an approval request is recorded |
| `never` (default) | reveal | **withheld** |

### What counts as agent-facing

- Anything that prints secret material to stdout: `show --out`,
  `show -o --once`, `list --json`, `list -v`, `list -o --code`, `list -p`,
  `list -n` (and TOTP secrets in `list -o`). These paths are the documented
  scripting surface — exactly what the agent skill uses — so they are
  agent-facing **even at an interactive terminal**.
- Any reveal attempted while stdin is not a terminal (e.g. `passlane show`
  driven by a pipe): there is no interactive owner present to approve it.
- Any reveal while stdout is not a terminal: the interactive display
  itself (verbose tables, the note line in credential tables) would carry
  secrets into a redirect or pager instead of the owner's screen, so it
  is treated like any other stdout reveal. `passlane show … | less` on a
  restricted entry is refused with the same guidance.
- `export`, which writes every secret to a plaintext file. At an
  interactive terminal the owner is asked once whether to include
  restricted entries (migration use case); non-interactively the restricted
  entries are skipped.

What is *not* agent-facing: the owner's own interactive use — `show`
tables, prompts, and the clipboard copy, the REPL, `show -o`'s code view.
The owner revealing their own entry is the approval. An `ask` entry still
prompts once in those flows (see below), which also covers the case of an
agent driving the owner's terminal: the human at the keyboard is the one
who answers. `edit` prompts pre-fill the entry's current secret fields
(TOTP secret, card number, note content), so edits are gated the same way
as reveals: `ask` entries prompt for approval first, and restricted
entries are refused without an interactive terminal.

Titles, usernames and other metadata are not secret material; listings that
never showed secrets (`list` without `-v`/`--json`, the completion cache)
continue to work for every entry. The completion cache
(`~/.passlane/.completion_cache.<vault>`) contains only `title:username`
pairs — never passwords, card numbers or TOTP secrets — and is created
owner-only.

### Behavior per command

- `show <pattern> --out`, `show -o --once`: exit code 1, an actionable
  message on stderr, no secret on stdout. `never` and `ask` both withhold;
  `ask` additionally records an approval request.
- `list`: the command still succeeds (exit 0) and stays parseable.
  Restricted entries are returned with the secret fields as `null`
  (`password`, `secret`, `content`, `number`/`cvv`/cardholder/billing
  address, `code`), with notes and custom attributes dropped except the
  `agent` policy itself, plus an `agent` field stating the policy that
  applied; a summary of what was withheld is printed to stderr. **Side
  effect:** every withheld `ask` entry records an approval request in the
  approval log — that is the audit signal of what an agent wanted, and it
  happens on each invocation, so a script polling `list` over `ask`
  entries grows the log (one line per entry per run). Metadata-only
  listings (`list` without `-v`/`--json`) log nothing unless they actually
  redacted a note or custom attribute. Plain-text verbose listings print
  `[withheld: agent=never]` markers instead of the secret.
- `show -v` / verbose tables: if any matched entry is restricted and the
  context is agent-facing, the cleartext table is refused with guidance
  rather than partially redacted.

## The `ask` flow (Phase 0)

Until the approval link transport ships (passlane#51), the approval flow
defers to the interactive prompt — with one deliberate limitation:

1. An agent requests an `ask` entry through an agent-facing path. The CLI
   does not reveal. It appends an **approval request** to the local
   approval log and tells the requester the entry needs approval. Bulk
   paths behave the same way: `list` redaction and `export` filtering
   record one request per withheld `ask` entry.
2. The owner then handles the request out of band: they run the reveal
   themselves — e.g. `passlane show '<entry>'` — and answer the approval
   prompt (`Approve once` / `Approve for this session` / `Deny`). That
   interaction is its own request/decision pair in the log. **The
   session handoff is the "for this session" choice**: it creates a
   timed `reveal` session in the [session agent](session-agent.md)
   (15 minutes by default, memory only), and from then on agent-facing
   reveals of that entry field pass without re-prompting until the
   session expires — every one of them audited as a `session` event in
   the approval log. Without a running agent the choice downgrades to
   `Approve once` with a warning. A plain `Approve once` still hands
   nothing to the agent: the agent's original request stays pending, and
   an agent-side retry simply records another request and is refused
   again. For permanent agent access, switch the entry to
   `agent = allow`.

When the link transport lands, step 2 becomes a real handoff: the same
request body travels to the approver (phone or the Phase 0 static page),
and the signed approval it returns is what releases the entry. The CLI
already records each request as the protocol's real `approval_request`
body (`crates/passlane-approval`), so nothing about what is being asked
changes.

### The approval log

`~/.passlane/approvals.log` — append-only JSONL, created owner-only
(0600). One line per event:

- `request` — an `ask` reveal was attempted (in either context); carries
  the vault, entry title, field, the requester, and the protocol approval
  request body.
- `decision` — how an owner resolved a request (`approved`/`denied`).
- `blocked` — an agent-facing reveal of a `never` entry was attempted and
  refused (logged for single-entry reveals, so the owner can see what an
  agent tried to take).
- `session` — an agent-facing reveal was served from a live session-agent
  session (an earlier *Approve for this session*); carries the session's
  expiry as `session_until`.
- `session_granted` — the owner chose *Approve for this session* and a
  covering session was created in the agent.

The log location can be overridden with `PASSLANE_APPROVAL_LOG` (used by
tests and scripted verification; hiding the log only suppresses audit
lines, it grants nothing).

## Cooperative enforcement — read this before relying on it

The policy is enforced **by the passlane CLI, on the passlane CLI's own
output paths**. It is a guardrail for cooperative agents — programs that
get secrets by running `passlane` — and an audit trail for the owner. It
is *not* a cryptographic boundary:

- Anything that can read the vault file and the keychain (or an open vault
  in another process) can bypass the CLI entirely.
- **An agent can fake the owner's terminal.** The non-stdout paths rely on
  "stdin is a terminal" to recognize the owner; an agent that allocates a
  pseudo-terminal (`script -q /dev/null passlane show …`) satisfies that
  check, reveals `never` entries, and can even answer an `ask` entry's
  approval prompt with a keystroke — including choosing *Approve for
  this session*, which would then mint a 15-minute session in the agent
  (`passlane sessions revoke`/`lock` kills it, and every use is audited,
  but it is granted). There is no reliable way to
  distinguish such a pty from a real terminal, so the CLI does not pretend
  to. The `ask` prompt is a speed bump against quiet exfiltration, not
  proof of human presence — that arrives with the approval link, where the
  approver must produce a passkey/Face ID the relaying agent cannot forge.
- An agent driving the owner's interactive terminal is trusted to be the
  owner; the `ask` prompt is the only speed bump there.
- The completion cache and non-verbose listings expose entry *names* by
  design.

### When you need real enforcement

Put the sensitive entries in a **separate vault gated by a phone-held
hardware key** (a YubiKey or the phone-as-key factor, see the passlane-ios
plan §3.1) **with no session caching**: then every open of that vault
requires a human approval with the second factor, regardless of what the
agent does. Passlane's multi-vault model already supports this — keep an
"agent vault" with only the entries a workflow needs (`agent = allow`),
and keep the crown jewels in the phone-gated vault that agents never see
unlocked.
