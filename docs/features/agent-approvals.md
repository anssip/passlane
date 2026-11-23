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
[passlane-ios PLAN §3.3]); the approver half is the link transport — the
[static approval page] and, later, the app.

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

## The `ask` flow

The approval link transport (passlane#51) carries `ask` requests to a
human approver over the cheapest possible channel: the CLI prints the
request as a terminal QR plus a copyable link, the approver opens it on
the [static approval page] (Phase 0; the iOS app later), decides with a
passkey, and pastes the signed reply back. One-time setup:

```
passlane approvals enroll     # pin the approval page (ECDH + passkey ceremony)
```

State lives under `~/.passlane` (override with `PASSLANE_APPROVALS_DIR`):
the CLI's protocol identity (`approval_identity.json`), pinned approvers
(`approval_peers.json`), the replay store (`.approval_nonces`) and
pending requests (`approval_pending.json`). See
`crates/passlane-approval/SPEC.md` for the protocol itself.

1. An agent requests an `ask` entry through an agent-facing path. The CLI
   does not reveal. Two earlier approvals can cover it, in this order:

   - a live **reveal session** (see step 2): repeated agent use until it
     expires — the agent consult also serves `list`/`export` bulk paths,
     which record requests without emitting links;
   - a **single-use grant** from the link transport (steps 3–5): exactly
     one reveal.

   Otherwise the CLI appends an **approval request** to the approval log
   and — when an approver is pinned — emits the request envelope over
   the link transport: the link goes to **stdout** (an agent can relay it
   in the chat the owner already uses), the QR to **stderr** (for the
   human at the terminal to scan). The envelope rides the URL fragment
   only, so the page's domain never sees it.
2. At the terminal the owner can also answer the request themselves:
   `passlane show '<entry>'` and the approval prompt offers `Approve
   once` / `Approve for this session` / `Deny`. *For this session*
   creates a timed `reveal` session in the [session
   agent](session-agent.md) (15 minutes by default, memory only), and
   from then on agent-facing reveals of that entry field pass without
   re-prompting until the session expires — every one of them audited as
   a `session` event in the approval log. The session is keyed by the
   entry's **stable UUID**, so another entry reusing the title never
   inherits the approval. Without a running agent the choice downgrades
   to `Approve once` with a warning.
3. The owner approves or denies on the approval page. The reply is
   end-to-end encrypted to the CLI's key and signed by the passkey
   (assertion over the exact envelope bytes).
4. `passlane approve --response '<blob>'` (or `--response @file`)
   verifies the reply — pinned keys, replay store, and the reply's
   request id must match a pending request — and releases it: an `Allow`
   becomes a **single-use grant** for exactly that entry and field.
5. The agent re-runs the original command and receives the secret. The
   grant is consumed by that one reveal; a replayed response blob is
   refused (`already approved` / replay), so the CLI proceeds exactly
   once. A single-use grant never funds the continuous TOTP code view —
   that asks for `show -o --once` (one code) or a session.

Without a pinned approver (or with the transport unavailable) the flow
falls back to the pre-link behavior: the request is recorded in the log
and the owner performs the reveal interactively themselves
(`passlane show '<entry>'`), or switches the entry to `agent = allow`.
Bulk paths (`list`, `export`) still record requests without emitting
links — one QR per entry would be approval fatigue; the emission rate
limiting hook (SPEC §4) belongs to the session agent (passlane#54).

`passlane approvals list` / `pending` / `remove <label>` manage the pins
and show what is awaiting an answer. Requests expire with their envelope
(a few minutes); expired requests are pruned automatically.

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
  proof of human presence. Real proof of a human arrives with the approval
  link: the approver must produce a passkey signature over the exact
  request bytes, which a relaying agent cannot forge — enroll an approver
  (`passlane approvals enroll`) and keep `ask` on the entries that matter.
- An agent driving the owner's interactive terminal is trusted to be the
  owner; the `ask` prompt is the only speed bump there.
- The completion cache and non-verbose listings expose entry *names* by
  design.

### When you need real enforcement

Put the sensitive entries in a **separate vault gated by a phone-held
key** (`passlane hwkey add --phone`, see [phone-held-key.md](phone-held-key.md))
**with no session caching**: then every open of that vault
requires a human approval with the second factor, regardless of what the
agent does. Passlane's multi-vault model already supports this — keep an
"agent vault" with only the entries a workflow needs (`agent = allow`),
and keep the crown jewels in the phone-gated vault that agents never see
unlocked.

[static approval page]: ../../page/README.md
