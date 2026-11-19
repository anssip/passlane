# Agent approvals: the `agent` policy attribute

Every entry in a passlane vault carries an **agent access policy** as a
standard KeePass custom attribute:

```
agent = never | ask | allow      (default: never)
```

Because it is an ordinary custom attribute, it round-trips through other
KeePass clients (KeePassXC, KeePassium, StrongBox) and can be edited there.
In passlane, `edit` → *advanced fields* → *custom attributes* offers the
same thing. Missing or unrecognized values read as `never` — a typo never
widens access.

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
- `export`, which writes every secret to a plaintext file. At an
  interactive terminal the owner is asked once whether to include
  restricted entries (migration use case); non-interactively the restricted
  entries are skipped.

What is *not* agent-facing: the owner's own interactive use — `show`
tables, prompts, and the clipboard copy, the REPL, `show -o`'s code view.
The owner revealing their own entry is the approval. An `ask` entry still
prompts once in those flows (see below), which also covers the case of an
agent driving the owner's terminal: the human at the keyboard is the one
who answers.

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
  (`password`, `secret`, `content`, `number`/`cvv`, `code`) plus an `agent`
  field stating the policy that applied; a summary of what was withheld is
  printed to stderr. Plain-text verbose listings print
  `[withheld: agent=never]` markers instead of the secret.
- `show -v` / verbose tables: if any matched entry is restricted and the
  context is agent-facing, the cleartext table is refused with guidance
  rather than partially redacted.

## The `ask` flow (Phase 0)

Until the approval link transport ships (passlane#51), the approval flow
defers to the interactive prompt:

1. An agent requests an `ask` entry through an agent-facing path. The CLI
   does not reveal. It appends an **approval request** to the local
   approval log and tells the requester the entry needs approval.
2. The owner resolves it by revealing the entry interactively — e.g.
   `passlane show '<entry>'` — and answering the approval prompt
   (`Approve once` / `Deny`). The decision is appended to the log,
   correlated with the request by its id.

When the link transport lands, the same request becomes an encrypted
envelope carried to the phone (or the Phase 0 static page) and the approval
arrives signed; the CLI-side log already records each request as the
protocol's real `approval_request` body (`crates/passlane-approval`), so
the flow extends without changing what is being asked.

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
