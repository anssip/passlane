# The session agent (`passlane-agent`)

The session agent is passlane's `ssh-agent`: a small, long-running
daemon that holds vault unlock factors and timed approvals **in memory
only**, until they expire, are revoked, the agent is locked, or it stops.
It exists so that one approval can serve many CLI uses without anything
secret ever being written to disk (passlane#54, [passlane-ios PLAN §3.1]).

```
$ passlane-agent &
passlane-agent 0.1.0 listening on /run/user/501/passlane-agent.sock (session cap 900s)

$ passlane --vault work unlock --session 3600
Unlocking vault...
Vault 'work' unlocked — the session agent holds the unlock factors until
2026-11-20T11:20:00+00:00 (memory only, nothing stored in the keychain)

$ passlane --vault work show github.com     # no password prompt: the agent serves the unlock
$ passlane sessions list
```

## Why a separate binary (not `passlane agent`)

The daemon is its own binary, `passlane-agent`, for the same reasons
`ssh` and `ssh-agent` are separate:

- **Lifetime.** The agent outlives every CLI invocation; it is started
  by the session manager (launchd, systemd) or the shell, and stops on
  logout. A subcommand would blur "the CLI process" with "the daemon
  process" and make autostart units awkward (`passlane agent` re-parses
  the full CLI grammar, inherits `--vault` resolution, etc.).
- **Attack surface.** The daemon holds key material for up to hours, so
  it should run the smallest code possible: a socket loop and a session
  map. It does not link the CLI's CSV import, REPL, clipboard, USB
  stacks or completion machinery; the CLI conversely only links the
  agent's *client* code.
- **Crash isolation.** A panicking CLI command cannot dump the agent's
  memory; a restarted agent starts clean (sessions die with it, by
  design).

The CLI still controls everything over the socket: `passlane sessions
list|revoke|lock`, `passlane unlock --session`, and every unlock
consults the agent transparently.

## The session model

A **session** is one granted approval:

| Kind | Holds | Created by | Ends |
| --- | --- | --- | --- |
| `unlock` | what opens the vault with no prompt: the master password, plus the hardware-key factor when it is one a session can hold (see below) | `passlane unlock --session` (later: a phone approval of `Operation::Unlock`) | expiry, revoke, `lock`, agent stop |
| `challenge_response` | a phone-held key's 20-byte answer for one vault file version, keyed by the challenge it answers | `passlane approve --response`, `unlock --session` | first use (single-use ones), expiry, revoke, `lock`, agent stop |
| `reveal` | no secret — a recorded "approve for this session" covering one entry field | the ask flow's *Approve for this session* | first use (`once`), expiry, revoke, `lock`, agent stop |

Reveal sessions are keyed by the entry's **stable UUID** (the title travels
along for display and audit only), so a different entry that reuses a
title — or a new one created with it — never inherits an approval.

Scopes come from the approval protocol (`passlane-approval`): `once`
dies on first use, `timed { seconds }` is reusable until it expires.
A `timed` unlock session is what lets **one approval serve many CLI
uses** — every command that opens the vault asks the agent first, so no
password prompt and no keychain write happens until the session ends.

**Duration cap.** No session may outlive the agent's cap
(`--max-session-secs`, default 900 = the approval protocol's default).
The cap is a hard ceiling of **8 hours** even when configured higher:
long-lived unlock factors widen the window on a compromised host. The
agent refuses over-cap requests with a `too_long` error rather than
silently clamping them.

**Zeroization.** Key material is held in `zeroize` buffers and wiped on
expiry, revocation, lock and shutdown. The agent writes **nothing to
disk** — the only file it ever creates is its socket (mode 0600). This
is test-asserted: the test suite creates sessions with canary secrets,
kills the agent, and scans every file it could have touched.

**Cooperative revocation.** Clients that subscribe receive pushed
events (`session_revoked`, `session_expired`, `sessions_locked`) so a
connected CLI knows to forget session-backed state instead of failing
obscurely later. This mirrors the protocol crate's
`Body::SessionRevoke`: cooperative, same-trust-domain enforcement.

## The socket

Discovery, in order:

1. `$PASSLANE_AGENT_SOCK` (both daemon and clients honor it)
2. `$XDG_RUNTIME_DIR/passlane-agent.sock` (Linux; per-user, 0700)
3. `$TMPDIR/passlane-agent.sock` (macOS; `TMPDIR` is per-user)

There is deliberately **no `/tmp` fallback**: a shared directory with a
guessed name is a slot for pre-created sockets. Discovery skips any
candidate runtime directory that is writable by group or others (a
stray `TMPDIR=/tmp` is rejected, not honored), and on Linux without
`XDG_RUNTIME_DIR` you set `PASSLANE_AGENT_SOCK` explicitly.

**Agent platforms should always set `PASSLANE_AGENT_SOCK`.** They
routinely override `TMPDIR` (so the default lookup misses) and run
commands without a terminal. With the variable set, a live session is
found whatever `TMPDIR` is, and a socket that cannot be used is an
error rather than a silent fall-through to a prompt nobody can answer.

**Socket trust.** Before a client sends anything, it validates the
socket path — and after connecting, re-validates it: it must be an
actual socket, carry no group/other permission bits, and be owned by
the connecting user (verified without libc by probing with a file the
client itself creates next to the socket). Nothing is transmitted
during `connect`, so the create/replace race on a shared-directory
path is closed by the second check before any secret can be sent;
metadata errors fail closed. A socket pre-created by another user in a
shared directory — e.g. an explicit `PASSLANE_AGENT_SOCK` pointing
into `/tmp` — is refused as *untrusted* instead of receiving your
master password. The daemon also refuses to delete a non-socket file
that happens to sit on the path (a `--socket` typo should not destroy
data).

On Windows there is no Unix domain socket support: the agent crate
compiles (so the CLI builds unchanged) but reports the agent as absent,
and the CLI falls back to its keychain/prompt flow.

The wire protocol is 4-byte big-endian length + JSON frames of
requests/responses (`ping`, `create_session`, `get_unlock_factors`,
`check_reveal`, `list_sessions`, `revoke_session`, `revoke_vault`,
`revoke_all`, `lock`, `subscribe`); see `crates/passlane-agent/src/protocol.rs`.
A client checks the agent's protocol dialect (`ping`) before trusting it
with a session. Secrets travel only over the local socket in
`SecretString` wrappers that zeroize on drop and redact in `Debug`
output.

## CLI integration

### How a command opens the vault

Every command that opens the vault walks the same unlock chain and takes
the **first source that opens it**:

1. **The session agent.** It is the only source guaranteed prompt-free, so
   it is asked first. With a live session the vault opens with no keychain
   dialog from any context — a terminal, a pipe, or a daemon with no
   terminal at all — and with no hardware-key prompt either when the
   session holds the vault's key factor (see below).
2. **The OS keychain.**
3. **The master-password prompt** — only when there is a terminal on
   stdin to ask at.

A source that fails does not end the chain: a session whose factors no
longer open the vault (it was re-keyed elsewhere) is reported and the
keychain is tried, a stale keychain password gives way to the prompt. The
hardware-key commands open the vault through the same chain, with the key
they chose (the recovery secret, or none while the first key is enrolled).
When several live sessions cover one vault, the agent serves the one that
holds the key factor, if any.

**What a session holds.** `passlane unlock --session` hands the agent
everything a command needs to open the vault without a prompt: the master
password, and — when the vault has a hardware-key factor a session *can*
hold — that factor too. A session can hold a **secret-backed** key (a
recovery secret, a virtual key): the factor answers every challenge,
including the fresh one a save issues, so such a vault stays writable
through the session. A **physical** key's secret never leaves the device,
so it cannot be handed over: for such a vault the session covers the
master password only and the key is still touched for every command, as
without a session. `passlane sessions list` shows which is which —
`unlock` versus `unlock + hwkey` — and `unlock --session` says so when it
creates the session.

**Without a terminal, nothing waits.** A command whose stdin is not a
terminal (an agent daemon, a scheduled job, `passlane … < /dev/null`) can
expect no answer to any prompt, so the chain never blocks on one:

- a hardware-key vault whose key factor the session does not hold fails
  at once, before the keychain is even asked, with a message that names
  the key and the session;
- the keychain is given a few seconds (the dialog macOS shows for a
  password stored by another build of passlane never closes by itself);
  a keychain that has not answered is reported as such;
- the master password is never prompted for; the error says how to open a
  session instead;
- `hwkey add` and `hwkey remove --secret` are refused outright — the first
  needs the new key touched to save, the second the secret typed in — and
  `hwkey remove` only when no live session holds the vault's key factor
  (with one, the key is removed with no key present at all);
- a request to the agent is given a few seconds too: a daemon that accepts
  connections and never answers them is reported as wedged instead of
  holding every command for good. (Subscribed event streams are not
  bounded — waiting for an event is their job.)

The completion cache follows the same rule. A command that opens the vault
brings a missing or stale cache up to date *from that vault*, with no
keychain read. Only the commands that open no vault refresh a stale cache
through the keychain, and only at a terminal while no live session serves
the vault.

**A configured agent is not optional.** When `PASSLANE_AGENT_SOCK` names
a socket, a command that cannot use it stops with an error saying what
is wrong and what to do — nothing is listening there, the socket is
untrusted, the agent speaks another protocol dialect (an agent left
running from an older binary; restart it), or it does not answer. Quietly moving on to the
keychain or a prompt is how an agent context used to end up waiting
forever (passlane#65). Without `PASSLANE_AGENT_SOCK` an absent agent is
just absent, and the chain continues with the keychain.

- **`passlane unlock --session [SECS]`** opens the vault and hands the
  factors to the agent *instead of* the keychain. Needs the agent — and
  starts one itself when none is running and that is allowed (see
  [Auto-start](#auto-start)); fails early with a hint when it is not
  running and could not be started, or cannot be used.
- **`passlane lock`** removes the keychain password *and* revokes the
  vault's agent sessions (`--all` drops every session). Locking must not
  leave a vault effectively unlocked through a live session.
- **The ask flow** (`agent = ask`) offers *Approve once* / *Approve for
  this session* / *Deny*. "For this session" records a `reveal` session
  (15 minutes by default) in the agent: agent-facing reveals of that
  entry field — `show --out`, `list --json`, non-interactive runs — then
  pass without re-prompting until it expires, matched by the entry's
  UUID. Every such reveal is audited in `approvals.log` (`session`
  events); the grant is audited as a `session_granted` event. If the
  agent is not running, the choice downgrades to a single-use approval
  with a warning — never silently.
- **Session-backed long-running actions stop when the session ends.**
  The continuous TOTP view (`show -o`) subscribes to the agent's push
  events when the vault was unlocked through a session (or the reveal
  gate itself used one), revalidates the session's expiry after
  subscribing, and stops generating and copying codes the moment the
  session is revoked, expires, the agent locks — or the agent itself
  dies (the stream loss is treated as the end of session-backed
  access).
- **`passlane sessions list | revoke <id|all> | lock`** manage the
  agent's sessions. `revoke` accepts the short id prefix shown by
  `list`; `--vault work sessions revoke all` scopes the revocation.

## The deposit-offer

The scenario auto-start exists for (passlane#77): with no agent running,
`passlane show` on a phone-held-key vault needs the full approval dance
*every* time — the pasted answer dies with the command that used it.
The answer can instead outlive that one process.

After an interactive approval is pasted and verified for a **vault
open** (an `Unlock` approval — a save's answer belongs to the save that
asked for it, an enrollment's proves the holder, and neither is
offered), the CLI asks once:

```
Hold this approval in the session agent for 15 minutes, so commands
until then do not ask the phone again? (y/N)
```

- **The default is No**: extending an approval's reach past the command
  that asked for it is an affirmative act, and declining leaves exactly
  today's behavior.
- The offer is made **only when holding could work**: an agent is
  running, or one would be auto-started on acceptance (see
  [Auto-start](#auto-start)). It never appears in non-terminal contexts
  (the non-interactive arm never reaches it) and never for answers that
  came from the agent itself.
- An accepted offer holds the answer for 900 s (the approval protocol's
  default cap, like an "Approve for this session" reveal) as a timed
  `challenge_response` session, keyed by the vault's current seed —
  every command until expiry opens without asking the phone again; the
  first save after it still asks, because the seed rotates.
- The agent's cap rules are obeyed, never bent: an agent started with a
  lower `--max-session-secs` refuses the deposit, and the command says
  so as a warning — the vault is already open, the offer was never a
  requirement. `passlane lock` and `passlane sessions revoke` drop the
  held answer like any other session.

## Auto-start

An idle agent holds no secrets — memory-only, empty until a human
approves — so a command that needs one can start it itself
(passlane#77). `session_agent::connect_or_start` runs wherever the CLI
is otherwise about to fail with "the session agent is not running":

- **`unlock --session`** — the headline case;
- **`approve --response`** when the answer is destined for the agent
  (the no-terminal deposit flow);
- an **accepted deposit-offer** (above) — the started agent is what the
  answer is held in.

How it starts the daemon:

- the `passlane-agent` binary is located **next to the running `passlane`
  executable** first (a `~/bin/passlane` symlink into a `target/release`
  checkout finds the `passlane-agent` beside the real binary), then on
  `PATH`; `$PASSLANE_AGENT_BIN` overrides the lookup when it names an
  executable;
- it is spawned **detached** — its own process group, so it survives the
  closing terminal — with stdio appended to `~/.passlane/agent.log` and
  **no other file descriptor inherited**: a daemon that outlives its
  spawner must not hold the spawning command's pipes open;
- it gets `--max-session-secs` **accommodating the triggering request**
  (an `unlock --session 3600` that spawns an agent must not be refused
  by it; the value is floored at the default cap and bounded by the hard
  cap of 28800 s);
- the CLI then waits — bounded at about two seconds — for the socket to
  **accept** a connection, because a socket file's existence is not
  readiness. Two racing commands each spawn an agent and both connect to
  the one that wins the bind; the loser exits on its own (the server
  replaces only stale sockets and refuses a live one).

The boundaries that make auto-start safe:

- **Only discovered default socket paths.** A socket named by
  `PASSLANE_AGENT_SOCK` that nothing serves stays the error it has
  always been — never a silent fallback (passlane#65). Auto-start never
  happens behind an explicitly configured socket.
- **An empty daemon only.** Starting an agent creates no session and
  approves nothing; it holds key material only after a human hands it
  over. Non-terminal contexts (agents, cron) auto-start too: spawning
  blocks on nothing, and the "nothing may block on stdin" rule is
  untouched.
- **Opt-out**: `PASSLANE_AGENT_AUTOSTART=0` restores today's behavior —
  for setups where launchd/systemd own the daemon and a second,
  privately-started one is unwanted. A live socket short-circuits
  everything regardless.
- **A missing binary degrades** to today's "start it with
  'passlane-agent'" message, unchanged — no surprise downloads.

launchd/systemd setups are unaffected: a running unit's socket answers
before any spawn is considered, and a pinned-socket unit exports
`PASSLANE_AGENT_SOCK`, which disables auto-start on that path entirely.
The launchd plist below remains the recommended path for pinned sockets
and a central `--max-session-secs` policy.

## Autostart (optional)

### macOS — launchd

`~/Library/LaunchAgents/net.passlane.agent.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>net.passlane.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/passlane-agent</string>
    <string>--socket</string><string>/Users/YOU/.passlane/agent.sock</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
```

launchd does not export per-user `TMPDIR` to agents, so the unit pins an
explicit socket and exports it to the session:

```sh
launchctl setenv PASSLANE_AGENT_SOCK "$HOME/.passlane/agent.sock"
launchctl load ~/Library/LaunchAgents/net.passlane.agent.plist
```

(Put the `setenv` in your shell profile too, for terminal use.)

### Linux — systemd user unit

`~/.config/systemd/user/passlane-agent.service`:

```ini
[Unit]
Description=Passlane session agent (in-memory vault unlock sessions)

[Service]
ExecStart=%h/.cargo/bin/passlane-agent
# systemd exports XDG_RUNTIME_DIR, so the default socket path already
# resolves to /run/user/<uid>/passlane-agent.sock for every CLI.
Restart=on-failure

[Install]
WantedBy=default.target
```

```sh
systemctl --user enable --now passlane-agent.service
```

## Security notes

- **Local, same-user trust domain.** The 0600 socket restricts access
  to the user's own processes. Anything running as the same user can
  already read an open vault or the keychain entry; the agent does not
  (and cannot, in-process) defend against a fully compromised host —
  see PLAN §2.3. What it *does* provide: bounded, revocable,
  never-on-disk key material instead of an unbounded keychain copy.
- **IPC buffers** holding serialized secrets are zeroized on both sides
  after use; `Debug` output redacts them; log lines never contain them.
- **A held hardware-key factor is the key's secret, never a key's
  response.** A session carries a challenge-response factor only as the
  secret of a secret-backed key, held and wiped like the master password
  beside it (the test suite plants a canary secret and scans for it). A
  physical key contributes nothing to a session: its secret stays in the
  device, and so does every response it computes.
- **A locked vault is locked everywhere**: `passlane lock` clears the
  keychain *and* the agent's sessions for that vault.
- Sessions die with the agent: there is no persistence file, by design.
  If you need a session across reboots, that is what the keychain (or a
  phone approval) is for.

## Relationship to the phone-key work

The phone-held key has landed (passlane#53, `passlane hwkey add
--phone`); see [phone-held-key.md](phone-held-key.md). The distinction
this section's earlier draft asked about is now real: the material an
`unlock` session holds is a *secret* (a recovery secret, a virtual key)
that answers every challenge, while a phone's approval is a *response to
one challenge* — valid only until the vault is saved. That answer arrives
through `passlane approve --response` and is held as a
`challenge_response` session keyed by the exact challenge it answers —
the vault's KDF seed, which rotates on every save, so a stale answer
can never open a re-saved vault. `passlane unlock --session` holds the
opening answer beside the master password, so one approval serves until
expiry; `passlane lock` drops it with everything else. Single-use
answers are consumed by the one command that uses them, and a response
presented while no agent runs — and none could be started — is refused
before anything is recorded, so it still works once one is. The
[deposit-offer](#the-deposit-offer) is the interactive counterpart: a
pasted answer can be held for the commands that follow.
`Body::SessionRevoke` from the phone maps
to `revoke_session`, as before. A physical key's one touch still cannot
serve a whole session — its secret never leaves the device — which is
why `unlock --session` says so plainly for those.
