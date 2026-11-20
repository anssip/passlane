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
| `unlock` | the vault's master password | `passlane unlock --session` (later: a phone approval of `Operation::Unlock`) | expiry, revoke, `lock`, agent stop |
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

**Socket trust.** Before a client sends anything, it validates the
socket path: it must be an actual socket, carry no group/other
permission bits, and be owned by the connecting user (verified without
libc by probing with a file the client itself creates next to the
socket). A socket pre-created by another user in a shared directory —
e.g. an explicit `PASSLANE_AGENT_SOCK` pointing into `/tmp` — is
refused as *untrusted* instead of receiving your master password. The
daemon also refuses to delete a non-socket file that happens to sit on
the path (a `--socket` typo should not destroy data).

On Windows there is no Unix domain socket support: the agent crate
compiles (so the CLI builds unchanged) but reports the agent as absent,
and the CLI falls back to its keychain/prompt flow.

The wire protocol is 4-byte big-endian length + JSON frames of
requests/responses (`ping`, `create_session`, `get_unlock_factors`,
`check_reveal`, `list_sessions`, `revoke_session`, `revoke_vault`,
`revoke_all`, `lock`, `subscribe`); see `crates/passlane-agent/src/protocol.rs`.
Secrets travel only over the local socket in `SecretString` wrappers
that zeroize on drop and redact in `Debug` output.

## CLI integration

- **Unlock consults the agent.** The password chain is: OS keychain →
  session agent → interactive prompt. A `once` unlock session is
  consumed by the unlock that uses it; a `timed` session serves every
  command until it expires.
- **`passlane unlock --session [SECS]`** opens the vault (verifying the
  password) and hands the factors to the agent *instead of* the
  keychain. Requires the agent; fails early with a hint when it is not
  running.
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
  events when the vault was unlocked through a session, and stops
  generating and copying codes the moment the session is revoked,
  expires, or the agent is locked.
- **`passlane sessions list | revoke <id|all> | lock`** manage the
  agent's sessions. `revoke` accepts the short id prefix shown by
  `list`; `--vault work sessions revoke all` scopes the revocation.

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
- **A locked vault is locked everywhere**: `passlane lock` clears the
  keychain *and* the agent's sessions for that vault.
- Sessions die with the agent: there is no persistence file, by design.
  If you need a session across reboots, that is what the keychain (or a
  phone approval) is for.

## Relationship to the phone-key work

When the link transport and phone-held key land (passlane-ios v1), the
phone's `ApprovalResponse { scope: Timed { .. } }` for an
`Operation::Unlock` becomes exactly one `unlock` session — the agent
already speaks the protocol's `Scope` shape. The HMAC response will be
held the same way the master password is today (memory only, wiped on
expiry), and `Body::SessionRevoke` from the phone maps to
`revoke_session`. That is why the session model lives in the shared
crates rather than the CLI.
