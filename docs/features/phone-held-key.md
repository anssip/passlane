# The phone-held key (`passlane hwkey add --phone`)

The vault's challenge-response secret lives on another device — the
iPhone, or for now the [approval page](../../page/README.md) — and this
computer only ever sees 20-byte answers. It is the same HMAC-SHA1
challenge-response KeePass uses for YubiKeys, so the vault stays
readable by a physical key programmed with the same secret, and the
recovery sheet works everywhere KeePass works.

```
$ passlane hwkey add --phone
Asking 'approval-page' to create the key for vault 'work'. On that device:
print or save the recovery sheet it shows, then scan or type the secret
back from that copy — the key is not enrolled until you do.
This enrollment needs 2 approvals from that device: create the key, then
save the vault with it. Each approval answers its own fresh request —
paste only the response the terminal is waiting for; a response from an
earlier request is refused.
Approval needed to creating a phone-held key for vault 'work' (request 4f2a…):
https://approve.example/approve.html#UExBUA…        ← link (stdout)
█████▀▀█▀ …                                       ← QR (stderr)
```

On the phone (or the approval page in its browser): the request appears,
the key is created, and the recovery sheet is shown. **The sheet is
printed or written down**, and its secret typed back from that copy —
the page hides the sheet before asking, because a copy on the same
screen proves nothing. Only then is the request answered. Back at the
computer (or from anywhere — see below), the answer re-keys the vault:

```
$ passlane approve --response @response.b64
Approved: enrolling a phone-held key for vault 'work' (request 4f2a…).
Re-run 'passlane hwkey add --phone' to continue.
$ passlane hwkey add --phone
… (the re-key asks for one more approval, then)
Phone-held key enrolled for vault 'work'.
```

From then on, every **open** and every **save** needs the phone's
approval: the challenge is the vault's KDF seed, which sits in the kdbx
outer header in cleartext, so a request can be minted while the vault is
locked — and it rotates on every save, which is why saving asks too.

```
$ passlane show github
Approval needed to opening vault 'work' …  ← scan/approve, then
$ passlane approve --response @blob
$ passlane show github                     ← re-run: the vault opens
```

## Where the answer lives

The 20-byte answer is a vault unlock factor. It is verified, used, and
dropped; it is **never written to disk** (this is test-asserted end to
end). The unlock chain asks for a held answer **before** the keychain —
a command with no terminal and no keychain opens through one, which is
the point (#61 finding 4). Two paths deliver it to the command that
needs it:
- **Interactive terminal**: the response is pasted into the waiting
  command and consumed on the spot. One paste, one verdict: a rejected
  paste ends the command — the message names which request the blob
  answered (the rid travels in the response envelope header, decodable
  even on a rejection) versus which one the prompt waited for, with the
  re-run guidance. There is no re-prompt; the recovery for a dead blob
  is a fresh request, and that comes from re-running the command.
  Multi-approval ceremonies are announced up front (an enrollment is
  "2 approvals: create the key, then save the vault"), and the approval
  page labels each response with the request it answers and expires it
  visually once that request lapses, so the current response is always
  identifiable on both ends.
- **Anywhere else** (`passlane approve --response` from another shell,
  an agent relaying over chat): the answer is held **in memory by the
  session agent**, keyed by the exact challenge it answers — the seed
  changes on every save, so a stale answer can never open a re-saved
  vault. A single-use answer serves one command; `passlane unlock
  --session <secs>` holds one approval (with the master password) for
  repeated use until it expires. `passlane lock` drops it with
  everything else.

Without a session agent there is nowhere to keep an answer: the
approval is refused *before* anything is recorded, so the same response
still works once an agent is running.

## Enrollment, in order

1. The holder is the pinned approver (`passlane approvals enroll`
   paired it). With none pinned, `hwkey add --phone` pairs first; with
   several, `--approver <label>` picks one (choosing needs a terminal).
2. The holder creates the secret and shows the **recovery sheet**. The
   enrollment request is not answered until the sheet's secret has been
   typed back from a copy — the page hides the sheet first. The secret
   exists as raw bytes exactly once, for the sheet; afterwards only as
   a non-extractable HMAC key.
3. The CLI re-keys the vault: the save asks the holder for the answer
   to the new seed, then opens the saved file with that one answer to
   prove the enrollment before recording the factor.
4. The registry records only *which holder* to ask —
   `phone_key: { holder_kid, vault_uid, enrolled_at }` — never anything
   secret. `vault_uid` is the vault's holder-side identity: derived
   from the holder and the vault's path, so a resumed enrollment asks
   under the same id the first run did, and `passlane vault rename`
   (which changes the name) does not orphan the holder's key — requests
   carry the uid, and the name only ever for display.

If anything fails along the way (a refusal, an abandoned sheet, a
registry that cannot be written), the re-key is rolled back and the
vault is exactly as it was. One failure is exempt from the rollback: a
vault file that a sync client replaced mid-enrollment is left exactly
as the sync client wrote it — the rollback's save would clobber it with
our older in-memory copy — and the enrollment simply did not happen.

## Recovery

- **The sheet**: `passlane hwkey remove --secret` prompts for the
  secret printed on it (or a backed-up YubiKey slot secret — same
  thing), opens the vault, and strips the factor. A YubiKey programmed
  from the sheet secret opens the vault too, without removing anything.
- **The holder is gone** (device lost, pin dropped): `hwkey remove
  --secret` from the sheet is the way in. Re-pairing does not restore
  the pin: the approval page generates a fresh identity on every
  pairing — even in the same browser profile — so the new pin holds no
  key for the vault while the registry still references the old
  holder. Recover from the sheet first, then pair
  (`passlane approvals enroll`) and enroll the key again
  (`passlane hwkey add --phone`).

## Limits, honestly

- Every open needs a human approval. That is the point; use
  `unlock --session` when a task needs many commands.
- Saving without a terminal blocks waiting for the approval (the new
  seed only exists during the save) — with the session agent it
  completes as soon as the owner approves; without it, the command
  refuses up front with guidance.
- Enrollment while a hardware key is enrolled (or the reverse) is
  refused: one challenge-response factor per vault, like the kdbx
  format.
- The link transport carries no proximity signal; the page says so on
  every approval screen.

See `crates/passlane-approval/SPEC.md` §7 for the protocol view, and
`docs/features/session-agent.md` for the agent that holds answers.
