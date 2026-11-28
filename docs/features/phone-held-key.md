# The phone-held key

The vault's challenge-response secret lives on another device — the
iPhone, paired over the pairing QR (or the [approval
page](../../page/README.md), pinned with `approvals enroll`) — and this
computer only ever sees 20-byte answers. It is the **default second
factor at vault setup**: `passlane init` and `passlane vault add` offer
it first (passlane#85), enrolling inline during setup. It is the same
HMAC-SHA1 challenge-response KeePass uses for YubiKeys, so the vault
stays readable by a physical key programmed with the same secret, and
the recovery sheet works everywhere KeePass works.

```
$ passlane hwkey add --phone
No approver is pinned yet, so pair first: the iOS app you pair now will
hold the key for this vault. (No app? Cancel here, run 'passlane
approvals enroll' to pin the approval page, then re-run this command.)
Pair with the passlane app — open this link there (scan or paste it):
https://approve.northernpeaks.dev/pair.html#s=…&e=…   ← link (stdout)
█████▀▀█▀ …                                          ← QR (stderr)
Confirmation code: 123456-789012 — the app must show the same code …
Paste the pairing response the app produced (leave empty to cancel): …
Mutual confirmation code: 987654-321098 — does the app show the same
code? y
Asking 'anssi-iphone' to create the key for vault 'work'. On that device:
print or save the recovery sheet it shows, then scan or type the secret
back from that copy — the key is not enrolled until you do.
This enrollment needs 2 approvals from that device: create the key, then
save the vault with it. Each approval answers its own fresh request —
paste only the response the terminal is waiting for; a response from an
earlier request is refused.
Approval needed to creating a phone-held key for vault 'work' (request 4f2a…):
https://approve.northernpeaks.dev/approve.html#UExBUA…  ← link (stdout)
█████▀▀█▀ …                                           ← QR (stderr)
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

1. The holder is the pinned approver — the app, paired with
   `passlane approvals pair` (or this command, when nothing is pinned
   yet). The approval page is the other path: `passlane approvals
   enroll` pins it first, and this command then uses that pin. With
   several pins, `--approver <label>` picks one (choosing needs a
   terminal). Pairing itself is the SPEC §5 ceremony: the QR-borne
   pairing secret, the CLI-side confirmation code, then the mutual code
   the app shows from the response — the pin is stored only when both
   match.
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
  the pin: the app generates a fresh identity on every pairing, so the
  new pin holds no key for the vault while the registry still
  references the old holder. Recover from the sheet first, then pair
  (`passlane approvals pair`; the approval page's path is `passlane
  approvals enroll`) and enroll the key again
  (`passlane hwkey add --phone`).

## At vault setup (passlane#85)

`passlane init` and `passlane vault add` offer the phone-held key as the
**default** second factor when creating a vault — phone first, the
hardware key as the alternative, none still available:

```
? Protect the vault with a second factor?
> Phone (approve on your phone)      ← the lead choice
  Hardware key (e.g. a YubiKey)
  No second factor
```

Choosing the phone pairs it inline (the SPEC §5 ceremony, when no
approver is pinned yet) and runs the enrollment ceremony — the recovery
sheet and its scan-back, then the two approvals — **before the vault is
registered**: the file is written password-only, the re-key rides the
ceremony's save approval (this machine never sees the secret), and the
registry entry is recorded together with the factor only once the vault
opens with the holder's answer. A ceremony that is refused or expires
registers nothing and removes the file it had just created; a registry
write that fails rolls the re-key back — the same failure semantics a
hardware key gets at creation. The setup ends by saying what the factor
means: every open and save of the vault asks the phone, and the
recovery sheet is the only way in without it.

Registering an **existing** phone-protected vault (created on another
machine) asks which second factor it requires, and `Phone-held key`
records the factor: the pinned holder is asked for the approval the
vault's own challenge needs, and only a vault that opens with the
password and that approval is registered — so unlocks route through
the approval flow instead of failing with a misleading wrong-password
error. The holder-side vault id is derived from the holder and the
vault's path, so the phone recognizes the vault when the file sits
where it was enrolled; the same phone, a different path, is an honest
refusal. With nothing pinned here, the error says where the pin lives
(`approval_peers.json` on the machine that enrolled the holder) —
pairing fresh would be a new identity that holds no key for this vault.

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
