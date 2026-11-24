# passlane FAQ

Questions about the phone-held key and how it interacts with hardware keys
and other KeePass clients. For the full picture see
[docs/features/phone-held-key.md](docs/features/phone-held-key.md) (the
runbook), [docs/features/session-agent.md](docs/features/session-agent.md)
(what holds answers between commands) and
[crates/passlane-approval/SPEC.md](crates/passlane-approval/SPEC.md) (the
protocol).

## Can I unlock my vault with my iPhone today, or do I need the iOS app?

You do not need the iOS app. The phone side is implemented today by the
**approval page** in the iPhone's browser:

```sh
passlane --vault <vault> hwkey add --phone --page <approval-page-url>
```

The page creates a **non-extractable WebCrypto HMAC key** (the raw secret
exists exactly once, for the recovery sheet) and your **passkey** provides
the Face ID step. From then on every open and every save of that vault asks
the phone for an approval over the link transport — scan the QR or open the
link, approve, paste the response back (or let the session agent hold it).

The iOS app (see the
[passlane-ios plan](https://github.com/anssip/passlane-ios/blob/main/PLAN.md))
later replaces the page with a native service — Secure Enclave, Face ID,
universal links. It is an upgrade to the same protocol, not a prerequisite:
the vault, the factor and the recovery sheet stay the same.

## My vault is already protected by a YubiKey. Can I enroll the iPhone as a second, alternative factor?

Not as an independent second factor. Enrollment is refused up front:

> Enrollment while a hardware key is enrolled (or the reverse) is refused:
> one challenge-response factor per vault, like the kdbx format.

The reason is the file format: the composite key is password (+ keyfile)
plus **exactly one** HMAC-SHA1 challenge-response secret. Two different
secrets produce two different composite keys — the vault can only be
encrypted with one of them.

**Alternatives, yes — by sharing the same secret.** All key types use the
same HMAC-SHA1 challenge-response scheme, so:

1. Remove the hardware-key factor, then enroll the phone
   (`hwkey add --phone`). The vault is re-keyed to the **phone's fresh
   secret** — note the direction: the phone generates a new secret, there
   is no way to import your existing YubiKey slot secret into the phone,
   so the old slot stops being this vault's factor.
2. The **recovery sheet** contains exactly that secret. Program it into a
   YubiKey slot (see the caution below).
3. Both devices now answer the challenge identically. The phone is the
   primary holder in passlane; the YubiKey opens the vault everywhere
   KeePass works.

The trade-off: the second factor then exists in three copies — phone,
YubiKey, paper sheet. That is the same model as backing up a YubiKey slot
secret, which KeePass users have done for years; keep the sheet offline.

## How does another KeePass client (KeePassXC, KeePass 2.x, KeePassium, StrongBox) open a phone-held vault?

To them the vault is an ordinary KDBX4 database whose key includes a
challenge-response component. The derivation is identical on both sides —
the challenge is the vault's **KDF seed**, which sits in the cleartext
outer header:

- keepass-ng (passlane): `perform_challenge(&outer_header.kdf_seed)`
- KeePassXC 2.7.10 (`CompositeKey::transform`): `kdf.seed()` is passed as
  the challenge (its master-seed variant is the legacy KDBX3 path only)

Given the same secret, every client computes the same key.

What they **cannot** do is ask the iPhone: the approval page speaks
passlane's approval protocol over HTTPS, and KeePass clients expect a
USB/NFC hardware key. The bridge is the recovery sheet:

1. Program the sheet's secret into a YubiKey slot, e.g. run
   `ykman otp chalresp <slot>` and enter the 40-hex-character secret at
   its prompt.
2. In the client, add the YubiKey as a **hardware key / challenge-response**
   factor (KeePassXC: database unlock → *Add Hardware Key* → slot).
   KeePass 2.x, KeePassium and StrongBox work the same way (NFC keys on
   iOS).

No KeePass client accepts a typed-in HMAC secret. Typing the secret is a
passlane-only recovery path (`passlane hwkey remove --secret`): it opens
the vault and **strips** the factor — see the runbook for the full
recovery order when the holder device is lost (recover from the sheet
first, then re-pair and re-enroll; a new pairing does not restore the old
holder's key).

## Which YubiKey slot should I program?

Never overwrite a slot that currently protects a vault — `ykman otp
chalresp` replaces the slot's secret, and the old secret is what encrypts
that vault. If your key's slot 1 protects an existing vault, program the
sheet secret into **slot 2**, or use a spare key. If you ever lose the
secret of a slot that protects a vault, the vault is unrecoverable without
a backup of that secret — which is exactly what the recovery sheet is.

## Where do I go deeper?

- Runbook, enrollment sequence, recovery:
  [docs/features/phone-held-key.md](docs/features/phone-held-key.md)
- Agent approvals and the `agent = never|ask|allow` policy:
  [docs/features/agent-approvals.md](docs/features/agent-approvals.md)
- The session agent (what holds unlock answers in memory):
  [docs/features/session-agent.md](docs/features/session-agent.md)
- The protocol: [crates/passlane-approval/SPEC.md](crates/passlane-approval/SPEC.md)
- The iOS app plan:
  [passlane-ios/PLAN.md](https://github.com/anssip/passlane-ios/blob/main/PLAN.md)
