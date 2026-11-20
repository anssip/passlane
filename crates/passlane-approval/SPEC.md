# passlane approval protocol — specification (draft 1)

Status: **implementable draft** for passlane#49. The reference implementation
is this crate; the Swift (UniFFI, passlane#44) and JavaScript (static
approval page, passlane#51) ports must interoperate with it via
[`vectors/v1.json`](vectors/v1.json).

## 1. Purpose and constraints

Two features share one protocol:

- **Phone-as-key** (passlane-ios PLAN §3.1): the vault's HMAC-SHA1
  challenge-response secret lives only on the iPhone; the CLI asks, the owner
  approves with Face ID, the CLI gets its 20-byte answer.
- **Agent approvals** (PLAN §3.3): an agent wanting a secret marked
  `agent = ask` triggers the same human approval.

The transport is never trusted. v1 carries envelopes in a terminal QR code /
URL fragment and pastes the reply back over Universal Clipboard; later
transports (BLE v1.1, private CloudKit v1.2) change only the carrier. A
malicious relay sees opaque bytes, and can drop, delay or replay them —
nothing else.

Non-goals: hiding *that* a request exists from the approver's own device;
post-quantum security; proximity binding (BLE adds that later).

## 2. Cryptographic profile (ADR: HPKE, not Noise)

**Decision: RFC 9180 HPKE, base mode, `DHKEM(P-256)` + `HKDF-SHA256` +
`AES-256-GCM`, plus ECDSA-P256/SHA-256 sender signatures.**

Alternatives considered:

| | HPKE (RFC 9180) | Noise (XX/IK) | custom ECIES |
|---|---|---|---|
| Message model | one-shot, store-and-forward | interactive session handshake | one-shot |
| Secure Enclave | P-256 ECDH ✓ P-256 ECDSA ✓ | ECDH per message with custom DH plumbing | ✓ |
| WebCrypto (Phase 0 page) | ECDH+HKDF+AESGCM, DHKEM is thin composition over natives | no native support | fully native |
| swift-crypto | native HPKE ✓ | manual | manual |
| Vectors / analysis | RFC test vectors, used by MLS/ECH | framework vectors, not of our protocol | none |

Why HPKE wins: our messages are **asynchronous** — the approver answers
minutes later over a relay, with no live connection and possibly no
connectivity at all (QR scan). Noise's security model is built around
interactive handshakes; bending it to one-shot relayed messages buys nothing
and costs a state machine on every platform. HPKE's single-shot seal/open is
exactly our shape, and every consumer platform has either a native
implementation (swift-crypto) or the primitives to compose the KEM
deterministically (WebCrypto). Sender authentication is layered as a
signature rather than HPKE `mode_auth`, because the approver's signing key is
a **Secure Enclave** key — the SE signs (ECDSA) and does ECDH, which maps
cleanly onto HPKE-base + signature, while `mode_auth` would require the SE
key to be the KEM sender key in the response direction.

Pairing messages cannot use HPKE (no pinned recipient exists yet), so they
use `AES-256-GCM` under a key derived by `HKDF-SHA256` from a 32-byte
QR-borne secret (§5).

Libraries: Rust uses `hpke-rs` 0.8 (Cryspen; MPL-2.0, GPL-compatible) with
its RustCrypto backend — this crate never implements HPKE itself.

## 3. Envelope wire format

All integers little-endian. One envelope = one message.

```text
offset size field
0      4    magic "PLAP"
4      1    version (= 1)
5      1    message type: 1 pairing_req, 2 pairing_resp, 3 approval_req,
                      4 approval_resp, 5 session_revoke
6      1    signature kind: 0 none, 1 ECDSA-P256 DER, 2 WebAuthn ES256
7      2    header length
9      n    header — compact JSON, cleartext
.      2    enc length     65 for HPKE envelopes, 0 for PSK pairing
.      n    enc             HPKE ephemeral public key (uncompressed SEC1)
.      4    ciphertext length
.      n    ciphertext      AEAD ct ‖ tag
.      2    signature length
.      n    signature       kind 1: DER ECDSA; kind 2: JSON WebauthnAssertion
```

**Header** (cleartext, deliberately compact — it rides in QR codes):

```json
{ "v":1, "t":3, "n":"<16B nonce hex>", "ts":1732000000, "exp":1732000300,
  "skid":"<sender enc kid>", "rkid":"<recipient enc kid>", "rid":"<16B request id hex>" }
```

Everything sensitive (vault name, entry titles, challenges, responses) is in
the encrypted body, never the header. A relay learns only: a message exists,
its lifetime, and opaque key ids. `skid`/`rkid` are the first 8 bytes of
`SHA-256("enc" ‖ public_key)` in hex — routing/pinning handles, not
identities.

**Body** (inside the ciphertext, JSON, `#[serde(tag="type")]`):
`pairing_request`, `pairing_response`, `approval_request`,
`approval_response`, `session_revoke` — see `src/message.rs` for the
authoritative field list. Bodies wipe themselves on drop
(`zeroize`); `Debug` prints secrets as `[redacted]`.

**AEAD binding**: AAD = `magic ‖ version ‖ type ‖ sig_kind ‖ header_len ‖
header`. HPKE `info` = `"passlane-approval/v1" ‖ type`. The header is
cleartext but cannot be modified without breaking decryption.

**Signatures** cover the entire prefix through the ciphertext (AAD ‖ `enc_len
‖ enc ‖ ct_len ‖ ct`), including the signature-kind byte. ECDSA nonces are
RFC 6979 deterministic on the CLI; the SE randomizes.

**WebAuthn (Phase 0)**: the signature-kind-2 block is the JSON
serialization of the assertion — field names `authenticator_data`,
`client_data_json`, `signature` (snake_case, base64url values), matching
the crate's serde representation exactly. Implementations on other
platforms must use these key names verbatim. The
WebAuthn challenge is `base64url(SHA-256(transcript))` — the passkey
signature thus commits to the exact envelope bytes. Verification additionally
checks `type == "webauthn.get"`, the pinned origin, the RP-id hash, and the
user-present flag (`src/webauthn.rs`).

Envelope sizes: a typical approval request is ~600 bytes → ~800 base64url
characters, comfortably inside QR capacity and URL fragments.

## 4. Freshness and replay

- `nonce`: 16 random bytes per envelope. Receivers record
  `(skid, nonce) → exp` **only after** full verification, so unverified
  envelopes cannot poison the store. Entries are pruned after `exp`.
- `ts`/`exp`: receiver policy (defaults): reject `ts > now + 120s` (skew),
  reject `exp - ts > 900s` (TTL cap), reject `now >= exp`.
- `rid`: request id; a response for a request must echo it (the CLI matches
  pending requests by `rid` before accepting an approval).
- Rate limiting is a **hook** (`RateLimiter` trait, sliding-window reference
  impl): the phone throttles *displays* (approval fatigue), the CLI
  throttles *emission*.

## 5. Pairing

1. CLI generates a 32-byte `PairingSecret`, embeds it (with its public keys
   and a request envelope) in the enrollment QR — URL fragment, never sent
   to any server.
2. `pairing_request` travels PSK-sealed (key = `HKDF-SHA256(salt =
   "passlane-pairing/v1", ikm = secret, info = "passlane-approval/v1" ‖
   type)`), signed by the CLI's signing key (carried inside the ciphertext).
3. **First human check** — the CLI-side code. Both sides display twelve
   digits (two six-digit groups): terminal over its own keys, phone over
   the keys from the decrypted request.
   `n = u64(HMAC-SHA256(k_display, "confirmation-code" ‖ cli_enc_pub ‖
   cli_sig_pub))[0..8] mod 10^12`, `k_display = HKDF-SHA256(salt =
   "passlane-pairing/v1", ikm = secret, info = "display-code")`,
   formatted `123456-789012`. The identity binding catches a swapped QR
   carrying substituted *CLI* keys.
4. `pairing_response` is normal HPKE to the CLI's key, signed by the
   approver, **and carries a binding proof**:
   `HMAC-SHA256(k_bind, "pairing-response-bind" ‖ request.rid ‖ cli_enc_pub
   ‖ responder_enc_pub ‖ responder_sig_pub)` with `k_bind =
   HKDF-SHA256(salt = "passlane-pairing/v1", ikm = secret, info =
   "response-binding")`. The proof binds the response to the exact request
   (by `rid`) and to **both** identities being pinned.
5. **Second human check** — the mutual code. Anyone holding the pairing
   secret (e.g. an attacker who read the QR) can produce a valid proof for
   *their own* keys, so cryptography alone cannot authenticate the
   responder. After the response arrives, the terminal displays
   `HMAC-SHA256(k_display, "mutual-confirmation-code" ‖ cli_enc_pub ‖
   cli_sig_pub ‖ responder_enc_pub ‖ responder_sig_pub)` (same 12-digit
   formatting) computed from the decrypted response, and the responder
   displays the same value computed from the request. **Both codes must
   match before either side persists its pin.**
6. The secret is discarded; both sides store a `PeerPin`
   (`label`, `enc_pub`, `sig_pub`, `paired_at`, optional WebAuthn RP data).

**Entropy honesty**: a substituted-QR attacker who can also read the
terminal's displayed code can grind a replacement secret offline until its
first-stage code collides — twelve digits puts that at ~2^40 HMACs (hours
of GPU time, on top of physically swapping the QR and shoulder-surfing),
six would have been grindable in under a second. If substitution is
suspected, the out-of-band escape hatch is comparing full key fingerprints
(the hex `enc_pub`/`sig_pub` of both pins) — the iOS app will later support
scanning the responder's fingerprint QR directly.

**Away-from-desk pairing is forbidden for initial pairing.** The QR scan is
the out-of-band channel; a chat-relayed "pairing" is a social-engineering
vector. Existing pairs may re-approve over relays.

## 6. Phase 0 bootstrap (passkeys before the app exists)

Before the iOS app ships, the approver is the static page plus **two** keys
it manages, because a WebAuthn passkey can *sign* but cannot *decrypt*:
its private key never leaves the authenticator, so it cannot perform the
ECDH that HPKE needs. The page therefore enrolls:

- an **encryption key**: a WebCrypto ECDH P-256 key pair, generated by the
  page, `extractable = false`, stored in IndexedDB (non-extractable keys
  survive reloads and cannot be read out by script);
- a **signing identity**: a WebAuthn passkey on the page's domain (the
  hardware-backed, human-present factor).

**Enrollment** (one-time, at the computer): `passlane approvals enroll`
prints a QR/link to `https://<domain>/enroll` carrying a fresh CLI
enrollment nonce plus the CLI's two public keys. The page generates the
ECDH keypair, creates the passkey with
`navigator.credentials.create()` (`attestation: "none"` is fine —
attestation statements are signed by vendor attestation keys, not the
credential key, so they cannot bind anything to this user's passkey), and
then — the binding step — requests a **subsequent assertion** with
`navigator.credentials.get()`, whose challenge is
`SHA-256(enrollment_nonce ‖ ECDH_public_key ‖ cli_enc_pub ‖ cli_sig_pub)`.
Covering the CLI's keys closes the swapped-link hole: a relay that
substitutes its own `c=`/`s=` key material produces a challenge the
genuine CLI never issued, so the assertion it elicits fails on the CLI,
which recomputes the challenge from **its own** identity keys — never
from the link. The credential-key
signature over that challenge is what proves the passkey (and the human
behind it) vouches for this exact ECDH key. The CLI verifies the assertion
(`webauthn::verify_assertion` semantics: origin, RP-id hash, UP flag,
credential-key signature) and pins
`enc_pub = ECDH public key`, `sig_pub = passkey public key`,
`webauthn = { rp_id, origin }`. (COSE parsing and this ceremony land with
the CLI command — passlane#51.)

**Approvals**: request envelopes are HPKE-sealed to the pinned ECDH key;
the page decrypts with WebCrypto (ECDH + HKDF + AES-GCM composing DHKEM
exactly as §3 specifies), shows the request, and produces an
`approval_response` HPKE-sealed to the CLI's key with signature-kind 2 —
the WebAuthn assertion over the envelope transcript (§3). The passkey
proves the human is present; the ECDH key provides confidentiality;
enrollment binds the two together.

**Domain**: the page domain later serves the app's
`apple-app-site-association`, so the universal link routes to the app
instead. The envelope always rides the URL **fragment**, which browsers
never send to the domain.

## 7. The unlock application flow (phone-held key)

Enrollment (`hwkey add --phone`, passlane#53) and every vault open reuse this
sequence; the HMAC-SHA1 semantics are exactly KeePass's challenge-response
(the vault stays readable by a physical YubiKey programmed with the same
secret). The challenge is the vault's 32-byte KDBX4 KDF seed; the response
is the 20-byte HMAC-SHA1 digest of it:

```text
CLI                                              Phone / page
---                                              ------------
pair: QR(secret, pubs) ─── scan, confirm code ──> pin CLI
      <──────── pairing_response (HPKE, signed) ── pin phone
open: approval_request{ Unlock, challenge }
      ── QR/link fragment ──────────────────────> display, Face ID
      <─ approval_response{ response = HMAC-SHA1(secret, challenge) } ─
derive composite key with the response
```

The response crosses only inside the HPKE ciphertext. Sessions
(`Scope::Timed`, passlane#54) let one approval serve until expiry while the
vault's challenge is unchanged (it rotates on save).

## 8. Threat model

| Attacker | Capability | Result |
|---|---|---|
| Relay/chat/link host | read, drop, delay, replay envelopes | sees opaque bytes; replays rejected (§4); drops = DoS only |
| Malicious page host (post-app) | serves its own JS on the domain | cannot decrypt (fragment never sent; keys pinned at enrollment); origin pinning fails closed |
| Stolen Mac, locked vault | full disk + memory of a dead process | no factors; unlock requires the phone's approval |
| Compromised Mac (live) | anything | **out of scope** — the CLI holds decrypted vault data by design; approvals defend entry *access*, not a rooted host |
| Phone thief | the device and its biometrics | `biometryCurrentSet` invalidation + recovery sheet re-import (PLAN §9) |
| QR swap at enrollment | attacker's QR in place of the CLI's | confirmation-code mismatch — pairing aborts |
| Approval-fatigue flood | many requests | display rate limiting (§4); `request_id` dedupe |

Honest limitations: revocation of a stolen *phone's* approvals is cooperative
(the CLI forgets pins on `session_revoke`/re-pair, but the HMAC secret it
holds does not rotate without re-keying the vault — re-key guidance lives in
passlane#53); the link transport carries no proximity signal (shown on the
approval screen; BLE adds it in v1.1).

## 9. Test vectors

[`vectors/v1.json`](vectors/v1.json) — fixed keys, exact envelope bytes, and
expected bodies for: an unlock request with challenge, a response carrying
the HMAC secret, and a PSK pairing request with its confirmation code.
Regenerate with `cargo run --example gen-vectors`. Cross-implementation
tests (Swift, JS) open these exact envelopes — no shared code required.

## 10. Implementation notes

- `#![forbid(unsafe_code)]`; zeroize on keys, bodies, and HPKE secrets.
- `open()` order: version → freshness → sender pinning → signature →
  AEAD → body consistency → replay record (never before verification).
- Decode limits (header 4 KiB, enc 1 KiB, ct 1 MiB) cap hostile allocations.
- All randomness enters through caller-provided RNGs; no hidden global state.
- `rand` 0.8 at the API boundary (matches the CLI); p256 0.14 shares one
  version with the hpke-rs backend.
