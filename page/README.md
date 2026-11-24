# The passlane approval page (Phase 0)

The static approver for the passlane [approval protocol] before the iOS
app exists (passlane#51; protocol SPEC §6, "Phase 0 bootstrap"). Two keys
live on this page because a WebAuthn passkey can *sign* but cannot
*decrypt* — its private key never leaves the authenticator, so it cannot
do the ECDH that HPKE needs:

- an **encryption key** — a WebCrypto ECDH P-256 key pair, generated with
  `extractable: false` and stored in IndexedDB (non-extractable keys
  survive reloads and cannot be read out by script);
- a **signing identity** — a WebAuthn passkey on this page's domain (the
  hardware-backed, human-present factor);
- per vault, a **phone-held key** (passlane#53) — a non-extractable
  HMAC-SHA1 key, created when the computer runs `passlane hwkey add
  --phone`. Unlock and save requests for that vault are answered with the
  20-byte HMAC of the challenge they carry; the raw secret exists only
  once, printed on the recovery sheet the enrollment shows, and the
  request is not answered until that secret has been typed back from a
  copy of the sheet.

Enrollment binds the two, and binds them to *your* terminal: the passkey
signs `SHA-256(enrollment_nonce ‖ ECDH_public_key ‖ both CLI keys)` via a
follow-up `credentials.get()` assertion (the CLI recomputes the challenge
from its own identity — a swapped enrollment link fails there), and both
devices then display a twelve-digit **confirmation code** derived from
both parties' keys (SPEC §5's human check); the CLI pins the keys only
after you confirm the codes match, so a substituted link or a raced-in
blob cannot become your approver. From then on approval
requests arrive HPKE-sealed to the ECDH key, and every answer leaves
signed by the passkey (signature kind 2: the assertion covers the exact
envelope bytes, SPEC §3).

The page has **no build step and no dependencies**: plain ES modules,
WebCrypto, WebAuthn, IndexedDB. `lib.js`, `cbor.js`, `hpke.js` and
`envelope.js` are the wasm-free protocol layer; the node test harness
runs the exact same files.

## Pages

| Path                | Purpose                                                            |
| ------------------- | ------------------------------------------------------------------ |
| `/enroll.html#…`    | One-time enrollment (`passlane approvals enroll` prints the link). Fragment: `n=<nonce hex>&c=<CLI encryption public key hex>&s=<CLI verifying public key hex>`. |
| `/approve.html#…`   | An approval request envelope (base64url in the fragment). Show, verify the CLI's signature, decide, paste the reply back into the terminal. Unlock/save/enrollment requests are answered with the vault's phone-held key; enrollment shows the recovery sheet first. Each produced response is labeled with the request it answers (purpose + short request id) and visibly expires when that request lapses — a stale blob is refused by the CLI, so the page stops offering it as current. |
| `/test.html`        | In-browser self-test of the protocol layer against pinned vectors. |
| `/`                 | Landing page for people who paste the domain.                      |

The links the CLI emits point at the `.html` endpoints, so the site works
on **any** plain static file server with zero routing configuration. A
real deployment can add a `/approve` → `/approve.html` rewrite later; the
bytes are the same.

The envelope always rides the URL **fragment**, which browsers never send
to the host. The domain later serves the app's
`apple-app-site-association` (see `.well-known/`, placeholder app ID
until the app ships) so universal links route to the app instead — the
same envelopes, a different carrier.

## Getting the blob back to the terminal

Both ceremonies end with text that must reach the waiting computer, and
on iOS Safari a bare `navigator.clipboard.writeText` is not enough: it
can reject, and even a successful write syncs to Universal Clipboard
unreliably. The handoff (passlane#76) therefore always shows what
happened: Copy tries the async Clipboard API and falls back to a
selection `execCommand("copy")` inside the click gesture; the textarea
is selected on reveal, so the native long-press → Copy path — the one
that reliably triggers Universal Clipboard — is one gesture away; and a
Share button offers the platform share sheet, which on iOS includes
AirDrop (a web page cannot invoke AirDrop directly; the sheet is the
supported route). One implementation in `js/lib.js` serves both pages.

## Deploying

Any static host serving this directory over HTTPS on a real domain
(WebAuthn needs a secure context and a registrable RP id). For local
development `python3 -m http.server` in this directory works (browsers
treat `localhost` as a secure context; some allow it as an RP id too).

There is exactly one deployment choice you should not make lightly: the
domain is pinned into every enrollment (`webauthn.rp_id` /
`webauthn.origin` in the CLI's `approval_peers.json`). Moving the page to
a new domain later means re-enrolling (`passlane approvals enroll`
again). The default the CLI assumes is `https://approve.passlane.app`,
overridable per enrollment with `--page` or `$PASSLANE_APPROVAL_PAGE`.

## Testing

```
cd page && node tests/run.mjs                  # protocol suite vs the crate's vectors
cd page && node tests/run.mjs --write-fixture  # regenerate the Rust-verified fixture
```

`tests/run.mjs` opens the envelopes in
`../crates/passlane-approval/vectors/v1.json` with node's WebCrypto — the
same primitives the browser uses — proving the DHKEM composition in
`hpke.js` matches the Rust reference byte for byte. With
`--write-fixture` it seals a WebAuthn-signed approval response (an ECDSA
WebCrypto key stands in for the passkey, exactly like the Rust tests'
mock) into `tests/fixtures/page-response-v1.json`, and drives the real
`runEnrollment` ceremony into `tests/fixtures/page-enrollment-v1.json`;
the CLI's Rust tests then open the response envelope and verify the
enrollment blob with passlane-approval — the JS↔Rust legs of the
end-to-end proof. `test.html` runs the same suite inside a browser
(the ceremony test included, via deterministic seams).

What only a real device can cover: the passkey prompts themselves. The
mocked-assertion paths are identical to the real ones up to
`navigator.credentials.*`.

## Honest limitations

- Approvals over a chat-relayed link carry no proximity signal; the page
  says so on every approval screen (BLE adds it in protocol v1.1).
- The recovery sheet is text (`passlane hwkey remove --secret` reads it
  back the same way). No QR: iOS Safari has no `BarcodeDetector`, so
  nothing on the phone could scan one, and the page does not vendor a
  decoder. When the iOS app lands, its sheet gets the QR.
- On browsers without WebCrypto HMAC-SHA1 (none known), phone-held keys
  cannot be held here; the approval card says so.

[approval protocol]: ../crates/passlane-approval/SPEC.md
