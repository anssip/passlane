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
  hardware-backed, human-present factor).

Enrollment binds the two: the passkey signs `SHA-256(enrollment_nonce ‖
ECDH_public_key)` via a follow-up `credentials.get()` assertion, and the
CLI verifies that signature (origin, RP-id hash, user-present flag,
credential-key signature) before pinning both keys. From then on approval
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
| `/approve.html#…`   | An approval request envelope (base64url in the fragment). Show, verify the CLI's signature, decide, paste the reply back into the terminal. |
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
mock) into `tests/fixtures/page-response-v1.json`; the CLI's Rust
integration test (`tests/link_transport.rs` in the repo root) then opens
and fully verifies that fixture with `passlane-approval` — the JS↔Rust
leg of the end-to-end proof. `test.html` runs the same suite inside a
browser.

What only a real device can cover: the passkey prompts themselves. The
mocked-assertion paths are identical to the real ones up to
`navigator.credentials.*`.

## Honest limitations

- The ECDH key is generated extractable and immediately re-imported as
  non-extractable (WebCrypto cannot export a public key from a
  non-extractable pair); a transient copy of the JWK exists in JS memory
  until garbage collection. The *stored* key can never be exported; the
  page never persists the extractable form. The iOS app removes this
  caveat (Secure Enclave keys).
- Approvals over a chat-relayed link carry no proximity signal; the page
  says so on every approval screen (BLE adds it in protocol v1.1).
- Unlock requests (`Operation::Unlock`) need the HMAC-SHA1 answer the
  phone-held-key app holds (passlane#53); this page can record consent
  but cannot compute the answer.

[approval protocol]: ../crates/passlane-approval/SPEC.md
