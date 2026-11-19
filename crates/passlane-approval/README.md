# passlane-approval

Message format and crypto for the [passlane](https://github.com/anssip/passlane)
approval protocol — the shared implementation behind **phone-as-key** vault
unlocking and **agent approvals**.

Self-contained, end-to-end-encrypted, one-shot envelopes over untrusted
relays (QR/link now, BLE and CloudKit later). No keepass-ng dependency, no
I/O, no CLI concepts: the CLI, the session agent, and — via UniFFI — the iOS
app and the static approval page all speak this one wire format.

- **Spec**: [SPEC.md](SPEC.md) — wire format, pairing, freshness, threat
  model, and the HPKE-versus-Noise decision record.
- **Crypto**: RFC 9180 HPKE (`DHKEM(P-256)` + `HKDF-SHA256` +
  `AES-256-GCM`) via [hpke-rs](https://crates.io/crates/hpke-rs); ECDSA
  P-256 sender signatures (Secure-Enclave- and WebAuthn-compatible); HKDF
  PSK mode for pairing.
- **Vectors**: [`vectors/v1.json`](vectors/v1.json) — regenerate with
  `cargo run --example gen-vectors`; consumed by the Swift/JS ports.

```sh
cargo test                # unit + property + flow + vector tests
cargo run --example gen-vectors
```

Tracking: [passlane#49](https://github.com/anssip/passlane/issues/49).
License: GPL-3.0-or-later.
