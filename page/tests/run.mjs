#!/usr/bin/env node
// The page's test runner: executes js/tests.js (the wasm-free protocol
// layer — codecs, CBOR, DHKEM/HPKE composition, envelope framing) against
// the crate's committed vectors, node's WebCrypto standing in for the
// browser's. With --write-fixture it also seals a WebAuthn-signed approval
// response (a WebCrypto ECDSA key standing in for the passkey) and writes
// tests/fixtures/page-response-v1.json, which the CLI's Rust integration
// test opens and verifies with passlane-approval — the JS↔Rust leg of the
// end-to-end proof.
//
// Usage:
//   node tests/run.mjs                 # run the suite
//   node tests/run.mjs --write-fixture # also regenerate the Rust fixture

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const page = dirname(here);
const root = dirname(page);

const vectors = JSON.parse(
  readFileSync(join(root, "crates", "passlane-approval", "vectors", "v1.json"), "utf8"),
);

const { runTests, setVectors, mockedApprovalResponse } = await import(
  join(page, "js", "tests.js")
);
setVectors(vectors);
const { passed, failed, results } = await runTests();

for (const r of results) {
  if (r.ok) console.log(`ok   ${r.name}`);
  else console.log(`FAIL ${r.name}\n     ${r.error}`);
}
console.log(`\n${passed} passed, ${failed} failed`);

if (process.argv.includes("--write-fixture")) {
  const request = vectors.cases.find((c) => c.name === "approval_request_unlock");
  const response = vectors.cases.find((c) => c.name === "approval_response_with_secret");
  const cliKeys = request.sender; // the CLI ("macbook-pro") keys
  const pageKeys = response.sender; // the approver ("anssi-iphone") keys
  const cliPublic = request.sender_pin.enc_pub;
  const pagePublic = response.sender_pin.enc_pub;
  const rid = "d13451de7160efa2b23076fd782de967"; // the unlock request's rid (case 1)
  const now = 1_760_000_050;

  const out = await mockedApprovalResponse({
    pagePrivateScalarHex: pageKeys.enc_secret,
    pagePublicSec1: hexToBytes(pagePublic),
    cliPublicSec1: hexToBytes(cliPublic),
    rid,
    decision: "Allow",
    origin: "https://approve.passlane.test",
    rpId: "approve.passlane.test",
    now,
    nonceHex: "ea9f11f8dfb0ca08a8810f9ea39c3a6a",
  });

  const fixture = {
    note: "Produced by page/tests/run.mjs --write-fixture (page/js logic, node WebCrypto). The Rust test opens this envelope with passlane-approval: the JS page side and the Rust CLI side speak the same protocol.",
    version: 1,
    now,
    rid,
    envelope_base64url: out.envelopeBase64Url,
    recipient: cliKeys,
    sender_pin: {
      label: "approval-page",
      enc_pub: pagePublic,
      sig_pub: out.passkeyPublicSec1Hex,
      paired_at: now,
      webauthn: { rp_id: "approve.passlane.test", origin: "https://approve.passlane.test" },
    },
    expected_body: out.body,
  };
  const fixtureDir = join(here, "fixtures");
  mkdirSync(fixtureDir, { recursive: true });
  const fixturePath = join(fixtureDir, "page-response-v1.json");
  writeFileSync(fixturePath, JSON.stringify(fixture, null, 2) + "\n");
  console.log(`fixture written: ${fixturePath}`);
}

process.exit(failed ? 1 : 0);

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  }
  return out;
}
