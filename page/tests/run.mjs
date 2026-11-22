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

// DOM-level wiring tests (node-only; see tests/dom.mjs).
const dom = await import(join(here, "dom.mjs"));
const domOut = await dom.runDomTests();
for (const r of domOut.results) {
  if (r.ok) console.log(`ok   ${r.name}`);
  else console.log(`FAIL ${r.name}\n     ${r.error}`);
}

for (const r of results) {
  if (r.ok) console.log(`ok   ${r.name}`);
  else console.log(`FAIL ${r.name}\n     ${r.error}`);
}
console.log(`\n${passed + domOut.passed} passed, ${failed + domOut.failed} failed`);

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

  // The enrollment fixture: run the page's real ceremony (runEnrollment,
  // deterministic seams) against the vector CLI keys, so the Rust
  // verifier proves the page's binding challenge byte-for-byte.
  const { runEnrollment } = await import(join(page, "js", "enroll.js"));
  const { sha256, toBase64Url, utf8, ecdsaRawToDer, toHex } = await import(
    join(page, "js", "lib.js")
  );
  const enrollmentNonce = hexToBytes("0a0b0c0d0e0f00112223334445556667");
  const rpId = "approve.passlane.test";
  const pagePair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  );
  const pageEcdhPub = new Uint8Array(await crypto.subtle.exportKey("raw", pagePair.publicKey));
  const passkey = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const passkeyPub = new Uint8Array(await crypto.subtle.exportKey("raw", passkey.publicKey));
  const credentialId = new Uint8Array(8).fill(0xc0);
  const coseKey = concatU8(
    new Uint8Array([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]),
    passkeyPub.subarray(1, 33),
    new Uint8Array([0x22, 0x58, 0x20]),
    passkeyPub.subarray(33, 65),
  );
  const authData = concatU8(
    await sha256(utf8(rpId)),
    new Uint8Array([0x41, 0, 0, 0, 0]),
    new Uint8Array(16),
    new Uint8Array([0, credentialId.length]),
    credentialId,
    coseKey,
  );
  const text = (s) => {
    const b = utf8(s);
    return concatU8(new Uint8Array([0x60 | b.length]), b);
  };
  const attestationObject = concatU8(
    new Uint8Array([0xa3]),
    text("fmt"), text("none"),
    text("attStmt"), new Uint8Array([0xa0]),
    text("authData"),
    new Uint8Array([0x58, authData.length]),
    authData,
  );
  const { blob } = await runEnrollment(
    {
      nonce: enrollmentNonce,
      cliPublicSec1: hexToBytes(cliPublic),
      cliSigPubSec1: hexToBytes(request.sender_pin.sig_pub),
    },
    {
      noStore: true,
      generateKey: () => ({ privateNonExportable: pagePair.privateKey, publicSec1: pageEcdhPub }),
      createCredential: async () => ({
        response: { attestationObject: attestationObject.buffer.slice(0) },
      }),
      assert: async (_id, challengeBytes) => {
        const challenge = toBase64Url(new Uint8Array(challengeBytes));
        const clientDataJson = JSON.stringify({
          type: "webauthn.get",
          challenge,
          origin: `https://${rpId}`,
        });
        const raw = new Uint8Array(
          await crypto.subtle.sign(
            { name: "ECDSA", hash: "SHA-256" },
            passkey.privateKey,
            concatU8(authData, await sha256(utf8(clientDataJson))),
          ),
        );
        return {
          authenticatorData: authData.buffer.slice(0),
          clientDataJSON: utf8(clientDataJson).buffer.slice(0),
          signature: ecdsaRawToDer(raw).buffer.slice(0),
        };
      },
    },
  );
  const enrollFixture = {
    note: "A page-produced enrollment blob (run.mjs --write-fixture driving page/js/enroll.js with node WebCrypto). The Rust test verifies it with the CLI's real ceremony verifier — the JS page side and the Rust CLI side derive the identical binding challenge.",
    version: 1,
    nonce_hex: "0a0b0c0d0e0f00112223334445556667",
    cli: cliKeys,
    origin: { rp_id: rpId, origin: `https://${rpId}` },
    blob,
    expected: { enc_pub: blob.enc_pub },
  };
  const enrollPath = join(fixtureDir, "page-enrollment-v1.json");
  writeFileSync(enrollPath, JSON.stringify(enrollFixture, null, 2) + "\n");
  console.log(`fixture written: ${enrollPath}`);
}

function concatU8(...parts) {
  const len = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(len);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

process.exit(failed ? 1 : 0);

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  }
  return out;
}
