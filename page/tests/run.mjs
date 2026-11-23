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
  // The phone-held-key fixture: the page's real phonekey.js answers a
  // challenge with HMAC-SHA1 under a fixed secret, and the Rust test
  // verifies the envelope AND recomputes the answer itself — the JS↔Rust
  // leg of the phone-key proof.
  {
    const hpkeMod = await import(join(page, "js", "hpke.js"));
    const { importSecret, computeResponse } = await import(join(page, "js", "phonekey.js"));
    const { buildApprovalResponse, attachAssertion, assertionToJson } = await import(
      join(page, "js", "envelope.js")
    );
    const secretHex = "3c".repeat(20);
    const challengeHex = "2a".repeat(32);
    const bytesOf = (hex) => new Uint8Array(hex.match(/.{2}/g).map((b) => parseInt(b, 16)));
    const key = await importSecret(bytesOf(secretHex));
    const answer = await computeResponse(key, bytesOf(challengeHex));

    const rid = "d13451de7160efa2b23076fd782de967";
    const now2 = 1_760_000_050;
    const built = await buildApprovalResponse({
      rid,
      senderKid: await hpkeMod.kid("enc", bytesOf(pagePublic)),
      recipientKid: await hpkeMod.kid("enc", bytesOf(cliPublic)),
      decision: "Allow",
      scope: { kind: "once" },
      response: toHex(answer),
      recipientPublicSec1: bytesOf(cliPublic),
      seal: hpkeMod.hpkeSeal,
      now: now2,
      ttl: 300,
      nonceHex: "ea9f11f8dfb0ca08a8810f9ea39c3a6a",
    });

    // The passkey (an ECDSA WebCrypto key stands in for the authenticator,
    // exactly like the other fixtures) signs the transcript challenge.
    const rpHash = await sha256(utf8(rpId));
    const authData = concatU8(rpHash, new Uint8Array([0x01, 0, 0, 0, 0]));
    const clientDataJson = JSON.stringify({
      type: "webauthn.get",
      challenge: built.challenge,
      origin: `https://${rpId}`,
    });
    const raw = new Uint8Array(
      await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        passkey.privateKey,
        concatU8(authData, await sha256(utf8(clientDataJson))),
      ),
    );
    const finalBytes = attachAssertion(
      built.transcript,
      assertionToJson({
        authenticator_data: toBase64Url(authData),
        client_data_json: toBase64Url(utf8(clientDataJson)),
        signature: toBase64Url(ecdsaRawToDer(raw)),
      }),
    );

    const phoneFixture = {
      note: "Produced by page/tests/run.mjs --write-fixture driving page/js/phonekey.js and envelope.js with node WebCrypto. The Rust test opens the envelope with passlane-approval and recomputes HMAC-SHA1(secret, challenge) itself.",
      version: 1,
      now: now2,
      rid,
      secret_hex: secretHex,
      challenge_hex: challengeHex,
      envelope_base64url: toBase64Url(finalBytes),
      recipient: cliKeys,
      sender_pin: {
        label: "approval-page",
        enc_pub: pagePublic,
        sig_pub: toHex(passkeyPub),
        paired_at: now2,
        webauthn: { rp_id: rpId, origin: `https://${rpId}` },
      },
    };
    const phonePath = join(fixtureDir, "page-phone-key-v1.json");
    writeFileSync(phonePath, JSON.stringify(phoneFixture, null, 2) + "\n");
    console.log(`fixture written: ${phonePath}`);
  }

  const enrollPath = join(fixtureDir, "page-enrollment-v1.json");
  writeFileSync(enrollPath, JSON.stringify(enrollFixture, null, 2) + "\n");
  console.log(`fixture written: ${enrollPath}`);
}

// Pure phone-key lifecycle tests (the staged-key rules and the
// deny-carries-no-answer rule): the wiring-level flows they drive are
// exercised by the CLI's Rust integration tests against this page's
// protocol output.
{
  const pk = await import(join(page, "js", "phonekey.js"));
  const pure = [];
  const pureTest = (name, fn) => {
    try {
      fn();
      pure.push({ ok: true, name });
    } catch (e) {
      pure.push({ ok: false, name, error: String(e && e.message ? e.message : e) });
    }
  };
  const assertEq = (a, b, msg) => {
    if (a !== b) throw new Error(`${msg ?? "values differ"}: ${JSON.stringify(a)} !== ${JSON.stringify(b)}`);
  };
  const assert = (cond, msg) => {
    if (!cond) throw new Error(msg ?? "assertion failed");
  };

  const VAULT = "3f7a2c9180e64b25a1d0f3c87592e641";
  const held = pk.newKeyRecord(VAULT, "work", "held-key");
  const staged = pk.newKeyRecord(VAULT, "work", "staged-key");  // must run after held for distinct ids
  if (held.id === staged.id) throw new Error("key records carry distinct generation ids");
  const save = { vault_id: VAULT, operation: { kind: "save" } };
  const unlock = { vault_id: VAULT, operation: { kind: "unlock" } };

  pureTest("staging leaves the held key untouched until promotion", () => {
    const record = { rkid: "k1", keys: { [VAULT]: held } };
    const next = pk.stageKey(record, VAULT, staged);
    assertEq(pk.heldKeyOf(next, VAULT), held, "the held key is unchanged");
    assertEq(pk.stagedKey(next, VAULT), staged, "the staged key sits beside it");
    assertEq(pk.heldKeyOf(record, VAULT), held, "pure: the input record is untouched");
    assert(!pk.stagedKey(record, VAULT), "pure: nothing staged in the input");
  });

  pureTest("the enrollment's save answers with the staged key and promotes it", () => {
    const record = pk.stageKey({ rkid: "k1", keys: { [VAULT]: held } }, VAULT, staged);
    const which = pk.keyDecision(record, save);
    assertEq(which.key, staged, "the staged key answers the save");
    assertEq(which.promote, true, "and is promoted by it");
    const next = pk.promoteStagedKey(record, VAULT, staged.id);
    assertEq(pk.heldKeyOf(next, VAULT), staged, "the staged key is now held");
    assert(!pk.stagedKey(next, VAULT), "nothing stays staged");
  });

  pureTest("promote and drop bind to the generation they were decided about", () => {
    const record = pk.stageKey({ rkid: "k1", keys: { [VAULT]: held } }, VAULT, staged);
    // Another tab replaced the staged key before the decision persisted.
    const newer = pk.newKeyRecord(VAULT, "work", "newer-key");
    const replaced = pk.stageKey(record, VAULT, newer);
    const promoted = pk.promoteStagedKey(replaced, VAULT, staged.id);
    assertEq(pk.heldKeyOf(promoted, VAULT), held, "an older decision promotes nothing");
    assertEq(pk.stagedKey(promoted, VAULT), newer, "the newer generation stays staged");
    const dropped = pk.dropStagedKey(replaced, VAULT, staged.id);
    assertEq(pk.stagedKey(dropped, VAULT), newer, "an older decision drops nothing");
    // The generation's own decision still applies.
    const ok = pk.dropStagedKey(replaced, VAULT, newer.id);
    assert(!pk.stagedKey(ok, VAULT), "the matching generation is dropped");
  });

  pureTest("an unlock answers with the held key and drops a staged one", () => {
    const record = pk.stageKey({ rkid: "k1", keys: { [VAULT]: held } }, VAULT, staged);
    const which = pk.keyDecision(record, unlock);
    assertEq(which.key, held, "the held key answers the unlock");
    assertEq(which.dropStaged, true, "the staged one is dead: the vault opened with the old key");
    const next = pk.dropStagedKey(record, VAULT, staged.id);
    assertEq(pk.heldKeyOf(next, VAULT), held, "the held key survives");
    assert(!pk.stagedKey(next, VAULT), "the staged key is gone");
  });

  pureTest("a save without a staged key is the held key's, unpromoted", () => {
    const record = { rkid: "k1", keys: { [VAULT]: held } };
    const which = pk.keyDecision(record, save);
    assertEq(which.key, held, "the held key answers");
    assertEq(which.promote, false, "nothing to promote");
  });

  pureTest("a vault with only a staged key has nothing to answer an unlock with", () => {
    const record = pk.stageKey({ rkid: "k1" }, VAULT, staged);
    assertEq(pk.keyDecision(record, unlock), null, "an unlock is not the staged key's to answer");
  });

  pureTest("the gate lets a staged key finish a first enrollment's save", () => {
    // No held key yet: the enrollment created and staged one. Its save
    // must be approvable — through the same rules the answer uses.
    const record = pk.stageKey({ rkid: "k1" }, VAULT, staged);
    const which = pk.keyDecision(record, save);
    assertEq(which.key, staged, "the save is the staged key's to answer");
    assertEq(which.promote, true, "and it is its promotion");
  });

  pureTest("a deny never carries an answer, however it was computed", () => {
    assertEq(pk.answerForDecision("deny", "abcd1234"), null, "a deny strips the answer");
    assertEq(pk.answerForDecision("allow", "abcd1234"), "abcd1234", "an allow carries it");
    assertEq(pk.answerForDecision("allow", null), null, "an allow without an answer carries none");
  });

  let purePassed = 0;
  let pureFailed = 0;
  for (const r of pure) {
    if (r.ok) {
      purePassed++;
      console.log(`ok   ${r.name}`);
    } else {
      pureFailed++;
      console.log(`FAIL ${r.name}\n     ${r.error}`);
    }
  }
  domOut.passed += purePassed;
  domOut.failed += pureFailed;
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

// Both suites contribute to the exit code: a failing DOM test must fail
// the run even when the protocol suite is green.
process.exit(failed + domOut.failed > 0 ? 1 : 0);

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  }
  return out;
}
