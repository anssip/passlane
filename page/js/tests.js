// The page's test suite — pure logic, no DOM, runnable in node
// (tests/run.mjs) and in the browser (test.html). It proves the wasm-free
// protocol layer composes DHKEM exactly as SPEC §3 specifies by opening
// the crate's committed cross-implementation vectors
// (crates/passlane-approval/vectors/v1.json), and by sealing envelopes
// the Rust side opens (tests/fixtures/, verified by the CLI's Rust tests).

import * as cbor from "./cbor.js";
import * as hpke from "./hpke.js";
import * as envelope from "./envelope.js";
import {
  concat,
  ecdsaDerToRaw,
  ecdsaRawToDer,
  fromBase64Url,
  fromHex,
  sha256,
  toBase64Url,
  toHex,
  utf8,
} from "./lib.js";
import {
  computeResponse,
  describeOperation,
  formatSecret,
  generateSecret,
  importSecret,
  isPhoneKeyOperation,
  newKeyRecord,
  parseSheetSecret,
  sheetInstructions,
  sheetText,
  verifySheetReadBack,
} from "./phonekey.js";

const CASES = new Map();
let passed = 0;
let failed = 0;

function test(name, fn) {
  CASES.set(name, fn);
}

export function suite() {
  return [...CASES.keys()];
}

export async function runTests() {
  const results = [];
  for (const [name, fn] of CASES) {
    try {
      await fn();
      passed++;
      results.push({ name, ok: true });
    } catch (e) {
      failed++;
      results.push({ name, ok: false, error: e.message });
    }
  }
  return { passed, failed, results };
}

function eq(actual, expected, what) {
  const a = show(actual);
  const b = show(expected);
  if (a !== b) throw new Error(`${what}: expected ${b}, got ${a}`);
}

/** Stable, key-order-insensitive serialization for deep comparisons. */
function show(value) {
  if (value instanceof Uint8Array) return `0x${toHex(value)}`;
  if (Array.isArray(value)) return `[${value.map(show).join(",")}]`;
  if (value && typeof value === "object") {
    const keys = Object.keys(value).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${show(value[k])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

// -- codecs ------------------------------------------------------------------

test("base64url: RFC 4648 §5 vectors (unpadded)", () => {
  eq(toBase64Url(new Uint8Array(0)), "", "empty");
  eq(toBase64Url(utf8("f")), "Zg", "f");
  eq(toBase64Url(utf8("fo")), "Zm8", "fo");
  eq(toBase64Url(utf8("foo")), "Zm9v", "foo");
  eq(toBase64Url(utf8("foob")), "Zm9vYg", "foob");
  eq(toBase64Url(utf8("fooba")), "Zm9vYmE", "fooba");
  eq(toBase64Url(utf8("foobar")), "Zm9vYmFy", "foobar");
  for (const [plain, enc] of [
    ["f", "Zg"],
    ["foobar", "Zm9vYmFy"],
  ]) {
    eq(fromBase64Url(enc), utf8(plain), `decode ${enc}`);
  }
});

test("base64url: rejects padding and standard alphabet", () => {
  let threw = 0;
  for (const bad of ["Zg==", "Zg=", "Zm9v+", "A"]) {
    try {
      fromBase64Url(bad);
    } catch {
      threw++;
    }
  }
  if (threw !== 4) throw new Error("invalid input must be rejected");
});

test("hex: roundtrip and rejection", () => {
  for (const n of [0, 1, 20, 32, 65]) {
    const bytes = new Uint8Array(n).map((_, i) => i * 37);
    eq(toHex(bytes).length, 2 * n, `length ${n}`);
    eq(fromHex(toHex(bytes)), bytes, `roundtrip ${n}`);
  }
  let threw = 0;
  for (const bad of ["AB", "0", "0g"]) {
    try {
      fromHex(bad);
    } catch {
      threw++;
    }
  }
  if (threw !== 3) throw new Error("invalid hex must be rejected");
});

test("ecdsaRawToDer: canonical DER with sign padding", () => {
  const raw = new Uint8Array(64);
  raw[0] = 0xff; // forces the 0x00 INTEGER pad on r
  raw.fill(0x7f, 32);
  const der = ecdsaRawToDer(raw);
  // 30 45 02 21 00 ff..(32) 02 1f 7f..(31)  — leading 0x7f stays, so 0x00
  // pad only applies where the high bit is set. 0x7f*32 has no leading
  // zero bytes, so s is 02 20 7f*32.
  const expected = concat(
    new Uint8Array([0x30, 0x45, 0x02, 0x21, 0x00]),
    raw.subarray(0, 32),
    new Uint8Array([0x02, 0x20]),
    raw.subarray(32),
  );
  eq(der, expected, "DER structure");
});

test("ecdsaDerToRaw inverts ecdsaRawToDer", () => {
  // Round-trip both padded and short-integer shapes; WebCrypto verify
  // needs the raw form the inverse produces.
  const cases = [
    [0xff, 0x7f], // padded r, plain s
    [0x01, 0xff], // plain r, padded s
    [0x80, 0x80], // both padded
  ];
  for (const [rHead, sHead] of cases) {
    const raw = new Uint8Array(64);
    raw[0] = rHead;
    raw.fill(rHead, 1, 32);
    raw[32] = sHead;
    raw.fill(sHead, 33, 64);
    eq(ecdsaDerToRaw(ecdsaRawToDer(raw)), raw, `roundtrip r=${rHead} s=${sHead}`);
  }
  // Garbage is rejected, not coerced.
  let threw = 0;
  for (const bad of [new Uint8Array(0), new Uint8Array([0x30, 0x02, 0x02, 0x01])]) {
    try {
      ecdsaDerToRaw(bad);
    } catch {
      threw++;
    }
  }
  if (threw !== 2) throw new Error("malformed DER must be rejected");
});

// -- CBOR --------------------------------------------------------------------

test("cbor: decodes a COSE ES256 key", () => {
  // {1:2, 3:-7, -1:1, -2: x32, -3: y32}
  const bytes = concat(
    new Uint8Array([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]),
    new Uint8Array(32).fill(0x11),
    new Uint8Array([0x22, 0x58, 0x20]),
    new Uint8Array(32).fill(0x22),
  );
  const [map, consumed] = cbor.decode(bytes);
  eq(consumed, bytes.length, "consumed all");
  eq(map.get(1), 2, "kty");
  eq(map.get(3), -7, "alg");
  eq(map.get(-1), 1, "crv");
  eq(map.get(-2), new Uint8Array(32).fill(0x11), "x");
  eq(map.get(-3), new Uint8Array(32).fill(0x22), "y");
});

test("cbor: authenticator data parsing (fixed offsets)", () => {
  const rpIdHash = fromHex(
    "6f9f90a1eec3636b05ce104cf6c8a0a99a83b17c55e2b6c2cc9b3d3c7cd67c26",
  ); // arbitrary fixed bytes; parsing does not check the hash
  const authData = concat(rpIdHash, new Uint8Array([0x01, 0, 0, 0, 0])); // UP only
  const parsed = cbor.parseAuthenticatorData(authData);
  eq(parsed.rpIdHash, rpIdHash, "rp id hash");
  if (parsed.attestedCredentialData !== null) throw new Error("no AT flag, no ACD");
  if (!cbor.userPresent(authData)) throw new Error("UP flag");

  // Truncated attested credential data fails with a clear error.
  let threw = null;
  try {
    cbor.parseAuthenticatorData(concat(rpIdHash, new Uint8Array([0x41, 0, 0, 0, 0])));
  } catch (e) {
    threw = e.message;
  }
  if (!threw?.includes("attested credential data")) throw new Error(`expected clear error, got ${threw}`);
});

test("cbor: rejects truncated input instead of clamping", () => {
  // [0x42, 0x11]: a byte string claiming 17 bytes with one present — JS
  // slice() would clamp to a short string; decoding must refuse.
  let threw = null;
  try {
    cbor.decode(new Uint8Array([0x42, 0x11]));
  } catch (e) {
    threw = e.message;
  }
  if (!threw?.includes("truncated")) throw new Error(`byte string: ${threw}`);

  // [0xa1, 0x01]: map(1) with a key but no value — the value read is out
  // of bounds and must error, not fabricate.
  threw = null;
  try {
    cbor.decode(new Uint8Array([0xa1, 0x01]));
  } catch (e) {
    threw = e.message;
  }
  if (threw === null) throw new Error("map without value must fail");

  // A truncated item header (8-byte length prefix cut short).
  threw = null;
  try {
    cbor.decode(new Uint8Array([0x1b, 0xff]));
  } catch (e) {
    threw = e.message;
  }
  if (!threw?.includes("truncated")) throw new Error(`header: ${threw}`);

  // An oversized declared container with no elements present
  // (array(5), nothing follows).
  threw = null;
  try {
    cbor.decode(new Uint8Array([0x99, 0x00, 0x05]));
  } catch (e) {
    threw = e.message;
  }
  if (threw === null) throw new Error("oversized array must fail");

  // Empty input.
  try {
    cbor.decode(new Uint8Array(0));
  } catch {
    /* expected */
  }

  // Deeply nested containers hit the depth limit instead of recursing
  // toward stack exhaustion.
  threw = null;
  try {
    const deep = new Uint8Array(100).fill(0x81); // array(1) x100
    cbor.decode(deep);
  } catch (e) {
    threw = e.message;
  }
  if (!threw?.includes("depth")) throw new Error(`deep nesting: ${threw}`);

  // The same limit must hold for the COSE key slot INSIDE authenticator
  // data (where credential public keys are parsed): a nested-bomb COSE
  // key must be rejected, not recursed into.
  threw = null;
  try {
    const rpIdHash = new Uint8Array(32).fill(0xaa);
    const bomb = new Uint8Array(100).fill(0x81); // array(1) x100
    const authData = concat(
      rpIdHash,
      new Uint8Array([0x41, 0, 0, 0, 0]), // UP | AT
      new Uint8Array(16), // aaguid
      new Uint8Array([0, 4]), // credential id length
      new Uint8Array(4), // credential id
      bomb,
    );
    cbor.parseAuthenticatorData(authData);
  } catch (e) {
    threw = e.message;
  }
  if (!threw?.includes("depth")) throw new Error(`nested COSE in authData: ${threw}`);
});

test("cbor: attested credential data and the COSE key slice", () => {
  const rpIdHash = new Uint8Array(32).fill(0xaa);
  const aaguid = new Uint8Array(16).fill(0xbb);
  const credentialId = new Uint8Array(8).fill(0xcc);
  const coseKey = concat(
    new Uint8Array([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]),
    new Uint8Array(32).fill(0x11),
    new Uint8Array([0x22, 0x58, 0x20]),
    new Uint8Array(32).fill(0x22),
  );
  const authData = concat(
    rpIdHash,
    new Uint8Array([0x41, 0, 0, 0, 0]), // UP|AT
    aaguid,
    new Uint8Array([0, credentialId.length]), // credential id length, BE
    credentialId,
    coseKey,
  );
  const parsed = cbor.parseAuthenticatorData(authData);
  const acd = parsed.attestedCredentialData;
  if (!acd) throw new Error("attested credential data expected");
  eq(acd.credentialId, credentialId, "credential id");
  eq(acd.credentialPublicKey, coseKey, "COSE key sliced verbatim");
});

// -- vectors: kid + envelope parse + HPKE open --------------------------------

/** The vectors document (injected by the runner). */
let vectors = null;
export function setVectors(doc) {
  vectors = doc;
}

function caseByName(name) {
  const c = vectors?.cases?.find((c) => c.name === name);
  if (!c) throw new Error(`vector case '${name}' missing`);
  return c;
}

test("vectors: key ids derive as the headers claim", async () => {
  const c = caseByName("approval_request_unlock");
  const pub = fromHex(c.sender_pin.enc_pub);
  eq(await hpke.kid("enc", pub), c.expected_header.skid, "skid");
});

test("vectors: envelope parses with exact header", () => {
  const c = caseByName("approval_request_unlock");
  const e = envelope.parseEnvelopeB64Url(c.envelope_base64url);
  eq(e.version, 1, "version");
  eq(e.msgType, 3, "type");
  eq(e.sigKind, 1, "sig kind");
  for (const [k, v] of Object.entries(c.expected_header)) {
    eq(e.header[k], v, `header.${k}`);
  }
  eq(e.enc.length, 65, "enc is the ephemeral public key");
});

/** Import a scalar (hex) as a non-extractable ECDH private key. */
async function importEcdhPrivate(hexScalar, publicSec1) {
  const d = fromHex(hexScalar);
  const jwk = {
    kty: "EC",
    crv: "P-256",
    x: toBase64Url(publicSec1.subarray(1, 33)),
    y: toBase64Url(publicSec1.subarray(33, 65)),
    d: toBase64Url(d),
  };
  return crypto.subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveBits",
  ]);
}

test("vectors: page opens the CLI's approval request (DHKEM over WebCrypto)", async () => {
  const c = caseByName("approval_request_unlock");
  const e = envelope.parseEnvelopeB64Url(c.envelope_base64url);
  // The recipient (the approver) has this public key: the sibling case's
  // sender pin describes the same party.
  const recipientPub = fromHex(caseByName("approval_response_with_secret").sender_pin.enc_pub);
  const priv = await importEcdhPrivate(c.recipient.enc_secret, recipientPub);
  const plaintext = await hpke.hpkeOpen(
    e.enc,
    priv,
    recipientPub,
    e.msgType,
    e.aad,
    e.ct,
  );
  const body = JSON.parse(new TextDecoder().decode(plaintext));
  eq(body, c.body, "decrypted body equals the vector body");
});

test("vectors: the page verifies the CLI's request signature", async () => {
  // HPKE base mode does not authenticate the sender; the page checks the
  // ECDSA signature over the transcript against the CLI verifying key
  // pinned at enrollment (sender_pin.sig_pub) before showing anything
  // actionable.
  const c = caseByName("approval_request_unlock");
  const e = envelope.parseEnvelopeB64Url(c.envelope_base64url);
  const verify = async (pubHex) => {
    const key = await crypto.subtle.importKey(
      "raw",
      fromHex(pubHex),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    return crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      ecdsaDerToRaw(e.sig),
      e.transcript,
    );
  };
  if (!(await verify(c.sender_pin.sig_pub))) throw new Error("genuine CLI signature must verify");
  // The approver's own key (or any other) must not verify it.
  const other = caseByName("approval_response_with_secret").sender_pin.sig_pub;
  if (await verify(other)) throw new Error("a foreign key must not verify the request");
});

test("vectors: CLI opens the approver's response the same way", async () => {
  const c = caseByName("approval_response_with_secret");
  const e = envelope.parseEnvelopeB64Url(c.envelope_base64url);
  const recipientPub = fromHex(caseByName("approval_request_unlock").sender_pin.enc_pub);
  const priv = await importEcdhPrivate(c.recipient.enc_secret, recipientPub);
  const plaintext = await hpke.hpkeOpen(
    e.enc,
    priv,
    recipientPub,
    e.msgType,
    e.aad,
    e.ct,
  );
  const body = JSON.parse(new TextDecoder().decode(plaintext));
  eq(body, c.body, "decrypted body equals the vector body");
});

test("seal→open roundtrip with fresh keys", async () => {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );
  const pub = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const message = utf8(JSON.stringify({ type: "approval_response", decision: "Allow" }));
  const [enc, ct] = await hpke.hpkeSeal(pub, 4, utf8("aad-test"), message);
  const priv = pair.privateKey;
  const opened = await hpke.hpkeOpen(enc, priv, pub, 4, utf8("aad-test"), ct);
  eq(opened, message, "roundtrip");
  // AAD binding: wrong AAD fails.
  let threw = false;
  try {
    await hpke.hpkeOpen(enc, priv, pub, 4, utf8("aad-other"), ct);
  } catch {
    threw = true;
  }
  if (!threw) throw new Error("wrong AAD must fail");
});

// -- the response builder (what the approve page produces) --------------------

test("response envelope: framing, challenge stability, rid echo", async () => {
  const cliPair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );
  const cliPub = new Uint8Array(await crypto.subtle.exportKey("raw", cliPair.publicKey));
  const pagePair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );
  const pagePub = new Uint8Array(await crypto.subtle.exportKey("raw", pagePair.publicKey));
  const rid = "d13451de7160efa2b23076fd782de967"; // vector request id

  const built = await envelope.buildApprovalResponse({
    rid,
    senderKid: await hpke.kid("enc", pagePub),
    recipientKid: await hpke.kid("enc", cliPub),
    decision: "Allow",
    scope: { kind: "once" },
    recipientPublicSec1: cliPub,
    seal: hpke.hpkeSeal,
    now: 1_760_000_000,
    ttl: 300,
    nonceHex: "ea9f11f8dfb0ca08a8810f9ea39c3a6a",
  });

  // Placeholder framing parses, and the challenge is the transcript hash.
  const parsed = envelope.parseEnvelope(built.framedBytes);
  eq(parsed.header.rid, rid, "rid echo");
  eq(parsed.msgType, 4, "type");
  eq(parsed.sigKind, 2, "sig kind 2");
  eq(parsed.sig, utf8(JSON.stringify(envelope.emptyAssertion())), "placeholder sig");
  eq(built.challenge, await envelope.webauthnChallenge(parsed), "challenge stability");

  // Attach an assertion: the framing stays valid, transcript unchanged.
  const final = envelope.attachAssertion(
    built.transcript,
    envelope.assertionToJson({
      authenticator_data: "YXV0aERhdGE",
      client_data_json: "Y2xpZW50RGF0YQ",
      signature: "c2ln",
    }),
  );
  const finalParsed = envelope.parseEnvelope(final);
  eq(finalParsed.transcript, parsed.transcript, "transcript unchanged by the assertion");
  eq(finalParsed.header, parsed.header, "header unchanged");

  // The CLI (holder of cliPair) can decrypt the body.
  const body = JSON.parse(
    new TextDecoder().decode(
      await hpke.hpkeOpen(
        finalParsed.enc,
        cliPair.privateKey,
        cliPub,
        4,
        finalParsed.aad,
        finalParsed.ct,
      ),
    ),
  );
  eq(body, { type: "approval_response", decision: "Allow", scope: { kind: "once" } }, "body");
});

// -- the full mocked approval (page side), also used for the fixture ----------

/**
 * Run the page side of an approval with a WebCrypto ECDSA key standing in
 * for the passkey (exactly the mock the Rust tests use). Produces the
 * final response envelope. `keys` carries the deterministic vector keys:
 * {cliPublicSec1, cliPrivateJwk? not needed — the CLI opens}.
 */
export async function mockedApprovalResponse({
  pagePrivateScalarHex,
  pagePublicSec1,
  cliPublicSec1,
  rid,
  decision,
  origin,
  rpId,
  now,
  nonceHex,
  passkeyJwk, // optional: reuse an enrolled "passkey" instead of a fresh one
}) {
  const priv = await importEcdhPrivate(pagePrivateScalarHex, pagePublicSec1);
  const built = await envelope.buildApprovalResponse({
    rid,
    senderKid: await hpke.kid("enc", pagePublicSec1),
    recipientKid: await hpke.kid("enc", cliPublicSec1),
    decision,
    scope: { kind: "once" },
    recipientPublicSec1: cliPublicSec1,
    seal: hpke.hpkeSeal,
    now,
    ttl: 300,
    nonceHex,
  });

  // The passkey stand-in signs authenticator_data || SHA-256(client_data).
  const passkey = passkeyJwk
    ? await crypto.subtle.importKey(
        "jwk",
        passkeyJwk,
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["sign"],
      )
    : await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
        "sign",
        "verify",
      ]);
  const passkeyPub = passkeyJwk
    ? concat(
        new Uint8Array([0x04]),
        fromBase64Url(passkeyJwk.x),
        fromBase64Url(passkeyJwk.y),
      )
    : new Uint8Array(await crypto.subtle.exportKey("raw", passkey.publicKey));
  const passkeyPrivate = passkeyJwk ? passkey : passkey.privateKey;
  const rpHash = await sha256(utf8(rpId));
  const authData = concat(rpHash, new Uint8Array([0x01, 0, 0, 0, 0])); // UP
  const clientDataJson = JSON.stringify({
    type: "webauthn.get",
    challenge: built.challenge,
    origin,
  });
  const signatureRaw = new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      passkeyPrivate,
      concat(authData, await sha256(utf8(clientDataJson))),
    ),
  );
  const finalBytes = envelope.attachAssertion(
    built.transcript,
    envelope.assertionToJson({
      authenticator_data: toBase64Url(authData),
      client_data_json: toBase64Url(utf8(clientDataJson)),
      signature: toBase64Url(ecdsaRawToDer(signatureRaw)),
    }),
  );
  return {
    envelopeBase64Url: toBase64Url(finalBytes),
    passkeyPublicSec1Hex: toHex(passkeyPub),
    body: JSON.parse(built.bodyJson),
  };
}

test("mocked approval: JS produces a response the same JS framing accepts", async () => {
  const cli = caseByName("approval_request_unlock").sender_pin.enc_pub; // macbook = CLI
  const page = caseByName("approval_response_with_secret").sender_pin.enc_pub; // iphone = page
  const out = await mockedApprovalResponse({
    pagePrivateScalarHex: caseByName("approval_response_with_secret").sender.enc_secret,
    pagePublicSec1: fromHex(page),
    cliPublicSec1: fromHex(cli),
    rid: "d13451de7160efa2b23076fd782de967",
    decision: "Allow",
    origin: "https://approve.passlane.test",
    rpId: "approve.passlane.test",
    now: 1_760_000_050,
    nonceHex: "11223344556677881122334455667788",
  });
  const parsed = envelope.parseEnvelopeB64Url(out.envelopeBase64Url);
  eq(parsed.sigKind, 2, "webauthn sig kind");
  if (out.passkeyPublicSec1Hex.length !== 130) throw new Error("passkey pub must be SEC1 hex");
});

// -- the phone-held key (passlane#53) ------------------------------------------

const SECRET_HEX = "3c".repeat(20);
const SECRET_BYTES_OF = (hex) => new Uint8Array(hex.match(/.{2}/g).map((b) => parseInt(b, 16)));

test("phone key: a generated secret imports non-extractable and signs", async () => {
  const secret = generateSecret();
  eq(secret.length, 20, "20 bytes");
  const key = await importSecret(secret);
  // The key can sign and cannot be exported — extractable is false.
  const challenge = new Uint8Array(32).fill(0x5a);
  const answer = await computeResponse(key, challenge);
  eq(answer.length, 20, "HMAC-SHA1");
  let exported = null;
  try {
    exported = await crypto.subtle.exportKey("raw", key);
  } catch {
    /* expected */
  }
  if (exported !== null && exported !== undefined) throw new Error("the key must not be exportable");
});

test("phone key: the answer is exactly HMAC-SHA1, as keepass computes it", async () => {
  // The same construction keepass-ng's LocalChallenge (and a YubiKey slot)
  // uses — HMAC-SHA1(secret, seed) — computed through the page's
  // non-extractable key and through an independent plain import; the two
  // must agree byte for byte. The Rust tests pin the same construction
  // against keepass-ng itself.
  const key = await importSecret(SECRET_BYTES_OF(SECRET_HEX));
  const challenge = new Uint8Array(32).fill(0x2a);
  const answer = await computeResponse(key, challenge);
  const plain = await crypto.subtle.importKey(
    "raw",
    SECRET_BYTES_OF(SECRET_HEX),
    { name: "HMAC", hash: "SHA-1" },
    true,
    ["sign"],
  );
  const expected = new Uint8Array(await crypto.subtle.sign("HMAC", plain, challenge));
  eq(toHex(answer), toHex(expected), "both import paths sign identically");
  eq(answer.length, 20, "HMAC-SHA1");

  // The challenge is the vault's 32-byte seed, and only that.
  for (const bad of [new Uint8Array(31), new Uint8Array(33), new Uint8Array(0)]) {
    let threw = 0;
    try {
      await computeResponse(key, bad);
    } catch {
      threw++;
    }
    if (!threw) throw new Error("a challenge is 32 bytes");
  }
});

test("phone key: the sheet formats, parses and verifies", async () => {
  const text = sheetText("work", SECRET_HEX, Date.UTC(2026, 10, 23));
  if (!text.includes("Vault: work")) throw new Error("the sheet names the vault");
  if (!text.includes("passlane hwkey remove --secret")) throw new Error("the sheet says how to recover");
  if (!text.includes(formatSecret(SECRET_HEX))) throw new Error("the sheet carries the secret, grouped");
  eq((SECRET_HEX.match(/.{4}/g) ?? []).length, 10, "ten groups of four");

  // Parsing accepts the sheet's own grouping and freer typing.
  eq(parseSheetSecret(formatSecret(SECRET_HEX)), SECRET_HEX);
  eq(parseSheetSecret(` ${SECRET_HEX.toUpperCase().match(/.{4}/g).join("-")}`), SECRET_HEX);
  let threw = 0;
  for (const bad of ["", "zz", "3c", SECRET_HEX.slice(0, 38), SECRET_HEX + "3c", "g".repeat(40)]) {
    try {
      parseSheetSecret(bad);
    } catch {
      threw++;
    }
  }
  if (threw !== 6) throw new Error(`bad secrets must be rejected (got ${threw}/6)`);

  // The read-back verifies against the held key and rejects a wrong copy.
  const key = await importSecret(SECRET_BYTES_OF(SECRET_HEX));
  if (!(await verifySheetReadBack(key, formatSecret(SECRET_HEX)))) {
    throw new Error("the sheet's own secret verifies");
  }
  if (await verifySheetReadBack(key, "ef".repeat(20))) {
    throw new Error("a wrong copy must not verify");
  }
});

test("phone key: request classification and descriptions", () => {
  for (const kind of ["unlock", "save", "enroll_key"]) {
    if (!isPhoneKeyOperation({ kind })) throw new Error(kind);
  }
  if (isPhoneKeyOperation({ kind: "reveal" })) throw new Error("a reveal is not ours");
  eq(
    describeOperation({ kind: "unlock" }, "work"),
    "Supply the challenge-response that opens vault 'work'",
  );
  eq(
    describeOperation({ kind: "save" }, "work"),
    "Supply the challenge-response for saving vault 'work'",
  );
  eq(
    describeOperation({ kind: "enroll_key" }, "work"),
    "Create this device's key for vault 'work'",
  );
  let threw = 0;
  try {
    describeOperation({ kind: "reveal" }, "work");
  } catch {
    threw++;
  }
  if (!threw) throw new Error("a reveal must not describe as ours");
  // The instructions must say that a copy on the same screen does not count.
  if (!sheetInstructions().includes("does not count")) throw new Error(sheetInstructions());
});

test("phone key: key records are created unconfirmed", () => {
  const record = newKeyRecord("work", "work", { fake: "key" }, 1234);
  eq(record.vault, "work");
  eq(record.sheetConfirmedAt, null, "unconfirmed until the read-back");
  eq(record.createdAt, 1234);
});

test("response envelope: an answer rides the encrypted body", async () => {
  const cliPair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );
  const cliPub = new Uint8Array(await crypto.subtle.exportKey("raw", cliPair.publicKey));
  const pagePair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );
  const pagePub = new Uint8Array(await crypto.subtle.exportKey("raw", pagePair.publicKey));
  const rid = "d13451de7160efa2b23076fd782de967";
  const answerHex = "77".repeat(20);

  const built = await envelope.buildApprovalResponse({
    rid,
    senderKid: await hpke.kid("enc", pagePub),
    recipientKid: await hpke.kid("enc", cliPub),
    decision: "Allow",
    scope: { kind: "once" },
    response: answerHex,
    recipientPublicSec1: cliPub,
    seal: hpke.hpkeSeal,
    now: 1_760_000_000,
    ttl: 300,
    nonceHex: "ea9f11f8dfb0ca08a8810f9ea39c3a6a",
  });
  const parsed = envelope.parseEnvelope(built.framedBytes);
  const body = JSON.parse(
    new TextDecoder().decode(
      await hpke.hpkeOpen(parsed.enc, cliPair.privateKey, cliPub, 4, parsed.aad, parsed.ct),
    ),
  );
  eq(body.response, answerHex, "the answer is in the body");

  // A body without an answer stays exactly as it was (optional field).
  const bare = await envelope.buildApprovalResponse({
    rid,
    senderKid: await hpke.kid("enc", pagePub),
    recipientKid: await hpke.kid("enc", cliPub),
    decision: "Deny",
    scope: { kind: "once" },
    recipientPublicSec1: cliPub,
    seal: hpke.hpkeSeal,
    now: 1_760_000_000,
    ttl: 300,
    nonceHex: "11223344556677881122334455667788",
  });
  eq(
    bare.bodyJson,
    '{"type":"approval_response","decision":"Deny","scope":{"kind":"once"}}',
    "no stray field",
  );

  // Malformed answers are refused at build time, not on the wire.
  for (const bad of ["ZZ".repeat(20), "77".repeat(19), "77".repeat(21), 42]) {
    let threw = 0;
    try {
      await envelope.buildApprovalResponse({
        rid,
        senderKid: await hpke.kid("enc", pagePub),
        recipientKid: await hpke.kid("enc", cliPub),
        decision: "Allow",
        scope: { kind: "once" },
        response: bad,
        recipientPublicSec1: cliPub,
        seal: hpke.hpkeSeal,
        now: 1_760_000_000,
        ttl: 300,
        nonceHex: "11223344556677881122334455667789",
      });
    } catch {
      threw++;
    }
    if (!threw) throw new Error(`a bad answer must be refused: ${bad}`);
  }
});

// -- the approval page's decision wiring for phone-held keys ------------------

const { phoneKeyGate, challengeBytes, describeBody } = await import("./approve.js");

test("approve page: an unlock with a held key and a challenge is approvable", () => {
  const record = { keys: { work: { key: {} } } };
  const gate = phoneKeyGate(record, {
    vault_id: "work",
    vault_name: "work",
    operation: { kind: "unlock" },
    challenge: "5a".repeat(32),
  });
  if (!gate.canApprove) throw new Error(gate.note);
  if (!gate.note.includes("holds for vault 'work'")) throw new Error(gate.note);
});

test("approve page: a vault with no held key cannot be approved", () => {
  for (const kind of ["unlock", "save"]) {
    const gate = phoneKeyGate({ keys: {} }, {
      vault_id: "work",
      vault_name: "work",
      operation: { kind },
      challenge: "5a".repeat(32),
    });
    if (gate.canApprove) throw new Error(kind);
    if (!gate.note.includes("holds no key for vault 'work'")) throw new Error(gate.note);
    if (!gate.note.includes("hwkey add --phone")) throw new Error(gate.note);
  }
});

test("approve page: a request without a challenge cannot open anything", () => {
  const gate = phoneKeyGate(
    { keys: { work: { key: {} } } },
    {
      vault_id: "work",
      vault_name: "work",
      operation: { kind: "unlock" },
      challenge: null,
    },
  );
  if (gate.canApprove) throw new Error("no challenge, no answer");
  if (!gate.note.includes("no challenge")) throw new Error(gate.note);
  eq(challengeBytes({ challenge: null }), null);
  eq(challengeBytes({ challenge: "5a".repeat(31) }), null, "31 bytes is no seed");
  eq(challengeBytes({ challenge: "5A".repeat(32) }), null, "upper case is not the wire form");
  eq(challengeBytes({ challenge: "5a".repeat(32) }).length, 32);
});

test("approve page: enrollment is always possible and says it replaces", () => {
  const fresh = phoneKeyGate(
    { keys: {} },
    { vault_id: "work", vault_name: "work", operation: { kind: "enroll_key" }, challenge: "00".repeat(32) },
  );
  if (!fresh.canApprove) throw new Error(fresh.note);
  if (fresh.replacing) throw new Error("nothing to replace");
  if (!fresh.note.includes("recovery sheet")) throw new Error(fresh.note);

  const again = phoneKeyGate(
    { keys: { work: { key: {} } } },
    { vault_id: "work", vault_name: "work", operation: { kind: "enroll_key" }, challenge: "00".repeat(32) },
  );
  if (!again.canApprove) throw new Error(again.note);
  if (!again.replacing) throw new Error("an existing key is being replaced");
});

test("approve page: the card describes phone-key operations", () => {
  const view = describeBody({
    type: "approval_request",
    vault_id: "work",
    vault_name: "work",
    operation: { kind: "enroll_key" },
    requester: "anssi@macbook",
    scope: { kind: "once" },
    challenge: "5a".repeat(32),
  });
  eq(view.op, "Create this device's key for vault 'work'");
  eq(view.vault, "work");
  const view2 = describeBody({
    type: "approval_request",
    vault_name: "work",
    operation: { kind: "save" },
    requester: "anssi@macbook",
    scope: { kind: "once" },
  });
  eq(view2.op, "Supply the challenge-response for saving vault 'work'");
});

// -- labeled, expiring responses (passlane#72) ----------------------------------

const { responseLabel, expiredResponseLabel, scheduleResponseExpiry, shortRid } = await import(
  "./approve.js"
);

test("approve page: a response is labeled with the request it answers", () => {
  const rid = "51d9af44c2b3e4d5f60718293a4b5c6d";
  eq(
    responseLabel({ vault_name: "default", operation: { kind: "save" } }, rid),
    `answers: SAVE vault 'default' · 51d9af44…`,
  );
  eq(
    responseLabel({ vault_name: "default", operation: { kind: "unlock" } }, rid),
    `answers: OPEN vault 'default' · 51d9af44…`,
  );
  eq(
    responseLabel({ vault_name: "default", operation: { kind: "enroll_key" } }, rid),
    `answers: CREATE the key for vault 'default' · 51d9af44…`,
  );
  eq(
    responseLabel(
      { operation: { kind: "reveal", entry: "github", field: "password" } },
      rid,
    ),
    `answers: REVEAL password of 'github' · 51d9af44…`,
  );
  // Two requests a person could mix up must be tellable apart by the label.
  const other = "fe523a8199b7c6d5e4f3021122334455";
  const a = responseLabel({ vault_name: "default", operation: { kind: "save" } }, rid);
  const b = responseLabel({ vault_name: "default", operation: { kind: "save" } }, other);
  if (a === b) throw new Error("labels of different requests must differ");
  if (!a.includes("51d9af44") || !b.includes("fe523a81")) throw new Error(`${a} / ${b}`);
});

test("approve page: response labels survive short or absent ids", () => {
  eq(shortRid("51d9af44"), "51d9af44…");
  eq(shortRid(null), "…");
  eq(shortRid(undefined), "…");
  eq(responseLabel({ vault_name: "w", operation: { kind: "save" } }, null), "answers: SAVE vault 'w' · …");
  eq(responseLabel({ vault_name: "w", operation: { kind: "weird" } }, "51d9af44…"), "answers: weird · 51d9af44…");
});

test("approve page: a lapsed response says it is no longer accepted", () => {
  const label = expiredResponseLabel("answers: SAVE vault 'default' · 51d9af44…");
  if (!label.startsWith("EXPIRED — answers: SAVE vault 'default' · 51d9af44…")) throw new Error(label);
  if (!label.includes("no longer accepted")) throw new Error(label);
  if (!label.includes("fresh request")) throw new Error(label);
});

test("approve page: response expiry fires at the request's deadline", () => {
  const now = 1_000;
  // Already lapsed: expires at once, no timer.
  let fired = 0;
  eq(scheduleResponseExpiry(now - 1, now, () => fired++), null);
  eq(fired, 1, "a lapsed request's response is expired immediately");
  // Live: scheduled with the exact remaining time, fires when run.
  let ran = null;
  const handle = scheduleResponseExpiry(
    now + 5,
    now,
    () => fired++,
    (fn, ms) => {
      ran = ms;
      return "timer-handle";
    },
  );
  eq(ran, 5_000, "the timer waits exactly the request's remaining life");
  eq(handle, "timer-handle");
  // Exactly at the deadline is already lapsed, not scheduled.
  eq(scheduleResponseExpiry(now, now, () => fired++, () => { throw new Error("no timer"); }), null);
  eq(fired, 2);
  // Fractional "now" (Date.now()/1000): the sub-second remainder is
  // kept, so the visual expiry never lags the true deadline by a
  // second — and never fires early either.
  let fractional = null;
  scheduleResponseExpiry(
    1_005,
    1_000.999,
    () => fired++,
    (fn, ms) => {
      fractional = ms;
      return null;
    },
  );
  eq(fractional, 4_001, "4000.1 ms rounds up, never truncates early");
});

// -- the handoff: copy with fallbacks, feedback, share (passlane#76) ------------

const { canShare, copyWithFallback, copyFeedback, wireHandoff } = await import("./lib.js");

test("handoff: copy tries the clipboard API, then selection copy, then gives up", async () => {
  const textarea = { value: "the-blob", selectCalls: 0, select() { this.selectCalls++; } };
  // API works: used alone.
  let apiText = null;
  eq(
    await copyWithFallback("the-blob", textarea, {
      clipboard: { writeText: async (t) => { apiText = t; } },
    }),
    { ok: true, how: "clipboard-api" },
  );
  eq(apiText, "the-blob");
  eq(textarea.selectCalls, 0, "no selection needed");
  // API rejects: execCommand over the selection carries it.
  eq(
    await copyWithFallback("the-blob", textarea, {
      clipboard: { writeText: async () => { throw new Error("not allowed"); } },
    }, { execCommand: () => true }),
    { ok: true, how: "selection-copy" },
  );
  eq(textarea.selectCalls, 1, "the textarea was selected for the fallback");
  // Both fail: a visible failure, not a silent one.
  eq(
    await copyWithFallback("the-blob", textarea, {
      clipboard: { writeText: async () => { throw new Error("not allowed"); } },
    }, { execCommand: () => false }),
    { ok: false, how: "none" },
  );
  eq(textarea.selectCalls, 2);
  // No clipboard API at all: straight to the selection copy.
  eq(await copyWithFallback("the-blob", textarea, {}, { execCommand: () => true }), {
    ok: true,
    how: "selection-copy",
  });
  // The pages call this with no `doc`: the browser document is the
  // default, so the execCommand fallback actually runs in production
  // (passlane#76, Copilot review) — proved by installing one.
  const failingApi = { clipboard: { writeText: async () => { throw new Error("nope"); } } };
  const savedDoc = globalThis.document;
  globalThis.document = { execCommand: () => true };
  try {
    eq(
      await copyWithFallback("the-blob", textarea, failingApi),
      { ok: true, how: "selection-copy" },
      "the default document's execCommand is used",
    );
  } finally {
    if (savedDoc === undefined) delete globalThis.document;
    else globalThis.document = savedDoc;
  }
});

test("handoff: feedback names Universal Clipboard on success, long-press on failure", () => {
  const ok = copyFeedback({ ok: true, how: "clipboard-api" });
  eq(ok.button, "Copied ✓");
  if (!ok.note.includes("Universal Clipboard can take a few seconds")) throw new Error(ok.note);
  const fell = copyFeedback({ ok: true, how: "selection-copy" });
  eq(fell.button, "Copied ✓");
  const bad = copyFeedback({ ok: false, how: "none" });
  if (!bad.button.startsWith("Copy failed")) throw new Error(bad.button);
  if (!bad.note.includes("Long-press")) throw new Error(bad.note);
  if (!bad.note.includes("Copy")) throw new Error(bad.note);
});

/** A stub element good enough for wireHandoff: listeners it can fire. */
function stubElement() {
  return {
    hidden: false,
    disabled: false,
    textContent: "",
    listeners: {},
    addEventListener(type, fn) {
      (this.listeners[type] ??= []).push(fn);
    },
    async click() {
      await Promise.all((this.listeners.click ?? []).map((fn) => fn()));
    },
  };
}

test("handoff: the Copy button shows what happened and falls back", async () => {
  const textarea = Object.assign(stubElement(), {
    value: "the-blob",
    select() {},
  });
  const copy = stubElement();
  const note = stubElement();
  wireHandoff({
    textarea,
    copy,
    share: null,
    note,
    nav: { clipboard: { writeText: async () => { throw new Error("nope"); } } },
    doc: { execCommand: () => true },
  });
  await copy.click();
  eq(copy.textContent, "Copied ✓", "the fallback copied");
  if (!note.textContent.includes("Universal Clipboard")) throw new Error(note.textContent);

  // And says so when nothing worked.
  const copy2 = stubElement();
  const note2 = stubElement();
  wireHandoff({
    textarea,
    copy: copy2,
    share: null,
    note: note2,
    nav: { clipboard: { writeText: async () => { throw new Error("nope"); } } },
    doc: { execCommand: () => false },
  });
  await copy2.click();
  if (!copy2.textContent.startsWith("Copy failed")) throw new Error(copy2.textContent);
  if (!note2.textContent.includes("Long-press")) throw new Error(note2.textContent);
});

test("handoff: Share offers the sheet and hides where there is none", async () => {
  eq(canShare({ share: async () => {} }), true);
  eq(canShare({}), false);
  eq(canShare(undefined), false);

  // No navigator.share: the button is hidden, clicking does nothing.
  const hidden = stubElement();
  wireHandoff({ textarea: { value: "b" }, copy: null, share: hidden, note: null, nav: {} });
  eq(hidden.hidden, true, "hidden without navigator.share");
  eq(hidden.listeners.click?.length ?? 0, 0, "and inert");

  // With it: the blob is handed to the sheet; a dismissed sheet is not
  // a failure; a real error says how to escape.
  const shared = [];
  const share = stubElement();
  const note = stubElement();
  wireHandoff({
    textarea: { value: "the-blob" },
    copy: null,
    share,
    note,
    nav: {
      share: async (payload) => {
        shared.push(payload);
        if (shared.length === 2) throw Object.assign(new Error("aborted"), { name: "AbortError" });
        if (shared.length === 3) throw new Error("no targets");
      },
    },
  });
  eq(share.hidden, false);
  await share.click();
  eq(shared, [{ text: "the-blob" }]);
  eq(note.textContent, "Shared.");
  await share.click();
  eq(note.textContent, "Shared.", "a dismissed sheet is not a failure");
  await share.click();
  if (!note.textContent.includes("long-press")) throw new Error(note.textContent);
});



// -- the enrollment ceremony (SPEC §6, with both CLI keys bound) --------------

test("enrollment confirmation code mirrors the Rust derivation", async () => {
  const { enrollmentConfirmationCode } = await import("./enroll.js");
  const k = (b) => new Uint8Array(65).fill(b);
  // The exact value the Rust implementation (passlane-approval) produces
  // for these keys — regenerable via its unit tests; both sides must
  // show identical digits for the human comparison to work.
  const code = await enrollmentConfirmationCode(k(0x01), k(0x02), k(0x03), k(0x04));
  if (code !== "082044-650996") {
    throw new Error(`mirror mismatch: got ${code}, want 082044-650996`);
  }
  // Bound to every key; the format is two six-digit groups.
  const swapped = await enrollmentConfirmationCode(k(0x09), k(0x02), k(0x03), k(0x04));
  if (swapped === code) throw new Error("substituted CLI key must change the code");
  if (!/^\d{6}-\d{6}$/.test(code)) throw new Error(`bad format: ${code}`);
});

test("enrollment ceremony: the binding challenge covers both CLI keys, in order", async () => {
  const { runEnrollment } = await import("./enroll.js");
  const cli = caseByName("approval_request_unlock").sender_pin; // the "CLI"
  const cliEnc = fromHex(cli.enc_pub);
  const cliSig = fromHex(cli.sig_pub);
  const nonce = fromHex("0a0b0c0d0e0f00112223334445556667");

  // Deterministic seams: fixed page key, fixed credential, and an assert
  // seam that captures the challenge it was handed.
  const pagePair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  );
  const pagePub = new Uint8Array(await crypto.subtle.exportKey("raw", pagePair.publicKey));

  const passkey = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const passkeyPub = new Uint8Array(await crypto.subtle.exportKey("raw", passkey.publicKey));
  const credentialId = new Uint8Array(8).fill(0xc0);
  const rpId = "page.test";
  // Full authenticator data with attested credential data (aaguid ‖ id
  // length ‖ id ‖ COSE key), as a real authenticator emits.
  const coseKey = concat(
    new Uint8Array([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]),
    passkeyPub.subarray(1, 33),
    new Uint8Array([0x22, 0x58, 0x20]),
    passkeyPub.subarray(33, 65),
  );
  const authData = concat(
    await sha256(utf8(rpId)),
    new Uint8Array([0x41, 0, 0, 0, 0]), // UP | AT
    new Uint8Array(16), // aaguid
    new Uint8Array([0, credentialId.length]),
    credentialId,
    coseKey,
  );
  const attestationObject = concat(
    new Uint8Array([0xa3]),
    cborText("fmt"), cborText("none"),
    cborText("attStmt"), new Uint8Array([0xa0]),
    cborText("authData"),
    new Uint8Array([0x58, authData.length]),
    authData,
  );

  let seenChallenge = null;
  const { blob, confirmationCode } = await runEnrollment(
    { nonce, cliPublicSec1: cliEnc, cliSigPubSec1: cliSig },
    {
      noStore: true,
      generateKey: () => ({ privateNonExportable: pagePair.privateKey, publicSec1: pagePub }),
      createCredential: async () => ({
        response: { attestationObject: attestationObject.buffer.slice(0) },
      }),
      assert: async (_credId, challengeBytes) => {
        // Record and answer like a real authenticator would.
        seenChallenge = toBase64Url(new Uint8Array(challengeBytes));
        const clientDataJson = JSON.stringify({
          type: "webauthn.get",
          challenge: seenChallenge,
          origin: `https://${rpId}`,
        });
        const raw = new Uint8Array(
          await crypto.subtle.sign(
            { name: "ECDSA", hash: "SHA-256" },
            passkey.privateKey,
            concat(authData, await sha256(utf8(clientDataJson))),
          ),
        );
        const { ecdsaRawToDer } = await import("./lib.js");
        return {
          authenticatorData: authData.buffer.slice(0),
          clientDataJSON: utf8(clientDataJson).buffer.slice(0),
          signature: ecdsaRawToDer(raw).buffer.slice(0),
        };
      },
    },
  );

  // The exact SPEC §6 construction: nonce ‖ ECDH pub ‖ cli_enc ‖ cli_sig.
  const expected = toBase64Url(await sha256(concat(nonce, pagePub, cliEnc, cliSig)));
  if (seenChallenge !== expected) {
    throw new Error(`challenge mismatch: got ${seenChallenge}, want ${expected}`);
  }
  // Omitting or reordering either CLI key must change it — the relay-swap
  // defense only works if both keys are covered, in this order.
  assertNotEqual(
    seenChallenge,
    toBase64Url(await sha256(concat(nonce, pagePub, cliSig, cliEnc))),
    "reordered keys",
  );
  assertNotEqual(
    seenChallenge,
    toBase64Url(await sha256(concat(nonce, pagePub))),
    "omitted CLI keys",
  );
  // And the blob is shaped for the CLI verifier, with the mutual
  // confirmation code the terminal will display alongside.
  eq(blob.v, 1, "blob version");
  eq(blob.enc_pub, toHex(pagePub), "page ECDH pub");
  if (!blob.cose_key || !blob.assertion.signature) throw new Error("blob incomplete");
  const { enrollmentConfirmationCode } = await import("./enroll.js");
  eq(
    confirmationCode,
    await enrollmentConfirmationCode(cliEnc, cliSig, pagePub, passkeyPub),
    "ceremony returns the confirmation code",
  );
});

function assertNotEqual(a, b, what) {
  if (a === b) throw new Error(`${what}: values must differ (${a})`);
}

/** CBOR text string header + bytes (lengths under 24 only). */
function cborText(s) {
  const bytes = utf8(s);
  if (bytes.length >= 24) throw new Error("test helper: text too long");
  return concat(new Uint8Array([0x60 | bytes.length]), bytes);
}
