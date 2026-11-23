// Envelope framing — the byte-exact mirror of passlane-approval's
// envelope.rs (SPEC §3):
//
//   magic(4) "PLAP" | version(1) | type(1) | sig kind(1) | header len(2 LE)
//   | header JSON | enc len(2 LE) | enc | ct len(4 LE) | ct | sig len(2 LE)
//   | sig
//
// AAD = everything through the header (including the sig-kind byte).
// The signature transcript = everything through the ciphertext; the
// WebAuthn challenge is base64url(SHA-256(transcript)) over the framing
// built with the assertion *placeholder* (fixed-shape empty strings),
// exactly as the Rust seal_webauthn / attach_webauthn_assertion pair
// defines it: the assertion is out-of-band, so it cannot cover itself.

import { concat, fromBase64Url, fromUtf8, sha256, toBase64Url, u16le, u32le, utf8 } from "./lib.js";

export const MAGIC = utf8("PLAP");
export const VERSION = 1;

export const MSG = {
  PAIRING_REQUEST: 1,
  PAIRING_RESPONSE: 2,
  APPROVAL_REQUEST: 3,
  APPROVAL_RESPONSE: 4,
  SESSION_REVOKE: 5,
};

export const SIG_KIND = { NONE: 0, ECDSA_P256: 1, WEBAUTHN: 2 };

/** An empty assertion serializes to this fixed shape — the placeholder. */
export function emptyAssertion() {
  return {
    authenticator_data: "",
    client_data_json: "",
    signature: "",
  };
}

/** Serialize the assertion JSON the way Rust's serde does (field order). */
export function assertionToJson(assertion) {
  // Field names are wire-format requirements (SPEC §3): snake_case.
  return JSON.stringify({
    authenticator_data: assertion.authenticator_data,
    client_data_json: assertion.client_data_json,
    signature: assertion.signature,
  });
}

/** Serialize the signature block bytes for a kind. */
function signatureBytes(sigKind, assertion) {
  switch (sigKind) {
    case SIG_KIND.NONE:
      return new Uint8Array(0);
    case SIG_KIND.ECDSA_P256:
      // The page never produces kind-1 envelopes; it only reads them.
      throw new Error("ECDSA signatures are produced by the CLI/app, not the page");
    default: {
      if (!assertion) throw new Error("missing assertion");
      return utf8(assertionToJson(assertion));
    }
  }
}

function encodeEnvelope({ msgType, sigKind, headerJson, enc, ct, sigKindFinal, assertion }) {
  const headerBytes = utf8(headerJson);
  const sig = signatureBytes(sigKind, assertion);
  return {
    headerBytes,
    sig,
    bytes: concat(
      MAGIC,
      new Uint8Array([VERSION, msgType, sigKind]),
      u16le(headerBytes.length),
      headerBytes,
      u16le(enc.length),
      enc,
      u32le(ct.length),
      ct,
      u16le(sig.length),
      sig,
    ),
  };
}

/**
 * Build an approval-response envelope in two stages:
 *
 *   buildApprovalResponse(...) with assertion omitted produces the
 *   unsigned (placeholder) envelope plus the WebAuthn challenge string
 *   the page must assert over;
 *
 *   attaching the assertion rebuilds the identical framing with the real
 *   signature block. The transcript does not include the signature block,
 *   so the challenge is stable across both stages.
 *
 * `seal` is the hpke.js hpkeSeal(recipientPubSec1, msgType, aad, pt).
 */
export async function buildApprovalResponse({
  rid,
  senderKid,
  recipientKid,
  decision, // "Allow" | { Deny: { reason?: string } }
  scope, // { kind: "once" } | { kind: "timed", seconds }
  response, // optional: 40 lower-case hex characters, the HMAC-SHA1 answer
  recipientPublicSec1,
  seal,
  now,
  ttl = 300,
  nonceHex, // 16-byte hex, tests supply deterministic values
}) {
  const header = {
    v: VERSION,
    t: MSG.APPROVAL_RESPONSE,
    n: nonceHex ?? (await randomHex16()),
    ts: now,
    exp: now + ttl,
    skid: senderKid,
    rkid: recipientKid,
    rid,
  };
  const headerJson = JSON.stringify(header);
  const body = { type: "approval_response", decision, scope };
  if (response !== undefined && response !== null) {
    if (!/^[0-9a-f]{40}$/.test(response)) {
      throw new Error("an approval answer is 40 hex characters (HMAC-SHA1)");
    }
    body.response = response;
  }
  const bodyJson = JSON.stringify(body);

  // Stage 1: frame with the placeholder assertion (sig-kind 2 is already
  // part of the AAD — the assertion form is bound before it exists).
  const placeholder = emptyAssertion();
  const stage1 = encodeEnvelope({
    msgType: MSG.APPROVAL_RESPONSE,
    sigKind: SIG_KIND.WEBAUTHN,
    headerJson,
    enc: new Uint8Array(0),
    ct: new Uint8Array(0),
    assertion: placeholder,
  });
  const aad = concat(
    MAGIC,
    new Uint8Array([VERSION, MSG.APPROVAL_RESPONSE, SIG_KIND.WEBAUTHN]),
    u16le(stage1.headerBytes.length),
    stage1.headerBytes,
  );
  const [enc, ct] = await seal(recipientPublicSec1, MSG.APPROVAL_RESPONSE, aad, utf8(bodyJson));

  const framed = encodeEnvelope({
    msgType: MSG.APPROVAL_RESPONSE,
    sigKind: SIG_KIND.WEBAUTHN,
    headerJson,
    enc,
    ct,
    assertion: placeholder,
  });
  // The transcript ends just before the signature-length field.
  const transcript = framed.bytes.subarray(0, framed.bytes.length - 2 - framed.sig.length);
  const challenge = toBase64Url(await sha256(transcript));
  return { header, bodyJson, aad, enc, ct, challenge, transcript, framedBytes: framed.bytes };
}

/**
 * Rebuild the final envelope with a real assertion. The framing's
 * signature block is `u16 len ‖ signature`, so the placeholder's bytes sit
 * immediately after `transcript` (which ends just before that length
 * field) — splice there rather than scanning from the end.
 */
export function attachAssertion(transcript, assertionJson) {
  const sig = utf8(assertionJson);
  return concat(transcript, u16le(sig.length), sig);
}

async function randomHex16() {
  const { randomBytes, toHex } = await import("./lib.js");
  return toHex(randomBytes(16));
}
/** Parse wire bytes into the envelope's parts (strict). */
export function parseEnvelope(bytes) {
  let at = 0;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const take = (n) => {
    if (at + n > bytes.length) throw new Error("envelope: truncated");
    const out = bytes.subarray(at, at + n);
    at += n;
    return out;
  };
  const u16 = () => {
    const v = view.getUint16(at, true);
    at += 2;
    return v;
  };
  const u32 = () => {
    const v = view.getUint32(at, true);
    at += 4;
    return v;
  };

  const magic = take(4);
  if (fromUtf8(magic) !== "PLAP") throw new Error("envelope: bad magic");
  const version = take(1)[0];
  if (version !== VERSION) throw new Error(`envelope: unsupported version ${version}`);
  const msgType = take(1)[0];
  const sigKind = take(1)[0];
  const headerLen = u16();
  const headerBytes = take(headerLen);
  const header = JSON.parse(fromUtf8(headerBytes));
  const encLen = u16();
  const enc = take(encLen);
  const ctLen = u32();
  const ct = take(ctLen);
  const sigLen = u16();
  const sig = take(sigLen);
  if (at !== bytes.length) throw new Error("envelope: trailing bytes");

  const aad = concat(magic, new Uint8Array([version, msgType, sigKind]), u16le(headerLen), headerBytes);
  const aadEnd = 4 + 1 + 1 + 1 + 2 + headerLen + 2 + encLen + 4 + ctLen;
  const transcript = bytes.subarray(0, aadEnd);

  return {
    version,
    msgType,
    sigKind,
    header,
    headerBytes,
    enc: new Uint8Array(enc),
    ct: new Uint8Array(ct),
    sig: new Uint8Array(sig),
    aad,
    transcript,
  };
}

/** Parse from a base64url fragment. */
export function parseEnvelopeB64Url(s) {
  return parseEnvelope(fromBase64Url(s));
}

/** The WebAuthn challenge string for a parsed (final) envelope. */
export async function webauthnChallenge(envelope) {
  return toBase64Url(await sha256(envelope.transcript));
}
