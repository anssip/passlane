// Minimal CBOR decoding — just enough for the WebAuthn structures the
// approval page touches (SPEC §6): the attestation object's map, and the
// COSE_Key of the credential public key, which is passed through verbatim
// to the CLI for pinning.
//
// Definite lengths only; unknown/simple values (ints, byte/text strings,
// arrays, maps) — exactly the value set WebAuthn emits. Anything the page
// does not need to interpret it leaves as decoded values; bytes it must
// forward (the COSE key) it slices out of the original input so the CLI
// sees byte-exact authenticator output.

import { fromUtf8 } from "./lib.js";

/** A decoded CBOR value: number | bigint | Uint8Array | string | Array | Map. */
export function decode(bytes, offset = 0) {
  const [value, consumed] = decodeItem(bytes, offset);
  return [value, consumed];
}

/** Decode one item; returns [value, bytesConsumedFromOffset]. */
function decodeItem(bytes, offset) {
  const major = bytes[offset];
  const mt = major >> 5;
  const info = major & 0x1f;
  const [arg, argLen] = readArgument(bytes, offset, info);
  const headLen = 1 + argLen;
  switch (mt) {
    case 0: // unsigned int
      return [arg, headLen];
    case 1: // negative int: -1 - n
      return [-1 - Number(arg), headLen];
    case 2: { // byte string
      const start = offset + headLen;
      return [bytes.slice(start, start + Number(arg)), headLen + Number(arg)];
    }
    case 3: { // text string
      const start = offset + headLen;
      const slice = bytes.slice(start, start + Number(arg));
      return [fromUtf8(slice), headLen + Number(arg)];
    }
    case 4: { // array
      let at = offset + headLen;
      const items = [];
      for (let i = 0; i < Number(arg); i++) {
        const [item, n] = decodeItem(bytes, at);
        items.push(item);
        at += n;
      }
      return [items, at - offset];
    }
    case 5: { // map
      let at = offset + headLen;
      const map = new Map();
      for (let i = 0; i < Number(arg); i++) {
        const [key, n1] = decodeItem(bytes, at);
        at += n1;
        const [value, n2] = decodeItem(bytes, at);
        at += n2;
        map.set(key, value);
      }
      return [map, at - offset];
    }
    default:
      throw new Error(`cbor: unsupported major type ${mt}`);
  }
}

function readArgument(bytes, offset, info) {
  let arg;
  let argLen = 0;
  switch (true) {
    case info <= 23:
      arg = BigInt(info);
      break;
    case info === 24:
      arg = BigInt(bytes[offset + 1]);
      argLen = 1;
      break;
    case info === 25:
      arg = BigInt((bytes[offset + 1] << 8) | bytes[offset + 2]);
      argLen = 2;
      break;
    case info === 26: {
      const v =
        (bytes[offset + 1] << 24) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 8) | bytes[offset + 4];
      arg = BigInt(v >>> 0);
      argLen = 4;
      break;
    }
    case info === 27: {
      let v = 0n;
      for (let i = 1; i <= 8; i++) v = (v << 8n) | BigInt(bytes[offset + i]);
      arg = v;
      argLen = 8;
      break;
    }
    case info === 31:
      throw new Error("cbor: indefinite lengths not supported");
    default:
      throw new Error("cbor: reserved additional information");
  }
  // Small integers as Numbers (Map keys compare by identity; every value
  // this parser feeds callers is well below 2^53).
  if (arg <= BigInt(Number.MAX_SAFE_INTEGER)) return [Number(arg), argLen];
  return [arg, argLen];
}

/**
 * Parse a WebAuthn authenticator data buffer into its fixed fields.
 * Layout: rpIdHash(32) flags(1) signCount(4) [attestedCredentialData]
 * where attestedCredentialData = aaguid(16) credIdLen(2 BE) credId(n)
 * credentialPublicKey(COSE CBOR, sliced verbatim).
 */
export function parseAuthenticatorData(authData) {
  const view = new DataView(authData.buffer, authData.byteOffset, authData.byteLength);
  const rpIdHash = authData.slice(0, 32);
  const flags = authData[32];
  const signCount = view.getUint32(33, false);
  const out = { rpIdHash, flags, signCount, attestedCredentialData: null };
  if (!(flags & 0x40)) return out; // AT flag unset: no attested credential data

  let at = 37;
  if (authData.length < at) throw new Error("authenticator data: too short for attested credential data");
  const aaguid = authData.slice(at, at + 16);
  at += 16;
  if (authData.length < at + 2) throw new Error("attested credential data: truncated before the credential id length");
  const credIdLen = view.getUint16(at, false);
  at += 2;
  const credentialId = authData.slice(at, at + credIdLen);
  at += credIdLen;
  if (authData.length < at) throw new Error("attested credential data: truncated credential id");
  // The COSE key's own CBOR head declares its length; slice it verbatim.
  const [, coseLen] = decodeItem(authData, at);
  const credentialPublicKey = authData.slice(at, at + coseLen);
  out.attestedCredentialData = { aaguid, credentialId, credentialPublicKey };
  return out;
}

/**
 * Parse a WebAuthn attestation object (CBOR map: fmt, attStmt, authData)
 * into { fmt, authData, credentialId, credentialPublicKey }.
 */
export function parseAttestationObject(attestationObject) {
  const [map] = decode(attestationObject);
  if (!(map instanceof Map) || !map.has("fmt") || !map.has("authData")) {
    throw new Error("attestation object: unexpected CBOR shape");
  }
  const parsed = parseAuthenticatorData(map.get("authData"));
  if (!parsed.attestedCredentialData) {
    throw new Error("attestation object: no attested credential data");
  }
  return {
    fmt: map.get("fmt"),
    authData: map.get("authData"),
    credentialId: parsed.attestedCredentialData.credentialId,
    credentialPublicKey: parsed.attestedCredentialData.credentialPublicKey,
  };
}

/** True when the user-present flag is set in authenticator data flags. */
export function userPresent(authData) {
  return (authData[32] & 0x01) !== 0;
}
