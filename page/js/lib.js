// Byte-string helpers for the passlane approval page: codecs and digests
// shared by the envelope, HPKE and WebAuthn layers. No dependencies; the
// same functions run in the browser and in the node test harness.
//
// Wire formats (SPEC §3): hex is lower-case, base64url is unpadded
// (RFC 4648 §5), integers little-endian unless CBOR (which is big-endian
// by definition of the format).

const HEX = "0123456789abcdef";
const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** UTF-8 encode. */
export function utf8(s) {
  return new TextEncoder().encode(s);
}

/** UTF-8 decode. */
export function fromUtf8(bytes) {
  return new TextDecoder().decode(bytes);
}

/** Concatenate byte strings. */
export function concat(...parts) {
  const len = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(len);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** Lower-case hex. */
export function toHex(bytes) {
  let out = "";
  for (const b of bytes) out += HEX[(b >> 4) & 0xf] + HEX[b & 0xf];
  return out;
}

/** Lower-case hex decode; throws on anything else. */
export function fromHex(s) {
  if (s.length % 2 !== 0) throw new Error("hex: odd length");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    const hi = HEX.indexOf(s[2 * i]);
    const lo = HEX.indexOf(s[2 * i + 1]);
    if (hi < 0 || lo < 0) throw new Error("hex: invalid character");
    out[i] = (hi << 4) | lo;
  }
  return out;
}

/** Unpadded base64url encode. */
export function toBase64Url(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
    const n = (b0 << 16) | (b1 << 8) | b2;
    out += B64URL[(n >> 18) & 0x3f] + B64URL[(n >> 12) & 0x3f];
    if (i + 1 < bytes.length) out += B64URL[(n >> 6) & 0x3f];
    if (i + 2 < bytes.length) out += B64URL[n & 0x3f];
  }
  return out;
}

/** Unpadded base64url decode; rejects padding, '+' and '/'. */
export function fromBase64Url(s) {
  if (s.length % 4 === 1) throw new Error("base64url: invalid length");
  const out = [];
  let acc = 0;
  let bits = 0;
  for (const c of s) {
    const v = B64URL.indexOf(c);
    if (v < 0) throw new Error(`base64url: invalid character '${c}'`);
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

/** Little-endian unsigned integers. */
export function u16le(n) {
  return new Uint8Array([n & 0xff, (n >> 8) & 0xff]);
}
export function u32le(n) {
  return new Uint8Array([n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff]);
}
/** Big-endian unsigned 16 (CBOR argument lengths). */
export function u16be(n) {
  return new Uint8Array([(n >> 8) & 0xff, n & 0xff]);
}

/** SHA-256 digest. */
export async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

/** Cryptographically random bytes. */
export function randomBytes(n) {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}

/** Constant-time string equality (challenges, ids). */
export function timingSafeEqualStr(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** Unix seconds now. */
export function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

/**
 * Convert a WebCrypto ECDSA signature (raw r||s, 64 bytes) to the DER
 * SEQUENCE(INTEGER r, INTEGER s) encoding the protocol's signature block
 * carries (Rust: `Signature::from_der`).
 */
export function ecdsaRawToDer(raw) {
  if (raw.length !== 64) throw new Error("ecdsa: expected a 64-byte raw signature");
  const half = raw.subarray(0, 32);
  const rest = raw.subarray(32, 64);
  const derInt = (bytes) => {
    let i = 0;
    while (i < bytes.length - 1 && bytes[i] === 0) i++;
    let v = bytes.subarray(i);
    if (v[0] & 0x80) v = concat(new Uint8Array([0]), v); // keep INTEGER positive
    return concat(new Uint8Array([0x02, v.length]), v);
  };
  const r = derInt(half);
  const s = derInt(rest);
  const body = concat(r, s);
  return concat(new Uint8Array([0x30, body.length]), body);
}
