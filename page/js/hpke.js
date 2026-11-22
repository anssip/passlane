// DHKEM(P-256) + HKDF-SHA256 + AES-256-GCM over WebCrypto — RFC 9180
// base mode, composed exactly as passlane SPEC §3 (and the RFC) specify,
// so envelopes sealed by the Rust CLI (hpke-rs) open here and vice versa.
//
// The page never implements its own primitives: ECDH, HKDF (via HMAC) and
// AES-GCM are all native WebCrypto; what this module composes is the
// *labeling* (RFC 9180 §4: LabeledExtract / LabeledExpand) around them.
//
// Cross-implementation correctness is enforced by
// crates/passlane-approval/vectors/v1.json (see tests/run.mjs).

import { concat, sha256, u16be, utf8 } from "./lib.js";

const KEM_ID = 0x0010; // DHKEM(P-256, HKDF-SHA256)
const KDF_ID = 0x0001; // HKDF-SHA256
const AEAD_ID = 0x0002; // AES-256-GCM

/** suite_id for the KEM context: "KEM" || I2OSP(kem_id, 2). */
const KEM_SUITE = concat(utf8("KEM"), new Uint8Array([0x00, KEM_ID]));
/** suite_id for the key schedule: "HPKE" || kem || kdf || aead. */
const HPKE_SUITE = concat(
  utf8("HPKE"),
  new Uint8Array([(KEM_ID >> 8) & 0xff, KEM_ID & 0xff, (KDF_ID >> 8) & 0xff, KDF_ID & 0xff, (AEAD_ID >> 8) & 0xff, AEAD_ID & 0xff]),
);

/** Domain-separation prefix of every labeled input (RFC 9180 §4). */
const HPKE_V1 = utf8("HPKE-v1");

// -- HMAC / HKDF over native WebCrypto --------------------------------------

async function hmac(keyBytes, data) {
  // An empty HMAC key is equivalent (after key padding) to 32 zero bytes,
  // and importKey rejects zero-length keys on some engines; use the zeros.
  const key = keyBytes.length
    ? keyBytes
    : new Uint8Array(32);
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, data));
}

/** HKDF-Extract(salt, ikm). */
async function hkdfExtract(salt, ikm) {
  return hmac(salt, ikm);
}

/** HKDF-Expand for L <= 32 (single block — all our lengths). */
async function hkdfExpand(prk, info, length) {
  if (length > 32) throw new Error("hkdfExpand: lengths above 32 are not needed");
  const block = await hmac(prk, concat(info, new Uint8Array([1])));
  return block.slice(0, length);
}

async function labeledExtract(suiteId, salt, label, ikm) {
  return hkdfExtract(salt, concat(HPKE_V1, suiteId, utf8(label), ikm));
}

async function labeledExpand(suiteId, prk, label, info, length) {
  return hkdfExpand(prk, concat(u16be(length), HPKE_V1, suiteId, utf8(label), info), length);
}

// -- DHKEM (RFC 9180 §4.1) ---------------------------------------------------

/** Import a 65-byte uncompressed SEC1 public key as an ECDH public key. */
export async function importEcdhPublicKey(sec1) {
  if (sec1.length !== 65 || sec1[0] !== 0x04) {
    throw new Error("expected a 65-byte uncompressed P-256 public key");
  }
  return crypto.subtle.importKey("raw", sec1, { name: "ECDH", namedCurve: "P-256" }, true, []);
}

/** ECDH raw shared secret: the x coordinate, 32 bytes. */
async function ecdh(privateKey, publicKey) {
  return new Uint8Array(
    await crypto.subtle.deriveBits({ name: "ECDH", public: publicKey }, privateKey, 256),
  );
}

/** DHKEM ExtractAndExpand: dh -> shared_secret over kem_context. */
async function kemSharedSecret(dh, kemContext) {
  const prk = await labeledExtract(KEM_SUITE, new Uint8Array(0), "eae_prk", dh);
  return labeledExpand(KEM_SUITE, prk, "shared_secret", kemContext, 32);
}

/** DHKEM decapsulation (opening): enc is the sender's ephemeral public. */
export async function kemOpen(enc, recipientPrivate, recipientPublicSec1) {
  const dh = await ecdh(recipientPrivate, await importEcdhPublicKey(enc));
  return kemSharedSecret(dh, concat(enc, recipientPublicSec1));
}

/** DHKEM encapsulation (sealing): returns [enc, shared_secret]. */
export async function kemSeal(recipientPublicSec1) {
  const ephemeral = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );
  const enc = new Uint8Array(await crypto.subtle.exportKey("raw", ephemeral.publicKey));
  const dh = await ecdh(ephemeral.privateKey, await importEcdhPublicKey(recipientPublicSec1));
  const shared = await kemSharedSecret(dh, concat(enc, recipientPublicSec1));
  return [enc, shared];
}

// -- Key schedule + AEAD (RFC 9180 §5.1, base mode) --------------------------

/**
 * HPKE `info` for passlane: "passlane-approval/v1" || message type
 * (SPEC §3 — binds the schedule to the message type byte).
 */
function infoFor(msgType) {
  return concat(utf8("passlane-approval/v1"), new Uint8Array([msgType]));
}

async function keySchedule(sharedSecret, msgType) {
  const info = infoFor(msgType);
  const empty = new Uint8Array(0);
  const pskIdHash = await labeledExtract(HPKE_SUITE, empty, "psk_id_hash", empty);
  const infoHash = await labeledExtract(HPKE_SUITE, empty, "info_hash", info);
  const context = concat(new Uint8Array([0x00]), pskIdHash, infoHash); // mode = base
  const secret = await labeledExtract(HPKE_SUITE, sharedSecret, "secret", empty);
  const key = await labeledExpand(HPKE_SUITE, secret, "key", context, 32);
  const baseNonce = await labeledExpand(HPKE_SUITE, secret, "base_nonce", context, 12);
  return { key, baseNonce };
}

async function aeadKey(raw) {
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
}

/**
 * Open an HPKE-sealed payload (one-shot; sequence number 0).
 * `recipientPrivate` is the page's non-extractable ECDH key.
 */
export async function hpkeOpen(enc, recipientPrivate, recipientPublicSec1, msgType, aad, ct) {
  const shared = await kemOpen(enc, recipientPrivate, recipientPublicSec1);
  const { key, baseNonce } = await keySchedule(shared, msgType);
  const cryptoKey = await aeadKey(key);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: baseNonce, additionalData: aad },
    cryptoKey,
    ct,
  );
  return new Uint8Array(plaintext);
}

/**
 * Seal a payload to a pinned recipient (one-shot; sequence number 0).
 * Returns [enc, ct] for the envelope framing.
 */
export async function hpkeSeal(recipientPublicSec1, msgType, aad, plaintext) {
  const [enc, shared] = await kemSeal(recipientPublicSec1);
  const { key, baseNonce } = await keySchedule(shared, msgType);
  const cryptoKey = await aeadKey(key);
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: baseNonce, additionalData: aad },
    cryptoKey,
    plaintext,
  );
  return [enc, new Uint8Array(ct)];
}

// -- Key ids (SPEC §3) --------------------------------------------------------

/** First 8 bytes of SHA-256(purpose || public_key), hex. */
export async function kid(purpose, publicSec1) {
  const digest = await sha256(concat(utf8(purpose), publicSec1));
  const hex = [];
  for (let i = 0; i < 8; i++) hex.push(digest[i].toString(16).padStart(2, "0"));
  return hex.join("");
}
