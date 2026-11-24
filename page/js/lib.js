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

// -- the blob/response handoff (passlane#76) -----------------------------------
//
// One implementation shared by approve.html and enroll.html for the thing
// both pages end with: a blob of text that must get from this screen to
// the waiting terminal. The async Clipboard API alone is not enough on
// iOS Safari — it can reject (gesture context, permissions) and even a
// successful write syncs to Universal Clipboard unreliably — so the
// handoff tries every path, always shows what happened, and keeps the
// share sheet (whose AirDrop the user asked for) one tap away.

/** Whether this platform has a share sheet (`navigator.share`). */
export function canShare(nav = globalThis.navigator) {
  return typeof nav?.share === "function";
}

/**
 * Copy `text` by every means a browser allows, best first, staying
 * inside the click's user activation: the async Clipboard API, then
 * (when it rejects) deprecated `execCommand("copy")` over the selected
 * textarea — the pragmatic last resort on iOS Safari. Returns how it
 * went, so the caller can tell the human.
 */
export async function copyWithFallback(text, textarea, nav = globalThis.navigator, doc) {
  try {
    if (typeof nav?.clipboard?.writeText !== "function") throw new Error("no clipboard API");
    await nav.clipboard.writeText(text);
    return { ok: true, how: "clipboard-api" };
  } catch {
    // Fall through to the selection copy.
  }
  if (textarea && typeof textarea.select === "function") {
    textarea.select();
    try {
      if (doc?.execCommand?.("copy")) return { ok: true, how: "selection-copy" };
    } catch {
      // Neither path worked.
    }
  }
  return { ok: false, how: "none" };
}

/**
 * What the Copy button and the note beside the blob say after an
 * attempt. Success carries the Universal Clipboard patience note;
 * failure names the escape that reliably syncs: the native long-press
 * → Copy path.
 */
export function copyFeedback(outcome) {
  return outcome.ok
    ? {
        button: "Copied ✓",
        note:
          "Copied — paste it on the Mac. Universal Clipboard can take a few seconds; " +
          "if nothing arrives there, use Share (AirDrop) or long-press the text → Copy.",
      }
    : {
        button: "Copy failed — long-press below",
        note:
          "Could not copy automatically. Long-press the text above and choose Copy — " +
          "the native copy path reaches the Mac reliably — or use Share.",
      };
}

/**
 * Wire one handoff: the Copy button (fallbacks + visible feedback), a
 * Share button that offers the platform share sheet (on iOS that
 * includes AirDrop — a web page cannot invoke AirDrop directly, this
 * is the supported route), hidden where the platform has no share,
 * and the note line the feedback lands in. Every element is optional:
 * briefly cached, older HTML without a button must not break the page.
 */
export function wireHandoff({ textarea, copy, share, note, nav = globalThis.navigator, doc }) {
  if (copy) {
    copy.addEventListener("click", async () => {
      const outcome = await copyWithFallback(textarea?.value ?? "", textarea, nav, doc);
      const feedback = copyFeedback(outcome);
      copy.textContent = feedback.button;
      if (note) note.textContent = feedback.note;
    });
  }
  if (share) {
    if (!canShare(nav)) {
      share.hidden = true;
    } else {
      share.addEventListener("click", async () => {
        try {
          await nav.share({ text: textarea?.value ?? "" });
          if (note) note.textContent = "Shared.";
        } catch (e) {
          // A dismissed share sheet is a choice, not a failure.
          if (e?.name !== "AbortError" && note) {
            note.textContent = "Sharing failed — long-press the text and Copy instead.";
          }
        }
      });
    }
  }
}


/**
 * Convert a WebCrypto ECDSA signature (raw r||s, 64 bytes) to the DER
 * SEQUENCE(INTEGER r, INTEGER s) encoding the protocol's signature block
 * carries (Rust: `Signature::from_der`).
 */
export function ecdsaRawToDer(raw) {
  if (raw.length !== 64) throw new Error("ecdsa: expected a 64-byte raw signature");
  const body = concat(derInt(raw.subarray(0, 32)), derInt(raw.subarray(32, 64)));
  return concat(new Uint8Array([0x30, body.length]), body);
}

function derInt(bytes) {
  let i = 0;
  while (i < bytes.length - 1 && bytes[i] === 0) i++;
  let v = bytes.subarray(i);
  if (v[0] & 0x80) v = concat(new Uint8Array([0]), v); // keep INTEGER positive
  return concat(new Uint8Array([0x02, v.length]), v);
}

/**
 * The inverse: DER SEQUENCE(INTEGER, INTEGER) → raw r||s (64 bytes), the
 * form WebCrypto's verify expects. Rejects anything that is not the exact
 * two-INTEGER shape with canonical lengths.
 */
export function ecdsaDerToRaw(der) {
  const err = new Error("ecdsa: not a DER ECDSA signature");
  if (der[0] !== 0x30) throw err;
  let at = 1;
  if (der[1] < 0x80) {
    if (der.length !== 2 + der[1]) throw err;
    at = 2;
  } else if (der[1] === 0x81) {
    if (der.length !== 3 + der[2]) throw err;
    at = 3;
  } else {
    throw err; // our signatures never exceed 255 bytes
  }
  const readInt = () => {
    if (der[at] !== 0x02) throw err;
    const len = der[at + 1];
    if (len > 33 || (len === 33 && der[at + 2] !== 0)) throw err;
    const start = at + 2 + (len === 33 ? 1 : 0);
    const int = der.subarray(start, at + 2 + len);
    at += 2 + len;
    // Left-pad to 32 (missing bytes are leading zeros).
    const out = new Uint8Array(32);
    out.set(int.subarray(Math.max(0, int.length - 32)), 32 - Math.min(32, int.length));
    return out;
  };
  const r = readInt();
  const s = readInt();
  if (at !== der.length) throw err;
  return concat(r, s);
}
