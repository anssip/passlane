// The phone-held key (passlane#53, SPEC §7): this page holds a vault's
// challenge-response secret and answers unlock, save and enrollment
// requests with the 20-byte HMAC-SHA1 of the challenge they carry.
//
// The secret is generated here and never leaves except onto the recovery
// sheet. It lives as a non-extractable WebCrypto HMAC key (SHA-1, sign
// only): script on this page — or any script injected into it — can ask
// it to sign, but cannot read it out, export it, or copy it to another
// vault. The raw bytes exist exactly once, while the sheet is shown;
// after the read-back they are wiped.
//
// The sheet is the only other copy. Enrollment answers nothing until the
// owner has typed the secret back from a copy of the sheet — which is
// why the sheet hides itself first: reading it off the same screen would
// prove nothing.

import { randomBytes, timingSafeEqualStr, toHex } from "./lib.js";

/// The secret's length in bytes: KeePass challenge-response slots hold
/// 20-byte HMAC-SHA1 keys.
export const SECRET_BYTES = 20;

/// The challenge of an unlock/save/enrollment request: the vault's KDF
/// seed, 32 bytes.
export const CHALLENGE_BYTES = 32;

/// The answer's length: the HMAC-SHA1 digest.
export const ANSWER_BYTES = 20;

/**
 * Generate the vault's secret: 20 random bytes, returned raw exactly
 * once — for the recovery sheet. Import it with {@link importSecret}
 * before storing anything.
 */
export function generateSecret() {
  return randomBytes(SECRET_BYTES);
}

/**
 * The sheet secret as a non-extractable HMAC-SHA1 key, sign only. From
 * here on the page works through the key; `crypto.subtle.exportKey` on
 * it fails by construction.
 */
export async function importSecret(secretBytes) {
  if (!(secretBytes instanceof Uint8Array) || secretBytes.length !== SECRET_BYTES) {
    throw new Error(`the secret is ${SECRET_BYTES} bytes`);
  }
  return crypto.subtle.importKey(
    "raw",
    secretBytes,
    { name: "HMAC", hash: "SHA-1" },
    false, // extractable: never
    ["sign"], // sign only
  );
}

/**
 * The 20-byte answer to a challenge: HMAC-SHA1(secret, challenge), as
 * the CLI's composite key needs it. Computed only on approval.
 */
export async function computeResponse(hmacKey, challenge) {
  if (!(challenge instanceof Uint8Array) || challenge.length !== CHALLENGE_BYTES) {
    throw new Error(`the challenge is ${CHALLENGE_BYTES} bytes (the vault's KDF seed)`);
  }
  const digest = await crypto.subtle.sign("HMAC", hmacKey, challenge);
  return new Uint8Array(digest);
}

/**
 * The text of the recovery sheet: everything a person needs, decades
 * from now, to recognize what the sheet opens and to re-import the key.
 * `secretHex` is the only copy that will ever exist in text form.
 */
export function sheetText(vaultName, secretHex, created) {
  const when = new Date(created).toISOString().slice(0, 10);
  return [
    "passlane recovery sheet",
    "",
    `Vault: ${vaultName}`,
    `Created: ${when}`,
    "",
    "The key this sheet recovers is held by one device. If that device",
    "is lost, this sheet is the only way in: with it,",
    "  passlane hwkey remove --secret",
    "removes the factor and the vault opens on the master password.",
    "",
    "Secret:",
    formatSecret(secretHex),
    "",
    "Keep this sheet offline. Anyone who reads it can help open the vault.",
  ].join("\n");
}

/** The secret in readable groups: `abcd 1234 …`, ten groups of four. */
export function formatSecret(secretHex) {
  return (secretHex.match(/.{4}/g) ?? []).join(" ");
}

/**
 * What {@link formatSecret} (and freer typing) prints, back to raw hex:
 * whitespace, colons and dashes are dropped, upper case is folded. The
 * result is exactly 40 hex characters or this throws.
 */
export function parseSheetSecret(text) {
  const cleaned = text.replace(/[\s:-]/g, "").toLowerCase();
  if (!/^[0-9a-f]+$/.test(cleaned)) {
    throw new Error("the secret is hex characters only");
  }
  if (cleaned.length !== SECRET_BYTES * 2) {
    throw new Error(`the secret is ${SECRET_BYTES * 2} hex characters, got ${cleaned.length}`);
  }
  return cleaned;
}

/**
 * Verify the owner really has a copy of the sheet: they typed its secret
 * back. Both the typed value and the held key sign the same fresh probe
 * and the digests must match — so the held secret is never compared as
 * text (it cannot be: it is not extractable) and a wrong copy fails.
 */
export async function verifySheetReadBack(heldKey, typedText) {
  const typedHex = parseSheetSecret(typedText);
  const typedKey = await importSecret(
    new Uint8Array(typedHex.match(/.{2}/g).map((b) => parseInt(b, 16))),
  );
  const probe = randomBytes(32);
  const [held, typed] = await Promise.all([
    crypto.subtle.sign("HMAC", heldKey, probe),
    crypto.subtle.sign("HMAC", typedKey, probe),
  ]);
  return timingSafeEqualStr(toHex(new Uint8Array(held)), toHex(new Uint8Array(typed)));
}

/**
 * Whether an approval-request body is one this module answers: the
 * operations that carry a challenge. A reveal is the ask flow's, not
 * ours.
 */
export function isPhoneKeyOperation(operation) {
  return ["unlock", "save", "enroll_key"].includes(operation?.kind);
}

/**
 * The human description of what answering a request does, for the
 * approval card. Shared with approve.js's describe() for these kinds.
 */
export function describeOperation(operation, vaultName) {
  switch (operation?.kind) {
    case "unlock":
      return `Supply the challenge-response that opens vault '${vaultName}'`;
    case "save":
      return `Supply the challenge-response for saving vault '${vaultName}'`;
    case "enroll_key":
      return `Create this device's key for vault '${vaultName}'`;
    default:
      throw new Error(`not a phone-held-key operation: ${operation?.kind}`);
  }
}

/** A vault's key record as it lives in the approver record. */
export function newKeyRecord(vaultId, vaultName, hmacKey, now = Date.now()) {
  return {
    vault: vaultId,
    vaultName,
    key: hmacKey,
    createdAt: now,
    /// Set once the sheet was read back; until then the key answers
    /// nothing and the next enrollment may replace it.
    sheetConfirmedAt: null,
  };
}

// -- the staged-key lifecycle -------------------------------------------------
//
// An enrollment creates a key and must be able to answer with it from the
// moment its sheet is confirmed — but the vault keeps opening with the old
// key until the enrollment completes (its save). So a fresh key is
// *staged* beside the held one, and the two rules that move it are:
//
//  - the answer to the enrollment's save promotes it (that answer is the
//    enrollment's last step: after it, the vault needs the new key);
//  - an unlock answered with the held key drops it (the vault demonstrably
//    still opens with the old one, so the enrollment never completed).
//
// An aborted ceremony — a declined replacement, a failed read-back, a
// cancelled passkey — therefore never destroys a working factor.

/** The key staged for one vault by an unfinished enrollment, if any. */
export function stagedKey(record, vaultId) {
  return record?.staged?.[vaultId] ?? null;
}

/** The vault's held key, if any (`keys`, not `staged`). */
export function heldKeyOf(record, vaultId) {
  return record?.keys?.[vaultId] ?? null;
}

/** Stage a freshly created, sheet-confirmed key beside the held one.
 *  Pure: returns the next record. */
export function stageKey(record, vaultId, keyRecord) {
  return { ...record, staged: { ...(record.staged ?? {}), [vaultId]: keyRecord } };
}

/** Promote the staged key to the vault's held key: after it answered a
 *  save, the vault needs it. Pure: returns the next record. */
export function promoteStagedKey(record, vaultId) {
  const staged = stagedKey(record, vaultId);
  if (!staged) return record;
  const rest = { ...record.staged };
  delete rest[vaultId];
  return { ...record, keys: { ...(record.keys ?? {}), [vaultId]: staged }, staged: rest };
}

/** Forget the staged key: the vault just opened with the held one, so
 *  the enrollment that staged it never completed. Pure. */
export function dropStagedKey(record, vaultId) {
  if (!stagedKey(record, vaultId)) return record;
  const rest = { ...record.staged };
  delete rest[vaultId];
  return { ...record, staged: rest };
}

/**
 * Which key answers an unlock or save request, and what the answer does
 * to a staged key — the lifecycle rules above, pure so the node tests
 * pin them. Enrollment requests are not answered from here at all: their
 * ceremony builds a key and stages it.
 *
 * Returns `{ key, promote, dropStaged }` (the key record to answer
 * with), or `null` when this record holds no key for the vault — an
 * unlock with only a staged key has nothing to answer with, which is
 * right: the vault is not phone-held until an enrollment completes.
 */
export function keyDecision(record, body) {
  const held = heldKeyOf(record, body.vault_id);
  const staged = stagedKey(record, body.vault_id);
  if (body.operation?.kind === "save") {
    // Only the enrollment saves without an unlock in between — any other
    // command would have opened first, and that unlock dropped the
    // staged key — so a save with a staged key present is the
    // enrollment's own.
    const key = staged ?? held;
    return key ? { key, promote: !!staged, dropStaged: false } : null;
  }
  if (!held) return null;
  return { key: held, promote: false, dropStaged: !!staged };
}

/**
 * The answer an approval envelope may carry: only an Allow carries one.
 * A Deny must never leak an unlock factor that happened to be computed
 * before the decision — the requesting computer can decrypt whatever the
 * body carries, denial or not.
 */
export function answerForDecision(decision, answerHex) {
  return decision === "allow" ? answerHex ?? null : null;
}

/**
 * The note about what the sheet is, shown beside the read-back. Kept
 * here so the node tests can check the wording says the one thing that
 * matters: a copy on the same screen does not count.
 */
export function sheetInstructions() {
  return [
    "Print this sheet, or write the secret down — a copy on this same screen",
    "does not count: the point is that the key survives losing this device.",
    "Then confirm it by typing the secret back from your copy.",
  ].join(" ");
}

/**
 * Wipe raw secret bytes after the sheet has been shown. JavaScript
 * cannot guarantee memory erasure; this is the best a page can do, and
 * it is why the secret exists as bytes only for the sheet, never
 * afterwards.
 */
export function wipe(bytes) {
  bytes.fill(0);
}
