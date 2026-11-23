// The page's key store: IndexedDB records pairing each enrolled CLI with
// the identities that CLI trusts this device with:
//
//   - the ECDH encryption key (WebCrypto, non-extractable, structured-
//     cloneable into IndexedDB where it survives reloads and can never be
//     read out by script);
//   - the WebAuthn passkey's credential id (the passkey private key itself
//     lives in the authenticator/platform, never here);
//   - phone-held keys (passlane#53): per vault, a non-extractable
//     HMAC-SHA1 key answering the vault's challenge-response. Same rules
//     as the ECDH key: structured-cloneable, never extractable.
//
// One record per enrolled CLI, keyed by the *page's* encryption key id —
// which is exactly the `rkid` a request envelope addressed to this key
// carries (SPEC §3), so incoming requests route to the right record.

const DB_NAME = "passlane-approval";
const DB_VERSION = 1;
const STORE = "approvers";

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) {
        db.createObjectStore(STORE, { keyPath: "rkid" });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("indexedDB open failed"));
  });
}

async function withStore(mode, fn) {
  const db = await openDb();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, mode);
      const store = tx.objectStore(STORE);
      const request = fn(store);
      tx.oncomplete = () => resolve(request?.result);
      tx.onerror = () => reject(tx.error ?? new Error("indexedDB transaction failed"));
      tx.onabort = () => reject(tx.error ?? new Error("indexedDB transaction aborted"));
    });
  } finally {
    db.close();
  }
}

/** Persist one approver record (see module docs for the shape). */
export async function putApprover(record) {
  return withStore("readwrite", (store) => store.put(record));
}

/**
 * The phone-held key this device holds for one vault, if any: the record
 * stored under `record.keys[vaultId]` by 'hwkey add --phone'.
 */
export function heldKey(record, vaultId) {
  return record?.keys?.[vaultId] ?? null;
}

/** The approver record for a request's `rkid`, if this key is enrolled. */
export async function getApprover(rkid) {
  return withStore("readonly", (store) => store.get(rkid));
}

/** All enrolled records. */
export async function listApprovers() {
  return withStore("readonly", (store) => store.getAll());
}

/** Forget one enrollment. */
export async function deleteApprover(rkid) {
  return withStore("readwrite", (store) => store.delete(rkid));
}

/**
 * Generate the page's ECDH identity for one enrollment.
 *
 * Generated non-extractable: WebCrypto always leaves a generated pair's
 * *public* key exportable, so the public bytes can be exported while the
 * private key never exists in exportable form — no JWK copy touches
 * JavaScript memory (SPEC §6: non-extractable, IndexedDB).
 */
export async function generateEnrollmentKey() {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  );
  const publicSec1 = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  return { privateNonExportable: pair.privateKey, publicSec1 };
}
