// The page's key store: IndexedDB records pairing each enrolled CLI with
// the two identities SPEC §6 gives the page:
//
//   - the ECDH encryption key (WebCrypto, non-extractable, structured-
//     cloneable into IndexedDB where it survives reloads and can never be
//     read out by script);
//   - the WebAuthn passkey's credential id (the passkey private key itself
//     lives in the authenticator/platform, never here).
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
 * The key is generated extractable (to export the public bytes), then
 * immediately re-imported non-extractable; only the non-extractable
 * handle is kept. The transient JWK copy is dropped on return — the
 * stored key can never be exported again, per SPEC §6.
 */
export async function generateEnrollmentKey() {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );
  const publicSec1 = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  jwk.key_ops = ["deriveBits"]; // lock down before re-import
  const privateNonExportable = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  );
  jwk.d = ""; // best-effort wipe of the transient scalar copy
  return { privateNonExportable, publicSec1 };
}
