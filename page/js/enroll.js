// The enrollment page (SPEC §6): one-time, at the computer.
//
// Fragment: #n=<enrollment nonce hex>&c=<CLI encryption public key hex>
// (everything stays in the fragment; the server never sees it).
//
// Ceremony:
//   1. generate the page's ECDH encryption identity (non-extractable);
//   2. create a WebAuthn passkey (attestation: "none" — vendor attestation
//      keys cannot bind anything to *this* credential);
//   3. request a credentials.get() assertion whose challenge is
//      SHA-256(nonce || ECDH public key) — the passkey's signature over
//      it is what vouches that the passkey owner binds this exact ECDH key;
//   4. show the enrollment blob to paste back into the terminal.
//
// The CLI verifies the assertion and pins enc_pub/sig_pub + the WebAuthn
// RP data; the page stores the ECDH key + credential id keyed by its own
// key id (the `rkid` of future requests).

import { decode as cborDecode, parseAttestationObject } from "./cbor.js";
import { kid } from "./hpke.js";
import {
  generateEnrollmentKey,
  putApprover,
} from "./keystore.js";
import { concat, fromHex, sha256, toBase64Url, toHex } from "./lib.js";

const $ = (id) => document.getElementById(id);

/**
 * The enrollment confirmation code (SPEC §5's human check, mirrored from
 * the CLI's passlane-approval derivation): twelve digits over BOTH
 * parties' public keys. The terminal derives it from its own keys plus
 * the pasted blob's; this page derives it from the link's CLI keys plus
 * its own. The human compares the two displays before the CLI persists
 * the pin — a substituted enrollment link produces a mismatch.
 */
export async function enrollmentConfirmationCode(
  cliEncPub,
  cliSigPub,
  pageEncPub,
  pageSigPub,
) {
  const digest = await sha256(
    concat(
      new TextEncoder().encode("passlane-enrollment-code/v1"),
      cliEncPub,
      cliSigPub,
      pageEncPub,
      pageSigPub,
    ),
  );
  const n = digest.subarray(0, 8).reduce((acc, b) => acc * 256n + BigInt(b), 0n) % 1000000000000n;
  const s = n.toString().padStart(12, "0");
  return `${s.slice(0, 6)}-${s.slice(6)}`;
}

/** Parse the enrollment fragment into { nonce, cliPublicSec1, cliSigPubSec1 }. */
export function parseEnrollFragment(hash) {
  const params = new URLSearchParams(hash.replace(/^#/, ""));
  const n = params.get("n");
  const c = params.get("c");
  const s = params.get("s");
  if (!n || !c || !s) {
    throw new Error(
      "the link is incomplete: it needs the nonce (n=…), the CLI encryption key (c=…) and the CLI verifying key (s=…)",
    );
  }
  const nonce = fromHex(n);
  if (nonce.length !== 16) throw new Error("the enrollment nonce must be 16 bytes of hex");
  const cliPublic = fromHex(c);
  if (cliPublic.length !== 65 || cliPublic[0] !== 0x04) {
    throw new Error("the CLI public key must be a 65-byte uncompressed P-256 point (hex)");
  }
  const cliSig = fromHex(s);
  if (cliSig.length !== 65 || cliSig[0] !== 0x04) {
    throw new Error("the CLI verifying key must be a 65-byte uncompressed P-256 point (hex)");
  }
  return { nonce, cliPublicSec1: cliPublic, cliSigPubSec1: cliSig };
}

/** Run the whole ceremony; returns the enrollment blob object. */
export async function runEnrollment({ nonce, cliPublicSec1, cliSigPubSec1 }, options = {}) {
  // 1. The page's encryption identity.
  const { privateNonExportable, publicSec1 } =
    options.generateKey?.() ?? (await generateEnrollmentKey());

  // 2. The passkey (the human-present factor).
  const created = await (options.createCredential ?? createPasskey)();
  const parsed = parseAttestationObject(new Uint8Array(created.response.attestationObject));

  // 3. The binding assertion: the passkey signs
  //    SHA-256(nonce ‖ ECDH pub ‖ CLI keys) — covering the CLI's keys
  //    makes a swapped enrollment link produce a challenge the genuine
  //    CLI never issued (it recomputes the challenge from its own keys).
  const challenge = await sha256(concat(nonce, publicSec1, cliPublicSec1, cliSigPubSec1));
  const assertion = await (options.assert ?? assertWithPasskey)(parsed.credentialId, challenge);

  // 4. Store and produce the paste-back blob. The record is keyed by the
  //    page's own encryption key id — the rkid requests to this key carry.
  // The mutual confirmation code, shown beside the paste-back blob: the
  // terminal displays the same value derived from ITS keys plus this
  // blob's; the human compares before the CLI pins anything.
  const confirmationCode = await enrollmentConfirmationCode(
    cliPublicSec1,
    cliSigPubSec1,
    publicSec1,
    passkeyPubBytes(parsed),
  );
  const ownKid = await kid("enc", publicSec1);
  const record = {
    rkid: ownKid,
    label: options.label ?? `cli-${await kid("enc", cliPublicSec1)}`,
    encPrivate: privateNonExportable,
    encPub: publicSec1,
    cliPublicSec1,
    // The CLI's verifying key: what request signatures are checked against
    // (HPKE base mode does not authenticate the sender).
    cliSigPubSec1,
    credentialId: parsed.credentialId,
    createdAt: Date.now(),
  };
  if (!options.noStore) await putApprover(record);
  return {
    blob: {
      v: 1,
      enc_pub: toHex(publicSec1),
      cose_key: toBase64Url(parsed.credentialPublicKey),
      assertion: {
        authenticator_data: toBase64Url(new Uint8Array(assertion.authenticatorData)),
        client_data_json: toBase64Url(new Uint8Array(assertion.clientDataJSON)),
        signature: toBase64Url(new Uint8Array(assertion.signature)),
      },
    },
    confirmationCode,
    record,
  };
}

/** The passkey's SEC1 public key from the parsed attestation's COSE
 * key ({1:2, 3:-7, -1:1, -2:x, -3:y}). */
function passkeyPubBytes(parsed) {
  const [map] = cborDecode(parsed.credentialPublicKey);
  const out = new Uint8Array(65);
  out[0] = 0x04;
  out.set(map.get(-2), 1);
  out.set(map.get(-3), 33);
  return out;
}

export async function createPasskey() {
  const credential = await navigator.credentials.create({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp: { id: location.hostname, name: "Passlane approvals" },
      user: {
        id: crypto.getRandomValues(new Uint8Array(16)),
        name: "passlane-approver",
        displayName: "Passlane approver",
      },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      attestation: "none",
      authenticatorSelection: { residentKey: "preferred", userVerification: "preferred" },
    },
  });
  if (!credential) throw new Error("no credential was created");
  return credential;
}

async function assertWithPasskey(credentialId, challenge) {
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge,
      allowCredentials: [{ type: "public-key", id: credentialId }],
      userVerification: "preferred",
    },
  });
  if (!assertion) throw new Error("no assertion was produced");
  return assertion.response;
}

// -- page wiring --------------------------------------------------------------

function requireSecureContext() {
  if (!window.isSecureContext || !location.hostname) {
    throw new Error(
      "WebAuthn needs a secure context with a real hostname (https, or localhost). " +
        "Serve the page (e.g. `python3 -m http.server`) instead of opening it from disk.",
    );
  }
}

async function main() {
  try {
    const parsed = parseEnrollFragment(location.hash);
    $("link-ok").hidden = false;
    requireSecureContext();
    $("start").disabled = false;
    $("start").addEventListener("click", async () => {
      try {
        $("start").disabled = true;
        $("status").textContent = "Creating keys — confirm the passkey prompt…";
        const { blob, confirmationCode } = await runEnrollment(parsed);
        $("blob").value = JSON.stringify(blob);
        $("blob-wrap").hidden = false;
        $("code").textContent = confirmationCode;
        $("code-wrap").hidden = false;
        $("status").textContent =
          "Done on this side. Compare the confirmation code with the one the terminal shows; if they match, confirm there and paste the blob.";
      } catch (e) {
        $("status").textContent = `Enrollment failed: ${e.message}`;
        $("start").disabled = false;
      }
    });
  } catch (e) {
    $("link-error").textContent = e.message;
    $("link-error").hidden = false;
  }
}

// Node (the test harness) has no DOM: run only in a browser context.
if (typeof document !== "undefined") main();
