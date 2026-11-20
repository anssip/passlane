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

import { parseAttestationObject } from "./cbor.js";
import { kid } from "./hpke.js";
import {
  generateEnrollmentKey,
  putApprover,
} from "./keystore.js";
import { concat, fromHex, sha256, toBase64Url, toHex } from "./lib.js";

const $ = (id) => document.getElementById(id);

/** Parse the enrollment fragment into { nonce, cliPublicSec1 }. */
export function parseEnrollFragment(hash) {
  const params = new URLSearchParams(hash.replace(/^#/, ""));
  const n = params.get("n");
  const c = params.get("c");
  if (!n || !c) throw new Error("the link is incomplete: it needs both the nonce (n=…) and the CLI key (c=…)");
  const nonce = fromHex(n);
  if (nonce.length !== 16) throw new Error("the enrollment nonce must be 16 bytes of hex");
  const cliPublic = fromHex(c);
  if (cliPublic.length !== 65 || cliPublic[0] !== 0x04) {
    throw new Error("the CLI public key must be a 65-byte uncompressed P-256 point (hex)");
  }
  return { nonce, cliPublicSec1: cliPublic };
}

/** Run the whole ceremony; returns the enrollment blob object. */
export async function runEnrollment({ nonce, cliPublicSec1 }, options = {}) {
  // 1. The page's encryption identity.
  const { privateNonExportable, publicSec1 } =
    options.generateKey?.() ?? (await generateEnrollmentKey());

  // 2. The passkey (the human-present factor).
  const created = await (options.createCredential ?? createPasskey)();
  const parsed = parseAttestationObject(new Uint8Array(created.response.attestationObject));

  // 3. The binding assertion: the passkey signs SHA-256(nonce ‖ pub).
  const challenge = await sha256(concat(nonce, publicSec1));
  const assertion = await (options.assert ?? assertWithPasskey)(parsed.credentialId, challenge);

  // 4. Store and produce the paste-back blob. The record is keyed by the
  //    page's own encryption key id — the rkid requests to this key carry.
  const ownKid = await kid("enc", publicSec1);
  const record = {
    rkid: ownKid,
    label: options.label ?? `cli-${await kid("enc", cliPublicSec1)}`,
    encPrivate: privateNonExportable,
    encPub: publicSec1,
    cliPublicSec1,
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
    record,
  };
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
        const { blob } = await runEnrollment(parsed);
        $("blob").value = JSON.stringify(blob);
        $("blob-wrap").hidden = false;
        $("status").textContent =
          "Done on this side. Paste the blob into the terminal waiting for it.";
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

main();
