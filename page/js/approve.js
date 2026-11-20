// The approval page: show what the CLI asked, let the human decide, and
// produce the signed, encrypted reply to paste back into the terminal.
//
// Fragment: #<envelope base64url> — the request travels entirely in the
// fragment; the page host never receives it (SPEC §1/§6).
//
// The request is HPKE-sealed to the page's pinned ECDH key (routed by the
// header's rkid); the reply is sealed back to the CLI's key and signed
// with a WebAuthn assertion over the reply envelope's transcript
// (signature kind 2, SPEC §3) — the passkey is the human-present factor,
// the ECDH key the confidentiality, and enrollment bound the two.

import {
  MSG,
  attachAssertion,
  assertionToJson,
  buildApprovalResponse,
  parseEnvelopeB64Url,
} from "./envelope.js";
import { hpkeOpen, hpkeSeal, kid } from "./hpke.js";
import { getApprover } from "./keystore.js";
import { ecdsaDerToRaw, fromUtf8, nowSeconds, toBase64Url } from "./lib.js";

const $ = (id) => document.getElementById(id);

/**
 * Verify the request envelope's sender signature (SPEC §3: ECDSA P-256
 * over the transcript). HPKE base mode encrypts but does not authenticate
 * the sender, so the page must check this before showing anything
 * actionable: only the CLI whose verifying key was pinned at enrollment
 * can have produced the request. A forged envelope (sealed to the page's
 * public key with a doctored body) fails here.
 */
export async function verifySenderSignature(envelope, cliSigPubSec1) {
  if (envelope.sigKind !== 1) {
    throw new Error(`unexpected signature kind ${envelope.sigKind}; CLI requests are ECDSA-signed`);
  }
  const key = await crypto.subtle.importKey(
    "raw",
    cliSigPubSec1,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  const ok = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    ecdsaDerToRaw(envelope.sig),
    envelope.transcript,
  );
  if (!ok) {
    throw new Error("the request is not signed by the CLI key enrolled on this device");
  }
}

/** Describe the operation for the approval card. */
export function describeBody(body) {
  if (body.type !== "approval_request") throw new Error(`not an approval request: ${body.type}`);
  const op =
    body.operation.kind === "reveal"
      ? `Reveal the ${body.operation.field} of '${body.operation.entry}'`
      : body.operation.kind === "unlock"
        ? "Supply the challenge-response that unlocks the vault"
        : `Allow a save (${body.operation.kind})`;
  const scope =
    body.scope.kind === "once" ? "single approval" : `reusable for ${body.scope.seconds}s`;
  return { op, scope, requester: body.requester, vault: body.vault_name };
}

/** Build the page's decision envelope and assert it with the passkey. */
export async function respond({ envelope, record, decision, reason, assert }) {
  const myKid = record.rkid;
  const cliKid = await kid("enc", record.cliPublicSec1);
  const built = await buildApprovalResponse({
    rid: envelope.header.rid,
    senderKid: myKid,
    recipientKid: cliKid,
    decision:
      decision === "allow"
        ? "Allow"
        : { Deny: reason ? { reason } : {} },
    scope: { kind: "once" },
    recipientPublicSec1: record.cliPublicSec1,
    seal: hpkeSeal,
    now: nowSeconds(),
  });

  // The passkey signs the transcript challenge: user presence is the
  // approval itself.
  const assertionResponse = await assert(record.credentialId, built.challenge);
  const assertionJson = assertionToJson({
    authenticator_data: toBase64Url(new Uint8Array(assertionResponse.authenticatorData)),
    client_data_json: toBase64Url(new Uint8Array(assertionResponse.clientDataJSON)),
    signature: toBase64Url(new Uint8Array(assertionResponse.signature)),
  });
  const finalBytes = attachAssertion(built.transcript, assertionJson);
  return toBase64Url(finalBytes);
}

// -- page wiring --------------------------------------------------------------

async function assertWithPasskey(credentialId, challenge) {
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: fromChallenge(challenge),
      allowCredentials: [{ type: "public-key", id: credentialId }],
      userVerification: "preferred",
    },
  });
  if (!assertion) throw new Error("no assertion was produced (the approval needs the passkey)");
  return assertion.response;
}

/** The transcript challenge string is base64url; WebAuthn wants raw bytes. */
function fromChallenge(challengeB64Url) {
  // Local decode avoids importing a base64url decoder for one call.
  const binary = atob(challengeB64Url.replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

async function main() {
  const fragment = decodeURIComponent(location.hash.replace(/^#/, ""));
  if (!fragment) {
    $("status").textContent =
      "Nothing to approve: open this page through the link passlane printed (the request rides the link's #fragment).";
    return;
  }
  let envelope;
  try {
    envelope = parseEnvelopeB64Url(fragment);
  } catch (e) {
    $("status").textContent = `The link does not carry a valid request envelope: ${e.message}`;
    return;
  }

  const record = await getApprover(envelope.header.rkid);
  if (!record) {
    $("status").textContent =
      `This device holds no key for request recipient '${envelope.header.rkid}'. ` +
      "Approving needs the device and browser profile that enrolled (passlane approvals enroll).";
    return;
  }

  let plaintext;
  try {
    plaintext = await hpkeOpen(
      envelope.enc,
      record.encPrivate,
      record.encPub,
      MSG.APPROVAL_REQUEST,
      envelope.aad,
      envelope.ct,
    );
  } catch {
    $("status").textContent =
      "Could not decrypt the request with the enrolled key — it was not sealed to this device's key.";
    return;
  }

  // Authenticate the sender before treating the (decrypted) body as
  // actionable: the signature binds the displayed operation to the CLI
  // that signed the exact envelope bytes.
  try {
    await verifySenderSignature(envelope, record.cliSigPubSec1);
  } catch (e) {
    $("status").textContent =
      `Refused: ${e.message}. Do not approve a request that fails this check.`;
    return;
  }
  // Display identity: the sender key id must match the enrolled CLI.
  const expectedSkid = await kid("enc", record.cliPublicSec1);
  if (envelope.header.skid !== expectedSkid) {
    $("status").textContent =
      `Refused: the request claims sender '${envelope.header.skid}' but the enrolled ` +
      `CLI is '${expectedSkid}'.`;
    return;
  }

  const body = JSON.parse(fromUtf8(plaintext));
  const view = describeBody(body);
  const fresh = nowSeconds() < envelope.header.exp;
  if (!fresh) {
    $("approve").disabled = true;
    $("deny").disabled = true;
  }
  const ttlLeft = Math.max(0, envelope.header.exp - nowSeconds());

  $("request").hidden = false;
  $("op").textContent = view.op;
  $("vault").textContent = view.vault;
  $("requester").textContent = view.requester;
  $("scope").textContent = view.scope;
  $("expires").textContent = fresh
    ? `expires in ${ttlLeft}s (link transport — no proximity signal)`
    : "EXPIRED — re-run the command to emit a fresh request";
  if (body.operation.kind === "unlock") {
    const note = document.createElement("p");
    note.className = "note";
    note.textContent =
      "Unlock requests need the HMAC answer from the passlane app (issue #53); approving here records consent only.";
    $("request").appendChild(note);
  }

  const decide = async (decision, reason) => {
    // Recheck the clock at decision time: a request opened before expiry
    // must not stay approvable past its deadline (the CLI would refuse
    // the answer anyway).
    if (nowSeconds() >= envelope.header.exp) {
      $("approve").disabled = true;
      $("deny").disabled = true;
      $("status").textContent =
        "The request expired while this page was open; nothing was answered. Re-run the command to emit a fresh request.";
      return;
    }
    try {
      $("approve").disabled = true;
      $("deny").disabled = true;
      $("status").textContent = "Confirm with the passkey…";
      const blob = await respond({ envelope, record, decision, reason, assert: assertWithPasskey });
      $("response").value = blob;
      $("response-wrap").hidden = false;
      $("status").textContent =
        decision === "allow"
          ? "Approved. Paste the response into the terminal (Universal Clipboard or copy) and re-run the command."
          : "Denied. Paste the response into the terminal to record the refusal.";
    } catch (e) {
      $("status").textContent = `Could not answer: ${e.message}`;
      $("approve").disabled = false;
      $("deny").disabled = false;
    }
  };

  $("approve").addEventListener("click", () => decide("allow"));
  $("deny").addEventListener("click", () => decide("deny", $("reason").value || undefined));
}

main();
