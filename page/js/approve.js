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
import { getApprover, heldKey, mutateApprover } from "./keystore.js";
import { ecdsaDerToRaw, fromUtf8, nowSeconds, toBase64Url, toHex } from "./lib.js";
import {
  answerForDecision,
  computeResponse,
  describeOperation,
  dropStagedKey,
  generateSecret,
  importSecret,
  isPhoneKeyOperation,
  keyDecision,
  newKeyRecord,
  promoteStagedKey,
  sheetInstructions,
  sheetText,
  stageKey,
  verifySheetReadBack,
  wipe,
} from "./phonekey.js";

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
      : describeOperation(body.operation, body.vault_name);
  const scope =
    body.scope.kind === "once" ? "single approval" : `reusable for ${body.scope.seconds}s`;
  return { op, scope, requester: body.requester, vault: body.vault_name };
}

/**
 * The challenge of a phone-held-key request, as bytes — or null when the
 * request carries none (then this device cannot answer it usefully).
 */
export function challengeBytes(body) {
  const hex = body.challenge;
  if (!hex || !/^[0-9a-f]{64}$/.test(hex)) return null;
  return new Uint8Array(hex.match(/.{2}/g).map((b) => parseInt(b, 16)));
}

/**
 * What the approval card should do with a phone-held-key request:
 * whether Approve is possible at all, and the note that says why. Pure,
 * so the node tests cover the wiring decisions (the ceremony itself is
 * phonekey.js's, also tested).
 */
export function phoneKeyGate(record, body) {
  const key = heldKey(record, body.vault_id);
  const challenge = challengeBytes(body);
  if (body.operation.kind === "enroll_key") {
    return {
      canApprove: true,
      replacing: key !== null,
      note:
        "This creates the key for the vault on this device and answers with it. " +
        "The recovery sheet is shown first; the request is only answered once its " +
        "secret has been typed back from a copy of the sheet.",
    };
  }
  if (!key) {
    return {
      canApprove: false,
      replacing: false,
      note:
        `This device holds no key for vault '${body.vault_name}' — it cannot answer. ` +
        "(Enroll one with 'passlane hwkey add --phone' on the computer; denying " +
        "records the refusal.)",
    };
  }
  if (!challenge) {
    return {
      canApprove: false,
      replacing: false,
      note: "The request carries no challenge to answer; it cannot open anything. Deny it.",
    };
  }
  return {
    canApprove: true,
    replacing: false,
    note: `Answered with the key this device holds for vault '${body.vault_name}'.`,
  };
}

/**
 * Build the page's decision envelope and assert it with the passkey.
 * For unlock, save and enrollment requests, `answerHex` (the HMAC-SHA1 of
 * the challenge) rides encrypted inside the body — but only for an
 * Allow: a Deny never carries one, so an answer computed before the
 * decision cannot leak through a denial (the requesting computer can
 * decrypt the body whatever the decision says). The body is sealed
 * before the assertion is made, and it leaves this page only together
 * with a valid passkey assertion over it.
 */
export async function respond({ envelope, record, decision, reason, assert, answerHex }) {
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
    response: answerForDecision(decision, answerHex),
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

function askConfirm(question) {
  return confirm(question);
}

/** Show the recovery sheet (its text is the only place the secret lives). */
function showSheet(text, instructions) {
  const sheet = $("sheet");
  sheet.querySelector("pre").textContent = text;
  sheet.querySelector(".instructions").textContent = instructions;
  sheet.hidden = false;
}

function hideSheet() {
  const sheet = $("sheet");
  sheet.querySelector("pre").textContent = "";
  sheet.hidden = true;
}

/**
 * The read-back: the secret typed from a copy of the sheet. The sheet is
 * hidden by then, so what is typed can only come from the copy.
 */
function readSheetSecret() {
  const wrap = $("sheet-readback");
  wrap.hidden = false;
  return new Promise((resolve) => {
    const input = wrap.querySelector("input");
    const done = () => {
      wrap.hidden = true;
      const value = input.value;
      input.value = "";
      resolve(value);
    };
    wrap.querySelector("button").onclick = done;
    input.onkeydown = (e) => {
      if (e.key === "Enter") done();
    };
    input.focus();
  });
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
  const phoneKeyRequest = isPhoneKeyOperation(body.operation);
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

  // A phone-held-key request is answered with the HMAC of its challenge
  // under the key this device holds for that vault. Everything the answer
  // needs is prepared before any button works: without a held key (or
  // without a challenge) there is nothing to approve.
  if (phoneKeyRequest) {
    const gate = phoneKeyGate(record, body);
    const note = document.createElement("p");
    note.className = "note";
    note.textContent = gate.note;
    $("request").appendChild(note);
    if (!gate.canApprove) $("approve").disabled = true;
  }

  /**
   * Enrollment's gate: create the key, show the recovery sheet, and only
   * prepare the answer once the sheet's secret has been typed back from
   * a copy. The key is *staged* beside any held one — an aborted
   * ceremony must not destroy a working factor; the enrollment's own
   * save (answered with the staged key) promotes it. Returns the answer
   * hex, or null when the ceremony stopped itself (the caller stops
   * with it: nothing was answered).
   */
  const runEnrollment = async () => {
    if (heldKey(record, body.vault_id)) {
      const replace = await askConfirm(
        `This device already holds a key for vault '${body.vault_name}'. Replace it? ` +
          "The old key stops working when the enrollment completes; its recovery sheet is the only copy left.",
      );
      if (!replace) {
        $("status").textContent = "Enrollment cancelled; nothing changed.";
        $("approve").disabled = false;
        $("deny").disabled = false;
        return null;
      }
    }
    const secret = generateSecret();
    const secretHex = toHex(secret);
    const hmacKey = await importSecret(secret);
    showSheet(sheetText(body.vault_name, secretHex, Date.now()), sheetInstructions());
    // The sheet's own step: its owner says a copy exists away from this
    // screen, and only then does the sheet hide — the read-back input
    // never shares a screen with the secret it asks for.
    const saved = await askConfirm(
      "Have you saved the recovery sheet away from this screen (printed it, or " +
        "written the secret down)? The sheet hides itself next, and the secret must " +
        "be typed back from your copy.",
    );
    if (!saved) {
      hideSheet();
      $("status").textContent =
        "Enrollment cancelled before the sheet was saved; nothing was created. " +
        "Approve to start again, or deny the request.";
      $("approve").disabled = false;
      $("deny").disabled = false;
      return null;
    }
    hideSheet();
    const readBack = await readSheetSecret();
    // The raw bytes have served their one purpose: the sheet. They do
    // not exist from here on.
    wipe(secret);
    if (!(await verifySheetReadBack(hmacKey, readBack))) {
      $("status").textContent =
        "That does not match the sheet's secret. Nothing was created; try again " +
        "(Approve) or deny the request.";
      $("approve").disabled = false;
      $("deny").disabled = false;
      return null;
    }
    const keyRecord = newKeyRecord(body.vault_id, body.vault_name, hmacKey);
    keyRecord.sheetConfirmedAt = Date.now();
    // Stage it — inside one transaction, against the record as it is on
    // disk now: another tab's enrollment may have completed meanwhile,
    // and its key must survive this one's.
    await mutateApprover(record.rkid, (current) => stageKey(current, body.vault_id, keyRecord));
    return toHex(await computeResponse(hmacKey, challengeBytes(body)));
  };

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
    // An answer exists only for an Allow, and only from here on in this
    // function — a Deny cannot carry one (see respond()).
    let answerHex = null;
    try {
      $("approve").disabled = true;
      $("deny").disabled = true;
      if (decision === "allow" && body.operation.kind === "enroll_key") {
        $("status").textContent = "Waiting for the recovery sheet to be confirmed…";
        answerHex = await runEnrollment();
        if (answerHex == null) {
          // The ceremony stopped itself and re-enabled the buttons;
          // nothing was answered, so nothing leaves this page.
          return;
        }
      } else if (decision === "allow" && phoneKeyRequest) {
        const which = keyDecision(record, body);
        if (which) {
          answerHex = toHex(await computeResponse(which.key.key, challengeBytes(body)));
          if (which.promote || which.dropStaged) {
            await mutateApprover(record.rkid, (current) => {
              let next = current;
              if (which.promote) next = promoteStagedKey(next, body.vault_id);
              if (which.dropStaged) next = dropStagedKey(next, body.vault_id);
              return next;
            });
          }
        }
      }
      $("status").textContent = "Confirm with the passkey…";
      const blob = await respond({
        envelope,
        record,
        decision,
        reason,
        assert: assertWithPasskey,
        answerHex,
      });
      $("response").value = blob;
      $("response-wrap").hidden = false;
      $("status").textContent =
        decision === "allow"
          ? body.operation.kind === "enroll_key"
            ? "Key created and the request approved. Paste the response into the terminal — the computer re-keys the vault with it."
            : "Approved. Paste the response into the terminal (Universal Clipboard or copy) and re-run the command."
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

// Node (the test harness) has no DOM: run only in a browser context.
if (typeof document !== "undefined") main();
