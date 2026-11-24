// DOM-level regression tests for the enrollment page wiring (main()).
//
// The page is deliberately dependency-free, so there is no jsdom: these
// tests hand-roll a minimal DOM stub, install it as globals, and only
// then dynamically import js/enroll.js — whose module top-level runs
// main() when it sees a `document`. This covers the wiring the pure
// protocol suite cannot: the link-id display (the stale-link warning)
// and the cached-HTML fallback where #link-id does not exist.
//
// Run from tests/run.mjs; browser runs (test.html) never load this file.

import { join } from "node:path";

function makeElement() {
  return {
    hidden: true,
    disabled: true,
    textContent: "",
    value: "",
    listeners: {},
    children: [],
    addEventListener(type, fn) {
      (this.listeners[type] ??= []).push(fn);
    },
    setAttribute() {},
    prepend(child) {
      this.children.unshift(child);
    },
  };
}

function installDom({ withLinkId = true, hash = "" } = {}) {
  const elements = {
    "link-ok": makeElement(),
    start: makeElement(),
    status: makeElement(),
    ...(withLinkId ? { "link-id": makeElement() } : {}),
  };
  globalThis.document = {
    getElementById: (id) => elements[id] ?? null,
    createElement: makeElement,
  };
  globalThis.window = { isSecureContext: true };
  globalThis.location = { hostname: "page.test", hash };
  return elements;
}

function uninstallDom() {
  delete globalThis.document;
  delete globalThis.window;
  delete globalThis.location;
}

export async function runDomTests() {
  const results = [];
  const test = async (name, fn) => {
    try {
      await fn();
      results.push({ ok: true, name });
    } catch (e) {
      results.push({ ok: false, name, error: String(e && e.message ? e.message : e) });
    }
  };
  const assert = (cond, msg) => {
    if (!cond) throw new Error(msg || "assertion failed");
  };

  // A valid enrollment fragment: 16-byte nonce + two 65-byte uncompressed
  // points (parseEnrollFragment checks shape, not curve membership).
  const nonceHex = "0a0b0c0d" + "11".repeat(12);
  const pub = "04" + "22".repeat(64);
  const hash = `#n=${nonceHex}&c=${pub}&s=${pub}`;

  await test("dom: main() shows the link id derived from the nonce", async () => {
    const elements = installDom({ withLinkId: true, hash });
    // Cache-bust so each test gets a fresh module evaluation (main() runs
    // at import time) and the elements dict of THIS installDom is used.
    await import(`../js/enroll.js?dom=${Date.now()}-${Math.random()}`);
    assert(elements["link-ok"].hidden === false, "link-ok must be unhidden");
    assert(
      elements["link-id"].textContent === "0a0b0c0d",
      `link id: got '${elements["link-id"].textContent}', want '0a0b0c0d'`,
    );
    assert(elements.start.disabled === false, "start button must be enabled");
    assert(
      (elements.start.listeners.click?.length ?? 0) === 1,
      "start click handler must be attached",
    );
    uninstallDom();
  });

  await test("dom: cached enroll.html without #link-id still starts enrollment", async () => {
    const elements = installDom({ withLinkId: false, hash });
    await import(`../js/enroll.js?dom=${Date.now()}-${Math.random()}`);
    assert(elements["link-ok"].hidden === false, "link-ok must be unhidden");
    assert(elements.start.disabled === false, "start button must be enabled");
    assert(
      (elements.start.listeners.click?.length ?? 0) === 1,
      "start click handler must be attached despite the missing #link-id",
    );
    assert(!("link-error" in elements), "no error may be surfaced for the missing element");
    uninstallDom();
  });

  await test("dom: an incomplete fragment surfaces the link error", async () => {
    const elements = installDom({ withLinkId: true, hash: "#n=abcd" });
    elements["link-error"] = makeElement();
    await import(`../js/enroll.js?dom=${Date.now()}-${Math.random()}`);
    assert(
      elements["link-error"].hidden === false && elements["link-error"].textContent !== "",
      "the fragment error must be visible",
    );
    assert(elements.start.disabled === true, "start must stay disabled on a bad link");
    uninstallDom();
  });

  // The response label, created when cached HTML predates it: a
  // versionless, file-by-file deploy can serve the new approve.js
  // against old markup for a few minutes (passlane#72, Copilot review).
  // approve.js's main() runs at import but returns early on the empty
  // hash; the export is what this exercises.
  await test("dom: the response label is created when cached HTML lacks it", async () => {
    const elements = installDom({ withLinkId: false, hash: "" });
    const approve = await import(`../js/approve.js?dom=${Date.now()}-${Math.random()}`);
    elements["response-wrap"] = makeElement();
    const created = approve.ensureResponseLabel();
    assert(created !== null, "a label is created");
    assert(
      elements["response-wrap"].children[0] === created,
      "prepended into the response wrap",
    );
    assert(created.id === "response-label" && created.className === "note");
    // Already present: the same element comes back, nothing re-created.
    elements["response-label"] = created;
    assert(approve.ensureResponseLabel() === created, "idempotent");
    // And with no wrap at all there is nothing to label — not a throw.
    const bare = installDom({ withLinkId: false, hash: "" });
    const again = await import(`../js/approve.js?dom2=${Date.now()}-${Math.random()}`);
    assert(again.ensureResponseLabel() === null, "no wrap: null, no crash");
    uninstallDom();
  });

  return { passed: results.filter((r) => r.ok).length, failed: results.filter((r) => !r.ok).length, results };
}
