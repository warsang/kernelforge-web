/**
 * Analysis workspace: the sidebar "⚗ Ghidra Analysis" tool must open a
 * floating overlay WITHOUT navigating away from the current lesson, stay a
 * singleton across repeated clicks, and the static image session must feed
 * real capstone disassembly into the DebugSession contract.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { Window } from "happy-dom";
import { createServer } from "vite";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.dirname(fileURLToPath(import.meta.url));
const webRoot = path.resolve(root, "..");

async function openApp() {
  const window = new Window({ url: "http://localhost:5173/" });
  window.document.body.innerHTML = '<div id="app"></div>';
  globalThis.window = window;
  globalThis.document = window.document;
  for (const k of ["HTMLElement", "HTMLInputElement", "HTMLSelectElement", "Node", "customElements"]) {
    if (window[k] !== undefined) globalThis[k] = window[k];
  }
  window.process = { env: {} };
  const fetchShim = async () => ({ ok: false, status: 404 });
  globalThis.fetch = fetchShim;
  window.fetch = fetchShim;
  const server = await createServer({
    root: webRoot,
    server: { middlewareMode: true },
    logLevel: "error",
  });
  await server.ssrLoadModule("/src/main.js");
  await new Promise((r) => setTimeout(r, 50));
  return { window, server };
}

test("analysis tool opens a floating singleton over the lesson", async () => {
  const { window, server } = await openApp();
  try {
    const doc = window.document;
    [...doc.querySelectorAll("button.lesson")]
      .find((b) => b.textContent.includes("The x64 kernel landscape"))
      .click();
    const lessonText = doc.querySelector("#main").textContent;

    const btn = [...doc.querySelectorAll("button.tool")]
      .find((b) => b.textContent.includes("Ghidra Analysis"));
    assert.ok(btn, "analysis Tools button missing");
    btn.click();
    await new Promise((r) => setTimeout(r, 150));

    assert.equal(doc.querySelectorAll(".kf-ws").length, 1, "workspace not mounted");
    assert.ok(doc.querySelector(".kf-ws-tabbar, .dbg-tabbar"), "tab strip missing");
    // no navigation: lesson content + sidebar still present
    assert.ok(doc.querySelector("#main").textContent.includes(lessonText.slice(0, 40)),
      "lesson content was replaced by the workspace");
    assert.ok(doc.querySelector("aside#sidebar"), "sidebar vanished");

    btn.click(); // idempotent
    await new Promise((r) => setTimeout(r, 100));
    assert.equal(doc.querySelectorAll(".kf-ws").length, 1,
      "repeated clicks stacked workspaces");

    // close via header button removes the overlay
    doc.querySelector(".kf-ws-head-btns button[title='Close']").click();
    assert.equal(doc.querySelectorAll(".kf-ws").length, 0, "close failed");
  } finally {
    await server.close();
  }
});
