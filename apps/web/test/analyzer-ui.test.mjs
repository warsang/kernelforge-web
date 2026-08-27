/**
 * Analyzer tab: renders from the live app shell, exposes upload + run +
 * IOCTL controls. Pipeline itself is covered by ntsim-analyzer tests.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { Window } from "happy-dom";
import { createServer } from "vite";
import path from "node:path";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const root = path.dirname(fileURLToPath(import.meta.url));
const webRoot = path.resolve(root, "..");

test("analyzer tab renders with upload + ioctl controls", async () => {
  const window = new Window({ url: "http://localhost:5173/" });
  window.document.body.innerHTML = '<div id="app"></div>';
  globalThis.window = window;
  globalThis.document = window.document;
  for (const k of ["HTMLElement", "HTMLInputElement", "HTMLSelectElement", "Node", "customElements"]) {
    if (window[k] !== undefined) globalThis[k] = window[k];
  }
  window.process = { env: {} };

  const fetchShim = async (url) => {
    const u = typeof url === "string" ? url : url.url;
    if (u.includes("/tables/")) {
      try {
        const data = await readFile(path.join(webRoot, "public", u.slice(u.indexOf("/tables/"))));
        return { ok: true, status: 200, json: async () => JSON.parse(data) };
      } catch { /* fallthrough */ }
    }
    return { ok: false, status: 404 };
  };
  globalThis.fetch = fetchShim;
  window.fetch = fetchShim;

  const server = await createServer({ root: webRoot, server: { middlewareMode: true }, logLevel: "error" });
  try {
    await server.ssrLoadModule("/src/main.js");
    await new Promise((r) => setTimeout(r, 50));

    const doc = window.document;
    const analyzerBtn = [...doc.querySelectorAll("button.tool")]
      .find((b) => b.textContent.includes("Driver Analyzer"));
    assert.ok(analyzerBtn, "analyzer sidebar entry missing");

    analyzerBtn.click();
    assert.ok(doc.body.textContent.includes("Driver Analyzer"), "panel not rendered");
    assert.ok(doc.querySelector('input[type="file"]'), "file input missing");
    assert.ok([...doc.querySelectorAll("button")].some((b) =>
      b.textContent.includes("DriverEntry")), "run button missing");
    assert.ok([...doc.querySelectorAll("button")].some((b) =>
      b.textContent.includes("Send IOCTL")), "ioctl button missing");
    assert.ok([...doc.querySelectorAll("button")].some((b) =>
      b.textContent.includes("Auto-drive IRPs")), "auto-drive button missing");
    // engine picker offers hybrid
    const opts = [...doc.querySelectorAll("select option")].map((o) => o.value);
    assert.ok(opts.includes("hybrid"), "hybrid engine option missing");
  } finally {
    await server.close();
  }
});
