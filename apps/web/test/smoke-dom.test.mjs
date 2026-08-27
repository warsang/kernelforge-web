/**
 * First-paint smoke test: executes the real app module graph (Vite transform
 * pipeline included) against a DOM. Guards the entire class of "blank page"
 * regressions that pure file-serving checks cannot see.
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

test("app boots: shell renders, lesson opens, lab card present", async () => {
  const window = new Window({ url: "http://localhost:5173/" });
  window.document.body.innerHTML = '<div id="app"></div>';

  // Globals main.js expects at import time
  globalThis.window = window;
  globalThis.document = window.document;
  for (const k of ["HTMLElement", "HTMLInputElement", "HTMLSelectElement", "Node", "customElements"]) {
    if (window[k] !== undefined) globalThis[k] = window[k];
  }
  // Dev flag defaults, mirroring index.html. main.js reads flags via the
  // vite define-replacement of window.process.env; give that object a home.
  window.process = { env: {
    KF_FLAG_M1L1F1: "kfprobe.sys",
    KF_FLAG_M1L1F2: "1312",
    KF_FLAG_M1L2F1: "0xffffa40bc9e74208",
  } };

  // File-backed fetch shim: serves /tables/** from public/ so the scenario's
  // table loader works identically without a network.
  const fetchShim = async (url) => {
    const u = typeof url === "string" ? url : url.url;
    if (u.startsWith("/tables/") || u.includes("/tables/")) {
      const rel = u.slice(u.indexOf("/tables/"));
      try {
        const data = await readFile(path.join(webRoot, "public", rel));
        return { ok: true, status: 200, json: async () => JSON.parse(data) };
      } catch {
        return { ok: false, status: 404 };
      }
    }
    return { ok: false, status: 404 };
  };
  globalThis.fetch = fetchShim;
  window.fetch = fetchShim;

  const server = await createServer({
    root: webRoot,
    server: { middlewareMode: true },
    logLevel: "error",
  });
  try {
    await server.ssrLoadModule("/src/main.js");
    await new Promise((r) => setTimeout(r, 50)); // let async init settle

    const doc = window.document;
    const lessons = [...doc.querySelectorAll("button.lesson")];
    assert.ok(lessons.length >= 6, `expected >=6 lesson buttons (4 modules), got ${lessons.length}`);
    assert.match(doc.querySelector(".points").textContent, /0 flags · 0 pts/);

    // open a lesson with a lab runner (m1.l0 is a reading-only primer) ->
    // lab card with boot controls renders
    [...doc.querySelectorAll("button.lesson")]
      .find((b) => b.textContent.includes("The x64 kernel landscape"))
      .click();
    assert.ok(doc.body.textContent.includes("Boot / Reset"), "lab runner not rendered");
    assert.ok(doc.querySelector("select"), "backend picker missing");
    assert.ok(doc.querySelectorAll(".flag").length >= 2, "flag prompts missing");

    // lesson body renders as HTML from its markdown source (content pipeline)
    const bodyEl = doc.querySelector(".lesson-body");
    assert.ok(bodyEl, "lesson body container missing");
    assert.match(bodyEl.innerHTML, /<h2/, "markdown heading not rendered");
    assert.ok(bodyEl.textContent.includes("PsActiveProcessHead") ||
      bodyEl.textContent.includes("kernel landscape"), "lesson prose missing");
    // legacy placeholder must be gone
    assert.ok(!doc.body.textContent.includes("MDX bodies land"), "stale MDX placeholder shown");
    // answers are plain strings now — no FLAG{} wrapper anywhere in prompts
    for (const p of doc.querySelectorAll(".flag .prompt")) {
      assert.doesNotMatch(p.textContent, /FLAG\{/, "prompt still uses FLAG{} syntax");
    }

    // glossary tooltips: lesson prose is annotated with hoverable terms
    const termEls = [...doc.querySelectorAll(".lesson-body [data-term-key]")];
    assert.ok(termEls.length >= 6, `expected >=6 annotated terms in m1.l1, got ${termEls.length}`);
    assert.ok(
      termEls.some((t) => t.getAttribute("data-term-key") === "hal"),
      "HAL should be annotated as a glossary term",
    );
    // debugger listings must stay untouched
    assert.equal(
      doc.querySelector("pre [data-term-key]"), null,
      "no glossary markers inside code listings",
    );
    // popover opens on hover with the entry's expansion text...
    const halEl = termEls.find((t) => t.getAttribute("data-term-key") === "hal");
    doc.dispatchEvent(new window.MouseEvent("mouseover", { bubbles: true }));
    halEl.dispatchEvent(new window.MouseEvent("mouseover", { bubbles: true }));
    let pop = doc.body.querySelector(".term-popover.open");
    assert.ok(pop, "popover did not open on hover");
    assert.ok(pop.textContent.includes("Hardware Abstraction Layer"), "popover missing HAL expansion");
    // ...and closes again when the pointer leaves
    halEl.dispatchEvent(new window.MouseEvent("mouseout", { bubbles: true, relatedTarget: doc.body }));
    pop = doc.body.querySelector(".term-popover.open");
    assert.ok(!pop || !pop.classList.contains("open"), "popover stayed open after mouseout");

    // Boot on BOTH backends; console must report success, never 'boot failed'
    for (const backend of ["js", "unicorn"]) {
      const sel = doc.querySelector("select");
      sel.value = backend;
      sel.dispatchEvent(new window.Event("change"));
      const bootBtn = [...doc.querySelectorAll("button")].find((b) => b.textContent === "Boot / Reset");
      // emscripten picks its NODE branch when process.versions is visible,
      // then dies on missing require() inside an ESM bundle. Under the DOM
      // shim we want the BROWSER branch even though we run in Node.
      let savedVersions;
      if (backend === "unicorn") {
        savedVersions = globalThis.process.versions;
        Object.defineProperty(globalThis.process, "versions", { value: {}, configurable: true });
      }
      bootBtn.click();
      try {
        await new Promise((r) => setTimeout(r, backend === "unicorn" ? 4000 : 300));
      } finally {
        if (savedVersions) {
          Object.defineProperty(globalThis.process, "versions", { value: savedVersions, configurable: true });
        }
      }
      const text = doc.querySelector(".console").textContent;
      assert.ok(!text.includes("boot failed"), `[${backend}] boot failed: ${text.slice(0, 300)}`);
      assert.ok(
        text.includes("Booted") && text.includes("boot-default") && text.includes(`${backend} backend`),
        `[${backend}] no success line: ${text.slice(0, 200)}`,
      );
    }
  } finally {
    await server.close();
  }
});
