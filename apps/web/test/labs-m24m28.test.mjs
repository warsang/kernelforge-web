/**
 * Headless e2e for the linux-internals track (m24-m28): every lab boots and
 * accepts its answers. Elf labs drive the real inspector console; quiz labs
 * grade through the same sha256 flag pipeline as the browser.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { Window } from "happy-dom";

import { catalog } from "@kernelforge/course-content";
import { checkFlag } from "@kernelforge/lab-runtime";
import { getScenario, scenarios } from "../src/scenarios.js";
import { createElfInspector } from "../src/elf/elfinspector.js";

const NEW = ["m24", "m25", "m26", "m27", "m28"];

const ANSWERS = {
  // m24.l1.lab1 — hello.elf facts
  "m24.l1.f1": "0x400100",
  "m24.l1.f2": "256",
  "m24.l1.f3": "0x400130",
  "m24.l1.f4": "56",
  "m24.l1.f5": "ei_data",
  "m24.l1.f6": "0x20",
  // m25.l1 — infected.elf + infection lore
  "m25.l1.f1": "0x400100",
  "m25.l1.f2": "1132",
  "m25.l1.f3": "pt_note",
  "m25.l1.f4": "0xc000000",
  "m25.l1.f5": "ff e0",
  "m25.l1.f6": "go",
  // m26.l1 — tiny.elf + fileless toolbox
  "m26.l1.f1": "0",
  "m26.l1.f2": "0x464c457f",
  "m26.l1.f3": "57",
  "m26.l1.f4": "313",
  "m26.l1.f5": "319",
  "m26.l1.f6": "execve",
  // m27.l1 — kernel survey
  "m27.l1.f1": "el0_svc_common",
  "m27.l1.f2": "proc_read",
  "m27.l1.f3": "12288",
  "m27.l1.f4": "512",
  "m27.l1.f5": "exitbootservices",
  "m27.l1.f6": "3",
  "m27.l1.f7": "granular aslr",
  // m28.l1 — obfuscation gauntlets
  "m28.l1.f1": "8",
  "m28.l1.f2": "2",
  "m28.l1.f3": "xlatb",
  "m28.l1.f4": "carry flag",
  "m28.l1.f5": "rsp",
  "m28.l1.f6": "(x+5)*3",
};

function collect() {
  return catalog.modules.filter((m) => NEW.includes(m.id));
}

test("linux-internals modules are registered with elf/quiz labs", () => {
  const mods = collect();
  assert.equal(mods.length, 5);
  for (const m of mods) {
    for (const l of m.lessons) {
      assert.ok(l.labs.length >= 1, `${m.id} has no labs`);
      for (const lab of l.labs) {
        assert.ok(["elf", "quiz"].includes(lab.kind), `${lab.id}: kind ${lab.kind}`);
        if (lab.kind === "elf") {
          assert.ok(scenarios[lab.scenario], `${lab.id}: scenario ${lab.scenario} missing`);
        }
      }
    }
  }
});

for (const scenarioId of ["elf-hello", "elf-infected", "elf-weird", "elf-tiny"]) {
  test(`${scenarioId} boots into a parsed session`, async () => {
    const s = await getScenario(scenarioId).boot({});
    assert.equal(s.kind, "elf");
    assert.ok(s.parsed.ehdr);
    assert.equal(s.bytes.length, s.parsed.size);
  });
}

function capture() {
  const lines = [];
  return {
    lines,
    write: (text) => lines.push(String(text)),
    scrollTop: 0,
    scrollHeight: 0,
  };
}

async function driveInspector(scenarioId, commands) {
  const session = await getScenario(scenarioId).boot({});
  const out = capture();
  const dbg = createElfInspector(session, out);
  dbg.banner();
  for (const cmd of commands) await dbg.exec(cmd);
  return { session, out: out.lines.join("\n") };
}

test("inspector console surfaces hello.elf's layout facts", async () => {
  const { out } = await driveInspector("elf-hello", [
    "info", "ehdr", "phdr", "shdr", "sym", "hex 0x100 32", "bogus",
  ]);
  assert.match(out, /ET_EXEC/);
  assert.match(out, /entry 0x400100/);
  assert.match(out, /kf_greet/);
  assert.match(out, /\.text/);
  assert.match(out, /unknown command "bogus"/);
  assert.match(out, /no parser anomalies/);
});

test("inspector console exposes the infected.elf parasite", async () => {
  const { out } = await driveInspector("elf-infected", [
    "info", "phdr", "str", "hex 0x46c 32", "note",
  ]);
  assert.match(out, /PT_LOAD.*0xc00046c/s); // far-VA outlier
  assert.match(out, /KFPARASITE/);
  assert.match(out, /48 b8 00 01/); // movabs rax, OEP (row-split imm)
  assert.match(out, /clean parse|no parser anomalies/);
});

test("inspector console reports weird.elf anomalies and tiny.elf aliasing", async () => {
  const weird = await driveInspector("elf-weird", ["info", "shdr", "note"]);
  assert.match(weird.out, /extended numbering, real count 6/);
  assert.match(weird.out, /SHN_XINDEX/);

  const tiny = await driveInspector("elf-tiny", ["info", "phdr", "hex 0 64", "note"]);
  assert.match(tiny.out, /aliases the Ehdr itself/);
  assert.match(tiny.out, /unknown\(0x464c457f\)/);
  assert.match(tiny.out, /^00000000: 7f 45 4c 46/m);
});

test("every new lab's flags grade their pinned answers (and reject junk)", async () => {
  let graded = 0;
  for (const m of collect()) {
    for (const l of m.lessons) {
      for (const lab of l.labs) {
        // elf-labs boot their scenario before grading in the UI; mirror that
        if (lab.kind === "elf") await getScenario(lab.scenario).boot({});
        for (const f of lab.flags) {
          const answer = ANSWERS[f.id];
          assert.ok(answer, `no ground truth for ${f.id}`);
          assert.equal(await checkFlag(answer, f), true, `${f.id} rejects ${answer}`);
          assert.equal(await checkFlag(`  ${answer.toUpperCase()} `, f), true,
            `${f.id} should normalize case/space`);
          assert.equal(await checkFlag("definitely-wrong", f), false);
          graded++;
        }
      }
    }
  }
  assert.equal(graded, 31);
});

test("elf lab card boots in a DOM and the inspector banner renders", async () => {
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

  const { createServer } = await import("vite");
  const path = await import("node:path");
  const { fileURLToPath } = await import("node:url");
  const webRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

  const server = await createServer({
    root: webRoot,
    server: { middlewareMode: true },
    logLevel: "error",
  });
  try {
    await server.ssrLoadModule("/src/main.js");
    await new Promise((r) => setTimeout(r, 50));

    const doc = window.document;
    const btn = [...doc.querySelectorAll("button.lesson")]
      .find((b) => b.textContent.includes("From \\x7fELF to execution"));
    assert.ok(btn, "m24 lesson button not rendered");
    btn.click();
    await new Promise((r) => setTimeout(r, 50));

    const body = doc.body.textContent;
    assert.ok(body.includes("Dissect hello.elf"), "elf lab card missing");
    assert.ok(doc.querySelectorAll(".flag").length >= 3, "elf lab flag prompts missing");

    // boot the elf lab: inspector banner + help flow through the console
    const bootBtn = [...doc.querySelectorAll("button")]
      .find((b) => b.textContent === "Boot / Reset");
    assert.ok(bootBtn, "boot button missing on elf lab");
    bootBtn.click();
    await new Promise((r) => setTimeout(r, 100));
    const text = doc.querySelector(".console")?.textContent ?? "";
    assert.ok(!text.includes("boot failed"), `boot failed: ${text.slice(0, 200)}`);
    assert.match(text, /elf-inspector: hello \(1132 bytes\)/);
  } finally {
    await server.close();
  }
});
