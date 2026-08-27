/**
 * Backend-parity gate for the blog-labs worlds: each NEW scenario must boot
 * AND complete a representative flow under BOTH CPU backends (JsInterpreter
 * reference and Unicorn/QEMU when the vendored wasm is present). Skips
 * loudly-not-silently when the unicorn bundle is unavailable locally.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { StructTables } from "@kernelforge/ntsim/src/structs.mjs";
import { JsInterpreter } from "@kernelforge/ntsim/src/cpu.mjs";
import { getScenario, PAGING_CONST, EDR_CONST, SSDT_CONST } from "../src/scenarios.js";
import { createCommands } from "../src/debugger.js";

const TABLES_DIR = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../packages/ntsim-assets/data/vergilius/windows-10/22h2"
);

async function loadTables() {
  const names = ["_EPROCESS", "_KPROCESS", "_LIST_ENTRY", "_UNICODE_STRING",
    "_KLDR_DATA_TABLE_ENTRY", "_PS_PROTECTION", "_KPCR", "_KPRCB", "_ETHREAD"];
  const tables = new StructTables();
  for (const name of names) {
    const json = JSON.parse(await readFile(path.join(TABLES_DIR, `${name}.json`), "utf8"));
    tables.register(name, json.totalSize, Object.values(json.fieldsByName));
  }
  return tables;
}

let unicornAvailable = false;
let createUnicornBackend = null;
try {
  ({ createUnicornBackend } = await import("@kernelforge/ntsim-unicorn/src/backend.mjs"));
  const mem = new (await import("@kernelforge/ntsim/src/memory.mjs")).SparseMemory();
  const probe = await createUnicornBackend(mem);
  unicornAvailable = !!probe;
} catch {
  unicornAvailable = false;
}

async function bootOn(id, makeBackend) {
  const session = await getScenario(id).boot({ makeBackend, loadTables });
  const lines = [];
  const commands = createCommands(session.kernel);
  return {
    kernel: session.kernel,
    exec: (line) => {
      lines.length = 0;
      const [c, ...a] = line.split(/\s+/);
      commands[c]?.(a, (t) => lines.push(t), {});
    },
    out: () => lines.join("\n"),
  };
}

/** Representative per-world flows; identical steps under both backends. */
const FLOWS = {
  async "paging-walk"(h) {
    const pts = h.kernel.paging;
    const target = pts.findProcess("kftarget");
    const walk = pts.translate(PAGING_CONST.CODE_VA, target);
    assert.equal(walk.ok, true);
    h.exec("!vtop 0x4a1cca43000");
    assert.match(h.out(), /-> 0x/);
    h.kernel.mem.w64(walk.rows.at(-1).entryVa, walk.rows.at(-1).value & ~(1n << 63n));
    h.exec("!vtop 0x4a1cca43000");
    assert.ok(h.kernel.dbgLog.some((l) => l.includes("kf-pt-healed")));
  },
  async "edr-sensor"(h) {
    h.exec(`!notifytest ${EDR_CONST.BLOCKED_NAME}`);
    assert.match(h.out(), /BLOCKED/);
    assert.equal(
      h.kernel.fireProcessNotify(1n, "notepad.exe").blocked, false);
  },
  async "ssdt-hook"(h) {
    h.exec("!ssdt");
    assert.match(h.out(), /HOOKED/);
    assert.equal(h.kernel.restorePrologue("NtOpenProcess"), true);
    h.exec("!ssdt");
    assert.match(h.out(), /no inline detours/);
    void SSDT_CONST;
  },
};

for (const id of Object.keys(FLOWS)) {
  test(`${id}: js backend completes lab flow`, async () => {
    await FLOWS[id](await bootOn(id, (mem) => new JsInterpreter(mem)));
  });

  test(`${id}: unicorn backend ${unicornAvailable ? "completes identical flow" : "(bundle missing -> loud skip)"}`, { skip: !unicornAvailable }, async () => {
    const h = await bootOn(id, (mem) => createUnicornBackend(mem));
    await FLOWS[id](h);
  });
}
