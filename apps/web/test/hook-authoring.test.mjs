/**
 * m3.l1.lab2 — author-your-own-inline-hook, end to end.
 *
 * The student's compiled COFF (committed fixture, built from the exact
 * catalog starter source with g_TargetFn filled in) is linked + mapped via
 * loadCompiledDriver and executed. Their bytes must write an E9 detour over
 * nt!PsLookupProcessByProcessId such that:
 *   - kernel.isDetoured() flips true (what !hookscan reports)
 *   - pid 888 lookups start failing (the model gates on live prologue bytes)
 *   - the driver's DbgPrint secret lands in the buffer
 *   - the driver shows up under its deterministic lab name
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { JsInterpreter } from "@kernelforge/ntsim/src/cpu.mjs";
import { StructTables } from "@kernelforge/ntsim/src/structs.mjs";
import { createUnicornBackend } from "@kernelforge/ntsim-unicorn/src/backend.mjs";
import { loadCompiledDriver } from "@kernelforge/ntsim-analyzer/src/compiled.mjs";
import { getScenario } from "../src/scenarios.js";
import { createCommands } from "../src/debugger.js";
import { validateDriverSource } from "../src/driver-builder.mjs";
import { module3 } from "@kernelforge/course-content";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const TABLES_DIR = path.join(root, "packages/ntsim-assets/data/vergilius/windows-10/22h2");
const FIXTURE = path.join(root, "packages/compiler-worker/test/fixtures/kfhookauthor.obj");

async function loadTables() {
  const names = ["_EPROCESS", "_LIST_ENTRY", "_UNICODE_STRING",
    "_KLDR_DATA_TABLE_ENTRY", "_PS_PROTECTION", "_KPCR", "_KPRCB", "_ETHREAD"];
  const tables = new StructTables();
  for (const name of names) {
    const json = JSON.parse(await readFile(path.join(TABLES_DIR, `${name}.json`), "utf8"));
    tables.register(name, json.totalSize, Object.values(json.fieldsByName));
  }
  return tables;
}

async function boot(backend = "js") {
  return getScenario("api-hook-blank").boot({
    makeBackend: (mem) => backend === "unicorn"
      ? createUnicornBackend(mem)
      : new JsInterpreter(mem),
    loadTables,
  });
}

test("api-hook-blank boots clean: no detour, no kfhook.sys", async () => {
  const { kernel, kind } = await boot();
  assert.equal(kind, "api-hook-blank");
  assert.equal(kernel.isDetoured("PsLookupProcessByProcessId"), false);
  assert.ok(!kernel.loadedModules.some((m) => m.name === "kfhook.sys"));
});

test("starter source validates against the inline-hook task patterns", () => {
  const lab = module3.lessons[0].labs.find((l) => l.id === "m3.l1.lab2");
  assert.ok(lab, "m3.l1.lab2 missing from catalog");
  const starter = lab.starterFiles[0].content;
  // starter has TODO placeholder -> address pattern matches but E9 write exists;
  // validation only requires structure, not a filled address
  assert.equal(validateDriverSource(starter, "inline-hook").ok, true);
  // garbage must fail
  assert.equal(validateDriverSource("int main(){return 0;}", "inline-hook").ok, false);
});

async function authorHookEndToEnd(backend) {
  const session = await boot(backend);
  const kernel = session.kernel;

  const obj = new Uint8Array(await readFile(FIXTURE));
  const loaded = loadCompiledDriver(kernel, obj, { labId: "m3.l1.lab2" });

  const regPathBuf = kernel.allocPool(0x100);
  kernel.mem.writeUtf16(regPathBuf,
    "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\" + loaded.name);
  const r = kernel.callFunctionSeh(loaded.entry, [loaded.drvRec.va, regPathBuf],
    loaded.image);
  return { kernel, loaded, r };
}

test("compiled hook driver detours the export; suppression + secret + lm (both backends)", async () => {
  for (const be of ["js", "unicorn"]) {
    const { kernel, r } = await authorHookEndToEnd(be);
    assert.equal(r.status, "ok", `[${be}] DriverEntry faulted: ${r.error?.message}`);

    // their bytes flipped the export to detoured — !hookscan will report it
    assert.equal(kernel.isDetoured("PsLookupProcessByProcessId"), true, `[${be}] no detour`);

    // behavior: the modeled lookup suppresses exactly the hidden pid
    const out = kernel.allocPool(8, "out");
    const status = kernel.apiImpls.get("PsLookupProcessByProcessId")(888n, out);
    assert.equal(status, 0xc000000bn, `[${be}] pid 888 not suppressed`);
    const okOut = kernel.allocPool(8, "out");
    assert.equal(kernel.apiImpls.get("PsLookupProcessByProcessId")(108n, okOut), 0n,
      `[${be}] unrelated pids must still resolve`);

    // secret line reached the DbgPrint buffer
    assert.match(kernel.dbgLog.join("\n"), /secret=kf-hook-author-ok/, `[${be}] secret`);

    // visible to lm under the deterministic per-lab name
    const name = "kf_m3_l1_lab2.sys";
    assert.ok(kernel.loadedModules.some((m) => m.name === name), `[${be}] not in lm`);
  }
});

test("!hookscan / !hooktest reflect the student-authored detour", async () => {
  const { kernel } = await authorHookEndToEnd("js");
  const lines = [];
  const commands = createCommands(kernel);
  const w = (t) => lines.push(t);
  const exec = async (l) => {
    const [c, ...a] = l.trim().split(/\s+/);
    await commands[c]?.(a, w, {});
  };
  await exec("!hookscan");
  const t = lines.join("\n");
  assert.match(t, /DETECTED INLINE HOOKS/);
  assert.match(t, /PsLookupProcessByProcessId/);

  lines.length = 0;
  await exec("!hooktest PsLookupProcessByProcessId 888");
  assert.match(lines.join("\n"), /STATUS_INVALID_PARAMETER.*PROLOGUE DETOURED/);
});
