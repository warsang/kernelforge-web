/**
 * Module-2 compiler lab, end to end: the student's compiled COFF is mapped
 * into the REAL booted world (dump overlay + rebuilt process ring), executed
 * on the emulation engine, hides kftarget.exe, prints the canonical flag
 * address, and shows up in lm.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { SparseMemory } from "@kernelforge/ntsim/src/memory.mjs";
import { JsInterpreter } from "@kernelforge/ntsim/src/cpu.mjs";
import { StructTables } from "@kernelforge/ntsim/src/structs.mjs";
import { loadCompiledDriver } from "@kernelforge/ntsim-analyzer/src/compiled.mjs";
import { getScenario } from "../src/scenarios.js";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const TABLES_DIR = path.join(root, "packages/ntsim-assets/data/vergilius/windows-10/22h2");
const FIXTURE = path.join(root, "packages/compiler-worker/test/fixtures/kfdkom.obj");

async function bootedWithDump() {
  const raw = JSON.parse(await readFile(
    path.join(root, "apps/web/public/dumps/kdemu-win10-19041.json"), "utf8"));
  const tables = new StructTables();
  for (const name of ["_EPROCESS", "_LIST_ENTRY", "_UNICODE_STRING",
    "_KLDR_DATA_TABLE_ENTRY", "_PS_PROTECTION", "_KPCR", "_KPRCB", "_ETHREAD"]) {
    const j = JSON.parse(await readFile(path.join(TABLES_DIR, `${name}.json`), "utf8"));
    tables.register(name, j.totalSize, Object.values(j.fieldsByName));
  }
  const scenario = getScenario("boot-default");
  return scenario.boot({
    makeBackend: (mem) => new JsInterpreter(mem),
    loadTables: async () => tables,
    dumpWorld: raw,
  });
}

test("compiled DKOM driver: real exec -> kftarget hidden -> canonical flag address -> in lm", async () => {
  const session = await bootedWithDump();
  const kernel = session.kernel ?? session.k ?? session;

  // locate target exactly like main.js does
  const kftarget = kernel.processesByName.get("kftarget.exe")
    ?? kernel.findEprocessByPid(888n);
  assert.ok(kftarget, "kftarget.exe missing from booted world");

  const obj = new Uint8Array(await readFile(FIXTURE));
  const loaded = loadCompiledDriver(kernel, obj, { labId: "m1.l2.lab1" });

  const r = kernel.callDriverEntry(loaded.entry, loaded.drvRec.va, 0n);
  assert.equal(r.status, "ok", r.error?.message);
  assert.equal(r.retval, 0n);

  // hidden for real
  assert.equal(kernel.listProcesses().some((p) => p.name === "kftarget.exe"), false);

  // the driver's OWN DbgPrint must carry the canonical links address
  const printed = kernel.dbgLog.find((l) => l.includes("Overwrote _LIST_ENTRY at:"));
  assert.ok(printed, "no DbgPrint from driver");
  assert.match(printed, /ffffa40bc9e74208/, `flag address diverged: ${printed}`);

  // option A: visible to lm
  const entry = kernel.loadedModules.find((m) => m.name === "kf_m1_l2_lab1.sys");
  assert.ok(entry, "driver not registered in loadedModules");
  assert.match(entry.full, /drivers\\kf_m1_l2_lab1\.sys/);
});
