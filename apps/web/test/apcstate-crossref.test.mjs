/**
 * EDR cross-reference surface: boot-time ApcState stamping, handle-table
 * enumeration and the debugger's THREAD annotations must stay consistent
 * with the m1.l0 primer lesson transcripts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { StructTables } from "@kernelforge/ntsim/src/structs.mjs";
import { JsInterpreter } from "@kernelforge/ntsim/src/cpu.mjs";
import { getScenario } from "../src/scenarios.js";
import { createCommands } from "../src/debugger.js";

const TABLES_DIR = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../packages/ntsim-assets/data/vergilius/windows-10/22h2"
);

/** Full table set (incl. _KTHREAD/_HANDLE_TABLE) like the browser loader. */
async function loadFullTables() {
  const names = ["_EPROCESS", "_LIST_ENTRY", "_UNICODE_STRING",
    "_KLDR_DATA_TABLE_ENTRY", "_PS_PROTECTION", "_KPCR", "_KPRCB", "_ETHREAD",
    "_KTHREAD", "_HANDLE_TABLE"];
  const tables = new StructTables();
  for (const name of names) {
    const json = JSON.parse(await readFile(path.join(TABLES_DIR, `${name}.json`), "utf8"));
    tables.register(name, json.totalSize, Object.values(json.fieldsByName));
  }
  return tables;
}

async function bootedFull() {
  const scenario = getScenario("boot-default");
  return scenario.boot({
    makeBackend: (mem) => new JsInterpreter(mem), loadTables: loadFullTables,
  });
}

test("!process <pid> 7 annotates threads with ApcState->owner", async () => {
  const { kernel } = await bootedFull();
  const lines = [];
  createCommands(kernel)["!process"](["108", "7"], (t) => lines.push(t));
  // exact rendering promised by the m1.l0 lesson transcript
  assert.match(lines.join("\n"), /Cid 108\.408.*ApcState->lsass\.exe/);
});

test("boot seeds every process with an ApcState.Process back-pointer", async () => {
  const { kernel } = await bootedFull();
  const apcOff = kernel.apcStateOffset();
  assert.ok(apcOff, "22h2 tables carry KTHREAD.ApcState");
  for (const p of kernel.listProcesses()) {
    const thr = kernel.threadsByPid.get(p.pid);
    assert.ok(thr, `${p.name} has a seeded thread`);
    assert.equal(kernel.mem.u64(thr + apcOff), p.eprocess,
      `${p.name}: ApcState.Process points home`);
  }
});
