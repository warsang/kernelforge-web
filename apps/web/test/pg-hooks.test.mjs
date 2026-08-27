/**
 * m20 mini-PatchGuard timing lab (#9): the fake PG sweeps protected ranges
 * on the lab clock. Staying hooked across a sweep bugchecks 0x109; hook ->
 * use -> restore -> clean sweep prints the stealth secret.
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

async function loadTables() {
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

const booted = async () => getScenario("pg-hooks").boot({
  makeBackend: (mem) => new JsInterpreter(mem), loadTables,
});

test("pg world arms four regions on a deterministic clock", async () => {
  const { kernel } = await booted();
  const st = kernel.patchguardStatus();
  assert.ok(st, "patchguard must be armed");
  assert.equal(st.regions, 4);
  assert.equal(st.period, 4);
  assert.equal(st.sweeps, 0, "no sweeps before the clock advances");
});

test("staying hooked across a sweep bugchecks CRITICAL_STRUCTURE_CORRUPTION", async () => {
  const { kernel } = await booted();
  const cmds = createCommands(kernel);
  const thunk = kernel.apiThunks.get("PsLookupProcessByProcessId");
  kernel.mem.write(thunk, [0xe9, 0x00, 0x00, 0x00, 0x00]); // detour

  cmds["!dpcpump"](["3"], () => {});
  const st = kernel.patchguardStatus();
  assert.equal(st.sweeps >= 1, true, "a sweep must have run");
  assert.notEqual(st.violatedAt, null, "PG must flag the tamper");
  assert.equal(kernel.bugcheck.code, 0x109n);
  assert.equal(kernel.cpu.halted, true);
});

test("hook -> use -> restore -> clean sweep prints the stealth secret", async () => {
  const { kernel } = await booted();
  const cmds = createCommands(kernel);
  const lines = [];
  const thunk = kernel.apiThunks.get("PsLookupProcessByProcessId");
  const pristine = [...kernel.pristineThunks.get("PsLookupProcessByProcessId")];

  // act 1: install + use
  kernel.mem.write(thunk, [0xe9, 0x00, 0x00, 0x00, 0x00]);
  cmds["!hooktest"](["PsLookupProcessByProcessId", "888"], (t) => lines.push(t));
  assert.match(lines.join("\n"), /STATUS_INVALID_PARAMETER.*PROLOGUE DETOURED/,
    "the hook must be provably live before restoring");

  // act 2+3: restore and cross a sweep
  kernel.mem.write(thunk, pristine);
  cmds["!dpcpump"](["4"], () => {});
  cmds["!pgstatus"]([], (t) => lines.push(t));

  const text = lines.join("\n");
  assert.match(text, /secret=kf-pg-evaded/,
    "clean window must award the stealth secret");
});
