/**
 * m22 EPT-shadow lab (#12): a hypervisor detour exists only in the guest
 * view; the host/EPT side stays pristine. !eptview exposes the split,
 * !eptverify awards the detection secret.
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
    "_KLDR_DATA_TABLE_ENTRY", "_PS_PROTECTION", "_KPCR", "_KPRCB", "_ETHREAD"];
  const tables = new StructTables();
  for (const name of names) {
    const json = JSON.parse(await readFile(path.join(TABLES_DIR, `${name}.json`), "utf8"));
    tables.register(name, json.totalSize, Object.values(json.fieldsByName));
  }
  return tables;
}

const booted = async () => getScenario("ept-shadow").boot({
  makeBackend: (mem) => new JsInterpreter(mem), loadTables,
});

test("guest sees the detour; the host/EPT view stays pristine", async () => {
  const { kernel } = await booted();
  const cmds = createCommands(kernel);
  const thunk = kernel.apiThunks.get("PsLookupProcessByProcessId");

  // guest view (plain memory read) carries the E9 detour...
  assert.equal(kernel.mem.u8(thunk), 0xe9);
  // ...and it is LIVE: pid 888 lookups are suppressed
  const lines = [];
  cmds["!hooktest"](["PsLookupProcessByProcessId", "888"], (t) => lines.push(t));
  assert.match(lines.join("\n"), /STATUS_INVALID_PARAMETER.*PROLOGUE DETOURED/);

  // host view disagrees
  const out = [];
  cmds["!eptview"]([thunk.toString(16)], (t) => out.push(t));
  const text = out.join("\n");
  assert.match(text, /host  \(physical\/EPT\): f4/, "host must show pristine f4");
  assert.match(text, /MISMATCH/);
});

test("!eptverify detects exactly one split range and prints the secret", async () => {
  const { kernel } = await booted();
  const cmds = createCommands(kernel);
  const lines = [];
  cmds["!eptverify"]([], (t) => lines.push(t));
  const text = lines.join("\n");
  assert.match(text, /1\/2 shadowed ranges disagree/);
  assert.match(text, /secret=kf-ept-detected/);

  // control sample: trampoline page views agree — reads counter incremented
  const trampoline = kernel.eptShadow.find((e) => e.name.includes("trampoline"));
  assert.equal(trampoline.reads, 1);
});
