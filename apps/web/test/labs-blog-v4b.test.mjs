/** m14/m16 lab flows: sogen AC gauntlet + fixture pseudocode surface. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { StructTables } from "@kernelforge/ntsim/src/structs.mjs";
import { JsInterpreter } from "@kernelforge/ntsim/src/cpu.mjs";
import { getScenario, EDR_CONST } from "../src/scenarios.js";
import { createCommands } from "../src/debugger.js";

const TABLES_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)),
  "../../../packages/ntsim-assets/data/vergilius/windows-10/22h2");

test("m14 tbm-ac: spoof, clean, setstat, godmode secret", async () => {
  const session = await getScenario("tbm-ac").boot({});
  const c = session.consoleEngine;
  const out = (l) => c.execute(l);
  assert.match(out("!actrace"), /detection vectors \(5\)/);
  out("!spoof-process"); out("!spoof-window");
  // debugger artifacts trip until cleared
  c.w.mem.beingDebugged = 1; c.w.mem.ntGlobalFlag = 0x70;
  assert.match(out("!godmode"), /DENIED/);
  assert.match(c.w.engine.tick().log.join(" "), /debug artifacts/);
  c.w.mem.beingDebugged = 0; c.w.mem.ntGlobalFlag = 0; c.w.mem.debugPort = 0;
  out("!setstat ammo 9999"); out("!setstat health 9999");
  assert.match(out("!godmode"), /GODMODE GRANTED/);
});

test("m16 reversing: !funcs count + !pseudocode fixture render", async () => {
  const tables = new StructTables();
  for (const n of ["_EPROCESS","_KPROCESS","_LIST_ENTRY","_UNICODE_STRING","_KLDR_DATA_TABLE_ENTRY","_PS_PROTECTION","_KPCR","_KPRCB","_ETHREAD"]) {
    const j = JSON.parse(await readFile(path.join(TABLES_DIR, `${n}.json`), "utf8"));
    tables.register(n, j.totalSize, Object.values(j.fieldsByName));
  }
  const s = await getScenario("edr-sensor").boot({
    makeBackend: (mem) => new JsInterpreter(mem), loadTables: async () => tables,
  });
  const cmds = createCommands(s.kernel);
  const lines = []; const w = (t) => lines.push(t);
  const exec = async (l) => {
    lines.length = 0;
    const [c, ...a] = l.split(/\s+/);
    await cmds[c]?.(a, w, {}); // handlers may return promises (e.g. !pseudocode)
  };

  await exec("!funcs kfwatch.sys");
  const gridCount = [...lines.join("\n").matchAll(/0x[0-9a-f]{16}/g)].length;
  assert.ok(gridCount >= 32, `grid functions visible (${gridCount})`);
  assert.match(lines.join("\n"), /kfwatch\.sys — \d+ function\(s\)/);

  await exec(`!pseudocode 0x${EDR_CONST.CALLBACK.toString(16)}`);
  const code = lines.join("\n");
  assert.match(code, /Cs_ProcessNotifyCallback/);
  assert.match(code, /CreationStatus = 0xC0000022/);
  assert.match(code, /\+0x40 \(decimal 64\)/);
});
