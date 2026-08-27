/**
 * Module 26 (ETW blindfolding) end to end, both halves:
 *  - sogen userland: patch ntdll!EtwEventWrite -> silent gap -> restore
 *  - ntsim kernel: compiled CKCL EnableFlags attack + Sentinel v7 sensor
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { StructTables } from "@kernelforge/ntsim/src/structs.mjs";
import { JsInterpreter } from "@kernelforge/ntsim/src/cpu.mjs";
import { loadCompiledDriver } from "@kernelforge/ntsim-analyzer/src/compiled.mjs";
import { checkFlag } from "@kernelforge/lab-runtime";
import { ETW_USER_CONSTANTS } from "@kernelforge/sogen-runtime";
import { getScenario, KFETW_CKCL } from "../src/scenarios.js";
import { createCommands } from "../src/debugger.js";
import { catalog } from "@kernelforge/course-content";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const TABLES_DIR = path.join(root, "packages/ntsim-assets/data/vergilius/windows-10/22h2");
const FIX = (name) => path.join(root, "packages/compiler-worker/test/fixtures", name);

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

function flagDef(id) {
  for (const m of catalog.modules)
    for (const l of m.lessons ?? [])
      for (const lab of l.labs ?? [])
        for (const f of lab.flags ?? [])
          if (f.id === id) return f;
  throw new Error(`no flag ${id}`);
}

const grade = (answer, id) => checkFlag(answer, flagDef(id));

// ------------------------------------------------------------- userland half

test("etw-blind world: wrapper patch silences events; restore heals the trace", async () => {
  const C = ETW_USER_CONSTANTS;
  const session = await getScenario("etw-blind").boot({});
  const world = session.world;
  assert.equal(session.kind, "etw-blind");
  assert.ok(world.etw);

  // healthy pump
  world.emitEvents(4);
  let trace = world.trace();
  assert.match(trace, /delivered=4 suppressed=0/);
  assert.match(trace, /SauerGame\s+RegHandle=0xe7000001/);

  // blind it
  world.mem.write(C.etwEventWrite, [0x31, 0xc0, 0xc3]);
  assert.equal(world.isPatched(), true);
  world.resetCounters();
  world.emitEvents(8);
  trace = world.trace();
  assert.match(trace, /DROPPED \(wrapper patched\)/);
  assert.match(trace, /delivered=0 suppressed=8/);

  // RegHandle variant is quiet too
  world.mem.w32(C.providerTable, 0);
  world.resetCounters();
  world.mem.write(C.etwEventWrite, C.pristinePrologue.concat([0x33, 0xc0, 0xc3]));
  world.emitEvents(2);
  assert.match(world.trace(), /RegHandle NULL/);

  // full restore (handles + bytes) -> honest end-to-end secret
  world.mem.w32(C.providerTable, C.providers[0].handle);
  world.resetCounters();
  world.emitEvents(8);
  trace = world.trace();
  assert.match(trace, /delivered=8 suppressed=0/);
  assert.match(trace, /secret=kf-etw-restored/);

  // flags
  assert.equal(await grade("0x7749e2a0", "m26.l1.f1"), true, "f1");
  assert.equal(await grade("8", "m26.l1.f2"), true, "f2");
  assert.equal(await grade("kf-etw-restored", "m26.l1.f3"), true, "f3");

  void session;
});

test("sogen console exposes !providers / !etwpump / !etwtrace", async () => {
  const { SogenConsole } = await import("@kernelforge/sogen-runtime");
  const session = await getScenario("etw-blind").boot({});
  const con = new SogenConsole(session.world);
  assert.match(con.execute("!providers"), /EtwEventWrite @ 0x7749e2a0/);
  assert.match(con.execute("!etwpump 5"), /emitted 5/);
  assert.match(con.execute("!etwtrace"), /delivered=5 suppressed=0/);
});

// --------------------------------------------------------------- kernel half

async function bootKernelWorld() {
  return getScenario("etw-kernel").boot({
    makeBackend: (mem) => new JsInterpreter(mem),
    loadTables,
  });
}

async function runFixture(kernel, objBytes, labId) {
  const loaded = loadCompiledDriver(kernel, objBytes, { labId });
  const regPathBuf = kernel.allocPool(0x100);
  kernel.mem.writeUtf16(regPathBuf,
    "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\" + loaded.name);
  return kernel.callFunctionSeh(loaded.entry, [loaded.drvRec.va, regPathBuf],
    loaded.image);
}

test("compiled CKCL tamper blinds telemetry silently", async () => {
  const { kernel } = await bootKernelWorld();
  assert.equal(kernel.mem.u32(KFETW_CKCL + 0x10n), 0xff);

  const obj = new Uint8Array(await readFile(FIX("kfetwtamper.obj")));
  const r = await runFixture(kernel, obj, "m26.l2.lab1");
  assert.equal(r.status, "ok", `fault: ${r.error?.message}`);
  const log = kernel.dbgLog.join("\n");
  assert.match(log, /ATTACK-ETW: CKCL EnableFlags was 0x000000ff/);
  assert.match(log, /now 0x00000000 - gate closed/);

  const c = (() => {
    let lines = [];
    const commands = createCommands(kernel);
    const exec = async (line) => {
      lines = [];
      const [cmd, ...args] = line.trim().split(/\s+/);
      await commands[cmd]?.(args, (t) => lines.push(t), {});
      return lines.join("\n");
    };
    return { exec };
  })();

  const pumpOut = await c.exec("!etwpump 8");
  assert.match(pumpOut, /suppressed: 8/);
  assert.match(kernel.dbgLog.join("\n"), /secret=kf-etw-blinded/);

  const loggers = await c.exec("!etwloggers");
  assert.match(loggers, /\[BLINDED\]/);

  assert.equal(await grade("blinded", "m26.l2.f2"), true, "f2");
  assert.equal(await grade("kf-etw-blinded", "m26.l2.f3"), true, "f3");
});

test("Sentinel v7 convicts drift and re-asserts the baseline", async () => {
  const { kernel } = await bootKernelWorld();
  // pre-blind the world the way the m26.l2 attack left it
  kernel.mem.w32(KFETW_CKCL + 0x10n, 0);

  const obj = new Uint8Array(await readFile(FIX("kfsentinel_v7.obj")));
  const r = await runFixture(kernel, obj, "m26.l3.lab1");
  assert.equal(r.status, "ok", `fault: ${r.error?.message}`);
  const log = kernel.dbgLog.join("\n");
  assert.match(log, /SENTINEL-V7: attesting logger CKCL @ fffff8055a740000/);
  assert.match(log, /EnableFlags DRIFT 0x000000ff -> 0x00000000 \(BLINDED\)/);
  assert.match(log, /baseline re-asserted -> 0x000000ff/);
  assert.match(log, /secret=kf-sentinel-v7-ok/);
  assert.equal(kernel.mem.u32(KFETW_CKCL + 0x10n), 0xff, "sensor repaired");

  assert.equal(await grade("0xff", "m26.l3.f1"), true, "f1");
  assert.equal(await grade("ckcl", "m26.l3.f2"), true, "f2");
  assert.equal(await grade("kf-sentinel-v7-ok", "m26.l3.f3"), true, "f3");
});
