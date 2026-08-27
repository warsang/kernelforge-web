/**
 * Module 25 (architectural hooks) end to end:
 *  - arch-hooks (legacy): LSTAR redirect proves reroute, then mini-PG 0x109
 *  - arch-hardened: HVCI refuses the WRMSR instantly
 *  - Sentinel v6 fixture attests + attributes the redirect
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
import { getScenario, KFARCH_HANDLER } from "../src/scenarios.js";
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

async function boot(id) {
  return getScenario(id).boot({
    makeBackend: (mem) => new JsInterpreter(mem),
    loadTables,
  });
}

function capture(kernel) {
  let lines = [];
  const commands = createCommands(kernel);
  const exec = async (line) => {
    lines = [];
    const [cmd, ...args] = line.trim().split(/\s+/);
    await commands[cmd]?.(args, (t) => lines.push(t), {});
    return lines.join("\n");
  };
  return { exec };
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

test("legacy world: LSTAR redirect reroutes syscalls, PG sweep ends it", async () => {
  const { kernel } = await boot("arch-hooks");
  const c = capture(kernel);

  const before = await c.exec("!syscalltest");
  assert.match(before, /honest completion/);

  // install the redirect through the modeled WRMSR path
  await c.exec("!msr lstar 0xfffff8055a760800");
  assert.equal(kernel.rdmsr(0xC0000082n), KFARCH_HANDLER);

  const after = await c.exec("!syscalltest");
  assert.match(after, /FOREIGN handler executed/);
  assert.match(after, /0xdead0004/);
  assert.match(kernel.dbgLog.join("\n"), /secret=kf-lstar-hijack-ok/);

  // pgscan sees MSR drift
  const scan = await c.exec("!pgscan");
  assert.match(scan, /IA32_LSTAR DRIFT baseline=0x[0-9a-f]+ live=0xfffff8055a760800/);

  // crossing a sweep is fatal
  await c.exec("!dpcpump 4");
  assert.equal(kernel.bugcheck?.code, 0x109n);
  assert.equal(kernel.cpu.halted, true);

  assert.equal(await grade("0xc0000082", "m25.l1.f1"), true, "f1");
  assert.equal(await grade("0xdead0004", "m25.l1.f2"), true, "f2");
  assert.equal(await grade("kf-lstar-hijack-ok", "m25.l1.f3"), true, "f3");
  assert.equal(await grade("109", "m25.l1.f4"), true, "f4");
});

test("hardened world: HVCI refuses the WRMSR with 0x109", async () => {
  const { kernel } = await boot("arch-hardened");
  assert.equal(kernel.hvciMode, true);
  const c = capture(kernel);

  const out = await c.exec("!msr lstar 0xfffff8055a760800");
  void out;
  assert.notEqual(kernel.rdmsr(0xC0000082n), KFARCH_HANDLER, "write refused");
  assert.equal(kernel.bugcheck?.code, 0x109n);
  assert.match(kernel.dbgLog.join("\n"),
    /\[hvci\] WRMSR to protected MSR intercepted/);

  assert.equal(await grade("hvci", "m25.l1.f5"), true, "f5");
});

test("Sentinel v6 attests and attributes the redirect", async () => {
  const { kernel } = await boot("arch-hooks");
  kernel.wrmsr(0xC0000082n, KFARCH_HANDLER); // pre-hooked as after lab 1 act 1

  const obj = new Uint8Array(await readFile(FIX("kfsentinel_v6.obj")));
  const loaded = loadCompiledDriver(kernel, obj, { labId: "m25.l2.lab1" });
  const regPathBuf = kernel.allocPool(0x100);
  kernel.mem.writeUtf16(regPathBuf,
    "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\" + loaded.name);
  const r = await kernel.callFunctionSeh(loaded.entry,
    [loaded.drvRec.va, regPathBuf], loaded.image);
  assert.equal(r.status, "ok", `fault: ${r.error?.message}`);

  const log = kernel.dbgLog.join("\n");
  assert.match(log, /SENTINEL-V6: IA32_LSTAR = fffff8055a760800/);
  assert.match(log, /LSTAR REDIRECTED -> foreign handler fffff8055a760800/);
  assert.match(log, /attributed to kfarch\.sys\+0x800/);
  assert.match(log, /secret=kf-sentinel-v6-ok/);

  assert.equal(await grade("0xfffff8055a760800", "m25.l2.f1"), true, "f6");
  assert.equal(await grade("kfarch.sys", "m25.l2.f2"), true, "f7");
  assert.equal(await grade("kf-sentinel-v6-ok", "m25.l2.f3"), true, "f8");
});
