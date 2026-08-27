/**
 * Module 2 defense workshop (m2.l4) end to end.
 *
 * Loads committed sensor fixtures compiled from the exact starter text and
 * drives the debugger command surface: telemetry sampling, self-watchdog
 * deadline alarms, and the clean-world baseline sweep (!dpcstat / !irql -a /
 * !pgscan / !dpcwatchdog).
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
import { getScenario, KFWARZ_VICTIM_DPC,
  KFWARZ_VICTIM_ROUTINE } from "../src/scenarios.js";
import { createCommands } from "../src/debugger.js";

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

async function bootScenario(id, backend = "js") {
  return getScenario(id).boot({
    makeBackend: (mem) => backend === "unicorn"
      ? createUnicornBackend(mem)
      : new JsInterpreter(mem),
    loadTables,
  });
}

function capture(kernel) {
  let lines = [];
  const commands = createCommands(kernel);
  const exec = async (line) => {
    lines = [];
    const [cmd, ...args] = line.trim().split(/\s+/);
    await commands[cmd]?.(args, (text) => lines.push(text), {});
    return lines.join("\n");
  };
  return { exec };
}

async function runSensor(kernel, objBytes, labId, backend = "js") {
  const loaded = loadCompiledDriver(kernel, objBytes, { labId });
  const regPathBuf = kernel.allocPool(0x100);
  kernel.mem.writeUtf16(regPathBuf,
    "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\" + loaded.name);
  const r = kernel.callFunctionSeh(loaded.entry, [loaded.drvRec.va, regPathBuf],
    loaded.image);
  assert.equal(r.status, "ok", `[${backend}] sensor faulted: ${r.error?.message}`);
  return loaded;
}

// ------------------------------------------------------------ m2.l4 lab1

test("telemetry sensor samples IRQL + queue depth on the pinned world (both backends)", async () => {
  for (const be of ["js", "unicorn"]) {
    const { kernel } = await bootScenario("irql-dpc", be);
    const obj = new Uint8Array(await readFile(FIX("kfsentinel_telemetry.obj")));
    await runSensor(kernel, obj, "m2.l4.lab1", be);
    const log = kernel.dbgLog.join("\n");

    assert.match(log, /SENTINEL-TELEMETRY: sampled IRQL = 15 queue-depth = 1/,
      `[${be}] sample`);
    assert.match(log, /stranded work on a pinned core/, `[${be}] anomaly`);
    assert.equal(kernel.currentIrql, 2, `[${be}] ladder restored`);

    // repair completes the classic flow: stranded DPC finally runs
    kernel.retireQueuedDpcs();
    assert.match(kernel.dbgLog.join("\n"), /kfdpc: secret=kf-dpc-drain-ok/,
      `[${be}] drain payoff`);
    void log;
  }
});

// ------------------------------------------------------------ m2.l4 lab2

for (const be of ["js", "unicorn"]) {
  test(`self-watchdog deadline alarm fires under lockdown (${be})`, async () => {
    const { kernel } = await bootScenario("irql-attackers", be);
    const obj = new Uint8Array(await readFile(FIX("kfdeadline.obj")));
    await runSensor(kernel, obj, "m2.l4.lab2", be);
    const log = kernel.dbgLog.join("\n");

    assert.match(log, /SENTINEL-WD: cores pinned; core 1 at IRQL 2/, `[${be}] pin`);
    // watchdog DPC targeted at a pinned core cannot retire in time
    assert.match(log, /DEADLINE-MISSED/, `[${be}] verdict`);
    assert.match(log, /secret=kf-deadline-ok/, `[${be}] secret`);

    // after release the world heals: cores idle, lock DPCs retired
    assert.equal(kernel.cpuIrql(1), 0, `[${be}] core 1 released`);
    assert.equal(kernel.cpuIrql(3), 0, `[${be}] core 3 released`);
  });
}

// ------------------------------------------------------------ m2.l4 lab3

test("baseline forensics sweep: healthy world reads clean on every defender surface", async () => {
  const { kernel } = await bootScenario("irql-attackers");
  const c = capture(kernel);

  const stat = await c.exec("!dpcstat");
  assert.match(stat, /queue depth: 1 total, 1 pending/);
  assert.match(stat, /timers: 1 armed/);
  assert.match(stat, /period=5 dpc=0xfffff8055a701000/, "heartbeat timer bound to victim");
  assert.doesNotMatch(stat, /anomaly:/, "no aged-DPC anomalies");

  const all = await c.exec("!irql -a");
  assert.match(all, /core 0: 2 \(DISPATCH_LEVEL\)/);
  assert.match(all, /core 1: 0 \(PASSIVE_LEVEL\)/);
  assert.doesNotMatch(all, /pinned/);

  const scan = await c.exec("!pgscan");
  assert.match(scan, /CR0: 0x80010031 \(WP=1\)/);
  assert.match(scan, /protected ranges: clean/);
  assert.match(scan, /deferred routines: all inside loaded modules/);
  assert.doesNotMatch(scan, /HIJACK\?|MODIFIED/);

  const wd = await c.exec("!dpcwatchdog");
  assert.match(wd, /within budget/);
});

test("aged-DPC anomaly surfaces when the executing core strands the queue", async () => {
  const { kernel } = await bootScenario("irql-attackers");
  // simulate m2.l1-style residency: raise core 0 and let ticks pass
  kernel.raiseIrql(15);
  kernel.advanceTicks(40);
  const c = capture(kernel);
  const stat = await c.exec("!dpcstat");
  assert.match(stat, /older than 10 ticks \(starvation signature\)/);
  const wd = await c.exec("!dpcwatchdog");
  assert.match(wd, /BUGCHECK 0x133/);
});
