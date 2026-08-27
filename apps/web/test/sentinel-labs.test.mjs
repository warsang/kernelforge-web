/**
 * KF-Sentinel defense labs (m1.l4, m2.l2, m3.l2, m4.l2) end to end.
 *
 * Each test loads the committed fixture (compiled from the EXACT catalog
 * starter source), executes DriverEntry on the real booted world, and
 * asserts the sensor's DbgPrint telemetry: findings + completion secret.
 * These are the same checks the browser compile pane performs.
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

// ------------------------------------------------------------------ m1.l4

test("sentinel-m1 world: kftarget unlinked but carveable; grid page unbacked", async () => {
  const { kernel, kind } = await bootScenario("sentinel-m1");
  assert.equal(kind, "sentinel-m1");
  // list no longer references the victim...
  assert.equal(kernel.findEprocessByPid(888n), null);
  assert.equal(kernel.listProcesses().some((p) => p.pid === 888n), false);
  // ...but its bytes remain in the eproc window
  const victim = kernel.processesByName.get("kftarget.exe");
  assert.ok(victim, "victim EPROCESS must stay addressable for carving");
});

for (const be of ["js", "unicorn"]) {
  test(`sentinel v1 detects DKOM + unbacked exec and prints its secret (${be})`, async () => {
    const { kernel } = await bootScenario("sentinel-m1", be);
    const obj = new Uint8Array(await readFile(FIX("kfsentinel_v1.obj")));
    await runSensor(kernel, obj, "m1.l4.lab1", be);
    const log = kernel.dbgLog.join("\n");

    // sensor 1: list walk count (7 procs - 1 hidden = 6) + carve conviction
    assert.match(log, /SENTINEL-V1: process list walk -> 6 linked entries/, `[${be}] count`);
    assert.match(log, /carve hit 'kftarget\.exe' pid=888/, `[${be}] carve`);
    assert.match(log, /DKOM DETECTED/, `[${be}] verdict`);

    // sensor 2: probe page holds code but belongs to no listed module
    assert.match(log, /UNBACKED EXEC DETECTED/, `[${be}] unbacked`);

    assert.match(log, /secret=kf-sentinel-v1-ok/, `[${be}] secret`);
  });
}

// ------------------------------------------------------------------ m2.l2

test("sentinel v2 samples pinned IRQL, restores ladder, prints secret (both backends)", async () => {
  for (const be of ["js", "unicorn"]) {
    const { kernel } = await bootScenario("irql-dpc", be);
    assert.equal(kernel.currentIrql, 15, `[${be}] fixture IRQL`);
    const obj = new Uint8Array(await readFile(FIX("kfsentinel_v2.obj")));
    await runSensor(kernel, obj, "m2.l2.lab1", be);
    const log = kernel.dbgLog.join("\n");

    assert.match(log, /SENTINEL-WATCHDOG: sampled IRQL = 15/, `[${be}] sample`);
    assert.match(log, /ladder restored to 2/, `[${be}] restore`);
    assert.equal(kernel.currentIrql, 2, `[${be}] model state after lower`);
    assert.match(log, /secret=kf-watchdog-ok/, `[${be}] secret`);
    // the watchdog's repair unblocks the exact attack-lab flow
    kernel.drainDpcs();
    assert.match(kernel.dbgLog.join("\n"), /kfdpc: secret=kf-dpc-drain-ok/,
      `[${be}] stranded DPC released`);
  }
});

// ------------------------------------------------------------------ m3.l2

test("sentinel v3 attests exports and convicts kfhook.sys's detour (both backends)", async () => {
  for (const be of ["js", "unicorn"]) {
    const { kernel } = await bootScenario("api-hook", be);
    assert.equal(kernel.isDetoured("PsLookupProcessByProcessId"), true,
      `[${be}] fixture detour`);
    const obj = new Uint8Array(await readFile(FIX("kfsentinel_v3.obj")));
    await runSensor(kernel, obj, "m3.l2.lab1", be);
    const log = kernel.dbgLog.join("\n");

    assert.match(log, /SENTINEL-ATTEST: PsLookupProcessByProcessId @ [0-9a-f]+ FIRST BYTE 000000e9 != baseline 000000f4 -> INLINE HOOK DETECTED/,
      `[${be}] conviction (%02x pads to 8 digits in the model formatter)`);
    assert.match(log, /SENTINEL-ATTEST: DbgPrint @ .* matches baseline/, `[${be}] clean pass`);
    assert.match(log, /control-flow integrity COMPROMISED\s+secret=kf-attest-ok/,
      `[${be}] secret`);
  }
});

// ------------------------------------------------------------------ m4.l2

test("sentinel v4 sweeps guards and convicts block 0x...1200 (both backends)", async () => {
  for (const be of ["js", "unicorn"]) {
    const { kernel } = await bootScenario("pool-corrupt", be);
    assert.equal(kernel.verifyGuards().length, 1, `[${be}] fixture corruption`);
    const obj = new Uint8Array(await readFile(FIX("kfsentinel_v4.obj")));
    await runSensor(kernel, obj, "m4.l2.lab1", be);
    const log = kernel.dbgLog.join("\n");

    assert.match(log, /block 0 @ fffff90000001000 guard intact/, `[${be}] block0`);
    assert.match(log, /block 1 @ fffff90000001200 guard\[0\]=000000de CORRUPTED/,
      `[${be}] conviction (%02x pads to 8 digits)`);
    assert.match(log, /block 2 @ fffff90000001400 guard intact/, `[${be}] block2`);
    assert.match(log, /secret=kf-poolmon-ok/, `[${be}] secret`);
  }
});
