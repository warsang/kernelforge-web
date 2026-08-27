/**
 * Module 2 attack workshop (m2.l3) end to end.
 *
 * Loads the committed fixtures (compiled from the EXACT catalog starter
 * source via scripts/gen-m2-fixtures.mjs), executes DriverEntry on the
 * booted warzone world, and drives the real debugger command surface — the
 * same checks the browser compile pane and WinDbg emulator perform.
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
  KFWARZ_CANARY } from "../src/scenarios.js";
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

async function runAttack(kernel, objBytes, labId, backend = "js") {
  const loaded = loadCompiledDriver(kernel, objBytes, { labId });
  const regPathBuf = kernel.allocPool(0x100);
  kernel.mem.writeUtf16(regPathBuf,
    "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\" + loaded.name);
  return kernel.callFunctionSeh(loaded.entry, [loaded.drvRec.va, regPathBuf],
    loaded.image);
}

// ------------------------------------------------------------- attack 1

for (const be of ["js", "unicorn"]) {
  test(`WPOFFx64 patches the canary inside a DISPATCH window (${be})`, async () => {
    const { kernel } = await bootScenario("irql-attackers", be);
    const pristine = Array.from(kernel.mem.read(KFWARZ_CANARY, 8));
    const obj = new Uint8Array(await readFile(FIX("kfwpoff.obj")));
    const r = await runAttack(kernel, obj, "m2.l3.lab1", be);
    assert.equal(r.status, "ok", `[${be}] fault: ${r.error?.message}`);
    const log = kernel.dbgLog.join("\n");

    assert.match(log, /ATTACK-WPOFF: raised to IRQL 2/, `[${be}] raise`);
    assert.match(log, /inside window IRQL=2 WP=0/, `[${be}] wp off`);
    assert.match(log, /window closed; CR0 restored to 0000000080010031 \(IRQL 2\)/,
      `[${be}] restore`);
    assert.equal(kernel.cr0 & 0x10000n, 0x10000n, `[${be}] WP back on`);
    assert.equal(kernel.cr0Trace.length, 2, `[${be}] cr0 history`);

    const live = Array.from(kernel.mem.read(KFWARZ_CANARY, 8));
    assert.deepEqual(live, [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe],
      `[${be}] detour landed`);

    const c = capture(kernel);
    const scan = await c.exec("!pgscan");
    assert.match(scan, /CR0\.WP was cleared 1 time\(s\)/, `[${be}] pgscan cr0`);
    assert.match(scan, /MODIFIED kvmdrv!CanaryPage/, `[${be}] pgscan delta`);
    void pristine;
  });
}

test("the same WPOFFx64 driver dies with 0x109 on the HVCI-hardened world", async () => {
  const { kernel } = await bootScenario("irql-hardened");
  assert.equal(kernel.hvciMode, true);
  const obj = new Uint8Array(await readFile(FIX("kfwpoff.obj")));
  // the interception surfaces as a fault through SEH (no handler in the
  // attack driver) with the modeled bugcheck recorded
  const r = await runAttack(kernel, obj, "m2.l4.lab4");
  assert.notEqual(r.status, "ok", "HVCI must stop the WP clear");
  const log = kernel.dbgLog.join("\n");
  assert.match(log, /\[hvci\] CR0\.WP-clearing write intercepted/);
  assert.equal(kernel.bugcheck?.code, 0x109n);
  assert.match(log, /mov cr0, 0x80000031/);   // attempted value (WP cleared)
});

// ------------------------------------------------------------- attack 2

test("directed-DPC lockdown pins secondary cores; watchdog trips 0x133", async () => {
  const { kernel } = await bootScenario("irql-attackers");
  const obj = new Uint8Array(await readFile(FIX("kflockdown.obj")));
  const r = await runAttack(kernel, obj, "m2.l3.lab2");
  assert.equal(r.status, "ok", `fault: ${r.error?.message}`);
  const log = kernel.dbgLog.join("\n");
  assert.match(log, /core 1 pinned at IRQL 2/);
  assert.match(log, /kernel structures exposed/);
  // the default starter releases before returning: cores idle again
  assert.match(log, /released; core 1 now at IRQL 0/);

  // student exercise variant: pins held -> !irql -a + !dpcwatchdog convict
  for (const cpu of [1, 2, 3]) kernel.setCpuIrql(cpu, 2);
  const c = capture(kernel);
  const all = await c.exec("!irql -a");
  assert.match(all, /core 1: 2 \(DISPATCH_LEVEL\)\s*<- pinned/);
  const verdict = await c.exec("!dpcwatchdog");
  assert.match(verdict, /BUGCHECK 0x133 DPC_WATCHDOG_VIOLATION/);
  assert.equal(kernel.bugcheck?.code, 0x133n);
  assert.equal(kernel.cpu.halted, true);
});

// ------------------------------------------------------------- attack 3

for (const be of ["js", "unicorn"]) {
  test(`timer-DPC persistence fires on schedule under pump (${be})`, async () => {
    const { kernel } = await bootScenario("irql-attackers", be);
    const obj = new Uint8Array(await readFile(FIX("kftimerdpc.obj")));
    const r = await runAttack(kernel, obj, "m2.l3.lab3", be);
    assert.equal(r.status, "ok", `[${be}] fault: ${r.error?.message}`);

    assert.equal(kernel.pendingTimers.length, 2, `[${be}] warzone + attack timer`);
    const mine = kernel.pendingTimers.find((t) => t.timerVa !== 0xfffff8055a701800n);
    assert.ok(mine, `[${be}] attack timer present`);
    assert.equal(mine.period, 5, `[${be}] period`);

    const c = capture(kernel);
    await c.exec("!dpcpump 13");
    const log = kernel.dbgLog.join("\n");
    assert.match(log, /payload run #1 at IRQL 2/, `[${be}] run 1`);
    assert.match(log, /payload run #3 at IRQL 2/, `[${be}] run 3`);
    assert.equal(mine.firedCount, 3, `[${be}] fired count`);

    const stat = await c.exec("!dpcstat");
    assert.match(stat, /timers: 2 armed/, `[${be}] dpcstat timer rows (kvmdrv + attack)`);
    assert.match(stat, /period=5/, `[${be}] dpcstat period`);
    assert.doesNotMatch(stat, /outside known modules/, `[${be}] routine in module`);
  });
}

// ------------------------------------------------------------- attack 4

test("DeferredRoutine hijack executes attacker code inside the victim slot", async () => {
  const { kernel } = await bootScenario("irql-attackers");
  const victimBefore = kernel.mem.u64(KFWARZ_VICTIM_DPC + 0x18n);
  assert.equal(victimBefore, 0xfffff8055a701400n, "victim queued with heartbeat routine");

  const obj = new Uint8Array(await readFile(FIX("kfhijack.obj")));
  const r = await runAttack(kernel, obj, "m2.l3.lab4");
  assert.equal(r.status, "ok", `fault: ${r.error?.message}`);
  const patched = kernel.mem.u64(KFWARZ_VICTIM_DPC + 0x18n);
  assert.notEqual(patched, victimBefore, "routine pointer rewritten");

  const c = capture(kernel);
  const dpcs = await c.exec("!dpcs");
  assert.match(dpcs, /QUEUED/, "still queued pre-drain");
  const drainOut = await c.exec("!dpcdrain");
  assert.match(drainOut, /\(patched!\)/, "drain flags the rewrite");

  const log = kernel.dbgLog.join("\n");
  assert.match(log, /HIJACK-PAYLOAD: victim slot executing attacker code at IRQL 2/,
    "attacker routine ran at DISPATCH");
  assert.match(log, /kvmdrv: DeferredRoutine redirected.*control-flow hijack/,
    "payoff hook convicted the redirection");
  assert.match(log, /kvmdrv: secret=kf-hijack-seen/, "secret released");

  // pgscan flags the rewrite even after retirement (insert-time vs live)
  const scan = await c.exec("!pgscan");
  assert.match(scan, /HIJACK\? DPC .*DeferredRoutine rewritten/);
});
