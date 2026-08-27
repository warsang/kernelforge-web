/**
 * Modules 2-4 lab flows, headless: IRQL/DPC, inline hooks, pool corruption.
 * Each test drives the real scenario + debugger command surface exactly as
 * the browser would.
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

async function boot(id) {
  return getScenario(id).boot({
    makeBackend: (mem) => new JsInterpreter(mem),
    loadTables,
  });
}

function capture(kernel) {
  const lines = [];
  const commands = createCommands(kernel);
  const w = (text, cls = "") => lines.push(cls ? `[${cls}]${text}` : text);
  const exec = (line) => {
    const [cmd, ...args] = line.trim().split(/\s+/);
    commands[cmd]?.(args, w, {});
  };
  return { exec, lines, text: () => lines.join("\n") };
}

// ------------------------------------------------------- module 2: irql-dpc

test("irql-dpc boots pinned above DISPATCH with one stranded DPC", async () => {
  const { kernel, kind } = await boot("irql-dpc");
  assert.equal(kind, "irql-dpc");
  assert.equal(kernel.currentIrql, 15);
  assert.equal(kernel.pendingDpcs.filter((d) => !d.drained).length, 1);

  const c = capture(kernel);
  c.exec("!irql");
  assert.match(c.text(), /IRQL: 15/);

  c.exec("!dpcs");
  assert.match(c.text(), /QUEUED/);
  assert.match(c.text(), /fffff8055a401400/i); // DeferredRoutine
});

test("irql-dpc drain refuses above DISPATCH, succeeds after repair", async () => {
  const { kernel } = await boot("irql-dpc");

  const stuck = capture(kernel);
  stuck.exec("!dpcdrain");
  assert.match(stuck.text(), /cannot request a DPC interrupt at IRQL 15/);
  assert.ok(kernel.pendingDpcs[0].drained === false);

  const fixed = capture(kernel);
  fixed.exec("!irql 2");
  assert.match(fixed.text(), /-> 2 \(DISPATCH_LEVEL\)/);
  fixed.exec("!dpcdrain");
  assert.ok(kernel.pendingDpcs[0].drained);
  const log = kernel.dbgLog.join("\n");
  assert.match(log, /kfdpc: deferred routine ran at DISPATCH_LEVEL/);
  assert.match(log, /kfdpc: secret=kf-dpc-drain-ok/);
});

// ------------------------------------------------------- module 3: api-hook

test("api-hook ships detoured export; scan reports it with repair bytes", async () => {
  const { kernel, kind } = await boot("api-hook");
  assert.equal(kind, "api-hook");
  assert.equal(kernel.isDetoured("PsLookupProcessByProcessId"), true);

  const c = capture(kernel);
  c.exec("!hookscan");
  const t = c.text();
  assert.match(t, /DETECTED INLINE HOOKS/);
  assert.match(t, /PsLookupProcessByProcessId/);
  assert.match(t, /\[kfhook\.sys\]/);
  assert.match(t, /eb 0x[0-9a-f]+ f4/); // pristine first byte shown
});

test("hook suppresses hidden PID only; eb repair restores lookup", async () => {
  const { kernel } = await boot("api-hook");
  const c = capture(kernel);

  // unhooked PID resolves fine even while detour is live
  c.exec("!hooktest PsLookupProcessByProcessId 108");
  assert.match(c.text(), /STATUS_SUCCESS/);

  // hidden PID is suppressed by the hook
  c.exec("!hooktest PsLookupProcessByProcessId 888");
  assert.match(c.text(), /STATUS_INVALID_PARAMETER.*PROLOGUE DETOURED/);

  // repair from the printed pristine byte
  c.exec(`!hookscan PsLookupProcessByProcessId`);
  const thunkAddr = c.text().match(/thunk   : (0x[0-9a-f]+)/)?.[1];
  assert.ok(thunkAddr, "scan did not print thunk address");
  c.exec(`eb ${thunkAddr} f4`);
  assert.ok(!kernel.isDetoured("PsLookupProcessByProcessId"));

  // fresh capture so assertions only see post-repair behavior
  const after = capture(kernel);
  after.exec("!hooktest PsLookupProcessByProcessId 888");
  assert.match(after.text(), /STATUS_SUCCESS/);
  assert.doesNotMatch(after.text(), /PROLOGUE DETOURED/);
});

// ---------------------------------------------------- module 4: pool-corrupt

test("pool-corrupt world has three KfPb blocks, one smashed guard", async () => {
  const { kernel, kind } = await boot("pool-corrupt");
  assert.equal(kind, "pool-corrupt");
  assert.equal(kernel.poolAllocs.length, 3);
  assert.equal(kernel.verifyGuards().length, 1);
  assert.equal(kernel.verifyGuards()[0].addr, 0xfffff90000001200n);

  const c = capture(kernel);
  c.exec("!poolfind KfPb");
  const t = c.text();
  assert.match(t, /0xfffff90000001000.*guard @ 0xfffff90000001080/);
  assert.match(t, /0xfffff90000001200.*CORRUPTED at guard\[0\] @ 0xfffff90000001280 \(got 0xde/);
  // repair hint must carry the EXACT guard address (block start != guard)
  assert.match(t, /eb 0xfffff90000001280 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5/);
});

test("pool repair flow: verify fails until guard healed, then secret prints", async () => {
  const { kernel } = await boot("pool-corrupt");
  let healedCalls = 0;
  kernel.onPoolHealed = (() => {
    const orig = kernel.onPoolHealed;
    return () => { healedCalls++; orig(); };
  })();

  const bad = capture(kernel);
  bad.exec("!poolverify");
  assert.match(bad.text(), /1 corrupted allocation/);
  assert.match(bad.text(), /guard @ 0xfffff90000001280 guard\[0\]=0xde/);
  assert.equal(healedCalls, 0);

  // wrong-byte repair keeps verification red
  const wrong = capture(kernel);
  wrong.exec("eb 0xfffff90000001280 ff");
  wrong.exec("!poolverify");
  assert.match(wrong.text(), /1 corrupted allocation/);

  // correct repair: rewrite full expected guard
  const good = capture(kernel);
  good.exec("eb 0xfffff90000001280 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5");
  good.exec("!poolverify");
  assert.match(good.text(), /all allocation guards intact/);
  assert.equal(healedCalls, 1);

  const log = kernel.dbgLog.join("\n");
  assert.match(log, /kfpooler: integrity pass complete/);
  assert.match(log, /checksum=kf-pool-guard-ok/);
});
