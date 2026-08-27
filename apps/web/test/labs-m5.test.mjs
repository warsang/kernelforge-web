/**
 * Module 5 lab flow, headless: tracing & anti-tracing (kftrace.sys).
 * Drives the real scenario + debugger command surface exactly as the
 * browser would — including real guest pushfq/popfq sequences executed on
 * the emulated CPU.
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

async function boot() {
  return getScenario("anti-trace").boot({
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

test("anti-trace boots kftrace.sys with armed gate and registered VEH", async () => {
  const { kernel, kind } = await boot();
  assert.equal(kind, "anti-trace");
  assert.equal(kernel.mem.u8(0xfffff8055a802000n), 1); // g_AntiTraceEnabled
  assert.equal(kernel.vectoredHandlers.length, 1);
  assert.equal(kernel.vectoredHandlers[0].name, "kftrace!TraceVeh");
  assert.equal(kernel.tracer.attached, false);
  assert.ok(kernel.loadedModules.some((m) => m.name === "kftrace.sys"));

  // evidence pages are searchable like every other world
  const c = capture(kernel);
  c.exec(`s -a 0xfffff8055a804000 0x800 "mov ss stall"`);
  assert.match(c.text(), /Found 0x/i);
});

test("!traceinfo maps defenses; !trace toggles the simulated tracer", async () => {
  const { kernel } = await boot();
  const c = capture(kernel);

  c.exec("!traceinfo");
  let t = c.text();
  assert.match(t, /TraceVeh/);
  assert.match(t, /0xfffff8055a801400/);
  assert.match(t, /g_AntiTraceEnabled.*= 1.*ARMED/);
  assert.match(t, /detached/);
  c.exec("!trace on");
  assert.equal(kernel.tracer.attached, true);
  assert.equal(kernel.cpu.tf, true); // single-stepping => trap flag armed
  c.exec("r");
  assert.match(c.text(), /TRAP FLAG ARMED/);
  c.exec("!trace off");
  assert.equal(kernel.tracer.attached, false);
  assert.equal(kernel.cpu.tf, false);
});

test("clean selftest: all checks pass through TraceVeh, verdict CLEAN", async () => {
  const { kernel } = await boot();
  const c = capture(kernel);
  c.exec("!selftest");
  const t = c.text();
  assert.match(t, /\[A\] tf-read.*-> clean/);
  assert.match(t, /\[B\].*handled by TraceVeh/);
  assert.match(t, /\[C\].*handled by TraceVeh/);
  assert.match(t, /verdict: CLEAN/);
  // both injections reached the guest handler, nothing was swallowed
  assert.equal(kernel.traceStats.int1Raised, 2);
  assert.equal(kernel.traceStats.vehHandled, 2);
  assert.equal(kernel.traceStats.swallowedByTracer, 0);
  // secret stays withheld while the gate is armed
  assert.doesNotMatch(t, /kf-trace-bypass-ok/);
});

test("traced selftest: Variant A fires, TraceVeh starved, exactly 4 swallowed", async () => {
  const { kernel } = await boot();
  const c = capture(kernel);
  c.exec("!trace on");
  c.exec("!selftest");
  const t = c.text();
  assert.match(t, /\[A\] tf-read.*DETECTED/);           // variant A saw TF=1
  assert.match(t, /bit8=1 UNMASKED/);                    // mov-ss stall snapshot
  assert.match(t, /swallowed by tracer \(TraceVeh starved\)/);
  assert.match(t, /verdict: TRACER DETECTED/);
  assert.equal(kernel.traceStats.int1Raised, 4);         // A + B + C(stall,nop)
  assert.equal(kernel.traceStats.swallowedByTracer, 4);
  assert.equal(kernel.traceStats.vehHandled, 0);         // handler never ran

  // repeatable: a second traced run reproduces the same counters
  const before = kernel.traceStats.int1Raised;
  c.exec("!selftest");
  assert.equal(kernel.traceStats.int1Raised - before, 4);
});

test("bypass flow: eb-clearing the gate releases the secret when clean", async () => {
  const { kernel } = await boot();

  // traced + bypassed is not enough — checks still detect the tracer
  const greedy = capture(kernel);
  greedy.exec("eb 0xfffff8055a802000 0");
  greedy.exec("!trace on");
  greedy.exec("!selftest");
  assert.match(greedy.text(), /verdict: TRACER DETECTED/);
  assert.doesNotMatch(greedy.text(), /kf-trace-bypass-ok/);

  // detach first: only then does the cleared gate pay out
  const win = capture(kernel);
  win.exec("!trace off");
  win.exec("!selftest");
  assert.match(win.text(), /verdict: CLEAN/);
  assert.match(win.text(), /secret=kf-trace-bypass-ok/);
  const log = kernel.dbgLog.join("\n");
  assert.match(log, /kftrace: secret=kf-trace-bypass-ok/);

  // flag answers grade against the catalog hashes via lab-runtime
  const { catalog } = await import("@kernelforge/course-content");
  const { checkFlag } = await import("@kernelforge/lab-runtime");
  const lab = catalog.modules.flatMap((m) => m.lessons)
    .flatMap((l) => l.labs).find((x) => x.id === "m5.l1.lab1");
  assert.equal(await checkFlag("0xfffff8055a801400", lab.flags[0]), true);
  assert.equal(await checkFlag("4", lab.flags[1]), true);
  assert.equal(await checkFlag("kf-trace-bypass-ok", lab.flags[2]), true);
});
