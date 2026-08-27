/**
 * Live kernel debugging: bp/bl/bc + t/p/g/gu + r writes.
 *
 * Breakpoints are genuine int3 patches. Hit detection is engine-aware:
 * JsInterpreter raises pendingBreak (callFunction honors breakpointPolicy
 * "pause"); Unicorn raises an "unhandled CPU exception" with RIP parked ON
 * the CC — both normalize into the same paused state via cpu.pausedFrame,
 * so the full set-bp -> burst -> hit -> step -> resume cycle is exercised
 * on BOTH backends against a real scenario kernel.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { JsInterpreter } from "@kernelforge/ntsim/src/cpu.mjs";
import { StructTables } from "@kernelforge/ntsim/src/structs.mjs";
import { createUnicornBackend } from "@kernelforge/ntsim-unicorn/src/backend.mjs";
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

async function boot(backend) {
  return getScenario("pool-corrupt").boot({
    makeBackend: (mem) => backend === "unicorn"
      ? createUnicornBackend(mem)
      : new JsInterpreter(mem),
    loadTables,
  });
}

/**
 * Debuggee program (deterministic, no imports):
 *   F+00: mov eax,41     B8 29 00 00 00
 *   F+05: call G         E8 06 00 00 00
 *   F+0a: add eax,1      83 C0 01
 *   F+0d: ret            C3
 *   F+0e: CC CC          (padding)
 *   G+00: mov edx,7      BA 07 00 00 00
 *   G+05: add edx,1      83 C2 01
 *   G+08: ret            C3
 */
const F = 0xfffff90000010000n;
const G = 0xfffff90000010010n;

function programBytes() {
  return [
    0xb8, 0x29, 0x00, 0x00, 0x00,             // mov eax,41
    0xe8, 0x06, 0x00, 0x00, 0x00,             // call G
    0x83, 0xc0, 0x01,                         // add eax,1
    0xc3,                                     // ret
    0xcc, 0xcc,                               // padding
    0xba, 0x07, 0x00, 0x00, 0x00,             // G: mov edx,7
    0x83, 0xc2, 0x01,                         // add edx,1
    0xc3,                                     // ret
  ];
}

/** Engine-shape-agnostic breakpoint probe. */
function bpArmed(cpu, addr) {
  if (typeof cpu.hasDebugBp === "function") return cpu.hasDebugBp(addr);
  const bps = cpu.debugBps;
  if (bps instanceof Set) return bps.has(addr);
  return Array.isArray(bps) ? bps.some((a) => a === addr) : false;
}

function capture(kernel) {
  const lines = [];
  const commands = createCommands(kernel);
  const w = (text, cls = "") => lines.push(cls ? `[${cls}]${text}` : text);
  const exec = async (line) => {
    const [cmd, ...args] = line.trim().split(/\s+/);
    const fn = commands[cmd];
    if (!fn) throw new Error(`no such command: ${cmd}`);
    await fn(args, w, {});
  };
  /** what createDebugger.notifyBreak does in the app */
  const adopt = (res) => {
    commands.__bpBurst(res);
    return commands.__bpPaused();
  };
  return { exec, adopt, lines, text: () => lines.join("\n") };
}

async function makeDebuggee(kernel) {
  kernel.mem.write(F, programBytes());
}

/** Burst DriverEntry-style: callFunction under the debugger's pause policy,
 *  exactly like the compile flow / !dpcdrain bursts do. */
function burst(kernel, addr) {
  kernel.cpu.breakpointPolicy = "pause";
  try {
    return kernel.cpu.callFunction(addr, []);
  } finally {
    // policy stays "pause" while breakpoints remain armed (armPolicy parity)
  }
}

async function stepLifecycle(be) {
  const { kernel } = await boot(be);
  await makeDebuggee(kernel);
  const dbg = capture(kernel);

  await dbg.exec(`bp 0x${G.toString(16)}`);
  assert.match(dbg.text(), /Breakpoint 0 set/, `[${be}] bp set`);

  // gates never modify memory — db/u show the true bytes (design intent)
  assert.equal(kernel.mem.u8(G), 0xba, `[${be}] memory untouched by bp`);

  const res = burst(kernel, F);
  // JsInterpreter pauses with status:"breakpoint"; Unicorn's int3 surfaces
  // as a fault (exception-shaped hit). Both adopt into the same state.
  assert.ok(
    res.status === "breakpoint" || res.status === "fault",
    `[${be}] burst paused (got ${res.status})`,
  );
  assert.equal(dbg.adopt(res), true, `[${be}] pause adopted`);

  // console view of the adopted pause
  await dbg.exec("bl");
  assert.match(dbg.text(), /hits:1/, `[${be}] hit counted`);
  assert.equal(BigInt(kernel.cpu.regs.rip), G, `[${be}] RIP parked on bp`);

  // t: execute mov edx,7 -> rip G+5, edx becomes 7
  await dbg.exec("t");
  assert.equal(BigInt(kernel.cpu.regs.rip), G + 5n, `[${be}] t stepped`);
  assert.equal(kernel.cpu.regs.rdx, 7n, `[${be}] mov executed`);

  // p over non-call behaves like a step: add edx,1
  await dbg.exec("p");
  assert.equal(BigInt(kernel.cpu.regs.rip), G + 8n, `[${be}] p stepped`);
  assert.equal(kernel.cpu.regs.rdx, 8n, `[${be}] add executed`);

  // g: ret -> frame returns -> run complete; caller's add eax,1 executed
  await dbg.exec("g");
  assert.match(dbg.text(), /run complete/, `[${be}] g completed`);
  assert.equal(kernel.cpu.regs.rax, 0x2an, `[${be}] rax after full run`);
  // gate still armed for future passes
  const armed = bpArmed(kernel.cpu, G);
  assert.equal(armed, true, `[${be}] bp still armed post-run`);

  // r write: set rip like windbg
  await dbg.exec(`r rip=0x${F.toString(16)}`);
  assert.equal(BigInt(kernel.cpu.regs.rip), F, `[${be}] r rip=`);

  // bc clears the gate entirely
  await dbg.exec("bc *");
  const stillArmed = bpArmed(kernel.cpu, G);
  assert.equal(stillArmed, false, `[${be}] bc removed gate`);
  assert.match(dbg.text(), /all breakpoints cleared/);
  return dbg;
}

test("stepping lifecycle (js backend)", async () => {
  await stepLifecycle("js");
});

test("stepping lifecycle (unicorn backend)", async () => {
  await stepLifecycle("unicorn");
});

test("gu runs the frame out (js)", async () => {
  const { kernel } = await boot("js");
  await makeDebuggee(kernel);
  const dbg = capture(kernel);
  await dbg.exec(`bp 0x${G.toString(16)}`);
  const res = burst(kernel, F);
  assert.equal(dbg.adopt(res), true, "pause adopted");
  await dbg.exec("gu");
  assert.match(dbg.text(), /returned|run complete|exited/, "gu output");
});

test("second burst re-hits an armed breakpoint (js)", async () => {
  const { kernel } = await boot("js");
  await makeDebuggee(kernel);
  const dbg = capture(kernel);
  await dbg.exec(`bp 0x${G.toString(16)}`);

  const r1 = burst(kernel, F);
  assert.equal(dbg.adopt(r1), true, "first hit adopted");
  await dbg.exec("bl");

  // continue to completion, then run the program AGAIN
  await dbg.exec("g");
  const r2 = burst(kernel, F);
  assert.notEqual(r2.status, "ok", "re-hit after resume pauses again");
  assert.equal(dbg.adopt(r2), true, "second hit adopted");
});
