/**
 * New debugger surface: WinDbg-native commands added for code analysis
 * (u/uf/da/du/x/?/!drivers/!drvobj), the L<length> argument parser fix,
 * symbol-aware address arguments, and the _MMVAD/_MMVAD_SHORT type tables.
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

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const TABLES_DIR = path.join(root, "packages/ntsim-assets/data/vergilius/windows-10/22h2");

async function loadTables() {
  const names = ["_EPROCESS", "_LIST_ENTRY", "_UNICODE_STRING",
    "_KLDR_DATA_TABLE_ENTRY", "_PS_PROTECTION", "_KPCR", "_KPRCB", "_ETHREAD",
    "_MMVAD", "_MMVAD_SHORT"];
  const tables = new StructTables();
  for (const name of names) {
    const json = JSON.parse(await readFile(path.join(TABLES_DIR, `${name}.json`), "utf8"));
    tables.register(name, json.totalSize, Object.values(json.fieldsByName));
  }
  return tables;
}

async function boot(id, backend = "js") {
  return getScenario(id).boot({
    makeBackend: (mem) => backend === "unicorn"
      ? createUnicornBackend(mem)
      : new JsInterpreter(mem),
    loadTables,
  });
}

function capture(kernel) {
  const lines = [];
  const commands = createCommands(kernel);
  const w = (text, cls = "") => lines.push(cls ? `[${cls}]${text}` : text);
  const exec = async (line) => {
    const [cmd, ...args] = line.trim().split(/\s+/);
    const fn = commands[cmd];
    if (!fn) throw new Error(`unimplemented in harness: ${cmd}`);
    await fn(args, w, {});
  };
  return { exec, lines, text: () => lines.join("\n") };
}

// ------------------------------------------------------------ L-length parser

test("db/dq/s accept windbg L<hex> length prefixes without NaN errors", async () => {
  const { kernel } = await boot("pool-corrupt");
  const c = capture(kernel);

  // previously threw "The number NaN cannot be converted to a BigInt"
  await c.exec("db 0xfffff8055a700000 L20"); // kfpooler.sys base, mapped extent
  assert.match(c.text(), /0xfffff8055a700000/);

  await c.exec("db 0xfffff90000001000 L40");
  assert.match(c.text(), /0xfffff90000001000/);
  assert.doesNotMatch(c.text(), /NaN|bad address|error:/);

  await c.exec("dq 0xfffff90000001000 L2");
  assert.match(c.text(), /0xfffff90000001000/);
  assert.match(c.text(), /0xfffff90000001008/);

  // plain decimal lengths still work (back-compat)
  const c2 = capture(kernel);
  await c2.exec("db 0xfffff90000001000 32");
  assert.match(c2.text(), /0xfffff90000001000/);
});

// --------------------------------------------------------- u / uf / da / du

test("u disassembles an export thunk and resolves symbols", async () => {
  const { kernel } = await boot("api-hook");
  const c = capture(kernel);
  // detoured export: first byte is E9 (jmp rel32) — capstone must show it
  await c.exec("u nt!PsLookupProcessByProcessId L2");
  const t = c.text();
  assert.match(t, /jmp/, "expected E9 decoded as jmp");
  assert.match(t, /\(nt\+0x[0-9a-f]+\)|0x[0-9a-f]{16}/);
});

test("uf walks a hand-planted function until ret", async () => {
  const { kernel } = await boot("boot-default");
  // mov qword ptr [rsp+8], rbx ; xor eax,eax ; ret
  kernel.mem.write(0x30000c00n, new Uint8Array([
    0x48, 0x89, 0x5c, 0x24, 0x08,
    0x31, 0xc0,
    0xc3,
  ]));
  const c = capture(kernel);
  await c.exec("uf 0x30000c00");
  const t = c.text();
  assert.match(t, /mov\s+qword ptr \[rsp \+ 8\], rbx/);
  assert.match(t, /xor\s+eax, eax/);
  assert.match(t, /ret/);
  assert.equal(t.split("\n").filter((l) => /^\S{18}/.test(l)).length >= 3, true);
});

test("da/du read ANSI and UTF-16 strings from memory", async () => {
  const { kernel } = await boot("boot-default");
  kernel.mem.writeAnsi(0x30000d00n, "hello from kernel land");
  kernel.mem.writeUtf16(0x30000e00n, "\\SystemRoot\\system32\\kfprobe.sys");

  const c = capture(kernel);
  await c.exec("da 0x30000d00");
  assert.match(c.text(), /"hello from kernel land"/);

  const c2 = capture(kernel);
  await c2.exec("du 0x30000e00");
  assert.match(c2.text(), /\\SystemRoot\\system32\\kfprobe\.sys/);
});

// ---------------------------------------------------------------- x / ? 

test("x lists matching export thunks", async () => {
  const { kernel } = await boot("boot-default");
  const c = capture(kernel);
  await c.exec("x nt!PsLookup*");
  const t = c.text();
  assert.match(t, /nt!PsLookupProcessByProcessId/);
  assert.match(t, /fffff80100000030/i); // deterministic 4th defined thunk
});

test("? evaluates expressions with symbols, registers and arithmetic", async () => {
  const { kernel } = await boot("boot-default");
  const c = capture(kernel);
  await c.exec("? 0x1000 + 0x10 * 2");
  assert.match(c.text(), /= 4128/); // decimal rendering of 0x1020
  assert.match(c.text(), /0000000000001020/); // hex rendering

  const c2 = capture(kernel);
  await c2.exec("? nt!PsLookupProcessByProcessId - nt!PsLookupProcessByProcessId");
  assert.match(c2.text(), /= 0\b/);
});

// ------------------------------------------------------- !drivers / !drvobj

test("!drivers merges loaded drivers and flags suspicious lab modules", async () => {
  const { kernel } = await boot("api-hook");
  const c = capture(kernel);
  await c.exec("!drivers");
  const t = c.text();
  assert.match(t, /kfhook\.sys.*suspicious/);
  assert.match(t, /ntoskrnl\.exe/);
});

test("!drvobj walks a modeled DRIVER_OBJECT incl. MajorFunction table", async () => {
  const { kernel } = await boot("boot-default");
  const { createDriverObject, initDriverObjectName } =
    await import("@kernelforge/ntsim/src/devices.mjs");
  const rec = createDriverObject(kernel, "kfdemo.sys");
  initDriverObjectName(kernel, rec, "kfdemo.sys", 0xfffff8055b000000n, 0x2000n);
  // student-driver convention: DriverUnload at +0x68
  kernel.mem.w64(rec.va + 0x68n, 0xfffff8055b000400n);

  const c = capture(kernel);
  await c.exec("!drvobj kfdemo.sys");
  const t = c.text();
  assert.match(t, /DRIVER_OBJECT .*kfdemo\.sys/);
  assert.match(t, /DriverStart\s+: 0xfffff8055b000000/);
  assert.match(t, /DriverName\s+: "kfdemo\.sys"/);
  assert.match(t, /IRP_MJ_CREATE/);
  assert.match(t, /IopInvalidDeviceRequest/);
  assert.match(t, /DriverUnload/);
  assert.ok(!/not set/.test(t), "unload was set — should not print '(not set)'");
});

// ------------------------------------------------------------- module ranges

test("module extents are readable across their full image range (both backends)", async () => {
  for (const be of ["js", "unicorn"]) {
    const { kernel } = await boot("api-hook", be);
    const c = capture(kernel);
    // kfhook.sys spans 0xfffff8055a600000 .. +0x8000 — every page backed
    await c.exec("db kfhook.sys+0x7ff0 L8");
    assert.match(c.text(), /0xfffff8055a607ff0/, `[${be}] tail of image unreadable`);

    // search across the full extent finds the detour-page evidence
    const c2 = capture(kernel);
    await c2.exec('s -a 0xfffff8055a600000 L8000 "kfhook:"');
    assert.match(c2.text(), /Found 0xfffff8055a603000/, `[${be}] evidence string`);
    assert.match(c2.text(), /Found 0xfffff8055a603080/, `[${be}] evidence string 2`);
  }
});

// --------------------------------------------------------------- MMVAD types

test("dt nt!_MMVAD_SHORT / nt!_MMVAD walk real 22h2 layouts", async () => {
  const { kernel } = await boot("boot-default");
  const c = capture(kernel);
  await c.exec("dt nt!_MMVAD_SHORT");
  let t = c.text();
  assert.match(t, /\+0x018 StartingVpn/);
  assert.match(t, /\+0x028 PushLock/);

  const c2 = capture(kernel);
  await c2.exec("dt nt!_MMVAD");
  t = c2.text();
  // Core is an embedded struct the generic walker skips; pointer fields show
  assert.match(t, /\+0x048 Subsection/);
  assert.match(t, /\+0x070 VadsProcess/);
  assert.match(t, /\+0x080 FileObject/);
});
