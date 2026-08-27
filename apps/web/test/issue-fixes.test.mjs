/**
 * Regression tests for the open-issue fix batch (issues #25, #27, #28, #29):
 *   - expression arithmetic in db/dq/eb/u/bp addresses (#27 "bad count")
 *   - !cr3/!pte/!vtop no longer crash in guest-paged Mmu worlds (#25
 *     "Cannot read properties of undefined (reading 'values')")
 *   - !cr / !dbgprint / !smram / !smmc exist on the app console (#25)
 *   - decorative separator lines are skipped, not executed (#28)
 *   - kfmm.sys has real page tables + alias windows in the paging-walk world (#27)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { StructTables } from "@kernelforge/ntsim/src/structs.mjs";
import { NtKernel } from "@kernelforge/ntsim/src/kernel.mjs";
import { PageTableSpace } from "@kernelforge/ntsim/src/paging.mjs";
import { Chipset, SmmEngine } from "@kernelforge/ntsim/src/index.mjs";
import { createCommands, createDebugger } from "../src/debugger.js";

const TABLES_DIR = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../packages/ntsim-assets/data/vergilius/windows-10/22h2"
);

async function loadTables(names = ["_EPROCESS", "_KPROCESS", "_LIST_ENTRY",
  "_KLDR_DATA_TABLE_ENTRY", "_KPCR", "_KPRCB", "_ETHREAD"]) {
  const tables = new StructTables();
  for (const name of names) {
    const json = JSON.parse(await readFile(path.join(TABLES_DIR, `${name}.json`), "utf8"));
    tables.register(name, json.totalSize, Object.values(json.fieldsByName));
  }
  return tables;
}

/** Plain low-memory kernel (no paging world) with materialized scratch pages. */
async function plainKernel() {
  const k = new NtKernel({ tables: await loadTables(), bases: {
    kva: 0x10000000n, pool: 0x20000000n,
    thunk: 0x30000000n, eproc: 0x40000000n, driver: 0x50000000n,
  } });
  k.bootstrap();
  k.loadedModules ??= [];
  return k;
}

/** Guest-paged Mmu world — same shape as the SMM-track boots (issue #25). */
async function mmuWorld() {
  const k = new NtKernel({ tables: await loadTables(["_EPROCESS"]), paging: true });
  k.bootstrap();
  return k;
}

function capture(kernel) {
  const lines = [];
  const commands = createCommands(kernel);
  const w = (text, cls = "") => lines.push(cls ? `[${cls}]${text}` : text);
  const exec = async (line) => {
    const [cmd, ...args] = line.trim().split(/\s+/);
    await commands[cmd]?.(args, w, {});
  };
  return { lines, exec, w };
}

// ---------------------------------------------------------------- #27

test("dq accepts inline arithmetic (`dq <addr>+<off> L1`)", async () => {
  const k = await plainKernel();
  k.mem.w64(0x50101078n, 0x4142434445464748n);
  const c = capture(k);
  await c.exec("dq 0x50101000+78 L1");
  assert.match(c.lines.join("\n"), /0x0000000050101078\s+0x4142434445464748/);
});

test("db folds spaced arithmetic into one address expression", async () => {
  const k = await plainKernel();
  k.mem.write(0x40000010n, Uint8Array.from([0xde, 0xad, 0xbe, 0xef]));
  const c = capture(k);
  await c.exec("db 0x40000000 + 0x10 L4");
  assert.match(c.lines.join("\n"), /de ad be ef/);
});

test("u resolves module-relative and nt!-style expression addresses", async () => {
  const k = await plainKernel();
  k.loadedModules.push({
    base: 0x50100000n, sizeOfImage: 0x8000, name: "kfmm.sys", lab: true,
  });
  // 48 89 d2 c3 = mov rdx,rdx; ret — decodable by capstone when available
  k.mem.write(0x50100040n, Uint8Array.from([0x48, 0x89, 0xd2, 0xc3]));
  const c = capture(k);
  await c.exec("u kfmm.sys+0x40 L2");
  const out = c.lines.join("\n");
  // either real disassembly or the distinct loader error — never a bogus
  // "Memory read error … magic word" conflation (#28/#29)
  assert.ok(
    /unassembly from kfmm\.sys\+0x40|disassembler-unavailable/.test(out),
    out);
  assert.doesNotMatch(out, /Memory read error.*magic word/);
});

test("eb takes an expression address", async () => {
  const k = await plainKernel();
  k.mem.write(0x50100000n, new Uint8Array(0x20));
  const c = capture(k);
  await c.exec("eb 0x50100000+0x16 78");
  assert.equal(Number(k.mem.u8(0x50100016n)), 0x78);
});

test("bp resolves arithmetic targets", async () => {
  const k = await plainKernel();
  const c = capture(k);
  await c.exec("bp 0x30000000+0x1010");
  assert.match(c.lines.join("\n"), /Breakpoint 0 set @ 0x0000000030001010/);
});

// ---------------------------------------------------------------- #25

test("!cr3 survives a guest-paged Mmu world (no 'values' TypeError)", async () => {
  const k = await mmuWorld();
  const c = capture(k);
  await c.exec("!cr3"); // must not throw
  const out = c.lines.join("\n");
  assert.match(out, /guest-paged world/);
  assert.match(out, /DirectoryTableBase/);
});

test("!vtop works through the Mmu in a guest-paged world", async () => {
  const k = await mmuWorld();
  const c = capture(k);
  await c.exec("!vtop 0xfffff78000000000");
  const out = c.lines.join("\n");
  assert.ok(/-> 0x[0-9a-f]+/.test(out) || /not mapped/.test(out), out);
  assert.doesNotMatch(out, /reading 'values'/);
});

test("!cr prints control registers in an Mmu world and cr0 in plain worlds", async () => {
  const km = await plainKernel();
  const cm = capture(km);
  await cm.exec("!cr");
  assert.match(cm.lines.join("\n"), /cr0=.*pg=1.*wp=1/);

  const kp = await mmuWorld();
  const cp = capture(kp);
  await cp.exec("!cr");
  const out = cp.lines.join("\n");
  assert.match(out, /cr0=/);
  assert.match(out, /cr3=/);
  assert.match(out, /efer=.*lma=1/);
});

test("!dbgprint dumps the buffered log", async () => {
  const k = await plainKernel();
  k.dbgLog.push("nt!PspProcessNotify: Ex cb ok");
  const c = capture(k);
  await c.exec("!dbgprint");
  assert.match(c.lines.join("\n"), /PspProcessNotify/);

  const c2 = capture(await plainKernel());
  await c2.exec("!dbgprint");
  assert.match(c2.lines.join("\n"), /no debug output buffered/);
});

test("!smram/!smmc report chipset state when an SMM engine is attached", async () => {
  const k = await mmuWorld();
  k.smm = new SmmEngine(k, new Chipset({}));
  const c = capture(k);
  await c.exec("!smram");
  await c.exec("!smmc");
  const out = c.lines.join("\n");
  assert.match(out, /SMRAM state/);
  assert.match(out, /D_OPEN=\d D_CLS=\d D_LCK=\d G_SMRAME=\d/);
  assert.match(out, /SMRAMC\) = 0x[0-9a-f]{2}/);

  const c2 = capture(await plainKernel());
  await c2.exec("!smram"); // graceful without an engine
  assert.match(c2.lines.join("\n"), /no SMM engine/);
});

// ---------------------------------------------------------------- #28

test("decorative separator lines are skipped by the console dispatcher", async () => {
  const k = await plainKernel();
  const out = [];
  const dbg = createDebugger(k, { write: (t) => out.push(t) });
  await dbg.exec("================================================================================0.==");
  await dbg.exec("========================================================");
  const text = out.join("\n");
  assert.doesNotMatch(text, /Couldn't resolve/);
  assert.equal(text, "");
  await dbg.exec("!cr3"); // console still functional afterwards
  assert.match(out.join("\n"), /kd> !cr3|no paging world/);
});

// ---------------------------------------------------------------- #16

test("!dpcs shows the LIVE DeferredRoutine after an in-place patch", async () => {
  const k = await plainKernel();
  const dpcVa = 0xfffff8055a701000n;
  const origRoutine = 0xfffff8055a701400n;
  k.mem.writeAnsi(dpcVa, "DPCk");
  k.mem.w64(dpcVa + 0x18n, origRoutine); // real x64 offset
  kernel_queueDpc(k, dpcVa, origRoutine);
  const patched = 0xfffff8055a702000n;
  k.mem.w64(dpcVa + 0x18n, patched);

  const c = capture(k);
  c.exec("!dpcs");
  const out = c.lines.join("\n");
  assert.match(out, new RegExp(patched.toString(16)), "live pointer shown");
  assert.doesNotMatch(out, new RegExp(origRoutine.toString(16).slice(8)), "snapshot hidden");
  assert.match(out, /\(patched\)/);
});

function kernel_queueDpc(k, va, routine) {
  k.queueDpc(va, routine, 0n);
}

test("KDPC layout is real x64: KeInitializeDpc writes routine @+0x18", async () => {
  const k = await plainKernel();
  const dpc = k.allocPool(64);
  k.apiImpls.get("KeInitializeDpc")(dpc, 0x60000100n, 0x60000200n);
  assert.equal(k.mem.u64(dpc), 0x4b444350n);              // 'DPCk' header marker
  assert.equal(k.mem.u64(dpc + 0x18n), 0x60000100n);      // DeferredRoutine
  assert.equal(k.mem.u64(dpc + 0x20n), 0x60000200n);      // DeferredContext

  // live readers agree with the memory image
  k.queueDpc(dpc, 0x60000100n, 0x60000200n);
  assert.equal(k.liveDpcRoutine({ dpcVa: dpc, routine: 0x60000100n }), 0x60000100n);
  k.mem.w64(dpc + 0x18n, 0x60000300n);
  assert.equal(k.liveDpcRoutine({ dpcVa: dpc, routine: 0x60000100n }), 0x60000300n);
});
