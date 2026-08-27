/**
 * Headless tests for the m11-m13 debugger surface: !cr3/!pte/!vtop over a
 * PageTableSpace, !ssdt over a ServiceTable, !notifyroutines listing.
 * Worlds are constructed directly (no scenario dependency).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { StructTables } from "@kernelforge/ntsim/src/structs.mjs";
import { JsInterpreter, M64 } from "@kernelforge/ntsim/src/cpu.mjs";
import { NtKernel } from "@kernelforge/ntsim/src/kernel.mjs";
import { PageTableSpace, joinVa } from "@kernelforge/ntsim/src/paging.mjs";
import { ServiceTable } from "@kernelforge/ntsim/src/ssdt.mjs";
import { createCommands } from "../src/debugger.js";

const TABLES_DIR = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../packages/ntsim-assets/data/vergilius/windows-10/22h2"
);

async function loadTables() {
  const names = ["_EPROCESS", "_KPROCESS", "_LIST_ENTRY", "_UNICODE_STRING",
    "_KLDR_DATA_TABLE_ENTRY", "_PS_PROTECTION", "_KPCR", "_KPRCB", "_ETHREAD"];
  const tables = new StructTables();
  for (const name of names) {
    const json = JSON.parse(await readFile(path.join(TABLES_DIR, `${name}.json`), "utf8"));
    tables.register(name, json.totalSize, Object.values(json.fieldsByName));
  }
  return tables;
}

/** Low-memory (unicorn-safe) kernel with a paging world + service table. */
async function booted() {
  const k = new NtKernel({
    tables: await loadTables(),
    bases: {
      kva: 0x10000000n, pool: 0x20000000n,
      thunk: 0x30000000n, eproc: 0x40000000n, driver: 0x50000000n,
    },
  });
  k.bootstrap();
  k.loadedDrivers.push({ name: "kfvillain.sys", base: 0x60000000n });
  const pts = new PageTableSpace(k, { physBase: 0x3000000n, selfRefIndex: 0xf });
  const proc = pts.createProcess({ name: "kftarget", pid: 888 });
  k.paging = pts;

  const st = new ServiceTable(k, { base: 0x10000000n + 0x200000n });
  st.add("NtCreateFile", () => 0n);
  const hookIdx = st.add("NtOpenProcess", function (pid) {
    return pid === 888n ? 0xc0000034n : 0n;
  });
  k.serviceTable = st;
  return { k, pts, proc, st, hookIdx };
}

function capture(kernel) {
  const lines = [];
  const commands = createCommands(kernel);
  const w = (text, cls = "") => lines.push(cls ? `[${cls}]${text}` : text);
  const exec = (line) => {
    const [cmd, ...args] = line.trim().split(/\s+/);
    commands[cmd]?.(args, w, {});
  };
  return { lines, exec, w };
}

test("!cr3 reports DTB and self-map index", async () => {
  const { k, proc } = await booted();
  const c = capture(k);
  c.exec(`!cr3 kftarget`);
  const out = c.lines.join("\n");
  assert.match(out, /DirectoryTableBase\s*: 0x0000000003000000/);
  assert.match(out, /self-map PML4 index : 0xf/);
  assert.equal(proc.dtb, 0x3000000n);
});

test("!pte walks four levels and exposes alias VAs backed by real bytes", async () => {
  const { k, pts, proc } = await booted();
  const va = joinVa(0x9, 0x87, 0x65, 0x43, 0x10, false);
  const m = pts.mapPage(proc, va, { writable: true });

  const c = capture(k);
  c.exec(`!pte 0x${va.toString(16)} kftarget`);
  const out = c.lines.join("\n");
  for (const lvl of ["PML4E", "PDPTE", "PDE", "PTE"]) assert.ok(out.includes(lvl), lvl);
  assert.match(out, /=> PA /);

  // alias column must be dq-able: read PTE row's alias and compare to entryPa
  const pteRow = pts.translate(va, proc).rows.at(-1);
  assert.equal(k.mem.u64(pteRow.entryVa), pteRow.value);
  assert.notEqual(pteRow.entryVa, pteRow.entryPa); // it is an ALIAS, not raw phys
  void m;
});

test("!vtop translates and flags unmapped VAs", async () => {
  const { k, pts, proc } = await booted();
  const va = joinVa(0x9, 0x87, 0x65, 0x44, 0x28, false);
  pts.mapPage(proc, va, {});
  const c = capture(k);
  c.exec(`!vtop 0x${va.toString(16)}`);
  assert.match(c.lines.at(-1), /-> 0x[0-9a-f]+  \(4K, kftarget\)/);

  const hole = joinVa(0x111, 0x2, 0x2, 0x2, 0, false);
  const c2 = capture(k);
  c2.exec(`!vtop 0x${hole.toString(16)}`);
  assert.match(c2.lines.at(-1), /not mapped \(PML4E not present/);
});

test("alias eb repair propagates into the physical walk", async () => {
  const { k, pts, proc } = await booted();
  const va = joinVa(0xa, 0xa, 0xa, 0x33, 0, false);
  pts.mapPage(proc, va, {});
  const row = pts.translate(va, proc).rows.at(-1);

  // student edits through the alias like `eb` would: clear NX (bit 63)
  const cur = k.mem.u64(row.entryVa);
  k.mem.w64(row.entryVa, cur & ~(1n << 63n));
  pts.translate(va, proc); // any walk flushes aliases back
  const after = k.mem.u64(row.entryPa);
  assert.equal(after & (1n << 63n), 0n);
});

test("!ssdt lists services and marks the hooked entry; repair clears it", async () => {
  const { k, st, hookIdx } = await booted();

  // install a detour over NtOpenProcess pointing into a fake module range
  const target = 0x60000100n;
  st.kernel.installDetour("NtOpenProcess", target);

  const c = capture(k);
  c.exec("!ssdt");
  const out = c.lines.join("\n");
  assert.match(out, /KiServiceTable @ 0x0000000010200000/);
  assert.match(out, /nt!NtCreateFile/);
  assert.match(out, new RegExp(`\\[\\s*${hookIdx}\\].*NtOpenProcess.*HOOKED.*E9 -> 0x${target.toString(16).padStart(16, "0")}`));

  st.repair(hookIdx);
  const c2 = capture(k);
  c2.exec("!ssdt");
  assert.match(c2.lines.join("\n"), /no inline detours detected/);
});

test("!notifyroutines lists registered callbacks with symbols", async () => {
  const { k } = await booted();
  k.notifyRoutines.process.push(0x60000200n);
  k.obCallbacks = [{ callback: 0x60000300n, altitude: "385201" }];
  const c = capture(k);
  c.exec("!notifyroutines");
  const out = c.lines.join("\n");
  assert.match(out, /process-creation:/);
  assert.match(out, /0x0000000060000200/);
  assert.match(out, /object \(ObRegisterCallbacks\)/);
  assert.match(out, /altitude=385201/);
});
