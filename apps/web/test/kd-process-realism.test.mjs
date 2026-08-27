/**
 * kd output realism (issues #6/#7):
 *   - unique Cids system-wide, PIDs/TIDs valid multiples of 4
 *   - lab fixtures live at realistic non-paged pool addresses with non-zero
 *     tokens and ParentCids — no page-aligned slab look-alikes, no Token 0x0
 *   - full WinDbg-style THREAD lines (Cid pair, Teb, Win32Thread, ApcState)
 *     instead of "(thread image not resident)" stub walls in dump worlds
 *   - `!process <pid|name> <flags>` renders the same block as `!process 0 N`
 *   - `!handles` enumerates the seeded cross-process references (row #3)
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

async function loadFullTables() {
  const names = ["_EPROCESS", "_LIST_ENTRY", "_UNICODE_STRING",
    "_KLDR_DATA_TABLE_ENTRY", "_PS_PROTECTION", "_KPCR", "_KPRCB", "_ETHREAD",
    "_KTHREAD", "_HANDLE_TABLE"];
  const tables = new StructTables();
  for (const name of names) {
    const json = JSON.parse(await readFile(path.join(TABLES_DIR, `${name}.json`), "utf8"));
    tables.register(name, json.totalSize, Object.values(json.fieldsByName));
  }
  return tables;
}

async function bootedDumpWorld() {
  const raw = JSON.parse(await readFile(
    path.join(path.dirname(fileURLToPath(import.meta.url)),
      "../../../apps/web/public/dumps/kdemu-win10-19041.json"), "utf8"));
  return getScenario("boot-default").boot({
    makeBackend: (mem) => new JsInterpreter(mem),
    loadTables: loadFullTables,
    dumpWorld: raw,
  });
}

test("dump world: Cids are unique and PIDs/TIDs are multiples of 4", async () => {
  const { kernel } = await bootedDumpWorld();
  const procs = kernel.listProcesses();
  const pids = procs.map((p) => p.pid);
  assert.equal(new Set(pids).size, pids.length,
    `duplicate Cids in !process listing: ${pids.filter((v, i) => pids.indexOf(v) !== i)}`);
  for (const pid of pids) {
    assert.equal(pid % 4n, 0n, `pid ${pid} is not a multiple of 4`);
  }
  // every seeded thread's Tid must also be a multiple of 4
  const cidOff = BigInt(kernel.tables.offsetOf("_ETHREAD", "Cid"));
  const seen = new Set();
  for (const thr of kernel.threadsByPid?.values() ?? []) {
    const tid = kernel.mem.u64(thr + cidOff + 8n);
    assert.ok(!seen.has(tid), `duplicate Tid ${tid}`);
    seen.add(tid);
    assert.equal(tid % 4n, 0n, `tid ${tid} is not a multiple of 4`);
  }
});

test("fixtures sit at realistic pool addresses with live tokens", async () => {
  const { kernel } = await bootedDumpWorld();
  const cmds = createCommands(kernel);
  const anchors = {
    kfsample: 0xffffa40bc9e731a0n,
    kftarget: 0xffffa40bc9e73dc0n,
  };
  for (const nm of ["kfsample", "kftarget"]) {
    const lines = [];
    cmds["!process"]([nm, "2"], (t) => lines.push(t));
    const text = lines.join("\n");
    assert.match(text, /PROCESS 0x[0-9a-f]+.*Cid: \d+/,
      `${nm}: kd-style header missing`);
    // no page-aligned slab addresses (the old 0xffffc800…000 tell)
    const addrLine = lines.find((l) => l.startsWith("PROCESS "));
    const addr = BigInt(addrLine.match(/PROCESS (0x[0-9a-f]+)/)[1]);
    assert.equal(addr, anchors[nm], `${nm}: EPROC anchor moved`);
    assert.notEqual(addr % 0x1000n, 0n,
      `${nm}: suspiciously page-aligned ${addr.toString(16)}`);
    assert.match(text, /Token: 0xffff/, `${nm}: token must be a kernel pointer`);
    assert.doesNotMatch(text, /Token: 0x0{16}/, `${nm}: NULL token`);
    assert.match(text, /ParentCid: \d{4}/, `${nm}: parent Cid missing`);
  }
});

test("!process 0 7 prints full THREAD lines — no not-resident stub wall", async () => {
  const { kernel } = await bootedDumpWorld();
  const cmds = createCommands(kernel);
  const lines = [];
  cmds["!process"](["0", "7"], (t) => lines.push(t));
  const text = lines.join("\n");
  const threadLines = lines.filter((l) => l.includes("THREAD "));
  assert.ok(threadLines.length >= kernel.listProcesses().length,
    "every process must show at least one THREAD line");
  for (const l of threadLines) {
    assert.doesNotMatch(l, /not resident/,
      `stub output leaked into kd listing: ${l}`);
    assert.match(l, /Cid \d+\.\d+/, `missing CLIENT_ID pair: ${l}`);
    assert.match(l, /Win32Thread:/, `missing Win32Thread: ${l}`);
    assert.match(l, /ApcState->\S+/, `missing ApcState owner: ${l}`);
    if (l.includes("4.6760")) continue; // authentic dumped thread — real bytes
    assert.match(l, /Teb: [0-9a-f]{12,}/, `missing Teb: ${l}`);
  }
  // the dumped CurrentThread keeps its authentic identity
  assert.match(text, /THREAD 0xffff8f8b8eb4d040\s+Cid 4\.6760/);
});

test("!process accepts pid AND name forms across worlds", async () => {
  const { kernel } = await bootedDumpWorld();
  const cmds = createCommands(kernel);
  const byName = [], byPid = [];
  cmds["!process"](["kfsample", "7"], (t) => byName.push(t));
  cmds["!process"](["1312", "7"], (t) => byPid.push(t));
  assert.equal(byName.join("\n"), byPid.join("\n"),
    "name and pid resolution must agree");
  assert.match(byName.join("\n"), /ImageFileName: kfsample\.exe/);
  // lsass has different pids between worlds; its NAME must still resolve
  const l = [];
  cmds["!process"](["lsass", "7"], (t) => l.push(t));
  assert.match(l.join("\n"), /ImageFileName: lsass\.exe/);
});

test("!handles enumerates the seeded cross-process references", async () => {
  const { kernel } = await bootedDumpWorld();
  const cmds = createCommands(kernel);
  const all = [];
  cmds["!handles"]([], (t) => all.push(t));
  const text = all.join("\n");
  // targets must point at CURRENT eproc addresses, not bootstrap-era blocks
  const target = kernel.processesByName.get("kftarget.exe");
  assert.match(text, new RegExp(`kfsample\\.exe.*${target.toString(16)}`),
    "kfsample→kftarget reference must survive the dump rebuild");
  const filtered = [];
  cmds["!handles"](["services"], (t) => filtered.push(t));
  assert.match(filtered.join("\n"), /lsass\.exe|ffff/);
});
