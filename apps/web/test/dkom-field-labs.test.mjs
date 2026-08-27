/**
 * m23 DKOM field labs (#11): PPL removal (eb the Protection byte -> open
 * succeeds + secret) and Cid spoofing (UniqueProcessId -> 4 duplicates the
 * System identity in !process while ApcState still tells the truth).
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
    "_KLDR_DATA_TABLE_ENTRY", "_PS_PROTECTION", "_KPCR", "_KPRCB", "_ETHREAD", "_KTHREAD"];
  const tables = new StructTables();
  for (const name of names) {
    const json = JSON.parse(await readFile(path.join(TABLES_DIR, `${name}.json`), "utf8"));
    tables.register(name, json.totalSize, Object.values(json.fieldsByName));
  }
  return tables;
}
const boot = async (id) => getScenario(id).boot({
  makeBackend: (mem) => new JsInterpreter(mem), loadTables,
});

test("PPL lab: open denied while protected, secret after the DKOM strip", async () => {
  const { kernel } = await boot("dkom-ppl");
  const cmds = createCommands(kernel);
  const lines = [];

  cmds["!openprocess"](["108"], (t) => lines.push(t));
  assert.match(lines.join("\n"), /STATUS_ACCESS_DENIED/, "PPL must deny the open");

  const lsass = kernel.processesByName.get("lsass.exe");
  const protOff = BigInt(kernel.tables.offsetOf("_EPROCESS", "Protection"));
  assert.equal(kernel.mem.u8(lsass + protOff), 0x62);
  kernel.mem.w8(lsass + protOff, 0x00); // the DKOM

  cmds["!openprocess"](["108", "0x143a"], (t) => lines.push(t));
  const text = lines.join("\n");
  assert.match(text, /STATUS_SUCCESS\s+handle 0x/);
  assert.match(text, /secret=kf-ppl-off/);
});

test("PID lab: spoofed Cid 0004 lists twice; ApcState still tells the truth", async () => {
  const { kernel } = await boot("dkom-pid");
  const cmds = createCommands(kernel);
  const kftarget = kernel.processesByName.get("kftarget.exe");

  // sanity: unique before
  let lines = [];
  cmds["!process"](["0", "0"], (t) => lines.push(t));
  assert.equal(lines.filter((l) => l.includes("Cid: 0004")).length, 1);

  // spoof UniqueProcessId (+0x440) to 4 via plain memory write == eb semantics
  const pidOff = BigInt(kernel.tables.offsetOf("_EPROCESS", "UniqueProcessId"));
  kernel.mem.w64(kftarget + pidOff, 4n);

  lines = [];
  cmds["!process"](["0", "0"], (t) => lines.push(t));
  assert.equal(lines.filter((l) => l.includes("Cid: 0004")).length, 2,
    "spoofed process must now wear System's Cid");

  // cross-check: the thread's ApcState back-pointer still names kftarget.exe
  const apcOff = BigInt(kernel.tables.offsetOf("_KTHREAD", "ApcState"));
  const thr = kernel.threadsByPid.get(888n);
  const owner = kernel.mem.u64(thr + apcOff);
  const name = kernel.mem.readAnsi(
    owner + BigInt(kernel.tables.offsetOf("_EPROCESS", "ImageFileName")), 15);
  assert.match(name, /kftarget\.exe/, "identity survives in ApcState");
});
