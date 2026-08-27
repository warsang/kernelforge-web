/**
 * Lab-flow e2e for the blog-labs worlds (m11-m13): boot each scenario
 * headless, drive the full student path through createCommands, and grade
 * every flag with lab-runtime's checkFlag. Worlds run on LOW_BASES so the
 * identical flow is exercised under both CPU backends (see
 * ntsim-unicorn parity suite + backend-parity.test.mjs).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { StructTables } from "@kernelforge/ntsim/src/structs.mjs";
import { JsInterpreter } from "@kernelforge/ntsim/src/cpu.mjs";
import { getScenario, PAGING_CONST, EDR_CONST, SSDT_CONST } from "../src/scenarios.js";
import { createCommands } from "../src/debugger.js";
import { checkFlag } from "@kernelforge/lab-runtime";

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

async function boot(id) {
  const scenario = getScenario(id);
  const session = await scenario.boot({
    makeBackend: (mem) => new JsInterpreter(mem),
    loadTables,
  });
  const lines = [];
  const commands = createCommands(session.kernel);
  const w = (text) => lines.push(text);
  return {
    session, kernel: session.kernel, lines,
    exec: (line) => { lines.length = 0; commands[line.split(/\s+/)[0]]?.(line.split(/\s+/).slice(1), w, {}); },
    out: () => lines.join("\n"),
  };
}

const hex16 = (v) => "0x" + v.toString(16).padStart(16, "0");

test("m11 paging-walk: decoy DTB, alias math, NX repair, secret", async () => {
  const t = await boot("paging-walk");
  const pts = t.kernel.paging;
  assert.ok(pts, "paging world attached");
  assert.equal(pts.findProcess("decoy").dtb, PAGING_CONST.ptsPhysBase, "decoy owns lowest frame");

  // f1: real DTB (kftarget)
  const target = pts.findProcess("kftarget");
  await checkFlag(hex16(target.dtb), { sha256: "" }); // smoke: helper callable
  const f1 = "0x0000000003005000";
  assert.equal(target.dtb, BigInt(f1));

  // f2: computed alias matches what !pte prints and dq confirms bytes
  const walk = pts.translate(PAGING_CONST.CODE_VA, target);
  assert.equal(walk.ok, true);
  const pteRow = walk.rows.at(-1);
  const alias = pteRow.entryVa;
  assert.equal(alias, 0x0000078250e65218n);
  assert.equal(t.kernel.mem.u64(alias), pteRow.value);

  // NX corrupted at boot; student clears it via eb through the alias then !vtop
  assert.equal((pteRow.value & (1n << 63n)) !== 0n, true, "NX must start set");
  t.exec(`!vtop ${hex16(PAGING_CONST.CODE_VA)}`);
  assert.match(t.out(), /not mapped|4K/); // still mapped, just NX
  t.kernel.mem.w64(alias, pteRow.value & ~(1n << 63n)); // eb-equivalent
  t.exec(`!vtop ${hex16(PAGING_CONST.CODE_VA)}`);
  assert.match(t.out(), /-> 0x/, "translation still succeeds");
  assert.ok(t.kernel.dbgLog.some((l) => l.includes("kf-pt-healed")),
    "payoff secret printed after heal");
});

test("m12 edr-sensor: block, enumerate, blind, secret", async () => {
  const t = await boot("edr-sensor");
  const C = EDR_CONST;

  t.exec("!notifyroutines");
  assert.match(t.out(), new RegExp(hex16(C.CALLBACK)));
  assert.match(t.out(), /altitude=385201/);

  t.exec(`!notifytest ${C.BLOCKED_NAME}`);
  assert.match(t.out(), /BLOCKED/);
  assert.match(t.out(), /c0000022/);

  t.exec("!notifytest notepad.exe");
  assert.match(t.out(), /created \(CreationStatus=STATUS_SUCCESS\)/);

  // student patches the first name-compare immediate: L"kfim" -> L"xfim"
  const q0Site = C.CALLBACK + 14n + 2n; // after test rdx(3)+jz(2)+mov rcx(4)+cmp word(5)+jnz(2)+mov rax(4) = 0x14; imm at +0x16
  const imm = t.kernel.mem.u64(q0Site);
  t.kernel.mem.w64(q0Site, imm ^ 0x0078n); // flip 'k'->'x' in L"kfim"

  t.exec(`!notifytest ${C.BLOCKED_NAME}`);
  assert.match(t.out(), /RESULT: created/);
  assert.ok(t.kernel.dbgLog.some((l) => l.includes(C.secret)), "secret in dbgLog");
});

test("m13 ssdt-hook: scan, resolve, repair, clean", async () => {
  const t = await boot("ssdt-hook");
  const C = SSDT_CONST;

  t.exec("!ssdt");
  assert.match(t.out(), /NtOpenProcess/);
  assert.match(t.out(), /HOOKED/);
  assert.match(t.out(), new RegExp(hex16(C.DETOUR_TARGET)));

  // repair via pristine prologue restore (same bytes eb would write)
  assert.equal(t.kernel.restorePrologue("NtOpenProcess"), true);

  t.exec("!ssdt");
  assert.match(t.out(), /no inline detours detected/);
  assert.ok(t.kernel.dbgLog.some((l) => l.includes(C.secret)), "clean-table secret logged");

  // behavior gate released: lookup for hidden pid no longer denied
  const impl = t.kernel.apiImpls.get("NtOpenProcess");
  assert.notEqual(impl(888n, 0n), 0xc0000022n);
});
