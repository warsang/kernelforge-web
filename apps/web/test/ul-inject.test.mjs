/**
 * m21 userland-injection lab (#10): the compiled starter must land payload
 * bytes in kftarget.exe through BOTH paths — a tracked handle
 * (ZwOpenProcess/ZwWriteVirtualMemory) and handleless attach — with the
 * engine enforcing access rights on the handle path.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { StructTables } from "@kernelforge/ntsim/src/structs.mjs";
import { JsInterpreter } from "@kernelforge/ntsim/src/cpu.mjs";
import { loadCompiledDriver } from "@kernelforge/ntsim-analyzer/src/compiled.mjs";
import { getScenario } from "../src/scenarios.js";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const TABLES_DIR = path.join(root, "packages/ntsim-assets/data/vergilius/windows-10/22h2");
const FIXTURE = path.join(root, "packages/compiler-worker/test/fixtures/kfulinject.obj");

async function booted() {
  const tables = new StructTables();
  for (const name of ["_EPROCESS", "_LIST_ENTRY", "_UNICODE_STRING",
    "_KLDR_DATA_TABLE_ENTRY", "_PS_PROTECTION", "_KPCR", "_KPRCB", "_ETHREAD"]) {
    const j = JSON.parse(await readFile(path.join(TABLES_DIR, `${name}.json`), "utf8"));
    tables.register(name, j.totalSize, Object.values(j.fieldsByName));
  }
  return getScenario("ul-inject").boot({
    makeBackend: (mem) => new JsInterpreter(mem),
    loadTables: async () => tables,
  });
}

test("handle-based path: ZwWriteVirtualMemory enforces PROCESS_VM_WRITE", async () => {
  const { kernel } = await booted();
  const k = kernel;
  // mint a handle WITHOUT the VM_WRITE bit -> write must be denied
  const implOpen = k.apiImpls.get("ZwOpenProcess");
  const implWrite = k.apiImpls.get("ZwWriteVirtualMemory");
  const hOut = k.allocPool(8);
  const cid = k.allocPool(16);
  k.mem.w64(cid, 888n); // CLIENT_ID.UniqueProcess
  assert.equal(implOpen(hOut, 0x0008n /* VM_OPERATION only */, 0n, cid), 0n);
  const h = k.mem.u64(hOut);
  assert.ok(h > 0n, "handle must be minted");
  const buf = k.allocPool(8);
  assert.equal(implWrite(h, 0x7ff600100000n, buf, 8n, 0n), 0xc0000022n,
    "write without PROCESS_VM_WRITE must be ACCESS_DENIED");
});

test("compiled driver lands both payloads and prints the secret", async () => {
  const { kernel } = await booted();
  const obj = new Uint8Array(await readFile(FIXTURE));
  const loaded = loadCompiledDriver(kernel, obj, { labId: "m21.l1.lab1" });

  const r = kernel.callDriverEntry(loaded.entry, loaded.drvRec.va, 0n);
  assert.equal(r.status, "ok", r.error?.message);
  assert.equal(r.retval, 0n);

  const log = kernel.dbgLog.join("\n");
  assert.match(log, /INJ: handle-based write -> ok/);
  assert.match(log, /INJ: attach-based write -> ok/);
  assert.match(log, /secret=kf-ul-inject-ok/);

  // both payloads really landed at INJECT_VA (+0 and +8)
  const va = kernel.ulInjectTarget.va;
  const bytes = kernel.mem.read(va, 16);
  assert.equal(String.fromCharCode(...bytes.slice(0, 8)), "KFHANDLE");
  assert.equal(String.fromCharCode(...bytes.slice(8, 16)), "KFATTACH");
});
