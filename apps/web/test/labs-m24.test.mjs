/**
 * Module 24 (dispatch-layer hooks) end to end.
 *
 * Drives the dispatch-hook world headless exactly as the browser would:
 * the windbg hunt (!dispatchscan / !ioctltest / !obopen / !objtype + eb
 * repair), the compiled IRP-hijack attack fixture, and the Sentinel v5
 * attestation fixture — every catalog flag graded through checkFlag.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { StructTables } from "@kernelforge/ntsim/src/structs.mjs";
import { JsInterpreter } from "@kernelforge/ntsim/src/cpu.mjs";
import { createUnicornBackend } from "@kernelforge/ntsim-unicorn/src/backend.mjs";
import { loadCompiledDriver } from "@kernelforge/ntsim-analyzer/src/compiled.mjs";
import { checkFlag } from "@kernelforge/lab-runtime";
import { getScenario, KFDSP_SLOT, KFDSP_FOREIGN_MJ,
  KFDSP_OT_PROCESS } from "../src/scenarios.js";
import { catalog } from "@kernelforge/course-content";
import { createCommands } from "../src/debugger.js";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const TABLES_DIR = path.join(root, "packages/ntsim-assets/data/vergilius/windows-10/22h2");
const FIX = (name) => path.join(root, "packages/compiler-worker/test/fixtures", name);

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

async function boot(id, backend = "js") {
  return getScenario(id).boot({
    makeBackend: (mem) => backend === "unicorn"
      ? createUnicornBackend(mem)
      : new JsInterpreter(mem),
    loadTables,
  });
}

function capture(kernel) {
  let lines = [];
  const commands = createCommands(kernel);
  const exec = async (line) => {
    lines = [];
    const [cmd, ...args] = line.trim().split(/\s+/);
    await commands[cmd]?.(args, (text) => lines.push(text), {});
    return lines.join("\n");
  };
  return { exec };
}

function flagDef(id) {
  for (const m of catalog.modules)
    for (const l of m.lessons ?? [])
      for (const lab of l.labs ?? [])
        for (const f of lab.flags ?? [])
          if (f.id === id) return f;
  throw new Error(`no flag ${id}`);
}

const grade = (answer, id) => checkFlag(answer, flagDef(id));

// ------------------------------------------------------- m24.l1.lab1: hunt

test("dispatch-hook boots with both hooks installed and kfser honest baseline", async () => {
  const { kernel } = await boot("dispatch-hook");
  assert.equal(kernel.mem.u64(KFDSP_SLOT), KFDSP_FOREIGN_MJ, "MJ slot hooked");
  assert.equal(
    kernel.mem.u64(KFDSP_OT_PROCESS + 0x40n), KFDSP_FOREIGN_MJ + 0x100n,
    "Process.OpenProcedure hooked");
});

for (const be of ["js", "unicorn"]) {
  test(`windbg hunt: convict, prove behavior, repair both surfaces (${be})`, async () => {
    const { kernel } = await boot("dispatch-hook", be);
    const c = capture(kernel);

    // --- conviction -----------------------------------------------------
    const scan = await c.exec("!dispatchscan");
    assert.match(scan, /IRP_MJ_DEVICE_CONTROL\s+\S+\s+FOREIGN -> kfsnoop\.sys/,
      `[${be}] foreign slot convicted`);
    assert.match(scan, /repair: eb 0xfffff8055a7100e0/, `[${be}] repair hint`);

    const otscan = await c.exec("!objtype");
    assert.match(otscan, /OpenProcedure.*HOOKED -> \S+ \(kfsnoop\.sys\)/,
      `[${be}] OpenProcedure convicted`);

    // --- behavioral proof -----------------------------------------------
    const ioctl = await c.exec("!ioctltest kfser");
    assert.match(ioctl, /0xdead0001/, `[${be}] hijacked completion`);
    const open = await c.exec("!obopen kftarget.exe");
    assert.match(open, /0xdead0002/, `[${be}] denied by OpenProcedure`);

    // --- repair ----------------------------------------------------------
    kernel.mem.w64(KFDSP_SLOT, 0xfffff8055a710800n);      // honest handler
    kernel.mem.w64(KFDSP_OT_PROCESS + 0x40n, 0n);          // NULL baseline

    const scan2 = await c.exec("!dispatchscan");
    assert.match(scan2, /all wired MajorFunction slots resolve inside their owning image/,
      `[${be}] clean scan`);
    const secret1 = await grade("kf-dispatch-clean", "m24.l1.f3");
    assert.equal(secret1, true, `[${be}] f3 graded`);

    const ioctl2 = await c.exec("!ioctltest kfser");
    assert.match(ioctl2, /honest completion/, `[${be}] honest completion`);
    const open2 = await c.exec("!obopen kftarget.exe");
    assert.match(open2, /handle granted/, `[${be}] grant restored`);

    const otscan2 = await c.exec("!objtype");
    assert.match(otscan2, /all initializer procedures match their baselines/,
      `[${be}] objtype clean`);
  });
}

test("hunt flags grade against catalog answers", async () => {
  assert.equal(await grade("IRP_MJ_DEVICE_CONTROL", "m24.l1.f1"), true, "f1");
  assert.equal(await grade("irp_mj_device_control ", "m24.l1.f1"), true, "f1 normalized");
  assert.equal(await grade("0xfffff8055a720800", "m24.l1.f2"), true, "f2");
  assert.equal(await grade("KF-OBTYPE-CLEAN", "m24.l1.f4"), true, "f4");
  assert.equal(await grade("kf-dispatch-wrong", "m24.l1.f3"), false, "f3 rejects wrong");
});

// ---------------------------------------------------- m24.l1.lab2: attack

async function runFixture(kernel, objBytes, labId, backend = "js") {
  const loaded = loadCompiledDriver(kernel, objBytes, { labId });
  const regPathBuf = kernel.allocPool(0x100);
  kernel.mem.writeUtf16(regPathBuf,
    "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\" + loaded.name);
  return kernel.callFunctionSeh(loaded.entry, [loaded.drvRec.va, regPathBuf],
    loaded.image);
}

for (const be of ["js", "unicorn"]) {
  test(`compiled IRP hook redirects the IOCTL path (${be})`, async () => {
    const { kernel } = await boot("dispatch-hook", be);
    const obj = new Uint8Array(await readFile(FIX("kfirp.obj")));
    const r = await runFixture(kernel, obj, "m24.l1.lab2", be);
    assert.equal(r.status, "ok", `[${be}] fault: ${r.error?.message}`);
    const log = kernel.dbgLog.join("\n");
    assert.match(log, /ATTACK-IRP: victim slot held fffff8055a720800/, `[${be}] observed`);
    assert.match(log, /now -> fffff8055a730000/, `[${be}] rewritten`);

    const c = capture(kernel);
    const ioctl = await c.exec("!ioctltest kfser");
    assert.match(ioctl, /0xdead0003/, `[${be}] trampoline owns completion`);
    const log2 = kernel.dbgLog.join("\n");
    assert.match(log2, /secret=kf-irp-hijack-ok/, `[${be}] payoff secret`);

    assert.equal(await grade("0xdead0003", "m24.l1.f5"), true, `[${be}] f5`);
    assert.equal(await grade("kf-irp-hijack-ok", "m24.l1.f6"), true, `[${be}] f6`);
  });
}

// --------------------------------------------------- m24.l2.lab1: sentinel

test("Sentinel v5 convicts both surfaces with attribution", async () => {
  const { kernel } = await boot("dispatch-hook");
  const obj = new Uint8Array(await readFile(FIX("kfsentinel_v5.obj")));
  const r = await runFixture(kernel, obj, "m24.l2.lab1");
  assert.equal(r.status, "ok", `fault: ${r.error?.message}`);
  const log = kernel.dbgLog.join("\n");

  assert.match(log, /SENTINEL-V5: attesting DRIVER_OBJECT kfser @ fffff8055a710000/);
  assert.match(log, /FOREIGN DISPATCH IRP_MJ_DEVICE_CONTROL -> fffff8055a720800/);
  assert.match(log, /Process\.OpenProcedure HOOKED -> fffff8055a720900/);
  assert.match(log, /secret=kf-sentinel-v5-ok/);

  assert.equal(await grade("kfsnoop.sys", "m24.l2.f1"), true, "f1");
  assert.equal(await grade("0x70", "m24.l2.f2"), true, "f2");
  assert.equal(await grade("kf-sentinel-v5-ok", "m24.l2.f3"), true, "f3");
});
