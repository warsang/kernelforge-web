/**
 * Module 28 (VM-exit MSR interception) end to end:
 *  - msr-exit world: hypervisor traps LSTAR writes via VM-exit
 *  - Install redirect, prove it, detect hypervisor via !vmexit
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { StructTables } from "@kernelforge/ntsim/src/structs.mjs";
import { JsInterpreter } from "@kernelforge/ntsim/src/cpu.mjs";
import { checkFlag } from "@kernelforge/lab-runtime";
import { getScenario } from "../src/scenarios.js";
import { createCommands } from "../src/debugger.js";
import { catalog } from "@kernelforge/course-content";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const TABLES_DIR = path.join(root, "packages/ntsim-assets/data/vergilius/windows-10/22h2");

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

async function boot(id) {
  return getScenario(id).boot({
    makeBackend: (mem) => new JsInterpreter(mem),
    loadTables,
  });
}

function capture(kernel) {
  let lines = [];
  const commands = createCommands(kernel);
  const exec = async (line) => {
    lines = [];
    const [cmd, ...args] = line.trim().split(/\s+/);
    await commands[cmd]?.(args, (t) => lines.push(t), {});
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

test("msr-exit world: hypervisor intercepts LSTAR, !vmexit detects it", async () => {
  const { kernel } = await boot("msr-exit");
  const c = capture(kernel);

  // Baseline: LSTAR points to KiSystemCallHandler
  const baseline = kernel.rdmsr(0xC0000082n);
  assert.ok(baseline > 0n, "LSTAR has baseline value");

  // Install redirect via !msr (guest thinks write succeeded)
  await c.exec("!msr lstar 0xfffff8055a768000");
  
  // Guest sees its value
  const guestView = kernel.rdmsr(0xC0000082n);
  assert.equal(guestView, 0xfffff8055a768000n, "guest sees its redirect");

  // !syscalltest proves the redirect (through the intercepted path)
  const syscallOut = await c.exec("!syscalltest");
  assert.match(syscallOut, /FOREIGN handler executed/, "syscall routes to foreign handler");

  // !vmexit shows the trap log
  const vmexitOut = await c.exec("!vmexit");
  assert.match(vmexitOut, /VM-exit log/, "trap log present");
  assert.match(vmexitOut, /WRMSR.*LSTAR/, "WRMSR trapped");
  assert.match(vmexitOut, /secret=kf-vmexit-detected/, "detection secret");

  // Flags
  assert.equal(await grade("0xc0000082", "m28.l1.f1"), true, "f1");
  assert.equal(await grade("kf-vmexit-detected", "m28.l1.f2"), true, "f2");
});

test("msr-exit: hypervisor can modify value between reads", async () => {
  const { kernel } = await boot("msr-exit");
  
  // Read LSTAR twice with a "serializing instruction" between
  // In reality, hypervisor could modify between reads
  const read1 = kernel.rdmsr(0xC0000082n);
  // Simulate hypervisor modifying value (in real attack, this happens via VM-exit)
  kernel.msrFile.set(0xC0000082n, 0xfffff8055a769999n); // hypervisor changes it
  const read2 = kernel.rdmsr(0xC0000082n);
  
  // Both reads go through intercept, so both see hypervisor's value
  assert.equal(read1, read2, "both reads return hypervisor's value");
  assert.notEqual(read1, 0xfffff8055a768000n, "not the guest's value");
});
