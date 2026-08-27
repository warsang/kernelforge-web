/**
 * Module 10 lab flow, headless: static analysis over the api-hook world.
 * Drives the real scenario + debugger command surface exactly as the
 * browser would — no wasm decompiler required for the graded flow.
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
import { checkFlag } from "@kernelforge/lab-runtime";

const TABLES_DIR = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../packages/ntsim-assets/data/vergilius/windows-10/22h2"
);

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

function capture(kernel) {
  const lines = [];
  const commands = createCommands(kernel);
  const w = (text, cls = "") => lines.push(cls ? `[${cls}]${text}` : text);
  const exec = (line) => {
    const [cmd, ...args] = line.trim().split(/\s+/);
    commands[cmd]?.(args, w, {});
  };
  return { exec, lines, text: () => lines.join("\n") };
}

test("m10.l1: !funcs recovers the kfhook.sys grid and answers grade true", async () => {
  const boot = getScenario("api-hook").boot;
  const { kernel } = await boot({
    makeBackend: (mem) => new JsInterpreter(mem),
    loadTables,
  });
  const c = capture(kernel);

  c.exec("!funcs kfhook.sys");
  const text = c.text();
  assert.match(text, /kfhook\.sys — 128 function\(s\)/);
  assert.ok(text.includes("0xfffff8055a601000"), "first boundary == detour page");
  assert.ok(text.includes("0xfffff8055a601010"), "second function listed");
});

test("m10.l1.f3: hookscan resolves the detour target statically", async () => {
  const boot = getScenario("api-hook").boot;
  const { kernel } = await boot({
    makeBackend: (mem) => new JsInterpreter(mem),
    loadTables,
  });
  const c = capture(kernel);
  c.exec("!hookscan");
  assert.match(c.text(), /detour\s+:\s+->\s+0xfffff8055a601000/);
});

test("m10 flag hashes accept the statically-derived answers", async () => {
  const { catalog } = await import("@kernelforge/course-content");
  const flags = catalog.modules
    .flatMap((m) => m.lessons).flatMap((l) => l.labs)
    .flatMap((x) => x.flags);
  const cases = {
    "m10.l1.f1": "128",
    "m10.l1.f2": "0xfffff8055a601010",
    "m10.l1.f3": "0xfffff8055a601000",
  };
  for (const [id, plain] of Object.entries(cases)) {
    const def = flags.find((f) => f.id === id);
    assert.ok(def, `missing ${id}`);
    assert.equal(await checkFlag(plain, def), true, `${id} accepts ${plain}`);
  }
});

test("!decomp degrades loudly without vendored wasm but resolves rel32 statically", async () => {
  const boot = getScenario("api-hook").boot;
  const { kernel } = await boot({
    makeBackend: (mem) => new JsInterpreter(mem),
    loadTables,
  });

  // the hooked thunk address comes from hookscan; resolve its E9 target
  const thunk = kernel.apiThunks.get("PsLookupProcessByProcessId");
  const c = capture(kernel);
  c.exec(`!decomp 0x${thunk.toString(16)}`);
  await new Promise((r) => setTimeout(r, 20)); // promise-based degrade path
  const text = c.text();
  assert.match(text, /!decomp: ghidra-decompiler wasm not vendored/);
});
