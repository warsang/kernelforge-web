/**
 * Pool guard write-back persistence (regression for the 'eb' bug report).
 *
 * Reported: `eb <addr> a5…` reported success but `!poolverify` kept seeing
 * the smashed byte — the repair must land in the SAME backing store the
 * guard sweep reads, and survive interleaved emulated calls on BOTH backends
 * (unicorn syncIn/pullAll/syncOut cycles must never clobber sparse-backed
 * repairs with stale pages).
 *
 * Also pins the addressing semantics that caused the original confusion:
 * the guard lives at user_addr + size, so writing A5s at the BLOCK start
 * does not heal anything.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { JsInterpreter } from "@kernelforge/ntsim/src/cpu.mjs";
import { StructTables } from "@kernelforge/ntsim/src/structs.mjs";
import { createUnicornBackend } from "@kernelforge/ntsim-unicorn/src/backend.mjs";
import { getScenario } from "../src/scenarios.js";
import { createCommands } from "../src/debugger.js";

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

async function boot(backend) {
  return getScenario("pool-corrupt").boot({
    makeBackend: (mem) => backend === "unicorn"
      ? createUnicornBackend(mem)
      : new JsInterpreter(mem),
    loadTables,
  });
}

const GUARD = "0xfffff90000001280"; // blocks[1].addr (0x…1200) + size 0x80
const BLOCK = "0xfffff90000001200";

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

/** Tiny guest function used to force a full emulation round-trip
 *  (syncIn -> run -> syncOut) across the pool region. Deliberately placed
 *  on the SAME 4K page as the KfPb guards so the post-run dirty-page
 *  pull-back touches their backing store. */
const PROBE_ADDR = 0xfffff90000001800n;
function retStubBytes() {
  return [0x31, 0xc0, 0xc3]; // xor eax, eax ; ret
}

test("eb guard repair persists across emulation round-trips (both backends)", async () => {
  for (const be of ["js", "unicorn"]) {
    const { kernel } = await boot(be);
    assert.equal(kernel.verifyGuards().length, 1, `[${be}] fixture corrupt count`);

    // wrong-address repair: block start is NOT the guard — stays corrupted
    const wrong = capture(kernel);
    wrong.exec(`eb ${BLOCK} a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5`);
    assert.equal(kernel.verifyGuards().length, 1,
      `[${be}] writing at block start must not clear the guard`);

    // exact-address repair via the debugger surface
    const fix = capture(kernel);
    fix.exec(`eb ${GUARD} a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5`);
    fix.exec("!poolverify");
    assert.match(fix.text(), /all allocation guards intact/, `[${be}] post-eb sweep`);
    assert.equal(kernel.verifyGuards().length, 0, `[${be}] verifyGuards clean`);

    // force emulation cycles AFTER the repair; stale-page pull-back must
    // not resurrect the smashed byte. The probe stub shares a page with
    // the guards, so each run dirties their exact backing page.
    for (let i = 0; i < 3; i++) {
      kernel.mem.write(PROBE_ADDR, Uint8Array.from(retStubBytes()));
      const r = kernel.cpu.callFunction(PROBE_ADDR, []);
      assert.equal(r.status, "ok", `[${be}] probe run ${i}: ${r.error?.message}`);
      assert.equal(kernel.verifyGuards().length, 0,
        `[${be}] guard clobbered by emulation round-trip ${i}`);
    }

    // !poolfind now reports intact guards with explicit addresses
    const after = capture(kernel);
    after.exec("!poolfind KfPb");
    assert.match(after.text(), /guard @ 0xfffff90000001280: intact/);
    assert.doesNotMatch(after.text(), /CORRUPTED/);
  }
});

test("!poolverify output carries exact guard addresses and repair line", async () => {
  const { kernel } = await boot("js");
  const c = capture(kernel);
  c.exec("!poolverify");
  const t = c.text();
  assert.match(t, /guard @ 0xfffff90000001280 guard\[0\]=0xde \(expected 0xa5\)/);
  assert.match(t, new RegExp(`repair: eb ${GUARD.replace(/x/g, "x")} a5 a5`));
});
