/**
 * Module 27 (userland deep cuts) end to end: vtable swap, hot-patch sled,
 * DRx hook vs the thread-context audit — driven through the SogenConsole
 * exactly as the browser lab would, flags graded via checkFlag.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { checkFlag } from "@kernelforge/lab-runtime";
import { UCHOOKS_CONSTANTS, SogenConsole } from "@kernelforge/sogen-runtime";
import { getScenario } from "../src/scenarios.js";
import { catalog } from "@kernelforge/course-content";

const C = UCHOOKS_CONSTANTS;

function flagDef(id) {
  for (const m of catalog.modules)
    for (const l of m.lessons ?? [])
      for (const lab of l.labs ?? [])
        for (const f of lab.flags ?? [])
          if (f.id === id) return f;
  throw new Error(`no flag ${id}`);
}

const grade = (answer, id) => checkFlag(answer, flagDef(id));

async function boot(id) {
  const session = await getScenario(id).boot({});
  const world = session.world;
  return { world, con: new SogenConsole(world) };
}

test("vtable-hook: hijacked call routes to cheat stub; restore heals", async () => {
  const { world, con } = await boot("vtable-hook");
  assert.equal(world.mem.u64(C.objectVa), C.vtableFake, "pre-swapped");

  const out1 = con.execute("!callview");
  assert.match(out1, /FOREIGN/);
  assert.match(out1, /REWRITTEN to 84\.2/);
  assert.match(con.execute("!callview"), /FOREIGN/, "still hooked");

  // student repair: point the object back at the honest table
  world.mem.w64(C.objectVa, C.vtableHonest);
  const out2 = con.execute("!callview");
  assert.match(out2, /passthrough OK/);
  assert.match(out2, /secret=kf-vtable-restored/);

  assert.equal(await grade("0x02100800", "m27.l1.f1"), true, "f1");
  assert.equal(await grade("0x0046f020", "m27.l1.f2"), true, "f2");
  assert.equal(await grade("kf-vtable-restored", "m27.l1.f3"), true, "f3");
});

test("hotpatch-hook: sled E9 rewrites spread; NOPs heal it", async () => {
  const { world, con } = await boot("hotpatch-hook");
  const site = C.calcSpreadFn;
  assert.deepEqual(Array.from(world.mem.read(site, 7)),
    [0x90, 0x90, 0x90, 0x90, 0x90, 0x8b, 0xff], "pristine sled+marker");

  // install the atomic detour into the sled
  const stub = C.cheatStub;
  const rel = Number(stub - (site + 5n)) >>> 0;
  world.mem.write(site,
    [0xe9, rel & 0xff, (rel >>> 8) & 0xff, (rel >>> 16) & 0xff, (rel >>> 24) & 0xff]);
  const hooked = con.execute("!spreadtest");
  assert.match(hooked, /detoured via sled/);
  assert.match(hooked, /REWRITTEN to 0\.010/);

  // hookscan-style pristine diff sees it
  assert.ok(world.hookscan().length > 0, "bytes differ from baseline");

  // heal
  world.mem.write(site, [0x90, 0x90, 0x90, 0x90, 0x90]);
  const honest = con.execute("!spreadtest");
  assert.match(honest, /honest \(spread 2\.400\)/);
  assert.match(honest, /secret=kf-hotpatch-restored/);

  assert.equal(await grade("0x00452060", "m27.l1.f4"), true, "f4");
  assert.equal(await grade("5", "m27.l1.f5"), true, "f5");
  assert.equal(await grade("kf-hotpatch-restored", "m27.l1.f6"), true, "f6");
});

test("drx-hook: trips without byte changes; audit flags; clean-after-use heals", async () => {
  const { world, con } = await boot("drx-hook");
  const before = Array.from(world.mem.read(C.sendInputFn, 8));

  assert.match(con.execute(`!drset 0x${C.sendInputFn.toString(16)}`),
    /execute bp armed/);
  const frames = con.execute("!frametest 16");
  assert.match(frames, /#DB raised 16 time\(s\)/);
  assert.deepEqual(Array.from(world.mem.read(C.sendInputFn, 8)), before,
    ".text untouched");

  const audit1 = con.execute("!drxaudit");
  assert.match(audit1, /FLAGGED/);

  assert.match(con.execute("!drclear"), /cleared/);
  const audit2 = con.execute("!drxaudit");
  assert.match(audit2, /DR0-DR7 all zero/);
  assert.match(audit2, /secret=kf-drx-clean/);
  assert.equal(world.trips, 16);

  assert.equal(await grade("16", "m27.l1.f7"), true, "f7");
  assert.equal(await grade("flagged", "m27.l1.f8"), true, "f8");
  assert.equal(await grade("kf-drx-clean", "m27.l1.f9"), true, "f9");
});
