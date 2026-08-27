# KERNELFORGE build-out plan (modules 2–4)

Status: approved 2026-08. Supersedes the roadmap stub previously only in README.

## Ground rules

- All work bases on `main`. `feat/browsercc-wasm` is owned by another agent — do not merge.
- Compiler labs use the existing `/api/compile` dev bridge until browsercc lands.
- Flags are **plain question answers** (no `FLAG{}` wrapper). Submissions are
  normalized (trim + lowercase) then sha256'd against precomputed constants in
  `packages/course-content/src/catalog.mjs`. Prompts pin the exact format
  (decimal / 0x-hex / symbol name) so grading stays unambiguous.

## Shipped baseline

Module 1 — Windows Kernel Fundamentals & Manual Mapping (`boot-default`,
`dkom-hide`, `manual-map` scenarios; windbg/compiler/ntsim labs).

## Module 2 — IRQL & Deferred Procedures (scenarios `irql-dpc`, `irql-attackers`, `irql-hardened`)

Infra (ntsim):
- Real IRQL model on `NtKernel`: raise/lower validation (raise below current or
  lower above current => modeled bugcheck 0xA), level-name table, per-core
  side-state (`cpuIrqls`, core 0 aliases `currentIrql`).
- Per-kernel DPC queue: `KeInitializeDpc`/`KeInsertQueueDpc` (deduped),
  `KeRemoveQueueDpc`, `drainDpcs()` (retire + scenario hook) and
  `retireQueuedDpcs()`/`advanceTicks()` (retire + CPU execution).
- KTIMER model (`setTimer`/`cancelTimer`, periodic re-arm), fired by the
  `!dpcpump [n]` lab clock; timers never fire while the executing core is
  above DISPATCH_LEVEL.
- Directed DPCs: `KeSetTargetProcessorDpc` records a target core; insertion
  raises that core to DISPATCH; `KfReleaseDirectedDpcs` unpins.
- Control registers: `KfReadCr0/KfWriteCr0/KfCli/KfSti` thunks behind wdm.h
  intrinsic shims; `hvciMode` intercepts WP-clearing writes with bugcheck
  0x109; `protectRange`/`scanProtectedRanges` power `!pgscan`.
- DPC watchdog analog: `checkDpcWatchdog()` raises 0x133 when any secondary
  core sits at/above DISPATCH or the executing core sits above it.

Debugger: `!irql [<n>|-a]` (inspect / all cores / lab-extension force),
`!dpcs`, `!dpcdrain` (refuses above DISPATCH_LEVEL, executes routines),
`!dpcpump [n]`, `!dpcstat`, `!dpcwatchdog`, `!pgscan`.

Lab flow (m2.l1/m2.l2): boot world where `kfdpc.sys` left the CPU at
POWER_LEVEL with a queued-not-drained DPC; student reads IRQL, records
DeferredRoutine address, lowers to DISPATCH and drains to release the secret;
then compiles the v2 watchdog to do the same from ring 0.

Attack workshop (m2.l3, world `irql-attackers`; anchors in scenarios.js
`KFWARZ_*`): four compiled attack drivers — WPOFFx64 canary patch inside a
raised window (flags: window IRQL, restored CR0), directed-DPC lockdown
(flags: pinned-core count, 0x133), timer-DPC persistence (flags: payload runs
after `!dpcpump 13`, payload IRQL), DeferredRoutine hijack (flags: victim DPC
VA, payoff secret `kf-hijack-seen`). Fixtures:
`packages/compiler-worker/test/fixtures/kf{wpoff,lockdown,timerdpc,hijack}.obj`
compiled from the exact starter text by `scripts/gen-m2-fixtures.mjs`.

Defense workshop (m2.l4): telemetry sensor on the pinned world (queue depth +
secret), self-watchdog deadline alarm under lockdown (`missed` +
`kf-deadline-ok`), baseline forensics sweep via the new commands (timer
period, boot queue depth), and the HVCI ceiling where the same WPOFFx64
source dies with 0x109.

## Module 3 — Inline Hooks & Control Flow (scenario `api-hook`)

Infra (ntsim):
- Pristine prologue snapshots for every defined API thunk (recorded in
  `defineApi`).
- Detour modeling: scenario writes an `E9 rel32` over a chosen thunk;
  behavior gates read live bytes, so repairing with `eb` instantly unhooks.

Debugger: `!hookscan [module]` diffs live vs pristine bytes and symbolizes the
detour target; repair uses existing `eb`; `!hooktest <api> <args…>` exercises
the modeled call.

Lab flow: `kfhook.sys` detoured `PsLookupProcessByProcessId` to hide PID 888.
Student identifies the hooked export, the suppressed PID, restores the
prologue, and confirms the lookup succeeds again.

Answers: hooked export name, hidden PID (decimal), post-repair NTSTATUS
symbolic name.

## Module 4 — Pool Internals & Corruption (scenario `pool-corrupt`)

Infra (ntsim):
- Pool upgrade: per-allocation header (magic) + trailing 16-byte 0xA5 guard,
  double-free detection (`BAD_POOL_CALLER` modeled bugcheck),
  `registerPoolBlock()` for scenario-seeded fixed-address allocations,
  `verifyGuards()` sweep.

Debugger: `!poolfind <tag>` (blocks + guard health + expected bytes),
`!poolverify`.

Lab flow: `kfpooler.sys` manages tagged `KfPb` blocks; one guard was smashed
by an upstream overflow. Student locates the corrupted block, repairs the
guard with `eb`, verifies, and captures the checksum secret.

Answers: corrupted block user VA (0x…), heal secret string.

## Module 5 — Tracing & Anti-Tracing (scenario `anti-trace`)

Infra (ntsim):
- CPU: RFLAGS.TF (bit 8) modeled; `PUSHFQ`/`POPFQ` (0x9C/0x9D) compose and
  reload the live flag image; `MOV SS` (0x8E /2) opens the Intel-documented
  one-instruction debug-exception inhibit window; `run()` raises
  `EXCEPTION_SINGLE_STEP` after an instruction executes with TF armed,
  auto-clears TF, and routes to `onDebugException` (handled = continue,
  unhandled = debugger-style stop, surfaced by `callFunction` as
  `debug-stop`). grp1 `0x81` fixed to canonical sign-extended imm32.
- Kernel: vectored-handler list (`registerVectoredHandler`),
  `deliverDebugException()` with deterministic counters
  (`int1Raised` / `vehHandled` / `swallowedByTracer`), attached-tracer
  simulation that intercepts events BEFORE guest handlers.

Debugger: `!traceinfo` (defenses map + counters), `!trace [on|off]`
(attach/detach simulated tracer — arms/clears TF), `!selftest` (executes
real guest sequences: variant A pushfq probe, variant B TF injection into
kftrace!TraceVeh, mov-ss stalled injection with unmasked snapshot).
`r` now prints the EFLAGS image including TF state.

Lab flow: `kftrace.sys` guards a payload secret. Student maps the defenses
(VEH address), validates every tripwire under the tracer (exactly 4 INT 1s
swallowed before TraceVeh sees one), then eb-clears `g_AntiTraceEnabled`
and reruns clean to release the secret.

Answers: TraceVeh VA (0x…), swallowed-event count (decimal), bypass secret.

## Integration checklist

- `catalog.version = 2`; lesson chain `m1.l3 -> m2.l1 -> m3.l1 -> m4.l1 -> m5.l1`.
- Lesson bodies ship as markdown-in-JS under `packages/course-content/src/lessons/`
  rendered client-side via `marked`.
- e2e extended: every new lab boots headless and accepts its answers.
- Unit tests mirror existing patterns (`winapi.test.mjs`, `debugger.test.mjs`,
  scenario tests) for IRQL/DPC/pool/hook infra and each debugger command.

## Later phases

Phase 2 Sogen/Sauerbraten userland track · Phase 3 v86 Linux LKM track ·
Phase 4 shadow-EPT hypervisor · Phase 5 UEFI bootkit sim · Phase 6 BYOVD labs.

## Phases 2–3 + Ghidra pane (implemented on feat/tracks-userland-linux-ghidra)

Status: implemented 2026-08. Branch base: main @ 7cf7a81. Worktree:
`../kf-phases234`. Catalog v3.

### M0 — platform plumbing
- apps/web pane registry (`panes.js`): lab.kind -> backends/debugger/editor;
  main.js core flow untouched by tracks.
- Vendored-wasm convention (from ntsim-unicorn): pinned provenance README +
  rebuild recipe + lazy dynamic import + loud degrade.

### Phase 2 — sogen userland track (modules 5–6)
- `packages/sogen-runtime`: sogen-shaped session API over a deterministic
  plain-JS reference backend; headless Sauerbraten world with pinned
  constants (image base 0x00400000, entity array stride 0x40, local player
  0x021000d0, health +0x24, cl_sendinput 0x004532a0, cheat stub 0x0046f010).
- kd-style console engine: lm/pe/x/scan/eb/hookscan + !damage/!inputtest.
- Wine root tooling: tools/build-wine-root.mjs (manifest + sha256s).
- GUI decision gate: docs/spike-sogen-gui.md — playable client is a stretch
  goal; OpenGL-in-wasm is the hard part (GPU paravirt is D3D/DXVK-shaped).
- Upgrade path: vendor the real sogen wasm core behind the same API.
- Instructor answers: m5 = 0x00400000 / 0x021000d0 / 0x24;
  m6 = 0x004532a0 / 0x0046f010 / kf-input-restored.

### Phase 3 — v86 linux track (modules 7–9)
- `packages/v86-lab`: serial capture harness (KFFLAG extraction), lazy v86
  session with instructive degrade, guest seed registry, dockerized buildroot
  script (kprobes on, KASLR off), kfvillain rootkit source (GPL-2.0) overlay.
- compiler-worker: ELF32 relocatable parser + i386 module staging
  (parseElf / validateLinuxModule / stageLinuxModule); final linking happens
  in-guest via gcc+insmod driven over serial.
- Instructor answers: m7 = 128 (__NR_init_module i386) / kf-lkm-hello;
  m8 = 11 (__NR_execve i386) / kf-trace-ok; m9 = 3 hidden tasks /
  kf-detector-ok. Seeds single-sourced in packages/v86-lab/src/seeds.mjs.

### Ghidra decompiler pane (module 10)
- `packages/ghidra-decompiler`: deterministic x64 prologue boundary scan,
  E9/E8 resolution, analyzeExtent helper, byte-stable function-grid writer
  for scenario worlds; real pseudocode via Ghidra's native decompiler
  compiled to wasm once vendored (loud DecompilerUnavailableError until then).
- debugger commands: !funcs <module> (static recovery listing + rel32 sites),
  !decomp <addr> (wasm path + static fallback info).
- api-hook world extended with a byte-stable 128-function grid inside
  kfhook.sys (evidence strings moved to a dedicated page).
- Instructor answers: m10 = 128 functions / 0xfffff8055a601010 /
  0xfffff8055a601000.

### Integration checklist status
- [x] catalog.version = 3; chain m1.l1 -> ... -> m10.l1 (linear).
- [x] Lessons ship as markdown-in-JS under packages/course-content/src/lessons/.
- [x] Unit tests per package (world constants, console flows, serial harness,
      ELF staging, boundary scanner); lab-flow tests drive the real scenario +
      command surface headless (labs-m2m4 pattern, labs-m10 added).
- [x] npm test + tsc --build green at every commit.
- [x] Ghidra decompiler wasm VENDORED (feat/debugger-analysis-suite): pyre
      pipeline via `npm run vendor:ghidra`; shim + dual-path loader; !decomp/
      !pseudocode feed whole module images. Artifacts untracked.
- [x] sogen wasm debugger client landed (same branch): FB codec
      (src/fb/debugger.mjs) + createWasmClient/createSogenDebugSession;
      shell binds to the real emulated process when assets probe ok AND a
      target binary is staged via the lab card upload. Windows emulation root
      (root.zip) still BYO for DLL-linked PEs.
- [x] Floating pyre-style analysis workspace (sidebar → Tools → ⚗ Ghidra
      Analysis): overlay window with functions/disasm/CFG/pseudocode/memory/
      script tabs; never navigates away from the lesson.
- Pending vendors: v86 bundle + bzImage artifact (documented in its
  package's vendor/README.md).

### Defense build-out: KF-Sentinel + debugger hardening (feat/defense-labs-debugger-fixes)

Course arc for the windows-kernel track is now explicitly
**attack theory -> attack lab -> defense theory -> defense lab**; every
custom `!command` is called out as a debugger extension in its lesson, with
the driver-mode C that produces the same information from inside the kernel.

**Debugger/emulator fixes (bug reports):**
- pool-corrupt `eb` write-back: guard addressing made unambiguous
  (`!poolfind`/`!poolverify` print `guard @ user_va+size` and a
  copy-pasteable eb line); persistence across unicorn syncIn/pullAll/syncOut
  cycles pinned by apps/web/test/pool-guard-persistence.test.mjs on both
  backends. Root cause of the original report was writing at the BLOCK start;
  output now makes that mistake impossible to make silently.
- missing commands added: u/uf (capstone-wasm; low-alias-base strategy keeps
  >2^53 kernel VAs exact), da/du, x, ?, !drivers, !drvobj (+!drivobj alias);
  db/dq/s parse WinDbg L<hex> length prefixes (NaN-BigInt fix) plus
  backtick-stripping and symbol args (nt!Export, module+offset).
- module extents materialized (int3-padded) + pre-mapped via
  UnicornCpuBackend.mapRange when a module joins lm — fixes !dh/s/u over
  kfhook.sys detour pages and compiled kf_*.sys images
  (NtKernel.materializeModuleRange).
- dt nt!_MMVAD / _MMVAD_SHORT: teaching tables hand-authored from public
  Vergilius 22h2 x64 dumps (marked synthetic-teaching), registered through
  both table loaders.

**KF-Sentinel defense lessons/labs (compiler kind, real wasm clang):**
- m1.l4 v1 (`sentinel-m1`): list-vs-carve DKOM detection + unbacked-exec
  classification against a linked KLDR chain. Answers: 888 / 6 / kf-sentinel-v1-ok.
- m2.l2 v2 (`irql-dpc`): IRQL watchdog samples KeGetCurrentIrql, restores
  DISPATCH_LEVEL, releases the stranded DPC. Answers: 15 / kf-watchdog-ok.
- m3.l2 v3 (`api-hook`): prologue attestation engine vs known-good baseline;
  convicts kfhook.sys's E9. Answers: PsLookupProcessByProcessId / kf-attest-ok.
- m4.l2 v4 (`pool-corrupt`): pool integrity monitor sweeps KfPb guard
  trailers in-driver. Answers: 0xfffff90000001200 / kf-poolmon-ok.
- Starters single-sourced in packages/course-content/src/starters.mjs;
  committed COFF fixtures compiled from the exact same text
  (packages/compiler-worker/test/fixtures/kfsentinel_v*.obj); verification
  matches the sensor's own DbgPrint telemetry (main.js COMPILE_TASKS).
- Progression chain extended linearly: ...m1.l4 -> m2.l1 -> m2.l2 -> m2.l3 ->
  m2.l4 -> m3.l1 ->
  m3.l2 -> m4.l1 -> m4.l2 -> m5.l1...

**Fidelity fixes surfaced by compiled sensor code:**
- JsInterpreter 0F 1E/1F/0D multi-byte NOP + endbr decode now consumes full
  ModRM/SIB/disp32 (was desyncing execution after clang padding nops).
- KeLowerIrql/KeRaiseIrql/KfRaiseIrql mask sub-dword args through BigInt
  before Number() — guest ABIs legally leave stale high register bits, and
  double conversion of huge values silently corrupted the level.
- MmIsAddressValid performs a genuine per-page backing check.

**New m3.l1.lab2** (`api-hook-blank`): author-your-own-inline-hook compiler
lab; students discover the export thunk VA via x/u/sym (deterministic:
bases.thunk+0x30 = 0xfffff80100000030), paste into the template, compile,
load; suppression gates on live prologue bytes exactly like kfhook.sys.
Answers: 0xfffff80100000030 / kf-hook-author-ok.

Teaching headers gained SAL annotation macros (_In_ etc.) and ULONG64/INT64/
TRUE/FALSE so tutorial sources compile unmodified; headers-manifest.json
regenerated.

### SMM track: modules m11-m13 (feat/smm-engine)

Guest-paged boot (ntsim/paging.mjs Mmu + TranslatedMemory), Q35-style
chipset/SMRAM model, SMI latch + RSM save-state relocation; smm-foundations/
smm-vault/smm-reloc worlds; windbg-web !vtop/!pte/!cr + !smram/!smmc.
Instructor answers: m11 0x10d000 / 7 / nx; m12 kfsmm-exfil-2026 / 0;
m13 0xfb04 / mf2k.

## Catalog v5 — blog-labs modules m14-m19 (feat/internals-blog-modules)

Status: implemented 2026-08. Branch base: main @ 60e052a. Worktree:
`../advanced_Cheat_Dev-wt4`. Sources scraped & cited in lesson bodies:
revers.engineering, secret.club, windows-internals.com (System Informer),
security-auditing.com, everdox.blogspot.com, momo5502.com, 0xdbgman
(CrowdStrike teardown), ssno.cc TAC, kernel-internals.org, ridpath
gamehacking cheatsheet, UnknownCheats TryBypassMe series.

### Engine additions
- ntsim/paging.mjs: 4-level walker + PageTableSpace; per-path self-map
  alias windows (mirrored pages); large pages; CR3-shuffle scan. Debugger:
  !cr3/!pte/!vtop.
- ntsim/notify.mjs: callback INVOCATION engine (Ex vs legacy tracking),
  PS_CREATE_NOTIFY_INFO materialization (+0x40 CreationStatus), thread/
  image fire helpers. Debugger: !notifyroutines/!notifytest.
- ntsim/ssdt.mjs: ServiceTable over real thunk bytes; !ssdt scan/repair.
- debugger !pseudocode: fixture-shaped decompilation (sensor idiom).
- sogen-runtime ac.mjs: tbm-ac world (5 ring-3 AC vectors).
- v86-lab: syscall-hook world seeds + kfhooksy.c villain (GPL-2.0).

### Backend parity (hard requirement)
All new worlds boot via LOW_BASES (< bit 47) so JsInterpreter and
Unicorn/QEMU execute identical flows; apps/web/test/backend-parity.test.mjs
gates each world under both engines (loud skip when wasm absent).

### Instructor answers (v4, renumbered m14-m19)
m14: 0x0000000003005000 / 0x0000078250e65218 / kf-pt-healed
m15: STATUS_ACCESS_DENIED / 0x0000000050101000 / kf-edr-blindspot
m16: NtOpenProcess / 0x0000000005201000 / kf-ssdt-clean
m17: 5 / 0x00600100 / kf-tbm-godmode
m18: 37 / kf-hookspotted / kf-syscall-clean
m19: 64 / 0x0000000050101000 / 64

Follow-on candidates: HWID spoofing lab, TBM-Kernel vectors, ept-sim.

## Catalog v6 — linux-internals modules m24-m28 (feat/module-linux-tmpout)

Built on the tmp.0ut zine (https://tmpout.sh, all five volumes 2021-2026).
New lab kind `elf`: static fixture + readelf-style inspector console
(`apps/web/src/elf/elfinspector.js`, parser `apps/web/src/elf/parse.mjs`,
fixtures generated by `tools/gen-elf-fixtures.mjs` into
`apps/web/public/fixtures/elf/` + embedded `src/elf/fixtures.gen.mjs`).
Pane registered in `apps/web/src/panes.js`; scenarios in
`apps/web/src/scenarios.js`. Research cache is gitignored:
`node tools/scrape-tmpout.mjs` -> `.cache/tmpout/`.

### Module 24 — ELF Anatomy & Forensics (scenario `elf-hello`)
Required infra: lenient ELF64 parser with kernel-fidelity zero-padding
readers, loader-check report, anomaly collection. Inspector commands:
info/ehdr/phdr/shdr/sym/strings/hex/note. Fixture geometry pinned by the
generator: e_entry 0x400100, .text at file offset 0x100, kf_greet @
0x400130. Answers: 0x400100 / 256 / 0x400130; quiz: 56 / ei_data / 0x20.

### Module 25 — ELF Parasites: Infection & Repair (`elf-infected`)
infected.elf = hello baseline + appended parasite at old EOF (file offset
1132), PT_NOTE->PT_LOAD at vaddr 0xc000000+size, e_entry -> parasite,
movabs rax,OEP; jmp rax stub after a KFPARASITE marker. Answers:
0x400100 / 1132 / pt_note; quiz lore: 0xc000000 / "ff e0" / go.

### Module 26 — Fileless & Memory-Resident Execution (`elf-tiny`)
tiny.elf = h4x.cz construction: magic-only ident, e_phoff=0 (Phdr aliases
Ehdr; p_type reads as magic 0x464c457f and is skipped as unknown),
e_phnum high byte elided at exactly 57 bytes. Parser mirrors the kernel's
zero-padded bprm->buf reads. Answers: 0 / 0x464c457f / 57; quiz: 313 /
319 / execve.

### Module 27 — Linux Kernel Offense & Defense Survey (quiz-only)
Seven pinned facts across v2-v5 articles: el0_svc_common / proc_read /
12288 / 512 / exitbootservices / 3 / granular aslr.

### Module 28 — Obfuscation, Polymorphism & Weird Machines (quiz-only)
Eight facts across the anti-RE arc: 8 / 2 / xlatb / carry flag / rsp /
(x+5)*3.

### Instructor answers (m24-m28)
m24: 0x400100 / 256 / 0x400130 | 56 / ei_data / 0x20
m25: 0x400100 / 1132 / pt_note | 0xc000000 / ff e0 / go
m26: 0 / 0x464c457f / 57 | 313 / 319 / execve
m27: el0_svc_common / proc_read / 12288 / 512 | exitbootservices / 3 /
     granular aslr
m28: 8 / 2 / xlatb | carry flag / rsp / (x+5)*3

Attribution: lesson prose cites author + volume per technique (sblip,
d3npa, manizzle, s01den, netspooky, ulexec, vrzh, deluks, g1inko, TMZ,
isra, dominikr, wintermute, lil.skelly, bah, PinkNoize, elfmaster,
FridayOrtiz, Matheuzsec & Humzak711, qkumba, patate, febnug, ti3f,
h4x.cz); article texts stay upstream (gitignored cache only).

Follow-on candidates: polyglot-ELF fixture (v5 dominikr #10) for m24;
in-browser parasite patcher writing cleaned files for m25; FixedASLR-style
.o relocation lab from gynvael's CTF writeup.
