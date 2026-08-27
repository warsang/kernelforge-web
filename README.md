# KERNELFORGE

Browser-native red-team / EDR-bypass / game-hacking course platform. Every lab runs
client-side: an emulated x64 Windows kernel anchored in real per-build struct tables,
a fake-but-faithful WinDbg, in-browser compilation of real drivers, and CTF-style
flag progression. Static hosting only — no nested virtualization, no accounts.

## Architecture

```
apps/web                     zero-build web shell (import maps) + dev/serve server
packages/
  ntsim                      emulated x64 Windows kernel
    memory.mjs               sparse 64-bit page store (BigInt addresses)
    cpu.mjs                  deterministic x86-64 interpreter (Win64 ABI)
                             debugBps execute-gates + breakpointPolicy pause
    structs.mjs              Vergilius-table-driven struct access (no hardcoded offsets)
    pe.mjs / pebuilder.mjs   PE32+ manual mapper + image builder
    devices.mjs              DRIVER_OBJECT/DEVICE_OBJECT/IRP model + scripted IRP engine
    seh.mjs                  x64 table-SEH: .pdata lookup + __C_specific_handler scopes
    kernel.mjs               process list, pool, API thunks, tracing, SEH-aware calls,
                             deferred drains (DPC/work/APC), IRQL violation tracking
    winapi.mjs + winapi-ext  249 modeled ntoskrnl exports (registry, virtual FS, sections,
                             interlocked, events, Se/Ob/Mm/Po/Etw/WMI/FsRtl)
    paging.mjs               guest x64 MMU: 4-level walker/builder, TranslatedMemory
                             (demand-zero, NX/RW/U-S), #PF-shaped faults into SEH
    smm.mjs                  Q35-style chipset (CF8/CFC, SMRAMC/D_LCK, TSEGMB),
                             SMRAM ring-0 hiding, SMI latch + modeled RSM/SMBASE reloc
  ntsim-analyzer             run-any-.sys harness: map -> DriverEntry -> IOCTLs -> report
  ntsim-assets               VergiliusProject scraper -> per-build offset JSON (CC0);
                             kdmp.mjs (crash-dump parser) + carve-dump.mjs (genuine pages)
  ntsim-unicorn              Unicorn/QEMU wasm CPU backend + HybridCpuBackend
                             (JS interpreter front end, automatic one-way handoff to
                             QEMU on any instruction the interpreter refuses;
                             stepInsn/runUntilStop/debugBp gates shared with the JS side)
  windbg-web                 kd> engine: dt/!process/lm/r/bp over live ntsim state
  compiler-worker            COFF parser + x64 linker: clang .obj -> runnable .sys
  course-content             module catalog, flag hashes, progression graph
  lab-runtime                flag checker, progress reducer, IndexedDB persistence
  debugger-ui                track-agnostic debugger shell (docked disasm/registers/
                             memory/stack/bp/threads/modules/pseudocode tabs, F5/F10/
                             F11 hotkeys) over the DebugSession contract; Monaco editor
                             service (all code surfaces) with textarea fallback
  sogen-runtime              windows-userland track: JS reference world + static
                             debug session + wasm-core client (worker transport,
                             loud-degrade until the FB verb codec lands)
  v86-lab                    i386 buildroot guest: serial harness + GDB RSP bridge
                             (rsp.mjs / GdbSession) over the second UART
  ghidra-decompiler          prologue boundary scanner + decompiler wrapper/client
                             (pyre-pipeline build recipe; loud degrade)
```

## The pipeline (all verified by tests)

```
student C source
  -> clang --target=x86_64-pc-windows-msvc -c        (wasm in-browser; dev bridge fallback)
  -> COFF .obj                                        (real compiler output)
  -> compiler-worker: linkDriver()                    (sections, relocs, extern resolve)
  -> PE32+ .sys                                       (pebuilder)
  -> ntsim mapPe(): manual-map into emulated kernel   (relocations, IAT -> API thunks)
  -> JsInterpreter / HybridBackend executes DriverEntry (Win64 ABI, table-SEH on fault)
  -> deferred drains (DPCs / work items / APCs)       (kernel.drainDeferred)
  -> scripted IRPs: MajorFunction[DEVICE_CONTROL]     (sendIrp/sendIoctl)
  -> DbgPrint + API trace captured; inspected via kd> dt/!process
  -> flags checked (sha256), progress persisted       (IndexedDB)
```

## Driver Analyzer

Upload any x64 `.sys` in the **Driver Analyzer** tab (sidebar → Tools):

1. Manual-mapped; every import resolves — modeled APIs behave faithfully,
   unknown exports become traced stubs returning STATUS_SUCCESS
   (`report.load.unmodeledExports` keeps it honest).
2. `DriverEntry` runs through the SEH path: faults are dispatched via the
   image's `.pdata` scope tables (__try/__except funclets re-entered as ABI
   calls); unhandled faults surface as bugcheck reports.
3. Queued DPCs / work items / APCs drain through the CPU.
4. Scripted IOCTLs drive `MajorFunction[IRP_MJ_DEVICE_CONTROL]`: craft an
   ioctl code + input hex, watch the handler run, read back
   IoStatus/SystemBuffer.
5. Zw/Nt calls above APC_LEVEL are recorded as IRQL violations.

Node API: `analyzeDriver(bytes, opts)` from `@kernelforge/ntsim-analyzer`.

## Ghidra Analysis workspace

Sidebar → Tools → **⚗ Ghidra Analysis** opens a floating pyre-style window
over whatever lesson you are on (it never navigates away): function list,
capstone disassembly, CFG graph (SVG pan/zoom), Monaco pseudocode, memory
hexdump, and a JavaScript scripting console (`emu.debug.*` /
`emu.memory.read`) — plus live Registers/Stack/Breakpoints/Modules tabs when
a session is booted. Pseudocode uses a real Ghidra decompiler build:

```bash
npm run vendor:ghidra    # one-time: builds pyre wasm with local emsdk (or docker)
```

Artifacts stay untracked under `apps/web/public/vendor/ghidra/`; provenance
lives in `packages/ghidra-decompiler/vendor/README.md`. Without the artifact
everything loud-degrades to static analysis (`!funcs`, rel32 resolution).

## Genuine kernel bytes (optional)

```bash
npm run carve -- <mem.dmp> --out apps/web/public/dumps --build win10-19041
cp apps/web/public/dumps/ntsim-state-win10-19041.json \
   apps/web/public/dumps/ntsim-state.json   # deployed asset name
```

Labs and the analyzer both fetch `/dumps/ntsim-state.json` at boot when
present: resident ntoskrnl/CI/cng pages land at their true VAs under the
synthetic overlay. Without it everything runs on synthetic bytes.

## Debugger surface (apps/web/src/debugger.js)

Native-engine commands: `lm`, `dt`, `r` (read + `r reg=expr` writes), `k/kp/kv`, `eb`,
`db/dq` (WinDbg `L<hex>` length prefixes supported), `s` (page-wise degrade on
partially mapped ranges), `u`/`uf` (capstone-wasm x64 disassembly, branch-target
symbolization), `da`/`du`, `x <pattern>`, `? <expr>`, `sym`.

**Live execution control** (real software breakpoints on BOTH CPU backends):
`bp/bc/bd/be/bl`, `t` (step into), `p` (step over calls), `g` (go),
`gu` (step out). Breakpoints are execute-gates — memory is never patched, so
no SMC/TLB hazards; a hit parks RIP on the address and any lab burst that
pauses (compile+load, `!dpcdrain`, ...) adopts into the same stepping state.

Debugger extensions (`!commands`, each documented in the lesson that
introduces it with its in-driver equivalent): `!process`, `!drivers`,
`!drvobj`, `!dh`, `!pcr`/`!prcb`/`!thread`, `!analyze`, `!dbgprint`,
`!irql [-a]`, `!dpcs`, `!dpcdrain`, `!dpcpump`, `!dpcstat`, `!dpcwatchdog`, `!pgscan`,
`!hookscan`, `!hooktest`, `!poolfind`, `!poolverify`,
`!mmstate`, `!mmrun`, `!funcs`, `!decomp`.
DbgPrint output streams live into the debugger console as drivers print
it (`NtKernel.onDebugPrint`) and replays from the `!dbgprint` buffer —
mirroring a real kernel debugger. `!analyze -v` reports machine state
only, matching WinDbg semantics (it never replays debug output).

Module image extents are materialized (int3-padded) and pre-mapped in the
Unicorn address space when a driver joins the module list
(`NtKernel.materializeModuleRange` + `backend.mapRange`), so `lm`-listed
modules are fully readable/executable instead of exposing unmapped holes.

## Graphical debugger shell (packages/debugger-ui)

The sogen userland labs and the linux gdb bridge mount a docked shell
(sogen.dev playground UX, vanilla-JS port): virtualized disassembly with
breakpoint gutter and branch-following, registers grid, hex memory viewer,
call stack, breakpoints/threads/modules panels, Monaco pseudocode tab, and
an embedded console tab — F5/F10/F11/Shift+F11/Ctrl+G hotkeys throughout.
Every view consumes only the `DebugSession` contract; backends plug in per
track (sogen static → wasm core, v86 RSP/gdbserver, ntsim kd console).

## GDB bridge for the Linux track

`gdb start /root/lab/app` in a linux-lab console launches gdbserver on the
guest's second UART (`BR2_PACKAGE_GDB_SERVER` in build-buildroot.sh) and
attaches `GdbSession` over a JS-side RSP client: real breakpoints,
single-stepping, register/memory access inside the live v86 guest, driven
through classic gdb syntax in the shell's Console tab.

## Quick start

```bash
npm install
npm test                 # unit tests across packages
node apps/web/server.mjs # serve on :8080 (+ /api/compile dev bridge)
# open http://localhost:8080 — WinDbg tab: `!process 0 0`, `dt nt!_EPROCESS`
# IDE tab: Compile driver; Lab tab: submit lab answers
cd apps/web && node test/e2e.mjs   # headless browser integration test (legacy branch)

npm run vendor:sogen     # optional: fetch the 90 MB sogen wasm payload (git LFS pulls it too)
npm run vendor:ghidra    # optional: build the Ghidra decompiler wasm (local emsdk or docker)
```

## Regenerating struct tables

```bash
cd packages/ntsim-assets
node scripts/scrape-vergilius.mjs --family windows-10 --build 22h2
node scripts/scrape-vergilius.mjs --family windows-7 --build sp1
```

Data source: VergiliusProject (CC0 — see their terms.html). Tables drive every
offset in ntsim and the debugger; switching build = swapping the table dir.

## Shipped modules

All lessons are freely navigable — pick any module from the sidebar and jump
straight in. Completion order and points are still tracked; progression
guides, it never gates.

Answers are plain question responses (names, PIDs, hex addresses, symbolic
NTSTATUS) normalized trim+lowercase then sha256-checked; no FLAG{} wrapper.
Ground truth lives with instructors; see docs/plan.md for the build-out plan.

**Track: windows-kernel (ntsim)**

Every windows-kernel module follows the same arc: **attack theory → attack
lab → defense theory → defense lab** where students compile a real detection
driver. The defense labs build **KF-Sentinel**, a progressive anticheat/EDR:
v1 process & module integrity, v2 IRQL watchdog, v3 prologue attestation, v4
pool integrity monitor — and each later attack must evade the sensors built
so far.

**Module 1 — Windows Kernel Fundamentals & Manual Mapping**
0. Kernel objects primer — the four places a process exists: `ActiveProcessLinks`, `KTHREAD→ApcState.Process`, handle tables (`SystemHandleInformation`), process-start telemetry
1. Kernel landscape — `lm` reveals `kfprobe.sys`; `!process 0 0` finds
   `kfsample.exe` PID 1312
2. DKOM process hiding — unlink `kftarget.exe` from `PsActiveProcessHead`
   (its seeded thread still shows `ApcState->kftarget.exe`; its
   `kfsample.exe→kftarget.exe` handle stays open — the EDR cross-check)
3. Kernel manual mapping — fix a loader driver's import resolution; capture
   the mapped payload's secret `DbgPrint`
4. **Defense: KF-Sentinel v1** (`sentinel-m1`) — compile a sensor that carves
   the EPROCESS pool window for DKOM-hidden processes and classifies an
   unbacked executable pool page against the linked module list

**Module 2 — IRQL & Deferred Procedures** (`irql-dpc`, `irql-attackers`, `irql-hardened`)
`kfdpc.sys` pins the CPU above DISPATCH_LEVEL and strands a DPC. Read the
stuck level (`!irql`), record the DeferredRoutine (`!dpcs`), lower and drain
(`!irql 2`, `!dpcdrain`) to release the secret.
5. **Defense: KF-Sentinel v2** — compile a watchdog that samples
   `KeGetCurrentIrql`, restores the ladder and releases the stranded DPC.
6. **Attack workshop (m2.l3)** — compile the four documented kernel
   techniques against the healthy `kvmdrv.sys` world: WPOFFx64 canary patch
   inside a raised window, directed-DPC multi-core lockdown, timer-DPC
   persistence, and in-place `DeferredRoutine` hijack — each audited from
   the debugger with `!irql -a`, `!dpcstat`, `!dpcwatchdog` and `!pgscan`.
7. **Defense workshop (m2.l4)** — telemetry sensor on the pinned world,
   self-watchdog deadline alarm (the anticheat heartbeat pattern), a
   baseline forensics sweep, and the HVCI ceiling where the same WPOFFx64
   source dies with modeled bugcheck 0x109.

**Module 3 — Inline Hooks & Control Flow** (`api-hook`, `api-hook-blank`)
`kfhook.sys` detoured `PsLookupProcessByProcessId` so PID 888 vanishes from
lookup. Find it (`!hookscan`), probe it (`!hooktest`), repair the prologue
with `eb`, prove the lookup succeeds again. Then author the detour yourself:
find the export's address with `x`/`u`/`sym`, paste it into the driver
template, compile, load — your bytes do the hooking.
8. **Defense: KF-Sentinel v3** — compile a prologue attestation engine that
   convicts both hooks from ring 0.

**Module 4 — Pool Internals & Corruption** (`pool-corrupt`)
An upstream overflow smashed one of `kfpooler.sys`'s trailing pool guards.
Locate the block (`!poolfind KfPb` prints exact guard addresses), rewrite the
guard with `eb`, verify (`!poolverify`), capture the checksum secret.
9. **Defense: KF-Sentinel v4** — compile a pool monitor that sweeps guard
   trailers from your own driver and attributes the overflow.

**Track: windows-userland (sogen)**

**Module 5 — Userland Recon Under an Emulator** (`sauer-recon`)
A headless Sauerbraten process under a sogen-style emulator: enumerate
modules (`lm`), two-scan for live health state with `!damage` as oracle,
locate the local player entity and its health field offset.

**Module 6 — Userland Hooks & Input Flow** (`sauer-hook`)
A cheat stub rewrote `cl_sendinput` into an E9 trampoline to an aim-assist
routine. `hookscan` it, resolve the target, repair with `eb`, prove honest
flow with `!inputtest`.

**Track: linux-kernel (v86)**

**Modules 7–9 — Linux LKM / Syscall Tracing / Rootkit Detection**
(`lkm-hello`, `syscall-trace`, `task-hide`)
A real i386 buildroot guest boots via v86 in the browser tab: write LKMs in
the IDE pane, ship them into the guest, insmod, read dmesg over serial.
m7 module basics + frozen syscall ABI; m8 kprobe-based execve tracing;
m9 detect a task-unlinking villain rootkit via nr_threads vs /proc
accounting, then make it confess through your completion path.

**Track: reversing (ghidra)**

**Module 10 — Static Analysis with Ghidra-Grade Tooling** (`api-hook`)
Function-boundary recovery over a driver image (`!funcs`) and rel32 detour
resolution; pseudocode via Ghidra's native decompiler engine compiled to
wasm once vendored (loud degrade until then).

**Track: smm (ring -2)**

**Module 11 — x64 Paging & the SMM Landscape** (`smm-foundations`)
First guest-paged boot: real 4-level tables. `!vtop`/`!pte`/`!cr` walk the
MMU; `KUSER_SHARED_DATA` is dual-mapped to one frame; decode SMRAMC and
find the unlocked door.

**Module 12 — Ring-0 → SMM Escalation** (`smm-vault`)
Write the exploit yourself: open SMRAM with one CF8/CFC write (D_OPEN on an
unlocked platform), patch the SMI handler at `SMBASE+0x8000`, close to
cover tracks, fire port 0xB2 — and let your bytes run in ring -2.

**Module 13 — SMBASE Relocation Persistence** (`smm-reloc`)
Capstone: rewrite the save-state's canonical `SMBASE @ +0xFB04` field
before RSM so the *next* SMI enters code you planted. Then set D_LCK and
prove your own exploit dead.

**Track: blog-labs v4 (windows-kernel / sogen / linux / reversing)**

**Module 14 — x64 Virtual Memory & Page Tables** (`paging-walk`)
Real PML4/PDPT/PD/PT bytes under a shuffled CR3 decoy (EAC-style): walk
translation by hand (`!cr3`/`!pte`/`!vtop`), compute self-map alias VAs,
repair an NX-smashed code PTE.

**Module 15 — Kernel Callbacks & EDR Sensors** (`edr-sensor`)
Falcon-style process-create blocking with REAL callback machine code on
both CPU backends; `PS_CREATE_NOTIFY_INFO.CreationStatus` kill switch,
enumerate → trigger → patch the name compare.

**Module 16 — SSDT & Syscall Hooking** (`ssdt-hook`)
Modeled `KiServiceTable` over API thunks: `!ssdt` inline-hook scan,
rel32 resolution, pristine-prologue repair, PatchGuard discussion.

**Module 17 — Userland Anti-Cheat Bypass Gauntlet** (`tbm-ac`)
TryBypassMe-style ring-3 vectors (blacklists, PEB debug artifacts,
XOR stats + shadow canaries, CRC thread); reach `!godmode` cleanly.

**Module 18 — Linux Syscall-Table Rootkits** (`syscall-hook`)
kfhooksy.ko hooks `sys_call_table[__NR_kill]`; kallsyms cross-check
detector + exported restore path, graded over serial KFFLAG lines.

**Module 19 — Reversing the Sensor Statically** (`edr-sensor`)
`!funcs` boundary recovery plus `!pseudocode` decompilation of the
CreationStatus store (+0x40 = decimal 64) — real Ghidra output once
`npm run vendor:ghidra` has run; deterministic fixture otherwise.

**Module 20 — Hooks & Integrity Monitoring** (`pg-hooks`)
Kernel hook taxonomy split into PatchGuard-compliant vs non-compliant,
plus a fake mini-PatchGuard (`!pgstatus`) sweeping four protected regions
on the lab clock: install a hook, use it, restore pristine bytes and cross
a clean sweep before CRITICAL_STRUCTURE_CORRUPTION (0x109) fires. Lesson 2
covers the userland techniques (IAT/EAT/inline/VEH/thread hijack).

**Module 21 — Userland Injection** (`ul-inject`)
Handle-based vs handleless injection into kftarget.exe's game page:
`ZwOpenProcess`/`ZwWriteVirtualMemory` with real access-right enforcement
against `PsLookupProcessByProcessId` + `KeStackAttachProcess` direct writes.
The Js interpreter gained a minimal SSE surface (movups/xorps/jcc rel32)
for clang's vectorized stores.

**Module 22 — Custom Hypervisors & EPT** (`ept-shadow`)
Ring -1 architecture (VMX root/non-root, VMCS, EPT second translation
floor), EPT-shadow hooks that split instruction fetches from data reads,
and the detection stack — dual-view hashing (`!eptview`/`!eptverify`),
A/D-bit timing counters, CPUID quirks and RDTSC drift.

**Module 23 — DKOM Field Labs** (`dkom-ppl`, `dkom-pid`)
Six edits that matter: strip lsass's PPL byte and open it for real, spoof
kftarget's Cid to 4 — plus the field guide to handle-pointer swaps, SMEP
toggles, CR0.WP page work and the Van1338 notify race.

**Track: linux-internals (tmp.0ut)**

Five modules distilled from all five volumes of the tmp.0ut zine
(https://tmpout.sh) — Linux/ELF internals research by xcellerator, sblip,
d3npa, manizzle, s01den, netspooky, ulexec, vrzh, deluks, g1inko, TMZ,
isra, dominikr, wintermute, lil.skelly, bah, PinkNoize, elfmaster,
FridayOrtiz, Matheuzsec & Humzak711, qkumba, patate, febnug, ti3f, h4x.cz
and others. Static ELF64 fixtures live in `apps/web/public/fixtures/elf/`
(regenerate via `node tools/gen-elf-fixtures.mjs`); the readelf-style
inspector console is `apps/web/src/elf/elfinspector.js` over the lenient
parser in `apps/web/src/elf/parse.mjs`. Article cache (gitignored):
`node tools/scrape-tmpout.mjs`.

**Module 24 — ELF Anatomy & Forensics** (`elf-hello`)
Dissect a real x86-64 static executable in-browser: ehdr/phdr/shdr/symbols,
what `fs/binfmt_elf.c` actually validates vs ignores, extended section
numbering, and how 57-byte degenerate headers still sail through.

**Module 25 — ELF Parasites: Infection & Repair** (`elf-infected`)
The PT_NOTE infection method end-to-end on a fixture infected with a real
parasite (far-VA PT_LOAD, movabs/jmp rax OEP stub): recover the original
entry point as the analyst, then quiz the zine's constants — disinfection
invariants, `.fini_array` EPO, `__cxa_finalize` GOT hijack.

**Module 26 — Fileless & Memory-Resident Execution** (`elf-tiny`)
memfd_create/finit_module LKM loading, SHELF reflective payloads and TMZ's
halfexec/halfshelf/phork trilogy, fd-less Perl execution — hands-on on the
57-byte header where the Phdr aliases the Ehdr itself.

**Module 27 — Linux Kernel Offense & Defense Survey**
ftrace/kprobe/eBPF rootkit taxonomy, procfs C2 channels, arm64 svc-handler
patching, boot-time bzImage patching; detection via tracefs walking, taint
forensics, GhostCache L1i side-channels and gASLR hardening.

**Module 28 — Obfuscation, Polymorphism & Weird Machines**
False disassembly with polymorphic junk bytes, M4rx's custom VM ISA and its
RE, code virtualization survey, XLAT table decoding, stateless control flow,
Brainfuck-compiled ROP chains and a metamorphic virus in 440 bytes.

**Module 5 — Tracing & Anti-Tracing** (`anti-trace`)
`kftrace.sys` arms CPU trap-flag tripwires: passive TF reads
(`pushfq`/`test 100h`), TF injection into a vectored handler, and the
mov-ss stall. Map them (`!traceinfo`), attach a simulated tracer and watch
it starve the driver's VEH (`!trace on`, `!selftest` — count swallowed
INT 1s), then clear the gate byte with `eb` to release the secret.

## Roadmap (see docs/plan.md)

- Phase 4: shadow-EPT hypervisor module (ept-sim) — Daax's EPT series +
  momo5502 hypervisor-hook detection are the source material
- Phase 5: UEFI bootkit simulator
- Phase 6: BYOVD/misconfiguration labs (RACEAC-style TOCTOU, mhyprot2 pattern)
- Sogen WASM core vendor step: replace the reference userland backend with
  real PE execution against Wine-derived DLLs (packages/sogen-runtime/vendor)
- Playable Sauerbraten client in-browser: gated behind the GUI spike
  (docs/spike-sogen-gui.md); headless labs are fully shippable without it
- TrySpoofHWID-style HWID-spoofing lab + TBM Kernel Edition vectors
  (VAD scanner, handle stripping)
- Infra: browsercc WASM fork (X86+BPF LLVM backends) to move compilation
  fully client-side; deeper API harness breadth (speakeasy-class),
  IRP/IOCTL-driven malware labs; real kernel-dump carve (kdmp-parser) to
  anchor ntoskrnl pages with genuine bytes

## Legal notes

- No AssaultCube anywhere (license prohibits commercial use + cheat-content redistribution).
- Sauerbraten engine is ZLIB (commercial OK); ship ZERO stock media — link official installer.
- Sogen core is GPL-2.0; vendored bundles follow the ntsim-unicorn policy
  (pinned source + rebuild recipe). Emulation roots ship Wine-derived DLLs
  (LGPL) built by tools/build-wine-root.mjs — never Microsoft's.
- v86 is BSD-2-Clause; guest kernel/modules are GPL-2.0 with sources in-repo.
- Ghidra decompiler engine is Apache-2.0. Full inventory: docs/legal.md.
- Vergilius tables: CC0. Dumps: vendor links only.
- Educational/defensive framing; responsible-use policy ships with the platform.
