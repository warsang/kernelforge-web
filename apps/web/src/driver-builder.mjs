/**
 * driver-builder.mjs — bridges student C source to executable ntsim drivers.
 *
 * Legacy guided-builder path. Students write kernel-mode C in the editor;
 * this module validates the structural approach and can emit equivalent
 * hand-assembled x86-64 for quick simulations.
 *
 * LIVE LABS NO LONGER USE THE SIMULATION: the compiler-lab flow links real
 * clang COFF via ntsim-analyzer/loadCompiledDriver and executes the
 * student's actual bytes on the emulated CPU (see main.js compiler branch).
 * runDkomDriver/loadDkomDriver are retained for their unit tests only.
 */

import { PeBuilder } from "@kernelforge/ntsim/src/pebuilder.mjs";

const PAGE = 4096;

// ---------------------------------------------------------- validation

const REQUIRED_PATTERNS = {
  "dkom-hide": [
    { pattern: /PsLookupProcessByProcessId|ActiveProcessLinks|EPROCESS|eproc|DKOM/i,
      hint: "You need to locate the target _EPROCESS (via PsLookupProcessByProcessId or by walking ActiveProcessLinks)." },
    { pattern: /RemoveEntryList|Flink|Blink|ActiveProcessLinks/i,
      hint: "You need to unlink from ActiveProcessLinks — either RemoveEntryList() or manually overwrite Flink/Blink." },
    { pattern: /DbgPrint/i,
      hint: "You must DbgPrint the address of the _LIST_ENTRY you overwrote so you can submit the flag." },
  ],
  // m3.l1.lab2 — author-your-own-inline-hook
  "inline-hook": [
    { pattern: /0x[0-9a-fA-F]{12,16}|g_TargetFn\s*=/i,
      hint: "Set g_TargetFn to the export's address. Discover it in the debugger with `x nt!PsLookup*`, `u nt!PsLookupProcessByProcessId` or `sym` — do NOT guess." },
    { pattern: /0xE9|0xe9/,
      hint: "Write the E9 (jmp rel32) opcode over the target prologue." },
    { pattern: /DbgPrint/i,
      hint: "DbgPrint the hooked address (and the secret line) so the lab can verify your detour landed." },
  ],
  // KF-Sentinel defense labs (shared structural requirements)
  "sentinel": [
    { pattern: /DriverEntry/i,
      hint: "Every kernel driver needs a DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING) entry point." },
    { pattern: /DbgPrint/i,
      hint: "Sensors emit findings via DbgPrint telemetry — the lab verifies your printed lines." },
  ],
  // m2.l3 attack workshop: technique drivers must reference a world anchor
  // and emit telemetry the debugger can audit.
  "attack": [
    { pattern: /DriverEntry/i,
      hint: "Every kernel driver needs a DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING) entry point." },
    { pattern: /0x[0-9a-fA-F]{12,16}/,
      hint: "Attack drivers target deterministic world anchors — keep the full-width VA/constant in your source." },
    { pattern: /DbgPrint/i,
      hint: "DbgPrint what you did so the lab (and !analyze -v) can verify the effect." },
  ],
};

export function validateDriverSource(source, labKind) {
  const errors = [];
  const warnings = [];
  if (!source || source.trim().length < 20)
    return { ok: false, errors: ["Source is empty or too short."], warnings };
  for (const { pattern, hint } of REQUIRED_PATTERNS[labKind] ?? [])
    if (!pattern.test(source)) errors.push(hint);
  if (/goto\s/i.test(source)) warnings.push("goto is discouraged in kernel code.");
  return { ok: errors.length === 0, errors, warnings };
}

// ----------------------------------------------------- machine-code gen

/**
 * Emit minimal DKOM unlink code.
 * Windows x64 ABI: rcx = target _EPROCESS VA.
 * Stores links_addr into a scratch qword immediately after the ret.
 *
 * Layout: [code][scratch u64][ret]
 */
function emitDkomCode(linksOffNum) {
  const c = [];
  const db = (...b) => c.push(...b);
  const dd = (d) => db(d & 0xff, (d >> 8) & 0xff, (d >> 16) & 0xff, (d >> 24) & 0xff);

  // mov rax, [rcx + linksOff]         ; flink = Target->Links.Flink
  db(0x48, 0x8b, 0x81); dd(linksOffNum);
  // mov rdx, [rcx + linksOff + 8]     ; blink = Target->Links.Blink
  db(0x48, 0x8b, 0x91); dd(linksOffNum + 8);

  // DKOM unlink: prev->Flink = next; next->Blink = prev
  // mov [rdx], rax                    ; prev->Flink = flink (= next)
  db(0x48, 0x89, 0x02);
  // mov [rax+8], rdx                  ; next->Blink = blink (= prev)
  db(0x48, 0x89, 0x50, 0x08);

  // xor eax, eax                      ; STATUS_SUCCESS
  db(0x31, 0xc0);
  // ret
  db(0xc3);

  return { code: Uint8Array.from(c) };
}

// ------------------------------------------------------------ build+load

export function loadDkomDriver(kernel, opts = {}) {
  const linksOff = Number(opts.linksOffset ??
    kernel.tables?.offsetOf("_EPROCESS", "ActiveProcessLinks") ?? 0x448n);
  const loadBase = opts.loadBase ?? 0xfffff80160000000n;

  const { code } = emitDkomCode(linksOff);
  const textData = new Uint8Array(Math.ceil(code.length / PAGE) * PAGE);
  textData.set(code);
  textData.fill(0xcc, code.length);

  kernel.mem.write(loadBase + 0x1000n, textData);

  const entry = loadBase + 0x1000n;
  return { entry, base: loadBase };
}

export function runDkomDriver(kernel, targetEproc, opts = {}) {
  const linksOff = BigInt(opts.linksOffset ??
    kernel.tables?.offsetOf("_EPROCESS", "ActiveProcessLinks") ?? 0x448n);
  const { entry } = loadDkomDriver(kernel, opts);

  // The address of the _LIST_ENTRY we're about to overwrite
  const linksAddress = targetEproc + linksOff;

  // Log like DbgPrint would
  kernel.debugPrint(`DKOM: unlinked kftarget.exe, LIST_ENTRY @ ${linksAddress.toString(16)}`);

  const before = kernel.listProcesses().map((p) => ({ pid: p.pid, name: p.name }));
  const r = kernel.callDriverEntry(entry, targetEproc, 0n);
  const after = kernel.listProcesses();
  const targetGone = !after.some((p) =>
    p.eprocess === targetEproc || p.name === "kftarget.exe");

  return {
    status: r.status,
    targetGone,
    linksAddress,
    processesAfter: after.map((p) => ({ pid: p.pid, name: p.name })),
    dbgLog: [...kernel.dbgLog],
  };
}
