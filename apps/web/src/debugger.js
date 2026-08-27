/**
 * Minimal WinDbg-flavored command console over a booted NtKernel.
 *
 * createCommands(kernel) is pure/DOM-free and returns the command map;
 * createDebugger(kernel, out) binds it to a console element.
 *
 * Every command handler shares one signature: (args: string[], w: writeFn).
 *
 * Field walks are driven entirely by the active build's Vergilius tables —
 * nothing here hardcodes struct layouts. Types absent from the scraped set
 * (_TOKEN, _CLIENT_ID as a standalone type, …) degrade to raw dumps or are
 * called out explicitly.
 */

import { irqlName } from "@kernelforge/ntsim/src/kernel.mjs";
import { DRIVER_OBJECT, IRP_MJ, IRP_MJ_NAMES, sendIrp } from "@kernelforge/ntsim/src/devices.mjs";
import { OBJ_PROCEDURES, objProcVa } from "@kernelforge/ntsim/src/objtypes.mjs";
import { MSR_NAMES, IDT_VECTOR_COUNT, GDT_ENTRY_COUNT } from "@kernelforge/ntsim/src/msr.mjs";
import { decodePte, pteBitsString } from "@kernelforge/ntsim/src/paging.mjs";
import { ServiceTable } from "@kernelforge/ntsim/src/ssdt.mjs";
import { analyzeExtent, resolveRel32, decompile as ghidraDecompile, loadDecompiler } from "@kernelforge/ghidra-decompiler";
import { disassemble, liftAliasHex } from "./disasm.mjs";

const FAST_REF_MASK = ~0xfn; // x64: low nibble holds reference count

/** Common NTSTATUS codes for symbolic display in lab output. */
const STATUS_NAMES = {
  0x00000000n: "STATUS_SUCCESS",
  0xc0000001n: "STATUS_NOT_IMPLEMENTED",
  0xc0000005n: "STATUS_ACCESS_VIOLATION",
  0xc000000bn: "STATUS_INVALID_PARAMETER",
  0xc000000dn: "STATUS_INVALID_PARAMETER",
  0xc0000022n: "STATUS_ACCESS_DENIED",
  0xc0000034n: "STATUS_OBJECT_NAME_NOT_FOUND",
  0xc00000bbn: "STATUS_NOT_SUPPORTED",
};

function statusName(v) {
  return STATUS_NAMES[BigInt.asUintN(32, BigInt(v))] ?? `0x${BigInt.asUintN(32, BigInt(v)).toString(16).padStart(8, "0")}`;
}

function hexBytes(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join(" ");
}

/** Parse 0x-prefixed (or bare hex) address text into BigInt; null on garbage. */
function parseAddr(s) {
  try {
    if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
    if (/^[0-9a-fA-F]{8,}$/.test(s)) return BigInt("0x" + s);
  } catch { /* fallthrough */ }
  return null;
}

/** Read up to `max` bytes forward from `start`, stopping at the first gap. */
function readForward(mem, start, max) {
  let avail = 0;
  while (avail < max) {
    const step = Math.min(64, max - avail);
    try {
      if (!mem.canRead(start + BigInt(avail), step)) break;
    } catch {
      if (!mem.hasPage?.(start + BigInt(avail))) break;
    }
    avail += step;
  }
  if (avail === 0 && mem.canRead(start, 1)) avail = Math.min(max, 64);
  return avail > 0 ? mem.read(start, avail) : new Uint8Array(0);
}

/**
 * Parse a WinDbg-style length/count argument into a Number.
 * Handles the `L`/`l` prefix form (`db 0x… L100` -> 0x100 bytes, matching
 * WinDbg's default hex radix), plain decimals (back-compat: `128` -> 128)
 * and 0x-prefixed values. Throws on garbage so callers can report usage.
 * WinDbg backtick digit separators are stripped.
 */
function parseLen(tok) {
  if (tok == null) throw new Error("missing length");
  const t = String(tok).replace(/`/g, "").trim();
  const m = t.match(/^[Ll]\+?(0x[0-9a-fA-F]+|[0-9a-fA-F]+)$/); // L / L+
  if (m) {
    // WinDbg's default radix is 16, so `L40` means 0x40 — always hex here
    const v = parseInt(m[1], 16);
    if (!Number.isFinite(v)) throw new Error(`bad length "${tok}"`);
    return v;
  }
  if (/^0x[0-9a-fA-F]+$/.test(t)) {
    const v = parseInt(t, 16);
    if (!Number.isFinite(v)) throw new Error(`bad length "${tok}"`);
    return v;
  }
  if (/^[0-9]+$/.test(t)) {
    const v = parseInt(t, 10);
    if (!Number.isFinite(v)) throw new Error(`bad length "${tok}"`);
    return v;
  }
  throw new Error(`bad length "${tok}"`);
}

/** Strip WinDbg backticks from address-ish text. */
const unquote = (s) => String(s ?? "").replace(/`/g, "");

/**
 * Tiny expression evaluator for the `?` command: hex/dec numbers, symbols
 * resolvable by `resolver`, registers via `@name`, unary +/-/~, and binary
 * + - * / % & | ^ << >> with C precedence and parentheses. BigInt throughout.
 *
 * opts.hexRadix: WinDbg's default radix is 16 — address expressions like
 * `dq <va>+78 L1` mean +0x78 (issue #27), while `?`/`r` keep the historic
 * decimal reading for bare integers unless written 0n<dec>.
 */
export function evalExpr(expr, resolver, { hexRadix = false } = {}) {
  const src = String(expr ?? "");
  let pos = 0;
  const skip = () => { while (pos < src.length && /\s/.test(src[pos])) pos++; };
  const peek = () => { skip(); return src[pos]; };

  function parsePrimary() {
    skip();
    if (src[pos] === "(") {
      pos++;
      const v = parseBinary(0);
      if (src[pos] !== ")") throw new Error("expected ')'");
      pos++;
      return v;
    }
    if (src[pos] === "-") { pos++; return -parsePrimary(); }
    if (src[pos] === "+") { pos++; return parsePrimary(); }
    if (src[pos] === "~") { pos++; return ~parsePrimary(); }
    if (src[pos] === "@") {
      pos++;
      const m = /^[A-Za-z0-9]+/.exec(src.slice(pos));
      if (!m) throw new Error("bad register");
      pos += m[0].length;
      const v = resolver("@", m[0].toLowerCase());
      if (v === null || v === undefined) throw new Error(`unknown register @${m[0]}`);
      return v;
    }
    const numM = /^0x[0-9a-fA-F`]+|^[0-9`]+(?![a-zA-Z_])|^`?[0-9a-fA-F]{8,}`?/.exec(src.slice(pos));
    if (numM && numM[0]) {
      const t = unquote(numM[0]);
      pos += numM[0].length;
      // windbg default radix is 16: bare numbers parse as hex when they
      // contain a-f or are >= 8 digits; plain decimals stay decimal (unless
      // hexRadix mode — then 0n<dec> is the explicit decimal escape)
      if (/^0x/i.test(t)) return BigInt(t);
      if (/^0n[0-9]+$/.test(t)) return BigInt(t.slice(2));
      if (/^[0-9]+$/.test(t)) return hexRadix ? BigInt("0x" + t) : BigInt(t);
      return BigInt("0x" + t);
    }
    const symM = /^[A-Za-z_][A-Za-z0-9_!.]*/.exec(src.slice(pos));
    if (symM) {
      pos += symM[0].length;
      const v = resolver("sym", symM[0]);
      if (v === null || v === undefined) throw new Error(`cannot resolve '${symM[0]}'`);
      return v;
    }
    throw new Error(`unexpected token at '${src.slice(pos, pos + 10)}'`);
  }

  const LEVELS = [
    ["|"], ["^"], ["&"],
    ["<<", ">>"], ["+", "-"], ["*", "/", "%"],
  ];
  function parseBinary(minLevel) {
    if (minLevel >= LEVELS.length) return parsePrimary();
    let left = parseBinary(minLevel + 1);
    for (;;) {
      skip();
      const op = LEVELS[minLevel].find((o) => src.startsWith(o, pos));
      if (!op) return left;
      pos += op.length;
      const right = parseBinary(minLevel + 1);
      switch (op) {
        case "|": left |= right; break;
        case "^": left ^= right; break;
        case "&": left &= right; break;
        case "<<": left <<= right; break;
        case ">>": left >>= right; break;
        case "+": left += right; break;
        case "-": left -= right; break;
        case "*": left *= right; break;
        case "/": left /= right; break;
        case "%": left %= right; break;
      }
      left = BigInt.asUintN(64, left);
    }
  }
  const v = parseBinary(0);
  skip();
  if (pos !== src.length) throw new Error(`trailing input at '${src.slice(pos)}'`);
  return BigInt.asUintN(64, v);
}

function fmtAddr(v) {
  return "0x" + v.toString(16).padStart(16, "0");}

function fmtValue(bytes /* LE Uint8Array */) {
  let v = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(bytes[i]);
  return v;
}

function byteSizeOf(base) {
  const b = String(base ?? "");
  if (/VOID\*|PTR$|\*$/.test(b)) return 8;
  if (/^(ULONG64|ULONGLONG|DWORD64|SIZE_T|long long)/i.test(b)) return 8;
  if (/^(ULONG|DWORD|unsigned long|^long$)/i.test(b)) return 4;
  return 8; // default pointer-ish
}

/** Fields eligible for the generic walker: pointers, scalars, fastrefs,
 *  and embedded _LIST_ENTRYs (decoded as Flink/Blink). Embedded structs,
 *  bitfields and arrays are skipped. */
function walkableFields(tables, typeName) {
  const info = tables.types.get(typeName);
  if (!info?.fieldsByName) return null;
  const out = [];
  for (const f of Object.values(info.fieldsByName)) {
    if (f.bitfield || f.array) continue;
    const base = String(f.base ?? "");
    const isPtr = /\*$/.test(base);            // e.g. "struct _KPCR*" — pointer
    const embedded = /^(struct|union)\b/.test(base) && !isPtr;
    // small scalar-like embeddeds render as raw qwords; everything else skips
    const simpleEmbedded = base === "struct _EX_FAST_REF"
      || base === "struct _EX_PUSH_LOCK"
      || base === "struct _LIST_ENTRY";
    if (embedded && !simpleEmbedded) continue;
    out.push(f);
  }
  return out.sort((a, b) => a.offset - b.offset);
}

export function createCommands(kernel) {
  const mem = kernel.mem;
  const tables = kernel.tables;

  /** Containing loaded-module image for a VA, else null. */
  function moduleImageAt(addr) {
    for (const m of kernel.loadedModules ?? []) {
      const base = BigInt(m.base);
      const size = Number(m.sizeOfImage ?? 0);
      if (size && addr >= base && addr < base + BigInt(size)) return { base, size };
    }
    return null;
  }

  // x64 canonical: bits 63..47 identical -> user < 2^47 or kernel >= 2^64-2^47
  const TOP17 = 0xffff800000000000n;
  /** x64 canonicality + backed-by-memory check. Returns null or error text. */
  function memFault(va, len = 8) {
    let v = BigInt(va);
    if (v < 0n) v = BigInt.asUintN(64, v);
    const hi = v >> 47n;
    const canonical = hi === 0n || hi === 0x1ffffn;
    if (!canonical) return "non-canonical address";
    if (typeof mem.canRead === "function" && !mem.canRead(v, len)) return "unmapped";
    return null;
  }
  const memErr = (va, why) =>
    `Memory read error at 0x${BigInt.asUintN(64, BigInt(va)).toString(16).padStart(16, "0")} (${why})`;

  const resolveProcess = (token) => {
    let v;
    try { v = BigInt(token); } catch {
      // not numeric — accept image names ("lsass", "kfsample.exe") so lab
      // commands stay world-agnostic (pids differ between dump overlays)
      const want = String(token).toLowerCase().replace(/\.(exe|sys)$/, "");
      for (const [nm, ep] of kernel.processesByName ?? []) {
        if (nm.toLowerCase().replace(/\.(exe|sys)$/, "") === want) return ep;
      }
      return null;
    }
    if (v > 0xffffn) return v;
    return kernel.findEprocessByPid(v);
  };

  /**
   * Resolve a WinDbg-style address argument to BigInt, or null when it is
   * not an address we can interpret:
   *   0x… / bare-hex / decimal (backticks stripped) | nt!Export | Export |
   *   module!+off / module+off / module+offset.
   * Exports resolve through the kernel API-thunk table; module bases come
   * from the loaded-module list (sym() below handles the reverse mapping).
   */
  const resolveArg = (tok) => {
    const t = unquote(tok ?? "").trim();
    if (!t) return null;
    // numeric forms: 0x-hex always; pure digits are DECIMAL (matches
    // BigInt() semantics used by every other handler); longer mixed
    // alphanumeric strings read as bare hex (windbg copy-paste style)
    let num = null;
    const tq = t.replace(/`/g, "");
    if (/^0x[0-9a-fA-F]+$/.test(tq)) num = BigInt(tq);
    else if (/^[0-9]+$/.test(tq)) num = BigInt(tq);
    else if (/^[0-9a-fA-F]{8,}$/.test(tq) && /[a-fA-F]/.test(tq)) num = BigInt("0x" + tq);
    if (num !== null) return num;
    // export symbol: nt!PsLookupProcessByProcessId or bare name
    const exportName = t.match(/^(?:nt|ntoskrnl(?:\.exe)?)!([A-Za-z0-9_]+)$/i)?.[1]
      ?? (/^[A-Z][A-Za-z0-9_]{3,}$/.test(t) ? t : null);
    if (exportName) {
      const thunk = kernel.apiThunks?.get(exportName);
      if (thunk !== undefined) return thunk;
    }
    // module-relative: kfhook.sys+0x1000 / nt+0x1000
    const rel = t.match(/^([A-Za-z0-9_.\\]+?)(?:!)?\+(?:0x)?([0-9a-fA-F]+)$/i);
    if (rel) {
      const want = rel[1].toLowerCase().replace(/\.(sys|exe|dll)$/, "");
      const mod = (kernel.loadedModules ?? []).find((m) => {
        const nm = String(m.name).toLowerCase();
        return nm === want || nm.replace(/\.(sys|exe|dll)$/, "") === want;
      });
      if (mod) return mod.base + BigInt(parseInt(rel[2], 16));
    }
    return null;
  };

  /** Module image base by (extension-tolerant) name — null when unknown. */
  const modBase = (name) => {
    const want = String(name).toLowerCase().replace(/\.(sys|exe|dll)$/, "");
    for (const m of kernel.loadedModules ?? []) {
      const nm = String(m.name).toLowerCase();
      if (nm === want || nm.replace(/\.(sys|exe|dll)$/, "") === want) return m.base;
    }
    return null;
  };

  /**
   * Expression-aware address argument: plain forms go through resolveArg,
   * everything else through the full evaluator so WinDbg-style inline
   * arithmetic works (`dq 0x50101000+78 L1`, `u nt!DbgPrint+0x10`,
   * `bp kfhook.sys+0x40+2`). Null when nothing resolves.
   */
  const tryEvalAddr = (tok) => {
    const text = String(tok ?? "").trim();
    if (!text) return null;
    const direct = resolveArg(unquote(text));
    if (direct !== null) return direct;
    try {
      return evalExpr(text, (kind, key) => {
        if (kind === "@") {
          const regs = kernel.cpu?.regs ?? {};
          if (key in regs) return BigInt.asUintN(64, BigInt(regs[key]));
          throw new Error(`unknown register @${key}`);
        }
        const v = resolveArg(key);
        if (v !== null) return v;
        const base = modBase(key);
        if (base !== null && base !== undefined) return base;
        throw new Error(`cannot resolve '${key}'`);
      }, { hexRadix: true });
    } catch { return null; }
  };

  /**
   * WinDbg memory commands take `<expr> [<len|Llen>]`, but students paste
   * spaced arithmetic too (`db 0x400000 + 0x40 L10`). Fold every token
   * except a trailing `L<count>` into one address expression; a non-L second
   * token stays the length (back-compat with plain decimal counts).
   */
  const splitAddrLen = (args, defaultLenTok) => {
    if (!args.length) return { exprText: "", lenTok: defaultLenTok };
    const lastTok = args[args.length - 1];
    if (/^[Ll]\+?(0x[0-9a-fA-F]+|[0-9a-fA-F]+|`[0-9a-fA-F`]+`)$/.test(unquote(lastTok))) {
      return { exprText: args.slice(0, -1).join(" "), lenTok: lastTok };
    }
    return { exprText: args[0], lenTok: args[1] ?? defaultLenTok };
  };

  /**
   * PageTableSpace world guard: `kernel.paging` doubles as the boolean flag
   * for guest-paged Mmu worlds, and truthiness alone crashed !cr3/!pte/
   * !vtop there ("Cannot read properties of undefined (reading 'values')",
   * identically under both backends because this is world-shape logic).
   */
  const pageWorld = () =>
    kernel.paging && kernel.paging.processes instanceof Map ? kernel.paging : null;

  /** Raw byte rows shared by the `u` degrade path. */
  const dumpRawRows = (va, len, w) => {
    const bytes = readForward(mem, va, Math.min(len, 128));
    if (!bytes.length) { w(`  <no readable bytes at ${fmtAddr(va)}>`, "dim"); return; }
    for (let row = 0; row < bytes.length; row += 16) {
      const chunk = [...bytes.slice(row, row + 16)];
      const hex = chunk.map((b) => b.toString(16).padStart(2, "0")).join(" ");
      const ascii = chunk.map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : ".")).join("");
      w(`${fmtAddr(va + BigInt(row))}  ${hex.padEnd(47)}  |${ascii}|`, "dim");
    }
  };

  /** Unassemble failure output: loader problems must not masquerade as
   *  memory faults (issue #28/#29 "expected magic word" confusion). */
  const unasmError = (cmd, va, e, w, count = 8) => {
    if (/^disassembler-unavailable/.test(e.message ?? "")) {
      w(`${cmd}: ${e.message}`, "err");
      w("  raw bytes instead (the capstone-wasm asset is missing/broken):", "dim");
      dumpRawRows(va, count * 8, w);
      return;
    }
    w(memErr(va, e.message === "unmapped" ? "unmapped" : e.message), "err");
  };

  /**
   * Walk _EPROCESS.ThreadListHead (LIST_ENTRY of _ETHREAD.ThreadListEntry
   * nodes). Returns { addr, backed }[] — `backed` false marks pointers into
   * non-resident dump images we can still report but not dereference.
   * Guards: zero head (empty ring), self-loop, visited-set and step cap so
   * corrupt/unbacked chains always terminate.
   */
  const listThreads = (eproc, cap = 64) => {
    const out = [];
    let tlhOff, tleOff;
    try {
      tlhOff = BigInt(tables.offsetOf("_EPROCESS", "ThreadListHead"));
      tleOff = BigInt(tables.offsetOf("_ETHREAD", "ThreadListEntry"));
    } catch { return out; } // build lacks the fields — no enumeration
    const head = eproc + tlhOff;
    let cur = mem.u64(head);
    const seen = new Set();
    for (let steps = 0; cur && cur !== head && steps < cap * 2; steps++) {
      if (seen.has(cur)) break; // corrupt ring
      seen.add(cur);
      // `cur` is a _LIST_ENTRY address inside some _ETHREAD (Flink target);
      // the thread base sits tleOff bytes below it.
      const backed = typeof mem.canRead === "function" && mem.canRead(cur, 16);
      out.push({ addr: cur, backed });
      if (!backed) break;       // cannot follow a chain we cannot read
      const next = mem.u64(cur);
      if (!next || next === cur) break;
      cur = next;
    }
    return out;
  };

  /**
   * One `THREAD <ethread>` output line per walked thread, kd-style:
   *   THREAD ffffa40b...  Cid 1312.4096  Teb: 000000e4....  Win32Thread: 0x...
   *                                                              ApcState->owner
   */
  const threadLines = (eproc, w) => {
    const threads = listThreads(eproc);
    if (!threads.length) return 0;
    let cidOff = null, tleOff = null, apcOff = null, tebOff = null, w32Off = null;
    try { cidOff = BigInt(tables.offsetOf("_ETHREAD", "Cid")); } catch { /* optional */ }
    try { tleOff = BigInt(tables.offsetOf("_ETHREAD", "ThreadListEntry")); } catch { /* optional */ }
    try { apcOff = BigInt(tables.offsetOf("_KTHREAD", "ApcState")); } catch { /* optional */ }
    try { tebOff = BigInt(tables.offsetOf("_KTHREAD", "Teb")); } catch { /* optional */ }
    try { w32Off = BigInt(tables.offsetOf("_KTHREAD", "Win32Thread")); } catch { /* optional */ }
    for (const t of threads) {
      // walkers carry _LIST_ENTRY addresses; WinDbg prints _ETHREAD bases
      const base = tleOff !== null ? t.addr - tleOff : t.addr;
      if (!t.backed) {
        w(`    THREAD ${fmtAddr(base)}  (thread image not resident — pointer from authentic list)`, "dim");
        continue;
      }
      let cidPair = "?.?";
      if (cidOff !== null) {
        try {
          const upid = mem.u64(base + cidOff);            // CLIENT_ID.UniqueProcess
          const utid = mem.u64(base + cidOff + 8n);       // CLIENT_ID.UniqueThread
          cidPair = `${upid}.${utid}`;
        } catch { /* optional */ }
      }
      let line = `    THREAD ${fmtAddr(base)}  Cid ${cidPair}`;
      if (tebOff !== null) {
        try {
          const teb = mem.u64(base + tebOff);
          if (teb) line += `  Teb: ${teb.toString(16).padStart(16, "0")}`;
        } catch { /* optional */ }
      }
      if (w32Off !== null) {
        try {
          const w32 = mem.u64(base + w32Off);
          line += `  Win32Thread: ${w32 ? "0x" + w32.toString(16) : "00000000"}`;
        } catch { /* optional */ }
      }
      if (apcOff !== null) {
        try {
          // KTHREAD.ApcState.Process — names the process this thread is
          // attached to. Survives DKOM unlinking, which is exactly why EDRs
          // cross-reference it against ActiveProcessLinks (lesson m1.l2).
          const tgt = mem.u64(base + apcOff);
          if (tgt) {
            const nm = mem.readAnsi(tgt + tables.offsetOf("_EPROCESS", "ImageFileName"), 15);
            line += `  ApcState->${nm}`;
          }
        } catch { /* optional */ }
      }
      w(line);
    }
    return threads.length;
  };

  /**
   * WinDbg-style per-process block shared by `!process 0 <flags>` and
   * `!process <pid|eproc> <flags>`:
   *   PROCESS ffffa40b...  SessionId: none  Cid: 00e4  Peb: ...  ParentCid: 0004
   *       ImageFileName: lsass.exe
   *       Token: ...  ActiveThreads: N     (flag 0x2)
   *       THREAD lines                     (flag 0x4)
   * Flag bits mirror WinDbg: 0x2 = wide walk (token/threads count),
   * 0x4 = enumerate ThreadListHead threads.
   */
  const processBlock = (eproc, bits, w) => {
    let pid = 0n, name = "";
    try {
      pid = mem.u64(eproc + BigInt(tables.offsetOf("_EPROCESS", "UniqueProcessId")));
      name = mem.readAnsi(eproc + tables.offsetOf("_EPROCESS", "ImageFileName"), 15);
    } catch { /* minimal fields */ }
    let pebStr = "00000000", parentStr = pid === 4n ? "0004" : "0000";
    try {
      const peb = mem.u64(eproc + BigInt(tables.offsetOf("_EPROCESS", "Peb")));
      if (peb) pebStr = peb.toString(16);
    } catch { /* optional field */ }
    try {
      const parent = mem.u64(eproc +
        BigInt(tables.offsetOf("_EPROCESS", "InheritedFromUniqueProcessId")));
      if (parent) parentStr = parent.toString().padStart(4, "0");
    } catch { /* optional field */ }
    w(`PROCESS ${fmtAddr(eproc)}  SessionId: none  Cid: ${pid.toString().padStart(4, "0")}  Peb: ${pebStr}  ParentCid: ${parentStr}`, "hdr");
    if (name) w(`    ImageFileName: ${name}`);
    if (bits & 2) {
      try {
        const tokOff = tables.offsetOf("_EPROCESS", "Token");
        const raw = mem.u64(eproc + tokOff);
        const threads = mem.u32(eproc + tables.offsetOf("_EPROCESS", "ActiveThreads"));
        w(`    Token: ${fmtAddr(raw & FAST_REF_MASK)}  ActiveThreads: ${threads}`, "dim");
      } catch { /* optional fields */ }
    }
    if (bits & 4) threadLines(eproc, w);
  };

  function* dumpStruct(typeName, addr, { max = 96 } = {}) {
    const fields = walkableFields(tables, typeName);
    if (!fields) {
      yield `dt: unknown type "${typeName}"`;
      yield `available: ${[...tables.types.keys()].sort().join(", ")}`;
      return;
    }
    yield `${typeName} @ ${fmtAddr(addr)}`;
    let shown = 0;
    for (const f of fields) {
      if (shown >= max) { yield `  ... (${fields.length - shown} more fields)`; break; }
      const fa = addr + BigInt(f.offset);
      const base = String(f.base ?? "");
      if (base === "struct _LIST_ENTRY") {
        yield `  +0x${f.offset.toString(16).padStart(3, "0")} ${f.name}.Flink : ${fmtAddr(mem.u64(fa))}`;
        shown++;
        if (shown >= max) break;
        yield `  +0x${(f.offset + 8).toString(16).padStart(3, "0")} ${f.name}.Blink : ${fmtAddr(mem.u64(fa + 8n))}`;
        shown++;
        continue;
      }
      const size = base === "struct _EX_FAST_REF" ? 8 : byteSizeOf(base);
      const raw = fmtValue(mem.read(fa, size));
      let extra = "";
      if (base === "struct _EX_FAST_REF") {
        const target = raw & FAST_REF_MASK;
        extra = target ? `  -> ${fmtAddr(target)} (fastref refs=${raw & 0xfn})` : "  -> NULL";
      } else if (/UniqueProcessId|InheritedFrom/.test(f.name)) {
        extra = `  (dec ${raw})`;
      }
      yield `  +0x${f.offset.toString(16).padStart(3, "0")} ${f.name.padEnd(26)} : ${fmtAddr(raw)}${extra}`;
      shown++;
    }
  }

  /** module+offset symbolization, e.g. ntoskrnl+0x2a1f0 */
  const sym = (va) => {
    for (const m of kernel.loadedModules ?? []) {
      const base = m.base;
      const end = base + BigInt(m.sizeOfImage ?? 0x100000);
      if (va >= base && va < end) {
        return `${m.name}+0x${(va - base).toString(16)}`;
      }
    }
    return null;
  };

  const kindNote = (k) => `ChildSP               RetAddr               Call Site`;

  /** Lift branch-target literals of one decoded instruction into kernel
   *  space and symbolize against loaded modules. */
  const disasmLine = (insn, hiBase) => {
    const branchy = /^(jmp|call|loop[a-z]*|j[a-z]{1,4})$/i.test(insn.mnemonic)
      && !insn.opStr.includes("["); // direct transfers only
    let op = insn.opStr;
    if (branchy) {
      op = liftAliasHex(op, hiBase);
      op = op.replace(/0x([0-9a-fA-F]+)/g, (m, hex) => {
        const v = BigInt("0x" + hex);
        const canonical = v === 0n || (v >> 47n) === 0x1ffffn;
        if (!canonical) return m;
        const s = sym(v);
        return s ? `${m} (${s})` : m;
      });
    }
    return `${insn.mnemonic}${op ? " " + op : ""}`;
  };

  const stack = (args, w, header) => {
    let sp;
    try { sp = kernel.cpu.kernel.cpu.regs.rsp; } catch { sp = undefined; }
    // fall back to PRCB.RspBase when kernel.cpu.regs.rsp is zero
    if (!sp && kernel.prcb) {
      try {
        sp = mem.u64(kernel.prcb + 0x28n);
        w("   ; ChildSP from PRCB.RspBase", "dim");
      } catch { sp = 0n; }
    }
    const ripSym = sym(kernel.cpu.regs.rip) ?? "<unknown>";
    w(header, "hdr");
    w(`00 ${fmtAddr(sp)}  ${fmtAddr(kernel.cpu.regs.rip)}  ${ripSym}`);
    // nearest-module annotation
    for (const m of kernel.loadedModules ?? []) {
      const base = m.base;
      if (kernel.cpu.regs.rsp >= base && kernel.cpu.regs.rsp < base + BigInt(m.sizeOfImage ?? 0x100000)) {
        w(`   ^ stack inside ${m.name} mapping`, "dim");
        break;
      }
    }
    w("   (single-frame model: no unwind metadata in emulated images)", "dim");
  };

  // ---- live debugging: bp / bl / bc / bd / be / t / p / g / gu --------------
  //
  // Software breakpoints are EXECUTE GATES, not byte patches: each engine
  // checks its breakpoint set BEFORE fetching an instruction. A hit parks
  // RIP on the address (nothing executes) and reports "breakpoint" through
  // the same channel an executed int3 would use:
  //   JsInterpreter — debugBps Set gate in step(); pendingBreak fires.
  //   Unicorn       — per-bp UC_HOOK_CODE stop-before hook; bpHit flag.
  //   Hybrid        — gates registered on BOTH engines, handoff-proof.
  // Memory is never modified: no SMC/TLB invalidation problems, and db/u
  // always show the true bytes.
  const bp = {
    map: new Map(),          // BigInt addr -> {enabled: boolean, hits: number}
    paused: null,            // {addr: BigInt|null, retMarker: BigInt|null}
  };

  const cpuOf = () => kernel.cpu;

  function armPolicy() {
    try { cpuOf().breakpointPolicy = "pause"; } catch { /* raw cpu */ }
  }
  function relaxPolicy() {
    if (!bp.map.size && !bp.paused) {
      try { cpuOf().breakpointPolicy = "continue"; } catch { /* raw cpu */ }
    }
  }

  /** Register/unregister a gate on whatever engine shape this kernel has. */
  function engineSetBp(addr2) {
    const cpu = cpuOf();
    if (typeof cpu.setDebugBp === "function") return cpu.setDebugBp(addr2);
    cpu.debugBps?.add(addr2);
  }
  function engineClearBp(addr2) {
    const cpu = cpuOf();
    if (typeof cpu.clearDebugBp === "function") return cpu.clearDebugBp(addr2);
    cpu.debugBps?.delete(addr2);
  }

  /**
   * Record a confirmed hit: bump counters and enter paused state.
   * RIP is already parked on the address by the engine gate.
   */
  function recordHit(hitAddr, retMarker) {
    const rec = bp.map.get(hitAddr);
    if (rec) rec.hits++;
    else if (!bp.map.has(hitAddr)) return null; // not one of ours
    bp.paused = { addr: hitAddr, retMarker: retMarker ?? null };
    return hitAddr;
  }

  /**
   * Convert a burst result into a paused-on-breakpoint state. With gates,
   * both engines report rip parked ON the address; keep a legacy fallback
   * for ripAfterInt3-shaped results just in case.
   */
  function normalizeHit(res) {
    let hitAddr = null;
    let retMarker = res?.retMarker ?? null;
    if (res?.status === "breakpoint") {
      hitAddr = bp.map.has(res.rip) ? res.rip
        : (res.ripAfterInt3 != null && bp.map.has(res.ripAfterInt3 - 1n)
          ? res.ripAfterInt3 - 1n : res.rip);
      if (!bp.map.has(hitAddr)) {
        // unregistered int3/padding: park before it so stepping is sane
        bp.paused = { addr: null, retMarker };
        cpuOf().regs.rip = hitAddr;
        return null;
      }
    } else if (res?.status === "fault" &&
               /unhandled CPU exception/i.test(String(res.error?.message ?? "")) &&
               res.error?.rip != null && bp.map.has(res.error.rip)) {
      hitAddr = res.error.rip;
      cpuOf().regs.rip = hitAddr;
      cpuOf().fault = null; // consumed: it was our gate, not a real fault
    } else {
      return null;
    }
    return recordHit(hitAddr, retMarker);
  }

  const fmtHit = (addr2) =>
    `Breakpoint hit @ ${fmtAddr(addr2)}${sym(addr2) ? ` (${sym(addr2)})` : ""}`;

  /**
   * Adopt a pause that happened OUTSIDE this console (compile flow,
   * !dpcdrain, ...): callFunction records cpu.pausedFrame when the policy
   * pauses, and both engines now report identical shapes.
   */
  function syncPausedFromCpu() {
    if (bp.paused) return;
    const cpu = cpuOf();
    if (!cpu.pausedFrame) return;
    const pf = cpu.pausedFrame;
    normalizeHit({
      status: "breakpoint",
      rip: pf.rip,
      ripAfterInt3: pf.ripAfterInt3,
      retMarker: pf.retMarker,
    });
  }

  function requirePaused(w) {
    syncPausedFromCpu();
    if (bp.paused) return bp.paused;
    w("not paused: set a breakpoint (bp <module!sym|addr>), re-run the driver " +
      "action (compile+load, !dpcdrain, !notifytest...), then step with t/p/g.", "err");
    return null;
  }

  /** One single-instruction step on whichever engine is active. */
  function stepOnce() {
    const cpu = cpuOf();
    if (typeof cpu.stepInsn === "function") return cpu.stepInsn();
    const start = cpu.opcodeStart ?? cpu.rip;
    cpu.step();
    return start;
  }

  /**
   * When RIP sits on an armed gate, temporarily disable it and execute the
   * single instruction underneath so a resume doesn't instantly re-hit.
   * Callers re-arm afterwards (engineSetBp).
   */
  function resumePastOwnGate() {
    const cpu = cpuOf();
    if (bp.paused?.addr === null || cpu.regs.rip !== bp.paused.addr) return false;
    engineClearBp(cpu.regs.rip);
    try {
      stepOnce();
    } finally {
      engineSetBp(bp.paused.addr);
    }
    return true;
  }

  function doStepInto(_args, w) {
    if (!requirePaused(w)) return;
    const cpu = cpuOf();
    let startRip;
    try {
      startRip = resumePastOwnGate() ? cpu.regs.rip : stepOnce();
    } catch (e) {
      bp.paused = null;
      relaxPolicy();
      return w(`t: ${e.message}`, "err");
    }
    const to = cpu.regs.rip;
    w(`${fmtAddr(startRip)} -> ${fmtAddr(to)}${sym(to) ? ` (${sym(to)})` : ""}`);
  }

  /** JsInterpreter-only stopOnRip runner (mirrors HybridCpuBackend.runUntilStop). */
  function runUntilStopJs(stopAddr, maxSteps = 10_000_000) {
    const cpu = cpuOf();
    const saved = cpu.stopOnRip;
    cpu.stopOnRip = stopAddr;
    try {
      const reason = cpu.run(maxSteps);
      if (reason === "returned") return cpu.rip === stopAddr ? "stopped" : "exited";
      return reason;
    } finally {
      cpu.stopOnRip = saved;
    }
  }

  /** Shared stop-runner: hybrid/unicorn expose runUntilStop, JS falls back. */
  function runUntil(stopAddr) {
    const cpu = cpuOf();
    return cpu.runUntilStop ? cpu.runUntilStop(stopAddr) : runUntilStopJs(stopAddr);
  }

  async function doStepOver(_args, w) {
    if (!requirePaused(w)) return;
    const cpu = cpuOf();
    const at = cpu.regs.rip;
    let next = null;
    let isCall = false;
    try {
      const [insn] = await disassemble(mem, at, { count: 1 });
      if (insn) {
        next = insn.va + BigInt(insn.len);
        isCall = /^call/i.test(insn.mnemonic);
      }
    } catch { /* unmapped: fall through to plain step */ }
    if (!next || !isCall) return doStepInto(_args, w);
    try {
      resumePastOwnGate();
      const r = runUntil(next);
      if (r === "breakpoint") {
        const hit = normalizeHit({
          status: "breakpoint",
          rip: cpu.regs.rip,
          retMarker: bp.paused?.retMarker ?? null,
        });
        if (hit !== null) return w(fmtHit(hit));
      }
      if (r === "error") {
        bp.paused = null; relaxPolicy();
        return w(`p: fault @ ${fmtAddr(cpu.fault?.rip ?? cpu.rip)}: ${cpu.fault?.message ?? "?"}`, "err");
      }
      if (r === "exited" || r === "halted" || r === "timeout") {
        bp.paused = null; relaxPolicy();
        return w(`frame exited -> rip=${fmtAddr(cpu.regs.rip)} rax=${fmtAddr(cpu.regs.rax)}`);
      }
      w(`${fmtAddr(at)} -> ${fmtAddr(cpu.regs.rip)} (over call)`);
    } catch (e) {
      w(`p: ${e.message}`, "err");
    }
  }

  function doStepOut(_args, w) {
    if (!requirePaused(w)) return;
    const marker = bp.paused.retMarker;
    if (marker === null || marker === undefined) {
      return w("gu: no active frame marker (pause came from outside a modeled call)", "err");
    }
    const cpu = cpuOf();
    resumePastOwnGate();
    const r = runUntil(marker);
    if (r === "breakpoint") {
      const hit = normalizeHit({
        status: "breakpoint",
        rip: cpu.regs.rip,
        retMarker: marker,
      });
      if (hit !== null) return w(fmtHit(hit));
    }
    if (r === "error") {
      bp.paused = null; relaxPolicy();
      return w("gu: faulted before return — inspect with !analyze", "err");
    }
    if (r === "exited" || r === "halted" || r === "timeout") {
      bp.paused = null; relaxPolicy();
      return w(`returned -> rip=${fmtAddr(cpu.regs.rip)} rax=${fmtAddr(cpu.regs.rax)}`);
    }
    w(`returned -> ${fmtAddr(cpu.regs.rip)} rax=${fmtAddr(cpu.regs.rax)}`);
  }

  function doGo(_args, w) {
    if (!requirePaused(w)) return;
    const cpu = cpuOf();
    // RIP sits ON a gate: execute its instruction once so the fresh run
    // doesn't instantly re-hit the same breakpoint.
    try {
      resumePastOwnGate();
    } catch (e) {
      bp.paused = null; relaxPolicy();
      return w(`g: ${e.message}`, "err");
    }
    const marker = bp.paused.retMarker;
    if (marker !== null && marker !== undefined) {
      // sentinel-aware run: stop cleanly at the frame's return marker
      const r = runUntil(marker);
      if (r === "breakpoint") {
        const hit = normalizeHit({
          status: "breakpoint",
          rip: cpu.regs.rip,
          retMarker: marker,
        });
        if (hit !== null) return w(fmtHit(hit));
      }
      if (r === "error") {
        bp.paused = null; relaxPolicy();
        return w(`g: fault @ ${fmtAddr(cpu.fault?.rip ?? cpu.rip)}: ${cpu.fault?.message ?? "?"} (see !analyze)`, "err");
      }
      const done = r === "stopped" || r === "exited" || r === "halted" || r === "timeout";
      bp.paused = null; relaxPolicy();
      if (done) {
        return w(`run complete -> rip=${fmtAddr(cpu.rip)} rax=${fmtAddr(cpu.regs.rax)}`);
      }
      return w(`g: ${r}`, "warn");
    }
    const saved = cpu.stopOnRip;
    try {
      for (;;) {
        let reason;
        try { reason = cpu.run(10_000_000); }
        catch (e) {
          bp.paused = null; relaxPolicy();
          return w(`g: ${e.message}`, "err");
        }
        if (reason === "breakpoint") {
          const hit = normalizeHit({
            status: "breakpoint",
            rip: cpu.regs.rip,
            retMarker: bp.paused.retMarker,
          });
          if (hit !== null) return w(fmtHit(hit));
          continue; // unregistered int3 (module padding): legacy tolerance
        }
        if (reason === "returned") {
          bp.paused = null; relaxPolicy();
          return w(`run complete -> rip=${fmtAddr(cpu.rip)} rax=${fmtAddr(cpu.regs.rax)}`);
        }
        if (reason === "error") {
          const hit = normalizeHit({
            status: "fault",
            error: { message: String(cpu.fault?.message ?? ""), rip: cpu.fault?.rip },
            retMarker: bp.paused.retMarker,
          });
          if (hit !== null) return w(fmtHit(hit));
          bp.paused = null; relaxPolicy();
          return w(`g: fault @ ${fmtAddr(cpu.fault?.rip ?? cpu.rip)}: ${cpu.fault?.message ?? "?"} (see !analyze)`, "err");
        }
        bp.paused = null; relaxPolicy();
        return w(`g: ${reason}`, "warn");
      }
    } finally {
      cpu.stopOnRip = saved;
    }
  }

  const commands = {
    help(args, w) {
      w("commands:");
      w("  lm                        loaded modules");
      w("  !drivers                  driver objects (loadedDrivers + lm merge)");
      w("  !drvobj [name|addr]       DRIVER_OBJECT walk incl. MajorFunction table");
      w("  !process 0 [flags]        process list (0x2 token/threads, 0x4 threads)");
      w("  !process <addr|pid> [f]   kd-style process block; 0x2 + 0x4 as above");
      w("  !eproc <addr|pid>         short summary");
      w("  !token <addr|pid>         decode Token EX_FAST_REF + raw dump");
      w("  !pcr [addr] / !kpcr       KPCR -> PRCB -> CurrentThread chain");
      w("  !ps / !pt                 alias for !process 0 0 / current thread summary");
      w("  !handles [pid]            seeded cross-process handle references (EDR row #3)");
      w("  !prcb [addr]              _KPRCB field walk");
      w("  dt <Type> [addr]          struct layout or memory walk from build tables");
      w("  dt <Type> <Field>         single field lookup");
      w("  !dh <module|base>         parse PE headers from memory");
      w("  s [-a] <start> <len> <pat> search memory (hex bytes or \"text\" w/ -a)");
      w("  k | kp | kv | ks          stack (rip frame + module+offset; no unwind data)");
      w("  !analyze [-v]             modeled crash/state analysis");
      w("  !dbgprint                 replay the buffered DbgPrint output");
      w("  sym <addr>                resolve module+offset");
      w("  x <pattern>               symbol listing, wildcards: x nt!Ps*");
      w("  ? <expr>                  evaluate expression (? nt!DbgPrint+0x10)");
      w("  u [addr|sym] [n|Ln]       unassemble n instructions (default rip, 12)");
      w("  uf <addr|sym>             unassemble until ret/jmp");
      w("  da <addr> [len]           display ASCII string");
      w("  du <addr> [len]           display UTF-16 string");
      w("  !thread [addr]            _ETHREAD walk (default: PRCB.CurrentThread)");
      w("  eb <a> <b1> [b2...]       write bytes into mapped memory");
      w("  db <a> [n|Ln] | dq <a> [n|Ln]   hex dump bytes/qwords (L40 => hex length)");
      w("  r                         register context | clear");
      w("  r <reg>=<expr>            set a register (r rip=nt!DbgPrint, r eax=5)");
      w("  --- execution control (real int3 breakpoints) -----------------------");
      w("  bp <addr|mod!sym>         set software breakpoint");
      w("  bc <addr|*>               clear breakpoint(s)");
      w("  bd / be <addr>            disable / re-enable a breakpoint");
      w("  bl                        list breakpoints (hit counts)");
      w("  t                         single-step (into)");
      w("  p                         step over calls");
      w("  g                         go: run until the next breakpoint");
      w("  gu                        go until this frame returns");
      w("  --- lab extensions -------------------------------------------------");
      w("  !mmstate / !mmrun         manual-map loader state / run (manual-map lab)");
      w("  !irql [-a|n]              current IRQL, all cores, or force a level (lab ext)");
      w("  !dpcs / !dpcdrain         DPC queue contents / drain at <= DISPATCH");
      w("  !dpcpump [n]              advance the clock n ticks (timers + DPC retire)");
      w("  !dpcstat                  DPC/timer telemetry: depth, age, anomalies");
      w("  !dpcwatchdog              modeled DPC_WATCHDOG check (bugcheck 0x133)");
      w("  !pgscan                   integrity scan: protected ranges, WP history, hijacks");
      w("  !pgstatus                 mini-PatchGuard state: sweeps, regions, verdict");
      w("  !eptlist / !eptview <va> / !eptverify   EPT shadow views (m22)");
      w("  !vmexit                                  VM-exit MSR intercept log (m28)");
      w("  !openprocess <pid> [access]  modeled userland open (PPL enforced)");
      w("  !hookscan [export]        diff live vs pristine export prologues");
      w("  !hooktest <exp> [args]    exercise a modeled nt! call path");
      w("  !poolfind <tag>           list tagged pool blocks + guard health");
      w("  !poolverify               sweep all allocation guards");
      w("  !funcs <module>           static function recovery over a module");
      w("  !decomp <addr>            Ghidra pseudocode (real engine once vendored: npm run vendor:ghidra)");
      w("  !cr3 [proc]               page-table base + self-map index (paging labs)");
      w("  !pte <va> [proc]          full 4-level walk: entries, aliases, bits");
      w("  !vtop <va> [proc]         translate VA -> PA");
      w("  !cr                       control registers (cr0/cr3/cr4/efer)");
      w("  !smep [0|1]               query or toggle SMEP (CR4 bit 20)");
      w("  !dbgprint                 dump the buffered DbgPrint log");
      w("  !smram / !smmc            SMRAM state / SMRAMC decode (SMM labs)");
      w("  !notifyroutines           registered process/thread/image/Ob/Cm callbacks");
      w("  !notifytest <exe> [pid]   drive a process-create through the notify chain");
      w("  !ssdt [module]            system service table + inline-hook scan");
      w("  !pseudocode <addr>        Ghidra pseudocode (fixture fallback without the wasm)");
      w("  !dispatchscan             attest every DRIVER_OBJECT MajorFunction table (m24)");
      w("  !ioctltest <drv> [ioctl]  send one IRP_MJ_DEVICE_CONTROL through the live slot");
      w("  !objtype [name]           OBJECT_TYPE_INITIALIZER procedure attestation (m24)");
      w("  !obopen <name> [access]   modeled ObOpenObjectByPointer via live OpenProcedure");
      w("  !etwloggers               kernel logger contexts + EnableFlags attestation (m26)");
      w("  !etwpump <n>              emit n modeled CKCL events (delivered vs suppressed)");
      w("  !msr [name|addr] [value]  MSR register file read/write (m25)");
      w("  !idt / !gdt               interrupt/global descriptor table attestation");
      w("  !syscalltest              issue a syscall through the live LSTAR");
    },
    "!help"(args, w) { commands.help(args, w); },
    clear(args, w, out) { out.innerHTML = "(cleared)\n"; },

    lm(args, w) {
      if (args.length && args[0] && /[a-zA-Z]/.test(args[0][0])) {
        w(`note: lm option '${args[0]}' is not modeled — showing standard list`, "dim");
      }
      const DIR_WORDS = new Set(["systemroot", "system32", "system", "drivers",
        "driverstore", "filerepository", "windows", "drivers"]);
      // name recovery: longest usable fragment wins; directory words skipped
      const used = new Map();
      for (const m of kernel.loadedModules ?? []) {
        const hint = (m.baseDllName || m.fullDllName || "");
        const frags = hint.split("\\").filter(Boolean)
          .filter((f) => !DIR_WORDS.has(f.toLowerCase()))
          .filter((f) => f.length >= 3);
        m._frag = frags.sort((a, b) => b.length - a.length)[0] ?? "";
      }
      w("start             end                 module name", "hdr");
      let repaired = 0;
      for (const m of kernel.loadedModules ?? []) {
        if (m.lab) {
          w(`${fmtAddr(m.base)} ${fmtAddr(m.base + BigInt(m.sizeOfImage ?? 0x100000))} ${m.name}` +
            "   <-- suspicious");
          continue;
        }
        let name = m.name;
        if (m.nameRepaired || /mod_[0-9a-f]+\.sys$/.test(name) ||
            /^(System3|System|system3|system|sy|syst|System32|driv|driver)$/.test(name)) {
          const frag = m._frag;
          name = frag ? frag + ".sys" : name;
          // dedupe repeats
          const n = (used.get(name) ?? 0);
          used.set(name, n + 1);
          if (n > 0 && frag) name = name.replace(/(\.[^.]+)$/, `_${n}$1`);
          repaired++;
        }
        m.name = name; // keep sym() consistent with the improved table
        const sizeOfImg = BigInt(m.sizeOfImage ?? 0x100000);
        w(`${fmtAddr(m.base)} ${fmtAddr(m.base + sizeOfImg)} ${name}`);
      }
      if (repaired) w(`(${repaired} names reconstructed from truncated dump strings)`, "dim");
    },

    "!process"(args, w) {
      if (!args.length || args[0] === "0") {
        const bits = Number(args[1] ?? 0);
        const procs = kernel.listProcesses();
        for (const p of procs) processBlock(p.eprocess, bits, w);
        return;
      }
      // thread-address guard: route obviously-thread addresses to a hint
      let asAddr = null;
      try { asAddr = BigInt(args[0]); } catch { /* name arg — no guard */ }
      if (asAddr !== null) {
        if (kernel.currentThread && asAddr === kernel.currentThread) {
          return w(`!process: ${fmtAddr(kernel.currentThread)} is an _ETHREAD — use !thread`, "err");
        }
        if (kernel.threads?.[String(asAddr)]) {
          return w(`!process: ${fmtAddr(asAddr)} is an _ETHREAD — use !thread`, "err");
        }
      }
      const eproc = resolveProcess(args[0]);
      if (!eproc) return w(`!process: no process for "${args[0]}"`, "err");
      processBlock(eproc, Number(args[1] ?? 0), w);
    },

    "!eproc"(args, w) {
      const eproc = args[0] ? resolveProcess(args[0]) : null;
      if (!eproc) return w("usage: !eproc <addr|pid>", "err");
      for (const l of dumpStruct("_EPROCESS", eproc, { max: 12 })) w(l);
    },

    "!token"(args, w) {
      if (!args[0]) return w("usage: !token <TokenAddress|pid|name>", "err");
      let target = 0n;
      try {
        let v = null;
        try { v = BigInt(args[0]); } catch { /* name form */ }
        if (v !== null && v > 0xffffn) target = v & FAST_REF_MASK;
        else {
          const off = tables.offsetOf("_EPROCESS", "Token");
          const e = resolveProcess(args[0]);
          target = e ? mem.u64(e + off) & FAST_REF_MASK : 0n;
        }
      } catch { return w("!token: bad argument", "err"); }
      if (!target) return w("!token: NULL token", "dim");
      w(`TOKEN @ ${fmtAddr(target)}`, "hdr");
      w("  NOTE: no Vergilius _TOKEN table loaded yet — raw qwords only.", "dim");
      for (let i = 0; i < 8; i++) {
        w(`  +0x${(i * 8).toString(16).padStart(2, "0")} ${fmtAddr(target + BigInt(i * 8))}  ${fmtAddr(mem.u64(target + BigInt(i * 8)))}`);
      }
    },

    "!pcr"(args, w) {
      const kpcr = args[0] ? BigInt(args[0]) : kernel.kpcr;
      if (!kpcr) return w("!pcr: kernel not booted with a synthesized KPCR", "err");
      w("KPCR (x64: normally addressed via GS base — see note)", "hdr");
      for (const l of dumpStruct("_KPCR", kpcr, { max: 24 })) w(l);
      const prcb = mem.u64(kpcr + tables.offsetOf("_KPCR", "CurrentPrcb"));
      w("", "dim");
      w(`CurrentPrcb -> ${fmtAddr(prcb)}   try: dt _KPRCB ${fmtAddr(prcb)}`, "dim");
      const ctOff = (() => { try { return tables.offsetOf("_KPRCB", "CurrentThread"); } catch { return null; } })();
      if (ctOff !== null) {
        const ct = mem.u64(prcb + ctOff);
        w(`PRCB.CurrentThread -> ${fmtAddr(ct)}   try: dt _ETHREAD ${fmtAddr(ct)}`, "dim");
        w("  (cross-ref to its process via Cid.UniqueProcess — 22h2 tables do not", "dim");
        w("   expose ETHREAD.ThreadsProcess)", "dim");
      }
    },

    "!dh"(args, w) {
      let base;
      if (!args[0]) {
        base = kernel.kpcr ? (() => { try { return null; } catch { return null; } })() : null;
        // default: ntoskrnl (largest real module)
        const mods = kernel.loadedModules ?? [];
        const nt = mods.find((m) => m.name === "ntoskrnl.exe") ?? mods[0];
        base = nt?.base;
      } else {
        try { base = BigInt(args[0]); } catch {
          const m = (kernel.loadedModules ?? []).find((x) => x.name === args[0]);
          base = m?.base;
        }
      }
      if (!base) return w("usage: !dh <module|base>   (e.g. !dh ntoskrnl.exe)", "err");
      if (!mem.canRead(base, 0x400)) return w(memErr(base, "unmapped"), "err");

      if (mem.u16(base) !== 0x5a4d) return w(`!dh: no MZ at ${fmtAddr(base)}`, "err");
      const e_lfanew = mem.u32(BigInt(base) + 0x3cn);
      const pe = BigInt(base) + BigInt(e_lfanew);
      if (mem.u32(pe) !== 0x00004550) return w(`!dh: bad PE signature`, "err");
      const machine = mem.u16(BigInt(pe) + 4n);
      const numSections = mem.u16(BigInt(pe) + 6n);
      const sizeOpt = mem.u16(BigInt(pe) + 20n);
      const opt = BigInt(pe) + 24n;
      const magic = mem.u16(opt);
      const entryRva = mem.u32(opt + 16n);
      const rawBase = magic === 0x20b ? mem.u64(opt + 24n) : BigInt(mem.u32(opt + 28));
      const imageBase = BigInt(rawBase);
      w(`PE signature OK`, "hdr");
      w(`  machine            : 0x${machine.toString(16)}${machine === 0x8664 ? " (x64)" : ""}`);
      w(`  sections           : ${numSections}`);
      w(`  entry point        : ${fmtAddr(imageBase + BigInt(entryRva))}`);
      w(`  image base         : ${fmtAddr(imageBase)}`);
      const secTab = opt + BigInt(sizeOpt);
      w(`  section table      :`, "hdr");
      for (let i = 0; i < numSections; i++) {
        const so = secTab + BigInt(i * 40);
        const nmBytes = mem.read(so, 8);
        const nm = [...nmBytes].map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : "")).join("");
        const vsize = mem.u32(so + 8n), vaddr = mem.u32(so + 12n);
        w(`    ${nm.padEnd(8)} VirtSize:0x${vsize.toString(16).padStart(6, "0")} VirtAddr:0x${vaddr.toString(16).padStart(6, "0")}`);
      }
    },

    "!ps"(args, w) {
      commands["!process"](["0", "0"], w);
    },
    "!handles"(args, w) {
      // Enumerate the seeded cross-process handle references (the row-#3
      // cross-check from the m1.l0 primer). Optional arg filters by owner
      // pid:  !handles          every owner's table
      //       !handles 1312     only kfsample.exe's open handles
      const refs = kernel.objectHandles ?? [];
      if (!refs.length) {
        return w("!handles: no handle tables seeded in this world", "err");
      }
      const byEproc = new Map(
        [...(kernel.processesByName ?? [])].map(([nm, ep]) => [ep, nm]));
      let ownerFilter = null;
      if (args[0]) {
        const eproc = resolveProcess(args[0]);
        if (!eproc) return w(`!handles: no process for "${args[0]}"`, "err");
        ownerFilter = eproc;
      }
      w("Owner process                          Handle   Object            GrantedAccess", "hdr");
      let shown = 0;
      for (const r of refs) {
        if (ownerFilter && r.ownerEproc !== ownerFilter) continue;
        w(`${(byEproc.get(r.ownerEproc) ?? "???").padEnd(38)} ` +
          `0x${r.handle.toString(16).padStart(4, "0")}   ` +
          `${fmtAddr(r.targetEproc)}  0x${r.grantedAccess.toString(16)}`);
        shown++;
      }
      if (!shown && ownerFilter) w("  (no seeded handles for this process)", "dim");
    },
    "!pt"(args, w) {
      // Walk threads of the current process
      const ct = kernel.currentThread ?? (kernel.kpcr ? (() => {
        try { return mem.u64(mem.u64(kernel.kpcr + tables.offsetOf("_KPCR", "CurrentPrcb")) +
          tables.offsetOf("_KPRCB", "CurrentThread")); } catch { return null; }
      })() : null);
      if (!ct) return w("!pt: no current thread", "err");
      w(`THREAD @ ${fmtAddr(ct)}`, "hdr");
      for (const line of dumpStruct("_ETHREAD", ct, { max: 24 })) w(line);
      w("  (use !thread <addr> for full walk)", "dim");
    },
    "!kpcr"(args, w) {
      commands["!pcr"](args, w);
    },
    "!prcb"(args, w) {
      const prcb = args[0] ? BigInt(args[0]) : kernel.prcb;
      if (!prcb) return w("!prcb: no PRCB (boot a scenario first)", "err");
      for (const l of dumpStruct("_KPRCB", prcb, { max: 40 })) w(l);
    },

    "!thread"(args, w) {
      const ctOff = (() => { try { return tables.offsetOf("_KPRCB", "CurrentThread"); } catch { return null; } })();
      let addr;
      try {
        addr = args[0] ? BigInt(args[0])
          : (kernel.kpcr && ctOff !== null
              ? mem.u64(mem.u64(kernel.kpcr + tables.offsetOf("_KPCR", "CurrentPrcb")) + ctOff)
              : 0n);
      } catch { return w("!thread: bad address", "err"); }
      if (!addr) return w("!thread: no current thread (boot a scenario first)", "err");
      for (const l of dumpStruct("_ETHREAD", addr, { max: 48 })) w(l);
    },

    dt(args, w) {
      let raw = args[0] ?? "";
      const clean = raw.replace(/^(?:nt|ntoskrnl|ntoskrnl\.exe)!/i, "");
      const tname = clean.startsWith("_") ? clean : `_${clean}`;
      const second = args[1] ?? null;
      const sym = kernel.symbolEngine;

      const knownType = !!tables.types.get(tname);
      if (!knownType) {
        return w(`dt: unknown type "${tname}"\navailable: ${[...tables.types.keys()].sort().join(", ")}`, "err");
      }

      // ---- 1. Layout-only mode (no second arg) ----
      if (!second) {
        const fields = walkableFields(tables, tname);
        w(`struct ${tname} (${fields.length} walkable fields, layout-only — pass an address or PID for a memory dump)`, "hdr");
        let shown = 0;
        for (const f of fields) {
          if (shown >= 48) { w(`  ... (${fields.length - shown} more)`); break; }
          const base = String(f.base ?? "");
          const sz = /\*$/.test(base) ? 8 : byteSizeOf(base);
          w(`  +0x${f.offset.toString(16).padStart(3, "0")} ${f.name.padEnd(28)} : ${base || "?"} (${sz} bytes)`);
          shown++;
        }
        return;
      }

      // ---- 2. Field-specific schema query (non-numeric second arg) ----
      // Try this BEFORE address/PID parsing — a field name like "ActiveProcessLinks"
      // would fail hex parsing but succeed as a field descriptor.
      if (!/^(0x)?[0-9]+$/i.test(second)) {
        if (sym) {
          const f = sym.getField(tname, second);
          if (f) {
            w(`${tname}.${second}`, "hdr");
            w(`  +0x${f.offset.toString(16).padStart(3, "0")} ${f.decl || second}`);
            w(`  offset=0x${f.offset.toString(16)} size=${f.size}`);
            return;
          }
          // not a field either → maybe it IS a hex address after all
        }
        // fall through to address parsing below
      }

      // ---- 3. Parse the value as BigInt (handles dec + hex) ----
      let val;
      try { val = BigInt(second); } catch { return w(`dt: bad address "${second}"`, "err"); }

      // ---- 4. PID resolution for process/thread types ----
      // Small integers (< 2^20 ≈ 1M) that match an active PID are resolved
      // via the kernel process table rather than dereferenced literally.
      if (/^_(?:EPROCESS|ETHREAD)$/.test(tname)) {
        if (val > 0n && val < 0x100000n) {
          const eproc = kernel.findEprocessByPid(val);
          if (eproc) {
            w(`Resolving pid ${val} -> _EPROCESS @ ${fmtAddr(eproc)}`, "dim");
            for (const line of dumpStruct(tname, eproc, { max: 96 })) w(line);
            return;
          }
          // small value but no matching PID — still treat as address
        }
      }

      // ---- 5. Literal address-dump mode with memory safety ----
      const totalSize = Math.max(
        ...walkableFields(tables, tname).map((f) => f.offset + 8));
      const why = memFault(val, totalSize);
      if (why) return w(memErr(val, why), "err");
      for (const line of dumpStruct(tname, val, { max: 96 })) w(line);
    },

    s(args, w) {
      // usage: s [-a] <startAddr> <len|Llen> <hex bytes | "ascii">
      let ascii = false;
      const a = [...args];
      if (a[0] === "-a") { ascii = true; a.shift(); }
      let start, len, pat = [];
      try {
        start = tryEvalAddr(a[0]) ?? BigInt(a[0]);
        len = parseLen(a[1] ?? "128");
        if (ascii) {
          const q = a.slice(2).join(" ").replace(/^"|"$/g, "");
          pat = [...q].map((ch) => ch.charCodeAt(0));
        } else {
          pat = a.slice(2).join("").match(/.{2}/g)?.map((x) => parseInt(x, 16)) ?? [];
        }
      } catch { return w('usage: s [-a] <start> <len> <hex | "text"> ', "err"); }
      if (!Number.isFinite(len) || len <= 0) return w("s: bad length", "err");
      if (!pat.length) return w("s: empty pattern", "err");
      if (start < 0n) start = BigInt.asUintN(64, start);
      len = Math.min(len, 0x100000);
      // Degrade page-wise instead of failing wholesale: search the largest
      // contiguously backed prefix and say so when the span crosses into
      // unmapped memory (real WinDbg faults; our worlds prefer partial hits).
      let avail = 0n;
      if (mem.canRead(start, 1)) {
        let cur = start;
        const endVa = start + BigInt(len);
        while (cur < endVa) {
          const pageEnd = (cur & ~0xfffn) + 0x1000n;
          const chunkEnd = pageEnd < endVa ? pageEnd : endVa;
          if (!mem.canRead(cur, Number(chunkEnd - cur))) break;
          cur = chunkEnd;
        }
        avail = cur - start;
      }
      if (avail === 0n) return w(memErr(start, memFault(start, 1) ?? "unmapped"), "err");
      if (avail < BigInt(len)) {
        w(`note: range partially mapped — searching first ${avail} bytes only`, "dim");
      }
      const hay = mem.read(start, Number(avail));
      let hits = 0;
      outer:
      for (let i = 0; i + pat.length <= hay.length; i++) {
        for (let j = 0; j < pat.length; j++) if (hay[i + j] !== pat[j]) continue outer;
        w(`Found ${fmtAddr(start + BigInt(i))}`); hits++;
        if (hits >= 32) { w("... (truncated)", "dim"); break; }
      }
      if (!hits) w("0 matches", "dim");
    },
    ks(args, w) { commands["kv"](args, w); },

    r(args, w) {
      // write form: r reg=expr — WinDbg assignment syntax
      if (args.length) {
        const joined = args.join(" ");
        const m = joined.match(/^([a-z0-9]{2,4})\s*=\s*(.+)$/i);
        if (!m) return w(`r: bad assignment "${joined}" (try: r rip=nt!DbgPrint)`, "err");
        const [, name, exprText] = m;
        const cpu = cpuOf();
        if (!(name.toLowerCase() in cpu.regs) && name.toLowerCase() !== "rip") {
          return w(`r: unknown register "${name}"`, "err");
        }
        const resolver = (key) => resolveArg(key) ?? (() => {
          try { return BigInt(key); } catch { return null; }
        })();
        let v;
        try { v = evalExpr(exprText, resolver); } catch (e) {
          return w(`r: ${e.message}`, "err");
        }
        const key = name.toLowerCase();
        try { cpu.regs[key] = BigInt.asUintN(64, v); } catch (e) {
          return w(`r: cannot write ${name}: ${e.message}`, "err");
        }
        return w(`${key} = ${fmtAddr(v)}${sym(v) ? `  ${sym(v)}` : ""}`);
      }
      const src = kernel.contextSource === "dump" ? "   ; context from dump" : "";
      for (const [k, v] of Object.entries(kernel.cpu.regs)) {
        const s = sym(v);
        w(`${k.padEnd(4)}=${fmtAddr(v)}${s ? `  ${s}` : ""}`);
      }
      if (src) w(src, "dim");
    },

    // ---- breakpoints -------------------------------------------------------
    bp(args, w) {
      const tok = args[0];
      if (!tok) return w("usage: bp <addr|module!sym|expr>   (e.g. bp kfhook.sys+0x1010)", "err");
      const addr = tryEvalAddr(tok);
      if (addr === null) return w(`bp: cannot resolve "${tok}"`, "err");
      if (bp.map.has(addr)) return w(`breakpoint already set @ ${fmtAddr(addr)}`, "warn");
      bp.map.set(addr, { enabled: true, hits: 0 });
      engineSetBp(addr);
      armPolicy();
      w(`Breakpoint ${bp.map.size - 1} set @ ${fmtAddr(addr)}${sym(addr) ? ` (${sym(addr)})` : ""}`);
      w("re-run the driver action to hit it; then t/p/g/gu step.", "dim");
    },

    bl(_args, w) {
      if (!bp.map.size) return w("no breakpoints set", "dim");
      let i = 0;
      for (const [addr2, rec] of bp.map) {
        w(`${i++} ${rec.enabled ? "e" : "d"} hits:${rec.hits} @ ${fmtAddr(addr2)}${sym(addr2) ? ` (${sym(addr2)})` : ""}`);
      }
    },

    bc(args, w) {
      const tok = args[0];
      if (!tok) return w("usage: bc <addr|*>", "err");
      if (tok === "*") {
        for (const [addr2] of bp.map) engineClearBp(addr2);
        bp.map.clear();
        bp.paused = null;
        relaxPolicy();
        return w("all breakpoints cleared");
      }
      const addr = tryEvalAddr(tok);
      if (addr === null || !bp.map.has(addr)) return w(`bc: no breakpoint at "${tok}"`, "err");
      engineClearBp(addr);
      bp.map.delete(addr);
      relaxPolicy();
      w(`breakpoint cleared @ ${fmtAddr(addr)}`);
    },

    bd(args, w) {
      const addr = args[0] ? tryEvalAddr(args[0]) : null;
      const rec = addr !== null ? bp.map.get(addr) : null;
      if (!rec) return w("usage: bd <addr>", "err");
      rec.enabled = false;
      engineClearBp(addr);
      w(`breakpoint disabled @ ${fmtAddr(addr)}`);
    },

    be(args, w) {
      const addr = args[0] ? tryEvalAddr(args[0]) : null;
      const rec = addr !== null ? bp.map.get(addr) : null;
      if (!rec) return w("usage: be <addr>", "err");
      rec.enabled = true;
      engineSetBp(addr);
      armPolicy();
      w(`breakpoint enabled @ ${fmtAddr(addr)}`);
    },

    t(args, w) { doStepInto(args, w); },
    async p(args, w) { await doStepOver(args, w); },
    gu(args, w) { doStepOut(args, w); },
    g(args, w) { doGo(args, w); },

    // internal: burst-pause adoption for the app adapter (never typed)
    __bpBurst(res) {
      syncPausedFromCpu();
      return bp.paused ? bp.paused.addr : null;
    },
    __bpPaused: () => !!bp.paused,


    k(args, w) { stack(args, w, kindNote("k")); },
    kp(args, w) { stack(args, w, kindNote("kp") + "\n   (parameters unavailable — no unwind data modeled)"); },
    kv(args, w) { stack(args, w, kindNote("kv") + "\n   (frame sizes unavailable — no unwind data modeled)"); },

    "!analyze"(args, w) {
      const verbose = args.includes("-v");
      w("======================= ANALYSIS =======================", "hdr");
      if (kernel.bugcheck) {
        w(`BUGCHECK_CODE: 0x${kernel.bugcheck.code.toString(16)}`);
        w(`BUGCHECK_P1..P4: ${kernel.bugcheck.params.map((p) => "0x" + p.toString(16)).join(" ")}`);
      } else {
        w("No bugcheck recorded — machine state is live-modeled.", "dim");
      }
      const rip = kernel.cpu.regs.rip;
      const ripSym = sym(rip) ?? "<unknown module>";
      w(`CONTEXT:  rip=${fmtAddr(rip)} (${ripSym})`);
      w(`          rsp=${fmtAddr(kernel.cpu.regs.rsp)}`);
      const curEproc = (() => {
        try {
          const pidOff = tables.offsetOf("_EPROCESS", "UniqueProcessId");
          const cidOff = (() => { try { return tables.offsetOf("_ETHREAD", "Cid"); } catch { return null; } })();
          if (kernel.currentThread && cidOff !== null) {
            const pid = mem.u64(kernel.currentThread + cidOff);
            return kernel.findEprocessByPid(pid);
          }
        } catch { /* none */ }
        return null;
      })();
      if (curEproc) {
        const pid = mem.u64(curEproc + tables.offsetOf("_EPROCESS", "UniqueProcessId"));
        const nm = mem.readAnsi(curEproc + tables.offsetOf("_EPROCESS", "ImageFileName"), 15);
        w(`PROCESS:  ${nm} (pid ${pid}) @ ${fmtAddr(curEproc)}`);
      }
      if (verbose) {
        w(`IRQL:     ${kernel.currentIrql ?? "?"}`);
        w(`MODULES:  ${(kernel.loadedModules ?? []).length} loaded` +
          ((kernel.loadedModules ?? []).some((m) => m.real) ? " (real-dump set)" : ""));
        w(`THREADS:  CurrentThread=${fmtAddr(kernel.currentThread ?? 0n)}`);
        // NB: debug output is NOT analyzed here (matches real !analyze, which
        // never replays DbgPrint history) — use !dbgprint for the buffer.
      }
      w("========================================================", "hdr");
    },

    sym(args, w) {
      try {
        const va = args[0] ? (resolveArg(args[0]) ?? BigInt(args[0])) : 0n;
        w(sym(va) ?? `${fmtAddr(va)} <no module>`);
      } catch { w("usage: sym <address>", "err"); }
    },

    async u(args, w) {
      // usage: u [addr|symbol|expr] [count|Lcount] — default: rip, 12 instructions
      let idx = 0;
      let va = kernel.cpu.regs.rip ?? 0n;
      let from = "rip";
      if (args[0] && !/^[Ll]/.test(args[0])) {
        va = tryEvalAddr(args[0]);
        if (va === null) return w(`u: cannot resolve "${args[0]}"`, "err");
        from = unquote(args[0]);
        idx = 1;
      }
      let count = 12;
      if (args[idx]) {
        try { count = parseLen(args[idx]); } catch { return w("u: bad count (try: u <addr> L20)", "err"); }
      }
      count = Math.min(Math.max(count, 1), 256);
      const hiBase = BigInt.asUintN(64, va) & ~0xffffffffn;
      try {
        const insns = await disassemble(mem, va, { count });
        if (!insns.length) return w(`u: no decodable instructions at ${fmtAddr(va)}`, "err");
        w(`unassembly from ${from} (${from === "rip" ? fmtAddr(va) : sym(va) ?? fmtAddr(va)}):`, "hdr");
        for (const i of insns) {
          const bytes = i.bytes.map((b) => b.toString(16).padStart(2, "0")).join(" ");
          w(`${fmtAddr(i.va)}  ${bytes.padEnd(21)} ${disasmLine(i, hiBase)}`);
        }
      } catch (e) {
        unasmError("u", va, e, w, count);
      }
    },

    async uf(args, w) {
      // usage: uf <addr|symbol> — unassemble until unconditional ret/jmp
      if (!args[0]) return w("usage: uf <addr|symbol>   e.g. uf nt!PsLookupProcessByProcessId", "err");
      const va = tryEvalAddr(args[0]);
      if (va === null) return w(`uf: cannot resolve "${args[0]}"`, "err");
      const hiBase = BigInt.asUintN(64, va) & ~0xffffffffn;
      try {
        const insns = await disassemble(mem, va, { count: 128, stopAfterRet: true });
        w(`function at ${sym(va) ?? fmtAddr(va)}:`, "hdr");
        for (const i of insns) {
          const bytes = i.bytes.map((b) => b.toString(16).padStart(2, "0")).join(" ");
          w(`${fmtAddr(i.va)}  ${bytes.padEnd(21)} ${disasmLine(i, hiBase)}`);
        }
        if (insns.length >= 128) w("... (cap reached — no terminating ret found)", "dim");
      } catch (e) {
        unasmError("uf", va, e, w, 12);
      }
    },

    da(args, w) {
      // usage: da <addr> [len|Llen] — ASCII string display (NUL-terminated)
      const addr = args[0] ? tryEvalAddr(args[0]) : null;
      if (addr === null) return w("usage: da <addr> [len]", "err");
      let len;
      try { len = parseLen(args[1] ?? "64"); } catch { return w("da: bad length", "err"); }
      len = Math.min(len, 512);
      const why = memFault(addr, len);
      if (why) return w(memErr(addr, why), "err");
      const bytes = mem.read(addr, len);
      let out = "";
      for (const b of bytes) {
        if (b === 0) break;
        out += b >= 32 && b < 127 ? String.fromCharCode(b) : ".";
      }
      w(`"${out}"`);
    },

    du(args, w) {
      // usage: du <addr> [len|Llen] — UTF-16 string display
      const addr = args[0] ? tryEvalAddr(args[0]) : null;
      if (addr === null) return w("usage: du <addr> [len]", "err");
      let len;
      try { len = parseLen(args[1] ?? "64"); } catch { return w("du: bad length", "err"); }
      len = Math.min(len & ~1, 512);
      const why = memFault(addr, len);
      if (why) return w(memErr(addr, why), "err");
      const chars = [];
      for (let i = 0; i < len; i += 2) {
        const c = mem.u16(addr + BigInt(i));
        if (c === 0) break;
        chars.push(c >= 32 && c < 127 ? c : 46); // '.' for non-printables
      }
      w(`"${String.fromCharCode(...chars)}"`);
    },

    x(args, w) {
      // usage: x <pattern> — symbol listing with * / ? wildcards.
      // Sources: modeled nt! export thunks (apiThunks). windbg-style output:
      //   <addr> nt!<name>
      let pat = args.join("") || "*";
      pat = pat.replace(/^(?:nt|ntoskrnl(?:\.exe)?)!/i, "");
      const rx = new RegExp("^" + pat.replace(/[.+^${}()|[\]\\]/g, "\\$&")
        .replace(/\*/g, ".*").replace(/\?/g, ".") + "$", "i");
      const hits = [...(kernel.apiThunks ?? []).entries()]
        .filter(([name]) => rx.test(name))
        .sort(([a], [b]) => a.localeCompare(b));
      if (!hits.length) return w(`no symbols match '${args.join("")}'`, "dim");
      for (const [name, thunk] of hits) {
        w(`${fmtAddr(thunk)} nt!${name}`);
      }
      w(`(${hits.length} match(es))`, "dim");
    },

    "?"(args, w) {
      if (!args.length) return w("usage: ? <expr>   e.g. ? nt!PsLookupProcessByProcessId + 0x10", "err");
      const exprText = args.join(" ");
      const resolver = (kind, key) => {
        if (kind === "@") {
          const regs = kernel.cpu?.regs ?? {};
          if (key in regs) return BigInt.asUintN(64, BigInt(regs[key]));
          return null;
        }
        // module+offset inside expressions: nt+0x1000, kfhook.sys+0x40
        const rel = key.match(/^([A-Za-z0-9_.]+?)\+(?:0x)?([0-9a-fA-F]+)$/i);
        if (rel) {
          const v = resolveArg(rel[1] + "+0x" + rel[2]);
          if (v !== null) return v;
        }
        return resolveArg(key);
      };
      try {
        const v = evalExpr(exprText, resolver);
        w(`Evaluate expression: ${v.toString(16).padStart(16, "0")} = ${v.toString()}`);
      } catch (e) {
        w(`? : ${e.message}`, "err");
      }
    },

    "!drivers"(args, w) {
      const mods = kernel.loadedModules ?? [];
      const drivers = kernel.loadedDrivers ?? [];
      const rows = new Map();
      for (const d of drivers) {
        rows.set(String(d.name), {
          name: String(d.name), base: BigInt(d.base), size: BigInt(d.imageSize ?? 0),
          lab: false,
        });
      }
      for (const m of mods) {
        rows.set(String(m.name), {
          name: String(m.name), base: m.base, size: BigInt(m.sizeOfImage ?? 0),
          lab: !!m.lab,
        });
      }
      w("start             end                 module name", "hdr");
      for (const r of rows.values()) {
        w(`${fmtAddr(r.base)} ${fmtAddr(r.base + r.size)} ${r.name}` +
          (r.lab ? "   <-- suspicious" : ""));
      }
      w(`(${rows.size} driver object(s))`, "dim");
    },

    "!drvobj"(args, w) {
      const target = args[0];
      if (!target) {
        const recs = [...(kernel.driverObjects ?? new Map()).values()];
        if (!recs.length) return w("usage: !drvobj <name|addr>   (no DRIVER_OBJECTs created yet)", "err");
        w("Driver objects:", "hdr");
        for (const r of recs) w(`  ${fmtAddr(r.va)}  ${r.name}`);
        return;
      }
      let rec = null;
      let va = resolveArg(unquote(target));
      if (va !== null) rec = (kernel.driverObjects ?? new Map()).get(va);
      if (!rec) {
        const byName = [...(kernel.driverObjects ?? new Map()).values()]
          .find((r) => r.name.toLowerCase() === target.toLowerCase().replace(/\.sys$/, "")
            || `${r.name}`.toLowerCase() === target.toLowerCase());
        if (byName) { rec = byName; va = byName.va; }
      }
      if (!rec) return w(`!drvobj: no DRIVER_OBJECT for '${target}' (compile+load a driver first, or list with !drvobj)`, "err");

      w(`DRIVER_OBJECT ${fmtAddr(va)} (${rec.name})`, "hdr");
      const rd = (off) => mem.u64(va + off);
      const typeSize = mem.u32(va + BigInt(DRIVER_OBJECT.TYPE));
      w(`  Type/Size           : 0x${typeSize.toString(16)}`);
      w(`  DeviceObject        : ${fmtAddr(rd(BigInt(DRIVER_OBJECT.DEVICE_OBJECT)))}`);
      w(`  Flags               : 0x${rd(BigInt(DRIVER_OBJECT.FLAGS)).toString(16)}`);
      w(`  DriverStart         : ${fmtAddr(rd(BigInt(DRIVER_OBJECT.DRIVER_START)))}` +
        (rd(BigInt(DRIVER_OBJECT.DRIVER_START)) ? `  (${rec.name})` : ""));
      w(`  DriverSize          : 0x${rd(BigInt(DRIVER_OBJECT.DRIVER_SIZE)).toString(16)}`);
      const usLen = mem.u16(va + BigInt(DRIVER_OBJECT.DRIVER_NAME));
      const usBuf = rd(BigInt(DRIVER_OBJECT.DRIVER_NAME) + 8n);
      w(`  DriverName          : "${usLen ? mem.readUtf16(usBuf, usLen / 2) : ""}"`);
      w(`  DriverSection       : ${fmtAddr(rd(BigInt(DRIVER_OBJECT.DRIVER_SECTION)))}`);
      w(`  DriverInit          : ${fmtAddr(rd(BigInt(DRIVER_OBJECT.DRIVER_INIT)))}`);
      w(`  DriverStartIo       : ${fmtAddr(rd(BigInt(DRIVER_OBJECT.DRIVER_STARTIO)))}`);
      w(`  DriverUnload        : ${fmtAddr(rd(BigInt(DRIVER_OBJECT.DRIVER_UNLOAD)))}` +
        (rd(BigInt(DRIVER_OBJECT.DRIVER_UNLOAD)) ? "" : "  (not set)"), "warn");
      w("  MajorFunction table :", "hdr");
      for (const [code, name] of Object.entries(IRP_MJ_NAMES)) {
        const fn = rd(BigInt(DRIVER_OBJECT.MAJOR_FUNCTION) + BigInt(Number(code) * 8));
        const isDefault = fn === rec.defaultMajorThunk;
        w(`    [+0x${(Number(code) * 8 + DRIVER_OBJECT.MAJOR_FUNCTION).toString(16).padStart(3, "0")}] IRP_MJ_${name.padEnd(22)} ${fmtAddr(fn)}${isDefault ? "  (IopInvalidDeviceRequest)" : ""}`,
          isDefault ? "dim" : "");
      }
    },
    "!drivobj"(args, w) { commands["!drvobj"](args, w); }, // alias (both spellings seen in the wild)

    // ------------------------------------------------- m24 dispatch-layer labs

    "!dispatchscan"(args, w) {
      const foreign = kernel.scanForeignDispatch?.() ?? [];
      const recs = [...(kernel.driverObjects ?? new Map()).values()];
      if (!recs.length) return w("!dispatchscan: no DRIVER_OBJECTs exist yet", "err");
      w("MajorFunction attestation (baseline vs live, containment vs own image):", "hdr");
      let convicted = 0;
      for (const rec of recs) {
        const rd = (off) => mem.u64(rec.va + off);
        const start = rd(BigInt(DRIVER_OBJECT.DRIVER_START));
        const size = rd(BigInt(DRIVER_OBJECT.DRIVER_SIZE));
        w(`  ${rec.name}  ${fmtAddr(rec.va)}  image ${fmtAddr(start)}+0x${size.toString(16)}`,
          "hdr");
        for (const [code, name] of Object.entries(IRP_MJ_NAMES)) {
          const slotVa = rec.va + BigInt(DRIVER_OBJECT.MAJOR_FUNCTION) +
            BigInt(Number(code) * 8);
          const fn = rd(BigInt(DRIVER_OBJECT.MAJOR_FUNCTION) + BigInt(Number(code) * 8));
          const isDefault = fn === rec.defaultMajorThunk;
          if (isDefault) continue; // lazy default: nothing to attest
          const bad = foreign.find((f) => f.drvRec === rec && f.code === Number(code));
          const baseQword = rec.majorBaseline
            ? (() => { const o = Number(code) * 8;
                let v = 0n;
                for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(rec.majorBaseline[o + i]);
                return v; })()
            : null;
          if (bad) {
            convicted++;
            w(`    [+0x${slotVa.toString(16).slice(-3)}] IRP_MJ_${name.padEnd(22)} ${fmtAddr(fn)}  FOREIGN -> ${bad.owner ?? "unbacked memory"}`, "err");
            if (baseQword !== null && baseQword !== 0n) {
              const le = [...new Uint8Array(new BigUint64Array([baseQword]).buffer)]
                .map((b) => b.toString(16).padStart(2, "0")).join(" ");
              w(`        repair: eb ${fmtAddr(slotVa)} ${le}`, "dim");
            }
          } else {
            w(`    [+0x${slotVa.toString(16).slice(-3)}] IRP_MJ_${name.padEnd(22)} ${fmtAddr(fn)}${baseQword !== null && baseQword !== fn ? "  (rewritten since baseline)" : ""}`);
          }
        }
      }
      if (!convicted) {
        w("all wired MajorFunction slots resolve inside their owning image", "good");
        if (kernel.onDispatchHealed && !kernel.dispatchHealedSeen) {
          kernel.dispatchHealedSeen = true;
          kernel.onDispatchHealed();
        }
        return;
      }
      w(`${convicted} foreign dispatch handler(s) — classic IRP-hook signature`, "warn");
    },

    async "!ioctltest"(args, w) {
      if (!args[0]) {
        return w("usage: !ioctltest <driver> [ioctl-hex]   e.g. !ioctltest kfser 0x222000", "err");
      }
      const target = unquote(args[0]);
      let rec = null;
      const va = parseAddr(target);
      if (va !== null) rec = (kernel.driverObjects ?? new Map()).get(va);
      if (!rec) {
        rec = [...(kernel.driverObjects ?? new Map()).values()]
          .find((r) => r.name.toLowerCase() === target.toLowerCase().replace(/\.sys$/, "")
            || `${r.name}`.toLowerCase() === target.toLowerCase());
      }
      if (!rec) return w(`!ioctltest: no DRIVER_OBJECT for '${target}'`, "err");
      const dev = rec.deviceList?.[0];
      if (!dev) return w(`!ioctltest: ${rec.name} has no DEVICE_OBJECT to target`, "err");

      let ioctl = 0x222000n;
      if (args[1]) {
        const p = parseAddr(args[1]);
        if (p === null) return w(`!ioctltest: bad ioctl '${args[1]}'`, "err");
        ioctl = p;
      }
      let r;
      try {
        r = await sendIrp(kernel, dev, {
          major: IRP_MJ.DEVICE_CONTROL,
          ioctl,
          outputLen: 8,
        });
      } catch (e) {
        return w(`!ioctltest: ${e.message}`, "err");
      }
      if (r.status !== "ok") {
        return w(`!ioctltest: dispatch faulted (${r.status}${r.error ? `: ${r.error.message}` : ""})`, "err");
      }
      const handler = mem.u64(rec.va + BigInt(DRIVER_OBJECT.MAJOR_FUNCTION) +
        BigInt(IRP_MJ.DEVICE_CONTROL * 8));
      w(`IOCTL 0x${ioctl.toString(16)} -> ${rec.name}!MajorFunction[DEVICE_CONTROL] @ ${fmtAddr(handler)}`,
        "hdr");
      w(`  IoStatus.Status      : 0x${r.ntstatus.toString(16).padStart(8, "0")} (${statusName(r.ntstatus)})`);
      w(`  IoStatus.Information : 0x${r.information.toString(16)}`);
      if (r.ntstatus === 0xdead0001n || r.ntstatus === 0xdead0003n) {
        w("  completion does NOT match this driver's honest contract", "warn");
        if (kernel.onIrpHijacked && !kernel.irpHijackSeen) {
          kernel.irpHijackSeen = true;
          kernel.onIrpHijacked(r.ntstatus);
        }
      }
      if (rec.majorBaseline) {
        const o = IRP_MJ.DEVICE_CONTROL * 8;
        let baseQword = 0n;
        for (let i = 7; i >= 0; i--) baseQword = (baseQword << 8n) | BigInt(rec.majorBaseline[o + i]);
        if (handler === baseQword && r.ntstatus !== 0xdead0001n && r.ntstatus !== 0xdead0003n) {
          w("  slot matches load-time baseline — honest completion", "good");
          if (kernel.onIoctlHealed && !kernel.ioctlHealedSeen) {
            kernel.ioctlHealedSeen = true;
            kernel.onIoctlHealed();
          }
        }
      }
    },
    "!objtype"(args, w) {
      if (!kernel.objectTypes?.length) {
        return w("!objtype: no OBJECT_TYPEs registered in this world", "err");
      }
      const want = args[0] ? args[0].toLowerCase() : null;
      const hooks = kernel.scanObjectTypeHooks?.() ?? [];
      w("OBJECT_TYPE_INITIALIZER attestation:", "hdr");
      let convicted = 0;
      for (const t of kernel.objectTypes) {
        if (want && t.name.toLowerCase() !== want) continue;
        w(`  ${t.name}  ${fmtAddr(t.va)}`, "hdr");
        for (const p of OBJ_PROCEDURES) {
          const procVa = objProcVa(t.va, p);
          const cur = mem.u64(procVa);
          const base = t.baseline.get(p) ?? 0n;
          if (cur === 0n && base === 0n) continue; // unset and never set
          const bad = hooks.find((h) => h.typeRec === t && h.procName === p);
          if (bad) {
            convicted++;
            const ownerTxt = cur === base ? "" :
              `  HOOKED -> ${fmtAddr(cur)}${bad.owner ? ` (${bad.owner})` : " (unbacked)"}`;
            w(`    OpenProcedure-style ${p.padEnd(20)} ${cur === 0n ? "(none)" : fmtAddr(cur)}${ownerTxt}`, "err");
            const le = [...new Uint8Array(new BigUint64Array([base]).buffer)]
              .map((b) => b.toString(16).padStart(2, "0")).join(" ");
            w(`        repair: eb ${fmtAddr(procVa)} ${le}`, "dim");
          } else {
            w(`    ${p.padEnd(24)} ${cur === 0n ? "(none)" : fmtAddr(cur)}`);
          }
        }
      }
      if (!convicted && hooks.filter((h) => !want || h.typeRec.name.toLowerCase() === want).length === 0) {
        w("all initializer procedures match their baselines", "good");
        if (kernel.onObTypeHealed && !kernel.obTypeHealedSeen) {
          kernel.obTypeHealedSeen = true;
          kernel.onObTypeHealed();
        }
      }
    },

    "!obopen"(args, w) {
      if (!args[0]) {
        return w("usage: !obopen <object-name> [access-hex]   e.g. !obopen kftarget.exe 0x143a", "err");
      }
      const name = args[0];
      const access = parseAddr(args[1] ?? "0x143a") ?? 0x143an;
      const typeRec = (kernel.objectTypes ?? []).find((t) => t.name === "Process")
        ?? (kernel.objectTypes ?? [])[0];
      if (!typeRec) return w("!obopen: no Process object type modeled", "err");
      const usName = kernel.allocPool(16);
      const bufName = kernel.allocPool((name.length + 1) * 2);
      mem.w16(usName, name.length * 2);
      mem.w16(usName + 2n, (name.length + 1) * 2);
      mem.w64(usName + 8n, bufName);
      mem.writeUtf16(bufName, name);
      const openProc = mem.u64(objProcVa(typeRec.va, "OpenProcedure"));
      if (!openProc) {
        w(`ObOpen by name "${name}" (access 0x${access.toString(16)}):`, "hdr");
        w(`  ${typeRec.name}.OpenProcedure not registered — default grant path`, "dim");
        w(`  -> handle granted (modeled)`);
        return;
      }
      w(`ObOpen by name "${name}" (access 0x${access.toString(16)}):`, "hdr");
      w(`  dispatching ${typeRec.name}.OpenProcedure @ ${fmtAddr(openProc)}`);
      let r;
      try {
        r = kernel.cpu.callFunction(openProc, [usName, access]);
      } catch (e) {
        return w(`  OpenProcedure faulted: ${e.message}`, "err");
      }
      const status = BigInt.asUintN(32, BigInt(r.retval ?? 0n));
      w(`  -> 0x${status.toString(16).padStart(8, "0")} (${statusName(status)})`,
        status === 0n ? "good" : "warn");
    },

    // ------------------------------------------------------- m26 ETW labs

    "!etwloggers"(args, w) {
      if (!kernel.etwLoggers?.length) {
        return w("!etwloggers: no kernel logger contexts modeled in this world", "err");
      }
      const tampered = kernel.scanEtwTamper?.() ?? [];
      w("kernel logger contexts (_WMI_LOGGER_CONTEXT):", "hdr");
      for (const l of kernel.etwLoggers) {
        const flags = kernel.loggerFlags(l);
        const id = mem.u32(l.va);
        const clock = mem.u32(l.va + 0x14n);
        const bad = flags === 0 ? "BLINDED" : (flags !== l.baseline.flags ? "TAMPERED" : null);
        w(`  ${l.name}  ${fmtAddr(l.va)}  id=${id} EnableFlags=0x${flags.toString(16).padStart(8, "0")} GetCpuClock=${clock}` +
          (bad ? `  [${bad}]` : ""), bad ? "err" : "");
        if (!bad) continue;
        const le = [...new Uint8Array(new Uint32Array([l.baseline.flags]).buffer)]
          .map((b) => b.toString(16).padStart(2, "0")).join(" ");
        w(`      repair: eb ${fmtAddr(l.va + 0x10n)} ${le}`, "dim");
      }
      if (!tampered.length) {
        w("all logger contexts match their boot baselines", "good");
        if (kernel.onEtwHealed && !kernel.etwHealedSeen) {
          kernel.etwHealedSeen = true;
          kernel.onEtwHealed();
        }
      }
    },

    async "!etwpump"(args, w) {
      const n = Number.parseInt(args[0] ?? "", 10);
      if (!Number.isFinite(n) || n <= 0 || n > 64) {
        return w("usage: !etwpump <n>   (emit 1-64 modeled kernel events)", "err");
      }
      if (!kernel.pumpKernelEvents) {
        return w("!etwpump: no ETW model in this world", "err");
      }
      const r = kernel.pumpKernelEvents(n);
      w(`CKCL emission of ${n} event(s):`, "hdr");
      w(`  delivered : ${r.delivered}`);
      w(`  suppressed: ${r.suppressed}`, r.suppressed > 0 ? "warn" : "");
      if (r.suppressed > 0) {
        w("  events died silently — providers still report success", "warn");
        if (kernel.onEtwBlind && !kernel.etwBlindSeen) {
          kernel.etwBlindSeen = true;
          kernel.onEtwBlind(r.suppressed);
        }
      } else if (kernel.etwBlindSeen && kernel.onEtwHealed && !kernel.etwPumpHealedSeen) {
        kernel.etwPumpHealedSeen = true;
        kernel.onEtwHealed();
      }
    },

    // ------------------------------------------------- m25 architectural labs

    "!msr"(args, w) {
      if (!kernel.msrFile) return w("!msr: no MSR model in this world", "err");
      if (!args[0]) {
        w("MSR register file:", "hdr");
        for (const [addr, base] of kernel.msrBaseline) {
          const nm = MSR_NAMES["0x" + addr.toString(16)] ?? `MSR_0x${addr.toString(16)}`;
          const cur = kernel.rdmsr(addr);
          const drifted = cur !== base;
          w(`  ${nm.padEnd(20)} 0x${addr.toString(16)}  live=0x${cur.toString(16).padStart(16, "0")}` +
            (drifted ? `  DRIFTED (baseline 0x${base.toString(16)})` : ""), drifted ? "err" : "");
        }
        w("write: !msr lstar <addr>   read: !msr lstar", "dim");
        return;
      }
      const key = args[0].toLowerCase()
        .replace(/^ia32_/, "")
        .replace(/^msr_/, "");
      const ADDR = key === "lstar" ? 0xC0000082n
        : key === "sysentereip" ? 0x176n
        : key === "efer" ? 0xC0000081n
        : parseAddr(key.replace(/^0x/, ""));
      if (ADDR === null || ADDR === undefined) return w(`!msr: unknown msr '${args[0]}'`, "err");
      if (!args[1]) {
        const v = kernel.rdmsr(ADDR);
        const base = kernel.msrBaseline.get(BigInt.asUintN(64, ADDR));
        w(`msr 0x${ADDR.toString(16)} = 0x${v.toString(16).padStart(16, "0")}` +
          (base !== undefined && base !== v ? `  [DRIFTED from 0x${base.toString(16)}]` : ""),
          base !== undefined && base !== v ? "err" : "");
        return;
      }
      const val = parseAddr(args[1]);
      if (val === null) return w(`!msr: bad value '${args[1]}'`, "err");
      try {
        kernel.wrmsr(ADDR, val);
        w(`wrmsr 0x${ADDR.toString(16)} <- 0x${val.toString(16)}`, "warn");
        if (!kernel.hvciMode && kernel.wrmsrSeenHook === undefined) kernel.wrmsrSeenHook = true;
      } catch (e) {
        w(`!msr: ${e.message}`, "err");
      }
    },

    "!idt"(args, w) {
      if (!kernel.archBases) return w("!idt: no IDT model in this world", "err");
      const { idtBase, idtBaseline } = kernel.archBases;
      const want = args[0] ? Number.parseInt(args[0], 10) : null;
      w(`IDT @ ${fmtAddr(idtBase)} (${IDT_VECTOR_COUNT} modeled vectors):`, "hdr");
      for (let i = 0; i < IDT_VECTOR_COUNT; i++) {
        if (want !== null && !Number.isNaN(want) && i !== want) continue;
        const cur = mem.u64(idtBase + BigInt(i * 8));
        const drift = cur !== idtBaseline[i];
        if (want === null && !drift && i % 8 !== 0) continue; // compact view
        w(`  [${i.toString().padStart(2, "0")}] ${fmtAddr(cur)}` +
          (drift ? "  REWRITTEN" : ""), drift ? "err" : "dim");
      }
      const hits = (kernel.scanArchTamper?.() ?? []).filter((h) => h.kind === "idt");
      w(hits.length ? `${hits.length} rewritten vector(s)` : "all vectors match baseline",
        hits.length ? "warn" : "good");
    },

    "!gdt"(args, w) {
      if (!kernel.archBases) return w("!gdt: no GDT model in this world", "err");
      const { gdtBase, gdtBaseline } = kernel.archBases;
      w(`GDT @ ${fmtAddr(gdtBase)}:`, "hdr");
      for (let i = 0; i < GDT_ENTRY_COUNT; i++) {
        const cur = mem.u64(gdtBase + BigInt(i * 8));
        const drift = cur !== gdtBaseline[i];
        w(`  [${i}] 0x${cur.toString(16).padStart(16, "0")}` +
          (drift ? "  REWRITTEN" : ""), drift ? "err" : "dim");
      }
    },

    "!syscalltest"(args, w) {
      const num = parseAddr(args[0] ?? "0x29") ?? 0x29n;
      if (!kernel.probeSyscall) return w("!syscalltest: no syscall model in this world", "err");
      const r = kernel.probeSyscall(num);
      const target = kernel.rdmsr(0xC0000082n);
      w(`syscall 0x${num.toString(16)} via IA32_LSTAR -> 0x${target.toString(16)}:`, "hdr");
      if (r.honest) {
        w("  KiSystemCallHandler dispatch — honest completion", "good");
        if (kernel.onArchHealed && !kernel.archHealedSeen) {
          kernel.archHealedSeen = true;
          kernel.onArchHealed();
        }
        return;
      }
      w(`  status 0x${r.status.toString(16).padStart(8, "0")} — FOREIGN handler executed`, "err");
      if (kernel.onArchHijack && !kernel.archHijackSeen) {
        kernel.archHijackSeen = true;
        kernel.onArchHijack(r.status);
      }
    },

    db(args, w) {
      const { exprText, lenTok } = splitAddrLen(args, "128");
      if (!exprText) return w("usage: db <addr> [n|Ln]", "err");
      const addr = tryEvalAddr(exprText);
      if (addr === null) return w(`db: cannot resolve "${exprText}"`, "err");
      let len;
      try { len = parseLen(lenTok); } catch { return w("db: bad length (try: db <addr> L40)", "err"); }
      len = Math.min(len, 512);
      if (addr !== 0n) {
        const why = memFault(addr, len);
        if (why) return w(memErr(addr, why), "err");
      }
      const bytes = mem.read(addr, len);
      for (let row = 0; row < len; row += 16) {
        const chunk = [...bytes.slice(row, row + 16)];
        const hex = chunk.map((b) => b.toString(16).padStart(2, "0")).join(" ");
        const ascii = chunk.map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : ".")).join("");
        w(`${fmtAddr(addr + BigInt(row))}  ${hex.padEnd(47)}  |${ascii}|`);
      }
    },

    dq(args, w) {
      const { exprText, lenTok } = splitAddrLen(args, "8");
      if (!exprText) return w("usage: dq <addr> [n|Ln]", "err");
      const addr = tryEvalAddr(exprText);
      if (addr === null) return w(`dq: cannot resolve "${exprText}"`, "err");
      let count;
      try { count = parseLen(lenTok); } catch { return w("dq: bad count (try: dq <addr> L8)", "err"); }
      count = Math.min(count, 64);
      if (addr !== 0n) {
        const why = memFault(addr, count * 8);
        if (why) return w(memErr(addr, why), "err");
      }
      for (let i = 0; i < count; i++) {
        w(`${fmtAddr(addr + BigInt(i * 8))}  ${fmtAddr(mem.u64(addr + BigInt(i * 8)))}`);
      }
    },

    // WinDbg-style byte write into MAPPED memory only — we never materialize
    // new pages on write so typos can't fabricate phantom backing.
    eb(args, w) {
      if (args.length < 2) return w("usage: eb <addr> <byte> [bytes...]", "err");
      let addr = tryEvalAddr(args[0]);
      if (addr === null) {
        try { addr = BigInt(args[0]); } catch { return w(`eb: cannot resolve "${args[0]}"`, "err"); }
      }
      if (addr < 0n) addr = BigInt.asUintN(64, addr);
      const vals = [];
      for (const tok of args.slice(1)) {
        const v = parseInt(tok, 16);
        if (!(v >= 0 && v <= 255)) return w(`eb: bad byte "${tok}"`, "err");
        vals.push(v);
      }
      const why = memFault(addr, vals.length);
      if (why) return w(memErr(addr, why), "err");
      mem.write(addr, vals);
      w(`wrote ${vals.length} byte(s) at ${fmtAddr(addr)}: ` +
        vals.map((v) => v.toString(16).padStart(2, "0")).join(" "), "dim");
    },

    "!irql"(args, w) {
      if (args[0] === "-a" || args[0] === "/a") {
        const n = (kernel.cpuIrqls?.length ?? 0) + 1;
        w("IRQL per logical core:", "hdr");
        for (let i = 0; i < n; i++) {
          const lvl = kernel.cpuIrql(i);
          const tag = i === 0 ? "" : (lvl >= 2 ? "  <- pinned (watchdog bait)" : "");
          w(`  core ${i}: ${lvl} (${irqlName(lvl)})${tag}`, lvl >= 2 && i !== 0 ? "warn" : "");
        }
        return;
      }
      if (!args[0]) {
        const lvl = kernel.currentIrql ?? 0;
        w(`IRQL: ${lvl} (${irqlName(lvl)})`, "hdr");
        if (lvl > 2) {
          w("  note: threads should never SIT here — drivers raise transiently", "warn");
        }
        w("  lab extension: '!irql <n>' forces a level; '!irql -a' shows all cores", "dim");
        return;
      }
      const n = Number(args[0]);
      if (!Number.isInteger(n) || n < 0 || n > 31) {
        return w("!irql: level must be an integer 0..31", "err");
      }
      const old = kernel.currentIrql ?? 0;
      kernel.currentIrql = n; // debugger force, not driver semantics
      kernel.dbgLog.push(`nt: (lab) IRQL forced ${old} -> ${n}`);
      w(`IRQL: ${old} -> ${n} (${irqlName(n)})`);
    },

    "!dpcs"(args, w) {
      const q = kernel.pendingDpcs ?? [];
      if (!q.length) return w("!dpcs: DPC queue is empty", "dim");
      w("DPC queue (per-CPU, drained at <= DISPATCH_LEVEL)", "hdr");
      w("  DPC               DeferredRoutine     Target  Status", "hdr");
      for (const d of q) {
        // LIVE read of KDPC.DeferredRoutine (+0x18) every invocation, resolved
        // against the current lm table — a patched slot shows the patch, not
        // the insert-time snapshot (issue #16)
        const live = kernel.liveDpcRoutine(d) ?? 0n;
        const drift = live !== d.routine ? "  (patched)" : "";
        const target = live ? `${fmtAddr(live)}${sym(live) ? ` (${sym(live)})` : ""}${drift}` : "NULL";
        const cpu = (d.targetCpu ?? 0) > 0 ? `cpu${d.targetCpu}` : "  -  ";
        w(`  ${fmtAddr(d.dpcVa)}  ${target}  ${cpu}   ${d.drained ? "drained" : "QUEUED"}`,
          d.drained ? "dim" : "");
      }
      const stuck = q.filter((d) => !d.drained).length;
      if (stuck && (kernel.currentIrql ?? 0) > 2) {
        w(`  ${stuck} DPC(s) stranded: CPU pinned above DISPATCH_LEVEL`, "warn");
      }
    },

    "!dpcdrain"(args, w) {
      const queued = (kernel.pendingDpcs ?? []).filter((d) => !d.drained);
      if (!queued.length) return w("!dpcdrain: nothing queued", "dim");
      if ((kernel.currentIrql ?? 0) > 2) {
        w(`!dpcdrain: cannot request a DPC interrupt at IRQL ${kernel.currentIrql}`, "err");
        w("hint: lower the level first ('!irql 2')", "dim");
        return;
      }
      // retire + execute (KiRetireDpcList runs each DeferredRoutine)
      const fired = kernel.retireQueuedDpcs();
      w(`drained ${fired} DPC(s):`, "hdr");
      for (const d of queued) {
        const live = kernel.liveDpcRoutine(d);
        const tag = live !== d.routine ? " (patched!)" : "";
        w(`  ${fmtAddr(d.dpcVa)} -> ${sym(live) ?? fmtAddr(live)}${tag}`);
      }
      const tail = (kernel.dbgLog ?? []).slice(-3);
      if (tail.length) { w("--- recent DbgPrint ---", "hdr"); for (const l of tail) w("  " + l); }
    },

    "!dbgprint"(args, w) {
      if (!kernel.dbgLog?.length) return w("!dbgprint: no debug output buffered", "dim");
      for (const l of kernel.dbgLog) w(l);

    },

    "!dpcpump"(args, w) {
      if (kernel.cpu?.halted) return w("!dpcpump: CPU is halted (post-bugcheck)", "err");
      const n = Number(args[0] ?? "1");
      if (!Number.isInteger(n) || n < 1 || n > 100000) {
        return w("!dpcpump: ticks must be an integer 1..100000", "err");
      }
      const r = kernel.advanceTicks(n);
      w(`clock +${r.ticks} tick(s) -> tick ${kernel.tickCount}`, "hdr");
      if (r.firedTimers) w(`  expired ${r.firedTimers} timer(s)`);
      if (r.retired) w(`  retired ${r.retired} queued DPC(s)`);
      else if ((kernel.currentIrql ?? 2) > 2) {
        w("  retired nothing: core pinned above DISPATCH_LEVEL", "warn");
      }
    },

    "!dpcstat"(args, w) {
      const now = kernel.tickCount ?? 0n;
      const q = kernel.pendingDpcs ?? [];
      const pending = q.filter((d) => !d.drained);
      w("DPC / timer telemetry (ETW EVENT_TRACE_FLAG_DPC analog)", "hdr");
      w(`  queue depth: ${q.length} total, ${pending.length} pending`);
      for (const d of pending.slice(0, 12)) {
        const age = now - (d.enqueuedAt ?? now);
        const where = (d.targetCpu ?? 0) > 0 ? ` directed@cpu${d.targetCpu}` : "";
        w(`    ${fmtAddr(d.dpcVa)} age=${age} tick(s)${where}`,
          age > 10n ? "warn" : "");
      }
      const timers = kernel.pendingTimers ?? [];
      w(`  timers: ${timers.length} armed`);
      for (const t of timers.slice(0, 8)) {
        const dueIn = t.dueTick - now;
        const bound = t.dpcVa ? fmtAddr(t.dpcVa) : "none";
        const live = t.dpcVa ? kernel.liveDpcRoutine({ dpcVa: t.dpcVa, routine: 0n }) : 0n;
        const mod = live ? sym(live) : null;
        const foreign = live && !mod ? "  <- routine outside known modules" : "";
        w(`    timer ${fmtAddr(t.timerVa)} due=+${dueIn > 0n ? dueIn : 0n} period=${t.period} dpc=${bound}${foreign}`,
          foreign ? "warn" : "");
      }
      const aged = pending.filter((d) => now - (d.enqueuedAt ?? now) > 10n).length;
      if (aged) w(`  anomaly: ${aged} DPC(s) older than 10 ticks (starvation signature)`, "err");
      w("  pump the clock with '!dpcpump <ticks>'", "dim");
    },

    "!dpcwatchdog"(args, w) {
      w("DPC watchdog check (KiProcessExpiredTimerList analog)", "hdr");
      const verdict = kernel.checkDpcWatchdog();
      if (verdict.ok) {
        w("  no core pinned at/above DISPATCH_LEVEL — within budget", "good");
        return;
      }
      for (const p of verdict.pinned) {
        w(`  core ${p.cpu}: IRQL ${p.irql} (${irqlName(p.irql)}) — residency over budget`, "err");
      }
      if (!verdict.pinned.length) {
        w(`  executing core at IRQL ${kernel.currentIrql} — above-DISPATCH residency`, "err");
      }
      w(`  BUGCHECK 0x133 DPC_WATCHDOG_VIOLATION raised (P1=${verdict.bugcheckLevel ?? kernel.bugcheck?.params?.[0]})`, "err");
    },

    "!pgscan"(args, w) {
      w("integrity scan (PatchGuard/HVCI analog)", "hdr");
      w(`  CR0: 0x${(kernel.cr0 ?? 0n).toString(16)} (WP=${(((kernel.cr0 ?? 0n) >> 16n) & 1n).toString()})` +
        `  HVCI: ${kernel.hvciMode ? "enforced" : "off"}`);
      const traces = kernel.cr0Trace ?? [];
      if (traces.length) {
        const wpClears = traces.filter((t) => ((t.old >> 16n) & 1n) === 1n && ((t.new >> 16n) & 1n) === 0n);
        if (wpClears.length) w(`  CR0.WP was cleared ${wpClears.length} time(s) this boot — write-protect tampering`, "warn");
      }
      if (kernel.msrFile) {
        const arch = kernel.scanArchTamper();
        for (const h of arch.slice(0, 4)) {
          const label = h.kind === "msr"
            ? `${h.name} DRIFT baseline=0x${h.baseline.toString(16)} live=0x${h.current.toString(16)}`
            : `${h.name} rewritten -> 0x${h.current.toString(16)}${h.foreign ? " (FOREIGN)" : ""}`;
          w(`  [arch] ${label}`, "err");
        }
        if (!arch.length) w("  MSR/IDT/GDT: all values match boot baselines", "good");
      }
      const diffs = kernel.scanProtectedRanges?.() ?? [];
      if (!diffs.length) w("  protected ranges: clean");
      for (const d of diffs) {
        w(`  MODIFIED ${d.name} @ ${fmtAddr(d.base)}+0x${d.firstDelta.toString(16)} ` +
          `(${d.count} byte(s), pristine 0x${d.pristineByte.toString(16)} -> live 0x${d.liveByte.toString(16)})`, "err");
      }
      // foreign DeferredRoutine sweep: a queued/timer-bound routine pointing
      // outside every loaded module is a hijack signature — and so is ANY
      // drift between the insert-time snapshot and live memory
      let foreign = 0;
      const inModule = (va) => (kernel.loadedModules ?? []).some((m) =>
        va >= m.base && va < m.base + BigInt(m.sizeOfImage ?? 0x8000));
      for (const d of (kernel.pendingDpcs ?? [])) {
        const live = kernel.liveDpcRoutine(d);
        if (!live) continue;
        if (!inModule(live)) {
          foreign++;
          w(`  HIJACK? DPC ${fmtAddr(d.dpcVa)} DeferredRoutine -> ${fmtAddr(live)} outside all modules` +
            (d.drained ? " (already drained)" : ""), "err");
        } else if (d.routine && live !== d.routine) {
          foreign++;
          w(`  HIJACK? DPC ${fmtAddr(d.dpcVa)} DeferredRoutine rewritten ` +
            `insert-time ${fmtAddr(d.routine)} -> now ${fmtAddr(live)} (${sym(live)})` +
            (d.drained ? " (already drained)" : ""), "err");
        }
      }
      for (const t of (kernel.pendingTimers ?? [])) {
        if (!t.dpcVa) continue;
        const probe = { dpcVa: t.dpcVa, routine: 0n };
        const live = kernel.liveDpcRoutine(probe);
        if (live && !inModule(live)) {
          foreign++;
          w(`  HIJACK? timer ${fmtAddr(t.timerVa)} bound DPC routine -> ${fmtAddr(live)} outside all modules`, "err");
        }
      }
      if (!foreign) w("  deferred routines: all inside loaded modules", "good");
      if (kernel.hvciMode && diffs.length) {
        w("  HVCI policy: CRITICAL_STRUCTURE_CORRUPTION (0x109) would have fired at write time", "dim");
      }
    },

    "!eptlist"(args, w) {
      const sh = kernel.eptShadow ?? [];
      if (!sh.length) return w("!eptlist: no EPT shadow entries in this world", "err");
      w("EPT shadow entries (host view differs from guest view)", "hdr");
      for (const e of sh) {
        w(`  ${e.name.padEnd(30)} ${fmtAddr(e.va)}  +0x${e.len.toString(16)} bytes  reads=${e.reads}`);
      }
    },

    "!eptview"(args, w) {
      const va = args[0] ? tryEvalAddr(args[0]) : null;
      if (va === null || va === undefined) {
        return w("usage: !eptview <va>   host(EPT) view of a shadowed range", "err");
      }
      const hits = kernel.eptShadowAt?.(va, 16) ?? [];
      if (!hits.length) return w(`!eptview: ${fmtAddr(va)} is not shadowed — host view == guest view`);
      for (const e of hits) {
        e.reads++; // A/D-bit analog: every host-view read is observable timing
        const off = Number(va - e.va);
        const start = Math.max(0, off);
        const host = [...e.hostBytes.slice(start, start + 8)];
        const guest = [...mem.read(e.va + BigInt(start), 8)];
        w(`${e.name} @ ${fmtAddr(e.va)} (+0x${start.toString(16)})`, "hdr");
        w(`  host  (physical/EPT): ${hexBytes(host)}`);
        w(`  guest (kernel view) : ${hexBytes(guest)}`);
        w(host.some((b, i) => b !== guest[i])
          ? "  MISMATCH — the two translations disagree (EPT hook present)"
          : "  views agree", "warn");
      }
    },

    "!eptverify"(args, w) {
      const sh = kernel.eptShadow ?? [];
      if (!sh.length) return w("!eptverify: no EPT shadow entries in this world", "err");
      let mismatches = 0;
      for (const e of sh) {
        e.reads++;
        const guest = mem.read(e.va, e.len);
        if (guest.some((b, i) => b !== e.hostBytes[i])) mismatches++;
      }
      w(`EPT verify: ${mismatches}/${sh.length} shadowed ranges disagree`, mismatches ? "warn" : "good");
      if (mismatches) {
        w("A hypervisor is splitting fetches from reads below the kernel.");
        w("secret=kf-ept-detected");
      }
    },

    "!vmexit"(args, w) {
      const log = kernel.vmExitLog ?? [];
      if (!log.length) return w("!vmexit: no VM-exit traps recorded", "err");
      w(`VM-exit log (${log.length} traps):`, "hdr");
      for (const [i, e] of log.entries()) {
        const msrName = MSR_NAMES["0x" + e.msr.toString(16)] ?? `MSR_0x${e.msr.toString(16)}`;
        if (e.kind === "wrmsr") {
          w(`  [${i}] WRMSR ${msrName} @ tick ${e.tick}: guest 0x${e.guestValue.toString(16)} -> host 0x${e.hostValue.toString(16)}`);
        } else {
          w(`  [${i}] RDMSR ${msrName} @ tick ${e.tick}: host 0x${e.hostValue.toString(16)} -> guest 0x${e.guestValue.toString(16)}`);
        }
      }
      w("The hypervisor owns these MSRs below the kernel.");
      w("secret=kf-vmexit-detected");
    },

    "!openprocess"(args, w) {
      // modeled userland OpenProcess through the same ZwOpenProcess impl the
      // compiler labs use — PPL enforced, handle minted, telemetry printed.
      if (!args[0]) return w("usage: !openprocess <pid> [access-hex]", "err");
      const open = kernel.apiImpls.get("ZwOpenProcess");
      if (!open) return w("!openprocess: ZwOpenProcess not modeled here", "err");
      const pid = /^\d+$/.test(args[0]) ? BigInt(args[0]) : null;
      if (pid === null) return w("!openprocess: pid must be decimal", "err");
      let access = 0x143an;
      if (args[1]) {
        const a = args[1].replace(/\`/g, "");
        access = BigInt(/^0x/i.test(a) ? a : "0x" + (/^[0-9a-fA-F]+$/.test(a) ? a : a));
      }
      const cidBuf = kernel.allocPool(16);
      mem.w64(cidBuf, pid);
      const hOut = kernel.allocPool(8);
      const st = BigInt.asUintN(32, BigInt(open(hOut, access, 0n, cidBuf)));
      const status = statusName(st) || `0x${st.toString(16)}`;
      if (st === 0n) {
        const h = mem.u64(hOut);
        w(`ZwOpenProcess(${pid}, 0x${access.toString(16)}) -> STATUS_SUCCESS  handle 0x${h.toString(16)}`, "good");
        // m23 PPL lab payoff: an open that succeeds against lsass while its
        // Protection byte is ZERO means the student's DKOM landed
        const target = kernel.findEprocessByPid(pid);
        try {
          const protOff = tables.offsetOf("_EPROCESS", "Protection");
          const nmOff = tables.offsetOf("_EPROCESS", "ImageFileName");
          const name = mem.readAnsi(target + nmOff, 15);
          if (name.startsWith("lsass") && mem.u8(target + protOff) === 0 && !kernel.pplSecretShown) {
            kernel.pplSecretShown = true;
            w("secret=kf-ppl-off");
          }
        } catch { /* optional fields */ }
        return;
      }
      w(`ZwOpenProcess(${pid}, 0x${access.toString(16)}) -> ${status}`);
    },

    "!pgstatus"(args, w) {
      const pg = kernel.patchguardStatus?.();
      if (!pg) return w("!pgstatus: mini-PatchGuard not armed in this world", "err");
      w("mini-PatchGuard state", "hdr");
      w(`  period: every ${pg.period} tick(s)   sweeps: ${pg.sweeps}` +
        (pg.lastSweepTick !== null ? `   last @ tick ${pg.lastSweepTick}` : "") +
        (pg.nextSweepIn !== null ? `   next in ${pg.nextSweepIn}` : ""));
      w(`  protected regions: ${pg.regions}`);
      for (const r of kernel.protectedRanges ?? []) {
        w(`    ${r.name.padEnd(28)} ${fmtAddr(r.base)} (+0x${r.size.toString(16)} bytes)`);
      }
      if (!pg.clean) {
        w(`  VERDICT: CRITICAL_STRUCTURE_CORRUPTION at tick ${pg.violatedAt} — a protected region changed under the sweeper`, "err");
        return;
      }
      if (kernel.pgHookObserved && pg.sweeps >= 1) {
        w("  verdict: hook window opened and closed between sweeps — never observed", "good");
        w("  secret=kf-pg-evaded");
      } else if (kernel.pgHookObserved) {
        w("  verdict: hook seen, not yet re-validated by a clean sweep", "warn");
        w("  advance the clock with !dpcpump so a sweep confirms the restore", "dim");
      } else {
        w("  verdict: clean — no tamper windows observed this boot");
      }
    },

    "!hookscan"(args, w) {
      // optional filter: tolerate nt!-prefixed export names
      const want = args[0] ? args[0].replace(/^nt!|ntoskrnl\.exe!/i, "") : null;
      const diffs = [];
      for (const [name, thunk] of kernel.apiThunks ?? []) {
        if (want && name.toLowerCase() !== want.toLowerCase()) continue;
        const pristine = kernel.pristineThunks.get(name);
        if (!pristine) continue;
        const live = mem.read(thunk, pristine.length);
        if (live.some((b, i) => b !== pristine[i])) diffs.push({ name, thunk, live, pristine });
      }
      if (!diffs.length) {
        w(want ? `${want}: prologue matches pristine bytes` : "no detoured exports found", "hdr");
        return;
      }
      w("DETECTED INLINE HOOKS:", "hdr");
      for (const d of diffs) {
        const hook = (kernel.inlineHooks ?? []).find((x) => x.api === d.name);
        const target = hook ? `${fmtAddr(hook.target)}${sym(hook.target) ? ` (${sym(hook.target)})` : ""}` : "<unknown>";
        w(`  ${d.name}`, "hdr");
        w(`    thunk   : ${fmtAddr(d.thunk)}`);
        w(`    live    : ${hexBytes(d.live.slice(0, 5))}`);
        w(`    pristine: ${hexBytes(d.pristine.slice(0, 5))}`);
        w(`    detour  : -> ${target}  [${hook?.module ?? "?"}]`, "warn");
        w(`    repair  : eb ${fmtAddr(d.thunk)} ${hexBytes(d.pristine.slice(0, 1))}`, "dim");
      }
    },

    "!hooktest"(args, w) {
      if (!args[0]) {
        return w("usage: !hooktest <Export> [args...]   e.g. !hooktest PsLookupProcessByProcessId 888", "err");
      }
      const name = args[0].replace(/^nt!|ntoskrnl\.exe!/i, "");
      const impl = kernel.apiImpls.get(name);
      const thunk = kernel.apiThunks.get(name);
      if (!impl || !thunk) return w(`!hooktest: unknown export "${name}"`, "err");

      // lookup-style exports: last arg is a PID; provide an out-pointer scratch
      const isLookup = /(ByProcessId|ByThreadId)$/i.test(name);
      let callArgs = args.slice(1);
      let scratch = null;
      if (isLookup) {
        scratch = kernel.allocPool(8);
        callArgs = [...callArgs, scratch];
      }
      try {
        const vals = callArgs.map((t) => /^\d+$/.test(t) ? BigInt(t)
          : t.startsWith("0x") ? BigInt(t) : t);
        if (vals.some((v) => typeof v === "string")) {
          return w("!hooktest: numeric arguments only in this model", "err");
        }
        const ret = impl(...vals);
        const status = BigInt.asUintN(32, BigInt(ret));
        const detoured = kernel.isDetoured(name);
        if (detoured && kernel.patchguard?.armed !== false && kernel.patchguard) {
          // the timing lab's evidence: a hook ran while PatchGuard was armed
          kernel.pgHookObserved = true;
        }
        const hookNote = detoured ? "  [PROLOGUE DETOURED]" : "";
        w(`${name}(${callArgs.map((a) => a.toString()).join(", ")}) -> ${statusName(status)}${hookNote}`,
          status === 0n ? "good" : "");
        if (isLookup && status === 0n && scratch) {
          const resolved = mem.u64(scratch);
          w(`  *out = ${resolved ? fmtAddr(resolved) + (sym(resolved) ? ` (${sym(resolved)})` : "") : "NULL"}`);
        }
      } catch (e) {
        w(`!hooktest: ${e.message}`, "err");
      }
    },

    "!poolfind"(args, w) {
      if (!args[0]) return w("usage: !poolfind <tag>   e.g. !poolfind KfPb", "err");
      const tag = args[0].toLowerCase();
      const blocks = (kernel.poolAllocs ?? []).filter((a) => a.tag.toLowerCase() === tag);
      if (!blocks.length) return w(`!poolfind: no blocks tagged "${args[0]}"`, "dim");
      w(`pool blocks tagged '${args[0]}' (guard lives at user_addr + size, NOT at the block itself):`, "hdr");
      let corrupted = 0;
      const smashed = [];
      for (const b of blocks) {
        let guard = "intact";
        const gaddr = b.addr + BigInt(b.size);
        for (let i = 0; i < 16; i++) {
          const got = mem.u8(gaddr + BigInt(i));
          if (got !== 0xa5) {
            guard = `CORRUPTED at guard[${i}] @ ${fmtAddr(gaddr + BigInt(i))} (got 0x${got.toString(16)}, expected 0xa5)`;
            corrupted++;
            smashed.push({ b, gaddr });
            break;
          }
        }
        w(`  ${fmtAddr(b.addr)}  size=0x${b.size.toString(16)}  ${b.freed ? "freed" : "active"}  guard @ ${fmtAddr(gaddr)}: ${guard}`,
          guard === "intact" ? "" : "warn");
      }
      if (corrupted) {
        for (const { b, gaddr } of smashed) {
          w(`repair this block's guard — copy-paste (writes the full 16-byte A5 trailer at its EXACT address):`,
            "dim");
          w(`eb ${fmtAddr(gaddr)} a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5`);
        }
        w("then confirm with !poolverify", "dim");
      } else {
        w("all guards read A5 patterns", "good");
      }
    },

    "!poolverify"(args, w) {
      const bad = kernel.verifyGuards?.() ?? [];
      if (!bad.length) {
        w("!poolverify: all allocation guards intact", "good");
        kernel.onPoolHealed?.();
        return;
      }
      w(`!poolverify: ${bad.length} corrupted allocation(s):`, "err");
      for (const b of bad) {
        const gaddr = b.addr + BigInt(b.size);
        const got = mem.u8(gaddr);
        w(`  ${fmtAddr(b.addr)} tag='${b.tag}' size=0x${b.size.toString(16)} ` +
          `guard @ ${fmtAddr(gaddr)} guard[0]=0x${got.toString(16)} (expected 0xa5)`, "warn");
        w(`  repair: eb ${fmtAddr(gaddr)} a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5`, "dim");
      }
      w("note: eb writes are live in the same memory !poolverify sweeps — no reload needed", "dim");
    },

    "!funcs"(args, w) {
      // static function recovery over a module extent (ghidra-decompiler)
      if (!args[0]) { w("usage: !funcs <module>", "err"); return; }
      const want = args[0].toLowerCase().replace(/\.sys$/, "");
      const mod = (kernel.loadedModules ?? []).find((m) =>
        m.name.toLowerCase().replace(/\.sys$/, "") === want);
      if (!mod) { w(`module '${args[0]}' not found — try lm`, "err"); return; }
      const size = Number(mod.sizeOfImage ?? 0);
      const res = analyzeExtent(mem, BigInt(mod.base), Math.min(size, 0x10000));
      if (!res.count) {
        w(`${mod.name}: no code pages materialized for analysis`, "dim");
        return;
      }
      w(`${mod.name} — ${res.count} function(s) recovered:`, "hdr");
      for (const f of res.funcs.slice(0, 32)) {
        const rel = res.rel32.find((r) => r.site === f.start);
        w(`  ${fmtAddr(f.start)}${rel ? `  E9 -> ${fmtAddr(rel.target)}` : ""}`);
      }
      if (res.count > 32) w(`  ... ${res.count - 32} more`);
      if (res.rel32.length) {
        w("rel32 transfer sites at boundary edges:", "hdr");
        for (const r of res.rel32) w(`  ${fmtAddr(r.site)} -> ${fmtAddr(r.target)}`, "warn");
      }
    },

    "!decomp"(args, w) {
      // pseudocode via the vendored Ghidra native decompiler; loud degrade.
      // Feed the whole containing module image (capped) so Ghidra sees real
      // context instead of a lone address.
      const addr = args[0] ? parseAddr(args[0]) : null;
      if (addr === null) { w("usage: !decomp <addr>  (static !funcs works without the wasm)", "err"); return; }
      const image = moduleImageAt(addr) ?? { base: addr, size: 4096 };
      const bytes = readForward(mem, image.base, Math.min(image.size, 0x20000));
      if (!bytes.length) {
        w(`!decomp: no readable code at ${fmtAddr(addr)}`, "err");
        return;
      }
      ghidraDecompile(bytes, image.base, addr)
        .then(({ c }) => w(c.split("\n").slice(0, 40).join("\n"), "code"))
        .catch((e) => {
          w(`!decomp: ${e.message}`, "warn");
          const t = resolveRel32(mem, addr);
          if (t !== null) w(`static: ${fmtAddr(addr)} is a rel32 transfer to ${fmtAddr(t)}`, "dim");
        });
    },

    "!mmstate"(args, w) {
      const mm = kernel.manualMap;
      if (!mm) return w("!mmstate: no manual-map loader booted (boot the manual-map lab)", "err");
      w("kfloader.sys manual-mapping state", "hdr");
      w(`  payload image : ${fmtAddr(mm.payloadBase)} (mmpayload.sys)`);
      w(`  loader base   : ${fmtAddr(mm.loaderBase)}`);
      const flag = mem.u8(mm.resolveFlag);
      w(`  g_ResolveImports @ ${fmtAddr(mm.resolveFlag)} = ${flag} ` +
        `(${flag ? "imports will be resolved" : "STUBBED — IAT left unmapped"})`,
        flag ? "" : "warn");
      mm.imports.forEach((imp, i) => {
        const slot = mem.u64(mm.iatBase + BigInt(i * 8));
        w(`  IAT[${i}] ${imp.padEnd(26)} : ${slot ? fmtAddr(slot) : "0000000000000000  (unresolved)"}`);
      });
      w(`  map attempts  : ${mm.runs}`);
    },

    "!mmrun"(args, w) {
      const mm = kernel.manualMap;
      if (!mm) return w("!mmrun: no manual-map loader booted (boot the manual-map lab)", "err");
      mm.runs++;
      if (!mem.u8(mm.resolveFlag)) {
        w("kfloader: mapping mmpayload.sys sections...", "dim");
        w("kfloader: import resolution is STUBBED — IAT left zeroed", "err");
        w("kfloader: payload DriverEntry skipped (first import call would fault)", "err");
        w("hint: inspect !mmstate, repair the loader with 'eb', retry !mmrun", "dim");
        kernel.debugPrint("kfloader: failed to resolve imports for mmpayload.sys");
        return;
      }
      mm.imports.forEach((_, i) => mem.w64(mm.iatBase + BigInt(i * 8), mm.thunks[i]));
      w(`kfloader: resolved ${mm.imports.length} import(s) against nt!`);
      for (const [i, imp] of mm.imports.entries()) {
        w(`  IAT[${i}] ${imp.padEnd(26)} -> ${fmtAddr(mm.thunks[i])}`, "dim");
      }
      w("kfloader: transferring control to mmpayload.sys!DriverEntry...");
      kernel.debugPrint("mmpayload: DriverEntry entered (manually mapped, imports resolved)");
      kernel.debugPrint(`mmpayload: secret=${mm.secret}`);
      w("(payload telemetry streams above; full history: !dbgprint)", "dim");
      if (!kernel.loadedModules.some((m) => m.name === "mmpayload.sys")) {
        kernel.loadedModules.push({
          base: mm.payloadBase, sizeOfImage: 0x4000, name: "mmpayload.sys",
          full: "\\SystemRoot\\system32\\mmpayload.sys",
        });
        kernel.materializeModuleRange(mm.payloadBase, 0x4000);
      }
    },

    "!cr"(args, w) {
      // control registers: Mmu worlds carry the authoritative state; plain
      // worlds keep cr0 on the kernel object (WP tamper labs)
      const mmu = kernel.mmu;
      const cr0 = BigInt(mmu?.cr0 ?? kernel.cr0 ?? 0n);
      const cr3 = mmu ? BigInt(mmu.cr3 ?? 0n) : null;
      const cr4 = mmu ? BigInt(mmu.cr4 ?? 0n) : null;
      const efer = mmu ? BigInt(mmu.efer ?? 0n) : null;
      if (!mmu && kernel.cr0 === undefined) {
        return w("!cr: no control-register state in this world", "err");
      }
      w(`cr0=${fmtAddr(cr0)}  pg=${(cr0 & 0x80000000n) !== 0n ? 1 : 0}` +
        `  wp=${(cr0 & 0x10000n) !== 0n ? 1 : 0}`);
      if (cr3 !== null) w(`cr3=${fmtAddr(cr3)}   (DirectoryTableBase)`);
      if (cr4 !== null) w(`cr4=${fmtAddr(cr4)}  pae=${(cr4 & 0x20n) !== 0n ? 1 : 0}` +
        `  smep=${(cr4 & (1n << 20n)) !== 0n ? 1 : 0}`);
      if (efer !== null) w(`efer=${fmtAddr(efer)}  lma=${(efer & 0x400n) !== 0n ? 1 : 0}`);
      if (!mmu) w("  (non-paged world: only cr0 is modeled)", "dim");
    },

    "!smep"(args, w) {
      // Toggle or query SMEP (Supervisor Mode Execution Prevention)
      // Usage: !smep [0|1]
      const mmu = kernel.mmu;
      if (!mmu) return w("!smep: no paging world (SMEP requires CR4)", "err");
      const SMEP_BIT = 1n << 20n;
      if (args.length === 0) {
        const on = (mmu.cr4 & SMEP_BIT) !== 0n;
        w(`SMEP: ${on ? "enabled" : "disabled"} (CR4 bit 20 = ${on ? 1 : 0})`);
        return;
      }
      const val = parseInt(args[0], 10);
      if (val !== 0 && val !== 1) return w("!smep: usage: !smep [0|1]", "err");
      if (val === 1) mmu.cr4 |= SMEP_BIT;
      else mmu.cr4 &= ~SMEP_BIT;
      w(`SMEP: ${val ? "enabled" : "disabled"} (CR4 = ${fmtAddr(mmu.cr4)})`);
    },

    "!dbgprint"(args, w) {
      const log = kernel.dbgLog ?? [];
      if (!log.length) return w("!dbgprint: no debug output buffered", "dim");
      for (const l of log) w(l);
    },

    "!smram"(args, w) {
      const smm = kernel.smm;
      if (!smm) return w("!smram: no SMM engine attached to this session", "err");
      const cs = smm.chipset;
      w("SMRAM state", "hdr");
      w(`  base=${fmtAddr(BigInt(cs.tsegBase))} end=${fmtAddr(BigInt(cs.tsegEnd))}` +
        ` size=0x${BigInt(cs.tsegSize).toString(16)}`);
      w(`  D_OPEN=${cs.dOpen ? 1 : 0} D_CLS=${cs.dCls ? 1 : 0}` +
        ` D_LCK=${cs.dLck ? 1 : 0} G_SMRAME=${cs.gSmrame ? 1 : 0}`);
      w(`  ring0 visibility: ${cs.isSmramVisibleFromRing0(BigInt(cs.tsegBase) + 0x1000n) ? "OPEN" : "HIDDEN"}`);
      w(`  SMBASE=${fmtAddr(BigInt(smm.currentSmbase))}` +
        ` entry=${fmtAddr(BigInt(smm.currentSmbase) + 0x8000n)}`);
      w(`  SMI: raised=${smm.stats.raised} exited=${smm.stats.exited}` +
        ` relocated=${smm.stats.relocated}${cs.smiPending ? " (PENDING)" : ""}`);
    },

    "!smmc"(args, w) {
      const smm = kernel.smm;
      if (!smm) return w("!smmc: no SMM engine attached to this session", "err");
      const cs = smm.chipset;
      w(`PCI 0:0:0 reg 0x9d (SMRAMC) = 0x${BigInt(cs.smramc).toString(16).padStart(2, "0")}`, "hdr");
      w(`  [3] D_OPEN  = ${cs.dOpen ? 1 : 0}   <- set to peek SMRAM from ring 0`);
      w(`  [2] D_CLS   = ${cs.dCls ? 1 : 0}`);
      w(`  [1] D_LCK   = ${cs.dLck ? 1 : 0}   <- locks D_OPEN/D_CLS until reset`);
      w(`  [0] G_SMRAME= ${cs.gSmrame ? 1 : 0}`);
    },

    "!cr3"(args, w) {
      const pts = pageWorld();
      if (!pts) {
        // guest-paged Mmu world (SMM track): report the live DirectoryTableBase
        // instead of crashing on the missing per-process table space (#25)
        if (kernel.paging && kernel.mmu) {
          const cr3 = BigInt(kernel.cr3 ?? kernel.mmu.cr3 ?? 0n);
          w("guest-paged world — one live CR3, translation via the MMU", "hdr");
          w(`  DirectoryTableBase  : 0x${cr3.toString(16).padStart(16, "0")}` +
            `  (PFN 0x${(cr3 >> 12n).toString(16)})`);
          w(`  self-map PML4 index : n/a (hardware walk; try !pte / !vtop <va>)`);
          return;
        }
        return w("!cr3: no paging world booted (this lab has no page tables)", "err");
      }
      const token = args[0];
      let proc = null;
      if (token) {
        proc = pts.findProcess(token.replace(/\.sys$/, ""));
        if (!proc) return w(`!cr3: no paging record for '${token}'`, "err");
      } else {
        proc = [...pts.processes.values()].find((p) => !p.decoy) ??
          [...pts.processes.values()][0];
        if (!proc) return w("!cr3: paging world is empty", "err");
      }
      w(`process ${proc.name}${proc.pid ? ` (pid ${proc.pid})` : ""}`, "hdr");
      w(`  DirectoryTableBase  : 0x${proc.dtb.toString(16).padStart(16, "0")}` +
        `  (PFN 0x${(proc.dtb >> 12n).toString(16)})`);
      w(`  self-map PML4 index : 0x${proc.selfRefIndex.toString(16)}` +
        `   (alias windows live under PML4 slot; dq/eb them directly)`);
      if (proc.decoy) w("  NOTE: this DTB looks shuffled/decoyed — verify before trusting", "warn");
    },

    "!pte"(args, w) {
      const pts = pageWorld();
      if (!pts) {
        if (kernel.paging && kernel.mmu) {
          const va = args[0] ? parseAddr(args[0]) : null;
          if (va === null) return w("usage: !pte <va> [proc]", "err");
          const pte = kernel.readPte(va);
          if (pte === null || pte === undefined) {
            return w(`!pte: no PTE for ${fmtAddr(va)} (unmapped or demand-filled on access)`, "err");
          }
          const d = decodePte(pte);
          w(`VA ${fmtAddr(va)}  (guest-paged world, DTB 0x${BigInt(kernel.cr3 ?? kernel.mmu.cr3 ?? 0n).toString(16)})`, "hdr");
          w(`         contains ${pte.toString(16).padStart(16, "0")}` +
            `   [${pteBitsString(pte)}]` +
            (d.large ? "  LARGE" : "") + `  pfn 0x${d.pfn.toString(16)}`);
          return;
        }
        return w("!pte: no paging world booted (this lab has no page tables)", "err");
      }
      const va = args[0] ? parseAddr(args[0]) : null;
      if (va === null) return w("usage: !pte <va> [proc]", "err");
      const proc = args[1] ? pts.findProcess(args[1]) :
        [...pts.processes.values()].find((p) => !p.decoy) ?? [...pts.processes.values()][0];
      if (!proc) return w("!pte: paging world is empty", "err");
      const res = pts.translate(va, proc);
      w(`VA ${fmtAddr(va)}  (${proc.name}, DTB 0x${proc.dtb.toString(16)}, ` +
        `split ${res.rows.map(() => "").join("")}9/9/9/9/12)`, "hdr");
      for (const row of res.rows) {
        const d = decodePte(row.value);
        w(`  ${row.label.padEnd(6)} @ phys 0x${row.entryPa.toString(16).padStart(12, "0")}` +
          `  alias ${fmtAddr(row.entryVa)}`);
        w(`         contains ${row.value.toString(16).padStart(16, "0")}` +
          `   [${pteBitsString(row.value)}]` +
          (d.large ? "  LARGE" : "") + `  pfn 0x${d.pfn.toString(16)}`);
      }
      if (!res.ok) {
        w(`  walk FAILS at ${res.failedAt} — page not present at this level`, "err");
        return;
      }
      w(`  => PA ${fmtAddr(res.pa)}  (${res.level} page)`, "good");
    },

    "!vtop"(args, w) {
      const pts = pageWorld();
      if (!pts) {
        if (kernel.paging && kernel.mmu) {
          const va = args[0] ? parseAddr(args[0]) : null;
          if (va === null) return w("usage: !vtop <va> [proc]", "err");
          const pa = kernel.vtop(va);
          if (pa === null || pa === undefined) {
            return w(`!vtop: ${fmtAddr(va)} -> not mapped (PTE not present in the live CR3)`, "err");
          }
          w(`!vtop: ${fmtAddr(va)} -> ${fmtAddr(pa)}  (guest-paged world, live CR3)`, "good");
          return;
        }
        return w("!vtop: no paging world booted (this lab has no page tables)", "err");
      }
      const va = args[0] ? parseAddr(args[0]) : null;
      if (va === null) return w("usage: !vtop <va> [proc]", "err");
      const proc = args[1] ? pts.findProcess(args[1]) :
        [...pts.processes.values()].find((p) => !p.decoy) ?? [...pts.processes.values()][0];
      if (!proc) return w("!vtop: paging world is empty", "err");
      const res = pts.translate(va, proc);
      if (!res.ok) {
        w(`!vtop: ${fmtAddr(va)} -> not mapped (${res.failedAt} not present for ${proc.name})`, "err");
        return;
      }
      w(`!vtop: ${fmtAddr(va)} -> ${fmtAddr(res.pa)}  (${res.level}, ${proc.name})`, "good");
      kernel.onVtopProbe?.(va, res);
    },

    "!notifyroutines"(args, w) {
      const nr = kernel.notifyRoutines;
      if (!nr) return w("!notifyroutines: kernel has no notify registry", "err");
      const groups = [
        ["process-creation", nr.process],
        ["thread-creation", nr.thread],
        ["image-load", nr.image],
        ["object (ObRegisterCallbacks)", kernel.obCallbacks ?? []],
        ["registry (CmRegisterCallback)", kernel.cmCallbacks ?? []],
      ];
      let any = false;
      for (const [label, arr] of groups) {
        if (!arr?.length) continue;
        any = true;
        w(`${label}:`, "hdr");
        for (const cb of arr) {
          const va = typeof cb === "bigint" ? cb : BigInt(cb?.callback ?? cb?.preOperation ?? 0);
          const mod = sym(va);
          const extra = typeof cb === "object" && cb.altitude ? ` altitude=${cb.altitude}` : "";
          w(`  ${fmtAddr(va)}${mod ? `  (${mod})` : ""}${extra}`);
        }
      }
      if (!any) w("no kernel notification callbacks registered", "dim");
      else w("hint: callbacks fire on kernel events — try !notifytest", "dim");
    },

    "!notifytest"(args, w) {
      const fire = kernel.fireProcessNotify ?? kernel._fireNotifyForTest;
      if (typeof fire !== "function") {
        return w("!notifytest: notify invocation engine not booted in this world", "err");
      }
      const name = args.find((a) => /[a-z]/i.test(a)) ?? "kftarget.exe";
      const pid = Number(args.find((a) => /^\d+$/.test(a)) ?? 4242);
      w(`spawning pid ${pid} (${name}) through PspCreateProcessNotify...`, "dim");
      const res = fire(BigInt(pid), name, { parentPid: 312n });
      for (const l of res.log) w("  " + l);
      if (res.blocked) {
        w(`RESULT: creation BLOCKED — CreationStatus=0x${res.status.toString(16)}`, "err");
      } else {
        w(`RESULT: created (CreationStatus=STATUS_SUCCESS)`, "good");
      }
    },

    "!ssdt"(args, w) {
      const st = kernel.serviceTable;
      if (!st) return w("!ssdt: no service table booted (this lab has none)", "err");
      const hooks = st.scanHooks();
      const want = args[0]?.toLowerCase().replace(/\.sys$/, "");
      w(`${st.name} @ ${fmtAddr(st.base)} — ${st.entries.length} service(s):`, "hdr");
      for (let i = 0; i < st.entries.length; i++) {
        const e = st.entries[i];
        const hooked = st.isHooked(i);
        if (want && !e.name.toLowerCase().includes(want)) continue;
        let note = "";
        if (hooked) {
          const t = ServiceTable.rel32Target(st.kernel.mem, e.thunk);
          note = `  [HOOKED] E9 -> ${fmtAddr(t ?? 0n)}`;
        }
        w(`  [${String(i).padStart(3, " ")}] ${fmtAddr(st.readEntry(i))}  nt!${e.name}${note}`,
          hooked ? "warn" : "");
      }
      if (!hooks.length) {
        w("no inline detours detected across the table", "good");
      } else {
        w(`${hooks.length} hooked service(s). Repair a prologue with 'eb' ` +
          `(pristine bytes via !hookscan <export>), then re-run !ssdt.`, "dim");
      }
      kernel.onSsdtScanned?.(hooks);
    },

    async "!pseudocode"(args, w) {
      const addr = args[0] ? parseAddr(args[0]) : null;
      if (addr === null) return w("usage: !pseudocode <addr>", "err");
      // Real Ghidra pseudocode when the wasm is vendored (npm run
      // vendor:ghidra); the deterministic fixture below remains the
      // offline/no-artifact path so m19's flag flow never changes.
      if (await loadDecompiler()) {
        const image = moduleImageAt(addr) ?? { base: addr, size: 4096 };
        const bytes = readForward(mem, image.base, Math.min(image.size, 0x20000));
        if (bytes.length) {
          try {
            const { c } = await ghidraDecompile(bytes, image.base, addr);
            for (const l of c.split("\n").slice(0, 48)) w(l, "code");
            return;
          } catch (e) {
            w(`// ghidra engine failed (${e.message}); falling back to fixture`, "dim");
          }
        }
      }
      // Fixture-shaped decompilation (deterministic, browser-contained):
      // recognize known sensor idioms by their immediate fingerprints.
      const b = mem.read(addr, 96);
      const le64 = (o) => BigInt.asUintN(64,
        b.slice(o, o + 8).reduceRight((a, x) => (a << 8n) | BigInt(x), 0n));
      const isSensor = b[0] === 0x48 && b[1] === 0x85 && b[2] === 0xd2 // test rdx,rdx
        && b[3] === 0x74                                              // jz done
        && b[5] === 0x48 && b[6] === 0x8b && b[7] === 0x4a && b[8] === 0x28 // mov rcx,[rdx+28]
        && b[9] === 0x66 && b[10] === 0x81;                           // cmp word
      if (!isSensor) {
        const t = resolveRel32(mem, addr);
        w(`// no fixture signature at ${fmtAddr(addr)}`, "dim");
        w(t !== null
          ? `// ${fmtAddr(addr)}: rel32 transfer to ${fmtAddr(t)} (see !funcs)`
          : "// try !funcs for boundary recovery; !decomp once wasm lands", "dim");
        return;
      }
      const q0 = le64(16), q1 = le64(16 + 10 + 2); // imm64 sites in the fixture
      const dec64 = (v, n) => {
        let s = "";
        for (let i = 0; i < n; i++) s += String.fromCharCode(Number((v >> BigInt(8 * i)) & 0xffn));
        return s;
      };
      const lit = (v) => "[" + dec64(v, 4).replace(/\x00+$/, "") + "]";
      const c = [
        "NTSTATUS Cs_ProcessNotifyCallback(PEPROCESS Process, PS_CREATE_NOTIFY_INFO *ci) {",
        "    if (!ci) return STATUS_SUCCESS;                       // termination path",
        "    UNICODE_STRING *name = ci->ImageFileName;             // +0x28",
        "    if (name->Length != 0x1A) return STATUS_SUCCESS;      // 13 chars",
        `    PCWSTR buf = name->Buffer;`,
        `    if (*(uint64_t*)buf       != 0x${q0.toString(16)}n  /* ${lit(q0)} */) return STATUS_SUCCESS;`,
        `    if (*(uint64_t*)(buf + 4) != 0x${q1.toString(16)}n  /* ${lit(q1)} */) return STATUS_SUCCESS;`,
        "    if (*(uint16_t*)(buf + 8) != 't') return STATUS_SUCCESS;",
        "",
        "    ci->CreationStatus = 0xC0000022;   // +0x40 (decimal 64): BLOCKED",
        "    return STATUS_SUCCESS;",
        "}",
      ];
      for (const l of c) w(l, "code");
    },
  };
  return commands;
}

export function createDebugger(kernel, out) {
  const commands = createCommands(kernel);
  const write = (text, cls = "") => {
    // console adapter (xterm/fallback from console.js) — preferred surface
    if (typeof out?.write === "function" && !out.appendChild) {
      out.write(text, cls);
      return;
    }
    const line = document.createElement("div");
    if (cls) line.className = cls;
    line.textContent = text;
    out.appendChild(line);
    out.scrollTop = out.scrollHeight;
  };
  // Live debug-output sink: like a real kernel debugger, DbgPrint telemetry
  // appears inline as it happens. The buffer stays available via !dbgprint.
  if (kernel && "onDebugPrint" in kernel) {
    kernel.onDebugPrint = (line) => write(line, "dim");
  }
  const exec = async (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    // Decorative separators pasted from lab transcripts ("====…0.==",
    // "----------") are transcript furniture, not commands — skip them
    // silently instead of emitting a confusing Couldn't-resolve error
    // (issue #28). A real command always carries letters after the junk.
    const compact = trimmed.replace(/\s+/g, "");
    if (/^[=\-_*~]{4,}/.test(compact) && !/[a-zA-Z]/.test(compact.replace(/^[=\-_*~]+/, ""))) {
      return;
    }
    write(`kd> ${trimmed}`, "prompt");
    let [cmd, ...args] = trimmed.split(/\s+/);
    // tolerate windbg-style command flags: lmD / lmv -> lm <flag>
    if (!commands[cmd]) {
      const m = cmd.match(/^(lm)([a-zA-Z]+)$/i);
      if (m) { cmd = m[1]; args = [m[2], ...args]; }
    }
    const fn = commands[cmd];
    if (!fn) {
      const bare = cmd.replace(/^!/, "").toLowerCase();
      const known = Object.keys(commands).map((c) => c.replace(/^!/, "").toLowerCase());
      const near = known.find((c) => c.startsWith(bare.slice(0, 3)) && bare.length >= 2);
      write(near
        ? `Couldn't resolve "${cmd}" — did you mean "!${near}"? (try help)`
        : `Couldn't resolve "${cmd}" — try help`, "err");
    }
    else try { await fn(args, write, out); } catch (e) { write(`error: ${e.message}`, "err"); }
  };
  /**
   * Lab flows (compile+load, !dpcdrain, ...) call this when a burst comes
   * back {status:"breakpoint"} — or a fault that is really our int3 hit.
   * Returns true when a debugger pause was adopted (real faults pass through).
   */
  const notifyBreak = (res) => {
    if (res?.status !== "breakpoint" && res?.status !== "fault") return false;
    commands.__bpBurst(res);
    if (!commands.__bpPaused()) return false;
    write(`Breakpoint hit @ ${fmtAddr(kernel.cpu.regs.rip)} — step with t/p, resume with g`, "warn");
    return true;
  };
  return { exec, write, notifyBreak };
}
