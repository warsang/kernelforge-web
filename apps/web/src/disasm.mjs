/**
 * disasm.mjs — x86-64 disassembly facade over capstone-wasm for the kd>
 * console (`u` / `uf` commands).
 *
 * Address precision: capstone's JS API takes Numbers, which silently corrupt
 * kernel-half VAs (> 2^53). Every call therefore disassembles against a LOW
 * ALIAS BASE — the low 32 bits of the real VA — and callers re-attach the
 * high half when printing. Branch targets that capstone renders as absolute
 * hex literals live in the same low-alias space; the caller can lift them
 * back into kernel space (same 4 GB region assumption, documented limit).
 *
 * The wrapper owns nothing about kernels: it reads bytes through any object
 * exposing read(addr, len) + hasPage/canRead (SparseMemory satisfies both),
 * so tests can drive it directly.
 */

let capstoneMod = null;
let loadFailure = null;
async function loadCapstoneOnce() {
  if (capstoneMod) return capstoneMod;
  if (loadFailure) throw loadFailure;
  try {
    const mod = await import("capstone-wasm");
    await mod.loadCapstone();
    capstoneMod = mod;
    return capstoneMod;
  } catch (e) {
    // Cache and rethrow a DISTINCT error so callers can tell "the disassembler
    // asset failed to load" apart from a genuine unmapped-VA fault — `u` used
    // to report instantiate failures as "Memory read error … expected magic
    // word" (issues #28/#29).
    loadFailure = new Error(
      `disassembler-unavailable: capstone-wasm failed to load ` +
      `(${String(e?.message ?? e).slice(0, 140)})`);
    throw loadFailure;
  }
}

/** Test/UX hook: clear a cached loader failure so the next call retries. */
export function resetDisassemblerCache() {
  capstoneMod = null;
  loadFailure = null;
}

const MAX_WINDOW = 4096; // bytes fetched per disassemble request

/** Low-alias split for a BigInt VA. Returns { hi, lo } (both BigInt). */
function splitAlias(va) {
  const v = BigInt.asUintN(64, BigInt(va));
  return { hi: v & ~0xffffffffn, lo: v & 0xffffffffn };
}

/**
 * Disassemble up to `count` instructions starting at `va`.
 *
 * @param {object} mem SparseMemory-like ({read, hasPage|canRead})
 * @param {bigint} va virtual address of the first instruction
 * @param {{count?: number, stopAfterRet?: boolean}} opts
 *   stopAfterRet: end the stream after an unconditional RET/JMP (uf mode)
 * @returns {Promise<Array<{va: bigint, len: number, bytes: number[],
 *           mnemonic: string, opStr: string}>>}
 * @throws Error("unmapped") when the first instruction's page is not backed,
 *         Error("short read") when the stream dies inside an instruction.
 */
export async function disassemble(mem, va, opts = {}) {
  const { count = 12, stopAfterRet = false } = opts;
  const start = BigInt.asUintN(64, BigInt(va));
  if (typeof mem.canRead === "function" && !mem.canRead(start, 1)) {
    throw new Error("unmapped");
  } else if (typeof mem.canRead !== "function" && typeof mem.hasPage === "function"
             && !mem.hasPage(start)) {
    throw new Error("unmapped");
  }

  const { hi, lo } = splitAlias(start);
  const cs = await loadCapstoneOnce();
  const engine = new cs.Capstone(cs.Const.CS_ARCH_X86, cs.Const.CS_MODE_64);
  try {
    // fetch one contiguous window; sparse pages materialized by scenarios are
    // contiguous around code regions in every lab world
    const want = Math.min(count * 16, MAX_WINDOW);
    let avail = 0;
    while (avail < want && mem.canRead(start + BigInt(avail), 1)) avail += 64;
    avail = Math.min(avail || Math.min(256, want), want);
    const bytes = mem.read(start, avail);

    const out = [];
    let offset = 0;
    let insns;
    try {
      insns = engine.disasm(bytes.subarray(0, avail), { address: Number(lo) });
    } catch (e) {
      throw new Error(`disasm failed: ${e.message}`);
    }
    for (const insn of insns) {
      if (out.length >= count) break;
      const len = insn.bytes?.length ?? insn.size ?? 0;
      const rec = {
        va: start + BigInt(offset),
        len,
        bytes: [...(insn.bytes ?? [])],
        mnemonic: String(insn.mnemonic ?? ""),
        opStr: String(insn.opStr ?? insn.op_str ?? ""),
      };
      out.push(rec);
      offset += len;
      if (stopAfterRet &&
          (rec.mnemonic === "ret" || rec.mnemonic === "jmp" ||
           rec.mnemonic.startsWith("iret"))) {
        break;
      }
    }
    return out;
  } finally {
    try { engine.close(); } catch { /* optional */ }
  }
}

/**
 * Lift a low-alias hex literal emitted inside an operand string back into
 * kernel space by re-adding the region's high half. Only meaningful for
 * branch targets rendered absolutely by capstone ("jmp 0x10b5").
 */
export function liftAliasHex(text, hiBase) {
  if (!hiBase || hiBase === 0n) return text;
  return text.replace(/0x([0-9a-fA-F]+)/g, (m, hex) => {
    const v = BigInt("0x" + hex);
    if (v > 0xffffffffn) return m; // already full-width — leave alone
    return "0x" + BigInt.asUintN(64, v | hiBase).toString(16);
  });
}
