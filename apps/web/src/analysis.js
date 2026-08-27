/**
 * analysis.js — app-side glue for the floating pyre-style workspace.
 *
 * Bridges whatever session is live (kernel ntsim world or sogen userland
 * world) into the track-agnostic seams @kernelforge/debugger-ui expects:
 *
 *   DebugSession  <- capstone facade (./disasm.mjs) over world memory
 *   decompiler    <- createDecompilerClient over the largest module extent
 *
 * openAnalysis() is idempotent: one window, re-attached per boot.
 */

import { createAnalysisWorkspace, disposeWorkspaces } from "@kernelforge/debugger-ui";
import { createDecompilerClient } from "@kernelforge/ghidra-decompiler";
import { disassemble, liftAliasHex } from "./disasm.mjs";

/** Extract {mem, modules} from whichever session shape is booted. */
export function sourceForSession(session) {
  const kernel = session?.kernel;
  if (kernel?.mem) return { mem: kernel.mem, modules: kernel.loadedModules ?? [] };
  const world = session?.world;
  if (world?.mem) return { mem: world.mem, modules: world.modules ?? [] };
  return null;
}

function hex(n, pad = 12) {
  return BigInt(n ?? 0).toString(16).padStart(pad, "0");
}

/** Static-image DebugSession: introspection only, visual breakpoints. */
export function createImageSession({ mem, modules }) {
  const breakpoints = new Map();

  async function disasmAt(address, count) {
    try {
      const insns = await disassemble(mem, BigInt("0x" + String(address).replace(/^0x/i, "")), { count });
      return insns.map((i) => {
        const hi = BigInt.asUintN(64, BigInt(i.va)) & ~0xffffffffn;
        const opStr = liftAliasHex(i.opStr, hi);
        const m = /0x([0-9a-fA-F]+)/.exec(opStr);
        const branch = /^(j|call|loop)/i.test(i.mnemonic) && m ? m[1].padStart(8, "0") : undefined;
        return {
          address: i.va.toString(16).padStart(12, "0"),
          size: i.len,
          mnemonic: i.mnemonic,
          operands: opStr,
          bytes: i.bytes,
          ...(branch ? { branch } : {}),
        };
      });
    } catch {
      return [];
    }
  }

  return {
    paused: true,
    pauseCount: 1,
    onStateChange() { return () => {}; },
    async getRegisters() { return []; },
    disassemble: disasmAt,

    async readMemory(address, size) {
      const base = BigInt("0x" + String(address).replace(/^0x/i, ""));
      const out = new Uint8Array(Number(size));
      for (let k = 0; k < out.length; k++) {
        const a = base + BigInt(k);
        out[k] = mem.canRead(a, 1)
          ? (mem.u8 ? mem.u8(a) : Number(mem.read(a, 1)[0] ?? 0))
          : 0;
      }
      return out;
    },
    async writeMemory(address, bytes) {
      const base = BigInt("0x" + String(address).replace(/^0x/i, ""));
      [...bytes].forEach((b, k) => {
        const a = base + BigInt(k);
        if (typeof mem.write === "function") mem.write(a, [b]);
        else mem.w8?.(a, b);
      });
    },

    async getModules() {
      return modules.map((m) => ({
        name: m.name,
        base: hex(m.base),
        size: Number(m.sizeOfImage ?? m.size ?? 0),
        entry: hex(m.base),
      }));
    },
    async getThreads() { return []; },
    async getCallStack() { return []; },
    async getMemoryRegions() {
      return modules.map((m) => ({
        base: hex(m.base),
        size: Number(m.sizeOfImage ?? m.size ?? 0),
        label: m.name,
      }));
    },

    async setBreakpoint(address) {
      const key = String(address).replace(/^0x/i, "");
      if (!breakpoints.has(key)) breakpoints.set(key, { address: key, type: 0, enabled: true });
      return [...breakpoints.values()];
    },
    async clearBreakpoint(address) {
      breakpoints.delete(String(address).replace(/^0x/i, ""));
      return [...breakpoints.values()];
    },
    async listBreakpoints() { return [...breakpoints.values()]; },

    stepInto() { throw new Error("static image — boot an executable lab for run control"); },
    stepOver() { return this.stepInto(); },
    stepOut() { return this.stepInto(); },
    runTo() { return this.stepInto(); },
    resume() { return this.stepInto(); },
    pause() {},
  };
}

/** Largest module extent becomes the decompiler's image window. */
function pickExtent(modules) {
  let best = null;
  for (const m of modules) {
    const size = Number(m.sizeOfImage ?? m.size ?? 0);
    if (size > 0 && (!best || size > best.size)) best = { base: BigInt(m.base), size };
  }
  return best;
}

let singleton = null;

/**
 * Open (or focus) the analysis workspace against the current session.
 * Safe to call repeatedly; call closeAnalysis() on lesson teardown.
 */
export function openAnalysis(currentSession = null) {
  const src = sourceForSession(currentSession);
  const imageSession = src
    ? createImageSession(src)
    : createImageSession({ mem: { canRead: () => false, read: () => new Uint8Array(0) }, modules: [] });

  const extent = src ? pickExtent(src.modules) : null;
  const decompiler = src && extent
    ? createDecompilerClient({
      readImage: (addr, size) => {
        try {
          if (typeof src.mem.canRead === "function" && !src.mem.canRead(BigInt(addr), 1)) return null;
          return src.mem.read(BigInt(addr), Math.min(Number(size), 0x40000));
        } catch {
          return null;
        }
      },
      extent,
    })
    : null;

  if (!singleton || !singleton.element.isConnected) {
    singleton?.dispose?.();
    singleton = createAnalysisWorkspace({
      title: "Ghidra Analysis",
      session: imageSession,
      decompiler,
      onClose: () => { singleton = null; },
    });
  }
  // first interesting address: entry of the biggest module
  const entry = extent ? extent.base : null;
  if (entry !== null) singleton.followAddr(entry);
  singleton.restore();
  return singleton;
}

export function closeAnalysis() {
  singleton?.dispose?.();
  singleton = null;
}

export { disposeWorkspaces };
