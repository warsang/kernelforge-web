/**
 * Pane registry: lab.kind -> presentation/behavior overrides for the lab
 * card. Tracks add new lab kinds by registering here instead of editing
 * main.js core flow.
 *
 * def shape (all optional):
 *   backends?: [{value,label}]         options for the CPU/backend select
 *   noDump?: boolean                   skip tryLoadDumpWorld() on boot
 *   rawBoot?: boolean                  skip the ntsim backend factory entirely
 *   createDebugger?(session, host)     console debugger factory over the
 *                                      booted session (default: kernel kd)
 *   mountShell?(session, ctx)          graphical debugger shell; ctx =
 *                                      {card, consoleHost, shellHost, h};
 *                                      returns a facade (or null)
 *   attachEditor?(ui)                  pane IDE hookup
 */

import { createSogenDebugger } from "./sogen-debugger.js";
import { createLinuxDebugger, attachLinuxEditor } from "./linux-pane.js";
import { createElfInspector } from "./elf/elfinspector.js";
import { createDebuggerShell } from "@kernelforge/debugger-ui";
import {
  createStaticDebugSession, SAUER_CONSTANTS,
  probeAssets, createSogenDebugSession,
} from "@kernelforge/sogen-runtime";
import { createDecompilerClient } from "@kernelforge/ghidra-decompiler";
import { createGdbConsole } from "./gdb-console.js";
import { latestSogenTarget } from "./sogen-targets.js";

const panes = new Map();

export function registerPane(kind, def) {
  panes.set(kind, def);
}

export function paneFor(kind) {
  return panes.get(kind) ?? null;
}

// --- ntsim family: default flow (kernel sessions + kd engine) -------------
registerPane("windbg", {});
registerPane("ntsim", {});
registerPane("compiler", {});

// --- windows-userland: sogen track ------------------------------------------
// Graphical shell over the reference world. When the vendored sogen WASM
// core is present AND the student uploaded a target binary, the shell binds
// to the REAL emulated process (registers/threads/stack, live breakpoints,
// stepping); otherwise it falls back to backend-static (disasm/memory/
// modules/visual breakpoints over the JS reference world).
registerPane("sogen", {
  backends: [
    { value: "js", label: "Emulator: sogen reference backend (deterministic)" },
  ],
  targetUpload: true,
  noDump: true,
  createDebugger: (session, host) => createSogenDebugger(session, host),
  mountShell: async (session, ctx) => {
    if (!session?.world) return null;
    const world = session.world;

    // --- preferred: real sogen wasm core + uploaded target -------------------
    try {
      const assets = await probeAssets();
      const target = assets.ok ? latestSogenTarget() : null;
      if (target) {
        const safe = target.name.replace(/[^\w.-]/g, "_").slice(0, 64) || "target.exe";
        const { session: dbgSession } = createSogenDebugSession({
          file: `c:/${safe}`,
          breakOnStart: true,
          files: [{ path: `/root-windows/filesys/c:/${safe}`, bytes: target.bytes }],
        });
        ctx.consoleDebugger?.write(
          `sogen WASM core attached — target ${safe} paused at start. ` +
          "F5/F10/F11 control the emulated process.", "dim");
        return mountShellViews(ctx, dbgSession,
          "sogen — userland debugger (wasm core)");
      }
      if (!assets.ok) {
        ctx.consoleDebugger?.write(
          "sogen WASM core assets missing (" + assets.missing.join(", ") +
          ") — debugger shell uses the static reference backend.", "warn");
      }
    } catch (err) {
      console.warn("sogen wasm attach failed; static fallback:", err);
    }

    // --- fallback: static DebugSession over the JS reference world ------------
    const dbgSession = createStaticDebugSession(world);
    const decompiler = createDecompilerClient({
      readImage: (addr, size) => {
        const base = BigInt(addr);
        if (typeof world.mem.canRead === "function" && !world.mem.canRead(base, 1)) return null;
        return world.mem.read(base, Number(size));
      },
      extent: { base: SAUER_CONSTANTS.imageBase, size: SAUER_CONSTANTS.imageSize },
    });
    return mountShellViews(ctx, dbgSession,
      "sogen — userland debugger", decompiler);
  },
});

/** Shared shell construction for both sogen backends. */
function mountShellViews(ctx, dbgSession, title, decompiler = null) {
  const shell = createDebuggerShell(ctx.shellHost, {
    session: dbgSession,
    title,
    initialTab: "disasm",
    decompiler: decompiler ?? undefined,
  });
  // console commands mutate the world; refresh panels after each exec
  if (ctx.consoleDebugger) ctx.consoleDebugger.onAfterExec = () => shell.refresh();
  return shell;
}

// --- linux-kernel: v86 buildroot guest --------------------------------------
registerPane("linux", {
  prompt: "guest> ",
  placeholder: "guest> command…  (ls, cat /proc/modules, dmesg | tail, gdb start /bin/sh)",
  backends: [
    { value: "v86", label: "Guest: v86 i386 Linux (buildroot)" },
  ],
  noDump: true,
  rawBoot: true, // no ntsim CPU factory involved
  createDebugger: (session, host) => createLinuxDebugger(session, host),
  attachEditor: attachLinuxEditor,
  /**
   * GDB shell docks above the guest console; the Console tab hosts a
   * dedicated (gdb) prompt. Attach happens lazily when the student runs
   * `gdb start <path>` in the guest terminal.
   */
  mountShell: (session, ctx) => {
    const adapter = ctx.consoleDebugger;
    if (!adapter?.hooks) return null;

    const placeholder = document.createElement("div");
    placeholder.className = "dim dbg-note pad";
    placeholder.textContent =
      'gdb bridge idle — kernel labs use insmod; for userspace debugging run "gdb start /bin/sh" ' +
      '(or "gdb start /root/lab/app") in the guest console (buildroot image must include gdbserver).';
    ctx.shellHost.append(placeholder);

    let shell = null;
    adapter.hooks.onGdbAttach.push((gdbSession) => {
      placeholder.remove();
      shell = createDebuggerShell(ctx.shellHost, {
        session: gdbSession,
        title: "gdb — v86 target",
        initialTab: "disasm",
        closable: true,
        onClose: () => {
          ctx.shellHost.append(placeholder);
          shell.dispose();
          shell = null;
        },
        /** Dedicated (gdb)-prompt console inside the shell's Console tab. */
        consoleFactory: (tabHost) => {
          tabHost.className = "dbg-console-host";
          const out = document.createElement("div");
          out.className = "console";
          const input = document.createElement("input");
          input.className = "cmd";
          input.placeholder = "(gdb) break *0x8048000 …";
          tabHost.append(input, out);
          const writeLine = (text, cls2 = "") => {
            const div = document.createElement("div");
            if (cls2) div.className = cls2;
            div.textContent = text;
            out.appendChild(div);
            out.scrollTop = out.scrollHeight;
          };
          const gdbConsole = createGdbConsole({
            getSession: () => gdbSession,
            write: writeLine,
          });
          return {
            write: writeLine,
            clear() { out.innerHTML = ""; },
            exec: (line) => gdbConsole.exec(line),
            focusTarget: input,
            dispose() { tabHost.innerHTML = ""; },
          };
        },
      });
      // keep panels fresh after every stop
      gdbSession.onStateChange(() => shell?.refresh());
    });
    // Facade so a re-boot disposes the placeholder + any attached gdb shell
    // instead of stacking another dock above the console.
    return {
      dispose() {
        try { shell?.dispose?.(); } catch { /* best effort */ }
        shell = null;
        placeholder.remove();
      },
    };
  },
});

// --- linux-internals: static ELF fixtures + readelf-style inspector ---------
// No world to boot: the "session" is a parsed fixture and the console runs
// the elfinspector command set (info/phdr/shdr/sym/hex/...).
registerPane("elf", {
  backends: [
    { value: "static", label: "Inspector: static ELF parser" },
  ],
  noDump: true,
  rawBoot: true,
  createDebugger: (session, host) => {
    const dbg = createElfInspector(session, host);
    dbg.banner();
    return dbg;
  },
});
