/**
 * Linux (v86) pane: serial console debugger adapter + editor attach hook +
 * GDB RSP bridge (`gdb start <path>` launches gdbserver on ttyS1 in the
 * guest and attaches the graphical debugger shell).
 */

import { validateLinuxSource, guestBuildSequence } from "./lkm-builder.mjs";
import { createCodeEditor } from "@kernelforge/debugger-ui";

const PROMPT = "guest> ";

/** Debugger adapter over a booted V86LabSession. */
export function createLinuxDebugger(session, out) {
  const linux = session.linux;

  // live-tail the serial stream into the console
  linux.serial.onLine = (line) => write(line);

  let gdb = null;
  const listeners = { onShellRefresh: [], onGdbAttach: [] };

  function write(text, cls = "") {
    if (typeof out?.write === "function" && !out.appendChild) {
      out.write(text, cls);
      return;
    }
    const el = document.createElement("div");
    if (cls) el.className = cls;
    el.textContent = text;
    out.appendChild(el);
    out.scrollTop = out.scrollHeight;
  }

  async function handleGdb(args) {
    const sub = args[0];
    if (sub === "start" || sub === "attach") {
      const path = args[1] ?? "/root/lab/app";
      write(`[gdb] starting gdbserver on ttyS1: ${path}`, "dim");
      linux.sendLine(sub === "start"
        ? `gdbserver /dev/ttyS1 ${path} ${args.slice(2).join(" ")}`.trim()
        : `gdbserver --attach /dev/ttyS1 ${path}`);
      
      // Retry attach with exponential backoff (gdbserver may take time to bind)
      const maxAttempts = 5;
      let lastError = null;
      for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        await new Promise((r) => setTimeout(r, 1000 * attempt)); // 1s, 2s, 3s, 4s, 5s
        try {
          gdb = await linux.attachGdb();
          for (const cb of listeners.onGdbAttach) cb(gdb);
          write("[gdb] attached — graphical debugger live; type `(gdb) help` there", "good");
          write("[gdb] quick start: break *0x8048000 · c · si · x/8xw $esp · info registers", "dim");
          return;
        } catch (e) {
          lastError = e;
          if (attempt < maxAttempts) {
            write(`[gdb] attempt ${attempt}/${maxAttempts} failed: ${e.message} — retrying...`, "warn");
          }
        }
      }
      write(`[gdb] attach failed after ${maxAttempts} attempts: ${lastError?.message}`, "err");
      write("[gdb] troubleshooting: is gdbserver built into this image? (BR2_PACKAGE_GDB_SERVER)", "dim");
      write("[gdb] check: run 'which gdbserver' in the guest console", "dim");
      return;
    }
    if (sub === "detach" && gdb) {
      await gdb.detach();
      gdb = null;
      write("[gdb] detached", "dim");
      return;
    }
    write("usage: gdb start <guest-path> | gdb attach <pid> | gdb detach", "warn");
  }

  return {
    async exec(line) {
      const trimmed = line.trim();
      if (!trimmed) return;
      if (/^gdb\b/.test(trimmed)) {
        return handleGdb(trimmed.split(/\s+/).slice(1));
      }
      write(`${PROMPT}${trimmed}`, "prompt");
      try { linux.sendLine(trimmed); } catch (e) { write(`error: ${e.message}`, "err"); }
    },
    write,
    get gdb() { return gdb; },
    /** Register shell integration hooks (used by panes.mountShell). */
    hooks: listeners,
  };
}

/**
 * Attach the module editor UI for linux labs.
 * @param {{h: Function, lab: object, getSession: () => object|null,
 *          status: (text: string, cls?: string) => void}} ui
 */
export function attachLinuxEditor(ui) {
  const { h, lab } = ui;
  const starter =
    (lab.starterFiles?.[0]?.content) ||
    `// Write your kernel module here\n#include <linux/module.h>\n\nstatic int __init mod_init(void)\n{\n    pr_info("KFFLAG: hello from your module\\n");\n    return 0;\n}\nmodule_init(mod_init);\nMODULE_LICENSE("GPL");\n`;

  const editorHost = h("div", { class: "lkm-editor-host" });
  let editorHandle = null;
  void createCodeEditor(editorHost, {
    value: starter,
    language: "c",
    minimap: true,
    height: "420px",
  }).then((hd) => { editorHandle = hd; });
  const readSrc = () => editorHandle?.getValue?.() ?? starter;

  const shipBtn = h("button", { class: "primary" }, "Ship & Load Module");

  shipBtn.addEventListener("click", () => {
    const src = readSrc();
    const v = validateLinuxSource(src);
    if (!v.ok) {
      for (const e of v.errors) ui.status("✗ " + e, "err");
      return;
    }
    ui.status("✓ source validated — shipping to guest…", "good");
    const session = ui.getSession();
    if (!session?.linux) {
      ui.status("boot the guest first (Boot / Reset)", "err");
      return;
    }
    (async () => {
      await session.linux.injectFile("/root/lab/student.c", new TextEncoder().encode(src));
      for (const line of guestBuildSequence("student")) {
        session.linux.sendLine(line);
      }
      ui.status("✓ shipped; build+insmod running — watch the console", "good");
    })().catch((e) => ui.status(`ship failed: ${e.message}`, "err"));
  });

  return h("div", { class: "lkm-editor" }, editorHost, h("div", { class: "controls" }, shipBtn));
}
