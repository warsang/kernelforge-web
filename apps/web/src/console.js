/**
 * terminal.js — kd> console surface.
 *
 * Real browsers get an @xterm/xterm terminal (inline editing, history,
 * ANSI colors, fit-to-width). Headless/DOM-shim environments (happy-dom
 * tests, SSR) fall back to the legacy .console div + .cmd input pair so
 * `textContent`-based assertions keep working.
 *
 * Both implementations expose the same adapter contract consumed by
 * createDebugger(kernel, out):
 *   - write(text, cls)          one logical line per call
 *   - innerHTML setter          `clear` command wipes the buffer
 *   - scrollTop/scrollHeight    harmless no-op writes on the xterm path
 */

import "@xterm/xterm/css/xterm.css";

const SGR = {
  "": "\x1b[0m",
  dim: "\x1b[2m",
  hdr: "\x1b[1;38;2;88;166;255m",   // bold accent (#58a6ff)
  err: "\x1b[38;2;248;81;73m",      // --bad
  good: "\x1b[38;2;63;185;80m",     // --good
  warn: "\x1b[38;2;210;153;34m",    // --warn
  prompt: "\x1b[38;2;139;148;158m", // --dim
};

const DEFAULT_PROMPT = "kd> ";

/** Consoles alive across lesson re-renders; disposed on next render. */
const live = [];

function track(adapter) {
  live.push(adapter);
  return adapter;
}

/** Dispose consoles from previous renderLesson() passes. */
export function disposeConsoles() {
  while (live.length) {
    try { live.pop().dispose?.(); } catch { /* best effort */ }
  }
}

/** True when running under a DOM shim that cannot host xterm. */
function isHeadlessDom() {
  return typeof window !== "undefined" && !!window.happyDOM;
}

// ------------------------------------------------------------- legacy path

function createFallbackConsole(container, { onSubmit, prompt = DEFAULT_PROMPT, placeholder }) {
  const out = document.createElement("div");
  out.className = "console";
  const input = document.createElement("input");
  input.className = "cmd";
  input.placeholder = placeholder ?? `${prompt}command…  (help, lm, !process 0 0, r, db <addr>, dq <addr>, !eproc <addr|pid>)`;
  input.addEventListener("keydown", (ev) => {
    if (ev.key !== "Enter") return;
    const line = input.value;
    input.value = "";
    if (line.trim()) onSubmit(line);
  });
  container.append(input, out);

  const history = [];
  return track({
    kind: "fallback",
    element: container,
    focusTarget: input,
    write(text, cls = "") {
      const line = document.createElement("div");
      if (cls) line.className = cls;
      line.textContent = text;
      out.appendChild(line);
      out.scrollTop = out.scrollHeight;
    },
    get lines() { return out.textContent; },
    clear() { out.innerHTML = ""; },
    dispose() {
      input.remove();
      out.remove();
    },
    history,
    get innerHTML() { return out.innerHTML; },
    set innerHTML(v) { out.innerHTML = v; },
  });
}

// -------------------------------------------------------------- xterm path

async function createXtermConsole(container, { onSubmit, prompt = DEFAULT_PROMPT }) {
  const [{ Terminal }, { FitAddon }] = await Promise.all([
    import("@xterm/xterm"),
    import("@xterm/addon-fit"),
  ]);

  const host = document.createElement("div");
  host.className = "console console-xterm";
  container.append(host);

  const term = new Terminal({
    fontFamily: 'ui-monospace, "SF Mono", Menlo, Consolas, monospace',
    fontSize: 12.5,
    lineHeight: 1.3,
    cursorBlink: true,
    convertEol: false,
    theme: {
      background: "#010409",
      foreground: "#e6edf3",
      brightBlack: "#8b949e",
      brightRed: "#f85149",
      brightGreen: "#3fb950",
      brightYellow: "#d29922",
      brightBlue: "#58a6ff",
      cursor: "#58a6ff",
    },
  });
  const fit = new FitAddon();
  term.loadAddon(fit);
  term.open(host);
  try { fit.fit(); } catch { /* zero-size hosts are fine pre-layout */ }

  let lineBuf = "";
  let historyIdx = -1;
  let adapter = null;

  const redrawPromptLine = () => {
    term.write("\r\x1b[2K" + "\x1b[38;2;139;148;158m" + prompt + "\x1b[0m" + lineBuf);
  };

  term.onData((data) => {
    if (!adapter) return;
    if (data === "\r") {
      term.write("\r\n");
      const line = lineBuf;
      lineBuf = "";
      if (line.trim()) {
        adapter.history.push(line);
        onSubmit(line);
      }
      redrawPromptLine();
    } else if (data === "\x7f") {           // backspace
      if (lineBuf.length) {
        lineBuf = lineBuf.slice(0, -1);
        redrawPromptLine();
      }
    } else if (data === "\x0c") {           // ctrl+l
      term.clear();
      redrawPromptLine();
    } else if (data === "\x1b[A") {         // up
      if (!adapter.history.length) return;
      historyIdx = historyIdx < 0
        ? adapter.history.length - 1
        : Math.max(0, historyIdx - 1);
      lineBuf = adapter.history[historyIdx];
      redrawPromptLine();
    } else if (data === "\x1b[B") {         // down
      if (historyIdx < 0) return;
      historyIdx++;
      if (historyIdx >= adapter.history.length) { historyIdx = -1; lineBuf = ""; }
      else lineBuf = adapter.history[historyIdx];
      redrawPromptLine();
    } else if (data >= " " || data === "\t") {
      lineBuf += data;
      term.write(data);
    }
  });

  if (typeof ResizeObserver !== "undefined") {
    const ro = new ResizeObserver(() => {
      try { fit.fit(); } catch { /* hidden container */ }
    });
    ro.observe(host);
  }

  adapter = track({
    kind: "xterm",
    element: container,
    focusTarget: term,
    write(text, cls = "") {
      const color = SGR[cls] ?? SGR[""];
      for (const seg of String(text).split("\n")) {
        term.writeln(color + seg + "\x1b[0m");
      }
    },
    clear() { term.clear(); },
    dispose() {
      try { term.dispose(); } catch { /* already gone */ }
      host.remove();
    },
    history: [],
    set innerHTML(v) {
      term.clear();
      if (v) for (const seg of String(v).split("\n")) {
        if (seg.trim()) term.writeln("\x1b[2m" + seg + "\x1b[0m");
      }
    },
  });

  redrawPromptLine();
  return adapter;
}

/**
 * Build the lab console inside `container`.
 * Resolves to the adapter described at the top of this file.
 * @param {object} opts
 * @param {string} [opts.prompt] - input prompt (e.g. "kd> " or "guest> ")
 * @param {string} [opts.placeholder]
 */
export async function createDebugConsole(container, { onSubmit, prompt, placeholder }) {
  if (!isHeadlessDom()) {
    try {
      return await createXtermConsole(container, { onSubmit, prompt });
    } catch {
      // xterm unavailable (offline bundle, odd embed) — degrade gracefully
    }
  }
  return createFallbackConsole(container, { onSubmit, prompt, placeholder });
}
