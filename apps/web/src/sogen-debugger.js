/**
 * Userland debugger adapter over a sogen-runtime session.
 * Same { exec, write } contract as createDebugger(kernel, out); commands are
 * served by the SogenConsole engine inside the package (unit-tested there),
 * this wrapper only owns presentation.
 */

const PROMPT = "> "; // userland debugger, not kernel

export function createSogenDebugger(session, out) {
  const engine = session.consoleEngine;

  const write = (text, cls = "") => {
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

  const exec = (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    write(`${PROMPT}${trimmed}`, "prompt");
    let result;
    try {
      result = engine.execute(trimmed);
    } catch (e) {
      write(`error: ${e.message}`, "err");
      return;
    }
    if (result) write(result);
    // graphical shell panels re-read world state after every command
    adapter.onAfterExec?.();
  };

  const adapter = { exec, write, onAfterExec: null };
  return adapter;
}
