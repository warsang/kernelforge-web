/**
 * gdb-console.js — GDB-style command console over a GdbSession (RSP).
 *
 * Syntax follows classic gdb so muscle memory transfers:
 *   b|break <addr|*addr>  tbreak   c|continue    n|next     s|step
 *   si                    ni       finish        r|run?      k|kill?
 *   p|print <expr>        x/Nfu <addr>           i|r|info registers|b|threads
 *   disassemble [addr]    bt       set $reg=val  monitor…    detach
 *
 * The session is created by `gdb start <path>` inside the guest terminal
 * (which launches gdbserver on ttyS1) — this engine only drives RSP.
 */

const PROMPT = "(gdb) ";

function fmtAddr(v, pad = 8) {
  const b = typeof v === "bigint" ? v : BigInt("0x" + String(v).replace(/^0x/i, ""));
  return "0x" + b.toString(16).padStart(pad, "0");
}

/** Tiny print-expression evaluator: hex/dec literals, $reg, +/- offsets. */
async function evalExpr(expr, getRegs) {
  const regs = await getRegs();
  const regMap = new Map(regs.map((r) => [r.name, BigInt("0x" + r.value)]));
  const tokens = expr.trim().split(/\s+/).filter(Boolean);
  let acc = null;
  let op = 1n;
  for (const tok of tokens) {
    let v = null;
    if (/^\$[a-z][a-z0-9]*$/i.test(tok)) {
      const name = tok.slice(1).toLowerCase();
      if (!regMap.has(name)) throw new Error(`unknown register ${tok}`);
      v = regMap.get(name);
    } else if (/^0x[0-9a-f]+$/i.test(tok)) {
      v = BigInt(tok);
    } else if (/^\d+$/.test(tok)) {
      v = BigInt(tok);
    }
    if (v === null) continue;
    acc = acc === null ? v : acc + op * v;
    op = 1n;
  }
  if (acc === null) throw new Error(`cannot evaluate "${expr}"`);
  return acc;
}

export function createGdbConsole({ getSession, write }) {
  let lastCmd = "";
  let lastXParams = { n: 16, size: "x", fmt: "x", addr: null };

  const regSnapshot = () => getSession()?.getRegisters?.() ?? Promise.resolve([]);

  async function doInfo(args, w) {
    const sub = args[0]?.toLowerCase() ?? "";
    const s = getSession();
    if (!s) return w("no gdb session — use `gdb start <path>` in the guest first", "err");
    if (sub.startsWith("r")) {
      for (const r of await s.getRegisters()) {
        w(`${r.name.padEnd(8)}${r.value}${r.name === "eip" ? "  <- rip" : ""}`);
      }
    } else if (sub.startsWith("b")) {
      const list = await s.listBreakpoints();
      if (!list.length) return w("No breakpoints.");
      for (let i = 0; i < list.length; i++) {
        w(`${i + 1} breakpoint  keep y  ${list[i].enabled ? "enable" : "disable"}  ${fmtAddr(list[i].address)}`);
      }
    } else if (sub.startsWith("t")) {
      for (const t of await s.getThreads()) {
        w(`* ${t.id}  process 1  ${fmtAddr(t.ip)}  (active)`);
      }
    } else if (sub.startsWith("f")) {
      const frames = await s.getCallStack();
      frames.forEach((f, i) => w(`#${i}  ${fmtAddr(f.ip)} in ?? ()`));
    } else {
      w("info: use `info registers|breakpoints|threads|frame`", "dim");
    }
  }

  async function doExamine(args, w) {
    // x/Nfu addr | x/16xb addr | x addr
    const m = args.join(" ").match(/^(?:\/(\d+)?([xbwdg])?([sxi])?)?\s*(.*)$/);
    const n = Math.min(parseInt(m?.[1] ?? "16", 10), 256);
    const sizeCode = m?.[2] ?? "x";
    const addrExpr = m?.[4]?.trim();
    if (!addrExpr) return w("usage: x/Nfu <addr|$reg+off>", "err");
    const addr = await evalExpr(addrExpr, regSnapshot);
    const sizeBytes = { b: 1, h: 2, w: 4, g: 8 }[sizeCode] ?? 4;
    const bytes = await getSession().readMemory(addr.toString(16), n * sizeBytes)
      .catch((e) => { w(`x: ${e.message}`, "err"); return null; });
    if (!bytes) return;
    lastXParams = { n, size: sizeCode, fmt: sizeBytes, addr };
    for (let row = 0; row * 4 < n; row++) {
      const cells = [];
      let ascii = "";
      for (let i = 0; i < 4 && row * 4 + i < n; i++) {
        const off = (row * 4 + i) * sizeBytes;
        let val = 0;
        for (let b = 0; b < sizeBytes; b++) val |= (bytes[off + b] ?? 0) << (8 * b);
        cells.push(val.toString(16).padStart(sizeBytes * 2, "0"));
        ascii += String.fromCharCode(bytes[off]).replace(/[^\x20-\x7e]/g, ".");
      }
      w(fmtAddr(addr + BigInt(row * 4 * sizeBytes)) + ": " + cells.join(" ") + "   " + ascii);
    }
  }

  async function doDisassemble(args, w) {
    const s = getSession();
    if (!s) return w("no gdb session", "err");
    const target = args.find((a) => !a.startsWith("/")) ?? null;
    const base = target
      ? await evalExpr(target, regSnapshot)
      : BigInt("0x" + (await regSnapshot()).find((r) => r.name === "eip")?.value ?? "0");
    const insns = await s.disassemble(base.toString(16), 12);
    if (!insns.length) return w("disassemble: unreadable memory", "err");
    const eipHex = ((await regSnapshot()).find((r) => r.name === "eip")?.value ?? "").replace(/^0x/, "");
    for (const insn of insns) {
      const cur = insn.address.replace(/^0x/, "") === eipHex;
      w(
        `${cur ? "=>" : "  "} ${insn.address}  ` +
        `${insn.bytes.map((b) => b.toString(16).padStart(2, "0")).join("").padEnd(12)} ` +
        `${insn.mnemonic} ${insn.operands}` +
        (cur ? "   ; current" : ""),
        cur ? "good" : "",
      );
    }
  }

  async function doPrint(args, w) {
    try {
      const v = await evalExpr(args.join(" "), regSnapshot);
      const signed = BigInt.asIntN(32, v);
      w(`\$1 = ${v} (${signed})`);
    } catch (e) {
      w(`p: ${e.message}`, "err");
    }
  }

  /** @returns {{exec: Function, write: Function}} adapter */
  const engine = {
    async exec(line) {
      const trimmed = line.trim();
      if (!trimmed) return;
      write(`${PROMPT}${trimmed}`, "prompt");
      const s = getSession();
      if (!s) return write("no gdb session — run `gdb start <path>` in the guest terminal", "err");

      let [cmd, ...args] = trimmed.split(/\s+/);
      // gdb single-letter abbreviations & empty repeat
      if (cmd === "" ) cmd = lastCmd || cmd;
      lastCmd = cmd;

      switch (cmd) {
        case "b": case "break": case "tbreak": {
          const target = args.find((a) => !a.startsWith("-"));
          if (!target) return write("usage: break <*addr|addr>", "err");
          const addr = await evalExpr(target.startsWith("*") ? target.slice(1) : target, regSnapshot)
            .catch(() => null);
          if (addr === null) return write(`break: cannot resolve "${target}"`, "err");
          await s.setBreakpoint(addr.toString(16));
          return write(`Breakpoint 1 at ${fmtAddr(addr)}`);
        }
        case "c": case "continue": {
          write("Continuing.", "dim");
          const stop = await s.continueRunInternal().catch((e) => ({ err: e }));
          if (stop.err) return write(`continue: ${stop.err.message}`, "err");
          return write(stopDescription(stop));
        }
        case "n": case "next":
          return engine.exec("si"); // no symbol table: next == stepi honestly
        case "s": case "step": case "si": case "stepi": {
          const pkt = await s.stepInto().catch((e) => ({ err: e }));
          if (pkt.err) return write(`stepi: ${pkt.err.message}`, "err");
          return write(pktDescription(pkt));
        }
        case "ni": case "nexti":
          return engine.exec("si");
        case "finish": {
          resumeNote(w);
          const pkt = await s.stepOut().catch((e) => ({ err: e }));
          if (pkt.err) return write(`finish: ${pkt.err.message}`, "err");
          return write(pktDescription(pkt));
        }
        case "p": case "print":
          return doPrint(args, write);
        case "set": {
          const m = args.join(" ").match(/^\$([a-z][a-z0-9]*)\s*=\s*(.+)$/i);
          if (!m) return write('usage: set $eax = 0x10', "err");
          const regs = await regSnapshot();
          if (!regs.find((r) => r.name === m[1])) return write(`No symbol "$${m[1]}".`, "err");
          const blob = buildGPacket(regs, m[1], await evalExpr(m[2], regSnapshot));
          await s.rsp.writeRegisters(blob);
          return write(`${m[1]} updated`);
        }
        case "x":
          return doExamine(args, write);
        case "disassemble": case "disas":
          return doDisassemble(args, write);
        case "bt": case "backtrace": {
          const frames = await s.getCallStack();
          frames.forEach((f, i) =>
            write(`#${i}  ${fmtAddr(f.ip)} in ?? ()`));
          return;
        }
        case "i": case "info":
          return doInfo(args, write);
        case "d": case "delete": {
          const list = await s.listBreakpoints();
          for (const b of list) await s.clearBreakpoint(b.address);
          return write(list.length ? "Deleted all breakpoints." : "No breakpoints.");
        }
        case "detach":
          await s.detach();
          write("Detaching from program...");
          return write("[Inferior 1 detached]");
        case "quit": case "q":
          await s.detach();
          return write("gdb session closed");
        case "help":
          write("commands: b/c/s/si/n/ni/finish/p/x/disassemble/bt/info/d/detach/quit");
          return write("(guest-side shell remains available in the main console)");
        default:
          return write(`Undefined command: "${cmd}". Try "help".`, "err");
      }
    },
    write,
  };

  function resumeNote(w) {
    w("Run till exit from current frame.", "dim");
  }

  return engine;
}

function pktDescription(pkt) {
  const parsed = parseStopLoose(pkt);
  if (parsed.exited) return `[Inferior 1 exited with code ${parsed.code}]`;
  return `Program received signal SIGTRAP — stopped at ${parsed.eip ?? "??"}`;
}

function stopDescription(pkt) {
  return pktDescription(pkt);
}

function parseStopLoose(pkt) {
  if (typeof pkt !== "string") return {};
  if (/^W|^X/.test(pkt)) return { exited: true, code: parseInt(pkt.slice(1), 16) };
  const m = /eip:([0-9a-f]+)/.exec(pkt);
  return { eip: m ? fmtAddr(BigInt(m[1].padEnd(8, "0")), 8) : null };
}

/** Build a full G packet with one register replaced. */
function buildGPacket(regs, name, value) {
  const order = [
    "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
    "eip", "eflags", "cs", "ss", "ds", "es", "fs", "gs",
  ];
  let out = "";
  for (const r of order) {
    const found = regs.find((x) => x.name === r);
    const v = r === name ? value : (found ? BigInt("0x" + found.value) : 0n);
    const u = BigInt.asUintN(32, v);
    for (let b = 0; b < 4; b++) {
      out += ((u >> BigInt(8 * b)) & 0xffn).toString(16).padStart(2, "0");
    }
  }
  return out;
}
