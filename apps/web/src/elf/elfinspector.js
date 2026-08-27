/**
 * elfinspector.js — readelf-flavored console over a parsed ELF fixture.
 *
 * Commands (muscle memory from binutils, shortened for the console):
 *   info              ehdr summary + loader checks + anomalies
 *   ehdr              full Elf64_Ehdr field dump
 *   phdr|phdrs        program header table
 *   shdr|shdrs        section headers
 *   sym|symbols       symbol table
 *   str|strings [n]   printable strings (min length n, default 6)
 *   hex <off> [n]     hexdump n bytes at file offset (0x ok)
 *   note|anomalies    parser-anomaly report
 *   help
 */

import { hexdump } from "./parse.mjs";

const PROMPT = "elf> ";

function hx(v) { return "0x" + BigInt(v).toString(16); }

export function createElfInspector(session, out) {
  const parsed = session.parsed;

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

  function banner() {
    write(`elf-inspector: ${session.name} (${parsed.size} bytes) — type 'help'`, "dim");
  }

  const commands = {
    help() {
      write("commands:");
      for (const l of [
        "  info                ehdr summary + loader checks + anomalies",
        "  ehdr                full Elf64_Ehdr",
        "  phdr | phdrs        program headers",
        "  shdr | shdrs        section headers",
        "  sym  | symbols      symbol table (.symtab)",
        "  str  | strings [n]  printable strings >= n chars",
        "  hex <off> [n]       hexdump at file offset",
        "  note | anomalies    anomaly report",
      ]) write(l, "dim");
    },

    info() {
      const e = parsed.ehdr;
      write(`${session.name}: ${e.class} ${e.typeName} ${e.machineName}, entry ${hx(e.entry)}`);
      write(`  phoff ${hx(e.phoff)} phnum ${e.phnum} phentsize ${hx(e.phentsize)} | shoff ${hx(e.shoff)} shnum ${e.shnum} shstrndx ${e.shstrndx === 0xffff ? "SHN_XINDEX" : e.shstrndx}`);
      write(`loader view (fs/binfmt_elf.c):`);
      for (const [check, pass] of parsed.loaderChecks) {
        write(`  ${pass === null ? " n/a " : pass ? "PASS" : "FAIL"}  ${check}`, pass === false ? "err" : "dim");
      }
      if (parsed.anomalies.length) {
        write(`${parsed.anomalies.length} parser anomaly(ies) — run 'note'`, "warn");
      } else {
        write("no parser anomalies", "dim");
      }
    },

    ehdr() {
      const e = parsed.ehdr;
      const rows = [
        ["e_ident[0..3]", "\\x7fELF"], ["ei_class", e.class], ["ei_data", e.ei_data === 1 ? "ELFDATA2LSB" : String(e.ei_data)],
        ["e_type", `${e.typeName} (${e.type})`], ["e_machine", `${e.machineName} (${e.machine})`],
        ["e_version", String(e.version)], ["e_entry", hx(e.entry)], ["e_phoff", hx(e.phoff)],
        ["e_shoff", hx(e.shoff)], ["e_flags", hx(e.flags)], ["e_ehsize", String(e.ehsize)],
        ["e_phentsize", `0x${e.phentsize.toString(16)}`], ["e_phnum", String(e.phnum)],
        ["e_shentsize", `0x${e.shentsize.toString(16)}`], ["e_shnum", String(e.shnum)],
        ["e_shstrndx", e.shstrndx === 0xffff ? "SHN_XINDEX" : String(e.shstrndx)],
      ];
      for (const [k, v] of rows) write(`  ${k.padEnd(14)} ${v}`);
    },

    phdr() {
      for (const p of parsed.phdrs) {
        write(
          `[${p.index}] ${p.typeName.padEnd(18)} off ${hx(p.offset).padEnd(10)} vaddr ${hx(p.vaddr).padEnd(12)} ` +
          `filesz ${hx(p.filesz).padEnd(8)} memsz ${hx(p.memsz).padEnd(8)} flags ${p.flagStr}${p.truncated ? "  <-- past EOF" : ""}`,
          p.truncated ? "warn" : "",
        );
      }
    },

    shdr() {
      for (const s of parsed.shdrs) {
        write(
          `[${s.index}] ${(s.name || "?").padEnd(14)} ${s.typeName.padEnd(15)} addr ${hx(s.addr).padEnd(12)} ` +
          `off ${hx(s.offset).padEnd(10)} size ${hx(s.size).padEnd(8)} entsize ${hx(s.entsize)}`,
        );
      }
    },

    sym() {
      if (!parsed.symbols.length) return write("(no symbol table)", "dim");
      for (const s of parsed.symbols) {
        if (!s.name && !s.value) continue; // null symbol
        write(
          `  ${hx(s.value).padEnd(12)} ${String(s.size).padStart(4)} ${s.bindName.padEnd(7)} ${s.typeName.padEnd(8)} ${s.name || "(unnamed)"}`,
        );
      }
    },

    str(args) {
      const minLen = Math.max(parseInt(args[0] ?? "6", 10) || 6, 2);
      for (const { offset, text } of parsed.strings(minLen)) {
        write(`  0x${offset.toString(16).padStart(6, "0")}: ${text}`);
      }
    },

    hex(args) {
      const off = parseInt(args[0]?.replace(/^0x/i, ""), 16);
      if (!Number.isFinite(off)) return write("usage: hex <offset> [count]", "err");
      const n = Math.min(parseInt(args[1] ?? "128", 10) || 128, 1024);
      write(hexdump(parsed.bytes, off, n));
    },

    note() {
      if (!parsed.anomalies.length) return write("clean parse", "dim");
      for (const a of parsed.anomalies) write(`  ⚠ ${a}`, "warn");
    },
  };
  commands.phdrs = commands.phdr;
  commands.shdrs = commands.shdr;
  commands.symbols = commands.sym;
  commands.strings = commands.str;
  commands.anomalies = commands.note;

  return {
    banner,
    async exec(line) {
      const trimmed = line.trim();
      if (!trimmed) return;
      write(`${PROMPT}${trimmed}`, "prompt");
      const [cmd, ...args] = trimmed.split(/\s+/);
      const fn = commands[cmd.toLowerCase()];
      if (!fn) return write(`unknown command "${cmd}" — try 'help'`, "err");
      fn(args);
    },
    write,
  };
}
