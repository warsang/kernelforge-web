/**
 * Minimal-but-honest ELF parser for the linux-internals track.
 *
 * Design goals:
 *   - pure Uint8Array in / structured object out; zero deps; browser+node.
 *   - LENIENT like the Linux loader: malformed inputs produce `anomalies[]`
 *     entries instead of throwing (except a truncated Ehdr).
 *   - Mirrors what fs/binfmt_elf.c actually validates vs ignores so labs can
 *     teach the loader/parser gap (tmpout v5 "deep dive", v1 "Dead Bytes").
 */

const PT_TYPES = {
  0: "PT_NULL", 1: "PT_LOAD", 2: "PT_DYNAMIC", 3: "PT_INTERP",
  4: "PT_NOTE", 5: "PT_SHLIB", 6: "PT_PHDR", 7: "PT_TLS",
  0x6474e550: "PT_GNU_EH_FRAME", 0x6474e551: "PT_GNU_STACK",
  0x6474e552: "PT_GNU_RELRO", 0x6474e553: "PT_GNU_PROPERTY",
};

const SH_TYPES = {
  0: "SHT_NULL", 1: "SHT_PROGBITS", 2: "SHT_SYMTAB", 3: "SHT_STRTAB",
  4: "SHT_RELA", 5: "SHT_HASH", 6: "SHT_DYNAMIC", 7: "SHT_NOTE",
  8: "SHT_NOBITS", 9: "SHT_REL", 11: "SHT_DYNSYM", 14: "SHT_INIT_ARRAY",
  15: "SHT_FINI_ARRAY", 17: "SHT_GROUP", 18: "SHT_SYMTAB_SHNDX",
};

const ET = { 1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN", 4: "ET_CORE" };
const EM = { 0x03: "EM_386", 0x06: "EM_486", 0x3e: "EM_X86_64", 0xb7: "EM_AARCH64" };
const SHN = { 0xfff1: "SHN_ABS", 0xffff: "SHN_XINDEX" };

function cstr(bytes, off) {
  if (off < 0 || off >= bytes.length) return "";
  let end = off;
  while (end < bytes.length && bytes[end] !== 0) end++;
  return new TextDecoder("latin1").decode(bytes.subarray(off, end));
}

/**
 * @param {Uint8Array} b raw ELF image
 * @returns {ElfImage}
 */
export function parseElf(b) {
  if (!b || b.length < 16) throw new Error("truncated: shorter than e_ident");
  const anomalies = [];
  const magic = new TextDecoder("latin1").decode(b.subarray(0, 4));
  if (magic !== "\x7fELF") throw new Error(`bad magic ${JSON.stringify(magic)} (expected \\x7fELF)`);

  const ei_class = b[4], ei_data = b[5], ei_version = b[6], ei_osabi = b[7];
  const le = ei_data !== 2; // big-endian would need a different reader; we note it
  if (!le) anomalies.push("EI_DATA declares big-endian; this inspector only decodes little-endian");
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);

  if (b.length < 64) {
    // h4x.cz-style trimmed header: fields past EOF read as zero (the kernel
    // copies the first 256 bytes into bprm->buf and zero-pads implicitly)
    anomalies.push(`ehdr extends past EOF (${b.length} < 64 bytes): missing fields decode as 0`);
  }
  // Zero-padding readers: mirrors the kernel reading fields out of the
  // zero-filled tail of bprm->buf (this is what makes 57-byte ELFs work).
  const rd16 = (o) => {
    let v = 0;
    for (let i = 1; i >= 0; i--) v = ((v << 8) | (b[o + i] ?? 0)) >>> 0;
    return v;
  };
  const rd32 = (o) => {
    let v = 0;
    for (let i = 3; i >= 0; i--) v = ((v << 8) | (b[o + i] ?? 0)) >>> 0;
    return v;
  };
  const rd64 = (o) => {
    let v = 0n;
    for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[o + i] ?? 0);
    return v;
  };

  const ehdr = {
    ei_class, ei_data, ei_version, ei_osabi,
    class: ei_class === 2 ? "ELFCLASS64" : ei_class === 1 ? "ELFCLASS32" : `invalid(${ei_class})`,
    type: rd16(16), typeName: ET[rd16(16)] ?? `0x${rd16(16).toString(16)}`,
    machine: rd16(18), machineName: EM[rd16(18)] ?? `0x${rd16(18).toString(16)}`,
    version: rd32(20),
    entry: rd64(24),
    phoff: rd64(32),
    shoff: rd64(40),
    flags: rd32(48),
    ehsize: rd16(52),
    phentsize: rd16(54),
    phnum: rd16(56),
    shentsize: rd16(58),
    shnum: rd16(60),
    shstrndx: rd16(62),
  };

  // --- loader-vs-parser notes (what binfmt_elf.c would say about this file) ---
  const loaderChecks = [];
  loaderChecks.push(["ELFMAG \"\\x7fELF\"", true]);
  loaderChecks.push(["e_type is ET_EXEC or ET_DYN", [1, 2, 3].includes(ehdr.type)]);
  loaderChecks.push(["e_machine == EM_X86_64", ehdr.machine === 0x3e]);
  loaderChecks.push([
    "e_phentsize == 0x38",
    ehdr.phnum > 0 ? ehdr.phentsize === 0x38 : null,
  ]);
  loaderChecks.push([
    "e_phnum * e_phentsize <= 65536",
    ehdr.phnum > 0 ? ehdr.phnum * ehdr.phentsize <= 65536 : null,
  ]);

  // --- program headers --------------------------------------------------------
  const phdrs = [];
  if (ehdr.phnum > 0 && ehdr.phoff === 0n) {
    anomalies.push("e_phnum>0 with e_phoff==0: Phdr aliases the Ehdr itself");
  }
  for (let i = 0; i < ehdr.phnum; i++) {
    const o = Number(ehdr.phoff) + i * ehdr.phentsize;
    if (o + 56 > b.length) {
      anomalies.push(`phdr[${i}] at 0x${o.toString(16)} runs past EOF`);
      break;
    }
    if (ehdr.phentsize < 56) {
      anomalies.push(`e_phentsize=${ehdr.phentsize} != 0x38 (kernel would fall through to compat)`);
    }
    const p_type = rd32(o);
    phdrs.push({
      index: i,
      type: p_type,
      typeName: PT_TYPES[p_type] ?? `unknown(0x${p_type.toString(16)})`,
      flags: rd32(o + 4),
      flagStr: ["r", "w", "x"].filter((_, k) => rd32(o + 4) & (4 >> k)).join("") || "---",
      offset: rd64(o + 8),
      vaddr: rd64(o + 16),
      paddr: rd64(o + 24),
      filesz: rd64(o + 32),
      memsz: rd64(o + 40),
      align: rd64(o + 48),
      get truncated() {
        return Number(this.offset) + Number(this.filesz) > b.length;
      },
    });
  }
  for (const p of phdrs) {
    if (p.truncated) {
      anomalies.push(
        `${p.typeName} phdr[${p.index}] spans 0x${p.offset.toString(16)}..0x` +
        `${(Number(p.offset) + Number(p.filesz)).toString(16)} which passes EOF`,
      );
    }
    if (p.typeName.startsWith("unknown(")) {
      anomalies.push(`phdr[${p.index}] has unrecognized p_type ${p.typeName}: kernel skips it silently`);
    }
    if ((BigInt(p.vaddr) & 0xfffn) !== (BigInt(p.offset) & 0xfffn) && p.align >= 0x1000n) {
      anomalies.push(
        `phdr[${p.index}] violates p_vaddr % p_align == p_offset % p_align congruence`,
      );
    }
  }

  // --- section headers (extended numbering aware) -----------------------------
  let shnum = ehdr.shnum;
  let shstrndx = ehdr.shstrndx;
  const shdr0Off = Number(ehdr.shoff);
  if (shnum === 0 && shdr0Off > 0 && shdr0Off + 64 <= b.length) {
    shnum = rd32(shdr0Off + 32); // real count lives in shdr[0].sh_size
    anomalies.push(
      `e_shnum==0 but SHT exists: extended numbering, real count ${shnum} from shdr[0].sh_size`,
    );
  }
  if (shstrndx === 0xffff && shdr0Off > 0 && shdr0Off + 64 <= b.length) {
    shstrndx = rd32(shdr0Off + 40); // real index in shdr[0].sh_link
    anomalies.push(`e_shstrndx==SHN_XINDEX: real index ${shstrndx} from shdr[0].sh_link`);
  }

  const shdrs = [];
  for (let i = 0; i < shnum; i++) {
    const o = shdr0Off + i * (ehdr.shentsize || 64);
    if (o + 64 > b.length) {
      anomalies.push(`shdr[${i}] at 0x${o.toString(16)} runs past EOF`);
      break;
    }
    shdrs.push({
      index: i,
      nameIdx: rd32(o),
      name: "",
      type: rd32(o + 4),
      typeName: SH_TYPES[rd32(o + 4)] ?? `0x${rd32(o + 4).toString(16)}`,
      flags: rd64(o + 8),
      addr: rd64(o + 16),
      offset: rd64(o + 24),
      size: rd64(o + 32),
      link: rd32(o + 40),
      info: rd32(o + 44),
      addralign: rd64(o + 48),
      entsize: rd64(o + 56),
    });
  }

  // resolve names via shstrtab (never fatal)
  const shstr = shstrndx > 0 && shstrndx < shdrs.length ? shdrs[shstrndx] : null;
  if (shstr) {
    for (const s of shdrs) {
      s.name = cstr(b, Number(shstr.offset) + s.nameIdx);
    }
  } else if (shdrs.length) {
    anomalies.push("no usable shstrtab: section names unresolved");
  }
  for (const s of shdrs) {
    if (s.size > 0n && BigInt(s.offset) + s.size > BigInt(b.length) &&
        s.typeName !== "SHT_NOBITS") {
      anomalies.push(
        `section ${s.name || s.index} claims file range past EOF ` +
        `(offset 0x${s.offset.toString(16)}, size 0x${s.size.toString(16)})`,
      );
    }
    if (s.typeName === "SHT_SYMTAB" && s.entsize === 0n && s.size > 0n) {
      anomalies.push(`section ${s.name || s.index} (symtab) has sh_entsize 0: division-by-zero trap`);
    }
  }

  // --- symbols (.symtab preferred over .dynsym) -------------------------------
  const symbols = [];
  const symtab = shdrs.find((s) => s.typeName === "SHT_SYMTAB") ??
    shdrs.find((s) => s.typeName === "SHT_DYNSYM");
  if (symtab && symtab.entsize > 0n) {
    const strtabSh = shdrs[symtab.link];
    const count = Math.floor(Number(symtab.size) / Number(symtab.entsize));
    for (let i = 0; i < count; i++) {
      const o = Number(symtab.offset) + i * Number(symtab.entsize);
      if (o + 24 > b.length) break;
      const st_name = rd32(o);
      const st_info = b[o + 4] ?? 0;
      const st_shndx = rd16(o + 6);
      symbols.push({
        name: strtabSh ? cstr(b, Number(strtabSh.offset) + st_name) : "",
        bind: st_info >> 4,
        bindName: ["LOCAL", "GLOBAL", "WEAK"][st_info >> 4] ?? `bind(${st_info >> 4})`,
        type: st_info & 0xf,
        typeName: ["NOTYPE", "OBJECT", "FUNC", "SECTION", "FILE"][st_info & 0xf] ?? `type(${st_info & 0xf})`,
        shndx: st_shndx,
        shndxName: SHN[st_shndx] ?? String(st_shndx),
        value: rd64(o + 8),
        size: rd64(o + 16),
      });
    }
  } else if (symtab) {
    anomalies.push("symbol table unreadable (bad entsize)");
  }

  // --- strings view ------------------------------------------------------------
  function strings(minLen = 6) {
    const out = [];
    let start = -1;
    for (let i = 0; i <= b.length; i++) {
      const printable = i < b.length && b[i] >= 0x20 && b[i] < 0x7f;
      if (printable && start < 0) start = i;
      else if (!printable && start >= 0) {
        if (i - start >= minLen) {
          out.push({ offset: start, text: new TextDecoder("latin1").decode(b.subarray(start, i)) });
        }
        start = -1;
      }
    }
    return out;
  }

  return {
    bits: ei_class === 2 ? 64 : 32,
    bytes: b,
    size: b.length,
    ehdr,
    phdrs,
    shdrs,
    symbols,
    anomalies,
    loaderChecks,
    strings,
    hexdump,
  };
}

/** Classic hexdump of [off, off+n). */
export function hexdump(b, off, n = 128) {
  const lines = [];
  for (let row = 0; row < n; row += 16) {
    const cells = [];
    let ascii = "";
    for (let i = 0; i < 16; i++) {
      const idx = off + row + i;
      if (idx >= b.length) { cells.push("  "); ascii += " "; continue; }
      cells.push(b[idx].toString(16).padStart(2, "0"));
      ascii += b[idx] >= 0x20 && b[idx] < 0x7f ? String.fromCharCode(b[idx]) : ".";
    }
    lines.push(`${(off + row).toString(16).padStart(8, "0")}: ${cells.join(" ")}  |${ascii}|`);
  }
  return lines.join("\n");
}
