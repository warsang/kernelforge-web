# Legal inventory — vendored engines & artifacts

Status: 2026-08-26 (analysis suite: ghidra wasm vendored, sogen wasm core
client landed). Update on every vendor bump.

| component | upstream | license | our obligations |
|---|---|---|---|
| Unicorn/QEMU wasm | AlexAltea/unicorn.js @ pinned commit (packages/ntsim-unicorn) | GPL-2.0 | source offer when distributing publicly; rebuild recipe in package README |
| sogen core — JS glue vendored (one local patch), wasm via git LFS | momo5502/sogen @ sogen.dev deploy 2026-08-25 (packages/sogen-runtime/vendor + apps/web/public/sogen) | GPL-2.0 | source offer + rebuild recipe (vendor/README.md); sha256 pins; our additive `writeFile` worker hunk is documented there and must survive re-vendoring |
| Monaco editor | microsoft/monaco-editor (npm dep) | MIT | attribution in package.json |
| pyre decompiler build pipeline | ant4g0nist/pyre @ 835d7dd871304966165339d8cc7ae2deb0d00789 (build-time only) | MIT | pipeline + vendored Ghidra C++ sources consumed by tools/build-ghidra-wasm.mjs (`npm run vendor:ghidra`); outputs untracked |
| blinkenlib (NOT vendored — reference) | robalb/x86-64-playground | ISC | UI/UX inspiration for the gdb shell; no code vendored |
| Wine DLLs (emulation root) | winehq, built by tools/build-wine-root.mjs from a local WINEPREFIX | LGPL-2.1 | attribution; ship manifest with sha256s; never redistribute Microsoft DLLs |
| Sauerbraten engine | sauerbraten/Cube 2 engine | ZLIB | commercial OK; ZERO stock media — official installer link only |
| v86 | copy/v86 @ pinned commit (packages/v86-lab/vendor) | BSD-2-Clause (core) | attribution; BIOS blobs per upstream packaging terms |
| buildroot guest kernel + kfvillain | kernel.org 6.6.x + overlay/root/lab/kfvillain.c | GPL-2.0 | sources stay in-repo; image artifacts never committed |
| Ghidra decompiler engine | NationalSecurityAgency/ghidra (Features/Decompiler cpp) via pyre's wasm build | Apache-2.0 | keep upstream NOTICE beside packages/ghidra-decompiler/vendor/; provenance + sha256 recorded in vendor/README.md; artifacts untracked, rebuilt via `npm run vendor:ghidra` |
| Vergilius struct tables | vergiliusproject (scraped by ntsim-assets) | CC0 | none |

## Standing policies

- **Vendored wasm**: pinned upstream commit + provenance README + rebuild
  recipe in the package's `vendor/` dir; lazy-loaded so bundles never load
  unless a lab needs them; loud degradation when absent.
- **No proprietary binaries**: Windows DLLs, game media, and dump files are
  never committed. Students BYO where legally required; platform defaults to
  Wine-derived roots.
- **Educational/defensive framing** throughout; the responsible-use policy
  ships with the platform.


## Blog-labs v4 sources (lesson citations only)

Lessons link to third-party research for further reading; no text is
reproduced beyond short quotes/summaries. Cited: revers.engineering,
secret.club, windows-internals.com, security-auditing.com,
everdox.blogspot.com, momo5502.com, 0xdbgman.github.io, ssno.cc,
kernel-internals.org (CC BY-SA), github.com/ridpath/gamehacking-cheatsheet
(MIT), UnknownCheats TryBypassMe thread (community crackme, used as design
reference only).
