# Spike: sogen GUI in the browser (Sauerbraten playable?)

**Decision gate for M1** — status: documented, spike pending vendor step.

## The question

Can the Sauerbraten *client* render inside a browser tab while running under
the sogen userspace emulator, giving fully playable game-hacking labs?

## What upstream supports today (verified 2026-08)

- sogen core compiles to WASM and runs in-browser (sogen.dev playground):
  emulator core in a Web Worker, Flatbuffers debugger protocol, IDBFS
  filesystem, PWA shell. Deterministic, snapshot/restore works.
- **Windows UI emulation** subsystem exists (user callbacks + window
  management): native GUI apps run with working windows/dialogs.
- **GPU paravirtualization** exists: D3D8/9/10/11 titles via DXVK → Vulkan on
  the host GPU (native backends; "fast enough for games" per upstream).

## Why Sauerbraten is the hard case

Cube 2 renders through **OpenGL**, not D3D. The DXVK bridge does not apply.
Options ranked:

| path | effort | risk | notes |
|---|---|---|---|
| GL → WebGPU/WebGL shim over sogen's windowing | high | medium | needs a GL syscall/API translation layer inside the worker; no upstream prior art |
| WGL software fallback (llvmpipe-style) into an OffscreenCanvas | medium | perf | i32/i64 wasm CPU-bound rasterizer will crawl for Cube2's octree renderer |
| headless client process (current reference world) | done ✅ | none | memory-recon/hook labs already shipped against it |

## Gate criteria to revisit

1. Vendor the real sogen WASM core (`packages/sogen-runtime/vendor/`).
2. Boot the media-free Sauerbraten client headless under it — assert clean
   exit of `main()` with null-render driver stubs.
3. Prototype the windowing path: does `user32!CreateWindowEx*` reach the
   browser surface? If yes, evaluate a minimal GL-to-WebGPU shim for
   Cube2's fixed-function-ish usage.

If (3) stalls, ship the staged plan: headless labs now, playable client as a
stretch goal behind its own milestone. The course never blocks on it.

## License guardrails (unchanged)

Engine ZLIB — commercial OK. ZERO stock media ships; official installer link
only. Any playable build must generate placeholder assets or require the
student-supplied install dir (IndexedDB mount).
