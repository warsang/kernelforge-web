/**
 * analyzer.js — run-any-.sys analysis tab.
 *
 * Upload a PE32+ driver, map it into the emulated kernel (every import
 * resolves — modeled or provisioned-stub), execute DriverEntry through the
 * SEH-aware path, drain DPC/work/APC queues, then drive MajorFunction with
 * scripted IOCTLs. Everything client-side; nothing leaves the tab.
 */

import { loadTables } from "./tables.js";
import { analyzeDriver } from "@kernelforge/ntsim-analyzer/src/index.mjs";
import {
  NtKernel,
  mapPe,
  parsePe,
  createDriverObject,
  initDriverObjectName,
  createDeviceObject,
  sendIrp,
  callDriverUnload,
} from "@kernelforge/ntsim/src/index.mjs";

const DRIVER_BASE = 0xfffff80300000000n;

function el(tag, attrs, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs ?? {})) {
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (v !== undefined && v !== null) e.setAttribute(k, String(v));
  }
  for (const c of children) e.append(c);
  return e;
}

function kv(label, value, cls) {
  return el("div", { class: `kv ${cls ?? ""}` },
    el("span", { class: "k" }, label),
    el("span", { class: "v" }, String(value)),
  );
}

const NTSTATUS_NAME = (s) => {
  const known = {
    "0x00000000": "STATUS_SUCCESS",
    "0xc0000001": "STATUS_NOT_IMPLEMENTED",
    "0xc000000b": "STATUS_INVALID_PARAMETER",
    "0xc0000005": "STATUS_ACCESS_VIOLATION",
    "0xc0000034": "STATUS_OBJECT_NAME_NOT_FOUND",
  };
  return known[s] ?? "";
};

export function renderAnalyzer(main) {
  main.innerHTML = "";

  let session = null; // {kernel, drvRec, image, report, imageSize}

  // ------------------------------------------------------------- layout
  const fileInput = el("input", { type: "file", accept: ".sys,.dll" });
  const engineSel = el("select", {},
    el("option", { value: "js" }, "JsInterpreter (deterministic)"),
    el("option", { value: "hybrid" }, "Hybrid (JS + Unicorn fallback)"),
    el("option", { value: "unicorn" }, "Unicorn (WASM-only)"),
  );
  const nameInput = el("input", { type: "text", placeholder: "uploaded.sys", value: "uploaded.sys", title: "Driver name — seeds DriverName and the Services\\<key> registry path. Auto-filled from the uploaded file." });
  fileInput.addEventListener("change", () => {
    const f = fileInput.files?.[0];
    if (f) nameInput.value = f.name;
  });

  const loadBtn = el("button", { class: "primary" }, "Load & run DriverEntry");

  const ioctlCode = el("input", { type: "text", placeholder: "0x222000", value: "0x222000" });
  const ioctlIn = el("input", { type: "text", placeholder: "input hex (e.g. deadbeef)" });
  const ioctlOut = el("input", { type: "number", value: "64", min: "0", max: "4096" });
  const ioctlBtn = el("button", {}, "Send IOCTL");
  ioctlBtn.disabled = true;

  const autoIrpBtn = el("button", { title: "Send CREATE/CLOSE + every harvested CTL_CODE with synthetic buffers" }, "Auto-drive IRPs");
  autoIrpBtn.disabled = true;

  // --- fuzz tickbox + sliders ---
  const LS = {
    get(k, d) { try { const v = localStorage.getItem(k); return v !== null ? v : d; } catch { return d; } },
    set(k, v) { try { localStorage.setItem(k, String(v)); } catch {} },
  };
  const fuzzTick = el("input", { type: "checkbox", title: "Coverage-guided mutation fuzzing" });
  fuzzTick.checked = LS.get("analyzer.fuzz.enabled", "false") === "true";
  fuzzTick.addEventListener("change", () => LS.set("analyzer.fuzz.enabled", fuzzTick.checked));

  const fuzzIter = el("input", { type: "range", min: "64", max: "1024", step: "64", value: LS.get("analyzer.fuzz.iter", "256") });
  const fuzzIterVal = el("span", { class: "dim" }, fuzzIter.value);
  fuzzIter.addEventListener("input", () => { fuzzIterVal.textContent = fuzzIter.value; LS.set("analyzer.fuzz.iter", fuzzIter.value); });

  const fuzzCorpus = el("input", { type: "range", min: "8", max: "64", step: "8", value: LS.get("analyzer.fuzz.corpus", "32") });
  const fuzzCorpusVal = el("span", { class: "dim" }, fuzzCorpus.value);
  fuzzCorpus.addEventListener("input", () => { fuzzCorpusVal.textContent = fuzzCorpus.value; LS.set("analyzer.fuzz.corpus", fuzzCorpus.value); });

  const concTick = el("input", { type: "checkbox", title: "Concolic execution for magic-value / structured inputs (Z3, JS backend)" });
  concTick.checked = LS.get("analyzer.conc.enabled", "false") === "true";
  concTick.addEventListener("change", () => LS.set("analyzer.conc.enabled", concTick.checked));

  const concSym = el("input", { type: "range", min: "16", max: "128", step: "8", value: LS.get("analyzer.conc.sym", "64") });
  const concSymVal = el("span", { class: "dim" }, concSym.value);
  concSym.addEventListener("input", () => { concSymVal.textContent = concSym.value; LS.set("analyzer.conc.sym", concSym.value); });

  const concTo = el("input", { type: "range", min: "100", max: "1000", step: "100", value: LS.get("analyzer.conc.to", "300") });
  const concToVal = el("span", { class: "dim" }, concTo.value);
  concTo.addEventListener("input", () => { concToVal.textContent = concTo.value; LS.set("analyzer.conc.to", concTo.value); });

  const concQ = el("input", { type: "range", min: "1", max: "16", step: "1", value: LS.get("analyzer.conc.queries", "8") });
  const concQVal = el("span", { class: "dim" }, concQ.value);
  concQ.addEventListener("input", () => { concQVal.textContent = concQ.value; LS.set("analyzer.conc.queries", concQ.value); });

  const bugTick = el("input", { type: "checkbox", title: "Find Bugs — taint + sink analysis for vuln hunting" });
  bugTick.checked = LS.get("analyzer.bugs.enabled", "false") === "true";
  bugTick.addEventListener("change", () => {
    LS.set("analyzer.bugs.enabled", bugTick.checked);
    if (bugTick.checked && !fuzzTick.checked) {
      fuzzTick.checked = true;
      LS.set("analyzer.fuzz.enabled", true);
    }
  });

  const unloadBtn = el("button", {}, "Call DriverUnload");
  unloadBtn.disabled = true;

  const out = el("div", { class: "analyzer-out" });
  const log = (msg, cls) => out.append(el("div", { class: `line ${cls ?? ""}` }, msg));

  const fuzzRow = el("div", { class: "analyzer-controls", style: "gap:6px;flex-wrap:wrap" },
    el("label", { class: "dim", style: "display:flex;gap:4px;align-items:center" }, fuzzTick, " Fuzz"),
    el("span", { class: "dim" }, "iters:"), fuzzIter, fuzzIterVal,
    el("span", { class: "dim" }, "corpus:"), fuzzCorpus, fuzzCorpusVal,
    el("span", { class: "dim", style:"font-size:10px;color:#b58900", title:"Higher iterations / corpus can take 5–30s. Reduce for quick triage." }, "⚠ may take time"),
    el("label", { class: "dim", style: "display:flex;gap:4px;align-items:center;margin-left:8px" }, concTick, " Concolic"),
    el("span", { class: "dim" }, "sym:"), concSym, concSymVal,
    el("span", { class: "dim" }, "to ms:"), concTo, concToVal,
    el("span", { class: "dim" }, "queries:"), concQ, concQVal,
    el("span", { class: "dim", style:"font-size:10px;color:#b58900", title:"Concolic solves with Z3 and can take a few seconds per IOCTL, especially with many queries." }, "⚠ may take time"),
  );

  const bugRow = el("div", { class: "analyzer-controls", style: "gap:6px;flex-wrap:wrap;margin-top:6px" },
    el("label", { class: "dim", style: "display:flex;gap:4px;align-items:center;font-weight:600" }, bugTick, " Find bugs"),
    el("span", { class: "dim", style:"font-size:10px;color:#b58900", title:"Runs taint + sink analysis. May take 10–60s per driver. Uses fuzz+concolic stack." }, "⚠ may take time — runs taint & directed fuzz toward sinks"),
    el("span", { class: "dim", style:"font-size:10px" }, "→ reports arbitrary R/W, handle, CR/MSR, alloc, probe, double-fetch, etc."),
  );

  const card = el("div", { class: "card" },
    el("h1", null, "Driver Analyzer"),
    el("p", { class: "dim" },
      "Upload any x64 .sys — it is manual-mapped into the emulated kernel, every import resolves " +
      "(modeled APIs behave; unknown ones become traced stubs), DriverEntry runs under table-SEH, " +
      "deferred work drains, and you can drive MajorFunction with scripted IOCTLs."),
    el("div", { class: "analyzer-controls" },
      fileInput, nameInput, engineSel, loadBtn),
    el("div", { class: "analyzer-controls" },
      el("span", { class: "dim" }, "IOCTL:"),
      ioctlCode, ioctlIn, el("span", { class: "dim" }, "out bytes:"), ioctlOut,
      ioctlBtn, autoIrpBtn, unloadBtn),
    fuzzRow,
    bugRow,
    out,
  );
  main.append(card);

  // ------------------------------------------------------------ helpers

  async function carvedStateOrNull() {
    try {
      const res = await fetch("/dumps/ntsim-state.json");
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  }

  function renderReport(report) {
    const wrap = el("div", { class: "report" });

    const loadSec = el("div", { class: "section" },
      el("h3", null, "Load"),
      kv("base", report.load.base),
      kv("image size", `0x${report.load.imageSize.toString(16)}`),
      kv("relocations", report.load.relocated),
      kv("imports resolved", report.load.imports.length),
      kv("unmodeled (stubbed)", report.load.unmodeledExports.length,
        report.load.unmodeledExports.length ? "warn" : ""),
    );
    if (report.load.unmodeledExports.length) {
      loadSec.append(el("div", { class: "mono dim" },
        report.load.unmodeledExports.slice(0, 24).join(", ") +
        (report.load.unmodeledExports.length > 24 ? " …" : "")));
    }

    const entrySec = el("div", { class: "section" },
      el("h3", null, "DriverEntry"),
      kv("status", report.entry.status, report.entry.status === "ok" ? "ok" : "err"),
    );
    if (report.entry.retval !== undefined) {
      entrySec.append(kv("retval", report.entry.retval));
    }
    if (report.entry.sehHandled) {
      entrySec.append(kv("SEH dispatch", report.entry.sehDetail, "warn"));
    }
    if (report.entry.error) entrySec.append(kv("error", report.entry.error, "err"));

    if (report.deferred) {
      wrap.append(el("div", { class: "section" },
        el("h3", null, "Deferred"),
        kv("DPCs drained", report.deferred.dpcs),
        kv("work items", report.deferred.workItems),
        kv("APCs", report.deferred.apcs),
      ));
    }
    if (report.irqlViolations.length) {
      const sec = el("div", { class: "section" }, el("h3", null, "IRQL violations"));
      for (const v of report.irqlViolations.slice(0, 12)) {
        sec.append(kv(`${v.name}`, `called at IRQL ${v.irql}`, "err"));
      }
      wrap.append(sec);
    }
    if (report.exceptions.length) {
      const sec = el("div", { class: "section" }, el("h3", null, "Exceptions"));
      for (const e of report.exceptions.slice(0, 12)) {
        sec.append(kv(e.faultRip, `${e.handled ? "handled" : "UNHANDLED"} — ${e.detail}`,
          e.handled ? "warn" : "err"));
      }
      wrap.append(sec);
    }

    wrap.append(loadSec, entrySec);

    const trace = report.apiTraceSummary;
    if (trace) {
      const sec = el("div", { class: "section" },
        el("h3", null, `API trace (${trace.totalCalls} calls, ${trace.distinct} distinct)`));
      const names = Object.keys(trace.byName).slice(0, 32);
      sec.append(el("div", { class: "mono dim" }, names.join(", ") +
        (trace.distinct > names.length ? ` … +${trace.distinct - names.length}` : "")));
      wrap.append(sec);
    }

    // chronological call trace (ktrace-style)
    if (report.traceText) {
      const sec = el("div", { class: "section" },
        el("h3", null, `Call trace (${(report.trace ?? []).length} events)`));
      const pre = el("pre", { class: "mono trace-log" });
      pre.textContent = report.traceText;
      sec.append(pre);
      const dl = el("button", { class: "btn btn-sm", type: "button" }, "Download trace");
      dl.addEventListener("click", () => {
        const blob = new Blob([report.traceText], { type: "text/plain" });
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = `${report.load?.driverName ?? "driver"}.trace.txt`;
        a.click();
        URL.revokeObjectURL(a.href);
      });
      const cp = el("button", { class: "btn btn-sm", type: "button" }, "Copy");
      cp.addEventListener("click", async () => {
        try { await navigator.clipboard.writeText(report.traceText); } catch { /* denied */ }
      });
      sec.append(el("div", { class: "row gap" }, dl, cp));
      wrap.append(sec);
    }

    if (report.dbgLog.length) {
      const sec = el("div", { class: "section" }, el("h3", null, "DbgPrint"));
      for (const line of report.dbgLog.slice(0, 64)) {
        sec.append(el("div", { class: "mono" }, line));
      }
      wrap.append(sec);
    }
    out.prepend(wrap);
  }

  function renderIoctl(io) {
    const sec = el("div", { class: "section" });
    const statusHex = io.ntstatus !== undefined
      ? `0x${BigInt.asUintN(32, io.ntstatus).toString(16).padStart(8, "0")}`
      : "—";
    const title = io.majorName === "__fuzz_summary"
      ? `Fuzz summary for 0x${io.ioctl?.toString(16) ?? ""}`
      : `IOCTL ${io.majorName ?? "DEVICE_CONTROL"}${io.source ? ` [${io.source}]` : ""}`;
    sec.append(
      el("h3", null, title),
      kv("ntstatus", `${statusHex} ${NTSTATUS_NAME(statusHex)}`,
        io.ntstatus === 0n ? "ok" : "warn"),
      kv("information", io.information?.toString() ?? "—"),
      kv("steps", io.steps ?? "—"),
    );
    if (io.inputHex) sec.append(kv("input", io.inputHex.slice(0,96), "mono"));
    if (io.coverage) {
      const covStr = io.coverage.blocks !== undefined ? `blocks ${io.coverage.blocks} edges ${io.coverage.edges ?? 0}`
        : io.coverage.corpus !== undefined ? `corpus ${io.coverage.corpus} blocks ${io.coverage.globalBlocks} iters ${io.coverage.iterations}`
        : JSON.stringify(io.coverage);
      sec.append(kv("coverage", covStr, "dim"));
    }
    if (io.outputHex && io.majorName !== "__fuzz_summary") sec.append(el("div", { class: "mono" }, io.outputHex.slice(0, 256)));
    if (io.smt2) {
      const pre = el("pre", { class: "mono dim", style: "max-height:120px;overflow:auto;font-size:11px" }, io.smt2.slice(0, 800));
      sec.append(el("div", { class: "kv" }, el("span", { class: "k" }, "SMT2"), pre));
    }
    if (io.error) sec.append(kv("error", io.error, "err"));
    out.append(sec);
  }

  function liveLine(msg, cls) {
    out.append(el("div", { class: `line ${cls ?? ""}` }, msg));
  }

  // -------------------------------------------------------------- actions

  loadBtn.addEventListener("click", async () => {
    const file = fileInput.files?.[0];
    if (!file) {
      log("pick a .sys file first", "err");
      return;
    }
    loadBtn.disabled = true;
    loadBtn.textContent = "analyzing…";
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const opts = {
        name: nameInput.value || "uploaded.sys",
        backendName: engineSel.value,
        tables: await loadTables(),
        carvedState: await carvedStateOrNull(),
        runUnload: false,
      };
      if (engineSel.value === "hybrid") {
        opts.makeBackend = async () => {
          const { HybridCpuBackend } = await import("@kernelforge/ntsim-unicorn/src/hybrid.mjs");
          const b = await HybridCpuBackend.create(null);
          return b;
        };
      } else if (engineSel.value === "unicorn") {
        opts.makeBackend = async () => {
          // pure Unicorn — high ISA coverage, WASM bundle lazy-loaded only here
          let mod;
          try {
            mod = await import("@kernelforge/ntsim-unicorn");
          } catch (e) {
            try { mod = await import("@kernelforge/ntsim-unicorn/src/backend.mjs"); } catch (_) { throw e; }
          }
          const createUnicornBackend =
            mod.createUnicornBackend ??
            mod.default?.createUnicornBackend ??
            mod.default ??
            mod.create;
          if (typeof createUnicornBackend !== "function") {
            throw new Error(`ntsim-unicorn: createUnicornBackend factory not found (exports: ${Object.keys(mod).join(", ")})`);
          }
          return await createUnicornBackend(null);
        };
      }
      const report = await analyzeDriver(bytes, opts);
      renderReport(report);
      log(`loaded ${file.name} (${bytes.length} bytes, engine=${opts.backendName})`, "ok");
      ioctlBtn.disabled = false;
      autoIrpBtn.disabled = false;
      unloadBtn.disabled = false;

      if (report.harvestedIoctls?.length) {
        const sec = el("div", { class: "section" },
          el("h3", null, `Harvested CTL_CODEs (${report.harvestedIoctls.length})`));
        sec.append(el("div", { class: "mono dim" },
          report.harvestedIoctls.map((h) => h.hex).join(", ")));
        out.prepend(sec);
      }

      // analyzeDriver returns the live kernel session for interactive IOCTLs
      session = report.__session;
      // store imageSize for coverage hook (mapped size, not file length)
      if (session && report.load) {
        session.imageSize = report.load.imageSize;
        // ensure base is BigInt
        if (typeof session.image.base === "string") session.image.base = BigInt(session.image.base);
      }
    } catch (e) {
      log(`load failed: ${e.message}`, "err");
    } finally {
      loadBtn.disabled = false;
      loadBtn.textContent = "Load & run DriverEntry";
    }
  });

  ioctlBtn.addEventListener("click", async () => {
    if (!session) return;
    ioctlBtn.disabled = true;
    try {
      const r = await sendIrp(session.kernel, session.device, {
        major: 0x0e, // IRP_MJ_DEVICE_CONTROL
        ioctl: ioctlCode.value.replace(/^0x/i, ""),
        inputHex: ioctlIn.value,
        outputLen: Number(ioctlOut.value) || 0,
      });
      renderIoctl({
        ...r,
        error: r.error ? String(r.error.message ?? r.error) : undefined,
      });
      for (const line of session.kernel.dbgLog.splice(0)) liveLine(line, "mono");
      for (const ex of session.kernel.exceptionTrace.splice(0)) {
        liveLine(`[seh] ${ex.faultRip}: ${ex.handled ? "handled" : "UNHANDLED"} — ${ex.detail}`,
          ex.handled ? "warn" : "err");
      }
      for (const v of session.kernel.irqlViolations.splice(0)) {
        liveLine(`[irql] ${v.name} at IRQL ${v.irql}`, "err");
      }
    } finally {
      ioctlBtn.disabled = false;
    }
  });

  function renderBugSummary(bugs, detailedLog) {
    const wrap = el("div", { class: "section", style:"border:2px solid #d73a49;padding:10px;border-radius:8px" },
      el("h3", null, `Find Bugs — ${bugs.length} potential vuln${bugs.length===1?"":"s"} found`));
    if (!bugs.length) {
      wrap.append(el("div", { class:"mono dim" }, "No sinks triggered with tainted data. Try larger corpus / enable concolic, or check that SystemBuffer is actually used as pointer/length."));
      const dl = el("button", { class:"btn btn-sm", type:"button" }, `Download full log (${detailedLog.length} lines)`);
      dl.addEventListener("click", ()=>{
        const blob=new Blob([detailedLog.join("\n")],{type:"text/plain"});
        const a=document.createElement("a"); a.href=URL.createObjectURL(blob); a.download=`findbugs-${new Date().toISOString().slice(0,19)}.log`; a.click(); URL.revokeObjectURL(a.href);
      });
      wrap.append(el("div", {class:"row gap", style:"margin-top:8px"}, dl));
      out.append(wrap);
      return;
    }
    // group by severity
    const bySev = {};
    for(const b of bugs){ const s=b.severity||0; const key=s>=10?"CRITICAL":s>=8?"HIGH":s>=5?"MEDIUM":s>=3?"LOW":"INFO"; (bySev[key]??=[]).push(b); bySev[key]=(bySev[key]||[]); }
    // sort within each group by controlDegree
    const order = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"];
    for(const sev of order){
      const list=bySev[sev];
      if(!list||!list.length) continue;
      const sec = el("div", { class:"section", style:"margin:8px 0" }, el("h4", null, `${sev} — ${list.length}`));
      for(const b of list.slice(0,12)){
        const row = el("div", { class:"section", style:"margin:6px 0;padding:6px;border:1px solid #444;border-radius:6px" },
          el("div", { style:"font-weight:600" }, `${b.sinkType} — ${b.sinkApi||""} @ ${b.sinkLocation}`),
          kv("IOCTL", b.ioctlCode, "dim"),
          kv("control", b.controlDegree, b.controlDegree==="full"?"err":b.controlDegree==="bounded"?"warn":"dim"),
          kv("location", b.sinkLocation, "dim"),
          kv("witness", (b.witnessInput||"").slice(0,48), "mono"),
        );
        if(b.taintedOperands?.length){
          for(const op of b.taintedOperands.slice(0,2)){
            row.append(el("div", {class:"mono dim", style:"font-size:11px"}, `tainted ${op.role||op.pos}: ${op.value||op.addr||""} ids ${op.taintIds||""}`));
          }
        }
        if(b.pathConstraints) row.append(el("pre", {class:"mono dim", style:"max-height:80px;overflow:auto;font-size:10px"}, String(b.pathConstraints).slice(0,300)));
        const cp = el("button", {class:"btn btn-sm", type:"button", style:"padding:0 4px;font-size:10px"}, "copy witness");
        cp.addEventListener("click", async()=>{ try{ await navigator.clipboard.writeText(b.witnessInput||""); }catch{} });
        row.append(cp);
        sec.append(row);
      }
      wrap.append(sec);
    }
    const blobJson = JSON.stringify(bugs, null, 2);
    const dlJson = el("button", {class:"btn btn-sm", type:"button"}, `Download bug report JSON (${bugs.length})`);
    dlJson.addEventListener("click", ()=>{
      const blob=new Blob([blobJson],{type:"application/json"});
      const a=document.createElement("a"); a.href=URL.createObjectURL(blob); a.download=`bugs-${new Date().toISOString().slice(0,19)}.json`; a.click(); URL.revokeObjectURL(a.href);
    });
    const dlLog = el("button", {class:"btn btn-sm", type:"button"}, `Download full log (${detailedLog.length} lines)`);
    dlLog.addEventListener("click", ()=>{
      const blob=new Blob([detailedLog.join("\n")],{type:"text/plain"});
      const a=document.createElement("a"); a.href=URL.createObjectURL(blob); a.download=`findbugs-${new Date().toISOString().slice(0,19)}.log`; a.click(); URL.revokeObjectURL(a.href);
    });
    const cpAll = el("button", {class:"btn btn-sm", type:"button"}, "Copy summary");
    cpAll.addEventListener("click", async()=>{ try{ await navigator.clipboard.writeText(wrap.innerText);}catch{} });
    wrap.append(el("div", {class:"row gap", style:"margin-top:8px"}, dlJson, dlLog, cpAll));
    out.append(wrap);
  }

  function renderAutoDriveSummary(results, harvested, detailedLog) {
    const wrap = el("div", { class: "section" },
      el("h3", null, `Auto-drive summary (${harvested.length} IOCTL${harvested.length===1?"":"s"} probed)`));

    // stats
    const devCtrls = results.filter(r => r.majorName === "DEVICE_CONTROL");
    const valid = devCtrls.filter(r => r.ntstatus === 0n);
    const lifecycle = results.filter(r => r.majorName === "CREATE" || r.majorName === "CLOSE");
    wrap.append(
      kv("trials", `${devCtrls.length} DEVICE_CONTROL + ${lifecycle.length} lifecycle`),
      kv("valid (likely good inputs)", `${valid.length}`, valid.length ? "ok" : ""),
      kv("unique IOCTL codes", `${harvested.length}`),
    );
    if (lifecycle.length) {
      const lc = lifecycle.map(r => `${r.majorName}: ${r.ntstatus===0n?"ok":"fail"} 0x${(r.ntstatus??0n).toString(16)}`).join(", ");
      wrap.append(el("div", { class: "mono dim" }, lc));
    }

    // per-code summary, top inputs by coverage
    for (const code of harvested) {
      const entries = results.filter(r => r.majorName === "DEVICE_CONTROL" && r.ioctl === BigInt(code.value));
      if (!entries.length) continue;
      // sort by coverage blocks desc, then valid first
      const sorted = [...entries].sort((a,b) => {
        const ca = a.coverage?.blocks ?? 0, cb = b.coverage?.blocks ?? 0;
        if (cb !== ca) return cb - ca;
        const va = a.ntstatus===0n ? -1 : 0, vb = b.ntstatus===0n ? -1 : 0;
        return va - vb;
      });
      const top = sorted.slice(0, 3);
      const bestValid = sorted.find(r => r.ntstatus===0n);
      const covBlocks = Math.max(...entries.map(e=>e.coverage?.blocks??0), 0);
      const codeHex = `0x${code.value.toString(16).padStart(8,"0")}`;
      const sec = el("div", { class: "section", style: "margin:8px 0;padding:8px;border:1px solid var(--border, #333);border-radius:6px" },
        el("h4", { style:"margin:0 0 6px 0" }, `IOCTL ${codeHex} — ${entries.length} trial${entries.length===1?"":"s"}, best ${covBlocks} blocks${bestValid ? ", 1+ valid ✓" : ""}`),
        kv("rva", `0x${code.rva.toString(16)}`, "dim"),
      );
      if (bestValid) {
        sec.append(kv("best valid input", `${(bestValid.inputHex??"").slice(0,32)}${(bestValid.inputHex?.length??0)>32?"…":""} — ${bestValid.coverage?`blocks ${bestValid.coverage.blocks}`:""} — STATUS_SUCCESS`, "ok"));
        if (bestValid.outputHex) sec.append(el("div", { class: "mono dim", style:"font-size:11px;word-break:break-all" }, `out: ${bestValid.outputHex.slice(0,64)}${bestValid.outputHex.length>64?"…":""}`));
      } else {
        sec.append(el("div", { class: "mono dim" }, "no STATUS_SUCCESS — likely need different structure / try larger corpus or enable concolic"));
      }
      sec.append(el("div", { class: "dim", style:"margin-top:6px;font-weight:600" }, "Top coverage inputs:"));
      for (let i=0;i<top.length;i++) {
        const e = top[i];
        const stHex = e.ntstatus!==undefined ? `0x${BigInt.asUintN(32,e.ntstatus).toString(16).padStart(8,"0")}` : "—";
        const likely = e.ntstatus===0n ? "✓ likely valid" : "—";
        const row = el("div", { class: "mono", style:"font-size:11px;display:flex;gap:8px;align-items:center;flex-wrap:wrap" },
          el("span", null, `#${i+1}`),
          el("span", { style:"font-weight:600" }, (e.inputHex??"").slice(0,32) + ((e.inputHex?.length??0)>32?"…":"")),
          el("span", { class:"dim" }, `blocks ${e.coverage?.blocks??0}${e.coverage?.edges!==undefined?` edges ${e.coverage.edges}`:""} ${e.source?`[${e.source}]`:""}`),
          el("span", { class: e.ntstatus===0n?"ok":"dim" }, `${stHex} ${likely}`),
        );
        // copy button
        if (e.inputHex) {
          const cp = el("button", { class:"btn btn-sm", type:"button", style:"padding:0 4px;font-size:10px" }, "copy");
          cp.addEventListener("click", async ()=> { try{ await navigator.clipboard.writeText(e.inputHex);}catch{} });
          row.append(cp);
        }
        sec.append(row);
        if (e.outputHex) sec.append(el("div", { class:"mono dim", style:"font-size:10px;word-break:break-all" }, `  out ${e.outputHex.slice(0,48)}`));
      }
      wrap.append(sec);
    }

    // full-log download
    const logText = detailedLog.join("\n") + "\n\n# --- per-result JSON ---\n" + results.map(r => {
      const o = {...r};
      if (typeof o.ntstatus==="bigint") o.ntstatus = `0x${o.ntstatus.toString(16)}`;
      if (typeof o.ioctl==="bigint") o.ioctl = `0x${o.ioctl.toString(16)}`;
      if (typeof o.information==="bigint") o.information = o.information.toString();
      return JSON.stringify(o);
    }).join("\n");
    const dl = el("button", { class:"btn btn-sm", type:"button" }, `Download full log (${detailedLog.length} lines)`);
    dl.addEventListener("click", ()=>{
      const blob=new Blob([logText],{type:"text/plain"});
      const a=document.createElement("a");
      a.href=URL.createObjectURL(blob);
      a.download=`autodrive-${new Date().toISOString().slice(0,19)}.log`;
      a.click();
      URL.revokeObjectURL(a.href);
    });
    const cpAll = el("button", { class:"btn btn-sm", type:"button" }, "Copy summary");
    cpAll.addEventListener("click", async ()=>{
      try{ await navigator.clipboard.writeText(wrap.innerText);}catch{}
    });
    wrap.append(el("div", { class:"row gap", style:"margin-top:8px" }, dl, cpAll));

    // also stash concise live line
    liveLine(`auto-drive done: ${devCtrls.length} trials, ${valid.length} valid, ${harvested.length} codes — full log ${detailedLog.length} lines (download below)`, valid.length?"ok":"dim");

    out.append(wrap);
  }

  autoIrpBtn.addEventListener("click", async () => {
    if (!session) return;
    autoIrpBtn.disabled = true;
    const detailedLog = [];
    const pushLog = (msg) => detailedLog.push(`[${new Date().toISOString().slice(11,19)}] ${msg}`);
    try {
      const { harvestCtlCodes, autoDriveIrps } =
        await import("@kernelforge/ntsim-analyzer/src/autoirp.mjs");
      const harvested = harvestCtlCodes(session.image.bytes, parsePe(session.image.bytes), {});
      pushLog(`auto-drive: MJ_CREATE + ${harvested.length} harvested code(s) + MJ_CLOSE`);
      const fuzz = fuzzTick.checked ? {
        iterations: Number(fuzzIter.value) || 256,
        corpusCap: Number(fuzzCorpus.value) || 32,
        inputLen: 16,
      } : null;
      const concolic = concTick.checked ? {
        maxSymBytes: Number(concSym.value) || 64,
        solverTimeoutMs: Number(concTo.value) || 300,
        maxQueries: Number(concQ.value) || 8,
        inputLen: 16,
      } : null;
      if (fuzz) pushLog(`[fuzz] iters=${fuzz.iterations} corpus=${fuzz.corpusCap}`);
      if (concolic) pushLog(`[concolic] sym=${concolic.maxSymBytes} timeout=${concolic.solverTimeoutMs}ms queries=${concolic.maxQueries}`);
      if (concolic && engineSel.value === "unicorn") {
        pushLog(`note: concolic runs on JS shadow and replays witness on Unicorn`);
      }
      const findBugs = bugTick.checked;
      if (findBugs && !fuzz) pushLog(`[find-bugs] fuzz auto-enabled for directed analysis`);
      liveLine(`auto-driving ${harvested.length} IOCTLs${fuzz?" + fuzz":""}${concolic?" + concolic":""}${findBugs?" + find-bugs":""}…`, "dim");
      const base = session.image.base ?? DRIVER_BASE;
      const size = session.imageSize ?? session.image.bytes.length;
      const driverHash = [...session.image.bytes.slice(0,64)].map(b=>b.toString(16).padStart(2,"0")).join("").slice(0,16);
      const results = await autoDriveIrps(session.kernel, session.device, {
        sendIrp,
        harvested,
        maxCodes: 32,
        imageBase: base,
        imageSize: size,
        fuzz: findBugs && !fuzz ? { iterations: 64, corpusCap: 16, inputLen: 16 } : fuzz,
        concolic,
        outputLen: 64,
        onPhase: (label) => { pushLog(`[phase] ${label}`); },
      });
      // capture kernel logs into detailedLog, not verbose UI
      for (const line of session.kernel.dbgLog.splice(0)) pushLog(`[dbg] ${line}`);
      for (const ex of session.kernel.exceptionTrace.splice(0)) pushLog(`[seh] ${ex.faultRip}: ${ex.handled ? "handled" : "UNHANDLED"} — ${ex.detail}`);
      for (const v of session.kernel.irqlViolations.splice(0)) pushLog(`[irql] ${v.name} at IRQL ${v.irql}`);
      if (fuzz || concolic || findBugs) {
        // per-result debug into detailed log
        for (const r of results) {
          if (r.majorName==="DEVICE_CONTROL") {
            pushLog(`[result] ioctl 0x${(r.ioctl??0n).toString(16)} src=${r.source??"canned"} blocks=${r.coverage?.blocks??0} nt=0x${(r.ntstatus??0n).toString(16)} in=${(r.inputHex??"").slice(0,32)}`);
          }
        }
      }
      // render only summary, not every trial
      renderAutoDriveSummary(results, harvested, detailedLog);

      if (findBugs) {
        try {
          liveLine(`find-bugs: taint analysis + directed fuzz toward sinks…`, "dim");
          const allBugs = [];
          const maxCodesForBugs = Math.min(harvested.length, 8);
          const useWorkers = typeof Worker !== "undefined" && maxCodesForBugs > 1 && (navigator.hardwareConcurrency||4) > 2;
          if (useWorkers) {
            pushLog(`[find-bugs] using ${Math.min(maxCodesForBugs, navigator.hardwareConcurrency||2)} workers for parallel probing`);
            // parallel via bugWorker — serialize tables for worker bootstrap
            function serializeTables(tbl){
              const out=[];
              for(const [k,v] of tbl.types.entries()){
                out.push([k, {totalSize: v.totalSize, fieldsByName: v.fieldsByName, fields: v.fields}]);
              }
              return out;
            }
            const tablesData = serializeTables(session.kernel.tables);
            const workerUrl = new URL("./workers/bugWorker.mjs", import.meta.url);
            const poolSize = Math.min(maxCodesForBugs, navigator.hardwareConcurrency||4, 4);
            let nextIdx = 0;
            const results = [];
            const runOne = (code, idx) => new Promise((resolve, reject)=>{
              const w = new Worker(workerUrl, { type:"module" });
              const timeout = setTimeout(()=>{ w.terminate(); reject(new Error("worker timeout")); }, 30000);
              w.onmessage = (e)=>{
                const {type, result, error} = e.data;
                if(type==="done"){
                  clearTimeout(timeout); w.terminate();
                  pushLog(`[find-bugs][worker] done ioctl 0x${code.value.toString(16)} bugs ${result.bugs.length}`);
                  resolve(result.bugs);
                } else if(type==="error"){
                  clearTimeout(timeout); w.terminate(); reject(new Error(error));
                }
              };
              w.onerror = (err)=>{ clearTimeout(timeout); w.terminate(); reject(err); };
              // transfer imageBytes (clone) + tables
              w.postMessage({ type:"run", id: idx, imageBytes: session.image.bytes, ctlCode: code.value, base: base.toString(), size: size.toString(), tablesData, opts:{ iterations: fuzz?fuzz.iterations:96, corpusCap: fuzz?fuzz.corpusCap:16, driverHash } });
            });
            // simple pool
            const queue = harvested.slice(0, maxCodesForBugs);
            const running = [];
            for(const code of queue){
              const p = runOne(code, queue.indexOf(code)).then(bugs=>{ allBugs.push(...bugs); for(const b of bugs) pushLog(`[bug][worker] ${b.sinkType} ${b.controlDegree} @${b.sinkLocation} ioctl ${b.ioctlCode}`); }).catch(e=>{ pushLog(`[find-bugs][worker] failed for 0x${code.value.toString(16)}: ${e.message}`); });
              running.push(p);
              if(running.length >= poolSize){
                await Promise.race(running);
              }
            }
            await Promise.allSettled(running);
            renderBugSummary(allBugs, detailedLog);
          } else {
            const { findBugsCampaign } = await import("@kernelforge/ntsim-analyzer/src/bug/engine.mjs");
            for (let i=0;i<maxCodesForBugs;i++) {
              const code = harvested[i];
              pushLog(`[find-bugs] probing ioctl 0x${code.value.toString(16)} (${i+1}/${maxCodesForBugs})`);
              liveLine(`[find-bugs] probing 0x${code.value.toString(16)} ${i+1}/${maxCodesForBugs}…`, "dim");
              const { bugDB } = await findBugsCampaign(session.kernel, session.device, code.value, {
                sendIrp, imageBase: base, imageSize: size,
                iterations: fuzz ? fuzz.iterations : 96,
                corpusCap: fuzz ? fuzz.corpusCap : 16,
                inputLen: 16, outputLen: 64,
                driverHash,
                onProgress: (evt)=>{
                  if (evt.phase==="bug-found") pushLog(`[bug] ${evt.bug.sinkType} ${evt.bug.controlDegree} at ${evt.bug.sinkLocation} ioctl 0x${code.value.toString(16)}`);
                }
              });
              for (const b of bugDB.all()) {
                pushLog(`[bug] ${b.sinkType} ${b.controlDegree} ${b.sinkApi||""} @${b.sinkLocation} ioctl ${b.ioctlCode} witness ${b.witnessInput?.slice(0,16)}`);
                allBugs.push(b);
              }
              for (const line of session.kernel.dbgLog.splice(0)) pushLog(`[dbg] ${line}`);
            }
            renderBugSummary(allBugs, detailedLog);
          }
        } catch (e) {
          pushLog(`[find-bugs] failed: ${e.message} ${e.stack?.slice(0,500)}`);
          liveLine(`find-bugs failed: ${e.message}`, "err");
        }
      }
      if (session.kernel.bugcheck || session.kernel.crash) {
        pushLog(`bugcheck during auto-drive: ${JSON.stringify(session.kernel.bugcheck ?? session.kernel.crash)}`);
        liveLine(`bugcheck during auto-drive: ${JSON.stringify(session.kernel.bugcheck ?? session.kernel.crash)}`, "err");
        unloadBtn.disabled = true;
      }
      // also keep detailedLog available as downloadable file via summary button
    } finally {
      autoIrpBtn.disabled = false;
    }
  });

  unloadBtn.addEventListener("click", async () => {
    if (!session) return;
    unloadBtn.disabled = true;
    try {
      const r = await callDriverUnload(session.kernel, session.drvRec);
      liveLine(`unload: ${r.status}${r.retval !== undefined ? ` (0x${r.retval.toString(16)})` : ""}`);
    } finally {
      unloadBtn.disabled = false;
    }
  });
}
