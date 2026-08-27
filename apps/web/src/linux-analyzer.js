/**
 * linux-analyzer.js — run-any-.ko analysis tab (Linux analog of analyzer.js).
 * Upload an ELF64 ET_REL .ko, relocs are applied against shims, init_module
 * runs under SysV ABI, file_operations are harvested, and you can drive
 * unlocked_ioctl/read/write/mmap/proc/netlink with fuzz+concolic+bugs.
 */
import { analyzeKo } from "@kernelforge/linux-analyzer/src/index.mjs";
import { sendFileOp } from "@kernelforge/linux-sim/src/file-ops.mjs";

const LINUX_MODULE_BASE = 0xffffffffc0000000n;

function el(tag, attrs, ...children){
  const e=document.createElement(tag);
  for(const [k,v] of Object.entries(attrs??{})){
    if(k==="class") e.className=v;
    else if(k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if(v!==undefined && v!==null) e.setAttribute(k, String(v));
  }
  for(const c of children) e.append(c);
  return e;
}
function kv(label,value,cls){
  return el("div",{class:`kv ${cls??""}`},
    el("span",{class:"k"},label),
    el("span",{class:"v"}, String(value)),
  );
}

export function renderLinuxAnalyzer(main){
  main.innerHTML="";
  let session=null;

  const fileInput=el("input",{type:"file", accept:".ko,.o"});
  const engineSel=el("select",{},
    el("option",{value:"js"},"JsInterpreter (deterministic)"),
    el("option",{value:"hybrid"},"Hybrid (JS + Unicorn fallback)"),
    el("option",{value:"unicorn"},"Unicorn (WASM-only)"),
  );
  const nameInput=el("input",{type:"text", placeholder:"uploaded.ko", value:"uploaded.ko", title:"Module name — seeds modinfo. Auto-filled from file."});
  fileInput.addEventListener("change",()=>{
    const f=fileInput.files?.[0];
    if(f) nameInput.value=f.name;
  });
  const loadBtn=el("button",{class:"primary"},"Load & run init_module");

  // file_op controls
  const opSel=el("select",{title:"file_operations target"},
    el("option",{value:"unlocked_ioctl"},"unlocked_ioctl"),
    el("option",{value:"compat_ioctl"},"compat_ioctl"),
    el("option",{value:"read"},"read"),
    el("option",{value:"write"},"write"),
    el("option",{value:"mmap"},"mmap"),
    el("option",{value:"open"},"open"),
    el("option",{value:"release"},"release"),
    el("option",{value:"proc_show"},"proc_show (read)"),
    el("option",{value:"proc_store"},"proc_store (write)"),
    el("option",{value:"netlink"},"netlink"),
  );
  const cmdInput=el("input",{type:"text", placeholder:"0x0 (ioctl cmd)", value:"0x0"});
  const argInput=el("input",{type:"text", placeholder:"input hex (e.g. deadbeef)"});
  const outLenInput=el("input",{type:"number", value:"64", min:"0", max:"4096"});
  const sendBtn=el("button",{}, "Send FileOp");
  sendBtn.disabled=true;
  const autoBtn=el("button",{title:"Drive open + every harvested file_operation with synthetic buffers"},"Auto-drive ops");
  autoBtn.disabled=true;

  const LS={
    get(k,d){ try{ const v=localStorage.getItem(k); return v!==null?v:d; }catch{ return d; }},
    set(k,v){ try{ localStorage.setItem(k,String(v)); }catch{} },
  };
  const fuzzTick=el("input",{type:"checkbox", title:"Coverage-guided fuzzing"});
  fuzzTick.checked=LS.get("linux-analyzer.fuzz.enabled","false")==="true";
  fuzzTick.addEventListener("change",()=> LS.set("linux-analyzer.fuzz.enabled", fuzzTick.checked));
  const fuzzIter=el("input",{type:"range", min:"64", max:"1024", step:"64", value:LS.get("linux-analyzer.fuzz.iter","256")});
  const fuzzIterVal=el("span",{class:"dim"}, fuzzIter.value);
  fuzzIter.addEventListener("input",()=>{ fuzzIterVal.textContent=fuzzIter.value; LS.set("linux-analyzer.fuzz.iter", fuzzIter.value);});
  const fuzzCorpus=el("input",{type:"range", min:"8", max:"64", step:"8", value:LS.get("linux-analyzer.fuzz.corpus","32")});
  const fuzzCorpusVal=el("span",{class:"dim"}, fuzzCorpus.value);
  fuzzCorpus.addEventListener("input",()=>{ fuzzCorpusVal.textContent=fuzzCorpus.value; LS.set("linux-analyzer.fuzz.corpus", fuzzCorpus.value);});
  const concTick=el("input",{type:"checkbox", title:"Concolic execution (Z3, JS backend)"});
  concTick.checked=LS.get("linux-analyzer.conc.enabled","false")==="true";
  concTick.addEventListener("change",()=> LS.set("linux-analyzer.conc.enabled", concTick.checked));
  const concSym=el("input",{type:"range", min:"16", max:"128", step:"8", value:LS.get("linux-analyzer.conc.sym","64")});
  const concSymVal=el("span",{class:"dim"}, concSym.value);
  concSym.addEventListener("input",()=>{ concSymVal.textContent=concSym.value; LS.set("linux-analyzer.conc.sym", concSym.value);});
  const concTo=el("input",{type:"range", min:"100", max:"1000", step:"100", value:LS.get("linux-analyzer.conc.to","300")});
  const concToVal=el("span",{class:"dim"}, concTo.value);
  concTo.addEventListener("input",()=>{ concToVal.textContent=concTo.value; LS.set("linux-analyzer.conc.to", concTo.value);});
  const concQ=el("input",{type:"range", min:"1", max:"16", step:"1", value:LS.get("linux-analyzer.conc.queries","8")});
  const concQVal=el("span",{class:"dim"}, concQ.value);
  concQ.addEventListener("input",()=>{ concQVal.textContent=concQ.value; LS.set("linux-analyzer.conc.queries", concQ.value);});
  const bugTick=el("input",{type:"checkbox", title:"Find Bugs — taint + sink analysis"});
  bugTick.checked=LS.get("linux-analyzer.bugs.enabled","false")==="true";
  bugTick.addEventListener("change",()=>{
    LS.set("linux-analyzer.bugs.enabled", bugTick.checked);
    if(bugTick.checked && !fuzzTick.checked){ fuzzTick.checked=true; LS.set("linux-analyzer.fuzz.enabled", true); }
  });
  const cleanupBtn=el("button",{},"Call cleanup_module");
  cleanupBtn.disabled=true;

  const out=el("div",{class:"analyzer-out"});
  const log=(msg,cls)=> out.append(el("div",{class:`line ${cls??""}`},msg));

  const fuzzRow=el("div",{class:"analyzer-controls", style:"gap:6px;flex-wrap:wrap"},
    el("label",{class:"dim", style:"display:flex;gap:4px;align-items:center"}, fuzzTick, " Fuzz"),
    el("span",{class:"dim"},"iters:"), fuzzIter, fuzzIterVal,
    el("span",{class:"dim"},"corpus:"), fuzzCorpus, fuzzCorpusVal,
    el("span",{class:"dim", style:"font-size:10px;color:#b58900", title:"Higher iterations / corpus can take 5–30s. Reduce for quick triage."},"⚠ may take time"),
    el("label",{class:"dim", style:"display:flex;gap:4px;align-items:center;margin-left:8px"}, concTick, " Concolic"),
    el("span",{class:"dim"},"sym:"), concSym, concSymVal,
    el("span",{class:"dim"},"to ms:"), concTo, concToVal,
    el("span",{class:"dim"},"queries:"), concQ, concQVal,
    el("span",{class:"dim", style:"font-size:10px;color:#b58900"},"⚠ may take time"),
  );
  const bugRow=el("div",{class:"analyzer-controls", style:"gap:6px;flex-wrap:wrap;margin-top:6px"},
    el("label",{class:"dim", style:"display:flex;gap:4px;align-items:center;font-weight:600"}, bugTick, " Find bugs"),
    el("span",{class:"dim", style:"font-size:10px;color:#b58900"},"⚠ runs taint & directed fuzz toward sinks"),
    el("span",{class:"dim", style:"font-size:10px"},"→ reports arbitrary R/W, cred escalation, kmalloc, double-fetch, etc."),
  );

  const card=el("div",{class:"card"},
    el("h1",null,"Linux Driver Analyzer"),
    el("p",{class:"dim"},
      "Upload any x86_64 .ko (ELF64 ET_REL, 6.6.18) — relocs applied against shims, init_module runs via SysV ABI, "+
      "file_operations captured (register_chrdev/misc_register/proc_create/netlink), then drive ops with fuzz+concolic."),
    el("div",{class:"analyzer-controls"}, fileInput, nameInput, engineSel, loadBtn),
    el("div",{class:"analyzer-controls"},
      el("span",{class:"dim"},"Op:"), opSel,
      el("span",{class:"dim"},"cmd:"), cmdInput,
      el("span",{class:"dim"},"arg hex:"), argInput,
      el("span",{class:"dim"},"out bytes:"), outLenInput,
      sendBtn, autoBtn, cleanupBtn),
    fuzzRow,
    bugRow,
    out,
  );
  main.append(card);

  function renderReport(report){
    const wrap=el("div",{class:"report"});
    const loadSec=el("div",{class:"section"},
      el("h3",null,"Load"),
      kv("base", report.load.base),
      kv("image size", `0x${report.load.imageSize?.toString(16) ?? "0"}`),
      kv("applied relocs", report.load.applied ?? 0),
      kv("unmodeled (stubbed)", report.load.unmodeledExports.length, report.load.unmodeledExports.length?"warn":""),
      kv("init_module", report.load.init ?? "none"),
      kv("cleanup_module", report.load.cleanup ?? "none"),
    );
    if(report.load.unmodeledExports.length){
      loadSec.append(el("div",{class:"mono dim"}, report.load.unmodeledExports.slice(0,24).join(", ")+(report.load.unmodeledExports.length>24?" …":"")));
    }
    if(report.load.modinfo) loadSec.append(el("div",{class:"mono dim"}, `modinfo: ${JSON.stringify(report.load.modinfo).slice(0,200)}`));
    const initSec=el("div",{class:"section"},
      el("h3",null,"init_module"),
      kv("status", report.init.status, report.init.status==="ok"?"ok":"err"),
    );
    if(report.init.retval!==undefined) initSec.append(kv("retval", report.init.retval));
    if(report.init.error) initSec.append(kv("error", report.init.error,"err"));
    wrap.append(loadSec, initSec);
    if(report.harvestedOps?.length){
      const sec=el("div",{class:"section"}, el("h3",null,`Harvested file_operations (${report.harvestedOps.length})`));
      sec.append(el("div",{class:"mono dim"}, report.harvestedOps.map(h=>`${h.op}@${h.va}`).join(", ")));
      wrap.append(sec);
    }
    if(report.harvestedOpsStatic?.length){
      const sec=el("div",{class:"section"}, el("h3",null,`Static candidates (${report.harvestedOpsStatic.length})`));
      sec.append(el("div",{class:"mono dim"}, report.harvestedOpsStatic.map(h=>`${h.sec}+${h.off}`).join(", ")));
      wrap.append(sec);
    }
    if(report.apiTraceSummary){
      const sec=el("div",{class:"section"}, el("h3",null,`API trace (${report.apiTraceSummary.totalCalls} calls, ${report.apiTraceSummary.distinct} distinct)`));
      const names=Object.keys(report.apiTraceSummary.byName).slice(0,32);
      sec.append(el("div",{class:"mono dim"}, names.join(", ")+(report.apiTraceSummary.distinct>names.length?` … +${report.apiTraceSummary.distinct-names.length}`:"")));
      wrap.append(sec);
    }
    if(report.traceText){
      const sec=el("div",{class:"section"}, el("h3",null,`Call trace (${(report.trace??[]).length} events)`));
      const pre=el("pre",{class:"mono trace-log"}); pre.textContent=report.traceText;
      sec.append(pre);
      wrap.append(sec);
    }
    if(report.dbgLog.length){
      const sec=el("div",{class:"section"}, el("h3",null,"printk"));
      for(const line of report.dbgLog.slice(0,64)) sec.append(el("div",{class:"mono"}, line));
      wrap.append(sec);
    }
    out.prepend(wrap);
  }

  function renderOp(r){
    const sec=el("div",{class:"section"});
    const title=`FileOp ${r.majorName} [${r.op}]`;
    sec.append(
      el("h3",null,title),
      kv("retval", r.retval!==undefined? `0x${BigInt(r.retval).toString(16)}` : r.ntstatus!==undefined? `0x${BigInt(r.ntstatus).toString(16)}` : "—", (r.retval===0n||r.ntstatus===0n)?"ok":"warn"),
      kv("steps", r.steps??"—"),
    );
    if(r.inputHex) sec.append(kv("input", r.inputHex.slice(0,96),"mono"));
    if(r.outputHex) sec.append(el("div",{class:"mono"}, r.outputHex.slice(0,256)));
    if(r.error) sec.append(kv("error", r.error,"err"));
    if(r.userVa) sec.append(kv("user arg VA", r.userVa,"dim"));
    out.append(sec);
  }

  function liveLine(msg,cls){ out.append(el("div",{class:`line ${cls??""}`},msg)); }

  function renderBugSummary(bugs, detailedLog){
    const wrap=el("div",{class:"section", style:"border:2px solid #d73a49;padding:10px;border-radius:8px"},
      el("h3",null,`Find Bugs — ${bugs.length} potential vuln${bugs.length===1?"":"s"} found`));
    if(!bugs.length){
      wrap.append(el("div",{class:"mono dim"},"No sinks triggered with tainted data. Try larger corpus / enable concolic."));
      const dl=el("button",{class:"btn btn-sm", type:"button"},`Download full log (${detailedLog.length} lines)`);
      dl.addEventListener("click",()=>{
        const blob=new Blob([detailedLog.join("\n")],{type:"text/plain"});
        const a=document.createElement("a"); a.href=URL.createObjectURL(blob); a.download=`findbugs-linux-${new Date().toISOString().slice(0,19)}.log`; a.click(); URL.revokeObjectURL(a.href);
      });
      wrap.append(el("div",{class:"row gap", style:"margin-top:8px"}, dl));
      out.append(wrap); return;
    }
    const bySev={};
    for(const b of bugs){ const s=b.severity||0; const key=s>=10?"CRITICAL":s>=8?"HIGH":s>=5?"MEDIUM":s>=3?"LOW":"INFO"; (bySev[key]=bySev[key]||[]).push(b); }
    const order=["CRITICAL","HIGH","MEDIUM","LOW","INFO"];
    for(const sev of order){
      const list=bySev[sev];
      if(!list||!list.length) continue;
      const sec=el("div",{class:"section", style:"margin:8px 0"}, el("h4",null,`${sev} — ${list.length}`));
      for(const b of list.slice(0,12)){
        const row=el("div",{class:"section", style:"margin:6px 0;padding:6px;border:1px solid #444;border-radius:6px"},
          el("div",{style:"font-weight:600"}, `${b.sinkType} — ${b.sinkApi||""} @ ${b.sinkLocation}`),
          kv("IOCTL/cmd", b.ioctlCode,"dim"),
          kv("control", b.controlDegree, b.controlDegree==="full"?"err":b.controlDegree==="bounded"?"warn":"dim"),
          kv("witness", (b.witnessInput||"").slice(0,48),"mono"),
        );
        if(b.taintedOperands?.length){
          for(const op of b.taintedOperands.slice(0,2)){
            row.append(el("div",{class:"mono dim", style:"font-size:11px"}, `tainted ${op.role||op.pos}: ${op.value||op.addr||""} ids ${op.taintIds||""}`));
          }
        }
        const cp=el("button",{class:"btn btn-sm", type:"button", style:"padding:0 4px;font-size:10px"},"copy witness");
        cp.addEventListener("click", async()=>{ try{ await navigator.clipboard.writeText(b.witnessInput||""); }catch{} });
        row.append(cp);
        sec.append(row);
      }
      wrap.append(sec);
    }
    const blobJson=JSON.stringify(bugs,null,2);
    const dlJson=el("button",{class:"btn btn-sm", type:"button"},`Download bug report JSON (${bugs.length})`);
    dlJson.addEventListener("click",()=>{
      const blob=new Blob([blobJson],{type:"application/json"});
      const a=document.createElement("a"); a.href=URL.createObjectURL(blob); a.download=`bugs-linux-${new Date().toISOString().slice(0,19)}.json`; a.click(); URL.revokeObjectURL(a.href);
    });
    const dlLog=el("button",{class:"btn btn-sm", type:"button"},`Download full log (${detailedLog.length} lines)`);
    dlLog.addEventListener("click",()=>{
      const blob=new Blob([detailedLog.join("\n")],{type:"text/plain"});
      const a=document.createElement("a"); a.href=URL.createObjectURL(blob); a.download=`findbugs-linux-${new Date().toISOString().slice(0,19)}.log`; a.click(); URL.revokeObjectURL(a.href);
    });
    wrap.append(el("div",{class:"row gap", style:"margin-top:8px"}, dlJson, dlLog));
    out.append(wrap);
  }

  // Actions
  loadBtn.addEventListener("click", async()=>{
    const file=fileInput.files?.[0];
    if(!file){ log("pick a .ko file first","err"); return; }
    loadBtn.disabled=true; loadBtn.textContent="analyzing…";
    try{
      const bytes=new Uint8Array(await file.arrayBuffer());
      const opts={
        name: nameInput.value||"uploaded.ko",
        backendName: engineSel.value,
      };
      if(engineSel.value==="hybrid"){
        opts.makeBackend=async()=>{
          const { HybridCpuBackend } = await import("@kernelforge/ntsim-unicorn/src/hybrid.mjs");
          return await HybridCpuBackend.create(null);
        };
      } else if(engineSel.value==="unicorn"){
        opts.makeBackend=async()=>{
          let mod;
          try{ mod=await import("@kernelforge/ntsim-unicorn"); } catch(e){ try{ mod=await import("@kernelforge/ntsim-unicorn/src/backend.mjs"); }catch(_){ throw e; } }
          const createUnicornBackend = mod.createUnicornBackend ?? mod.default?.createUnicornBackend ?? mod.default ?? mod.create;
          if(typeof createUnicornBackend!=="function") throw new Error(`unicorn factory not found`);
          return await createUnicornBackend(null);
        };
      }
      const report=await analyzeKo(bytes, opts);
      renderReport(report);
      log(`loaded ${file.name} (${bytes.length} bytes, engine=${opts.backendName})`,"ok");
      sendBtn.disabled=false; autoBtn.disabled=false; cleanupBtn.disabled=false;
      if(report.harvestedOps?.length){
        // populate opSel with harvested
        const cur=opSel.value;
        opSel.innerHTML="";
        for(const h of report.harvestedOps){
          opSel.append(el("option",{value:h.op}, `${h.op} @ ${h.va} (${h.device})`));
        }
        // also add generic options if not present
        ["read","write","mmap","open","release","proc_show","proc_store","netlink"].forEach(o=>{
          if(![...opSel.options].some(x=>x.value===o)) opSel.append(el("option",{value:o},o));
        });
        if([...opSel.options].some(o=>o.value===cur)) opSel.value=cur;
      }
      session=report.__session;
      if(session && report.load){
        session.imageSize=report.load.imageSize;
        if(typeof session.image?.base==="string") session.image.base=BigInt(session.image.base);
      }
    } catch(e){
      log(`load failed: ${e.message} ${e.stack?.slice(0,500)??""}`,"err");
    } finally{
      loadBtn.disabled=false; loadBtn.textContent="Load & run init_module";
    }
  });

  sendBtn.addEventListener("click", async()=>{
    if(!session) return;
    sendBtn.disabled=true;
    try{
      const r=await sendFileOp(session.kernel, session.device, {
        op: opSel.value,
        cmd: cmdInput.value.replace(/^0x/i,"") ? BigInt("0x"+cmdInput.value.replace(/^0x/,"")) : 0n,
        inputHex: argInput.value,
        outputLen: Number(outLenInput.value)||0,
      });
      renderOp({...r, error: r.error ? String(r.error.message??r.error):undefined});
      for(const line of session.kernel.dbgLog.splice(0)) liveLine(line,"mono");
    } finally{ sendBtn.disabled=false; }
  });

  function renderAutoDriveSummary(results, harvested, detailedLog){
    const wrap=el("div",{class:"section"}, el("h3",null,`Auto-drive summary (${harvested.length} ops probed)`));
    const valid=results.filter(r=> r.retval===0n || r.ntstatus===0n);
    wrap.append(kv("trials", `${results.length}`), kv("valid (likely good inputs)", `${valid.length}`, valid.length?"ok":""));
    for(const entry of harvested.slice(0, 8)){
      const entries=results.filter(r=> r.majorName===entry.op.toUpperCase() || r.op===entry.op);
      if(!entries.length) continue;
      const sorted=[...entries].sort((a,b)=> (b.coverage?.blocks??0)-(a.coverage?.blocks??0));
      const top=sorted.slice(0,3);
      const bestValid=sorted.find(r=> r.retval===0n || r.ntstatus===0n);
      const sec=el("div",{class:"section", style:"margin:8px 0;padding:8px;border:1px solid #333;border-radius:6px"},
        el("h4",{style:"margin:0 0 6px 0"}, `${entry.op} — ${entries.length} trials${bestValid?" 1+ valid ✓":""}`),
        kv("fops", `0x${entry.va.toString(16)}`,"dim"),
      );
      if(bestValid) sec.append(kv("best valid", `${(bestValid.inputHex??"").slice(0,32)} — blocks ${bestValid.coverage?.blocks??0}`,"ok"));
      sec.append(el("div",{class:"dim", style:"margin-top:6px;font-weight:600"},"Top coverage inputs:"));
      for(let i=0;i<top.length;i++){
        const e=top[i];
        const row=el("div",{class:"mono", style:"font-size:11px;display:flex;gap:8px;align-items:center;flex-wrap:wrap"},
          el("span",null,`#${i+1}`),
          el("span",{style:"font-weight:600"}, (e.inputHex??"").slice(0,32)+((e.inputHex?.length??0)>32?"…":"")),
          el("span",{class:"dim"}, `blocks ${e.coverage?.blocks??0} ${e.source?`[${e.source}]`:""}`),
        );
        sec.append(row);
      }
      wrap.append(sec);
    }
    const dl=el("button",{class:"btn btn-sm", type:"button"},`Download full log (${detailedLog.length} lines)`);
    dl.addEventListener("click",()=>{
      const blob=new Blob([detailedLog.join("\n")],{type:"text/plain"});
      const a=document.createElement("a"); a.href=URL.createObjectURL(blob); a.download=`autodrive-linux-${new Date().toISOString().slice(0,19)}.log`; a.click(); URL.revokeObjectURL(a.href);
    });
    wrap.append(el("div",{class:"row gap", style:"margin-top:8px"}, dl));
    liveLine(`auto-drive done: ${results.length} trials, ${valid.length} valid`, valid.length?"ok":"dim");
    out.append(wrap);
  }

  autoBtn.addEventListener("click", async()=>{
    if(!session) return;
    autoBtn.disabled=true;
    const detailedLog=[];
    const pushLog=(msg)=> detailedLog.push(`[${new Date().toISOString().slice(11,19)}] ${msg}`);
    try{
      const harvested = session.kernel.deviceRegistry.length ? (()=> {
        // Build harvested like autoops expects: [{op, va}]
        const ops=[];
        for(const dev of session.kernel.deviceRegistry){
          if(!dev.fops) continue;
          // read ops
          const { readFileOps } = (()=>{ try{ return require("@kernelforge/linux-sim/src/file-ops.mjs"); }catch{ return {readFileOps:()=>({})}; } })();
        }
        // Use getHarvestedOps via dynamic import
        return session.harvestedOps || [];
      })() : [];
      // Actually await import
      const { getHarvestedOps } = await import("@kernelforge/linux-sim/src/file-ops.mjs");
      const harvestedOps = getHarvestedOps(session.kernel).slice(0, 32);
      pushLog(`auto-drive: open + ${harvestedOps.length} harvested ops + release`);
      const fuzz = fuzzTick.checked ? { iterations: Number(fuzzIter.value)||256, corpusCap: Number(fuzzCorpus.value)||32, inputLen:16 } : null;
      const concolic = concTick.checked ? { maxSymBytes: Number(concSym.value)||64, solverTimeoutMs: Number(concTo.value)||300, maxQueries: Number(concQ.value)||8, inputLen:16 } : null;
      if(fuzz) pushLog(`[fuzz] iters=${fuzz.iterations} corpus=${fuzz.corpusCap}`);
      if(concolic) pushLog(`[concolic] sym=${concolic.maxSymBytes} timeout=${concolic.solverTimeoutMs}ms queries=${concolic.maxQueries}`);
      const findBugs=bugTick.checked;
      if(findBugs && !fuzz) pushLog(`[find-bugs] fuzz auto-enabled`);
      liveLine(`auto-driving ${harvestedOps.length} ops${fuzz?" + fuzz":""}${concolic?" + concolic":""}${findBugs?" + find-bugs":""}…`,"dim");
      const base=session.image.base ?? LINUX_MODULE_BASE;
      const size=session.imageSize ?? session.image.bytes.length;
      const driverHash=[...session.image.bytes.slice(0,64)].map(b=>b.toString(16).padStart(2,"0")).join("").slice(0,16);
      const { autoDriveFileOps } = await import("@kernelforge/linux-analyzer/src/autoops.mjs");
      const results=await autoDriveFileOps(session.kernel, session.device, {
        sendFileOp,
        harvested: harvestedOps,
        maxOps: 32,
        imageBase: base,
        imageSize: size,
        fuzz: findBugs && !fuzz ? {iterations:64, corpusCap:16, inputLen:16} : fuzz,
        concolic,
        outputLen: 64,
        onPhase:(label)=> pushLog(`[phase] ${label}`),
      });
      for(const line of session.kernel.dbgLog.splice(0)) pushLog(`[dbg] ${line}`);
      for(const ex of session.kernel.exceptionTrace.splice(0)) pushLog(`[exception] ${ex.faultRip}: ${ex.detail}`);
      renderAutoDriveSummary(results, harvestedOps, detailedLog);
      if(findBugs){
        try{
          liveLine(`find-bugs: taint analysis toward sinks…`,"dim");
          const allBugs=[];
          const maxOpsForBugs=Math.min(harvestedOps.length,8);
          const useWorkers= typeof Worker!=="undefined" && maxOpsForBugs>1 && (navigator.hardwareConcurrency||4)>2;
          if(useWorkers){
            pushLog(`[find-bugs] using workers for parallel probing`);
            const workerUrl=new URL("./workers/linuxBugWorker.mjs", import.meta.url);
            const running=[];
            for(let i=0;i<maxOpsForBugs;i++){
              const entry=harvestedOps[i];
              const p=new Promise((resolve,reject)=>{
                const w=new Worker(workerUrl,{type:"module"});
                const timeout=setTimeout(()=>{ w.terminate(); reject(new Error("worker timeout")); },30000);
                w.onmessage=(e)=>{
                  const {type, result, error}=e.data;
                  if(type==="done"){ clearTimeout(timeout); w.terminate(); pushLog(`[find-bugs][worker] done ${entry.op} bugs ${result.bugs.length}`); resolve(result.bugs); }
                  else if(type==="error"){ clearTimeout(timeout); w.terminate(); reject(new Error(error)); }
                };
                w.onerror=(err)=>{ clearTimeout(timeout); w.terminate(); reject(err); };
                w.postMessage({type:"run", id:i, imageBytes: session.image.bytes, op: entry.op, cmd: 0, base: base.toString(), size: size.toString(), opts:{iterations: fuzz?fuzz.iterations:96, corpusCap: fuzz?fuzz.corpusCap:16, driverHash}});
              }).then(bugs=>{ allBugs.push(...bugs); for(const b of bugs) pushLog(`[bug][worker] ${b.sinkType} ${b.controlDegree} @${b.sinkLocation} op ${b.ioctlCode}`); }).catch(e=> pushLog(`[find-bugs][worker] failed ${entry.op}: ${e.message}`));
              running.push(p);
              if(running.length>=Math.min(4, maxOpsForBugs)) await Promise.race(running);
            }
            await Promise.allSettled(running);
            renderBugSummary(allBugs, detailedLog);
          } else {
            const { findLinuxBugsCampaign } = await import("@kernelforge/linux-analyzer/src/bug/linux-engine.mjs");
            for(let i=0;i<maxOpsForBugs;i++){
              const entry=harvestedOps[i];
              pushLog(`[find-bugs] probing ${entry.op} (${i+1}/${maxOpsForBugs})`);
              liveLine(`[find-bugs] probing ${entry.op} ${i+1}/${maxOpsForBugs}…`,"dim");
              const {bugDB}=await findLinuxBugsCampaign(session.kernel, session.device, entry.op, {
                sendFileOp, imageBase: base, imageSize: size,
                iterations: fuzz? fuzz.iterations:96,
                corpusCap: fuzz? fuzz.corpusCap:16,
                inputLen:16, outputLen:64, cmd:0, driverHash,
                onProgress:(evt)=>{ if(evt.phase==="bug-found") pushLog(`[bug] ${evt.bug.sinkType} ${evt.bug.controlDegree} at ${evt.bug.sinkLocation} op ${entry.op}`); }
              });
              for(const b of bugDB.all()){
                pushLog(`[bug] ${b.sinkType} ${b.controlDegree} ${b.sinkApi||""} @${b.sinkLocation} op ${entry.op} witness ${b.witnessInput?.slice(0,16)}`);
                allBugs.push(b);
              }
              for(const line of session.kernel.dbgLog.splice(0)) pushLog(`[dbg] ${line}`);
            }
            renderBugSummary(allBugs, detailedLog);
          }
        } catch(e){
          pushLog(`[find-bugs] failed: ${e.message} ${e.stack?.slice(0,500)}`);
          liveLine(`find-bugs failed: ${e.message}`,"err");
        }
      }
    } finally{ autoBtn.disabled=false; }
  });

  cleanupBtn.addEventListener("click", async()=>{
    if(!session) return;
    cleanupBtn.disabled=true;
    try{
      // call cleanup_module if present
      const mapped=session.mapped;
      if(mapped?.cleanup){
        const r=session.kernel.callFunctionSeh(mapped.cleanup, [], session.image);
        liveLine(`cleanup: ${r.status}${r.retval!==undefined? ` (0x${r.retval.toString(16)})`:""}`);
      } else liveLine("no cleanup_module","warn");
    } finally{ cleanupBtn.disabled=false; }
  });
}
