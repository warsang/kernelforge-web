/**
 * fuzzWorker.mjs — Web Worker for coverage-guided fuzzing of a single IOCTL
 * Runs fuzzIoctl in a separate thread to keep UI responsive.
 */

import { StructTables } from "@kernelforge/ntsim/src/structs.mjs";
import { NtKernel, createDriverObject, initDriverObjectName, createDeviceObject, sendIrp, mapPe, parsePe } from "@kernelforge/ntsim/src/index.mjs";
import { fuzzIoctl } from "@kernelforge/ntsim-analyzer/src/fuzz.mjs";

let tablesCache = null;

async function ensureTables(tablesData) {
  if (tablesCache) return tablesCache;
  if (tablesData && Array.isArray(tablesData) && tablesData.length) {
    tablesCache = new StructTables();
    for (const [name, info] of tablesData) {
      try {
        const fields = info.fields ? info.fields : Object.values(info.fieldsByName || {});
        tablesCache.register(name, info.totalSize, fields);
      } catch {}
    }
    if (tablesCache.has("_EPROCESS")) return tablesCache;
  }
  const TYPES = ["_EPROCESS","_ETHREAD","_KPROCESS","_KTHREAD","_LIST_ENTRY","_UNICODE_STRING","_OBJECT_TYPE","_OBJECT_HEADER","_HANDLE_TABLE","_PS_PROTECTION","_KLDR_DATA_TABLE_ENTRY","_LDR_DATA_TABLE_ENTRY","_KPCR","_KPRCB","_MMVAD","_MMVAD_SHORT"];
  tablesCache = new StructTables();
  await Promise.all(TYPES.map(async (name)=>{
    try{
      const res = await fetch(`/tables/windows-10/22h2/${name}.json`);
      if(!res.ok) return;
      const json = await res.json();
      const fields = json.fields ? json.fields : Object.values(json.fieldsByName || {});
      tablesCache.register(name, json.totalSize, fields);
    }catch{}
  }));
  if(!tablesCache.has("_EPROCESS")) throw new Error("EPROCESS table not loaded");
  return tablesCache;
}

self.onmessage = async (e) => {
  const { type, id, imageBytes, ctlCode, base, size, opts, tablesData } = e.data;
  if (type !== "run") return;
  try {
    const tables = await ensureTables(tablesData);
    const kernel = new NtKernel({ tables });
    kernel.bootstrap();
    const drvRec = createDriverObject(kernel, "worker.sys");
    const mapped = mapPe(imageBytes, kernel.mem, BigInt(base), (q)=> kernel.resolveImportProvisioned(q));
    initDriverObjectName(kernel, drvRec, "worker.sys", mapped.base, mapped.imageSize);
    drvRec.image = { base: mapped.base, bytes: imageBytes };
    kernel.materializeModuleRange(mapped.base, mapped.imageSize, { fill: 0 });
    const pe = parsePe(imageBytes);
    const entry = mapped.base + BigInt(pe.entryRva);
    kernel.callFunctionSeh(entry, [drvRec.va, 0n], drvRec.image);
    const device = drvRec.deviceList[0] ?? createDeviceObject(kernel, drvRec, {});
    const result = await fuzzIoctl(kernel, device, ctlCode, {
      sendIrp: (k,d,spec)=> sendIrp(k,d,spec),
      imageBase: BigInt(base),
      imageSize: BigInt(size),
      iterations: opts.iterations ?? 128,
      corpusCap: opts.corpusCap ?? 16,
      onProgress: (evt)=>{
        self.postMessage({type:"progress", id, evt});
      }
    });
    self.postMessage({type:"done", id, result: {
      ctlCode,
      corpus: result.corpus.map(c=> ({ hex: [...c.buf].map(b=>b.toString(16).padStart(2,"0")).join(""), coverage: {blocks: c.coverage.blocks.size}})),
      globalSeen: result.globalSeen.size,
      best: result.best ? { hex: [...result.best.buf].map(b=>b.toString(16).padStart(2,"0")).join(""), nt: result.best.res?.ntstatus?.toString(16)} : null
    }});
  } catch (err) {
    self.postMessage({type:"error", id, error: err.message + "\n" + err.stack});
  }
};
