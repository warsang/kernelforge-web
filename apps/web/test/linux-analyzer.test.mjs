import { test } from "node:test";
import assert from "node:assert/strict";
import { Window } from "happy-dom";

test("linux analyzer tab renders with ko upload + engine select", async ()=>{
  const window=new Window({url:"http://localhost:5173/"});
  window.document.body.innerHTML='<div id="app"></div>';
  globalThis.window=window;
  globalThis.document=window.document;
  for(const k of ["HTMLElement","HTMLInputElement","HTMLSelectElement","Node","customElements"]) if(window[k]!==undefined) globalThis[k]=window[k];
  window.process={env:{}};
  const fetchShim=async()=>({ok:false, status:404});
  globalThis.fetch=fetchShim;
  window.fetch=fetchShim;

  const { createServer } = await import("vite");
  const path=await import("node:path");
  const { fileURLToPath } = await import("node:url");
  const webRoot=path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const server=await createServer({ root: webRoot, server:{middlewareMode:true}, logLevel:"error"});
  try{
    await server.ssrLoadModule("/src/main.js");
    await new Promise(r=>setTimeout(r,50));
    const doc=window.document;
    // Find Linux Analyzer button
    const btn=[...doc.querySelectorAll("button.tool")].find(b=>b.textContent.includes("Linux Driver Analyzer"));
    assert.ok(btn, "Linux Driver Analyzer button not found");
    btn.click();
    await new Promise(r=>setTimeout(r,50));
    const body=doc.body.textContent;
    assert.ok(body.includes("Linux Driver Analyzer"), "linux analyzer card missing");
    assert.ok(doc.querySelector('input[type="file"][accept*=".ko"]'), "ko file input missing");
    assert.ok(doc.querySelector("select"), "engine select missing");
    const loadBtn=[...doc.querySelectorAll("button")].find(b=>b.textContent.includes("Load & run init_module"));
    assert.ok(loadBtn, "Load & run init_module button missing");
  } finally { await server.close(); }
});

test("linux analyzer handles fake ko load", async ()=>{
  const { analyzeKo } = await import("@kernelforge/linux-analyzer/src/index.mjs");
  const { execFileSync } = await import("node:child_process");
  const { mkdtempSync, writeFileSync, readFileSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const path=await import("node:path");
  function compileKo(src){
    const dir=mkdtempSync(path.join(tmpdir(),"kf-ui-"));
    try{
      const c=path.join(dir,"mod.c");
      const o=path.join(dir,"mod.o");
      writeFileSync(c, src);
      execFileSync("clang", ["--target=x86_64-linux-gnu","-O1","-ffreestanding","-fno-stack-protector","-fno-pic","-mno-red-zone","-mcmodel=kernel","-isystem", path.join(process.cwd(),"packages/compiler-worker/include"),"-D__KERNEL__","-DMODULE","-c",c,"-o",o],{timeout:15000});
      return new Uint8Array(readFileSync(o));
    } finally{ try{ rmSync(dir,{recursive:true,force:true}); }catch{} }
  }
  const src=`
#include <linux/module.h>
#include <linux/fs.h>
MODULE_LICENSE("GPL");
static long my_ioctl(struct file *f, unsigned int cmd, unsigned long arg){ return 0; }
static struct file_operations fops={ .unlocked_ioctl=my_ioctl };
static int __init myinit(void){ register_chrdev(240,"uiv",&fops); return 0; }
module_init(myinit);
`;
  const bytes=compileKo(src);
  const report=await analyzeKo(bytes, {name:"ui.ko", backendName:"js"});
  assert.equal(report.init.status,"ok");
  assert.ok(report.harvestedOps.length===1);
});
