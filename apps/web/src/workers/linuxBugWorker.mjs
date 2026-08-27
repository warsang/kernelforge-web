/**
 * linuxBugWorker.mjs — Worker for Linux Find Bugs campaign
 */
import { LinuxKernel } from "@kernelforge/linux-sim/src/linux-kernel.mjs";
import { parseElfKo, mapModule } from "@kernelforge/linux-sim/src/module-loader.mjs";
import { sendFileOp } from "@kernelforge/linux-sim/src/file-ops.mjs";
import { findLinuxBugsCampaign } from "@kernelforge/linux-analyzer/src/bug/linux-engine.mjs";

self.onmessage=async(e)=>{
  const {type,id,imageBytes,op,cmd,base,size,opts}=e.data;
  if(type!=="run") return;
  try{
    const bytes = imageBytes instanceof Uint8Array ? imageBytes : new Uint8Array(imageBytes);
    const kernel=new LinuxKernel({});
    const parsed=parseElfKo(bytes);
    const mapped=mapModule(kernel, parsed, BigInt(base), (name)=>kernel.resolveImportProvisioned(name));
    // call init_module if present
    if(mapped.init) kernel.callFunctionSeh(mapped.init, [], {base:mapped.base, bytes});
    const device=kernel.deviceRegistry[0] ?? {name:"dummy", fops: kernel.allocSlub(0x80,"fops_dummy")};
    const res=await findLinuxBugsCampaign(kernel, device, op||"unlocked_ioctl", {
      sendFileOp,
      imageBase:BigInt(base), imageSize:BigInt(size),
      iterations: opts.iterations??64, corpusCap: opts.corpusCap??16,
      cmd: cmd??0,
      driverHash: opts.driverHash,
      driverName:"worker.ko",
      inputLen:16, outputLen:64,
      onProgress:(evt)=> self.postMessage({type:"progress", id, evt})
    });
    self.postMessage({type:"done", id, result:{
      op, cmd,
      bugs: res.bugDB.all(),
      corpus: res.corpus.length
    }});
  }catch(err){
    self.postMessage({type:"error", id, error: err.message+"\n"+err.stack});
  }
};
