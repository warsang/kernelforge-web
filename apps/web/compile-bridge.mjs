#!/usr/bin/env node
/**
 * KERNELFORGE compile bridge — POST /api/compile {source} -> x64 COFF .obj.
 *
 * The Vite app (apps/web) calls this to run real clang on student sources
 * until the browsercc WASM fork replaces it client-side. Static file serving
 * is Vite's job (`npm run dev` in apps/web); this process only compiles.
 */

import http from "node:http";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { includeDir as wdkIncludeDir } from "@kernelforge/compiler-worker/wdk-headers.mjs";
import { linuxIncludeDir } from "@kernelforge/compiler-worker/linux-headers.mjs";

const execFileP = promisify(execFile);
const PORT = process.env.PORT ?? 8087;

async function handleCompile(req, res) {
  let body = "";
  for await (const chunk of req) body += chunk;
  let source, target="windows";
  try {
    const j=JSON.parse(body);
    source=j.source;
    target=j.target||"windows";
    if (typeof source !== "string" || source.length > 100_000) throw new Error("bad source");
  } catch {
    res.writeHead(400).end("bad request");
    return;
  }
  const dir = await mkdtemp(path.join(tmpdir(), "kf-compile-"));
  try {
    const cFile = path.join(dir, "driver.c");
    const oFile = path.join(dir, "driver.obj");
    await writeFile(cFile, source);
    try {
      if(target==="linux"){
        await execFileP("clang", [
          "--target=x86_64-linux-gnu",
          "-O1", "-ffreestanding", "-fno-stack-protector", "-fno-pic", "-mno-red-zone", "-mcmodel=kernel",
          `-isystem`, linuxIncludeDir(),
          "-D__KERNEL__", "-DMODULE",
          "-c", cFile, "-o", oFile,
        ], { timeout: 15000 });
      } else {
        await execFileP("clang", [
          "--target=x86_64-pc-windows-msvc",
          "-O1", "-ffreestanding", "-fno-stack-protector",
          `-isystem`, wdkIncludeDir(),
          "-c", cFile, "-o", oFile,
        ], { timeout: 15000 });
      }
    } catch (e) {
      res.writeHead(422, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: e.stderr || e.message }));
      return;
    }
    const obj = await readFile(oFile);
    res.writeHead(200, {
      "content-type": "application/json",
      "access-control-allow-origin": "http://localhost:5173",
    });
    res.end(JSON.stringify({ objBase64: obj.toString("base64") }));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

const server = http.createServer((req, res) => {
  if (req.method === "POST" && new URL(req.url, "http://x").pathname === "/api/compile") {
    handleCompile(req, res).catch(() => res.writeHead(500).end());
    return;
  }
  if (req.method === "OPTIONS") {
    // CORS preflight for the Vite dev origin
    res.writeHead(204, {
      "access-control-allow-origin": "http://localhost:5173",
      "access-control-allow-methods": "POST, OPTIONS",
      "access-control-allow-headers": "content-type",
    }).end();
    return;
  }
  res.writeHead(404).end();
});

server.listen(PORT, () => {
  console.log(`KERNELFORGE compile bridge on http://localhost:${PORT} (POST /api/compile)`);
});
