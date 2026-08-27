import { defineConfig } from "vite";

export default defineConfig({
  server: {
    port: 5173,
    strictPort: true,
    headers: {
      // SharedArrayBuffer / cross-origin isolation for future unicorn backend
      "cross-origin-opener-policy": "same-origin",
      "cross-origin-embedder-policy": "require-corp",
    },
    proxy: {
      // dev convenience only; production uses the wasm path.
      // When the bridge is down we return a JSON 503 the app understands,
      // instead of Vite's default HTML error page (which surfaces as an
      // opaque 500 in the console).
      "/api": {
        target: "http://localhost:8087",
        configure(proxy) {
          proxy.on("error", (err, _req, res) => {
            if (res && !res.headersSent) {
              res.writeHead(503, { "content-type": "application/json" });
              res.end(JSON.stringify({
                error: "compile bridge not running — start it with: node apps/web/compile-bridge.mjs",
              }));
            }
          });
        },
      },
    },
  },
  build: { outDir: "dist", target: "es2022" },
  // Flag hashes are precomputed constants in the catalog; window.process shim
  // kept for compatibility with older content packages.
  define: { "process.env": "window.process.env" },
});
