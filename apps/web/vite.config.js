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
  // v86's libv86.js does `if (typeof process !== "undefined") global.setImmediate`
  // which would ReferenceError in browsers where `process` is polyfilled but
  // `global` is not. Shim `global` to `globalThis` and keep `process.env` minimal.
  define: { "process.env": "{}", global: "globalThis" },
});
