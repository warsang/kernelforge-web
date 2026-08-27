import { defineConfig } from "vite";

export default defineConfig({
  server: {
    port: 5174,
    strictPort: true,
    headers: {
      "cross-origin-opener-policy": "same-origin",
      "cross-origin-embedder-policy": "require-corp",
    },
  },
  build: { outDir: "dist", target: "es2022" },
});
