import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Tauri expects a fixed port; fail if unavailable.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: { port: 1420, strictPort: true, watch: { ignored: ["**/src-tauri/**"] } },
  envPrefix: ["VITE_", "TAURI_ENV_*"],
  // Cytoscape is ~400 kB; this is a desktop app loaded from disk.
  build: { target: "safari16", sourcemap: true, chunkSizeWarningLimit: 1200 },
});
