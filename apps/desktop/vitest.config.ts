import { defineConfig } from "vitest/config";

// Unit tests for pure UI logic (formatting, series, topology model, demo
// store). Components that need a browser are covered by preview screenshots.
export default defineConfig({
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
    coverage: {
      provider: "v8",
      include: ["src/lib/**/*.ts"],
      exclude: ["src/**/*.test.ts"],
      reporter: ["text", "json-summary"],
    },
  },
});
