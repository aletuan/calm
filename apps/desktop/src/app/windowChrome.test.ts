/**
 * The window uses titleBarStyle "Overlay", so macOS draws no title bar to grab.
 * Moving the window then depends on two things the app must provide itself:
 * a Tauri drag region in the markup and the start-dragging permission.
 * (`-webkit-app-region` is Electron-only; WKWebView ignores it.)
 */
import { describe, expect, it } from "vitest";
import cap from "../../src-tauri/capabilities/default.json";
import app from "./App.tsx?raw";
import css from "../styles/global.css?raw";

describe("window chrome", () => {
  it("grants the permission that lets a drag region move the window", () => {
    expect(cap.permissions).toContain("core:window:allow-start-dragging");
  });

  it("has a drag strip along the top and a draggable sidebar", () => {
    expect(app).toMatch(/className="titlebar-drag"[^>]*data-tauri-drag-region/);
    expect(app).toMatch(/className="sidebar"[^>]*data-tauri-drag-region="deep"/);
  });

  it("does not rely on the Electron-only app-region property", () => {
    expect(css).not.toContain("-webkit-app-region");
  });
});
