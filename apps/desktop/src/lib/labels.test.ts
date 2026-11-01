import { describe, expect, it } from "vitest";
import { importLabel, liveLabel } from "./labels";

// Same rules as `records::live_label` in the desktop shell (Rust), so the
// browser preview and the app name snapshots alike.
describe("snapshot labels", () => {
  it("tell two saves of one capture apart", () => {
    expect(liveLabel(null)).toBe("This Mac — network profile");
    expect(liveLabel({ flows: 182, elapsedMs: 113_000 })).toBe("This Mac — 182 flows, 01:53 capture");
    expect(liveLabel({ flows: 1, elapsedMs: 3_725_000 })).toBe("This Mac — 1 flow, 62:05 capture");
    expect(importLabel("a.pcapng")).toBe("Imported — a.pcapng");
  });
});
