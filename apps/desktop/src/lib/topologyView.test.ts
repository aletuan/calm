import { describe, expect, it } from "vitest";
import { defaultTopologyView, setActivityLink, viewportFor, viewportKey } from "./topologyView";

describe("topology view state kept across screens", () => {
  it("starts with overlays off (design §5)", () => {
    expect(defaultTopologyView()).toEqual({ showTraffic: false, observedOnly: false, viewport: null });
  });

  it("restores the user's zoom and pan only for the same graph and filters", () => {
    const key = viewportKey("live", "sig-a", { showTraffic: true, observedOnly: false });
    const saved = { key, zoom: 1.6, pan: { x: -120, y: 40 } };
    expect(viewportFor(saved, key)).toEqual({ zoom: 1.6, pan: { x: -120, y: 40 } });
    // A new device (different graph), another filter or another source: fit again.
    expect(viewportFor(saved, viewportKey("live", "sig-b", { showTraffic: true, observedOnly: false }))).toBeNull();
    expect(viewportFor(saved, viewportKey("live", "sig-a", { showTraffic: false, observedOnly: false }))).toBeNull();
    expect(viewportFor(saved, viewportKey("import:x", "sig-a", { showTraffic: true, observedOnly: false }))).toBeNull();
    expect(viewportFor(null, key)).toBeNull();
  });

  it("turning live activity on also shows traffic, since dots move on traffic edges", () => {
    expect(setActivityLink({ showTraffic: false, observedOnly: true, viewport: null }, true)).toEqual({ showTraffic: true, observedOnly: true, viewport: null });
    // Turning it off leaves the traffic choice alone.
    expect(setActivityLink({ showTraffic: true, observedOnly: false, viewport: null }, false).showTraffic).toBe(true);
  });
});
