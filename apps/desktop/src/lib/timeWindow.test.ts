import { describe, expect, it } from "vitest";
import { fractionsOf, presets, windowFromFractions } from "./timeWindow";

const S: [number, number] = [1_000_000, 1_000_000 + 20 * 60_000]; // 20 minutes

describe("time window", () => {
  it("presets: whole span plus last 1/5/15 min, only when shorter than the span", () => {
    const p = presets(S);
    expect(p.map((x) => x.key)).toEqual(["all", "last1", "last5", "last15"]);
    expect(p[0]!.window).toBeNull();
    // The window end is exclusive, so it reaches 1 ms past the last flow.
    expect(p[1]!.window).toEqual({ from_ms: S[1] - 60_000, to_ms: S[1] + 1 });
    expect(presets([0, 3 * 60_000]).map((x) => x.key)).toEqual(["all", "last1"]);
  });
  it("fractions of the span map to a window and back", () => {
    const w = windowFromFractions(S, 0.25, 0.5);
    expect(w).toEqual({ from_ms: S[0] + 5 * 60_000, to_ms: S[0] + 10 * 60_000 });
    expect(fractionsOf(S, w)).toEqual([0.25, 0.5]);
    expect(fractionsOf(S, null)).toEqual([0, 1]);
  });
  it("keeps from < to and inside the span", () => {
    const w = windowFromFractions(S, 0.8, 0.3);
    expect(w.from_ms).toBeLessThan(w.to_ms);
    const c = windowFromFractions(S, -1, 2);
    expect(c).toEqual({ from_ms: S[0], to_ms: S[1] + 1 });
    const tiny = windowFromFractions(S, 0.5, 0.5);
    expect(tiny.to_ms - tiny.from_ms).toBeGreaterThanOrEqual(1000);
  });
});
