import { describe, expect, it } from "vitest";
import { chartAxis, percentile } from "./chartAxis";

const KB = 1024;
const baseline = (n: number, v: number) => Array.from({ length: n }, (_, i) => v + (i % 5) * 1000);

describe("percentile", () => {
  it("nearest-rank, ignores order", () => {
    expect(percentile([5, 1, 3, 2, 4], 0.5)).toBe(3);
    expect(percentile([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 0.95)).toBe(10);
    expect(percentile([], 0.95)).toBe(0);
  });
});

describe("chartAxis auto", () => {
  it("stays linear when there is no outlier", () => {
    const a = chartAxis(baseline(120, 40 * KB), "auto");
    expect(a.kind).toBe("linear");
    expect(a.top).toBe(Math.max(...baseline(120, 40 * KB)));
    expect(a.clippedCount).toBe(0);
  });

  it("cuts the axis when one spike dwarfs the rest, and says which points are above", () => {
    const v = [...baseline(119, 40 * KB), 8.8 * 1024 * KB];
    const a = chartAxis(v, "auto");
    expect(a.kind).toBe("clipped");
    expect(a.top).toBeLessThan(200 * KB);
    expect(a.top).toBeGreaterThanOrEqual(percentile(v.filter((x) => x > 0), 0.95));
    expect(a.isClipped(8.8 * 1024 * KB)).toBe(true);
    expect(a.isClipped(40 * KB)).toBe(false);
    expect(a.clippedCount).toBe(1);
    // A clipped value is drawn at the top edge, never above it.
    expect(a.frac(8.8 * 1024 * KB)).toBe(1);
    // The baseline now uses a real share of the height.
    expect(a.frac(40 * KB)).toBeGreaterThan(0.2);
  });

  it("moderate bursts stay fully visible; only true outliers are cut", () => {
    // 3 bursts in 104 s: below the 95th percentile rank, so p95 is the baseline.
    const v = [...baseline(100, 20 * KB), 80 * KB, 80 * KB, 80 * KB, 2.1 * 1024 * KB];
    const a = chartAxis(v, "auto");
    expect(a.kind).toBe("clipped");
    expect(a.isClipped(80 * KB)).toBe(false);
    expect(a.frac(80 * KB)).toBeLessThan(1);
    expect(a.clippedCount).toBe(1);
  });

  it("does not cut with too few non-zero seconds to judge", () => {
    expect(chartAxis([0, 0, 0, 0, 5 * 1024 * KB, 10], "auto").kind).toBe("linear");
  });

  it("all zeros: linear with a minimum height", () => {
    const a = chartAxis(Array(60).fill(0), "auto");
    expect(a.kind).toBe("linear");
    expect(a.top).toBe(1024);
    expect(a.frac(0)).toBe(0);
  });

  it("several spikes above the cut are all flagged", () => {
    const v = [...baseline(100, 20 * KB), 5e6, 6e6, 7e6];
    const a = chartAxis(v, "auto");
    expect(a.kind).toBe("clipped");
    expect(a.clippedCount).toBe(3);
  });
});

describe("chartAxis linear", () => {
  it("never cuts, even with an outlier", () => {
    const v = [...baseline(119, 40 * KB), 9e6];
    const a = chartAxis(v, "linear");
    expect(a.kind).toBe("linear");
    expect(a.top).toBe(9e6);
    expect(a.clippedCount).toBe(0);
    expect(a.ticks).toEqual([0, 4.5e6, 9e6]);
  });
});

describe("chartAxis log", () => {
  it("maps zero to the bottom and the max to the top, monotonic in between", () => {
    const v = [0, 10, 1000, 1e5, 9e6];
    const a = chartAxis(v, "log");
    expect(a.kind).toBe("log");
    expect(a.frac(0)).toBe(0);
    expect(a.frac(9e6)).toBeCloseTo(1);
    const f = v.map(a.frac);
    for (let i = 1; i < f.length; i++) expect(f[i]!).toBeGreaterThan(f[i - 1]!);
    expect(a.clippedCount).toBe(0);
  });
  it("ticks are 0 and whole binary units from 1 KB (1 B would sit on 0)", () => {
    const a = chartAxis([0, 9e6], "log");
    expect(a.ticks).toEqual([0, 1024, 1024 ** 2]);
    expect(chartAxis([0, 500], "log").ticks).toEqual([0, 1]);
    expect(Math.max(...a.ticks)).toBeLessThanOrEqual(9e6);
    expect(a.ticks.length).toBeLessThanOrEqual(5);
  });
});
