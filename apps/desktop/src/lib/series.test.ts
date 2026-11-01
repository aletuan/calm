import { describe, expect, it } from "vitest";
import type { SeriesPoint } from "./ipc";
import { livePoints, spanPoints } from "./series";

const pt = (t: number, i: number, o: number): SeriesPoint => ({ t, bytes_in: i, bytes_out: o, packets: 1 });

describe("livePoints", () => {
  it("covers the window ending at the newest point", () => {
    const s = [pt(100, 10, 1), pt(102, 30, 3)];
    const p = livePoints(s, 0, 5);
    expect(p.map((x) => x.x)).toEqual([0, 1, 2, 3, 4]);
    expect(p.map((x) => x.inb)).toEqual([0, 0, 10, 0, 30]);
  });
  it("drops seconds before the capture started instead of drawing zero", () => {
    const p = livePoints([pt(100, 5, 5)], 99_000, 5);
    expect(p.map((x) => x.x)).toEqual([3, 4]);
  });
  it("uses the given clock when there is no data yet", () => {
    expect(livePoints([], 0, 3, 50)).toHaveLength(3);
    expect(livePoints([], 51_000, 3, 50)).toHaveLength(0);
  });
});

describe("spanPoints", () => {
  it("one point per second for short spans", () => {
    const r = spanPoints([pt(10, 100, 50), pt(12, 200, 0)], 10_000, 12_900);
    expect(r.bucket).toBe(1);
    expect(r.spanSec).toBe(3);
    expect(r.pts.map((p) => p.inb)).toEqual([100, 0, 200]);
    expect(r.span).toBe(2);
  });
  it("buckets long spans and averages to bytes per second", () => {
    const series = Array.from({ length: 1000 }, (_, i) => pt(i, 10, 0));
    const r = spanPoints(series, 0, 999_000, 100);
    expect(r.bucket).toBe(10);
    expect(r.pts).toHaveLength(100);
    expect(r.pts.every((p) => p.inb === 10)).toBe(true);
  });
  it("ignores points outside the span", () => {
    const r = spanPoints([pt(5, 999, 999), pt(10, 1, 1)], 10_000, 10_000);
    expect(r.pts).toEqual([{ x: 0, inb: 1, out: 1 }]);
    expect(r.span).toBe(1);
  });
  it("total bytes are preserved by bucketing", () => {
    const series = Array.from({ length: 333 }, (_, i) => pt(i, i, 0));
    const r = spanPoints(series, 0, 332_000, 50);
    const total = r.pts.reduce((a, p) => a + p.inb * r.bucket, 0);
    expect(total).toBeCloseTo(series.reduce((a, p) => a + p.bytes_in, 0));
  });
});

describe("spanPoints with per-minute history", () => {
  it("spreads each minute evenly over its 60 seconds, preserving bytes", () => {
    // One minute of history (6000 B in) at t=0..59, then per-second data from t=60.
    const minutes = [pt(0, 6000, 600)];
    const seconds = [pt(60, 100, 10), pt(61, 100, 10)];
    const r = spanPoints(seconds, 0, 61_000, 1000, minutes);
    expect(r.bucket).toBe(1);
    expect(r.pts[0]!.inb).toBe(100);
    expect(r.pts[59]!.inb).toBe(100);
    expect(r.pts[60]!.inb).toBe(100);
    const total = r.pts.reduce((a, p) => a + p.inb * r.bucket, 0);
    expect(total).toBe(6000 + 200);
    expect(r.averagedUntilX).toBe(60);
  });
  it("no history: no averaged region", () => {
    expect(spanPoints([pt(10, 1, 1)], 10_000, 10_000).averagedUntilX).toBeNull();
  });
});
