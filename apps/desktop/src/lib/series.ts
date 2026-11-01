import type { SeriesPoint } from "./ipc";

export type Pt = { x: number; inb: number; out: number };

/**
 * Live chart: the last `window` seconds ending at the newest point. Seconds
 * before the capture started are dropped (shown blank), never drawn as 0.
 */
export function livePoints(series: SeriesPoint[], startedAtMs: number, window: number, nowSec?: number): Pt[] {
  const now = series.length ? series[series.length - 1]!.t : (nowSec ?? Math.floor(Date.now() / 1000));
  const byT = new Map(series.map((p) => [p.t, p]));
  const startSec = Math.floor(startedAtMs / 1000);
  const pts: Pt[] = [];
  for (let i = 0; i < window; i++) {
    const sec = now - (window - 1 - i);
    if (sec < startSec) continue;
    const p = byT.get(sec);
    pts.push({ x: i, inb: p?.bytes_in ?? 0, out: p?.bytes_out ?? 0 });
  }
  return pts;
}

/**
 * Whole-span chart (imported or saved data): buckets of whole seconds so at
 * most `maxPoints` points; values are bytes per second averaged per bucket.
 * Seconds without a series point inside the span were measured as zero.
 *
 * `minutes` (per-minute sums kept for long captures) are spread evenly over
 * their 60 seconds: the shape there is a per-minute average, and
 * `averagedUntilX` tells the chart where that region ends.
 */
export function spanPoints(
  series: SeriesPoint[],
  firstMs: number,
  lastMs: number,
  maxPoints = 240,
  minutes: SeriesPoint[] = [],
): { pts: Pt[]; span: number; spanSec: number; bucket: number; averagedUntilX: number | null } {
  const first = Math.floor(firstMs / 1000);
  const spanSec = Math.max(1, Math.floor(lastMs / 1000) - first + 1);
  const bucket = Math.max(1, Math.ceil(spanSec / maxPoints));
  const n = Math.ceil(spanSec / bucket);
  const pts: Pt[] = Array.from({ length: n }, (_, i) => ({ x: i * bucket, inb: 0, out: 0 }));
  const add = (sec: number, inb: number, out: number) => {
    const i = Math.floor((sec - first) / bucket);
    if (i >= 0 && i < n) {
      pts[i]!.inb += inb / bucket;
      pts[i]!.out += out / bucket;
    }
  };
  let averagedUntil: number | null = null;
  for (const m of minutes) {
    for (let k = 0; k < 60; k++) add(m.t + k, m.bytes_in / 60, m.bytes_out / 60);
    averagedUntil = Math.max(averagedUntil ?? 0, m.t + 60);
  }
  for (const p of series) add(p.t, p.bytes_in, p.bytes_out);
  return {
    pts,
    span: Math.max((n - 1) * bucket, 1),
    spanSec,
    bucket,
    averagedUntilX: averagedUntil == null ? null : Math.min(Math.max(averagedUntil - first, 0), spanSec),
  };
}
