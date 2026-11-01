/**
 * Y axis for throughput charts. One large spike must not flatten everything
 * else, and the chart must never hide a value: in "auto" the axis is cut only
 * when the peak is more than 10× the 95th percentile, just above the largest
 * value that is not such an outlier, and every point
 * above the cut is reported (`isClipped`) so it can be drawn as a ▲ marker with
 * its real value. "linear" and "log" are explicit choices for the user.
 */

export type AxisMode = "auto" | "linear" | "log";

export interface Axis {
  kind: "linear" | "clipped" | "log";
  /** Value at the top edge (bytes/s). */
  top: number;
  ticks: number[];
  /** 0 (bottom) … 1 (top) for a value; clipped values return 1. */
  frac: (v: number) => number;
  isClipped: (v: number) => boolean;
  clippedCount: number;
}

/** Minimum top so an idle chart is not scaled to a few bytes. */
const MIN_TOP = 1024;
/** Cut only when the peak exceeds the 95th percentile this many times. */
const OUTLIER_RATIO = 10;
/** Headroom above the largest ordinary value when cutting. */
const HEADROOM = 1.2;
/** Need at least this many non-zero seconds to judge what "normal" is. */
const MIN_SAMPLES = 10;

/** Nearest-rank percentile (p in 0..1); 0 for an empty list. */
export function percentile(values: number[], p: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const rank = Math.max(1, Math.ceil(p * sorted.length));
  return sorted[rank - 1]!;
}

function linear(top: number, kind: "linear" | "clipped", values: number[]): Axis {
  const isClipped = (v: number) => kind === "clipped" && v > top;
  return {
    kind,
    top,
    ticks: [0, top / 2, top],
    frac: (v) => Math.min(Math.max(v, 0), top) / top,
    isClipped,
    clippedCount: values.filter(isClipped).length,
  };
}

export function chartAxis(values: number[], mode: AxisMode): Axis {
  const max = Math.max(MIN_TOP, ...values);
  if (mode === "log") {
    const top = Math.max(...values, 1);
    const scale = Math.log1p(top);
    // Whole binary units; start at 1 KB when the data reaches it, since 1 B
    // sits right on top of 0.
    const ticks = [0];
    for (let t = top >= 1024 ? 1024 : 1; t <= top && ticks.length < 5; t *= 1024) ticks.push(t);
    return {
      kind: "log",
      top,
      ticks,
      frac: (v) => (v <= 0 ? 0 : Math.min(1, Math.log1p(v) / scale)),
      isClipped: () => false,
      clippedCount: 0,
    };
  }
  if (mode === "auto") {
    const positive = values.filter((v) => v > 0);
    if (positive.length >= MIN_SAMPLES) {
      const p95 = percentile(positive, 0.95);
      const limit = OUTLIER_RATIO * p95;
      if (p95 > 0 && max > limit) {
        // Top = largest value that is not an outlier, so ordinary bursts keep
        // their shape; only values beyond 10 × p95 are cut and marked.
        const ordinary = Math.max(...positive.filter((v) => v <= limit));
        return linear(Math.max(MIN_TOP, ordinary * HEADROOM), "clipped", values);
      }
    }
  }
  return linear(max, "linear", values);
}
