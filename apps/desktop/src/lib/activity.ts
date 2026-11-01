import type { Flow, GraphSnapshot } from "./ipc";
import { nodeForAddress } from "./nodeFlows";

/**
 * Live activity on the topology: which traffic edges carried bytes in the last
 * few seconds and in which direction, and which local devices are new.
 * Only flows captured live by this Mac feed it; configuration edges (route,
 * DNS, Wi-Fi) never move, because no data is observed on them.
 */

/** An edge counts as active for this long after its last bytes. */
export const ACTIVE_MS = 5000;
/** Devices seen in the first seconds of a capture are the baseline, not "new". */
export const WARMUP_MS = 10_000;
/** A new-device marker fades by itself after this long. */
export const NEW_MARK_MS = 60_000;

export interface Direction {
  /** When bytes last moved this way, and how fast (bytes per second) over the last poll. */
  at: number;
  rate: number;
}

/** Per remote address: this Mac → remote ("out") and remote → this Mac ("in"). */
export type Activity = Map<string, { out: Direction | null; in: Direction | null }>;

const flowKey = (f: Flow) => `${f.key.transport}|${f.key.local}|${f.key.local_port}|${f.key.remote}|${f.key.remote_port}`;

/** Bytes that moved per remote address between two capture polls. */
export function addressDeltas(prev: Flow[] | null, cur: Flow[]): Map<string, { out: number; in: number }> {
  const before = new Map((prev ?? []).map((f) => [flowKey(f), f]));
  const out = new Map<string, { out: number; in: number }>();
  for (const f of cur) {
    const p = before.get(flowKey(f));
    // Without a previous poll there is no "since": nothing counts as moving yet.
    if (!prev) continue;
    const dOut = Math.max(0, f.bytes_out - (p?.bytes_out ?? 0));
    const dIn = Math.max(0, f.bytes_in - (p?.bytes_in ?? 0));
    if (dOut === 0 && dIn === 0) continue;
    const acc = out.get(f.key.remote) ?? { out: 0, in: 0 };
    acc.out += dOut;
    acc.in += dIn;
    out.set(f.key.remote, acc);
  }
  return out;
}

/** Fold one poll's deltas into the running activity. */
export function stepActivity(state: Activity, deltas: Map<string, { out: number; in: number }>, now: number, elapsedMs: number): Activity {
  const next: Activity = new Map(state);
  const per = (bytes: number) => (bytes * 1000) / Math.max(elapsedMs, 1);
  for (const [addr, d] of deltas) {
    const was = next.get(addr) ?? { out: null, in: null };
    next.set(addr, {
      out: d.out > 0 ? { at: now, rate: per(d.out) } : was.out,
      in: d.in > 0 ? { at: now, rate: per(d.in) } : was.in,
    });
  }
  return next;
}

export const isActive = (d: Direction | null, now: number) => d != null && now - d.at < ACTIVE_MS;

/** 1–3 moving dots: volume is read from their number, never from their speed. */
export function dotCount(bytesPerSecond: number): 1 | 2 | 3 {
  if (bytesPerSecond >= 100_000) return 3;
  if (bytesPerSecond >= 10_000) return 2;
  return 1;
}

export interface EdgeMotion {
  /** The graph node at the far end of the traffic edge from this Mac. */
  nodeId: string;
  out: 0 | 1 | 2 | 3;
  in: 0 | 1 | 2 | 3;
}

/** Which traffic edges move now, per node of the graph. Several addresses of one node add up. */
export function edgeMotions(g: GraphSnapshot, activity: Activity, now: number): EdgeMotion[] {
  const byNode = new Map<string, { out: number; in: number }>();
  for (const [addr, a] of activity) {
    const node = nodeForAddress(g, addr);
    if (!node) continue;
    const acc = byNode.get(node) ?? { out: 0, in: 0 };
    if (isActive(a.out, now)) acc.out += a.out!.rate;
    if (isActive(a.in, now)) acc.in += a.in!.rate;
    byNode.set(node, acc);
  }
  return [...byNode]
    .filter(([, r]) => r.out > 0 || r.in > 0)
    .map(([nodeId, r]) => ({ nodeId, out: r.out > 0 ? dotCount(r.out) : 0, in: r.in > 0 ? dotCount(r.in) : 0 }));
}

/** First time each remote address appeared in this capture. */
export function stepFirstSeen(firstSeen: Map<string, number>, cur: Flow[], now: number): Map<string, number> {
  let next: Map<string, number> | null = null;
  for (const f of cur) {
    if (firstSeen.has(f.key.remote) || next?.has(f.key.remote)) continue;
    next ??= new Map(firstSeen);
    next.set(f.key.remote, now);
  }
  return next ?? firstSeen;
}

/**
 * Local devices to mark as new: first seen after the warm-up, within the last
 * minute, and not yet looked at. Internet destinations are not "devices".
 */
export function newNodes(g: GraphSnapshot, firstSeen: Map<string, number>, captureStart: number, seenByUser: Set<string>, now: number): string[] {
  const out = new Set<string>();
  for (const [addr, at] of firstSeen) {
    if (at - captureStart < WARMUP_MS || now - at >= NEW_MARK_MS) continue;
    const id = nodeForAddress(g, addr);
    if (!id || id === "external" || seenByUser.has(id)) continue;
    const node = g.nodes.find((n) => n.id === id);
    if (node?.role_hypothesis === "local_peer") out.add(id);
  }
  return [...out];
}
