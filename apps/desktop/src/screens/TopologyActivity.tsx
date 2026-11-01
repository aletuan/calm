import { useEffect, useRef } from "react";
import type { Core, EdgeSingular, NodeSingular } from "cytoscape";
import type { EdgeMotion } from "../lib/activity";

/**
 * Overlay that animates live traffic on the topology without touching the
 * graph: dots travel along Traffic edges towards the receiving side (1–3 dots
 * by volume), and a new device gets three expanding rings, then a small dot
 * that stays until it is looked at. Dots, not dashes: a dashed line already
 * means "inferred". With reduced motion nothing moves; active edges are only
 * tinted (by the graph's own style) and new devices keep their dot.
 */

const PERIOD_MS = 1400;
const PULSE_MS = 2100;
const PULSES = 3;

interface Props {
  cy: Core | null;
  centerId: string | null;
  motions: EdgeMotion[];
  /** Nodes to mark "new" (persistent dot). */
  newIds: string[];
  /** New nodes whose rings have not played yet. */
  pulseIds: string[];
  onPulsed: (ids: string[]) => void;
  reduced: boolean;
  color: string;
}

type P = { x: number; y: number };

const quad = (a: P, c: P, b: P, t: number): P => ({
  x: (1 - t) * (1 - t) * a.x + 2 * (1 - t) * t * c.x + t * t * b.x,
  y: (1 - t) * (1 - t) * a.y + 2 * (1 - t) * t * c.y + t * t * b.y,
});

function trafficEdge(cy: Core, center: string, node: string): EdgeSingular | null {
  const e = cy
    .edges('[relation = "FLOW_OBSERVED"]')
    .filter((x) => (x.source().id() === center && x.target().id() === node) || (x.source().id() === node && x.target().id() === center));
  return e.length ? e[0]! : null;
}

export function TopologyActivity({ cy, centerId, motions, newIds, pulseIds, onPulsed, reduced, color }: Props) {
  const canvas = useRef<HTMLCanvasElement>(null);
  const pulseStart = useRef(new Map<string, number>());

  useEffect(() => {
    const el = canvas.current;
    if (!el || !cy || !centerId) return;
    const ctx = el.getContext("2d");
    if (!ctx) return;
    let raf = 0;
    let alive = true;

    const draw = (now: number) => {
      // The graph is rebuilt when its data changes; a frame may still be queued for the old one.
      if (cy.destroyed()) return;
      const dpr = window.devicePixelRatio || 1;
      const w = el.clientWidth;
      const h = el.clientHeight;
      if (el.width !== Math.round(w * dpr) || el.height !== Math.round(h * dpr)) {
        el.width = Math.round(w * dpr);
        el.height = Math.round(h * dpr);
      }
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, w, h);
      ctx.fillStyle = color;
      ctx.strokeStyle = color;

      if (!reduced) {
        for (const m of motions) {
          const e = trafficEdge(cy, centerId, m.nodeId);
          if (!e || e.hidden()) continue;
          let s: P, t: P, mid: P;
          try {
            // Not yet laid out (first frames after a rebuild): skip this frame.
            s = e.renderedSourceEndpoint();
            t = e.renderedTargetEndpoint();
            mid = e.renderedMidpoint();
          } catch {
            continue;
          }
          // Control point of the quadratic through the rendered midpoint (straight edges stay straight).
          const c = { x: 2 * mid.x - (s.x + t.x) / 2, y: 2 * mid.y - (s.y + t.y) / 2 };
          const fromCenter = e.source().id() === centerId;
          const lanes: [number, boolean][] = [
            [m.out, fromCenter],
            [m.in, !fromCenter],
          ];
          for (const [count, forward] of lanes) {
            for (let k = 0; k < count; k++) {
              const phase = ((now / PERIOD_MS + k / count) % 1 + 1) % 1;
              // Keep dots off the node boxes: travel the middle 80 % of the edge.
              const u = 0.1 + 0.8 * phase;
              const p = quad(s, c, t, forward ? u : 1 - u);
              ctx.globalAlpha = 0.9;
              ctx.beginPath();
              ctx.arc(p.x, p.y, 3, 0, Math.PI * 2);
              ctx.fill();
            }
          }
        }
      }

      const done: string[] = [];
      for (const id of pulseIds) {
        const n = cy.getElementById(id) as NodeSingular;
        if (!n.length || n.hidden()) continue;
        if (reduced) {
          done.push(id);
          continue;
        }
        const start = pulseStart.current.get(id) ?? now;
        pulseStart.current.set(id, start);
        const age = now - start;
        if (age >= PULSE_MS) {
          done.push(id);
          continue;
        }
        const bb = n.renderedBoundingBox({ includeLabels: false });
        const cx = (bb.x1 + bb.x2) / 2;
        const cyy = (bb.y1 + bb.y2) / 2;
        const base = Math.max(bb.w, bb.h) / 2;
        const ring = (age % (PULSE_MS / PULSES)) / (PULSE_MS / PULSES);
        ctx.globalAlpha = 0.6 * (1 - ring);
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.arc(cx, cyy, base + 4 + ring * 26, 0, Math.PI * 2);
        ctx.stroke();
      }
      if (done.length) onPulsed(done);

      ctx.globalAlpha = 1;
      for (const id of newIds) {
        const n = cy.getElementById(id) as NodeSingular;
        if (!n.length || n.hidden()) continue;
        const bb = n.renderedBoundingBox({ includeLabels: false });
        ctx.beginPath();
        ctx.arc(bb.x2 - 6, bb.y1 + 6, 4, 0, Math.PI * 2);
        ctx.fill();
      }

      const moving = (!reduced && motions.length > 0) || pulseIds.length > done.length;
      if (alive && moving) raf = requestAnimationFrame(draw);
    };

    raf = requestAnimationFrame(draw);
    // Static marks (new-device dots, reduced motion) follow pans and zooms.
    const redraw = () => {
      cancelAnimationFrame(raf);
      raf = requestAnimationFrame(draw);
    };
    cy.on("render", redraw);
    return () => {
      alive = false;
      cancelAnimationFrame(raf);
      cy.removeListener("render", redraw);
    };
  }, [cy, centerId, motions, newIds, pulseIds, onPulsed, reduced, color]);

  return <canvas className="topo-activity" ref={canvas} aria-hidden />;
}
