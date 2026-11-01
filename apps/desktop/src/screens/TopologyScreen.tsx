import cytoscape, { type Core, type StylesheetJson } from "cytoscape";
import { iconDataUri, roleIcon } from "../lib/topologyIcons";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { edgeMotions, newNodes } from "../lib/activity";
import { TopologyActivity } from "./TopologyActivity";
import { useCapture } from "../app/capture";
import { useImport } from "../app/imported";
import { useProfile } from "../app/profile";
import { useSelection } from "../app/selection";
import { useI18n } from "../i18n";
import type { MessageKey } from "../i18n/en";
import type { Asset, TopologyEdge } from "../lib/ipc";
import { edgeId, flowOnly, graphSignature, isCenter, primaryIdentifier, radialPositions, roleKey, toElements } from "../lib/topologyModel";
import { endpoint, fmtBytes, fmtLocalTime, fmtNum, transportName } from "../lib/format";
import { flowsFor, graphView, type FlowSelection, type GraphSnapshot, type GraphView, type SourceRef, type TimeWindow } from "../lib/ipc";
import { filterForNode, nodeForAddress, trafficFilterFor } from "../lib/nodeFlows";
import { resolveSource, toSourceRef } from "../lib/source";
import { fractionsOf, presets, windowFromFractions } from "../lib/timeWindow";
import { SourceBar } from "./SourceBar";

/**
 * Topology V2 (design §5): one spacious evidence graph, inspector closed until
 * something is selected, overlays off. Edge line style encodes epistemic status
 * (solid / dashed / dotted), never colour alone.
 */

type Subject = { kind: "node"; asset: Asset } | { kind: "edge"; edge: TopologyEdge };

function cssVar(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function stylesheet(): StylesheetJson {
  const fg = cssVar("--color-text-primary");
  const muted = cssVar("--color-text-secondary");
  const elev = cssVar("--color-bg-elevated");
  const surface = cssVar("--color-bg-surface");
  const accent = cssVar("--color-accent-primary");
  const font = cssVar("--font-sans");
  return [
    {
      selector: "node",
      style: {
        shape: "round-rectangle",
        "background-color": elev,
        "border-width": 1,
        "border-color": muted,
        "border-opacity": 0.55,
        label: "data(label)",
        color: fg,
        "font-family": font,
        "font-size": 13,
        "text-wrap": "wrap",
        "line-height": 1.25,
        // Icon on top, the role and its identifier underneath.
        "text-valign": "center",
        "text-halign": "center",
        "text-margin-y": 13,
        "background-image": (n: cytoscape.NodeSingular) => iconDataUri(roleIcon(n.data("role")), fg),
        "background-width": "24px",
        "background-height": "24px",
        "background-position-x": "50%",
        "background-position-y": "11px",
        "background-clip": "none",
        // Explicit size: `width: "label"` is deprecated in Cytoscape 3.3x.
        width: (n: cytoscape.NodeSingular) =>
          Math.max(104, ...String(n.data("label") ?? "").split("\n").map((l) => l.length * 7.6)) + 28,
        height: 82,
      },
    },
    { selector: 'node[role = "this_mac"], node[role = "capture_host"]', style: { "border-style": "double", "border-width": 3 } },
    { selector: 'node[status = "inferred"]', style: { "border-style": "dashed" } },
    {
      selector: 'node[status = "unverified"]',
      style: {
        "border-style": "dotted",
        "background-color": surface,
        color: muted,
        "background-image": (n: cytoscape.NodeSingular) => iconDataUri(roleIcon(n.data("role")), muted),
      },
    },
    {
      selector: "edge",
      style: {
        width: 1.5,
        "line-color": muted,
        "line-opacity": 0.7,
        "curve-style": "bezier",
        "target-arrow-shape": "triangle",
        "target-arrow-color": muted,
        "arrow-scale": 0.8,
        // Parallel relations between the same two nodes (route and traffic) fan out.
        "control-point-step-size": 44,
        // Every edge says what it is, in plain words, on a pill that hides the line under it.
        label: "data(relationLabel)",
        "font-family": font,
        "font-size": 11,
        color: fg,
        "text-rotation": "none",
        "text-background-color": surface,
        "text-background-opacity": 1,
        "text-background-shape": "roundrectangle",
        "text-background-padding": "3px",
        "text-border-color": muted,
        "text-border-width": 1,
        "text-border-opacity": 0.35,
      },
    },
    { selector: 'edge[relation = "FLOW_OBSERVED"]', style: { width: 1.2, "line-opacity": 0.55 } },
    {
      selector: "edge[?bidir]",
      style: { "source-arrow-shape": "triangle", "source-arrow-color": muted },
    },
    { selector: 'edge[status = "inferred"]', style: { "line-style": "dashed" } },
    { selector: 'edge[status = "unverified"]', style: { "line-style": "dotted" } },
    // Live activity: an edge that carried bytes in the last seconds, a device that just appeared.
    { selector: "edge.active", style: { "line-color": accent, "target-arrow-color": accent, "source-arrow-color": accent, "line-opacity": 1, width: 2 } },
    { selector: "node.is-new", style: { "border-color": accent, "border-width": 2, "border-opacity": 1 } },
    { selector: "node:selected", style: { "border-color": accent, "border-width": 2, "border-opacity": 1 } },
    { selector: 'node[role = "this_mac"]:selected', style: { "border-width": 4 } },
    {
      selector: "edge:selected",
      style: { "line-color": accent, "target-arrow-color": accent, "line-opacity": 1, width: 2 },
    },
  ];
}

function statusKey(s: string): MessageKey {
  return `status.${s}` as MessageKey;
}

/** Flows behind the selected node or edge (FR-005), same window as the graph. */
function NodeFlows({ subject, graph, source, window }: { subject: Subject; graph: GraphSnapshot; source: SourceRef; window: TimeWindow | null }) {
  const { t } = useI18n();
  const { setSelection, selection, setScreen } = useSelection();
  const nodeId =
    subject.kind === "node"
      ? subject.asset.id
      : [subject.edge.source, subject.edge.target].find((id) => {
          const n = graph.nodes.find((x) => x.id === id);
          return n && !isCenter(n);
        }) ?? subject.edge.source;
  const filter = filterForNode(graph, nodeId);
  const trafficFilter = trafficFilterFor(graph, nodeId, source);
  const [sel, setSel] = useState<FlowSelection | null>(null);
  const [error, setError] = useState<string | null>(null);
  const key = JSON.stringify([source, filter, window]);
  useEffect(() => {
    if (!filter) return;
    let alive = true;
    setSel(null);
    flowsFor(source, filter, window)
      .then((v) => alive && setSel(v))
      .catch((e) => alive && setError(String(e)));
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);
  if (!filter || (filter.kind === "remotes" && filter.addresses.length === 0)) return <p className="meta">{t("inspector.traffic.noAddress")}</p>;
  if (error) return <p className="meta">{error}</p>;
  if (!sel) return <p className="meta">{t("topology.loading")}</p>;
  if (sel.total === 0) return <p className="meta">{t(window ? "inspector.traffic.noneInWindow" : "inspector.traffic.none")}</p>;
  return (
    <div className="node-flows">
      <p className="meta">
        <span className="mono">{fmtNum(sel.total)}</span> {t("traffic.flows")} · <span className="mono">{fmtBytes(sel.bytes)}</span>
        {sel.total > sel.flows.length && (
          <>
            {" "}
            · {t("inspector.traffic.top")} {sel.flows.length}
          </>
        )}
      </p>
      <ul className="ids">
        {sel.flows.map((f) => (
          <li key={`${f.key.transport}|${f.key.local}|${f.key.local_port}|${f.key.remote}|${f.key.remote_port}`}>
            <span className="meta mono">{transportName(f.key.transport)}</span> <span className="mono">{endpoint(f.key.remote, f.key.remote_port)}</span>
            <span className="meta"> · {fmtBytes(f.bytes_in + f.bytes_out)}</span>
          </li>
        ))}
      </ul>
      {trafficFilter && (
        <button
          className="chip"
          onClick={() => {
            setSelection({ ...selection, trafficFilter });
            setScreen("traffic");
          }}
        >
          {t("inspector.traffic.open")}
        </button>
      )}
      {window && <p className="meta small">{t("inspector.traffic.windowNote")}</p>}
    </div>
  );
}

function Inspector({ subject, onClose, graph, source, window }: { subject: Subject; onClose: () => void; graph: GraphSnapshot; source: SourceRef; window: TimeWindow | null }) {
  const { t } = useI18n();
  const [tab, setTab] = useState<"overview" | "services" | "traffic" | "findings" | "evidence" | "explain">("overview");
  const tabs = ["overview", "services", "traffic", "findings", "evidence", "explain"] as const;
  const isNode = subject.kind === "node";
  const evidence = isNode ? subject.asset.evidence_refs : subject.edge.evidence_ids;
  const status = isNode ? subject.asset.epistemic_status : subject.edge.epistemic_status;
  const confidence = isNode ? subject.asset.confidence : subject.edge.confidence;
  const title = isNode ? t(roleKey(subject.asset.role_hypothesis)) : subject.edge.relation_type;
  const sub = isNode ? subject.asset.id : `${subject.edge.source} → ${subject.edge.target}`;

  return (
    <aside className="inspector" aria-label={title}>
      <header className="inspector-head">
        <div>
          <div className="inspector-title">{title}</div>
          <div className="mono meta">{sub}</div>
        </div>
        <button className="chip" onClick={onClose}>
          {t("inspector.close")}
        </button>
      </header>
      <div className="tabs" role="tablist">
        {tabs.map((k) => (
          <button key={k} role="tab" aria-selected={tab === k} className="tab" onClick={() => setTab(k)}>
            {t(`inspector.tab.${k}` as MessageKey)}
          </button>
        ))}
      </div>
      <div className="inspector-body" role="tabpanel">
        {tab === "overview" && (
          <dl className="facts">
            {!isNode && (
              <>
                <dt>{t("inspector.relation")}</dt>
                <dd className="mono">{subject.edge.relation_type}</dd>
                <dt>{t("inspector.from")}</dt>
                <dd className="mono">{subject.edge.source}</dd>
                <dt>{t("inspector.to")}</dt>
                <dd className="mono">{subject.edge.target}</dd>
              </>
            )}
            <dt>{t("inspector.status")}</dt>
            <dd>{t(statusKey(status))}</dd>
            <dt>{t("inspector.confidence")}</dt>
            <dd>{t(`confidence.${confidence}` as MessageKey)}</dd>
            {isNode && (
              <>
                <dt>{t("inspector.identifiers")}</dt>
                <dd>
                  {subject.asset.observed_identifiers.length === 0 ? (
                    <span className="meta">{t("inspector.noIdentifiers")}</span>
                  ) : (
                    <ul className="ids">
                      {subject.asset.observed_identifiers.map((i) => (
                        <li key={i.kind + i.value}>
                          <span className="meta mono">{i.kind}</span> <span className="mono">{i.value}</span>
                        </li>
                      ))}
                    </ul>
                  )}
                  {subject.asset.observed_identifiers.some((i) => i.kind === "mac_address_private") && (
                    <p className="meta small">{t("inspector.privateMac")}</p>
                  )}
                  {subject.asset.evidence_refs.some((e) => e.endsWith(":link-binding")) && (
                    <p className="meta small">{t("inspector.mergedByMac")}</p>
                  )}
                </dd>
              </>
            )}
          </dl>
        )}
        {tab === "services" && <p className="meta">{t("inspector.services.empty")}</p>}
        {tab === "traffic" && <NodeFlows subject={subject} graph={graph} source={source} window={window} />}
        {tab === "findings" && <p className="meta">{t("inspector.findings.empty")}</p>}
        {tab === "evidence" && (
          <ul className="evidence">
            {evidence.map((ev) => (
              <li key={ev}>
                <div>{t(`ev.${ev}` as MessageKey) ?? ev}</div>
                <div className="mono meta">{ev}</div>
              </li>
            ))}
          </ul>
        )}
        {tab === "explain" &&
          (isNode ? (
            <div className="explain-block">
              <p>{t(`explain.${subject.asset.role_hypothesis}.what` as MessageKey)}</p>
              <p className="meta">{t(`explain.${subject.asset.role_hypothesis}.not` as MessageKey)}</p>
            </div>
          ) : (
            <div className="explain-block">
              <p>{t(`explain.${subject.edge.relation_type}` as MessageKey)}</p>
            </div>
          ))}
      </div>
    </aside>
  );
}

const MAX_FIT_ZOOM = 1;

/** Fit the graph, but never zoom a small graph in beyond MAX_FIT_ZOOM. */
const ACTIVITY_KEY = "calm.topology.activity";

/** "Live activity" is on unless the viewer turned it off. */
function readActivityPref(): boolean {
  try {
    return window.localStorage.getItem(ACTIVITY_KEY) !== "off";
  } catch {
    return true;
  }
}

function saveActivityPref(on: boolean) {
  try {
    window.localStorage.setItem(ACTIVITY_KEY, on ? "on" : "off");
  } catch {
    /* per-viewer convenience only */
  }
}

/** macOS "Reduce motion": nothing moves, state is still shown. */
function useReducedMotion(): boolean {
  const [reduced, setReduced] = useState(() => window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false);
  useEffect(() => {
    const m = window.matchMedia?.("(prefers-reduced-motion: reduce)");
    if (!m) return;
    const on = () => setReduced(m.matches);
    m.addEventListener("change", on);
    return () => m.removeEventListener("change", on);
  }, []);
  return reduced;
}

function fitCapped(cy: Core, padding = 48) {
  cy.fit(undefined, padding);
  if (cy.zoom() > MAX_FIT_ZOOM) {
    cy.zoom(MAX_FIT_ZOOM);
    cy.center();
  }
}

function TimePanel({ span, window, onChange, inWindow, total }: {
  span: [number, number];
  window: TimeWindow | null;
  onChange: (w: TimeWindow | null) => void;
  inWindow: number;
  total: number;
}) {
  const { t } = useI18n();
  const [a, b] = fractionsOf(span, window);
  const set = (x: number, y: number) => onChange(x <= 0 && y >= 1 ? null : windowFromFractions(span, x, y));
  return (
    <div className="time-panel" role="group" aria-label={t("topology.tool.time")}>
      <div className="seg-chips">
        {presets(span).map((p) => (
          <button
            key={p.key}
            className="chip small"
            aria-pressed={JSON.stringify(p.window) === JSON.stringify(window)}
            onClick={() => onChange(p.window)}
          >
            {t(`time.${p.key}` as MessageKey)}
          </button>
        ))}
      </div>
      <label>
        <span className="meta">{t("time.from")}</span>
        <input type="range" min={0} max={1000} value={Math.round(a * 1000)} onChange={(e) => set(Number(e.target.value) / 1000, b)} />
      </label>
      <label>
        <span className="meta">{t("time.to")}</span>
        <input type="range" min={0} max={1000} value={Math.round(b * 1000)} onChange={(e) => set(a, Number(e.target.value) / 1000)} />
      </label>
      <p className="meta">
        <span className="mono">{fmtLocalTime(window?.from_ms ?? span[0])}</span> – <span className="mono">{fmtLocalTime(Math.min(window?.to_ms ?? span[1], span[1]))}</span> ·{" "}
        <span className="mono">{fmtNum(inWindow)}</span> / <span className="mono">{fmtNum(total)}</span> {t("time.flowsActive")}. {t("time.note")}
      </p>
    </div>
  );
}

export function TopologyScreen() {
  const { t, locale } = useI18n();
  const { graph: liveGraph, loading, refresh } = useProfile();
  const { selection, setSelection } = useSelection();
  const [timeOpen, setTimeOpen] = useState(false);
  const [windowView, setWindowView] = useState<GraphView | null>(null);
  const [observedOnly, setObservedOnly] = useState(false);
  // Overlays are off by default (design §5).
  const [trafficToggle, setShowTraffic] = useState(false);
  const { running: capturing, view: captureView, activity, firstSeen, seenByUser, markSeen, pulsed, markPulsed } = useCapture();
  const imp = useImport();
  const [activityOn, setActivityOn] = useState(readActivityPref);
  const reduced = useReducedMotion();
  const [cyInst, setCyInst] = useState<Core | null>(null);
  // While capturing, the live graph is re-read every 5 s; redrawn only when it changed.
  const [polledGraph, setPolledGraph] = useState<GraphSnapshot | null>(null);
  // Imported files and saved snapshots are shown on their own, never merged
  // with this Mac's live graph.
  const r = resolveSource(imp.source, liveGraph, imp.view, imp.saved);
  const sourceRef = toSourceRef(r, imp.saved);
  const sourceKey = JSON.stringify(sourceRef);
  const imported = r.perspective === "host";
  const win = selection.timeWindow;
  // With a time window the backend rebuilds the graph from flows in that window.
  const live = r.isLive && capturing;
  const graph = win && windowView ? windowView.graph : live && polledGraph ? polledGraph : r.graph;
  const showTraffic = !r.isLive || trafficToggle || win != null;

  // A different source has a different time span: start from everything again.
  const firstSource = useRef(true);
  useEffect(() => {
    if (firstSource.current) {
      firstSource.current = false;
      return;
    }
    setWindowView(null);
    if (selection.timeWindow) setSelection({ ...selection, timeWindow: null });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sourceKey]);

  // Span and windowed graph, while the time panel is open or a window is set.
  useEffect(() => {
    if (!timeOpen && !win) return;
    let alive = true;
    const load = () =>
      graphView(sourceRef, win)
        .then((v) => alive && setWindowView(v))
        .catch(() => undefined);
    void load();
    const id = r.isLive && capturing ? window.setInterval(() => void load(), 5000) : null;
    return () => {
      alive = false;
      if (id) window.clearInterval(id);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sourceKey, JSON.stringify(win), timeOpen, capturing]);

  useEffect(() => {
    if (!live || win) {
      setPolledGraph(null);
      return;
    }
    let alive = true;
    const load = () =>
      graphView(sourceRef, null)
        .then((v) => alive && setPolledGraph((cur) => (graphSignature(cur) === graphSignature(v.graph) ? cur : v.graph)))
        .catch(() => undefined);
    void load();
    const id = window.setInterval(() => void load(), 5000);
    return () => {
      alive = false;
      window.clearInterval(id);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [live, sourceKey, JSON.stringify(win)]);

  // Live activity, recomputed on every capture poll (once a second).
  const now = useMemo(() => Date.now(), [activity, captureView]); // eslint-disable-line react-hooks/exhaustive-deps
  const motions = useMemo(
    () => (graph && live && activityOn && showTraffic ? edgeMotions(graph, activity, now) : []),
    [graph, live, activityOn, showTraffic, activity, now],
  );
  const newIds = useMemo(
    () => (graph && live && captureView ? newNodes(graph, firstSeen, captureView.started_at_ms, seenByUser, now) : []),
    [graph, live, captureView, firstSeen, seenByUser, now],
  );
  const pulseIds = useMemo(() => (activityOn ? newIds.filter((id) => !pulsed.has(id)) : []), [activityOn, newIds, pulsed]);
  const centerId = graph?.nodes.find(isCenter)?.id ?? null;
  const accentColor = useMemo(() => cssVar("--color-accent-primary"), []);
  const onPulsed = useCallback((ids: string[]) => markPulsed(ids), [markPulsed]);

  // Tint the edges that move and frame the new devices (also under reduced motion).
  useEffect(() => {
    if (!cyInst || !centerId) return;
    cyInst.batch(() => {
      cyInst.edges().removeClass("active");
      cyInst.nodes().removeClass("is-new");
      for (const m of motions) {
        cyInst
          .edges('[relation = "FLOW_OBSERVED"]')
          .filter((e) => (e.source().id() === centerId && e.target().id() === m.nodeId) || (e.source().id() === m.nodeId && e.target().id() === centerId))
          .addClass("active");
      }
      for (const id of newIds) cyInst.getElementById(id).addClass("is-new");
    });
  }, [cyInst, centerId, motions, newIds]);

  // Looking at a new device clears its marker.
  useEffect(() => {
    if (selection.subjectId && newIds.includes(selection.subjectId)) markSeen(selection.subjectId);
  }, [selection.subjectId, newIds, markSeen]);

  // "Show in Topology" from Traffic: select the node that owns the address.
  useEffect(() => {
    const addr = selection.focusAddress;
    if (!addr || !graph) return;
    if (r.isLive && !trafficToggle) {
      setShowTraffic(true);
      return; // the graph with traffic arrives on the next render
    }
    setSelection({ ...selection, subjectId: nodeForAddress(graph, addr), focusAddress: null });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selection.focusAddress, graph, trafficToggle]);

  // While traffic is shown and capture runs, re-read the graph every 5 s.
  useEffect(() => {
    if (!showTraffic || !capturing) return;
    const id = window.setInterval(() => void refresh(), 5000);
    return () => window.clearInterval(id);
  }, [showTraffic, capturing, refresh]);
  const host = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);

  const subject: Subject | null = useMemo(() => {
    const id = selection.subjectId;
    if (!graph || !id) return null;
    const asset = graph.nodes.find((n) => n.id === id);
    if (asset) return { kind: "node", asset };
    const edge = graph.edges.find((e) => edgeId(e) === id);
    return edge ? { kind: "edge", edge } : null;
  }, [graph, selection.subjectId]);

  // (Re)build the graph when data, language or filter changes.
  useEffect(() => {
    if (!host.current || !graph) return;
    const cy = cytoscape({
      container: host.current,
      elements: toElements(graph, t, observedOnly, showTraffic),
      style: stylesheet(),
      layout: { name: "preset", positions: radialPositions(graph, observedOnly, showTraffic), fit: true, padding: 40 },
      minZoom: 0.4,
      maxZoom: 2.5,
      wheelSensitivity: 0.3,
      boxSelectionEnabled: false,
      autoungrabify: false,
    });
    cy.on("tap", "node, edge", (evt) => setSelection({ ...selection, subjectId: evt.target.id() }));
    cy.on("tap", (evt) => {
      if (evt.target === cy) setSelection({ ...selection, subjectId: null });
    });
    if (selection.subjectId) cy.getElementById(selection.subjectId).select();
    // A small graph (e.g. a narrow time window) should not be blown up to fill the canvas.
    fitCapped(cy, 40);
    cyRef.current = cy;
    setCyInst(cy);
    return () => {
      cy.destroy();
      cyRef.current = null;
      setCyInst(null);
    };
    // selection is applied once per rebuild; tap handlers write it back.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graph, locale, observedOnly, showTraffic]);

  // A different graph: drop a selection that no longer exists.
  useEffect(() => {
    if (selection.subjectId && graph && !graph.nodes.some((n) => n.id === selection.subjectId) && !graph.edges.some((e) => edgeId(e) === selection.subjectId)) {
      setSelection({ ...selection, subjectId: null });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graph]);

  // Re-fit when the inspector opens or closes: the canvas width changes.
  const inspectorOpen = subject !== null;
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.resize();
    fitCapped(cy);
  }, [inspectorOpen]);

  // Mirror the shared selection onto the canvas (also when set from the list).
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.elements().unselect();
    if (selection.subjectId) cy.getElementById(selection.subjectId).select();
  }, [selection.subjectId]);

  const counts = graph
    ? {
        assets: graph.nodes.filter((n) => showTraffic || !flowOnly(n)).length,
        relations: graph.edges.filter((e) => showTraffic || e.relation_type !== "FLOW_OBSERVED").length,
      }
    : { assets: 0, relations: 0 };

  return (
    <>
      <header className="screen-header screen-header-row">
        <div>
          <h1>{t("nav.topology")}</h1>
          <p>{t(imported ? "topology.descImport" : "topology.desc")}</p>
          <p className="summary-line">
            <span className="mono">{counts.assets}</span> {t("topology.summary.assets")} ·{" "}
            <span className="mono">{counts.relations}</span> {t("topology.summary.relations")} ·{" "}
            <span className="mono">0</span> {t("topology.summary.findings")} —{" "}
            {t(
              imported
                ? "topology.summary.scopeImport"
                : showTraffic && graph?.edges.some((e) => e.relation_type === "FLOW_OBSERVED")
                  ? "topology.summary.scopeTraffic"
                  : "topology.summary.scope",
            )}
            {newIds.length > 0 && (
              <>
                {" · "}
                <button className="link-button" onClick={() => setSelection({ ...selection, subjectId: newIds[0]! })}>
                  <span className="mono">{newIds.length}</span> {t(newIds.length === 1 ? "topology.newDevice" : "topology.newDevices")}
                </button>
              </>
            )}
          </p>
        </div>
        {r.isLive && (
          <button className="chip" onClick={() => void refresh()} disabled={loading}>
            {t("overview.refresh")}
          </button>
        )}
      </header>

      <SourceBar />
      {r.kind.startsWith("saved") && imp.saved && (
        <div className="notice saved-banner">
          <strong>
            {t("session.savedBanner.title")}: {imp.saved.snapshot.label}
          </strong>
          <p>{t("session.savedBanner.topology")}</p>
        </div>
      )}
      {imported && (
        <div className="notice import-banner">
          <strong>{t("import.banner.title")}</strong>
          <p>{t("import.banner.topology")}</p>
        </div>
      )}

      <div className="toolbar" role="toolbar">
        <button className="chip" onClick={() => cyRef.current && fitCapped(cyRef.current)}>
          {t("topology.reset")}
        </button>
        <button className="chip" aria-pressed={observedOnly} onClick={() => setObservedOnly((v) => !v)}>
          {t("topology.tool.epistemic")}: {observedOnly ? t("status.observed") : t("topology.filter.all")}
        </button>
        {r.isLive && (
          <button className="chip" aria-pressed={showTraffic} onClick={() => setShowTraffic((v) => !v)}>
            {t("topology.tool.traffic")}
          </button>
        )}
        {r.isLive && (
          <button
            className="chip"
            aria-pressed={activityOn}
            title={t("topology.tool.activityHint")}
            onClick={() => {
              const v = !activityOn;
              setActivityOn(v);
              saveActivityPref(v);
            }}
          >
            {t("topology.tool.activity")}
          </button>
        )}
        <button className="chip" aria-pressed={timeOpen || win != null} onClick={() => setTimeOpen((v) => !v)}>
          {t("topology.tool.time")}
          {win ? `: ${fmtLocalTime(win.from_ms)}–${fmtLocalTime(win.to_ms - 1)}` : ""}
        </button>
        <button className="chip" disabled title={t("topology.disabledHint")}>
          {t("topology.tool.findings")}
        </button>
      </div>
      {live && activityOn && !showTraffic && <p className="meta small activity-hint">{t("topology.activityNeedsTraffic")}</p>}
      {timeOpen &&
        (windowView?.span ? (
          <TimePanel
            span={windowView.span}
            window={win}
            onChange={(w) => setSelection({ ...selection, timeWindow: w })}
            inWindow={windowView.flows_in_window}
            total={windowView.flows_total}
          />
        ) : (
          <p className="meta time-panel">{t(windowView ? "time.noFlows" : "topology.loading")}</p>
        ))}

      <div className={`topo-body ${subject ? "with-inspector" : ""}`}>
        <div className="topo-stage">
          <div className="topo-canvas" ref={host} aria-label={t("nav.topology")} role="img">
            {!graph && <div className="empty">{t("topology.loading")}</div>}
          </div>
          <TopologyActivity
            cy={cyInst}
            centerId={centerId}
            motions={motions}
            newIds={newIds}
            pulseIds={pulseIds}
            onPulsed={onPulsed}
            reduced={reduced}
            color={accentColor}
          />
        </div>
        {subject && (
          <Inspector
            key={selection.subjectId}
            subject={subject}
            graph={graph!}
            source={sourceRef}
            window={win}
            onClose={() => setSelection({ ...selection, subjectId: null })}
          />
        )}
      </div>

      {/* Keyboard and screen-reader access to the same elements as the canvas. */}
      {graph && (
        <ul className="sr-assets" aria-label={t("inspector.identifiers")}>
          {graph.nodes.map((n) => (
            <li key={n.id}>
              <button onClick={() => setSelection({ ...selection, subjectId: n.id })}>
                {t(roleKey(n.role_hypothesis))} {primaryIdentifier(n)} — {t(statusKey(n.epistemic_status))}
              </button>
            </li>
          ))}
        </ul>
      )}

      <div className="legend" aria-label="Edge legend">
        <span>
          <i /> {t("legend.observed")}
        </span>
        <span>
          <i className="dashed" /> {t("legend.inferred")}
        </span>
        <span>
          <i className="dotted" /> {t("legend.unverified")}
        </span>
        <span className="legend-note">{t(imported ? "topology.importNote" : "topology.unknownRel")}</span>
      </div>
    </>
  );
}
