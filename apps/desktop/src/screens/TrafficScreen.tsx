import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useCapture } from "../app/capture";
import { useImport } from "../app/imported";
import { useSelection } from "../app/selection";
import { useSession } from "../app/session";
import { autoSaveOnStop } from "../lib/autoSave";
import { useI18n } from "../i18n";
import type { MessageKey } from "../i18n/en";
import { flowsFor, type Availability, type Flow, type FlowSelection, type ImportView, type LiveView, type SeriesPoint } from "../lib/ipc";
import { resolveSource, sameSource, toSourceRef } from "../lib/source";
import { roleKey } from "../lib/topologyModel";
import { dirKey, localCell, type Perspective } from "../lib/flowLabels";
import { flowPurpose } from "../lib/flowPurpose";
import { FLOW_COLUMNS, parseHidden, toggleColumn, visibleColumns, type FlowColumn } from "../lib/columns";
import { endpoint, fmtBytes, fmtDuration, fmtNum, fmtUtc, isGroup, shortHash, transportName } from "../lib/format";
import { chartAxis, type AxisMode } from "../lib/chartAxis";
import { livePoints, spanPoints, type Pt } from "../lib/series";
import { SourceBar } from "./SourceBar";

/**
 * Traffic (M1.3). Primary surface: throughput over time; flows below.
 * Everything is traffic that reached this Mac's interface — never other clients'.
 */

const WINDOW = 120; // seconds shown in the chart



const AXIS_MODES: AxisMode[] = ["auto", "linear", "log"];
const AXIS_KEY = "calm.chart.axis";

/** The user's axis choice; kept per viewer (browser storage may be unavailable). */
function useAxisMode(): [AxisMode, (m: AxisMode) => void] {
  const [mode, setMode] = useState<AxisMode>(() => {
    try {
      const v = window.localStorage.getItem(AXIS_KEY);
      return AXIS_MODES.includes(v as AxisMode) ? (v as AxisMode) : "auto";
    } catch {
      return "auto";
    }
  });
  const set = (m: AxisMode) => {
    setMode(m);
    try {
      window.localStorage.setItem(AXIS_KEY, m);
    } catch {
      /* per-viewer convenience only */
    }
  };
  return [mode, set];
}

/** Clipped points that get a value label; the rest get a marker only. */
const MAX_PEAK_LABELS = 3;

/**
 * Two lines over a fixed x range [0, span]. `markerX` draws a vertical start
 * marker. The Y axis follows `chartAxis`: in "auto" a lone spike no longer
 * flattens the baseline; points above the cut are drawn as ▲ at the top edge
 * with their real value, so nothing is hidden.
 */
function ChartSvg({ pts, span, left, right, markerX, markerText, label, inLabel, outLabel, unit }: {
  pts: Pt[];
  span: number;
  left: string;
  right: string;
  markerX?: number;
  markerText?: string;
  label: string;
  inLabel: string;
  outLabel: string;
  unit: string;
}) {
  const { t } = useI18n();
  const [mode, setMode] = useAxisMode();
  const W = 960;
  const H = 168;
  const P = { l: 84, r: 12, t: 18, b: 22 };
  const axis = chartAxis(pts.flatMap((p) => [p.inb, p.out]), mode);
  const x = (v: number) => P.l + (v / Math.max(span, 1)) * (W - P.l - P.r);
  const y = (v: number) => P.t + (1 - axis.frac(v)) * (H - P.t - P.b);
  const line = (k: "inb" | "out") => pts.map((p, i) => `${i ? "L" : "M"}${x(p.x).toFixed(1)},${y(p[k]).toFixed(1)}`).join(" ");
  const area = pts.length
    ? `${line("inb")} L${x(pts[pts.length - 1]!.x)},${y(0)} L${x(pts[0]!.x)},${y(0)} Z`
    : "";
  const peaks = pts
    .map((p) => ({ x: p.x, v: Math.max(p.inb, p.out) }))
    .filter((p) => axis.isClipped(p.v));
  const labelled = new Set([...peaks].sort((a, b) => b.v - a.v).slice(0, MAX_PEAK_LABELS).map((p) => p.x));
  return (
    <figure className="chart">
      <div className="chart-tools" role="group" aria-label={t("chart.axis")}>
        <span className="meta">{t("chart.axis")}:</span>
        {AXIS_MODES.map((m) => (
          <button key={m} className="chip small" aria-pressed={mode === m} onClick={() => setMode(m)}>
            {t(`chart.axis.${m}` as MessageKey)}
          </button>
        ))}
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={label} preserveAspectRatio="none">
        {axis.ticks.map((v) => (
          <g key={v}>
            <line x1={P.l} x2={W - P.r} y1={y(v)} y2={y(v)} className="grid" />
            <text x={P.l - 8} y={y(v) + 4} textAnchor="end" className="axis">
              {fmtBytes(Math.round(v))}/{unit}
            </text>
          </g>
        ))}
        {axis.kind === "clipped" && <line x1={P.l} x2={W - P.r} y1={P.t} y2={P.t} className="cut-line" />}
        {markerX != null && x(markerX) > P.l + 1 && (
          <g>
            <line x1={x(markerX)} x2={x(markerX)} y1={P.t} y2={H - P.b} className="start-mark" />
            {/* Near the left edge the note goes right of the marker, so it never covers the axis labels. */}
            <text
              x={x(markerX) - P.l > 200 ? x(markerX) - 6 : x(markerX) + 6}
              y={P.t + 12}
              textAnchor={x(markerX) - P.l > 200 ? "end" : "start"}
              className="axis"
            >
              {markerText}
            </text>
          </g>
        )}
        <path d={area} className="area-in" />
        <path d={line("inb")} className="line-in" />
        <path d={line("out")} className="line-out" />
        {peaks.map((p) => (
          <g key={p.x} className="peak">
            <path d={`M${x(p.x) - 4},${P.t} L${x(p.x) + 4},${P.t} L${x(p.x)},${P.t - 7} Z`} />
            {labelled.has(p.x) && (
              <text x={x(p.x)} y={P.t - 9} textAnchor={x(p.x) > W - 80 ? "end" : "middle"} className="axis peak-label">
                {fmtBytes(Math.round(p.v))}/{unit}
              </text>
            )}
          </g>
        ))}
        <text x={P.l} y={H - 4} className="axis">
          {left}
        </text>
        <text x={W - P.r} y={H - 4} textAnchor="end" className="axis">
          {right}
        </text>
      </svg>
      <figcaption className="chart-legend">
        <span>
          <i className="sw-in" /> {inLabel}
        </span>
        <span>
          <i className="sw-out" /> {outLabel}
        </span>
        {axis.kind === "clipped" && (
          <span className="chart-note">
            ▲ {t("chart.clippedNote")} {fmtBytes(Math.round(axis.top))}/{unit} ({peaks.length} {t("chart.clippedPoints")})
          </span>
        )}
        {axis.kind === "log" && <span className="chart-note">{t("chart.logNote")}</span>}
      </figcaption>
    </figure>
  );
}

/** Live: last 120 s; seconds before the capture started are left blank, never 0. */
function LiveChart({ series, startedAtMs }: { series: SeriesPoint[]; startedAtMs: number }) {
  const { t } = useI18n();
  const pts = livePoints(series, startedAtMs, WINDOW);
  return (
    <ChartSvg
      pts={pts}
      span={WINDOW - 1}
      left={`−${WINDOW}s`}
      right={t("traffic.chart.now")}
      markerX={pts.length ? pts[0]!.x : WINDOW - 1}
      markerText={t("traffic.chart.notMeasured")}
      label={t("traffic.chart.label")}
      inLabel={t("traffic.chart.in")}
      outLabel={t("traffic.chart.out")}
      unit="s"
    />
  );
}

/** Imported: the whole file span, bucketed to at most 240 points. */
function SpanChart({ series, minutes, firstMs, lastMs, perspective }: {
  series: SeriesPoint[];
  minutes?: SeriesPoint[];
  firstMs: number;
  lastMs: number;
  perspective: Perspective;
}) {
  const { t } = useI18n();
  const { pts, span, spanSec, averagedUntilX } = spanPoints(series, firstMs, lastMs, 240, minutes ?? []);
  return (
    <ChartSvg
      pts={pts}
      span={span}
      left="0s"
      right={`+${fmtDuration(spanSec * 1000)}`}
      markerX={averagedUntilX ?? undefined}
      markerText={t("chart.averagedBefore")}
      label={t("import.chart.label")}
      inLabel={t(perspective === "host" ? "import.chart.in" : "traffic.chart.in")}
      outLabel={t(perspective === "host" ? "import.chart.out" : "traffic.chart.out")}
      unit="s"
    />
  );
}

function CaptureControl() {
  const { t } = useI18n();
  const { probe, view, running, busy, startError, recheck, start, stop } = useCapture();
  const session = useSession();
  const { autoSave, setAutoSave } = useCapture();
  const stopAndMaybeSave = async () => {
    const packets = view?.snapshot.total_packets ?? 0;
    await stop();
    const d = autoSaveOnStop({
      enabled: autoSave,
      storeReady: session.status?.state === "ready",
      hasActive: session.active != null,
      packets,
    });
    if (d.save) await session.saveLive();
  };
  const [, tick] = useState(0);
  useEffect(() => {
    if (!running) return;
    const id = window.setInterval(() => tick((n) => n + 1), 1000);
    return () => window.clearInterval(id);
  }, [running]);

  const problem: Availability | null =
    startError ?? (probe && probe.availability.state !== "ready" ? probe.availability : null);

  if (running && view) {
    const s = view.stats;
    return (
      <div className="capture-bar" role="status">
        <span className="live-dot" aria-hidden />
        <span>
          {t("traffic.capturingOn")} <span className="mono">{view.interface}</span>
        </span>
        <span className="mono">{fmtDuration(Date.now() - view.started_at_ms)}</span>
        <span>
          <span className="mono">{fmtNum(view.snapshot.total_packets)}</span> {t("traffic.packets")}
        </span>
        <span>
          {t("traffic.drops")} <span className="mono">{fmtNum(s.dropped + s.if_dropped)}</span>
        </span>
        <span className="meta">{t("traffic.headersOnly")}</span>
        <span className="push stop-group">
          <label
            className="autosave"
            title={session.active ? `${t("capture.autosaveTitle")} “${session.active.meta.name}”` : t("session.saveNeedsActive")}
          >
            <input
              type="checkbox"
              checked={autoSave}
              disabled={!session.active}
              onChange={(e) => setAutoSave(e.target.checked)}
            />{" "}
            {session.active ? t("capture.autosave") : t("capture.autosaveNoSession")}
          </label>
          <button className="chip" onClick={() => void stopAndMaybeSave()} disabled={busy}>
            {t("traffic.stop")}
          </button>
        </span>
      </div>
    );
  }

  if (problem && problem.state === "permission_denied") {
    return (
      <div className="notice">
        <strong>{t("traffic.perm.title")}</strong>
        <p>{t("traffic.perm.body")}</p>
        <pre className="cmd mono">pnpm bpf:install</pre>
        <p className="meta">{t("traffic.perm.note")}</p>
        <button className="chip" onClick={() => void recheck()}>
          {t("traffic.retry")}
        </button>
      </div>
    );
  }
  if (problem) {
    return (
      <div className="notice">
        <strong>{t(problem.state === "no_interface" ? "traffic.noIface.title" : "traffic.error.title")}</strong>
        <p className="mono meta">{"detail" in problem ? problem.detail : ""}</p>
        <button className="chip" onClick={() => void recheck()}>
          {t("traffic.retry")}
        </button>
      </div>
    );
  }

  return (
    <div className="notice consent">
      <strong>{t(view ? "traffic.stopped.title" : "traffic.consent.title")}</strong>
      <ul>
        <li>{t("traffic.consent.headers")}</li>
        <li>{t("traffic.consent.vantage")}</li>
        <li>{t("traffic.consent.memory")}</li>
      </ul>
      <button className="button-primary" onClick={() => void start()} disabled={busy || !probe}>
        {t(view ? "traffic.startAgain" : "traffic.start")}
        {probe?.interface ? ` (${probe.interface})` : ""}
      </button>
    </div>
  );
}

const COLUMNS_KEY = "calm.flows.hiddenColumns";

/** Columns the viewer chose to hide; kept per viewer (browser storage may be unavailable). */
function useHiddenColumns(): [FlowColumn[], (h: FlowColumn[]) => void] {
  const [hidden, setHidden] = useState<FlowColumn[]>(() => {
    try {
      return parseHidden(window.localStorage.getItem(COLUMNS_KEY));
    } catch {
      return [];
    }
  });
  const set = (h: FlowColumn[]) => {
    setHidden(h);
    try {
      window.localStorage.setItem(COLUMNS_KEY, JSON.stringify(h));
    } catch {
      /* per-viewer convenience only */
    }
  };
  return [hidden, set];
}

/** "Columns" menu: tick the columns to show. */
function ColumnPicker({ hidden, onChange, label }: { hidden: FlowColumn[]; onChange: (h: FlowColumn[]) => void; label: (c: FlowColumn) => string }) {
  const { t } = useI18n();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const away = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const esc = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("mousedown", away);
    document.addEventListener("keydown", esc);
    return () => {
      document.removeEventListener("mousedown", away);
      document.removeEventListener("keydown", esc);
    };
  }, [open]);
  const shown = visibleColumns(hidden).length;
  return (
    <div className="column-picker" ref={ref}>
      <button className="chip small" aria-expanded={open} aria-haspopup="true" onClick={() => setOpen(!open)}>
        {t("traffic.columns")}
        {hidden.length > 0 && (
          <span className="mono">
            {" "}
            {shown}/{FLOW_COLUMNS.length}
          </span>
        )}{" "}
        ▾
      </button>
      {open && (
        <div className="column-menu" role="group" aria-label={t("traffic.columns")}>
          {FLOW_COLUMNS.map((c) => {
            const on = !hidden.includes(c);
            return (
              <label key={c}>
                <input type="checkbox" checked={on} disabled={on && shown === 1} onChange={() => onChange(toggleColumn(hidden, c))} /> {label(c)}
              </label>
            );
          })}
          <div className="column-menu-foot">
            <button className="chip small" onClick={() => onChange([])} disabled={hidden.length === 0}>
              {t("traffic.columns.showAll")}
            </button>
            <span className="meta small">{t("traffic.columns.note")}</span>
          </div>
        </div>
      )}
    </div>
  );
}

/**
 * Flow rows. With `startMs` the time column is "+s since start" (imported or
 * saved data); otherwise "seconds ago" (live). Columns can be hidden.
 */
function FlowTable({ flows, now, startMs, perspective }: { flows: Flow[]; now: number; startMs?: number; perspective: Perspective }) {
  const { t } = useI18n();
  const { selection, setSelection, setScreen } = useSelection();
  const [hidden, setHidden] = useHiddenColumns();
  const relative = startMs != null;
  const cols = visibleColumns(hidden);
  const label = (c: FlowColumn) => (c === "last" && relative ? t("import.col.at") : t(`traffic.col.${c}` as MessageKey));
  const numeric = (c: FlowColumn) => c === "packets" || c === "bytes" || c === "last";

  const cell = (c: FlowColumn, f: Flow) => {
    const k = f.key;
    switch (c) {
      case "proto":
        return <td key={c} className="mono">{transportName(k.transport)}</td>;
      case "purpose": {
        const p = flowPurpose(f);
        return (
          <td key={c} className="purpose" title={t(`purpose.${p}.why` as MessageKey)}>
            <span className={`purpose-mark p-${p}`} />
            {t(`purpose.${p}` as MessageKey)}
          </td>
        );
      }
      case "remote":
        return (
          <td key={c} className="mono remote">
            {isGroup(k.remote) ? (
              <span className="addr" title={endpoint(k.remote, k.remote_port)}>
                {endpoint(k.remote, k.remote_port)}
              </span>
            ) : (
              <button
                className="addr link"
                title={`${endpoint(k.remote, k.remote_port)} — ${t("traffic.showInTopology")}`}
                onClick={() => {
                  setSelection({ ...selection, subjectId: null, focusAddress: k.remote });
                  setScreen("topology");
                }}
              >
                {endpoint(k.remote, k.remote_port)}
              </button>
            )}
            {isGroup(k.remote) && <span className="tag">{t("traffic.group")}</span>}
          </td>
        );
      case "local": {
        const lc = localCell(f);
        return (
          <td key={c} className="mono meta">
            {lc.prefix && <span className="local-prefix">{t(lc.prefix)} </span>}
            {lc.value}
          </td>
        );
      }
      case "direction":
        return <td key={c} className="dir">{t(dirKey(f, perspective))}</td>;
      case "packets":
        return (
          <td key={c} className="mono num">
            {fmtNum(f.packets_out)} ↑ {fmtNum(f.packets_in)} ↓
          </td>
        );
      case "bytes":
        return <td key={c} className="mono num">{fmtBytes(f.bytes_in + f.bytes_out)}</td>;
      case "last":
        return (
          <td key={c} className="mono num meta">
            {relative ? `+${((f.first_seen_ms - (startMs ?? 0)) / 1000).toFixed(1)}s` : `${Math.max(0, Math.round((now - f.last_seen_ms) / 1000))}s`}
          </td>
        );
    }
  };

  return (
    <>
      <div className="table-tools">
        <ColumnPicker hidden={hidden} onChange={setHidden} label={label} />
      </div>
      <div className="table-scroll">
        <table className="flow-table">
          <thead>
            <tr>
              {cols.map((c) => (
                <th key={c} className={numeric(c) ? "num" : undefined} title={c === "purpose" ? t("traffic.purposeHint") : undefined}>
                  {label(c)}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {flows.map((f) => {
              const k = f.key;
              const id = `${transportName(k.transport)}|${k.local}|${k.local_port}|${k.remote}|${k.remote_port}`;
              return <tr key={id}>{cols.map((c) => cell(c, f))}</tr>;
            })}
          </tbody>
        </table>
      </div>
    </>
  );
}

/**
 * The flow list, or — after "Open Traffic" on a Topology node — only that
 * node's flows, fetched from the same data and time window as the graph.
 * A filter made from other data (the source changed) is not applied.
 */
function FlowsOrNode({ now, startMs, perspective, children }: { now: number; startMs?: number; perspective: Perspective; children: ReactNode }) {
  const { t } = useI18n();
  const { selection, setSelection } = useSelection();
  const imp = useImport();
  const { running } = useCapture();
  const r = resolveSource(imp.source, null, imp.view, imp.saved);
  const ref = toSourceRef(r, imp.saved);
  const tf = selection.trafficFilter && sameSource(selection.trafficFilter.source, ref) ? selection.trafficFilter : null;
  const live = r.kind === "live" && running;
  const [sel, setSel] = useState<FlowSelection | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  useEffect(() => {
    if (!tf || !live) return;
    const h = window.setInterval(() => setTick((x) => x + 1), 2000);
    return () => window.clearInterval(h);
  }, [tf, live]);
  const key = JSON.stringify([tf, selection.timeWindow, tick]);
  // Arriving from "Open Traffic": bring the node's flows into view.
  const bannerRef = useRef<HTMLDivElement>(null);
  const nodeId = tf?.nodeId ?? null;
  useEffect(() => {
    if (nodeId) bannerRef.current?.scrollIntoView?.({ block: "start" });
  }, [nodeId]);
  useEffect(() => {
    if (!tf) return;
    let alive = true;
    flowsFor(tf.source, tf.filter, selection.timeWindow)
      .then((v) => {
        if (!alive) return;
        setSel(v);
        setError(null);
      })
      .catch((e) => alive && setError(String(e)));
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);
  if (!tf) return <>{children}</>;
  const role = tf.role ? t(roleKey(tf.role)) : null;
  return (
    <>
      <div className="notice node-filter" role="status" ref={bannerRef}>
        <p>
          {t("traffic.nodeFilter.title")}: <strong>{role}</strong> <span className="mono">{tf.title}</span>
          {sel && (
            <>
              {" "}
              · <span className="mono">{fmtNum(sel.total)}</span> {t("traffic.flows")} · <span className="mono">{fmtBytes(sel.bytes)}</span>
            </>
          )}
          {selection.timeWindow && <> · {t("traffic.nodeFilter.window")}</>}
        </p>
        <button className="chip" onClick={() => setSelection({ ...selection, trafficFilter: null })}>
          {t("traffic.nodeFilter.clear")}
        </button>
      </div>
      {error ? (
        <p className="meta">{error}</p>
      ) : !sel ? (
        <p className="meta">{t("topology.loading")}</p>
      ) : sel.flows.length ? (
        <FlowTable flows={sel.flows} now={now} startMs={startMs} perspective={perspective} />
      ) : (
        <p className="meta">{t(selection.timeWindow ? "inspector.traffic.noneInWindow" : "inspector.traffic.none")}</p>
      )}
      {sel && sel.total > sel.flows.length && (
        <p className="footnote">
          {t("traffic.showingTop")} {sel.flows.length} / {fmtNum(sel.total)}
        </p>
      )}
    </>
  );
}

function ImportedTraffic({ v }: { v: ImportView }) {
  const { t } = useI18n();
  const s = v.summary;
  const snap = v.snapshot;
  const span = s.first_ts_ms != null && s.last_ts_ms != null ? s.last_ts_ms - s.first_ts_ms : null;
  const share = s.vantage.unicast_frames ? Math.round((100 * s.vantage.involved_frames) / s.vantage.unicast_frames) : 0;
  const reason = s.error ? s.error.reason.kind : null;
  return (
    <>
      <div className="notice import-banner">
        <strong>{t("import.banner.title")}</strong>
        <p>{t("import.banner.body")}</p>
      </div>
      {s.error && (
        <div className="notice" role="alert">
          <strong>{t("import.partial.title")}</strong>
          <p>
            {t(`import.reason.${reason}` as MessageKey)} — {t("import.partial.at")} <span className="mono">{fmtNum(s.error.offset)}</span>.{" "}
            {t("import.partial.body")}
          </p>
        </div>
      )}
      {s.unsupported_link_frames > 0 && (
        <div className="notice">
          <span className="mono">{fmtNum(s.unsupported_link_frames)}</span> {t("import.unsupported")}{" "}
          <span className="mono">{s.linktypes.filter((l) => l !== 1).join(", ")}</span>
        </div>
      )}
      <dl className="file-facts">
        <dt>{t("import.fact.file")}</dt>
        <dd>
          <span className="mono">{v.file_name}</span> · {fmtBytes(v.size_bytes)} · {s.format.toUpperCase().replace("_NANOS", " (ns)")}
        </dd>
        <dt>SHA-256</dt>
        <dd className="mono" title={v.sha256}>
          {shortHash(v.sha256)}
        </dd>
        <dt>{t("import.fact.recorded")}</dt>
        <dd>
          {s.first_ts_ms != null ? <span className="mono">{fmtUtc(s.first_ts_ms)}</span> : "—"}
          {span != null && <> · {fmtDuration(span)}</>}
        </dd>
        <dt>{t("import.fact.frames")}</dt>
        <dd>
          <span className="mono">{fmtNum(s.frames)}</span> · {t("import.fact.unparsed")} <span className="mono">{fmtNum(snap.unparsed_frames)}</span>
          {s.untimed_frames > 0 && (
            <>
              {" "}
              · {t("import.fact.untimed")} <span className="mono">{fmtNum(s.untimed_frames)}</span>
            </>
          )}
        </dd>
        <dt>{t("import.fact.host")}</dt>
        <dd>
          <span className="status-mark inferred" />
          {t("status.inferred")} ·{" "}
          <span className="mono">{s.vantage.addresses.slice(0, 3).join(", ") || "—"}</span>
          {s.vantage.mac && <span className="mono meta"> · {s.vantage.mac}</span>}
          <div className="meta small">
            {t("import.fact.hostWhy")} <span className="mono">{share}%</span> {t("import.fact.hostWhy2")}
          </div>
        </dd>
      </dl>
      {s.first_ts_ms != null && s.last_ts_ms != null && (
        <SpanChart series={snap.series} minutes={snap.series_minutes} firstMs={s.first_ts_ms} lastMs={s.last_ts_ms} perspective="host" />
      )}
      <h2 className="section-title">{t("traffic.flowsTitle")}</h2>
      <FlowsOrNode now={Date.now()} startMs={s.first_ts_ms ?? 0} perspective="host">
        {snap.flows.length ? (
          <FlowTable flows={snap.flows} now={Date.now()} startMs={s.first_ts_ms ?? 0} perspective="host" />
        ) : (
          <p className="meta">{t("import.noFlows")}</p>
        )}
        {snap.total_flows > snap.flows.length && (
          <p className="footnote">
            {t("traffic.showingTop")} {snap.flows.length} / {fmtNum(snap.total_flows)}
          </p>
        )}
      </FlowsOrNode>
      <p className="footnote">{t("import.dirHint")}</p>
    </>
  );
}

function SavedBanner({ label, savedAtMs }: { label: string; savedAtMs: number }) {
  const { t } = useI18n();
  return (
    <div className="notice saved-banner">
      <strong>
        {t("session.savedBanner.title")}: {label}
      </strong>
      <p>
        {t("session.savedBanner.body")} <span className="mono">{fmtUtc(savedAtMs)}</span>.
      </p>
    </div>
  );
}

/** A saved snapshot of this Mac: the capture as it was when saved. */
function SavedLiveTraffic({ v }: { v: LiveView }) {
  const { t } = useI18n();
  const c = v.capture;
  if (!c) return <p className="meta">{t("session.savedNoCapture")}</p>;
  const snap = c.snapshot;
  return (
    <>
      <dl className="file-facts">
        <dt>{t("session.fact.interface")}</dt>
        <dd className="mono">{c.interface}</dd>
        <dt>{t("import.fact.recorded")}</dt>
        <dd>
          <span className="mono">{fmtUtc(c.started_at_ms)}</span> · {fmtDuration(c.elapsed_ms)}
        </dd>
        <dt>{t("traffic.drops")}</dt>
        <dd className="mono">{fmtNum(c.stats.dropped + c.stats.if_dropped)}</dd>
      </dl>
      <SpanChart series={snap.series} minutes={snap.series_minutes} firstMs={c.started_at_ms} lastMs={c.started_at_ms + c.elapsed_ms} perspective="mac" />
      <h2 className="section-title">{t("traffic.flowsTitle")}</h2>
      <FlowsOrNode now={Date.now()} startMs={c.started_at_ms} perspective="mac">
        <FlowTable flows={snap.flows} now={Date.now()} startMs={c.started_at_ms} perspective="mac" />
        {snap.total_flows > snap.flows.length && (
          <p className="footnote">
            {t("traffic.showingTop")} {snap.flows.length} / {fmtNum(snap.total_flows)}
          </p>
        )}
      </FlowsOrNode>
    </>
  );
}

export function TrafficScreen() {
  const { t } = useI18n();
  const { view } = useCapture();
  const imp = useImport();
  const r = resolveSource(imp.source, null, imp.view, imp.saved);
  const shown = r.importView?.snapshot ?? r.savedLive?.capture?.snapshot ?? view?.snapshot;

  return (
    <>
      <header className="screen-header">
        <h1>{t("nav.traffic")}</h1>
        <p>{t(r.kind === "live" ? "traffic.desc" : r.kind === "saved_live" ? "session.savedDesc" : "import.desc")}</p>
        {shown && (
          <p className="summary-line">
            <span className="mono">{fmtNum(shown.total_flows)}</span> {t("traffic.flows")} ·{" "}
            <span className="mono">{fmtNum(shown.total_packets)}</span> {t("traffic.packets")} ·{" "}
            <span className="mono">{fmtBytes(shown.total_bytes)}</span> ·{" "}
            {t(r.kind === "live" || r.kind === "saved_live" ? "traffic.scopeNote" : "import.scopeNote")}
          </p>
        )}
      </header>

      <SourceBar />
      {imp.saved && r.kind.startsWith("saved") && <SavedBanner label={imp.saved.snapshot.label} savedAtMs={imp.saved.snapshot.created_at_ms} />}
      {r.importView ? <ImportedTraffic v={r.importView} /> : r.savedLive ? <SavedLiveTraffic v={r.savedLive} /> : <LiveTraffic />}
    </>
  );
}

function LiveTraffic() {
  const { t } = useI18n();
  const { view } = useCapture();
  const snap = view?.snapshot;
  const now = useMemo(() => Date.now(), [view]);
  const incomplete = snap && (snap.evicted_flows > 0 || (view?.stats.dropped ?? 0) + (view?.stats.if_dropped ?? 0) > 0);
  return (
    <>
      {view?.demo && <div className="notice">{t("perm.demo")}</div>}
      <CaptureControl />

      {incomplete && (
        <div className="notice">
          {t("traffic.incomplete")}: <span className="mono">{fmtNum(snap!.evicted_flows)}</span> {t("traffic.evicted")},{" "}
          <span className="mono">{fmtNum((view?.stats.dropped ?? 0) + (view?.stats.if_dropped ?? 0))}</span>{" "}
          {t("traffic.dropped")}
        </div>
      )}
      {view?.stats.error && (
        <div className="notice">
          {t("traffic.error.title")}: <span className="mono">{view.stats.error}</span>
        </div>
      )}

      {snap ? (
        <>
          <LiveChart series={snap.series} startedAtMs={view!.started_at_ms} />
          <h2 className="section-title">{t("traffic.flowsTitle")}</h2>
          <FlowsOrNode now={now} perspective="mac">
            {snap.flows.length ? (
              <FlowTable flows={snap.flows} now={now} perspective="mac" />
            ) : (
              <p className="meta">{t("traffic.noFlows")}</p>
            )}
            {snap.total_flows > snap.flows.length && (
              <p className="footnote">
                {t("traffic.showingTop")} {snap.flows.length} / {fmtNum(snap.total_flows)}
              </p>
            )}
          </FlowsOrNode>
          <p className="footnote">{t("traffic.dirHint")}</p>
        </>
      ) : (
        <section className="surface">
          <div className="empty">
            <h2>{t("traffic.empty.title")}</h2>
            <p>{t("traffic.empty.body")}</p>
          </div>
        </section>
      )}
    </>
  );
}
