import { useEffect, useMemo, useState } from "react";
import { useSelection } from "../app/selection";
import { useSession } from "../app/session";
import { useI18n } from "../i18n";
import type { MessageKey } from "../i18n/en";
import { findingsList, type CheckResult, type StoredRun } from "../lib/assess";
import { claimKey, confidenceText, countByStatus, fromText, outcomeText, positionKey, reasonKey, resultId, severityKey, sortResults, statusKey } from "../lib/findingsView";
import { fmtLocal } from "../lib/format";

/**
 * Findings (M2): results of the authorized checks. Status, severity and
 * confidence are separate; every result shows what was verified, what was
 * not, and the probes behind it.
 */

function StatusBadge({ r }: { r: CheckResult }) {
  const { t } = useI18n();
  return (
    <span className={`finding-status s-${r.status}`}>
      <span className="finding-mark" aria-hidden />
      {t(statusKey(r.status))}
    </span>
  );
}

function Detail({ r, run, onClose }: { r: CheckResult; run: StoredRun; onClose: () => void }) {
  const { t } = useI18n();
  const target = r.target ? `${r.target}${r.label ? ` (${r.label})` : ""}` : t("finding.noTarget");
  const title = fromText(`check.${r.check}.title` as MessageKey, run.run.vantage, t);
  const claim = (c: CheckResult["verified"][number]) => fromText(claimKey(c), run.run.vantage, t);
  return (
    <aside className="inspector finding-detail" aria-label={title}>
      <header className="inspector-head">
        <div>
          <div className="inspector-title">
            <span className="mono">{r.check}</span> {title}
          </div>
          <div className="meta mono">{target}</div>
        </div>
        <button className="chip" onClick={onClose}>
          {t("inspector.close")}
        </button>
      </header>
      <div className="inspector-body">
        <dl className="file-facts">
          <dt>{t("finding.col.status")}</dt>
          <dd>
            <StatusBadge r={r} />
          </dd>
          <dt>{t("finding.col.severity")}</dt>
          <dd>{t(severityKey(r.severity))}</dd>
          <dt>{t("finding.col.confidence")}</dt>
          <dd>{confidenceText(r, t)}</dd>
          <dt>{t("assess.from")}</dt>
          <dd>{t(positionKey(run.run.vantage ?? "unknown"))}</dd>
        </dl>
        <p>{t(reasonKey(r.reason))}</p>
        {r.verified.length > 0 && (
          <>
            <h3 className="subsection">{t("finding.verified")}</h3>
            <ul className="claims verified">
              {r.verified.map((c) => (
                <li key={c}>{claim(c)}</li>
              ))}
            </ul>
          </>
        )}
        {r.unverified.length > 0 && (
          <>
            <h3 className="subsection">{t("finding.unverified")}</h3>
            <ul className="claims unverified">
              {r.unverified.map((c) => (
                <li key={c}>{claim(c)}</li>
              ))}
            </ul>
          </>
        )}
        {r.status === "fail" && (
          <>
            <h3 className="subsection">{t("finding.action")}</h3>
            <p>{t(`check.${r.check}.action` as MessageKey)}</p>
          </>
        )}
        <h3 className="subsection">{t("finding.evidence")}</h3>
        {r.ports.length === 0 ? (
          <p className="meta">{t("finding.noProbes")}</p>
        ) : (
          <ul className="ids">
            {r.ports.map((p) => (
              <li key={p.port}>
                <span className="mono">
                  {r.target}:{p.port}
                </span>{" "}
                — {outcomeText(p.outcome, t)}
              </li>
            ))}
          </ul>
        )}
        <p className="meta small">
          {t("finding.method")} · {t("finding.run")} <span className="mono">{fmtLocal(run.run.started_at_ms)}</span> · scope{" "}
          <span className="mono">{run.run.scope_id.slice(0, 8)}</span>
          {run.run.receiver_confirmed && <> · {t("finding.receiverConfirmed")}</>}
        </p>
        <p className="meta small">{t(`check.${r.check}.limits` as MessageKey)}</p>
      </div>
    </aside>
  );
}

export function FindingsScreen() {
  const { t } = useI18n();
  const session = useSession();
  const { setScreen } = useSelection();
  const [runs, setRuns] = useState<StoredRun[] | null>(null);
  const [runId, setRunId] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  useEffect(() => {
    void findingsList().then((r) => {
      setRuns(r);
      setRunId(r[0]?.snapshot_id ?? null);
    });
  }, [session.active?.id]);
  const run = runs?.find((r) => r.snapshot_id === runId) ?? null;
  const results = useMemo(() => (run ? sortResults(run.run.results) : []), [run]);
  const counts = useMemo(() => countByStatus(results), [results]);
  const sel = results.find((r) => resultId(r) === selected) ?? null;

  return (
    <div className="findings-layout" data-inspector={sel ? "open" : "closed"}>
      <div className="findings-main">
        <header className="screen-header">
          <h1>{t("nav.findings")}</h1>
          <p>{t("findings.desc")}</p>
          {run && (
            <p className="summary-line">
              <span className="mono">{counts.fail}</span> {t("finding.status.fail")} · <span className="mono">{counts.warning}</span> {t("finding.status.warning")} ·{" "}
              <span className="mono">{counts.inconclusive}</span> {t("finding.status.inconclusive")} · <span className="mono">{counts.not_tested}</span>{" "}
              {t("finding.status.not_tested")} · <span className="mono">{counts.pass}</span> {t("finding.status.pass")} · {t("assess.from")}{" "}
              <strong>{t(`position.from.${run.run.vantage ?? "unknown"}` as MessageKey)}</strong>
            </p>
          )}
        </header>
        {!runs ? (
          <p className="meta">{t("topology.loading")}</p>
        ) : !run ? (
          <section className="surface">
            <div className="empty">
              <h2>{t("findings.empty.title")}</h2>
              <p>{t("findings.empty.body")}</p>
              <button className="chip" onClick={() => setScreen("assessment")}>
                {t("nav.assessment")}
              </button>
            </div>
          </section>
        ) : (
          <>
            <div className="toolbar">
              <label className="meta">
                {t("finding.runPick")}
                <select value={runId ?? ""} onChange={(e) => (setRunId(e.target.value), setSelected(null))}>
                  {runs.map((r) => (
                    <option key={r.snapshot_id} value={r.snapshot_id}>
                      {fmtLocal(r.run.started_at_ms)}
                      {r.run.stopped ? ` — ${t("assess.stopped")}` : ""}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            {run.run.stopped && <div className="notice">{t("finding.stoppedNote")}</div>}
            <div className="table-scroll">
              <table className="flow-table findings-table">
                <thead>
                  <tr>
                    <th>{t("finding.col.status")}</th>
                    <th>{t("finding.col.check")}</th>
                    <th>{t("scope.col.target")}</th>
                    <th>{t("finding.col.result")}</th>
                    <th>{t("finding.col.severity")}</th>
                    <th>{t("finding.col.confidence")}</th>
                  </tr>
                </thead>
                <tbody>
                  {results.map((r) => (
                    <tr
                      key={resultId(r)}
                      aria-selected={resultId(r) === selected}
                      tabIndex={0}
                      onClick={() => setSelected(resultId(r))}
                      onKeyDown={(e) => e.key === "Enter" && setSelected(resultId(r))}
                    >
                      <td>
                        <StatusBadge r={r} />
                      </td>
                      <td>
                        <span className="mono">{r.check}</span> <span className="meta">{fromText(`check.${r.check}.title` as MessageKey, run.run.vantage, t)}</span>
                      </td>
                      <td>
                        {r.target ? <span className="mono">{r.target}</span> : <span className="meta">—</span>} {r.label && <span className="meta">{r.label}</span>}
                      </td>
                      <td className="wrap">{t(reasonKey(r.reason))}</td>
                      <td>{t(severityKey(r.severity))}</td>
                      <td>{confidenceText(r, t)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="footnote">{t("finding.footnote")}</p>
          </>
        )}
      </div>
      {sel && run && <Detail r={sel} run={run} onClose={() => setSelected(null)} />}
    </div>
  );
}
