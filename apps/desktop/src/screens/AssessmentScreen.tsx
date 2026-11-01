import { useCallback, useEffect, useState } from "react";
import { useCapture } from "../app/capture";
import { useSelection } from "../app/selection";
import { useSession } from "../app/session";
import { useI18n } from "../i18n";
import type { MessageKey } from "../i18n/en";
import { checksPreflight, checksRun, checksStatus, emergencyStop, type Preflight, type Progress, type RunError } from "../lib/assess";
import { finishedSummary, fromText, outcomeText, positionKey } from "../lib/findingsView";
import { findingsList } from "../lib/assess";
import { NetworkLine, ScopePanel } from "./ScopePanel";

/**
 * Assessment (M2), in three steps: 1 the scope grant (what the owner
 * allowed), 2 preflight (what will be probed, from where), 3 run. Emergency
 * Stop stays on top. Nothing runs without the Run button.
 */
export function AssessmentScreen() {
  const { t } = useI18n();
  const session = useSession();
  const { setScreen } = useSelection();
  const { running: capturing } = useCapture();
  const [pre, setPre] = useState<Preflight | null>(null);
  const [progress, setProgress] = useState<Progress | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [summary, setSummary] = useState<ReturnType<typeof finishedSummary>>(null);

  const refresh = useCallback(async () => {
    setPre(await checksPreflight());
    const p = await checksStatus();
    setProgress(p);
    // Coming back to this screen after a run: show its counts again.
    if (p && !p.running && p.snapshot_id) setSummary(finishedSummary(p, await findingsList()));
  }, []);
  useEffect(() => {
    void refresh();
  }, [refresh, session.active?.id]);

  const running = progress?.running ?? false;
  useEffect(() => {
    if (!running) return;
    const h = window.setInterval(async () => {
      const p = await checksStatus();
      setProgress(p);
      if (p && !p.running) setSummary(finishedSummary(p, await findingsList()));
    }, 400);
    return () => window.clearInterval(h);
  }, [running]);

  const start = async () => {
    setError(null);
    setSummary(null);
    try {
      setProgress(await checksRun(confirmed));
    } catch (e) {
      setError(t(`assess.err.${(e as RunError)?.kind ?? "store"}` as MessageKey));
      void refresh();
    }
  };

  const listeners = pre?.plan.some((p) => p.check !== "S01") ?? false;
  const outside = pre?.plan.some((p) => p.outside_subnet) ?? false;
  const s = pre?.scope?.scope;

  return (
    <>
      <header className="screen-header">
        <h1>{t("nav.assessment")}</h1>
        <p>{t("assessment.desc")}</p>
      </header>

      <div className="stop-bar" role="group" aria-label={t("assess.stop")}>
        <span className="meta">{running ? t("assess.runningNote") : capturing ? t("assess.captureNote") : t("assess.idleNote")}</span>
        <span className="push" />
        <button className="chip danger stop-button" onClick={() => void emergencyStop().then(refresh)} disabled={!running && !capturing}>
          ■ {t("assess.stop")}
        </button>
      </div>

      {!session.active ? (
        <div className="notice">
          <strong>{t("assessment.empty.title")}</strong>
          <p>{t("assess.needSession")}</p>
          <button className="chip" onClick={() => setScreen("setup")}>
            {t("nav.setup")}
          </button>
        </div>
      ) : (
        <>
          <section className="assess-step" aria-labelledby="step-scope">
            <h2 className="section-title" id="step-scope">
              <span className="step-n">1</span> {t("scope.title")}
            </h2>
            <ScopePanel key={session.active.id} operator={session.active.meta.operator} onChange={() => void refresh()} />
          </section>

          <section className="assess-step" aria-labelledby="step-preflight" data-locked={!s || undefined}>
            <h2 className="section-title" id="step-preflight">
              <span className="step-n">2</span> {t("assess.preflight")}
            </h2>
            {!pre ? (
              <p className="meta">{t("topology.loading")}</p>
            ) : !s ? (
              <p className="meta">{t("assess.step.locked")}</p>
            ) : (
              <>
                <dl className="file-facts">
                  <dt>{t("assess.boundTo")}</dt>
                  <dd>
                    <NetworkLine n={s.network} />
                  </dd>
                  <dt>{t("assess.now")}</dt>
                  <dd>
                    <span className={`status-mark ${pre.same_network ? "observed" : "unknown"}`} />
                    <NetworkLine n={pre.network} /> <strong>{pre.same_network ? t("assess.sameNetwork") : t("assess.otherNetwork")}</strong>
                  </dd>
                  <dt>{t("assess.from")}</dt>
                  <dd>{t(positionKey(s.vantage ?? "unknown"))}</dd>
                  <dt>{t("scope.budget")}</dt>
                  <dd>
                    <span className="mono">{s.budget.max_probes_per_second}</span> {t("scope.perSecond")} · {t("scope.timeout")}{" "}
                    <span className="mono">{s.budget.timeout_ms / 1000}s</span> · {t("assess.duration")} <span className="mono">{pre.min_seconds}</span>–
                    <span className="mono">{pre.max_seconds}</span>s
                  </dd>
                </dl>

                <h3 className="subsection">
                  {t("assess.plan")} <span className="meta">({pre.plan.length})</span>
                </h3>
                {pre.plan.length === 0 ? (
                  <p className="meta">{t("assess.noPlan")}</p>
                ) : (
                  <div className="table-scroll">
                    <table className="flow-table session-table">
                      <thead>
                        <tr>
                          <th>{t("finding.col.check")}</th>
                          <th>{t("scope.col.target")}</th>
                          <th className="num">{t("assess.port")}</th>
                          <th>{t("assess.whatItTests")}</th>
                        </tr>
                      </thead>
                      <tbody>
                        {pre.plan.map((p) => (
                          <tr key={`${p.check}|${p.target}|${p.port}`}>
                            <td className="mono">{p.check}</td>
                            <td>
                              <span className="mono">{p.target}</span> {p.label && <span className="meta">{p.label}</span>}
                              {p.outside_subnet && <span className="tag-outside">{t("assess.outside")}</span>}
                            </td>
                            <td className="mono num">{p.port}</td>
                            <td className="meta">{fromText(`check.${p.check}.short` as MessageKey, s.vantage, t)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
                {outside && <p className="notice small">{t("assess.outsideNote")}</p>}
              </>
            )}
          </section>

          <section className="assess-step" aria-labelledby="step-run" data-locked={!pre?.ready || undefined}>
            <h2 className="section-title" id="step-run">
              <span className="step-n">3</span> {t("assess.step.run")}
            </h2>
            {!pre || !s ? (
              <p className="meta">{t("assess.step.locked")}</p>
            ) : (
              <>
                {listeners && (
                  <label className="confirm-line">
                    <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} disabled={running} /> {t("assess.receiverConfirm")}
                  </label>
                )}
                <p className="footnote">{t("assess.whatIsSent")}</p>
                <div className="form-actions">
                  <button className="button-primary" onClick={() => void start()} disabled={!pre.ready || running}>
                    {running ? t("assess.running") : t("assess.run")}
                  </button>
                  {!pre.ready && pre.plan.length > 0 && <span className="form-error">{t(pre.same_network === false ? "assess.err.network_changed" : "assess.notReady")}</span>}
                  {error && (
                    <span className="form-error" role="alert">
                      {error}
                    </span>
                  )}
                </div>
              </>
            )}
          </section>
        </>
      )}

      {progress && (progress.running || progress.run_id) && (
        <section className="run-progress" aria-live="polite">
          <div className="progress-bar" role="progressbar" aria-valuemin={0} aria-valuemax={progress.total} aria-valuenow={progress.done}>
            <span style={{ width: `${progress.total ? (100 * progress.done) / progress.total : 0}%` }} />
          </div>
          <p className="meta">
            <span className="mono">
              {progress.done}/{progress.total}
            </span>{" "}
            {progress.running ? t("assess.probing") : progress.stopped ? t("assess.stopped") : t("assess.finished")}
            {progress.last && (
              <>
                {" "}
                · <span className="mono">{progress.last.target}</span> {outcomeText(progress.last.outcome, t)}
              </>
            )}
          </p>
          {progress.error && <p className="form-error">{progress.error}</p>}
          {!progress.running && summary && (
            <p>
              <span className="mono">{summary.fail}</span> {t("finding.status.fail")} · <span className="mono">{summary.warning}</span> {t("finding.status.warning")} ·{" "}
              <span className="mono">{summary.inconclusive}</span> {t("finding.status.inconclusive")} · <span className="mono">{summary.pass}</span>{" "}
              {t("finding.status.pass")} ·{" "}
              <button className="chip" onClick={() => setScreen("findings")}>
                {t("assess.openFindings")}
              </button>
            </p>
          )}
        </section>
      )}
    </>
  );
}
