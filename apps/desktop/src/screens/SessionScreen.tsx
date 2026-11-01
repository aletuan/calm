import { useEffect, useState } from "react";
import { useImport } from "../app/imported";
import { useStoreOpened } from "../app/session";
import { useI18n } from "../i18n";
import type { MessageKey } from "../i18n/en";
import { fmtBytes, fmtLocal } from "../lib/format";
import { storeErrorMessage } from "../lib/errorMessage";
import { ErrorText, FormErrors } from "./ErrorText";
import { SaveButton, SaveStatusLine } from "./SaveStatus";
import { useSelection } from "../app/selection";
import { findingsList, scopeList, type ScopeView } from "../lib/assess";
import { journey } from "../lib/journey";
import { defaultTab, filterSessions, type SessionTab } from "../lib/sessionList";
import type { SessionSummary } from "../lib/ipc";
import { emptyForm, parseSessionForm, RETENTION_CHOICES, type FormError, type SessionForm } from "../lib/sessionForm";

/**
 * Sessions: the container for one assessment. The active session comes
 * first, with a four-step checklist (session → scope → run → findings);
 * creating a session is a button; how data is stored is one click away.
 * The scope grant itself lives in Assessment, where probes are sent.
 */

function NewSession({ onCreate, onCancel, busy }: { onCreate: (f: SessionForm) => Promise<FormError[] | null>; onCancel?: () => void; busy: boolean }) {
  const { t } = useI18n();
  const [f, setF] = useState<SessionForm>(emptyForm());
  const [errors, setErrors] = useState<FormError[]>([]);
  const set = (k: keyof SessionForm) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });
  return (
    <form
      className="session-form"
      onSubmit={async (e) => {
        e.preventDefault();
        const errs = await onCreate(f);
        setErrors(errs ?? []);
        if (!errs) setF(emptyForm());
      }}
    >
      <label>
        <span>{t("session.field.name")} *</span>
        <input value={f.name} onChange={set("name")} maxLength={120} required aria-invalid={errors.includes("name_required")} />
      </label>
      <label>
        <span>{t("session.field.site")}</span>
        <input value={f.site} onChange={set("site")} maxLength={200} />
      </label>
      <label>
        <span>{t("session.field.operator")}</span>
        <input value={f.operator} onChange={set("operator")} maxLength={200} />
      </label>
      <label className="wide">
        <span>{t("session.field.notes")}</span>
        <textarea value={f.notes} onChange={set("notes")} maxLength={2000} rows={2} />
      </label>
      <label>
        <span>{t("session.field.retention")}</span>
        <select value={f.retention} onChange={set("retention")}>
          {RETENTION_CHOICES.map((r) => (
            <option key={r} value={r}>
              {r === "keep" ? t("session.retention.keep") : `${r} ${t("session.retention.days")}`}
            </option>
          ))}
        </select>
      </label>
      <div className="form-actions">
        <button className="button-primary" type="submit" disabled={busy}>
          {t("session.create")}
        </button>
        {onCancel && (
          <button type="button" className="chip" onClick={onCancel}>
            {t("session.cancel")}
          </button>
        )}
        <FormErrors messages={errors.map((e) => t(`session.err.${e}` as MessageKey))} />
      </div>
    </form>
  );
}

function retentionText(days: number | null, t: (k: MessageKey) => string) {
  return days == null ? t("session.retention.keep") : `${days} ${t("session.retention.days")}`;
}

/** The active session: what it holds, its scope, and what to do next. */
function ActiveSession({ x, onDelete, busy }: { x: SessionSummary; onDelete: () => void; busy: boolean }) {
  const { t } = useI18n();
  const { setScreen } = useSelection();
  const [scope, setScope] = useState<ScopeView | null | undefined>(undefined);
  const [runs, setRuns] = useState(0);
  const [confirm, setConfirm] = useState(false);
  useEffect(() => {
    let live = true;
    void Promise.all([scopeList(), findingsList()]).then(([scopes, rs]) => {
      if (!live) return;
      setScope(scopes.find((v) => !v.revoked && !v.expired) ?? null);
      setRuns(rs.length);
    });
    return () => {
      live = false;
    };
  }, [x.id, x.updated_at_ms]);
  const steps = journey({ hasSession: true, hasScope: !!scope, runs });
  const sc = scope?.scope;
  return (
    <section className="active-session" aria-label={t("session.activeTitle")}>
      <div className="active-session-head">
        <div>
          <span className="eyebrow-label">{t("session.activeTitle")}</span>
          <h2>{x.meta.name}</h2>
          <p className="meta">
            {[x.meta.site, x.meta.operator].filter(Boolean).join(" · ") || "—"} · {t("session.col.created")}{" "}
            <span className="mono">{fmtLocal(x.created_at_ms)}</span>
          </p>
        </div>
        <span className="push" />
        {confirm ? (
          <>
            <button className="chip danger" onClick={onDelete} disabled={busy}>
              {t("session.confirmDelete")}
            </button>
            <button className="chip" onClick={() => setConfirm(false)}>
              {t("session.cancel")}
            </button>
          </>
        ) : (
          <button className="chip" onClick={() => setConfirm(true)} disabled={busy}>
            {t("session.delete")}
          </button>
        )}
      </div>
      <dl className="file-facts">
        <dt>{t("session.col.snapshots")}</dt>
        <dd>
          <span className="mono">{x.snapshot_count}</span> · <span className="mono">{fmtBytes(x.stored_bytes)}</span> · {retentionText(x.retention_days, t)}
        </dd>
        <dt>{t("scope.title")}</dt>
        <dd>
          {scope === undefined ? (
            "…"
          ) : sc ? (
            <>
              <span className="mono">{sc.authorization_reference}</span> · {t("session.scope.until")} <span className="mono">{fmtLocal(sc.expires_at_ms)}</span> ·{" "}
              <span className="mono">{sc.targets.length}</span> {t(sc.targets.length === 1 ? "session.scope.target" : "session.scope.targets")}
            </>
          ) : (
            <span className="meta">{t("session.scope.none")}</span>
          )}
        </dd>
        <dt>{t("session.runs")}</dt>
        <dd className="mono">{runs}</dd>
      </dl>
      <ol className="journey" aria-label={t("session.journey")}>
        {steps.map((s, i) => (
          <li key={s.id} data-state={s.state}>
            <button type="button" onClick={() => setScreen(s.screen)} aria-current={s.state === "current" ? "step" : undefined}>
              <span className="journey-mark" aria-hidden>
                {s.state === "done" ? "✓" : i + 1}
              </span>
              <span className="journey-text">
                <strong>{t(`journey.${s.id}` as MessageKey)}</strong>
                <span className="meta small">{t(`journey.${s.id}.hint` as MessageKey)}</span>
              </span>
              <span className="journey-state small">{t(`journey.state.${s.state}` as MessageKey)}</span>
            </button>
          </li>
        ))}
      </ol>
    </section>
  );
}

export function SessionScreen() {
  const { t } = useI18n();
  const s = useStoreOpened();
  const imp = useImport();
  const [confirm, setConfirm] = useState<string | null>(null);
  const [showNew, setShowNew] = useState(false);
  // null: follow the default (Current when a session is active).
  const [tabChoice, setTabChoice] = useState<SessionTab | null>(null);
  const [query, setQuery] = useState("");
  const ready = s.status?.state === "ready";
  const tab: SessionTab = tabChoice === "current" && !s.active ? "all" : (tabChoice ?? defaultTab(!!s.active));
  const shown = filterSessions(s.sessions, query);
  const formOpen = ready && (showNew || s.sessions.length === 0);

  return (
    <>
      <header className="screen-header screen-header-row">
        <div>
          <h1>{t("nav.setup")}</h1>
          <p>{t("session.desc")}</p>
        </div>
        {ready && s.sessions.length > 0 && !showNew && (
          <button className="chip" onClick={() => setShowNew(true)}>
            + {t("session.new")}
          </button>
        )}
      </header>

      {s.status?.state === "error" && s.status.error && (
        <div className="notice" role="alert">
          <strong>{t("store.locked.title")}</strong>
          <ErrorText message={storeErrorMessage(s.status.error)} />
          {s.status.error.kind === "key_mismatch" && (
            <>
              <p className="meta">{t("store.setAside.body")}</p>
              <button className="chip" onClick={() => void s.setAside()} disabled={s.busy}>
                {t("store.setAside")}
              </button>
            </>
          )}
        </div>
      )}
      {s.error && (
        <div className="notice" role="alert">
          <ErrorText message={storeErrorMessage(s.error)} />
        </div>
      )}
      {s.status && s.status.purged_on_open > 0 && (
        <div className="notice">
          <span className="mono">{s.status.purged_on_open}</span> {t("store.purged")}
        </div>
      )}

      {formOpen && (
        <section className="new-session">
          <h2 className="section-title">{t("session.new")}</h2>
          <NewSession
            busy={s.busy}
            onCancel={s.sessions.length > 0 ? () => setShowNew(false) : undefined}
            onCreate={async (f) => {
              const r = parseSessionForm(f);
              if (!r.ok) return r.errors;
              await s.create(r.input);
              setShowNew(false);
              setTabChoice("current");
              return null;
            }}
          />
        </section>
      )}

      {ready && s.sessions.length > 0 && (
        <div className="tabs page-tabs" role="tablist" aria-label={t("nav.setup")}>
          <button role="tab" id="tab-current" aria-controls="panel-current" aria-selected={tab === "current"} className="tab" onClick={() => setTabChoice("current")} disabled={!s.active}>
            {t("session.tab.current")}
          </button>
          <button role="tab" id="tab-all" aria-controls="panel-all" aria-selected={tab === "all"} className="tab" onClick={() => setTabChoice("all")}>
            {t("session.tab.all")} <span className="tab-count">{s.sessions.length}</span>
          </button>
        </div>
      )}

      {ready && tab === "current" && s.active && (
        <div role="tabpanel" id="panel-current" aria-labelledby="tab-current">
          <ActiveSession key={s.active.id} x={s.active} busy={s.busy} onDelete={() => void s.remove(s.active!.id)} />
          <h2 className="section-title">{t("session.snapshots")}</h2>
          <div className="toolbar">
            <SaveButton kind="live" label={t("session.saveLive")} />
            <SaveButton kind="import" label={t("session.saveImport")} />
          </div>
          <SaveStatusLine />
          {s.snapshots.length === 0 ? (
            <p className="meta">{t("session.noSnapshots")}</p>
          ) : (
            <div className="table-scroll">
              <table className="flow-table session-table">
                <thead>
                  <tr>
                    <th>{t("session.col.label")}</th>
                    <th>{t("session.col.kind")}</th>
                    <th>{t("session.col.saved")}</th>
                    <th className="num">{t("session.col.size")}</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {s.snapshots.map((x) => (
                    <tr key={x.id} aria-current={imp.saved?.snapshot.id === x.id ? "true" : undefined}>
                      <td>
                        {x.label}
                        {s.lastSaved?.snapshot.id === x.id && <span className="tag new">{t("save.new")}</span>}
                      </td>
                      <td className="meta">{t(x.kind === "live" ? "session.kind.live" : "session.kind.import")}</td>
                      <td className="mono meta">{fmtLocal(x.created_at_ms)}</td>
                      <td className="mono num">{fmtBytes(x.size_bytes)}</td>
                      <td className="row-actions">
                        <button className="chip" onClick={() => void s.view(x.id)} disabled={s.busy}>
                          {t("session.view")}
                        </button>
                        <button className="chip" onClick={() => void s.removeSnapshot(x.id)} disabled={s.busy}>
                          {t("session.delete")}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <p className="footnote">{t("session.viewHint")}</p>
        </div>
      )}

      {ready && tab === "all" && s.sessions.length > 0 && (
        <div role="tabpanel" id="panel-all" aria-labelledby="tab-all">
          <div className="toolbar">
            <input
              type="search"
              className="session-search"
              placeholder={t("session.search")}
              aria-label={t("session.search")}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            {query && (
              <span className="meta">
                <span className="mono">{shown.length}</span> / <span className="mono">{s.sessions.length}</span>
              </span>
            )}
          </div>
          {shown.length === 0 ? (
            <p className="meta">{t("session.noMatch")}</p>
          ) : (
            <div className="table-scroll">
              <table className="flow-table session-table">
                <thead>
                  <tr>
                    <th>{t("session.field.name")}</th>
                    <th>{t("session.field.site")}</th>
                    <th>{t("session.col.created")}</th>
                    <th className="num">{t("session.col.snapshots")}</th>
                    <th className="num">{t("session.col.size")}</th>
                    <th>{t("session.field.retention")}</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {shown.map((x) => (
                    <tr key={x.id} aria-current={s.active?.id === x.id ? "true" : undefined}>
                      <td>
                        {x.meta.name}
                        {s.active?.id === x.id && <span className="tag">{t("session.active")}</span>}
                      </td>
                      <td className="meta">{x.meta.site || "—"}</td>
                      <td className="mono meta">{fmtLocal(x.created_at_ms)}</td>
                      <td className="mono num">{x.snapshot_count}</td>
                      <td className="mono num">{fmtBytes(x.stored_bytes)}</td>
                      <td className="meta">{retentionText(x.retention_days, t)}</td>
                      <td className="row-actions">
                        {s.active?.id === x.id ? (
                          <button className="chip" onClick={() => setTabChoice("current")}>
                            {t("session.open")}
                          </button>
                        ) : (
                          <button className="chip" onClick={() => void s.activate(x.id).then(() => setTabChoice("current"))} disabled={s.busy}>
                            {t("session.use")}
                          </button>
                        )}
                        {confirm === x.id ? (
                          <>
                            <button className="chip danger" onClick={() => void s.remove(x.id).then(() => setConfirm(null))} disabled={s.busy}>
                              {t("session.confirmDelete")}
                            </button>
                            <button className="chip" onClick={() => setConfirm(null)}>
                              {t("session.cancel")}
                            </button>
                          </>
                        ) : (
                          <button className="chip" onClick={() => setConfirm(x.id)} disabled={s.busy}>
                            {t("session.delete")}
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      <details className="storage-facts">
        <summary>{t("session.storage")}</summary>
        <dl className="file-facts">
          <dt>{t("store.fact.where")}</dt>
          <dd className="mono small">{s.status?.path ?? "…"}</dd>
          <dt>{t("store.fact.encryption")}</dt>
          <dd>{t("store.fact.encryptionValue")}</dd>
          <dt>{t("store.fact.what")}</dt>
          <dd>{t("store.fact.whatValue")}</dd>
          <dt>{t("store.fact.delete")}</dt>
          <dd>{t("store.fact.deleteValue")}</dd>
        </dl>
      </details>
    </>
  );
}
