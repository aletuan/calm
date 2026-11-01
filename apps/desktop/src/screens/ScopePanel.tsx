import { useCallback, useEffect, useState } from "react";
import { useI18n } from "../i18n";
import type { MessageKey } from "../i18n/en";
import { POSITIONS, scopeApprove, scopeList, scopeNetwork, scopeRevoke, TARGET_ROLES, type DraftError, type NetworkBinding, type ScopeError, type ScopeView } from "../lib/assess";
import { fmtLocal } from "../lib/format";
import { FormErrors } from "./ErrorText";
import { CAPABILITIES, capabilityLevel, capsText, NSE_ALLOWLIST, toggleCapability } from "../lib/capabilities";
import { outsideNetwork, placeholders, rangeSuggestion, routerSuggestion, withRange, withRouter } from "../lib/scopeSuggest";
import { draftErrorKey, draftErrorRangeRow, draftErrorRow, emptyRange, emptyScopeForm, emptyTarget, exclusionList, toDraft, VALIDITY_CHOICES, type FormProblem, type RangeRow, type ScopeForm } from "../lib/scopeForm";

/**
 * Scope grant, step 1 of Assessment: what may be probed, from which network,
 * until when, and which kinds of traffic (ADR-011). Approved once; a change
 * means revoke and approve again.
 */

export function NetworkLine({ n }: { n: NetworkBinding | null }) {
  const { t } = useI18n();
  if (!n) return <span className="meta">{t("scope.network.unknown")}</span>;
  return (
    <span>
      {t("scope.network.gateway")} <span className="mono">{n.gateway}</span>
      {n.subnet && (
        <>
          {" "}
          · {t("scope.network.subnet")} <span className="mono">{n.subnet}</span>
        </>
      )}
      {n.ssid && (
        <>
          {" "}
          · SSID <span className="mono">{n.ssid}</span>
        </>
      )}
    </span>
  );
}

function ScopeCard({ v, onRevoke, busy }: { v: ScopeView; onRevoke: () => void; busy: boolean }) {
  const { t } = useI18n();
  const [confirm, setConfirm] = useState(false);
  const s = v.scope;
  const state = v.revoked ? "revoked" : v.expired ? "expired" : "active";
  return (
    <div className="scope-card" data-state={state}>
      <div className="scope-card-head">
        <strong>{t(`scope.state.${state}` as MessageKey)}</strong>
        <span className="meta">
          {s.authorization_reference} · {t("scope.grantedBy")} {s.granted_by} · {t("scope.operator")} {s.operator}
        </span>
        <span className="push" />
        {state === "active" &&
          (confirm ? (
            <>
              <button className="chip danger" onClick={onRevoke} disabled={busy}>
                {t("scope.revokeConfirm")}
              </button>
              <button className="chip" onClick={() => setConfirm(false)}>
                {t("session.cancel")}
              </button>
            </>
          ) : (
            <button className="chip" onClick={() => setConfirm(true)} disabled={busy}>
              {t("scope.revoke")}
            </button>
          ))}
      </div>
      <dl className="file-facts">
        <dt>{t("scope.valid")}</dt>
        <dd className="mono">
          {fmtLocal(s.approved_at_ms)} → {fmtLocal(s.expires_at_ms)}
        </dd>
        <dt>{t("scope.network")}</dt>
        <dd>
          <NetworkLine n={s.network} />
        </dd>
        <dt>{t("position.label")}</dt>
        <dd>{t(`position.${s.vantage ?? "unknown"}` as MessageKey)}</dd>
        <dt>{t("scope.budget")}</dt>
        <dd>
          <span className="mono">{s.budget.max_probes_per_second}</span> {t("scope.perSecond")} · {t("scope.timeout")}{" "}
          <span className="mono">{s.budget.timeout_ms / 1000}s</span> · {t("scope.oneAtATime")}
        </dd>
        <dt>{t("scope.allowed")}</dt>
        <dd>{capsText(s.capabilities ?? ["tcp_connect"], t)}</dd>
        {(s.nse_scripts ?? []).length > 0 && (
          <>
            <dt>{t("scope.scripts")}</dt>
            <dd className="mono">{s.nse_scripts.join(", ")}</dd>
          </>
        )}
        {(s.exclusions ?? []).length > 0 && (
          <>
            <dt>{t("scope.neverTouched")}</dt>
            <dd className="mono">{s.exclusions.join(", ")}</dd>
          </>
        )}
        {s.nothing_to_exclude && (
          <>
            <dt>{t("scope.neverTouched")}</dt>
            <dd>{t("scope.noneToAvoid")}</dd>
          </>
        )}
      </dl>
      <table className="flow-table session-table">
        <thead>
          <tr>
            <th>{t("scope.col.target")}</th>
            <th>{t("scope.col.ports")}</th>
            <th>{t("scope.col.role")}</th>
            <th>{t("scope.col.label")}</th>
          </tr>
        </thead>
        <tbody>
          {s.targets.map((x) => (
            <tr key={x.address}>
              <td className="mono">{x.address}</td>
              <td className="mono">{x.ports.join(", ")}</td>
              <td>{t(`scope.role.${x.role}` as MessageKey)}</td>
              <td className="meta">{x.label || "—"}</td>
            </tr>
          ))}
          {(s.ranges ?? []).map((r) => (
            <tr key={r.cidr}>
              <td className="mono">{r.cidr}</td>
              <td className="mono">{r.ports.join(", ")}</td>
              <td>{t("scope.col.range")}</td>
              <td className="meta">{r.label || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function problemKey(p: FormProblem): MessageKey {
  if (p.kind === "port_text") return "scope.err.port_text";
  if (p.kind === "range_port_text") return "scope.err.range_port_text";
  return `scope.err.number.${p.field}` as MessageKey;
}

function NewScope({ onDone, operator }: { onDone: () => void; operator: string }) {
  const { t } = useI18n();
  const [f, setF] = useState<ScopeForm>(() => emptyScopeForm(operator));
  const [network, setNetwork] = useState<NetworkBinding | null | undefined>(undefined);
  const [errors, setErrors] = useState<DraftError[]>([]);
  const [problems, setProblems] = useState<FormProblem[]>([]);
  // Which form row each sent target came from (empty rows are not sent).
  const [targetRows, setTargetRows] = useState<number[]>([]);
  const [other, setOther] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    void scopeNetwork().then(setNetwork);
  }, []);
  const set = (k: keyof ScopeForm) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });
  const setRow = (i: number, k: keyof ScopeForm["targets"][number], v: string) =>
    setF({ ...f, targets: f.targets.map((r, j) => (j === i ? { ...r, [k]: v } : r)) });
  const rowErrors = (i: number) => [
    ...problems.filter((p) => p.kind === "port_text" && p.index === i).map((p) => t(problemKey(p))),
    ...errors.filter((e) => draftErrorRow(e, targetRows) === i).map((e) => t(draftErrorKey(e))),
  ];
  // One-tap suggestions and placeholders from the network this Mac is on.
  const net = network ?? null;
  const router = routerSuggestion(net);
  const suggestedRange = rangeSuggestion(net);
  const ph = placeholders(net);
  const outside = (text: string) => outsideNetwork(text, net) === true;
  const setRange = (i: number, k: keyof RangeRow, v: string) => setF({ ...f, ranges: f.ranges.map((r, j) => (j === i ? { ...r, [k]: v } : r)) });
  const rangeErrors = (i: number) => [
    ...problems.filter((p) => p.kind === "range_port_text" && p.index === i).map((p) => t(problemKey(p))),
    ...errors.filter((e) => draftErrorRangeRow(e) === i).map((e) => t(draftErrorKey(e)).replace("{example}", ph.range)),
  ];
  const isExclusionError = (e: DraftError) => e.kind === "bad_exclusion" || e.kind === "exclusions_required" || e.kind === "exclusions_contradict";
  const exclusionErrors = errors.filter(isExclusionError).map((e) =>
    e.kind === "bad_exclusion" ? t("scope.err.bad_exclusion_value").replace("{value}", exclusionList(f.exclusions)[e.index] ?? "") : t(draftErrorKey(e)),
  );
  const general = [
    ...problems.filter((p) => p.kind === "number_text").map((p) => t(problemKey(p))),
    ...errors.filter((e) => draftErrorRow(e, targetRows) == null && draftErrorRangeRow(e) == null && !isExclusionError(e)).map((e) => t(draftErrorKey(e))),
  ];
  // After a refused submit, bring the first error into view: it may be far above the button.
  const showFirstError = () => requestAnimationFrame(() => document.querySelector(".scope-form .form-error")?.scrollIntoView({ block: "center", behavior: "smooth" }));

  const submit = async () => {
    setOther(null);
    const r = toDraft(f, Date.now());
    if (!r.ok) {
      setProblems(r.problems);
      setErrors([]);
      showFirstError();
      return;
    }
    setProblems([]);
    setTargetRows(r.targetRows);
    setBusy(true);
    try {
      await scopeApprove(r.draft);
      setErrors([]);
      onDone();
    } catch (e) {
      const se = e as ScopeError;
      if (se?.kind === "invalid") {
        setErrors(se.detail);
        showFirstError();
      } else setOther(t(`scope.err.${se?.kind ?? "store"}` as MessageKey));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form
      className="scope-form"
      onSubmit={(e) => {
        e.preventDefault();
        void submit();
      }}
    >
      <p className="meta">{t("scope.formIntro")}</p>
      <div className="session-form">
        <label>
          <span>{t("scope.field.auth")} *</span>
          <input value={f.authorization_reference} onChange={set("authorization_reference")} maxLength={200} />
        </label>
        <label>
          <span>{t("scope.field.grantedBy")} *</span>
          <input value={f.granted_by} onChange={set("granted_by")} maxLength={200} />
        </label>
        <label>
          <span>{t("scope.field.operator")} *</span>
          <input value={f.operator} onChange={set("operator")} maxLength={200} />
        </label>
        <label>
          <span>{t("scope.field.validity")}</span>
          <select value={f.hours} onChange={set("hours")}>
            {VALIDITY_CHOICES.map((h) => (
              <option key={h} value={h}>
                {Number(h) < 24 ? `${h} ${t("scope.hours")}` : `${Number(h) / 24} ${t("session.retention.days")}`}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span>{t("scope.field.rate")}</span>
          <input value={f.rate} onChange={set("rate")} inputMode="numeric" />
        </label>
        <label>
          <span>{t("scope.field.timeout")}</span>
          <input value={f.timeout_s} onChange={set("timeout_s")} inputMode="decimal" />
        </label>
      </div>

      <h3 className="subsection">{t("scope.targets")}</h3>
      <p className="meta small field-hint">{t("scope.targetsHint")}</p>
      <div className="target-rows">
        {f.targets.map((r, i) => (
          <div className="target-row" key={i}>
            <input
              className="mono"
              placeholder={ph.target}
              aria-label={t("scope.col.target")}
              value={r.address}
              onChange={(e) => setRow(i, "address", e.target.value)}
            />
            <input
              className="mono"
              placeholder="80, 443"
              aria-label={t("scope.col.ports")}
              value={r.ports}
              onChange={(e) => setRow(i, "ports", e.target.value)}
            />
            <select aria-label={t("scope.col.role")} value={r.role} onChange={(e) => setRow(i, "role", e.target.value)}>
              {TARGET_ROLES.map((role) => (
                <option key={role} value={role}>
                  {t(`scope.role.${role}` as MessageKey)}
                </option>
              ))}
            </select>
            <input placeholder={t("scope.col.label")} aria-label={t("scope.col.label")} value={r.label} onChange={(e) => setRow(i, "label", e.target.value)} />
            <button
              type="button"
              className="chip small"
              aria-label={t("scope.removeTarget")}
              disabled={f.targets.length === 1 && f.ranges.length === 0}
              onClick={() => setF({ ...f, targets: f.targets.filter((_, j) => j !== i) })}
            >
              ×
            </button>
            <FormErrors className="row-error" messages={rowErrors(i)} />
            {outside(r.address) && <span className="small outside-note">{t("scope.outsideNetwork")}</span>}
            <span className="meta small role-hint">{t(`scope.roleHint.${r.role}` as MessageKey)}</span>
          </div>
        ))}
      </div>
      <button type="button" className="chip small" onClick={() => setF({ ...f, targets: [...f.targets, emptyTarget("other")] })} disabled={f.targets.length >= 16}>
        + {t("scope.addTarget")}
      </button>
      {router && !f.targets.some((x) => x.address.trim() === router.address) && (
        <button type="button" className="chip small suggest" onClick={() => setF(withRouter(f, router))}>
          {t("scope.suggest.router").replace("{address}", router.address)}
        </button>
      )}

      <h3 className="subsection">{t("scope.ranges")}</h3>
      <p className="meta small field-hint">{t("scope.rangesHint").replace("{example}", ph.range)}</p>
      {f.ranges.length > 0 && (
        <div className="target-rows">
          {f.ranges.map((r, i) => (
            <div className="target-row range-row" key={i}>
              <input className="mono" placeholder={ph.range} aria-label={t("scope.col.range")} value={r.cidr} onChange={(e) => setRange(i, "cidr", e.target.value)} />
              <input className="mono" placeholder="22, 80, 443" aria-label={t("scope.col.ports")} value={r.ports} onChange={(e) => setRange(i, "ports", e.target.value)} />
              <input placeholder={t("scope.col.label")} aria-label={t("scope.col.label")} value={r.label} onChange={(e) => setRange(i, "label", e.target.value)} />
              <button type="button" className="chip small" aria-label={t("scope.removeRange")} onClick={() => setF({ ...f, ranges: f.ranges.filter((_, j) => j !== i) })}>
                ×
              </button>
              <FormErrors className="row-error" messages={rangeErrors(i)} />
              {outside(r.cidr) && <span className="small outside-note">{t("scope.outsideNetwork")}</span>}
            </div>
          ))}
        </div>
      )}
      <button type="button" className="chip small" onClick={() => setF({ ...f, ranges: [...f.ranges, emptyRange()] })} disabled={f.ranges.length >= 16}>
        + {t("scope.addRange")}
      </button>
      {suggestedRange && !f.ranges.some((x) => x.cidr.trim() === suggestedRange.cidr) && (
        <>
          <button type="button" className="chip small suggest" onClick={() => setF(withRange(f, suggestedRange.cidr))}>
            {t("scope.suggest.range").replace("{cidr}", suggestedRange.cidr)}
          </button>
          {suggestedRange.narrowed && <p className="meta small field-hint">{t("scope.suggest.narrowed")}</p>}
        </>
      )}
      {f.ranges.length > 0 && (
        <label className="wide exclusions">
          <span>{t("scope.exclusions")}</span>
          <textarea className="mono" rows={3} placeholder={ph.exclusion} value={f.exclusions} onChange={(e) => setF({ ...f, exclusions: e.target.value })} />
          <span className="meta small">{t("scope.exclusionsHint")}</span>
        </label>
      )}
      {f.ranges.length > 0 && (
        <label className="confirm-line nothing-to-exclude">
          <input type="checkbox" checked={f.nothing_to_exclude} onChange={(e) => setF({ ...f, nothing_to_exclude: e.target.checked })} />{" "}
          {t("scope.nothingToExclude")}
        </label>
      )}
      {f.ranges.length > 0 && <FormErrors messages={exclusionErrors} />}

      <h3 className="subsection">{t("scope.capabilities")}</h3>
      <p className="meta small field-hint">{t("scope.capabilitiesHint")}</p>
      <div className="cap-groups">
        {(["L1", "L2"] as const).map((level) => (
          <fieldset key={level} className="cap-group" data-level={level}>
            <legend>{t(`scope.level.${level}` as MessageKey)}</legend>
            {CAPABILITIES.filter((c) => capabilityLevel(c) === level).map((c) => (
              <label key={c} className="cap-item">
                <input type="checkbox" checked={f.capabilities.includes(c)} onChange={() => setF(toggleCapability(f, c))} />
                <span>
                  <span className="cap-name">{t(`capability.${c}` as MessageKey)}</span>
                  <span className="meta small">{t(`capability.${c}.sends` as MessageKey)}</span>
                </span>
              </label>
            ))}
          </fieldset>
        ))}
      </div>
      {!f.capabilities.includes("tcp_connect") && <p className="meta small field-hint">{t("scope.checksNote")}</p>}
      {f.capabilities.includes("nse") && (
        <fieldset className="cap-group scripts">
          <legend>{t("scope.scripts")}</legend>
          <p className="meta small">{t("scope.scriptsHint")}</p>
          {NSE_ALLOWLIST.map((n) => (
            <label key={n} className="cap-item">
              <input
                type="checkbox"
                checked={f.nse_scripts.includes(n)}
                onChange={() => setF({ ...f, nse_scripts: f.nse_scripts.includes(n) ? f.nse_scripts.filter((x) => x !== n) : [...f.nse_scripts, n] })}
              />
              <span>
                <span className="cap-name mono">{n}</span>
                <span className="meta small">{t(`nse.${n}` as MessageKey)}</span>
              </span>
            </label>
          ))}
        </fieldset>
      )}

      <div className="bind-line">
        <span className="meta">{t("scope.bindTo")}:</span> {network === undefined ? <span className="meta">…</span> : <NetworkLine n={network} />}
      </div>
      <div className="session-form position-line">
      <label className="wide">
        <span>{t("position.label")} *</span>
        <select value={f.vantage} onChange={(e) => setF({ ...f, vantage: e.target.value as ScopeForm["vantage"] })}>
          <option value="" disabled>
            {t("position.choose")}
          </option>
          {POSITIONS.map((p) => (
            <option key={p} value={p}>
              {t(`position.${p}` as MessageKey)}
            </option>
          ))}
        </select>
        <span className="small">{t("position.hint")}</span>
      </label>
      </div>
      <label className="confirm-line">
        <input type="checkbox" checked={f.confirmed} onChange={(e) => setF({ ...f, confirmed: e.target.checked })} />{" "}
        {t("scope.confirm").replace("{caps}", capsText(f.capabilities, t))}
      </label>
      <div className="form-actions">
        <button className="button-primary" type="submit" disabled={busy}>
          {t("scope.approve")}
        </button>
        <FormErrors messages={[...general, ...(other ? [other] : [])]} />
      </div>
    </form>
  );
}

export function ScopePanel({ operator, onChange }: { operator: string; onChange?: () => void }) {
  const { t } = useI18n();
  const [scopes, setScopes] = useState<ScopeView[] | null>(null);
  const [busy, setBusy] = useState(false);
  const loaded = useCallback(() => void scopeList().then(setScopes), []);
  // After approve or revoke, the screen around the panel refreshes too.
  const reload = useCallback(() => {
    loaded();
    onChange?.();
  }, [loaded, onChange]);
  useEffect(loaded, [loaded]);
  if (!scopes) return <p className="meta">{t("topology.loading")}</p>;
  const current = scopes.find((v) => !v.revoked && !v.expired) ?? null;
  const past = scopes.filter((v) => v !== current);
  return (
    <div className="scope-panel">
      {current ? (
        <ScopeCard
          v={current}
          busy={busy}
          onRevoke={() => {
            setBusy(true);
            void scopeRevoke(current.scope.id)
              .then(reload)
              .finally(() => setBusy(false));
          }}
        />
      ) : (
        <>
          <div className="notice">
            <strong>{t("assessment.empty.title")}</strong>
            <p>{t("scope.noneBody")}</p>
          </div>
          <NewScope operator={operator} onDone={reload} />
        </>
      )}
      {past.length > 0 && (
        <details className="past-scopes">
          <summary className="meta">
            {t("scope.past")} ({past.length})
          </summary>
          {past.map((v) => (
            <ScopeCard key={v.scope.id} v={v} busy onRevoke={() => {}} />
          ))}
        </details>
      )}
    </div>
  );
}
