import type { CheckResult, Claim, DenyReason, FindingStatus, NetworkPosition, ProbeOutcome, Progress, Severity, StoredRun } from "./assess";
import type { MessageKey } from "../i18n/en";

/** Most important first: failures, then warnings, inconclusive, not tested, passes. */
const STATUS_ORDER: FindingStatus[] = ["fail", "warning", "inconclusive", "not_tested", "informational", "pass"];
const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export function sortResults(rs: CheckResult[]): CheckResult[] {
  return [...rs].sort(
    (a, b) =>
      STATUS_ORDER.indexOf(a.status) - STATUS_ORDER.indexOf(b.status) ||
      SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
      a.check.localeCompare(b.check) ||
      (a.target ?? "").localeCompare(b.target ?? ""),
  );
}

export type StatusCounts = Record<FindingStatus, number>;

export function countByStatus(rs: CheckResult[]): StatusCounts {
  const c = { pass: 0, fail: 0, warning: 0, inconclusive: 0, not_tested: 0, informational: 0 } as StatusCounts;
  for (const r of rs) c[r.status] += 1;
  return c;
}

/** Stable id of a result within a run, for selection. */
export const resultId = (r: CheckResult) => `${r.check}|${r.target ?? "-"}`;

export const statusKey = (s: FindingStatus) => `finding.status.${s}` as MessageKey;
export const severityKey = (s: Severity) => `finding.severity.${s}` as MessageKey;
export const claimKey = (c: Claim) => `finding.claim.${c}` as MessageKey;
export const reasonKey = (r: CheckResult["reason"]) => `finding.reason.${r}` as MessageKey;
export const denyKey = (d: DenyReason) => `probe.denied.${d}` as MessageKey;

export function outcomeKey(o: ProbeOutcome): MessageKey {
  return `probe.outcome.${o.kind}` as MessageKey;
}

/** A short "what the probe saw", e.g. "accepted · 4 ms". */
export function outcomeText(o: ProbeOutcome, t: (k: MessageKey) => string): string {
  switch (o.kind) {
    case "connected":
    case "refused":
      return `${t(outcomeKey(o))} · ${o.rtt_ms} ms`;
    case "denied":
      return `${t(outcomeKey(o))}: ${t(denyKey(o.reason.kind))}`;
    case "unreachable":
      return `${t(outcomeKey(o))} (${o.detail})`;
    default:
      return t(outcomeKey(o));
  }
}

/** Confidence as shown: nothing tested means no confidence (older runs stored "high"). */
export function confidenceText(r: CheckResult, t: (k: MessageKey) => string): string {
  if (r.status === "not_tested" || r.confidence == null) return "—";
  return t(`confidence.${r.confidence}` as MessageKey);
}

export const positionKey = (p: NetworkPosition) => `position.${p}` as MessageKey;

/** A message whose "{from}" names where the Mac stood: "Guest Wi-Fi", "the main network"… */
export function fromText(key: MessageKey, position: NetworkPosition | undefined, t: (k: MessageKey) => string): string {
  return t(key).replaceAll("{from}", t(`position.from.${position ?? "unknown"}` as MessageKey));
}

/** Counts for the finished run the progress points at, or null while running or not stored. */
export function finishedSummary(progress: Progress | null, runs: StoredRun[]): StatusCounts | null {
  if (!progress || progress.running || !progress.snapshot_id) return null;
  const run = runs.find((r) => r.snapshot_id === progress.snapshot_id);
  return run ? countByStatus(run.run.results) : null;
}

/** The newest run and what it found, or null. */
export function latest(runs: StoredRun[]): StoredRun | null {
  return [...runs].sort((a, b) => b.run.started_at_ms - a.run.started_at_ms)[0] ?? null;
}
