import type { Capability, DraftError, NetworkPosition, ScopeDraft, TargetRole } from "./assess";
import type { MessageKey } from "../i18n/en";

/** The "new scope" form as typed; numbers and ports are still text. */
export interface TargetRow {
  address: string;
  ports: string;
  role: TargetRole;
  label: string;
}

export interface RangeRow {
  cidr: string;
  ports: string;
  label: string;
}

export interface ScopeForm {
  authorization_reference: string;
  operator: string;
  granted_by: string;
  hours: string;
  rate: string;
  timeout_s: string;
  confirmed: boolean;
  /** "" until the user picks one: there is no safe default. */
  vantage: NetworkPosition | "";
  targets: TargetRow[];
  /** ADR-011. Starts as TCP connect only, the M2 behaviour. */
  capabilities: Capability[];
  ranges: RangeRow[];
  /** Addresses never touched, as typed (one per line, or separated by commas). */
  exclusions: string;
  nse_scripts: string[];
}

export const VALIDITY_CHOICES = ["1", "4", "8", "24", "72", "168"] as const;

export const emptyRange = (): RangeRow => ({ cidr: "", ports: "", label: "" });

export const emptyTarget = (role: TargetRole = "admin_interface"): TargetRow => ({ address: "", ports: "", role, label: "" });

export const emptyScopeForm = (operator = ""): ScopeForm => ({
  authorization_reference: "",
  operator,
  granted_by: "",
  hours: "4",
  rate: "5",
  timeout_s: "3",
  confirmed: false,
  vantage: "",
  targets: [emptyTarget()],
  capabilities: ["tcp_connect"],
  ranges: [],
  exclusions: "",
  nse_scripts: [],
});

/** "80, 443 8443" → [80, 443, 8443]; null when any piece is not a port number. */
export function parsePorts(text: string): number[] | null {
  const parts = text.split(/[\s,;]+/).filter(Boolean);
  const out: number[] = [];
  for (const p of parts) {
    if (!/^\d{1,5}$/.test(p)) return null;
    const n = Number(p);
    if (n < 1 || n > 65535) return null;
    if (!out.includes(n)) out.push(n);
  }
  return out;
}

export type FormProblem =
  | { kind: "port_text"; index: number }
  | { kind: "range_port_text"; index: number }
  | { kind: "number_text"; field: "hours" | "rate" | "timeout_s" };

/**
 * Turn the form into a draft for the shell. Only text that cannot become a
 * draft at all is reported here; every rule is enforced by the shell.
 */
/** Excluded addresses as typed: one per line, or separated by commas, spaces or semicolons. */
export const exclusionList = (text: string): string[] => text.split(/[\s,;]+/).filter(Boolean);

/** A target row the user never touched (the form always shows one). */
const untouched = (t: TargetRow) => !t.address.trim() && !t.ports.trim() && !t.label.trim();

export function toDraft(
  f: ScopeForm,
  now: number,
): { ok: true; draft: ScopeDraft; targetRows: number[] } | { ok: false; problems: FormProblem[] } {
  const problems: FormProblem[] = [];
  const num = (field: "hours" | "rate" | "timeout_s") => {
    const v = Number(f[field].trim());
    if (!f[field].trim() || !Number.isFinite(v)) problems.push({ kind: "number_text", field });
    return v;
  };
  const hours = num("hours");
  const rate = num("rate");
  const timeout = num("timeout_s");
  // Draft target i is form row targetRows[i]: the shell's error indexes count sent rows only.
  const targetRows = f.targets.flatMap((t, index) => (untouched(t) ? [] : [index]));
  const targets = targetRows.map((index) => {
    const t = f.targets[index]!;
    const ports = parsePorts(t.ports);
    if (!ports) problems.push({ kind: "port_text", index });
    return { address: t.address.trim(), ports: ports ?? [], role: t.role, label: t.label };
  });
  const ranges = f.ranges.map((r, index) => {
    const ports = parsePorts(r.ports);
    if (!ports) problems.push({ kind: "range_port_text", index });
    return { cidr: r.cidr.trim(), ports: ports ?? [], label: r.label };
  });
  if (problems.length) return { ok: false, problems };
  return {
    ok: true,
    targetRows,
    draft: {
      authorization_reference: f.authorization_reference,
      operator: f.operator,
      granted_by: f.granted_by,
      targets,
      expires_at_ms: now + Math.round(hours * 3_600_000),
      max_probes_per_second: Math.round(rate),
      timeout_ms: Math.round(timeout * 1000),
      authorization_confirmed: f.confirmed,
      vantage: f.vantage || null,
      capabilities: f.capabilities,
      ranges,
      exclusions: exclusionList(f.exclusions),
      nse_scripts: f.nse_scripts,
    },
  };
}

/** Message key for a shell validation error. */
export function draftErrorKey(e: DraftError): MessageKey {
  if (e.kind === "bad_address") return `scope.err.address.${e.reason}` as MessageKey;
  return `scope.err.${e.kind}` as MessageKey;
}

/** Errors whose index is a target row. Range, exclusion and script errors index other lists. */
const TARGET_ROW_ERRORS: DraftError["kind"][] = ["bad_address", "duplicate_address", "no_ports", "too_many_ports", "bad_port"];

/** Which form target row an error belongs to, if any. `targetRows` maps draft targets to form rows. */
export function draftErrorRow(e: DraftError, targetRows?: number[]): number | null {
  if (!("index" in e) || !TARGET_ROW_ERRORS.includes(e.kind)) return null;
  return targetRows ? (targetRows[e.index] ?? null) : e.index;
}

const RANGE_ROW_ERRORS: DraftError["kind"][] = ["bad_range", "range_too_large", "bad_range_ports"];

/** Which range row an error belongs to, if any. */
export function draftErrorRangeRow(e: DraftError): number | null {
  return "index" in e && RANGE_ROW_ERRORS.includes(e.kind) ? e.index : null;
}

export const DRAFT_ERROR_KINDS: DraftError["kind"][] = [
  "authorization_required",
  "operator_required",
  "granted_by_required",
  "text_too_long",
  "not_confirmed",
  "no_targets",
  "too_many_targets",
  "duplicate_address",
  "no_ports",
  "too_many_ports",
  "bad_port",
  "expiry_in_past",
  "expiry_too_far",
  "rate_out_of_range",
  "timeout_out_of_range",
  "network_unknown",
  "vantage_required",
  "no_capabilities",
  "bad_range",
  "range_too_large",
  "bad_range_ports",
  "exclusions_required",
  "bad_exclusion",
  "host_discovery_needs_range",
  "scripts_need_nse",
  "nse_needs_scripts",
  "script_not_allowed",
];
