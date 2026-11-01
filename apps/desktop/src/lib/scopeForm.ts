import type { DraftError, NetworkPosition, ScopeDraft, TargetRole } from "./assess";
import type { MessageKey } from "../i18n/en";

/** The "new scope" form as typed; numbers and ports are still text. */
export interface TargetRow {
  address: string;
  ports: string;
  role: TargetRole;
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
}

export const VALIDITY_CHOICES = ["1", "4", "8", "24", "72", "168"] as const;

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

export type FormProblem = { kind: "port_text"; index: number } | { kind: "number_text"; field: "hours" | "rate" | "timeout_s" };

/**
 * Turn the form into a draft for the shell. Only text that cannot become a
 * draft at all is reported here; every rule is enforced by the shell.
 */
export function toDraft(f: ScopeForm, now: number): { ok: true; draft: ScopeDraft } | { ok: false; problems: FormProblem[] } {
  const problems: FormProblem[] = [];
  const num = (field: "hours" | "rate" | "timeout_s") => {
    const v = Number(f[field].trim());
    if (!f[field].trim() || !Number.isFinite(v)) problems.push({ kind: "number_text", field });
    return v;
  };
  const hours = num("hours");
  const rate = num("rate");
  const timeout = num("timeout_s");
  const targets = f.targets.map((t, index) => {
    const ports = parsePorts(t.ports);
    if (!ports) problems.push({ kind: "port_text", index });
    return { address: t.address.trim(), ports: ports ?? [], role: t.role, label: t.label };
  });
  if (problems.length) return { ok: false, problems };
  return {
    ok: true,
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
    },
  };
}

/** Message key for a shell validation error. */
export function draftErrorKey(e: DraftError): MessageKey {
  if (e.kind === "bad_address") return `scope.err.address.${e.reason}` as MessageKey;
  return `scope.err.${e.kind}` as MessageKey;
}

/** Which target row an error belongs to, if any. */
export function draftErrorRow(e: DraftError): number | null {
  return "index" in e ? e.index : null;
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
];
