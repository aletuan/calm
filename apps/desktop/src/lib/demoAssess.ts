import type {
  AddressReason,
  CheckId,
  CheckResult,
  ChecksRun,
  Claim,
  DraftError,
  NetworkBinding,
  PlanItem,
  Preflight,
  ProbeOutcome,
  ProbeRecord,
  Progress,
  Reason,
  Scope,
  ScopeDraft,
  ScopeView,
  StoredRun,
} from "./assess";
import type { Confidence } from "./ipc";

/**
 * Browser-preview stand-in for the M2 shell commands. Same rules as
 * `calm_orchestrator` (scope validation, plan order, decision table) so the
 * preview behaves like the app; the "network" is simulated and nothing is
 * sent: port 443/8443 accept, 80 resets, anything else stays silent.
 */

const CHECKS: CheckId[] = ["S01", "N03", "N01"];
const ROLE: Record<CheckId, string> = { S01: "admin_interface", N03: "pos_test", N01: "cooperative_receiver" };
export const DEMO_NETWORK: NetworkBinding = { gateway: "192.168.0.1", subnet: "192.168.0.0/24", ssid: null };
const MAX_VALIDITY_MS = 7 * 24 * 3600 * 1000;

function v4(text: string): number[] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text);
  if (!m) return null;
  const o = m.slice(1).map(Number);
  return o.every((x) => x <= 255) ? o : null;
}

/** Same policy as `check_address`: private IPv4, 100.64/10, IPv6 ULA. */
export function checkAddress(raw: string): { ok: true; address: string } | { ok: false; reason: AddressReason } {
  const text = raw.trim();
  const o = v4(text);
  if (o) {
    const a = o[0]!;
    const b = o[1]!;
    if (o.every((x) => x === 0)) return { ok: false, reason: "unspecified" };
    if (a === 127) return { ok: false, reason: "loopback" };
    if (a >= 224 && a <= 239) return { ok: false, reason: "multicast" };
    if (o.every((x) => x === 255)) return { ok: false, reason: "broadcast" };
    if (a === 169 && b === 254) return { ok: false, reason: "link_local" };
    const priv = a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
    return priv ? { ok: true, address: o.join(".") } : { ok: false, reason: "not_private" };
  }
  if (!/^[0-9a-fA-F:]+$/.test(text) || !text.includes(":")) return { ok: false, reason: "not_an_address" };
  const lower = text.toLowerCase();
  if (lower === "::") return { ok: false, reason: "unspecified" };
  if (lower === "::1") return { ok: false, reason: "loopback" };
  if (lower.startsWith("ff")) return { ok: false, reason: "multicast" };
  if (/^fe[89ab]/.test(lower)) return { ok: false, reason: "link_local" };
  if (/^f[cd]/.test(lower)) return { ok: true, address: lower };
  return { ok: false, reason: "not_private" };
}

export function validateDraft(d: ScopeDraft, now: number, network: NetworkBinding | null): DraftError[] {
  const e: DraftError[] = [];
  if (!d.authorization_reference.trim()) e.push({ kind: "authorization_required" });
  if (!d.operator.trim()) e.push({ kind: "operator_required" });
  if (!d.granted_by.trim()) e.push({ kind: "granted_by_required" });
  const texts = [d.authorization_reference, d.operator, d.granted_by, ...d.targets.map((t) => t.label)];
  if (texts.some((t) => [...t].length > 200)) e.push({ kind: "text_too_long" });
  if (!d.authorization_confirmed) e.push({ kind: "not_confirmed" });
  if (d.targets.length === 0) e.push({ kind: "no_targets" });
  if (d.targets.length > 16) e.push({ kind: "too_many_targets" });
  const seen = new Set<string>();
  d.targets.forEach((t, index) => {
    const a = checkAddress(t.address);
    if (!a.ok) return void e.push({ kind: "bad_address", index, reason: a.reason });
    if (seen.has(a.address)) return void e.push({ kind: "duplicate_address", index });
    seen.add(a.address);
    const ports = [...new Set(t.ports)];
    if (ports.length === 0) e.push({ kind: "no_ports", index });
    else if (ports.length > 16) e.push({ kind: "too_many_ports", index });
    else if (ports.some((p) => p < 1 || p > 65535 || !Number.isInteger(p))) e.push({ kind: "bad_port", index });
  });
  if (d.expires_at_ms <= now) e.push({ kind: "expiry_in_past" });
  else if (d.expires_at_ms - now > MAX_VALIDITY_MS) e.push({ kind: "expiry_too_far" });
  if (!(d.max_probes_per_second >= 1 && d.max_probes_per_second <= 10)) e.push({ kind: "rate_out_of_range" });
  if (!(d.timeout_ms >= 500 && d.timeout_ms <= 5000)) e.push({ kind: "timeout_out_of_range" });
  if (!network) e.push({ kind: "network_unknown" });
  if (!d.vantage) e.push({ kind: "vantage_required" });
  return e;
}

/** Port of `in_subnet`: null when either side cannot be read or the target is IPv6. */
export function inSubnet(address: string, subnet: string): boolean | null {
  const ip = v4(address);
  const [net, prefixText] = subnet.split("/");
  const n = net ? v4(net) : null;
  if (!ip || !n || prefixText === undefined || !/^\d{1,2}$/.test(prefixText)) return null;
  const prefix = Number(prefixText);
  if (prefix > 32) return null;
  const num = (o: number[]) => ((o[0]! << 24) | (o[1]! << 16) | (o[2]! << 8) | o[3]!) >>> 0;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return ((num(ip) & mask) >>> 0) === ((num(n) & mask) >>> 0);
}

export function planOf(s: Scope): PlanItem[] {
  return CHECKS.flatMap((check) =>
    s.targets
      .filter((t) => t.role === ROLE[check])
      .flatMap((t) =>
        t.ports.map((port) => ({ check, target: t.address, port, label: t.label, outside_subnet: s.network.subnet ? inSubnet(t.address, s.network.subnet) === false : false })),
      ),
  );
}

/** Port of `checks::result`: keep in step with the Rust decision table. */
export function evaluateTarget(check: CheckId, ports: { port: number; outcome: ProbeOutcome }[], confirmed: boolean): Omit<CheckResult, "check" | "target" | "label" | "ports"> {
  const r = (status: CheckResult["status"], severity: CheckResult["severity"], confidence: Confidence, reason: Reason, verified: Claim[] = [], unverified: Claim[] = []) => ({
    status,
    severity,
    confidence: status === "not_tested" ? null : confidence,
    reason,
    verified,
    unverified,
  });
  const k = ports.map((p) => p.outcome.kind);
  const any = (x: string) => k.includes(x as never);
  const all = (x: string) => k.length > 0 && k.every((y) => y === x);
  const listener = check !== "S01";
  if (any("connected"))
    return r("fail", check === "S01" ? "medium" : "high", "high", "connected", ["tcp_accepted"], check === "S01" ? ["login_or_auth_bypass", "access_to_management_data", "service_identity"] : ["service_identity"]);
  if (all("denied")) return r("not_tested", "info", "high", "denied");
  if (any("cancelled")) return r("not_tested", "info", "high", "stopped");
  if (any("denied")) return r("not_tested", "info", "high", "denied");
  if (any("unreachable")) return r("inconclusive", "info", "low", "local_error");
  if (listener && any("refused"))
    return r(check === "N01" ? "fail" : "warning", "medium", check === "N01" ? "medium" : "low", "reset_from_listener", ["tcp_reset"], ["service_identity"]);
  if (!listener && all("refused")) return r("pass", "info", "medium", "all_refused", ["tcp_reset"], ["blocked_on_other_ports"]);
  if (listener && all("timed_out"))
    return confirmed
      ? r("pass", "info", "medium", "silent_confirmed_listener", ["no_reply", "listener_confirmed_by_user"], ["listener_was_running", "blocked_for_other_devices"])
      : r("inconclusive", "info", "low", "silent_unconfirmed", ["no_reply"], ["listener_was_running"]);
  return r("inconclusive", "info", "low", "silent", ["no_reply"]);
}

export function evaluateRun(s: Scope, probes: { check: CheckId; record: ProbeRecord }[], confirmed: boolean): CheckResult[] {
  const out: CheckResult[] = [];
  for (const check of CHECKS) {
    const targets = s.targets.filter((t) => t.role === ROLE[check]);
    if (targets.length === 0) {
      out.push({ check, target: null, label: "", ports: [], status: "not_tested", severity: "info", confidence: null, reason: "no_target", verified: [], unverified: [] });
      continue;
    }
    for (const t of targets) {
      const ports = t.ports.map((port) => {
        const rec = probes.find((p) => p.check === check && p.record.target === `${t.address.includes(":") ? `[${t.address}]` : t.address}:${port}`);
        return { port, outcome: rec?.record.outcome ?? ({ kind: "cancelled" } as ProbeOutcome) };
      });
      out.push({ check, target: t.address, label: t.label, ports, ...evaluateTarget(check, ports, confirmed) });
    }
  }
  return out;
}

export function simulatedOutcome(port: number): ProbeOutcome {
  if (port === 443 || port === 8443) return { kind: "connected", rtt_ms: 4 };
  if (port === 80) return { kind: "refused", rtt_ms: 3 };
  return { kind: "timed_out" };
}

type Timer = (f: () => void, ms: number) => unknown;

export class DemoAssess {
  private scopes = new Map<string, { scope: Scope; revoked: boolean }>();
  private stored: StoredRun[] = [];
  private progress: Progress | null = null;
  private stopped = false;
  private seq = 0;

  constructor(
    private readonly now: () => number,
    private readonly activeSession: () => string | null,
    private readonly timer: Timer = (f, ms) => setTimeout(f, ms),
    private readonly net: NetworkBinding | null = DEMO_NETWORK,
  ) {}

  private id(p: string) {
    this.seq += 1;
    return `${p}${String(this.seq).padStart(12, "0")}`;
  }

  network(): NetworkBinding | null {
    return this.net;
  }

  list(): ScopeView[] {
    const sid = this.activeSession();
    return [...this.scopes.values()]
      .filter((x) => x.scope.session_id === sid)
      .reverse()
      .map((x) => ({ scope: x.scope, revoked: x.revoked, expired: this.now() >= x.scope.expires_at_ms }));
  }

  current(): ScopeView | null {
    return this.list().find((v) => !v.revoked && !v.expired) ?? null;
  }

  approve(d: ScopeDraft): ScopeView {
    const sid = this.activeSession();
    if (!sid) throw { kind: "no_active_session" };
    if (this.current()) throw { kind: "active_exists" };
    const now = this.now();
    const errors = validateDraft(d, now, this.net);
    if (errors.length) throw { kind: "invalid", detail: errors };
    const scope: Scope = {
      id: this.id("scope"),
      session_id: sid,
      authorization_reference: d.authorization_reference.trim(),
      operator: d.operator.trim(),
      granted_by: d.granted_by.trim(),
      targets: d.targets.map((t) => ({ address: (checkAddress(t.address) as { address: string }).address, ports: [...new Set(t.ports)].sort((a, b) => a - b), role: t.role, label: t.label.trim() })),
      max_level: "L1",
      budget: { max_probes_per_second: d.max_probes_per_second, timeout_ms: d.timeout_ms, max_parallel_targets: 1 },
      network: this.net!,
      vantage: d.vantage ?? "unknown",
      approved_at_ms: now,
      expires_at_ms: d.expires_at_ms,
      // The form has no capability choices yet (ADR-011): same as Rust's default.
      capabilities: ["tcp_connect"],
      ranges: [],
      exclusions: [],
      nse_scripts: [],
    };
    this.scopes.set(scope.id, { scope, revoked: false });
    return { scope, revoked: false, expired: false };
  }

  revoke(id: string): void {
    const s = this.scopes.get(id);
    if (!s || s.scope.session_id !== this.activeSession()) throw { kind: "not_found" };
    s.revoked = true;
  }

  preflight(): Preflight {
    const v = this.current();
    if (!v) return { scope: null, network: this.net, same_network: null, plan: [], min_seconds: 0, max_seconds: 0, ready: false };
    const plan = planOf(v.scope);
    const n = plan.length;
    const rate = v.scope.budget.max_probes_per_second;
    const min = Math.ceil(Math.max(0, n - 1) / rate);
    const same = this.net ? this.net.gateway === v.scope.network.gateway : null;
    return { scope: v, network: this.net, same_network: same, plan, min_seconds: min, max_seconds: min + Math.ceil((n * v.scope.budget.timeout_ms) / 1000), ready: same === true && n > 0 };
  }

  status(): Progress | null {
    return this.progress ? { ...this.progress } : null;
  }

  stop(): void {
    this.stopped = true;
  }

  runs(): StoredRun[] {
    const sid = this.activeSession();
    return this.stored.filter((r) => this.scopes.get(r.run.scope_id)?.scope.session_id === sid);
  }

  run(confirmed: boolean): Progress {
    if (this.progress?.running) throw { kind: "already_running" };
    if (!this.activeSession()) throw { kind: "no_active_session" };
    const v = this.current();
    if (!v) throw { kind: "no_scope" };
    const plan = planOf(v.scope);
    const runId = this.id("run");
    this.stopped = false;
    const started = this.now();
    this.progress = { run_id: runId, running: true, done: 0, total: plan.length, last: null, stopped: false, started_at_ms: started, error: null, snapshot_id: null };
    const probes: ChecksRun["probes"] = [];
    const gap = Math.round(1000 / v.scope.budget.max_probes_per_second);
    const step = (i: number) => {
      if (i >= plan.length) return finish();
      const p = plan[i]!;
      const target = `${p.target.includes(":") ? `[${p.target}]` : p.target}:${p.port}`;
      const outcome: ProbeOutcome = this.stopped ? { kind: "cancelled" } : simulatedOutcome(p.port);
      const record: ProbeRecord = { target, role: v.scope.targets.find((t) => t.address === p.target)?.role ?? null, scope_id: outcome.kind === "cancelled" ? null : v.scope.id, started_at_ms: this.now(), outcome };
      probes.push({ check: p.check, record });
      this.progress = { ...this.progress!, done: i + 1, last: record };
      this.timer(() => step(i + 1), this.stopped ? 0 : outcome.kind === "timed_out" ? Math.max(gap, 600) : gap);
    };
    const finish = () => {
      const run: ChecksRun = { id: runId, scope_id: v.scope.id, started_at_ms: started, finished_at_ms: this.now(), stopped: this.stopped, receiver_confirmed: confirmed, vantage: v.scope.vantage, probes, results: evaluateRun(v.scope, probes, confirmed) };
      const snapshot_id = this.id("findings");
      this.stored.unshift({ snapshot_id, run });
      this.progress = { ...this.progress!, running: false, stopped: this.stopped, snapshot_id };
    };
    this.timer(() => step(0), 0);
    return { ...this.progress };
  }
}
