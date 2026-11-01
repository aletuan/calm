import { invoke, isTauri } from "@tauri-apps/api/core";
import type { Confidence, StoreError } from "./ipc";
import { demoActiveSessionId } from "./ipc";
import { DemoAssess } from "./demoAssess";

/** M2 types, mirroring `calm_domain::scope`, `calm_orchestrator::{scope,probe,checks}` and the shell's `assess`. */

export type TargetRole = "gateway" | "admin_interface" | "pos_test" | "cooperative_receiver" | "other";
export const TARGET_ROLES: TargetRole[] = ["admin_interface", "pos_test", "cooperative_receiver", "gateway", "other"];

/** Where this Mac stands while testing, as the user states it in the scope. */
export type NetworkPosition = "guest" | "main" | "unknown";
export const POSITIONS: NetworkPosition[] = ["guest", "main", "unknown"];

export interface ScopeTarget {
  address: string;
  ports: number[];
  role: TargetRole;
  label: string;
}

export interface NetworkBinding {
  gateway: string;
  subnet: string | null;
  ssid: string | null;
}

/** ADR-011: kinds of traffic a scope allows. Mirrors `calm_domain::Capability`. */
export type Capability = "tcp_connect" | "host_discovery" | "reverse_dns" | "syn_scan" | "service_detection" | "os_detection" | "nse";

export interface ScopeRange {
  cidr: string;
  ports: number[];
  label: string;
}

export interface Scope {
  id: string;
  session_id: string;
  authorization_reference: string;
  operator: string;
  granted_by: string;
  targets: ScopeTarget[];
  max_level: "L0" | "L1" | "L2" | "L3";
  budget: { max_probes_per_second: number; timeout_ms: number; max_parallel_targets: number };
  network: NetworkBinding;
  vantage: NetworkPosition;
  approved_at_ms: number;
  expires_at_ms: number;
  /** Scopes stored before ADR-011 read as ["tcp_connect"] on the Rust side. */
  capabilities: Capability[];
  ranges: ScopeRange[];
  exclusions: string[];
  /** The user confirmed no device in the ranges needs avoiding (instead of listing exclusions). */
  nothing_to_exclude: boolean;
  nse_scripts: string[];
}

export interface ScopeView {
  scope: Scope;
  revoked: boolean;
  expired: boolean;
}

export interface TargetDraft {
  address: string;
  ports: number[];
  role: TargetRole;
  label: string;
}

export interface ScopeDraft {
  authorization_reference: string;
  operator: string;
  granted_by: string;
  targets: TargetDraft[];
  expires_at_ms: number;
  max_probes_per_second: number;
  timeout_ms: number;
  authorization_confirmed: boolean;
  /** Required: null is rejected with `vantage_required`. */
  vantage: NetworkPosition | null;
  /** ADR-011. Left out: TCP connect only, no ranges, no scripts. */
  capabilities?: Capability[];
  ranges?: { cidr: string; ports: number[]; label: string }[];
  exclusions?: string[];
  nothing_to_exclude?: boolean;
  nse_scripts?: string[];
}

export type AddressReason = "not_an_address" | "unspecified" | "loopback" | "multicast" | "broadcast" | "link_local" | "not_private";

export type DraftError =
  | { kind: "authorization_required" }
  | { kind: "operator_required" }
  | { kind: "granted_by_required" }
  | { kind: "text_too_long" }
  | { kind: "not_confirmed" }
  | { kind: "no_targets" }
  | { kind: "too_many_targets" }
  | { kind: "bad_address"; index: number; reason: AddressReason }
  | { kind: "duplicate_address"; index: number }
  | { kind: "no_ports"; index: number }
  | { kind: "too_many_ports"; index: number }
  | { kind: "bad_port"; index: number }
  | { kind: "expiry_in_past" }
  | { kind: "expiry_too_far" }
  | { kind: "rate_out_of_range" }
  | { kind: "timeout_out_of_range" }
  | { kind: "network_unknown" }
  | { kind: "vantage_required" }
  | { kind: "no_capabilities" }
  | { kind: "bad_range"; index: number }
  | { kind: "range_too_large"; index: number }
  | { kind: "bad_range_ports"; index: number }
  | { kind: "exclusions_required" }
  | { kind: "exclusions_contradict" }
  | { kind: "bad_exclusion"; index: number }
  | { kind: "host_discovery_needs_range" }
  | { kind: "scripts_need_nse" }
  | { kind: "nse_needs_scripts" }
  | { kind: "script_not_allowed"; index: number };

export type ScopeError =
  | { kind: "invalid"; detail: DraftError[] }
  | { kind: "active_exists" }
  | { kind: "no_active_session" }
  | { kind: "store"; detail: StoreError };

export type CheckId = "S01" | "N03" | "N01";
export const CHECKS: CheckId[] = ["S01", "N03", "N01"];
export const CHECK_ROLE: Record<CheckId, TargetRole> = { S01: "admin_interface", N03: "pos_test", N01: "cooperative_receiver" };

export type DenyReason =
  | "no_grant"
  | "revoked"
  | "expired"
  | "level_exceeded"
  | "target_not_allowed"
  | "port_not_allowed"
  | "network_unknown"
  | "network_changed"
  | "address_not_allowed"
  | "capability_not_granted";

export type ProbeOutcome =
  | { kind: "connected"; rtt_ms: number }
  | { kind: "refused"; rtt_ms: number }
  | { kind: "timed_out" }
  | { kind: "unreachable"; detail: string }
  | { kind: "denied"; reason: { kind: DenyReason } }
  | { kind: "cancelled" };

export interface ProbeRecord {
  target: string;
  role: TargetRole | null;
  scope_id: string | null;
  started_at_ms: number;
  outcome: ProbeOutcome;
}

export type FindingStatus = "pass" | "fail" | "warning" | "inconclusive" | "not_tested" | "informational";
export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type Reason =
  | "connected"
  | "all_refused"
  | "reset_from_listener"
  | "silent_confirmed_listener"
  | "silent_unconfirmed"
  | "silent"
  | "local_error"
  | "denied"
  | "stopped"
  | "no_target";

export type Claim =
  | "tcp_accepted"
  | "tcp_reset"
  | "no_reply"
  | "listener_confirmed_by_user"
  | "login_or_auth_bypass"
  | "access_to_management_data"
  | "service_identity"
  | "listener_was_running"
  | "blocked_on_other_ports"
  | "blocked_for_other_devices";

export interface CheckResult {
  check: CheckId;
  target: string | null;
  label: string;
  status: FindingStatus;
  severity: Severity;
  /** null when nothing was tested. */
  confidence: Confidence | null;
  reason: Reason;
  ports: { port: number; outcome: ProbeOutcome }[];
  verified: Claim[];
  unverified: Claim[];
}

export interface ChecksRun {
  id: string;
  scope_id: string;
  started_at_ms: number;
  finished_at_ms: number;
  stopped: boolean;
  receiver_confirmed: boolean;
  vantage: NetworkPosition;
  probes: { check: CheckId; record: ProbeRecord }[];
  results: CheckResult[];
}

export interface StoredRun {
  snapshot_id: string;
  run: ChecksRun;
}

export interface PlanItem {
  check: CheckId;
  target: string;
  port: number;
  label: string;
  /** Outside this Mac's subnet: routed through the gateway. */
  outside_subnet: boolean;
}

export interface Preflight {
  scope: ScopeView | null;
  network: NetworkBinding | null;
  same_network: boolean | null;
  plan: PlanItem[];
  min_seconds: number;
  max_seconds: number;
  ready: boolean;
}

export interface Progress {
  run_id: string;
  running: boolean;
  done: number;
  total: number;
  last: ProbeRecord | null;
  stopped: boolean;
  started_at_ms: number;
  error: string | null;
  snapshot_id: string | null;
}

export type RunError =
  | { kind: "already_running" }
  | { kind: "no_active_session" }
  | { kind: "no_scope" }
  | { kind: "network_changed" }
  | { kind: "store"; detail: StoreError };

/** Browser preview only: a simulated network, nothing is sent. */
const demo = new DemoAssess(() => Date.now(), demoActiveSessionId);
export const demoAssess = demo;

export async function scopeNetwork(): Promise<NetworkBinding | null> {
  if (!isTauri()) return demo.network();
  return invoke<NetworkBinding | null>("scope_network");
}

export async function scopeList(): Promise<ScopeView[]> {
  if (!isTauri()) return demo.list();
  return invoke<ScopeView[]>("scope_list");
}

export async function scopeApprove(draft: ScopeDraft): Promise<ScopeView> {
  if (!isTauri()) return demo.approve(draft);
  return invoke<ScopeView>("scope_approve", { draft });
}

export async function scopeRevoke(scopeId: string): Promise<void> {
  if (!isTauri()) return demo.revoke(scopeId);
  return invoke<void>("scope_revoke", { scopeId });
}

export async function checksPreflight(): Promise<Preflight> {
  if (!isTauri()) return demo.preflight();
  return invoke<Preflight>("checks_preflight");
}

export async function checksRun(receiverConfirmed: boolean): Promise<Progress> {
  if (!isTauri()) return demo.run(receiverConfirmed);
  return invoke<Progress>("checks_run", { receiverConfirmed });
}

export async function checksStatus(): Promise<Progress | null> {
  if (!isTauri()) return demo.status();
  return invoke<Progress | null>("checks_status");
}

export async function emergencyStop(): Promise<void> {
  if (!isTauri()) return demo.stop();
  return invoke<void>("emergency_stop");
}

export async function findingsList(): Promise<StoredRun[]> {
  if (!isTauri()) return demo.runs();
  return invoke<StoredRun[]>("findings_list");
}
