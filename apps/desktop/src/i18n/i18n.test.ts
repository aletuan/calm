import { describe, expect, it } from "vitest";
import { CHECKS, POSITIONS, TARGET_ROLES } from "../lib/assess";
import { FLOW_COLUMNS } from "../lib/columns";
import { DRAFT_ERROR_KINDS } from "../lib/scopeForm";
import { PURPOSES } from "../lib/flowPurpose";
import { RETENTION_CHOICES, parseSessionForm, emptyForm, type FormError } from "../lib/sessionForm";
import { en } from "./en";
import { vi } from "./vi";

const keys = Object.keys(en) as (keyof typeof en)[];

describe("i18n", () => {
  it("Vietnamese has a non-empty text for every English key", () => {
    for (const k of keys) expect(vi[k]?.trim(), k).toBeTruthy();
    expect(Object.keys(vi).sort()).toEqual([...keys].sort());
  });

  it("keys built at runtime exist", () => {
    const dynamic = [
      ...["this_mac", "capture_host", "access_point_radio", "default_gateway", "dns_resolver", "local_peer", "external_destinations", "unknown"].map((r) => `role.${r}`),
      ...["not_a_capture", "truncated", "bad_length", "length_mismatch", "unknown_interface", "bad_capture_length", "io"].map((r) => `import.reason.${r}`),
      ...(["name_required", "name_too_long", "field_too_long", "notes_too_long", "retention_invalid"] satisfies FormError[]).map((e) => `session.err.${e}`),
      ...["observed", "inferred", "validated", "unverified"].map((s) => `status.${s}`),
      ...["low", "medium", "high"].map((c) => `confidence.${c}`),
      ...["capture:flows", "capture:link-binding", "import:flows", "import:link-binding", "import:vantage", "import:forwarding", "profile:corewlan", "profile:route", "profile:scutil-dns", "profile:ifconfig"].map((e) => `ev.${e}`),
      ...TARGET_ROLES.flatMap((r) => [`scope.role.${r}`, `scope.roleHint.${r}`]),
      ...["active", "revoked", "expired"].map((x) => `scope.state.${x}`),
      ...DRAFT_ERROR_KINDS.map((k) => `scope.err.${k}`),
      ...POSITIONS.flatMap((p) => [`position.${p}`, `position.from.${p}`]),
      ...["session", "scope", "run", "findings"].flatMap((x) => [`journey.${x}`, `journey.${x}.hint`]),
      ...["done", "current", "todo"].map((x) => `journey.state.${x}`),
      ...["not_an_address", "unspecified", "loopback", "multicast", "broadcast", "link_local", "not_private"].map((r) => `scope.err.address.${r}`),
      ...["hours", "rate", "timeout_s"].map((f) => `scope.err.number.${f}`),
      ...["active_exists", "no_active_session", "store", "invalid"].map((k) => `scope.err.${k}`),
      ...["already_running", "no_active_session", "no_scope", "network_changed", "store"].map((k) => `assess.err.${k}`),
      ...CHECKS.flatMap((c) => ["title", "short", "action", "limits"].map((x) => `check.${c}.${x}`)),
      ...["pass", "fail", "warning", "inconclusive", "not_tested", "informational"].map((x) => `finding.status.${x}`),
      ...["info", "low", "medium", "high", "critical"].map((x) => `finding.severity.${x}`),
      ...["connected", "all_refused", "reset_from_listener", "silent_confirmed_listener", "silent_unconfirmed", "silent", "local_error", "denied", "stopped", "no_target"].map((x) => `finding.reason.${x}`),
      ...["tcp_accepted", "tcp_reset", "no_reply", "listener_confirmed_by_user", "login_or_auth_bypass", "access_to_management_data", "service_identity", "listener_was_running", "blocked_on_other_ports", "blocked_for_other_devices"].map((x) => `finding.claim.${x}`),
      ...["connected", "refused", "timed_out", "unreachable", "denied", "cancelled"].map((x) => `probe.outcome.${x}`),
      ...["no_grant", "revoked", "expired", "level_exceeded", "target_not_allowed", "port_not_allowed", "network_unknown", "network_changed", "address_not_allowed"].map((x) => `probe.denied.${x}`),
      ...PURPOSES.flatMap((p) => [`purpose.${p}`, `purpose.${p}.why`]),
      ...FLOW_COLUMNS.map((c) => `traffic.col.${c}`),
      ...["capture_host", "local_peer", "external_destinations"].flatMap((r) => [`explain.${r}.what`, `explain.${r}.not`]),
    ];
    for (const k of dynamic) expect(en, k).toHaveProperty([k]);
  });

  it("every retention choice can be submitted", () => {
    for (const r of RETENTION_CHOICES) expect(parseSessionForm({ ...emptyForm(), name: "x", retention: r }).ok).toBe(true);
  });

  it("product claims stay honest in both languages", () => {
    // Imported data must never be described as observed by this Mac.
    expect(en["import.banner.title"]).toMatch(/not observed by this Mac/);
    expect(vi["import.banner.title"]).toMatch(/không phải do Mac này quan sát/);
    // A reachable admin port is never described as a login (AT-08).
    expect(en["check.S01.limits"]).toMatch(/does not show that anyone can log in/);
    expect(vi["check.S01.limits"]).toMatch(/Không cho thấy ai đăng nhập được/);
    // Where the Mac stood is filled in, never assumed to be Guest Wi-Fi.
    for (const d of [en, vi]) for (const k of ["check.S01.title", "check.N01.title", "check.S01.short", "check.N03.short", "check.N01.short", "finding.claim.tcp_accepted"] as const) expect(d[k], k).toContain("{from}");
  });
});
