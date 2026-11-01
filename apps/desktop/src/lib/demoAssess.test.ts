import { describe, expect, it } from "vitest";
import type { ProbeOutcome, ScopeDraft } from "./assess";
import { checkAddress, DemoAssess, evaluateTarget, inSubnet, parseRange, planOf, validateDraft, DEMO_NETWORK } from "./demoAssess";

const NOW = 1_800_000_000_000;

const draft = (over: Partial<ScopeDraft> = {}): ScopeDraft => ({
  authorization_reference: "ROE",
  operator: "A",
  granted_by: "O",
  targets: [
    { address: "192.168.1.1", ports: [443, 80], role: "admin_interface", label: "router" },
    { address: "10.0.0.9", ports: [9999], role: "cooperative_receiver", label: "" },
  ],
  expires_at_ms: NOW + 3_600_000,
  max_probes_per_second: 5,
  timeout_ms: 3000,
  authorization_confirmed: true,
  vantage: "main",
  ...over,
});

/** Runs scheduled callbacks synchronously, in order. */
function queue() {
  const q: (() => void)[] = [];
  return {
    timer: (f: () => void) => void q.push(f),
    drain: () => {
      while (q.length) q.shift()!();
    },
  };
}

describe("demo address policy mirrors the shell", () => {
  it.each([
    ["10.1.2.3", true],
    ["172.16.0.1", true],
    ["172.32.0.1", false],
    ["100.64.0.1", true],
    ["192.0.2.10", false],
    ["8.8.8.8", false],
    ["fd00::a", true],
    ["fe80::1", false],
    ["127.0.0.1", false],
    ["router.local", false],
    ["192.168.1.0/24", false],
  ])("%s → %s", (a, ok) => {
    expect(checkAddress(a).ok).toBe(ok);
  });
});

describe("demo validation", () => {
  it("accepts a good draft and lists every problem of a bad one", () => {
    expect(validateDraft(draft(), NOW, DEMO_NETWORK)).toEqual([]);
    const e = validateDraft(draft({ authorization_confirmed: false, targets: [], timeout_ms: 100 }), NOW, null).map((x) => x.kind);
    expect(e).toEqual(["not_confirmed", "no_targets", "timeout_out_of_range", "network_unknown"]);
  });
});

describe("demo validation of capabilities, ranges and scripts (same as Rust approve, ADR-011)", () => {
  const kinds = (over: Partial<ScopeDraft>) => validateDraft(draft(over), NOW, DEMO_NETWORK).map((x) => x.kind);
  const range = (cidr: string, ports = [80]) => ({ cidr, ports, label: "" });

  it("a draft without the new fields is TCP connect only, as before", () => {
    expect(kinds({})).toEqual([]);
    expect(kinds({ capabilities: [] })).toEqual(["no_capabilities"]);
  });

  it.each([
    ["192.168.68.0/24", null],
    ["10.20.0.0/28", null],
    ["100.64.1.0/24", null],
    ["192.168.68.0/23", "range_too_large"],
    ["8.8.8.0/24", "bad_range"],
    ["192.168.68.7/24", "bad_range"],
    ["fd00::/120", "bad_range"],
    ["192.168.68.0", "bad_range"],
    ["192.168.68.0/33", "bad_range"],
  ])("range %s → %s", (cidr, want) => {
    const e = kinds({ ranges: [range(cidr)], exclusions: ["192.168.68.50"] });
    expect(e).toEqual(want ? [want] : []);
  });

  it("ranges need valid ports and exclusions; exclusions must be addresses", () => {
    expect(kinds({ ranges: [range("192.168.68.0/24")] })).toEqual(["exclusions_required"]);
    expect(kinds({ ranges: [range("192.168.68.0/24", [])], exclusions: ["192.168.68.50"] })).toEqual(["bad_range_ports"]);
    expect(kinds({ ranges: [range("192.168.68.0/24", [0])], exclusions: ["192.168.68.50"] })).toEqual(["bad_range_ports"]);
    expect(kinds({ ranges: [range("192.168.68.0/24")], exclusions: ["router"] })).toEqual(["bad_exclusion"]);
    expect(kinds({ targets: [], ranges: [range("10.20.0.0/28")], exclusions: ["10.20.0.1"] })).toEqual([]);
  });

  it("discovery needs a range; NSE needs allowlisted scripts and scripts need NSE", () => {
    expect(kinds({ capabilities: ["host_discovery"] })).toEqual(["host_discovery_needs_range"]);
    expect(kinds({ nse_scripts: ["http-title"] })).toEqual(["scripts_need_nse"]);
    expect(kinds({ capabilities: ["nse"], nse_scripts: [] })).toEqual(["nse_needs_scripts"]);
    expect(kinds({ capabilities: ["nse"], nse_scripts: ["smb-brute"] })).toEqual(["script_not_allowed"]);
    expect(kinds({ capabilities: ["nse"], nse_scripts: ["http-title"] })).toEqual([]);
  });

  it("parseRange is the port of parse_range", () => {
    expect(parseRange("192.168.68.0/24")).toEqual({ net: "192.168.68.0", prefix: 24 });
    expect(parseRange("192.168.68.1/24")).toBeNull();
    expect(parseRange("1.1.1.0/24")).toBeNull();
  });

  it("an approved demo scope keeps the capabilities and the highest level", () => {
    const d = new DemoAssess(() => NOW, () => "s1", (f) => f());
    const v = d.approve(draft({ capabilities: ["syn_scan", "tcp_connect"], ranges: [range("192.168.1.0/24")], exclusions: [" 192.168.1.50 "] }));
    expect(v.scope.capabilities).toEqual(["tcp_connect", "syn_scan"]);
    expect(v.scope.max_level).toBe("L2");
    expect(v.scope.ranges).toEqual([{ cidr: "192.168.1.0/24", ports: [80], label: "" }]);
    expect(v.scope.exclusions).toEqual(["192.168.1.50"]);
  });
});

describe("demo decision table (same as Rust)", () => {
  const o = (kind: string): ProbeOutcome => (kind === "connected" || kind === "refused" ? ({ kind, rtt_ms: 1 } as ProbeOutcome) : ({ kind } as ProbeOutcome));
  it.each([
    ["S01", ["connected"], false, "fail", "connected"],
    ["S01", ["refused", "refused"], false, "pass", "all_refused"],
    ["S01", ["timed_out"], true, "inconclusive", "silent"],
    ["N01", ["timed_out"], false, "inconclusive", "silent_unconfirmed"],
    ["N01", ["timed_out"], true, "pass", "silent_confirmed_listener"],
    ["N01", ["refused"], true, "fail", "reset_from_listener"],
    ["N03", ["refused"], true, "warning", "reset_from_listener"],
    ["S01", ["refused", "cancelled"], false, "not_tested", "stopped"],
    ["S01", ["refused", "denied"], false, "not_tested", "denied"],
  ] as const)("%s %j confirmed=%s → %s", (check, kinds, confirmed, status, reason) => {
    const ports = kinds.map((k, i) => ({ port: i + 1, outcome: k === "denied" ? ({ kind: "denied", reason: { kind: "expired" } } as ProbeOutcome) : o(k) }));
    const r = evaluateTarget(check, ports, confirmed);
    expect([r.status, r.reason]).toEqual([status, reason]);
    expect(r.confidence === null).toBe(status === "not_tested");
    if (check === "S01" && status === "fail") expect(r.unverified).toContain("login_or_auth_bypass");
  });
});

describe("network position", () => {
  it("is required: the user must say where the Mac is", () => {
    expect(validateDraft(draft({ vantage: null }), NOW, DEMO_NETWORK)).toEqual([{ kind: "vantage_required" }]);
    expect(validateDraft(draft({ vantage: "unknown" }), NOW, DEMO_NETWORK)).toEqual([]);
  });
});

describe("subnet check mirrors in_subnet", () => {
  it.each([
    ["192.168.68.20", "192.168.68.0/24", true],
    ["192.168.1.1", "192.168.68.0/24", false],
    ["192.168.69.4", "192.168.68.0/22", true],
    ["192.168.72.4", "192.168.68.0/22", false],
    ["10.1.2.3", "0.0.0.0/0", true],
    ["10.0.0.1", "10.0.0.1/32", true],
    ["10.0.0.2", "10.0.0.1/32", false],
    ["fd00::1", "192.168.68.0/24", null],
    ["192.168.68.2", "192.168.68.0", null],
    ["192.168.68.2", "192.168.68.0/33", null],
  ] as const)("%s in %s → %s", (a, n, want) => expect(inSubnet(a, n)).toBe(want));

  it("marks plan items outside the bound subnet", () => {
    const d = new DemoAssess(() => NOW, () => "s1");
    d.approve(draft({ targets: [{ address: "192.168.0.7", ports: [80], role: "admin_interface", label: "" }, { address: "192.168.1.1", ports: [443], role: "admin_interface", label: "" }] }));
    expect(d.preflight().plan.map((p) => p.outside_subnet)).toEqual([false, true]);
  });
});

describe("DemoAssess", () => {
  it("needs a session, keeps one usable scope, revokes", () => {
    let sid: string | null = null;
    const d = new DemoAssess(() => NOW, () => sid);
    expect(() => d.approve(draft())).toThrow();
    sid = "s1";
    const v = d.approve(draft());
    expect(v.scope.targets[0]?.ports).toEqual([80, 443]);
    expect(() => d.approve(draft())).toThrowError();
    try {
      d.approve(draft());
    } catch (e) {
      expect(e).toEqual({ kind: "active_exists" });
    }
    d.revoke(v.scope.id);
    expect(d.current()).toBeNull();
    expect(d.list()[0]?.revoked).toBe(true);
  });

  it("without TCP connect in the scope, every probe of the checks is refused (as authorize)", () => {
    const q = queue();
    const d = new DemoAssess(() => NOW, () => "s1", q.timer);
    d.approve(draft({ capabilities: ["syn_scan"] }));
    d.run(true);
    q.drain();
    const run = d.runs()[0]!.run;
    expect(run.probes.every((p) => p.record.outcome.kind === "denied")).toBe(true);
    expect(run.probes[0]!.record.outcome).toEqual({ kind: "denied", reason: { kind: "capability_not_granted" } });
    expect(run.results.find((r) => r.check === "S01")?.reason).toBe("denied");
  });

  it("runs the plan, stores results, and the stop cancels the rest", () => {
    const q = queue();
    const d = new DemoAssess(() => NOW, () => "s1", q.timer);
    d.approve(draft());
    expect(planOf(d.current()!.scope).map((p) => `${p.check}:${p.port}`)).toEqual(["S01:80", "S01:443", "N01:9999"]);
    const p = d.run(true);
    expect(p.running).toBe(true);
    expect(() => d.run(true)).toThrow();
    q.drain();
    const done = d.status()!;
    expect(done.running).toBe(false);
    expect(done.done).toBe(3);
    const results = d.runs()[0]!.run.results;
    expect(results.find((r) => r.check === "S01")?.status).toBe("fail");
    expect(results.find((r) => r.check === "N01")?.status).toBe("pass");
    expect(results.find((r) => r.check === "N03")?.reason).toBe("no_target");
    expect(results.find((r) => r.check === "N03")?.confidence).toBeNull();
    expect(d.runs()[0]!.run.vantage).toBe("main");

    d.run(false);
    d.stop();
    q.drain();
    const stopped = d.runs()[0]!.run;
    expect(stopped.stopped).toBe(true);
    expect(stopped.probes.every((p) => p.record.outcome.kind === "cancelled")).toBe(true);
    expect(stopped.results.find((r) => r.check === "S01")?.reason).toBe("stopped");
  });

  it("preflight is not ready without a scope", () => {
    const d = new DemoAssess(() => NOW, () => "s1");
    expect(d.preflight().ready).toBe(false);
    d.approve(draft());
    const p = d.preflight();
    expect(p.ready).toBe(true);
    expect(p.plan).toHaveLength(3);
    expect(p.min_seconds).toBe(1);
  });
});
