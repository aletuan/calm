import { describe, expect, it } from "vitest";
import type { CheckResult, Progress, StoredRun } from "./assess";
import { confidenceText, countByStatus, finishedSummary, fromText, latest, outcomeText, resultId, sortResults } from "./findingsView";

const r = (check: CheckResult["check"], status: CheckResult["status"], severity: CheckResult["severity"] = "info", target: string | null = "10.0.0.1"): CheckResult => ({
  check,
  target,
  label: "",
  status,
  severity,
  confidence: "high",
  reason: "connected",
  ports: [],
  verified: [],
  unverified: [],
});

describe("findings view", () => {
  it("puts failures first, then by severity", () => {
    const sorted = sortResults([r("N01", "pass"), r("S01", "fail", "medium"), r("N03", "fail", "high"), r("N01", "not_tested", "info", null), r("S01", "inconclusive")]);
    expect(sorted.map((x) => `${x.check}:${x.status}`)).toEqual(["N03:fail", "S01:fail", "S01:inconclusive", "N01:not_tested", "N01:pass"]);
  });
  it("counts by status", () => {
    const c = countByStatus([r("S01", "fail"), r("N03", "fail"), r("N01", "pass")]);
    expect(c.fail).toBe(2);
    expect(c.pass).toBe(1);
    expect(c.warning).toBe(0);
  });
  it("ids are unique per check and target", () => {
    expect(resultId(r("S01", "fail"))).not.toBe(resultId(r("N03", "fail")));
    expect(resultId(r("N01", "not_tested", "info", null))).toBe("N01|-");
  });
  it("describes probe outcomes with their detail", () => {
    const t = (k: string) => k.split(".").pop()!;
    expect(outcomeText({ kind: "connected", rtt_ms: 4 }, t)).toBe("connected · 4 ms");
    expect(outcomeText({ kind: "denied", reason: { kind: "network_changed" } }, t)).toBe("denied: network_changed");
    expect(outcomeText({ kind: "unreachable", detail: "host_unreachable" }, t)).toBe("unreachable (host_unreachable)");
    expect(outcomeText({ kind: "timed_out" }, t)).toBe("timed_out");
  });
  it("latest run by start time", () => {
    const run = (id: string, at: number): StoredRun => ({ snapshot_id: id, run: { id, scope_id: "s", started_at_ms: at, finished_at_ms: at, stopped: false, receiver_confirmed: false, vantage: "unknown", probes: [], results: [] } });
    expect(latest([])).toBeNull();
    expect(latest([run("a", 1), run("b", 3), run("c", 2)])?.snapshot_id).toBe("b");
  });
  it("shows no confidence for what was not tested, even in older stored runs", () => {
    const t = (k: string) => k;
    expect(confidenceText(r("S01", "fail"), t as never)).toBe("confidence.high");
    expect(confidenceText(r("N01", "not_tested", "info", null), t as never)).toBe("—");
    expect(confidenceText({ ...r("S01", "inconclusive"), confidence: null }, t as never)).toBe("—");
  });
  it("names where the Mac stood", () => {
    const dict: Record<string, string> = { k: "reachable from {from}", "position.from.guest": "Guest Wi-Fi", "position.from.unknown": "this network" };
    const t = (k: string) => dict[k] ?? k;
    expect(fromText("k" as never, "guest", t as never)).toBe("reachable from Guest Wi-Fi");
    expect(fromText("k" as never, undefined, t as never)).toBe("reachable from this network");
  });
  it("rebuilds the run summary when coming back to the screen", () => {
    const stored: StoredRun = { snapshot_id: "f1", run: { id: "r", scope_id: "s", started_at_ms: 1, finished_at_ms: 2, stopped: false, receiver_confirmed: false, vantage: "main", probes: [], results: [r("S01", "fail"), r("N01", "not_tested", "info", null)] } };
    const p = (over: Partial<Progress>): Progress => ({ run_id: "r", running: false, done: 2, total: 2, last: null, stopped: false, started_at_ms: 1, error: null, snapshot_id: "f1", ...over });
    expect(finishedSummary(p({}), [stored])?.fail).toBe(1);
    expect(finishedSummary(p({ running: true }), [stored])).toBeNull();
    expect(finishedSummary(p({ snapshot_id: null }), [stored])).toBeNull();
    expect(finishedSummary(p({ snapshot_id: "gone" }), [stored])).toBeNull();
    expect(finishedSummary(null, [stored])).toBeNull();
  });
});
