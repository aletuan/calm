import { describe, expect, it } from "vitest";
import type { CheckResult, FindingStatus, Reason } from "./assess";
import { DETAIL_SECTIONS, todoKey } from "./findingDetail";

const result = (status: FindingStatus, reason: Reason, check: CheckResult["check"] = "S01"): CheckResult => ({
  check,
  target: "192.0.2.1",
  label: "",
  status,
  severity: "info",
  confidence: null,
  reason,
  ports: [],
  verified: [],
  unverified: [],
});

describe("finding detail", () => {
  it("always has the same six parts, in the voice guide's order", () => {
    expect(DETAIL_SECTIONS).toEqual(["saw", "shows", "notShows", "todo", "evidence", "method"]);
  });

  it.each([
    // A failed or warning result: the check's own fix.
    ["fail", "connected", "S01", "check.S01.action"],
    ["warning", "reset_from_listener", "N03", "check.N03.action"],
    ["fail", "reset_from_listener", "N01", "check.N01.action"],
    // Passed: nothing to change, re-run after changes.
    ["pass", "all_refused", "S01", "finding.todo.pass"],
    ["pass", "silent_confirmed_listener", "N01", "finding.todo.pass"],
    // Inconclusive and not tested: what would make the result conclusive.
    ["inconclusive", "silent_unconfirmed", "N01", "finding.todo.silent_unconfirmed"],
    ["inconclusive", "silent", "S01", "finding.todo.silent"],
    ["inconclusive", "local_error", "S01", "finding.todo.local_error"],
    ["not_tested", "denied", "S01", "finding.todo.denied"],
    ["not_tested", "stopped", "N03", "finding.todo.stopped"],
    ["not_tested", "no_target", "N01", "finding.todo.no_target"],
  ] as const)("%s / %s on %s → %s", (status, reason, check, key) => {
    expect(todoKey(result(status, reason, check))).toBe(key);
  });
});
