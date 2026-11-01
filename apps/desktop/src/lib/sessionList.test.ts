import { describe, expect, it } from "vitest";
import type { SessionSummary } from "./ipc";
import { defaultTab, filterSessions } from "./sessionList";

const s = (id: string, name: string, site = "", operator = ""): SessionSummary => ({
  id,
  meta: { name, site, operator, authorization_ref: "", notes: "" },
  created_at_ms: 0,
  updated_at_ms: 0,
  retention_days: 30,
  snapshot_count: 0,
  stored_bytes: 0,
});
const list = [s("a", "Quán cà phê Đông", "Hà Nội", "Andy"), s("b", "Home check", "Wireless LAN at Home"), s("c", "Hotel lobby", "Đà Nẵng", "Minh")];

describe("session list", () => {
  it("opens on Current only when a session is active", () => {
    expect(defaultTab(true)).toBe("current");
    expect(defaultTab(false)).toBe("all");
  });
  it("an empty query keeps everything, in order", () => {
    expect(filterSessions(list, "  ").map((x) => x.id)).toEqual(["a", "b", "c"]);
  });
  it("matches name, site and operator, ignoring case and Vietnamese accents", () => {
    expect(filterSessions(list, "home").map((x) => x.id)).toEqual(["b"]);
    expect(filterSessions(list, "ca phe dong").map((x) => x.id)).toEqual(["a"]);
    expect(filterSessions(list, "da nang").map((x) => x.id)).toEqual(["c"]);
    expect(filterSessions(list, "MINH").map((x) => x.id)).toEqual(["c"]);
  });
  it("every word must match", () => {
    expect(filterSessions(list, "hotel andy")).toEqual([]);
    expect(filterSessions(list, "andy hà")).toHaveLength(1);
  });
});
