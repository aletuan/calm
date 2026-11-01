import { describe, expect, it } from "vitest";
import type { NetworkBinding } from "./assess";
import { emptyScopeForm, emptyTarget } from "./scopeForm";
import { outsideNetwork, placeholders, rangeSuggestion, routerSuggestion, withRange, withRouter } from "./scopeSuggest";

const net = (gateway: string, subnet: string | null): NetworkBinding => ({ gateway, subnet, ssid: null });
const home = net("192.168.68.1", "192.168.68.0/24");

describe("router suggestion", () => {
  it("is this network's gateway as the admin interface on 80 and 443", () => {
    expect(routerSuggestion(home)).toEqual({ address: "192.168.68.1", ports: "80, 443", role: "admin_interface", label: "" });
  });

  it("is offered only for a known, private gateway", () => {
    expect(routerSuggestion(null)).toBeNull();
    expect(routerSuggestion(net("8.8.8.8", null))).toBeNull();
    expect(routerSuggestion(net("fe80::1", null))).toBeNull();
  });
});

describe("range suggestion", () => {
  it("is the subnet itself when it is /24 or smaller", () => {
    expect(rangeSuggestion(home)).toEqual({ cidr: "192.168.68.0/24", narrowed: false });
    expect(rangeSuggestion(net("10.0.0.1", "10.0.0.0/28"))).toEqual({ cidr: "10.0.0.0/28", narrowed: false });
  });

  it("narrows a wider subnet to the /24 around the gateway, and says so", () => {
    expect(rangeSuggestion(net("192.168.69.1", "192.168.68.0/22"))).toEqual({ cidr: "192.168.69.0/24", narrowed: true });
  });

  it("is not offered without a readable private subnet", () => {
    expect(rangeSuggestion(null)).toBeNull();
    expect(rangeSuggestion(net("192.168.68.1", null))).toBeNull();
    expect(rangeSuggestion(net("192.168.68.1", "nonsense"))).toBeNull();
    expect(rangeSuggestion(net("1.2.3.1", "1.2.3.0/24"))).toBeNull();
  });
});

describe("outside the network this Mac is on", () => {
  it.each([
    ["192.168.68.20", false],
    ["192.168.1.1", true],
    ["192.168.68.0/24", false],
    ["192.168.68.128/25", false],
    ["192.168.1.0/24", true],
    ["192.168.68.0/23", true], // wider than this network
    ["", null],
    ["printer", null],
    ["fd00::1", null],
  ])("%s → %s", (text, want) => {
    expect(outsideNetwork(text, home)).toBe(want);
  });

  it("cannot tell without a subnet", () => {
    expect(outsideNetwork("192.168.1.1", net("192.168.68.1", null))).toBeNull();
    expect(outsideNetwork("192.168.1.1", null)).toBeNull();
  });
});

describe("placeholders", () => {
  it("show this network's own addresses, not a fixed example", () => {
    expect(placeholders(home)).toEqual({ target: "192.168.68.1", range: "192.168.68.0/24", exclusion: "192.168.68.50" });
  });

  it("fall back to documentation addresses when the network is unknown", () => {
    expect(placeholders(null)).toEqual({ target: "192.0.2.1", range: "192.0.2.0/24", exclusion: "192.0.2.50" });
  });
});

describe("applying a suggestion", () => {
  const router = routerSuggestion(home)!;

  it("fills the untouched first target row, or adds a row, never a duplicate", () => {
    const f1 = withRouter(emptyScopeForm(), router);
    expect(f1.targets).toEqual([router]);
    const f2 = withRouter({ ...emptyScopeForm(), targets: [{ ...emptyTarget(), address: "192.168.68.9", ports: "22" }] }, router);
    expect(f2.targets.map((t) => t.address)).toEqual(["192.168.68.9", "192.168.68.1"]);
    expect(withRouter(f1, router).targets).toHaveLength(1);
  });

  it("adds the range once and keeps other ranges", () => {
    const f1 = withRange(emptyScopeForm(), "192.168.68.0/24");
    expect(f1.ranges).toEqual([{ cidr: "192.168.68.0/24", ports: "22, 80, 443", label: "" }]);
    expect(withRange(f1, "192.168.68.0/24").ranges).toHaveLength(1);
    expect(withRange({ ...f1, ranges: [{ cidr: "", ports: "", label: "" }] }, "192.168.68.0/24").ranges).toEqual(f1.ranges);
  });
});
