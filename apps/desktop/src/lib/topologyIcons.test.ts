import { describe, expect, it } from "vitest";
import { iconDataUri, relationKey, roleIcon } from "./topologyIcons";

describe("topology icons and edge labels", () => {
  it("gives every known role its own icon and anything else the unknown one", () => {
    const roles = ["this_mac", "capture_host", "access_point_radio", "default_gateway", "dns_resolver", "local_peer", "external_destinations"];
    const icons = roles.map(roleIcon);
    expect(new Set(icons).size).toBe(roles.length);
    expect(icons).not.toContain("unknown");
    expect(roleIcon(null)).toBe("unknown");
    expect(roleIcon("printer")).toBe("unknown");
  });
  it("draws the icon in the requested colour as an SVG data URI", () => {
    const uri = iconDataUri("router", "#e5e9e8");
    expect(uri.startsWith("data:image/svg+xml;utf8,")).toBe(true);
    const svg = decodeURIComponent(uri.split(",")[1]!);
    expect(svg).toContain('stroke="#e5e9e8"');
    expect(svg).toContain("<rect");
  });
  it("names each relation in plain words, never by its code", () => {
    expect(relationKey("DEFAULT_ROUTE_VIA")).toBe("relation.DEFAULT_ROUTE_VIA");
    expect(relationKey("FLOW_OBSERVED")).toBe("relation.FLOW_OBSERVED");
    expect(relationKey("SOMETHING_NEW")).toBe("relation.other");
  });
});
