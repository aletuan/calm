import { describe, expect, it } from "vitest";
import { FLOW_COLUMNS, parseHidden, toggleColumn, visibleColumns } from "./columns";

describe("flow table columns", () => {
  it("everything is visible by default, in a fixed order", () => {
    expect(visibleColumns([])).toEqual(FLOW_COLUMNS);
    expect(FLOW_COLUMNS[0]).toBe("proto");
    expect(FLOW_COLUMNS).toContain("purpose");
  });
  it("hides and shows a column", () => {
    const h = toggleColumn([], "local");
    expect(h).toEqual(["local"]);
    expect(visibleColumns(h)).not.toContain("local");
    expect(toggleColumn(h, "local")).toEqual([]);
  });
  it("never hides the last visible column", () => {
    const allButBytes = FLOW_COLUMNS.filter((c) => c !== "bytes");
    expect(toggleColumn(allButBytes, "bytes")).toEqual(allButBytes);
  });
  it("reads stored choices defensively", () => {
    expect(parseHidden(null)).toEqual([]);
    expect(parseHidden("not json")).toEqual([]);
    expect(parseHidden('{"a":1}')).toEqual([]);
    expect(parseHidden('["local","nope","local"]')).toEqual(["local"]);
    // A stored set that hides everything falls back to all visible.
    expect(parseHidden(JSON.stringify(FLOW_COLUMNS))).toEqual([]);
  });
});
