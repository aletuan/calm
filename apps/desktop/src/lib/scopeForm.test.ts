import { describe, expect, it } from "vitest";
import { draftErrorKey, draftErrorRangeRow, draftErrorRow, emptyScopeForm, emptyTarget, exclusionList, parsePorts, toDraft } from "./scopeForm";

const NOW = 1_800_000_000_000;

describe("parsePorts", () => {
  it("reads lists separated by commas, spaces or semicolons", () => {
    expect(parsePorts("80, 443 8443;8080")).toEqual([80, 443, 8443, 8080]);
    expect(parsePorts(" 443 ,443 ")).toEqual([443]);
    expect(parsePorts("")).toEqual([]);
  });
  it("rejects anything that is not a port number", () => {
    for (const bad of ["0", "65536", "80-90", "http", "4.5", "-1", "123456"]) expect(parsePorts(bad), bad).toBeNull();
    expect(parsePorts("65535")).toEqual([65535]);
  });
});

describe("toDraft", () => {
  const filled = () => ({
    ...emptyScopeForm("Andy"),
    authorization_reference: "ROE-1",
    granted_by: "Owner",
    confirmed: true,
    targets: [{ ...emptyTarget(), address: " 192.168.68.1 ", ports: "443, 80" }],
  });
  it("converts hours, rate and timeout and keeps the text for the shell", () => {
    const r = toDraft(filled(), NOW);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.draft.expires_at_ms).toBe(NOW + 4 * 3_600_000);
    expect(r.draft.max_probes_per_second).toBe(5);
    expect(r.draft.timeout_ms).toBe(3000);
    expect(r.draft.targets[0]).toEqual({ address: "192.168.68.1", ports: [443, 80], role: "admin_interface", label: "" });
    expect(r.draft.authorization_confirmed).toBe(true);
    expect(r.draft.vantage).toBeNull();
    const g = toDraft({ ...filled(), vantage: "guest" }, NOW);
    expect(g.ok && g.draft.vantage).toBe("guest");
  });
  it("reports text it cannot read, by row and field", () => {
    const f = { ...filled(), hours: "four", targets: [{ ...emptyTarget(), ports: "443" }, { ...emptyTarget(), ports: "http" }] };
    const r = toDraft(f, NOW);
    expect(r).toEqual({ ok: false, problems: [{ kind: "number_text", field: "hours" }, { kind: "port_text", index: 1 }] });
  });
  it("leaves real validation to the shell (empty fields still make a draft)", () => {
    const r = toDraft(emptyScopeForm(), NOW);
    expect(r.ok).toBe(true);
  });
});

describe("draft errors", () => {
  it("map to message keys and rows", () => {
    expect(draftErrorKey({ kind: "bad_address", index: 1, reason: "not_private" })).toBe("scope.err.address.not_private");
    expect(draftErrorKey({ kind: "not_confirmed" })).toBe("scope.err.not_confirmed");
    expect(draftErrorRow({ kind: "no_ports", index: 2 })).toBe(2);
    expect(draftErrorRow({ kind: "no_targets" })).toBeNull();
  });

  it("only target errors belong to a target row; a range or exclusion index is another list", () => {
    expect(draftErrorRow({ kind: "bad_address", index: 1, reason: "not_private" })).toBe(1);
    expect(draftErrorRow({ kind: "bad_range", index: 0 })).toBeNull();
    expect(draftErrorRow({ kind: "range_too_large", index: 0 })).toBeNull();
    expect(draftErrorRow({ kind: "bad_range_ports", index: 0 })).toBeNull();
    expect(draftErrorRow({ kind: "bad_exclusion", index: 0 })).toBeNull();
    expect(draftErrorRow({ kind: "script_not_allowed", index: 0 })).toBeNull();
  });
});

describe("ranges, exclusions and capabilities in the draft (ADR-011)", () => {
  const filled = () => ({
    ...emptyScopeForm("Andy"),
    authorization_reference: "R",
    granted_by: "O",
    targets: [{ address: "192.168.1.1", ports: "443", role: "admin_interface" as const, label: "" }],
  });

  it("an untouched form asks for TCP connect only, with no ranges", () => {
    const r = toDraft(filled(), 0);
    if (!r.ok) throw new Error("draft");
    expect(r.draft.capabilities).toEqual(["tcp_connect"]);
    expect(r.draft.ranges).toEqual([]);
    expect(r.draft.exclusions).toEqual([]);
    expect(r.draft.nse_scripts).toEqual([]);
  });

  it("carries ranges with their ports and splits exclusions on lines, commas or spaces", () => {
    const f = { ...filled(), ranges: [{ cidr: " 192.168.1.0/24 ", ports: "22, 80", label: "shop" }], exclusions: "192.168.1.50\n192.168.1.51, 192.168.1.52  " };
    const r = toDraft(f, 0);
    if (!r.ok) throw new Error("draft");
    expect(r.draft.ranges).toEqual([{ cidr: "192.168.1.0/24", ports: [22, 80], label: "shop" }]);
    expect(r.draft.exclusions).toEqual(["192.168.1.50", "192.168.1.51", "192.168.1.52"]);
  });

  it("reports range ports it cannot read, by range row", () => {
    const f = { ...filled(), ranges: [{ cidr: "192.168.1.0/24", ports: "80, x", label: "" }] };
    expect(toDraft(f, 0)).toEqual({ ok: false, problems: [{ kind: "range_port_text", index: 0 }] });
  });

  it("range errors belong to range rows, not target rows", () => {
    expect(draftErrorRangeRow({ kind: "bad_range", index: 1 })).toBe(1);
    expect(draftErrorRangeRow({ kind: "range_too_large", index: 0 })).toBe(0);
    expect(draftErrorRangeRow({ kind: "bad_range_ports", index: 2 })).toBe(2);
    expect(draftErrorRangeRow({ kind: "bad_address", index: 0, reason: "not_private" })).toBeNull();
    expect(draftErrorRangeRow({ kind: "bad_exclusion", index: 0 })).toBeNull();
  });
});

describe("a scope with ranges only (bug: the empty target row was sent)", () => {
  const rangesOnly = () => ({
    ...emptyScopeForm("Andy"),
    authorization_reference: "R",
    granted_by: "O",
    ranges: [{ cidr: "192.168.1.0/24", ports: "80", label: "" }],
    exclusions: "192.168.1.50",
  });

  it("an untouched target row is left out of the draft", () => {
    const r = toDraft(rangesOnly(), 0);
    if (!r.ok) throw new Error("draft");
    expect(r.draft.targets).toEqual([]);
    expect(r.targetRows).toEqual([]);
  });

  it("a row with anything typed in it is still sent, and errors map back to form rows", () => {
    const f = {
      ...rangesOnly(),
      targets: [emptyTarget(), { address: "192.168.1.9", ports: "443", role: "other" as const, label: "" }],
    };
    const r = toDraft(f, 0);
    if (!r.ok) throw new Error("draft");
    expect(r.draft.targets.map((t) => t.address)).toEqual(["192.168.1.9"]);
    expect(r.targetRows).toEqual([1]);
    // An error on draft target 0 belongs to form row 1.
    expect(draftErrorRow({ kind: "no_ports", index: 0 }, r.targetRows)).toBe(1);
  });

  it("exclusions are split the same way for the draft and for naming a bad entry", () => {
    expect(exclusionList(" 192.168.1.50\n192.168.1.50/32, printer.local ")).toEqual(["192.168.1.50", "192.168.1.50/32", "printer.local"]);
  });
});

describe("nothing to exclude", () => {
  it("is sent with the draft, and starts unticked", () => {
    const base = { ...emptyScopeForm("Andy"), authorization_reference: "R", granted_by: "O", ranges: [{ cidr: "192.168.1.0/24", ports: "80", label: "" }] };
    expect(base.nothing_to_exclude).toBe(false);
    const r = toDraft({ ...base, nothing_to_exclude: true }, 0);
    if (!r.ok) throw new Error("draft");
    expect(r.draft.nothing_to_exclude).toBe(true);
    expect(r.draft.exclusions).toEqual([]);
  });
});

