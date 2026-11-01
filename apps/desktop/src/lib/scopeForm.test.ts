import { describe, expect, it } from "vitest";
import { draftErrorKey, draftErrorRow, emptyScopeForm, emptyTarget, parsePorts, toDraft } from "./scopeForm";

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
