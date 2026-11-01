import { describe, expect, it } from "vitest";
import { RETENTION_CHOICES, emptyForm, parseSessionForm } from "./sessionForm";

describe("parseSessionForm", () => {
  it("requires a name and trims every field", () => {
    expect(parseSessionForm({ ...emptyForm(), name: "   " })).toEqual({ ok: false, errors: ["name_required"] });
    const r = parseSessionForm({ ...emptyForm(), name: "  Lobby  ", site: " Cafe ", retention: "30" });
    expect(r).toEqual({
      ok: true,
      input: { meta: { name: "Lobby", site: "Cafe", operator: "", authorization_ref: "", notes: "" }, retention_days: 30 },
    });
  });
  it("'keep' means no automatic deletion", () => {
    const r = parseSessionForm({ ...emptyForm(), name: "x", retention: "keep" });
    expect(r.ok && r.input.retention_days).toBe(null);
  });
  it("rejects retention values that are not offered", () => {
    expect(parseSessionForm({ ...emptyForm(), name: "x", retention: "3" })).toEqual({ ok: false, errors: ["retention_invalid"] });
  });
  it("limits field lengths", () => {
    const r = parseSessionForm({ ...emptyForm(), name: "n".repeat(121), notes: "x".repeat(2001) });
    expect(r).toEqual({ ok: false, errors: ["name_too_long", "notes_too_long"] });
  });
  it("defaults to 30 days, which is one of the choices", () => {
    expect(emptyForm().retention).toBe("30");
    expect(RETENTION_CHOICES).toContain("30");
    expect(RETENTION_CHOICES).toContain("keep");
  });
});
