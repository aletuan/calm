import { describe, expect, it } from "vitest";
import type { GraphSnapshot, ImportView, RecordedView } from "./ipc";
import { resolveSource, toSourceRef, sameSource } from "./source";

const G = (n: string): GraphSnapshot => ({ nodes: [{ id: n, observed_identifiers: [], role_hypothesis: null, epistemic_status: "observed", confidence: "high", evidence_refs: [] }], edges: [] });
const imp = { file_name: "f.pcapng", graph: G("imported") } as unknown as ImportView;
const savedImport = { snapshot: { label: "s", kind: "import" }, live: null, import: { file_name: "old.pcapng", graph: G("saved-import") } } as unknown as RecordedView;
const savedLive = { snapshot: { label: "l", kind: "live" }, live: { graph: G("saved-live"), profile: {}, capture: null }, import: null } as unknown as RecordedView;

describe("resolveSource", () => {
  it("live by default", () => {
    const r = resolveSource("live", G("live"), imp, savedLive);
    expect(r.kind).toBe("live");
    expect(r.graph?.nodes[0]!.id).toBe("live");
  });
  it("imported only when an import exists", () => {
    expect(resolveSource("imported", G("live"), imp, null).graph?.nodes[0]!.id).toBe("imported");
    expect(resolveSource("imported", G("live"), null, null).kind).toBe("live");
  });
  it("saved snapshots resolve by their kind", () => {
    const a = resolveSource("saved", G("live"), imp, savedImport);
    expect(a.kind).toBe("saved_import");
    expect(a.graph?.nodes[0]!.id).toBe("saved-import");
    expect(a.importView?.file_name).toBe("old.pcapng");
    const b = resolveSource("saved", G("live"), imp, savedLive);
    expect(b.kind).toBe("saved_live");
    expect(b.graph?.nodes[0]!.id).toBe("saved-live");
  });
  it("falls back to live when the saved snapshot is gone", () => {
    expect(resolveSource("saved", G("live"), imp, null).kind).toBe("live");
  });
  it("only live data may be refreshed or extended with the traffic toggle", () => {
    expect(resolveSource("live", null, null, null).isLive).toBe(true);
    expect(resolveSource("saved", null, null, savedLive).isLive).toBe(false);
    expect(resolveSource("imported", null, imp, null).isLive).toBe(false);
  });
  it("the centre perspective is this Mac only for live and saved-live data", () => {
    expect(resolveSource("live", null, null, null).perspective).toBe("mac");
    expect(resolveSource("saved", null, null, savedLive).perspective).toBe("mac");
    expect(resolveSource("saved", null, null, savedImport).perspective).toBe("host");
    expect(resolveSource("imported", null, imp, null).perspective).toBe("host");
  });
});

describe("toSourceRef", () => {
  it("names the data the backend should read", () => {
    expect(toSourceRef(resolveSource("live", null, null, null), null)).toEqual({ kind: "live" });
    expect(toSourceRef(resolveSource("imported", null, imp, null), null)).toEqual({ kind: "imported" });
    const saved = { ...savedImport, snapshot: { ...savedImport.snapshot, id: "s1" } } as RecordedView;
    expect(toSourceRef(resolveSource("saved", null, null, saved), saved)).toEqual({ kind: "saved", snapshot_id: "s1" });
  });
});

describe("sameSource (a node filter belongs to the data it was made from)", () => {
  it("live and imported match themselves only", () => {
    expect(sameSource({ kind: "live" }, { kind: "live" })).toBe(true);
    expect(sameSource({ kind: "imported" }, { kind: "imported" })).toBe(true);
    expect(sameSource({ kind: "live" }, { kind: "imported" })).toBe(false);
  });
  it("saved snapshots must be the same snapshot", () => {
    expect(sameSource({ kind: "saved", snapshot_id: "a" }, { kind: "saved", snapshot_id: "a" })).toBe(true);
    expect(sameSource({ kind: "saved", snapshot_id: "a" }, { kind: "saved", snapshot_id: "b" })).toBe(false);
    expect(sameSource({ kind: "saved", snapshot_id: "a" }, { kind: "live" })).toBe(false);
  });
});
