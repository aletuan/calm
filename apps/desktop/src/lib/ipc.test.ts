import { describe, expect, it } from "vitest";
import {
  captureProbe,
  captureStart,
  captureStop,
  captureView,
  getAppInfo,
  getLocationStatus,
  getNetworkOverview,
  importClear,
  importPick,
  importView,
  requestLocation,
  sessionActivate,
  sessionCreate,
  sessionDelete,
  sessionList,
  snapshotDelete,
  snapshotList,
  snapshotOpen,
  snapshotSaveImport,
  snapshotSaveLive,
  storeOpen,
  storeSetAside,
  type GraphSnapshot,
} from "./ipc";
import { isGroup } from "./format";

/** Invariants every graph must keep (ADR-003), including the preview data. */
function checkGraph(g: GraphSnapshot) {
  const ids = new Set(g.nodes.map((n) => n.id));
  expect(ids.size).toBe(g.nodes.length);
  for (const e of g.edges) {
    expect(ids.has(e.source), e.source).toBe(true);
    expect(ids.has(e.target), e.target).toBe(true);
    expect(e.evidence_ids.length).toBeGreaterThan(0);
  }
  const role = (r: string) => g.nodes.filter((n) => n.role_hypothesis === r).map((n) => n.id);
  for (const ap of role("access_point_radio"))
    for (const gw of role("default_gateway"))
      expect(g.edges.some((e) => (e.source === ap && e.target === gw) || (e.source === gw && e.target === ap))).toBe(false);
  for (const n of g.nodes) for (const i of n.observed_identifiers) if (i.kind.startsWith("ip")) expect(isGroup(i.value), i.value).toBe(false);
}

describe("browser preview fallbacks", () => {
  it("app is passive and preview data is labelled as demo", async () => {
    const info = await getAppInfo();
    expect(info.mode).toBe("passive");
    expect(info.activeScanningEnabled).toBe(false);
    expect(await getLocationStatus()).toBe("unavailable");
    expect(await requestLocation()).toBe(false);
    const o = await getNetworkOverview();
    expect(o.profile.demo).toBe(true);
    checkGraph(o.graph);
  });

  it("demo capture lifecycle", async () => {
    expect((await captureProbe()).availability.state).toBe("ready");
    expect(await captureView()).toBeNull();
    const v = await captureStart();
    expect(v.running).toBe(true);
    expect(v.demo).toBe(true);
    expect((await captureView())?.running).toBe(true);
    const s = await captureStop();
    expect(s?.running).toBe(false);
    expect(await captureView()).toBeNull();
    expect(v.snapshot.flows.every((f) => f.origin !== "imported")).toBe(true);
  });

  it("demo import mirrors the fixture and keeps imported provenance", async () => {
    expect(await importView()).toBeNull();
    const v = await importPick();
    checkGraph(v.graph);
    expect(v.snapshot.flows.every((f) => f.origin === "imported")).toBe(true);
    const host = v.graph.nodes.find((n) => n.id === "capture-host")!;
    expect(host.epistemic_status).toBe("inferred");
    expect(v.graph.nodes.some((n) => n.role_hypothesis === "this_mac")).toBe(false);
    expect(v.graph.nodes.flatMap((n) => n.observed_identifiers).every((i) => i.source === "imported_sensor")).toBe(true);
    expect(await importView()).toEqual(v);
    await importClear();
    expect(await importView()).toBeNull();
  });

  it("storage round trip through the preview store", async () => {
    const st = await storeOpen();
    expect(st.state).toBe("ready");
    expect((await storeSetAside()).state).toBe("ready");
    const s = await sessionCreate({ meta: { name: "p", site: "", operator: "", authorization_ref: "", notes: "" }, retention_days: 7 });
    expect((await storeOpen()).active_session?.id).toBe(s.id);
    await expect(snapshotSaveImport()).rejects.toEqual({ kind: "not_found" });
    const live = await snapshotSaveLive();
    // An earlier test stopped a capture, which (as in the app) stays saveable.
    expect(live.label).toMatch(/^This Mac — /);
    await importPick();
    const imp = await snapshotSaveImport("mine");
    expect(imp.label).toBe("mine");
    expect((await snapshotList(s.id)).map((x) => x.kind).sort()).toEqual(["import", "live"]);
    const ol = await snapshotOpen(live.id);
    expect(ol.live?.graph.nodes.length).toBeGreaterThan(0);
    expect(ol.import).toBeNull();
    const oi = await snapshotOpen(imp.id);
    expect(oi.import?.file_name).toBe("guest-sample.pcapng");
    await snapshotDelete(live.id);
    expect(await snapshotList(s.id)).toHaveLength(1);
    expect(await sessionActivate(null)).toBeNull();
    await sessionDelete(s.id);
    expect(await sessionList()).toEqual([]);
    await importClear();
  });
});

describe("preview capture after stop", () => {
  it("a stopped capture is still saved with its flows (as in the app)", async () => {
    await storeOpen();
    await sessionCreate({ meta: { name: "q", site: "", operator: "", authorization_ref: "", notes: "" }, retention_days: null });
    await captureStart();
    await captureStop();
    const s = await snapshotSaveLive();
    expect(s.label).toMatch(/flows?, \d\d:\d\d capture$/);
  });
});
