import { beforeEach, describe, expect, it } from "vitest";
import { DemoStore } from "./demoStore";

const meta = (name: string) => ({ name, site: "", operator: "", authorization_ref: "", notes: "" });
const DAY = 86_400_000;

/** Errors mirror the Rust `StoreError` sent over IPC: `{ kind }` objects. */
function errorKind(f: () => unknown): string | undefined {
  try {
    f();
  } catch (e) {
    return (e as { kind?: string }).kind;
  }
  return undefined;
}

describe("DemoStore (browser preview mirrors calm-store semantics)", () => {
  let s: DemoStore;
  let now: number;
  beforeEach(() => {
    now = 1_000_000;
    s = new DemoStore(() => now);
  });

  it("creating a session makes it active; newest first", () => {
    const a = s.create({ meta: meta("a"), retention_days: 30 });
    now += 1;
    const b = s.create({ meta: meta("b"), retention_days: null });
    expect(s.active()?.id).toBe(b.id);
    expect(s.list().map((x) => x.meta.name)).toEqual(["b", "a"]);
    expect(a.id).not.toBe(b.id);
  });

  it("saving needs an active session and touches it", () => {
    expect(errorKind(() => s.save("live", "x", {}))).toBe("not_found");
    const a = s.create({ meta: meta("a"), retention_days: 1 });
    now += 10;
    const snap = s.save("live", "x", { a: 1 });
    expect(s.get(a.id).updated_at_ms).toBe(now);
    expect(s.get(a.id).snapshot_count).toBe(1);
    expect(s.snapshots(a.id)[0]!.id).toBe(snap.id);
    expect(s.open(snap.id).payload).toEqual({ a: 1 });
  });

  it("deleting the active session clears it and removes its snapshots", () => {
    const a = s.create({ meta: meta("a"), retention_days: null });
    const snap = s.save("import", "f", {});
    s.remove(a.id);
    expect(s.active()).toBeNull();
    expect(errorKind(() => s.open(snap.id))).toBe("not_found");
    expect(errorKind(() => s.remove(a.id))).toBe("not_found");
  });

  it("retention purges sessions idle for longer than their period", () => {
    s.create({ meta: meta("short"), retention_days: 1 });
    s.create({ meta: meta("keep"), retention_days: null });
    now += DAY + 1;
    expect(s.purge()).toBe(1);
    expect(s.list().map((x) => x.meta.name)).toEqual(["keep"]);
  });

  it("deleting one snapshot keeps the others", () => {
    s.create({ meta: meta("a"), retention_days: null });
    const x = s.save("live", "x", 1);
    const y = s.save("live", "y", 2);
    s.removeSnapshot(x.id);
    expect(s.snapshots(s.active()!.id).map((v) => v.id)).toEqual([y.id]);
  });

  it("activate rejects unknown sessions and accepts null", () => {
    expect(errorKind(() => s.activate("nope"))).toBe("not_found");
    s.create({ meta: meta("a"), retention_days: null });
    s.activate(null);
    expect(s.active()).toBeNull();
  });
});
