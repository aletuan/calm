import { describe, expect, it } from "vitest";
import { applyDensity, DENSITY_KEY, readDensity, saveDensity } from "./density";

const mem = () => {
  const m = new Map<string, string>();
  return { getItem: (k: string) => m.get(k) ?? null, setItem: (k: string, v: string) => void m.set(k, v), m };
};

describe("density preference", () => {
  it("defaults to comfortable", () => {
    expect(readDensity(mem())).toBe("comfortable");
    expect(readDensity(null)).toBe("comfortable");
  });
  it("survives a relaunch", () => {
    const s = mem();
    saveDensity("compact", s);
    expect(s.m.get(DENSITY_KEY)).toBe("compact");
    expect(readDensity(s)).toBe("compact");
  });
  it("ignores unknown values and broken storage", () => {
    const s = mem();
    s.setItem(DENSITY_KEY, "tiny");
    expect(readDensity(s)).toBe("comfortable");
    const broken = { getItem: () => { throw new Error("denied"); }, setItem: () => { throw new Error("denied"); } };
    expect(readDensity(broken)).toBe("comfortable");
    expect(() => saveDensity("compact", broken)).not.toThrow();
  });
  it("sets the attribute the tokens switch on", () => {
    const root = { dataset: {} as DOMStringMap };
    applyDensity("compact", root);
    expect(root.dataset.density).toBe("compact");
  });
});
