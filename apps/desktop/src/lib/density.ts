/** Table/control density (design §4). Chosen in Settings, kept across launches. */
export type Density = "comfortable" | "compact";
export const DENSITIES: Density[] = ["comfortable", "compact"];
export const DENSITY_KEY = "calm.density";

type Storage = Pick<globalThis.Storage, "getItem" | "setItem">;

const store = (): Storage | null => {
  try {
    return globalThis.localStorage ?? null;
  } catch {
    return null;
  }
};

/** The saved density, or Comfortable when nothing valid is saved or storage is unavailable. */
export function readDensity(s: Storage | null = store()): Density {
  try {
    const v = s?.getItem(DENSITY_KEY);
    return v === "compact" || v === "comfortable" ? v : "comfortable";
  } catch {
    return "comfortable";
  }
}

export function saveDensity(d: Density, s: Storage | null = store()): void {
  try {
    s?.setItem(DENSITY_KEY, d);
  } catch {
    /* not critical: the choice still applies for this launch */
  }
}

/** The tokens in tokens.css switch on this attribute. */
export function applyDensity(d: Density, root: { dataset: DOMStringMap } = document.documentElement): void {
  root.dataset.density = d;
}
