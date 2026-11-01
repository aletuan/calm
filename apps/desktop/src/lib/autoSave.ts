export type AutoSaveDecision = { save: true } | { save: false; reason: "disabled" | "store_closed" | "no_session" | "empty" };

/** Whether stopping a capture should also save a snapshot to the active session. */
export function autoSaveOnStop(p: { enabled: boolean; storeReady: boolean; hasActive: boolean; packets: number }): AutoSaveDecision {
  if (!p.enabled) return { save: false, reason: "disabled" };
  if (!p.storeReady) return { save: false, reason: "store_closed" };
  if (!p.hasActive) return { save: false, reason: "no_session" };
  if (p.packets <= 0) return { save: false, reason: "empty" };
  return { save: true };
}
