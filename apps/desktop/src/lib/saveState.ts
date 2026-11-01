import type { Source } from "./source";

/** How long the button says "Saved" after a successful save. */
export const SAVED_FLASH_MS = 4000;

export type SaveState = "opening" | "no_session" | "viewing_saved" | "saving" | "saved" | "failed" | "ready";

/**
 * State of the "Save to session" button. Pure, so every state the user can
 * see is tested: progress while saving, a confirmation afterwards, an error
 * when it fails, and why it is disabled otherwise.
 */
export function saveUi(p: {
  storeReady: boolean;
  hasActive: boolean;
  source: Source;
  saving: boolean;
  lastSavedAt: number | null;
  failed: boolean;
  now: number;
}): { state: SaveState; disabled: boolean } {
  if (!p.storeReady) return { state: "opening", disabled: true };
  if (!p.hasActive) return { state: "no_session", disabled: true };
  if (p.source === "saved") return { state: "viewing_saved", disabled: true };
  if (p.saving) return { state: "saving", disabled: true };
  if (p.failed) return { state: "failed", disabled: false };
  if (p.lastSavedAt != null && p.now - p.lastSavedAt <= SAVED_FLASH_MS) return { state: "saved", disabled: false };
  return { state: "ready", disabled: false };
}
