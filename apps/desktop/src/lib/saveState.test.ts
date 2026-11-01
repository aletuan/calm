import { describe, expect, it } from "vitest";
import { SAVED_FLASH_MS, saveUi } from "./saveState";

const base = { storeReady: true, hasActive: true, source: "live" as const, saving: false, lastSavedAt: null, failed: false, now: 10_000 };

describe("saveUi", () => {
  it("ready to save this Mac or an imported file", () => {
    expect(saveUi(base)).toEqual({ state: "ready", disabled: false });
    expect(saveUi({ ...base, source: "imported" })).toEqual({ state: "ready", disabled: false });
  });
  it("needs an open store and an active session", () => {
    expect(saveUi({ ...base, storeReady: false })).toEqual({ state: "opening", disabled: true });
    expect(saveUi({ ...base, hasActive: false })).toEqual({ state: "no_session", disabled: true });
  });
  it("a saved snapshot cannot be saved again", () => {
    expect(saveUi({ ...base, source: "saved" })).toEqual({ state: "viewing_saved", disabled: true });
  });
  it("shows progress, then a short confirmation", () => {
    expect(saveUi({ ...base, saving: true })).toEqual({ state: "saving", disabled: true });
    expect(saveUi({ ...base, lastSavedAt: 9_000 })).toEqual({ state: "saved", disabled: false });
    expect(saveUi({ ...base, lastSavedAt: 10_000 - SAVED_FLASH_MS - 1 })).toEqual({ state: "ready", disabled: false });
  });
  it("a failure wins over an older confirmation", () => {
    expect(saveUi({ ...base, lastSavedAt: 9_999, failed: true })).toEqual({ state: "failed", disabled: false });
  });
});
