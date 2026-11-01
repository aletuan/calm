import { describe, expect, it } from "vitest";
import { autoSaveOnStop } from "./autoSave";

const ok = { enabled: true, storeReady: true, hasActive: true, packets: 10 };

describe("autoSaveOnStop", () => {
  it("saves when enabled, a session is active and something was captured", () => {
    expect(autoSaveOnStop(ok)).toEqual({ save: true });
  });
  it("says why it does not save, so the UI can tell the user", () => {
    expect(autoSaveOnStop({ ...ok, enabled: false })).toEqual({ save: false, reason: "disabled" });
    expect(autoSaveOnStop({ ...ok, storeReady: false })).toEqual({ save: false, reason: "store_closed" });
    expect(autoSaveOnStop({ ...ok, hasActive: false })).toEqual({ save: false, reason: "no_session" });
    expect(autoSaveOnStop({ ...ok, packets: 0 })).toEqual({ save: false, reason: "empty" });
  });
});
