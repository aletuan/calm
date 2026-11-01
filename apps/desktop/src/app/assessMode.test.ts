import { describe, expect, it } from "vitest";
import { assessMode } from "./assessMode";

describe("assessMode", () => {
  it("running wins, then an approved scope, else passive", () => {
    expect(assessMode(true, true)).toBe("running");
    expect(assessMode(true, false)).toBe("running");
    expect(assessMode(false, true)).toBe("scoped");
    expect(assessMode(false, false)).toBe("passive");
  });
});
