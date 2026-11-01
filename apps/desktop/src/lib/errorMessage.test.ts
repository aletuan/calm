import { describe, expect, it } from "vitest";
import { importErrorMessage, saveErrorDetail, storeErrorMessage } from "./errorMessage";

describe("error messages", () => {
  it("each store error maps to its own sentence, with raw details kept out of it", () => {
    expect(storeErrorMessage({ kind: "key_mismatch" })).toEqual({ key: "store.err.keyMismatch" });
    expect(storeErrorMessage({ kind: "not_found" })).toEqual({ key: "store.err.notFound" });
    expect(storeErrorMessage({ kind: "unsupported_schema", detail: 7 })).toEqual({ key: "store.err.schema", detail: "schema 7" });
    expect(storeErrorMessage({ kind: "key_unavailable", detail: "errSecAuthFailed" })).toEqual({ key: "store.err.keyUnavailable", detail: "errSecAuthFailed" });
    for (const kind of ["db", "io", "corrupt"] as const) expect(storeErrorMessage({ kind, detail: "x" })).toEqual({ key: "store.err.other", detail: "x" });
  });

  it("import errors say nothing was imported; sizes go to the detail line", () => {
    expect(importErrorMessage({ kind: "not_a_capture" })).toEqual({ key: "import.err.notCapture" });
    expect(importErrorMessage({ kind: "too_large", size_bytes: 3 * 1024 ** 3, limit_bytes: 2 * 1024 ** 3 })).toEqual({ key: "import.err.tooLarge", detail: "3.00 GB > 2.00 GB" });
    expect(importErrorMessage({ kind: "unreadable", detail: "permission denied" })).toEqual({ key: "import.err.unreadable", detail: "permission denied" });
  });

  it("a cancelled import is not an error", () => {
    expect(importErrorMessage({ kind: "cancelled" })).toBeNull();
  });

  it("a failed save shows the cause as a detail, or the error kind when there is none", () => {
    expect(saveErrorDetail({ kind: "db", detail: "disk full" })).toBe("disk full");
    expect(saveErrorDetail({ kind: "key_mismatch" })).toBe("key_mismatch");
  });
});
