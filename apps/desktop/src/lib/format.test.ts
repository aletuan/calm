import { describe, expect, it } from "vitest";
import { endpoint, fmtBytes, fmtDuration, fmtLocal, fmtLocalTime, fmtUtc, isGroup, shortHash, transportName } from "./format";

describe("fmtBytes", () => {
  it.each([
    [0, "0 B"],
    [1023, "1023 B"],
    [1024, "1.0 KB"],
    [1536, "1.5 KB"],
    [1024 ** 2, "1.0 MB"],
    [5 * 1024 ** 3, "5.00 GB"],
  ])("%d → %s", (n, s) => expect(fmtBytes(n)).toBe(s));
});

describe("fmtDuration", () => {
  it("pads minutes and seconds", () => expect(fmtDuration(59_030)).toBe("00:59"));
  it("keeps counting minutes past an hour", () => expect(fmtDuration(3_725_000)).toBe("62:05"));
  it("never shows negative time", () => expect(fmtDuration(-5)).toBe("00:00"));
});

describe("endpoint", () => {
  it("brackets IPv6 with a port (RFC 3986)", () => expect(endpoint("2001:db8::1", 443)).toBe("[2001:db8::1]:443"));
  it("keeps IPv4 plain", () => expect(endpoint("192.0.2.1", 53)).toBe("192.0.2.1:53"));
  it("shows a bare address without a port", () => {
    expect(endpoint("fe80::1", null)).toBe("fe80::1");
    expect(endpoint("192.0.2.1", null)).toBe("192.0.2.1");
  });
  it("port 0 is still a port", () => expect(endpoint("192.0.2.1", 0)).toBe("192.0.2.1:0"));
});

describe("isGroup", () => {
  it.each([
    ["224.0.0.251", true],
    ["239.255.255.250", true],
    ["255.255.255.255", true],
    ["192.0.2.255", true],
    ["ff02::fb", true],
    ["FF02::1", true],
    ["192.0.2.1", false],
    ["223.255.255.1", false],
    ["240.0.0.1", false],
    ["fe80::1", false],
  ])("%s → %s", (ip, g) => expect(isGroup(ip)).toBe(g));
});

describe("misc", () => {
  it("transport names", () => {
    expect(transportName("tcp")).toBe("TCP");
    expect(transportName({ other: 47 })).toBe("IP/47");
  });
  it("short hash keeps both ends", () => {
    const h = "a".repeat(12) + "b".repeat(46) + "cdef01";
    expect(shortHash(h)).toBe(`${"a".repeat(12)}…cdef01`);
    expect(shortHash("short")).toBe("short");
  });
  it("UTC timestamps", () => expect(fmtUtc(1_793_437_200_000)).toBe("2026-10-31 09:00:00 UTC"));
});

/** Runs `f` with the process time zone set to `tz` (Node reads TZ on each use). */
function withTZ(tz: string, f: () => void) {
  const env = (globalThis as unknown as { process: { env: Record<string, string | undefined> } }).process.env;
  const prev = env.TZ;
  env.TZ = tz;
  try {
    f();
  } finally {
    env.TZ = prev;
  }
}

describe("fmtLocal", () => {
  it("shows the Mac's local time with its UTC offset", () => {
    withTZ("Asia/Saigon", () => expect(fmtLocal(1_793_437_200_000)).toBe("2026-10-31 16:00:00 (UTC+7)"));
  });
  it("handles negative and half-hour offsets", () => {
    withTZ("America/New_York", () => expect(fmtLocal(1_793_437_200_000)).toBe("2026-10-31 05:00:00 (UTC−4)"));
    withTZ("Asia/Kolkata", () => expect(fmtLocal(1_793_437_200_000)).toBe("2026-10-31 14:30:00 (UTC+5:30)"));
  });
  it("time of day only", () => {
    withTZ("UTC", () => expect(fmtLocalTime(1_793_437_200_000)).toBe("09:00:00"));
  });
});
