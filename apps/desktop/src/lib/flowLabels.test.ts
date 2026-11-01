import { describe, expect, it } from "vitest";
import { dirKey, localCell } from "./flowLabels";
import type { Flow } from "./ipc";

function flow(p: Partial<Flow> & { transport?: Flow["key"]["transport"] }): Flow {
  return {
    key: { transport: p.transport ?? "tcp", local: "192.0.2.108", local_port: 1, remote: "203.0.113.1", remote_port: 443 },
    direction: p.direction ?? "outbound",
    origin: p.origin ?? "local_interface",
    initiated_by: p.initiated_by ?? "unknown",
    packets_out: 1,
    packets_in: 1,
    bytes_out: 1,
    bytes_in: 1,
    first_seen_ms: 0,
    last_seen_ms: 0,
  };
}

describe("dirKey", () => {
  it("names who opened a TCP connection only when the SYN was seen", () => {
    expect(dirKey(flow({ initiated_by: "local" }), "mac")).toBe("traffic.dir.outOpened");
    expect(dirKey(flow({ initiated_by: "local" }), "host")).toBe("import.dir.outOpened");
    expect(dirKey(flow({ initiated_by: "remote", direction: "inbound" }), "mac")).toBe("traffic.dir.inOpened");
    expect(dirKey(flow({}), "mac")).toBe("traffic.dir.out");
    expect(dirKey(flow({ direction: "inbound" }), "host")).toBe("traffic.dir.in");
  });
  it("UDP and ICMP have no opener", () => {
    expect(dirKey(flow({ transport: "udp" }), "mac")).toBe("traffic.dir.outPlain");
    expect(dirKey(flow({ transport: "icmp", direction: "inbound" }), "mac")).toBe("traffic.dir.inPlain");
  });
  it("heard wins over everything", () => {
    expect(dirKey(flow({ direction: "heard", initiated_by: "local", origin: "local_broadcast" }), "mac")).toBe("traffic.dir.heard");
  });
  it("heard unicast to another address is not called broadcast", () => {
    // The Origin column was dropped: Direction alone must keep this distinction.
    expect(dirKey(flow({ direction: "heard", origin: "local_interface" }), "mac")).toBe("traffic.dir.heardUnicast");
    expect(dirKey(flow({ direction: "heard", origin: "local_broadcast" }), "mac")).toBe("traffic.dir.heard");
  });
  it("imported heard flows: broadcast or not is decided by the destination", () => {
    const f = flow({ direction: "heard", origin: "imported" });
    expect(dirKey({ ...f, key: { ...f.key, local: "224.0.0.251" } }, "host")).toBe("traffic.dir.heard");
    expect(dirKey({ ...f, key: { ...f.key, local: "ff02::fb" } }, "host")).toBe("traffic.dir.heard");
    expect(dirKey({ ...f, key: { ...f.key, local: "192.0.2.9" } }, "host")).toBe("traffic.dir.heardUnicast");
    expect(dirKey({ ...f, key: { ...f.key, local: "192.0.2.9", transport: "arp" } }, "host")).toBe("traffic.dir.heard");
  });
});

describe("localCell (the Local column)", () => {
  const withKey = (f: Flow, k: Partial<Flow["key"]>): Flow => ({ ...f, key: { ...f.key, ...k } });
  it("a heard ARP request names the address being asked about", () => {
    const f = withKey(flow({ transport: "arp", direction: "heard", origin: "local_broadcast" }), { local: "192.168.68.101", local_port: null });
    expect(localCell(f)).toEqual({ prefix: "traffic.local.askedAbout", value: "192.168.68.101" });
  });
  it("other heard traffic shows the address it was sent to", () => {
    const f = withKey(flow({ transport: "udp", direction: "heard", origin: "local_broadcast" }), { local: "224.0.0.251", local_port: 5353 });
    expect(localCell(f)).toEqual({ prefix: null, value: "224.0.0.251" });
  });
  it("this Mac's own flows show its port, or a dash when there is none", () => {
    expect(localCell(flow({}))).toEqual({ prefix: null, value: ":1" });
    expect(localCell(withKey(flow({ transport: "arp", direction: "inbound" }), { local_port: null }))).toEqual({ prefix: null, value: "—" });
  });
});
