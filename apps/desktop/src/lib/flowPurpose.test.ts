import { describe, expect, it } from "vitest";
import type { Flow, Transport } from "./ipc";
import { flowPurpose, PURPOSES } from "./flowPurpose";

function f(transport: Transport, remote_port: number | null, local_port: number | null = 50000, direction: Flow["direction"] = "outbound"): Flow {
  return {
    key: { transport, local: "192.0.2.108", local_port, remote: "203.0.113.1", remote_port },
    direction,
    origin: "local_interface",
    initiated_by: "unknown",
    packets_out: 1,
    packets_in: 1,
    bytes_out: 1,
    bytes_in: 1,
    first_seen_ms: 0,
    last_seen_ms: 0,
  };
}

describe("flowPurpose", () => {
  it("name lookups, plain and encrypted", () => {
    expect(flowPurpose(f("udp", 53))).toBe("dns");
    expect(flowPurpose(f("tcp", 53))).toBe("dns");
    expect(flowPurpose(f("tcp", 853))).toBe("dns_encrypted");
  });
  it("web: encrypted (TLS and QUIC) vs not encrypted", () => {
    expect(flowPurpose(f("tcp", 443))).toBe("web_encrypted");
    expect(flowPurpose(f("udp", 443))).toBe("web_encrypted");
    expect(flowPurpose(f("tcp", 80))).toBe("web_plain");
    expect(flowPurpose(f("tcp", 8080))).toBe("web_plain");
  });
  it("network housekeeping", () => {
    expect(flowPurpose(f("arp", null, null))).toBe("address_lookup");
    expect(flowPurpose(f("udp", 67, 68))).toBe("dhcp");
    expect(flowPurpose(f("udp", 547, 546))).toBe("dhcp");
    expect(flowPurpose(f("udp", 123))).toBe("time");
    expect(flowPurpose(f("icmp", null, null))).toBe("network_control");
    expect(flowPurpose(f("icmpv6", null, null))).toBe("network_control");
  });
  it("devices announcing themselves, including heard multicast", () => {
    expect(flowPurpose(f("udp", 5353, 5353, "heard"))).toBe("discovery");
    expect(flowPurpose(f("udp", 1900))).toBe("discovery");
    expect(flowPurpose(f("udp", 5355))).toBe("discovery");
    expect(flowPurpose(f("udp", 137, 137))).toBe("discovery");
  });
  it("the service port wins over the ephemeral one, on either side", () => {
    // Someone connected to this Mac's SSH: the well-known port is local.
    expect(flowPurpose(f("tcp", 51515, 22, "inbound"))).toBe("remote_access");
    expect(flowPurpose(f("tcp", 5223))).toBe("apple_push");
    expect(flowPurpose(f("udp", 51820))).toBe("vpn");
    expect(flowPurpose(f("tcp", 993))).toBe("email");
  });
  it("anything unknown is 'other', never a guess", () => {
    expect(flowPurpose(f("tcp", 40000, 50000))).toBe("other");
    expect(flowPurpose(f({ other: 47 }, null, null))).toBe("other");
    expect(flowPurpose(f("udp", 9999))).toBe("other");
  });
  it("every purpose is listed (for labels and filters)", () => {
    expect(new Set(PURPOSES).size).toBe(PURPOSES.length);
    expect(PURPOSES).toContain("other");
  });
});
