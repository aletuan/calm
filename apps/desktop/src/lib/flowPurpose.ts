import type { Flow } from "./ipc";

/**
 * What a flow is for, in plain words (Traffic "Purpose" column). Decided only
 * by protocol and well-known port — a label for orientation, not a claim about
 * the content: a port says what a service usually is, not what was sent.
 */
export const PURPOSES = [
  "dns",
  "dns_encrypted",
  "web_encrypted",
  "web_plain",
  "address_lookup",
  "dhcp",
  "discovery",
  "time",
  "network_control",
  "apple_push",
  "email",
  "remote_access",
  "vpn",
  "other",
] as const;
export type Purpose = (typeof PURPOSES)[number];

const TCP: Record<number, Purpose> = {
  53: "dns",
  853: "dns_encrypted",
  443: "web_encrypted",
  8443: "web_encrypted",
  80: "web_plain",
  8080: "web_plain",
  5223: "apple_push",
  25: "email",
  110: "email",
  143: "email",
  465: "email",
  587: "email",
  993: "email",
  995: "email",
  22: "remote_access",
  3389: "remote_access",
  5900: "remote_access",
  1194: "vpn",
};

const UDP: Record<number, Purpose> = {
  53: "dns",
  853: "dns_encrypted",
  443: "web_encrypted", // QUIC (HTTP/3), always encrypted
  67: "dhcp",
  68: "dhcp",
  546: "dhcp",
  547: "dhcp",
  123: "time",
  5353: "discovery", // mDNS / Bonjour
  1900: "discovery", // SSDP / UPnP
  5355: "discovery", // LLMNR
  137: "discovery", // NetBIOS name
  138: "discovery", // NetBIOS datagram
  3702: "discovery", // WS-Discovery
  500: "vpn",
  4500: "vpn",
  1194: "vpn",
  51820: "vpn",
};

export function flowPurpose(f: Flow): Purpose {
  const t = f.key.transport;
  if (t === "arp") return "address_lookup";
  if (t === "icmp" || t === "icmpv6") return "network_control";
  const table = t === "tcp" ? TCP : t === "udp" ? UDP : null;
  if (!table) return "other";
  // The far side's port is usually the service; if it isn't known, try ours
  // (someone connected to a service on this Mac).
  for (const p of [f.key.remote_port, f.key.local_port]) {
    if (p != null && table[p]) return table[p];
  }
  return "other";
}
