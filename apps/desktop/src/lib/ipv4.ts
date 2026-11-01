/**
 * IPv4 address rules shared by the scope form and the browser preview.
 * Ports of `calm_orchestrator::scope` (check_address, parse_range, in_subnet):
 * keep them in step with Rust.
 */
import type { AddressReason } from "./assess";

export function v4(text: string): number[] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text);
  if (!m) return null;
  const o = m.slice(1).map(Number);
  return o.every((x) => x <= 255) ? o : null;
}

/** Same policy as `check_address`: private IPv4, 100.64/10, IPv6 ULA. */
export function checkAddress(raw: string): { ok: true; address: string } | { ok: false; reason: AddressReason } {
  const text = raw.trim();
  const o = v4(text);
  if (o) {
    const a = o[0]!;
    const b = o[1]!;
    if (o.every((x) => x === 0)) return { ok: false, reason: "unspecified" };
    if (a === 127) return { ok: false, reason: "loopback" };
    if (a >= 224 && a <= 239) return { ok: false, reason: "multicast" };
    if (o.every((x) => x === 255)) return { ok: false, reason: "broadcast" };
    if (a === 169 && b === 254) return { ok: false, reason: "link_local" };
    const priv = a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
    return priv ? { ok: true, address: o.join(".") } : { ok: false, reason: "not_private" };
  }
  if (!/^[0-9a-fA-F:]+$/.test(text) || !text.includes(":")) return { ok: false, reason: "not_an_address" };
  const lower = text.toLowerCase();
  if (lower === "::") return { ok: false, reason: "unspecified" };
  if (lower === "::1") return { ok: false, reason: "loopback" };
  if (lower.startsWith("ff")) return { ok: false, reason: "multicast" };
  if (/^fe[89ab]/.test(lower)) return { ok: false, reason: "link_local" };
  if (/^f[cd]/.test(lower)) return { ok: true, address: lower };
  return { ok: false, reason: "not_private" };
}

/** Port of `parse_range`: a private IPv4 network address, prefix ≤ 32, canonical. */
export function parseRange(cidr: string): { net: string; prefix: number } | null {
  const [net, prefixText] = cidr.trim().split("/");
  const o = net ? v4(net) : null;
  if (!o || prefixText === undefined || !/^\d{1,2}$/.test(prefixText)) return null;
  const prefix = Number(prefixText);
  if (prefix > 32) return null;
  const n = ((o[0]! << 24) | (o[1]! << 16) | (o[2]! << 8) | o[3]!) >>> 0;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  if (((n & mask) >>> 0) !== n || !checkAddress(net!).ok) return null;
  return { net: o.join("."), prefix };
}

/** Port of `in_subnet`: null when either side cannot be read or the target is IPv6. */
export function inSubnet(address: string, subnet: string): boolean | null {
  const ip = v4(address);
  const [net, prefixText] = subnet.split("/");
  const n = net ? v4(net) : null;
  if (!ip || !n || prefixText === undefined || !/^\d{1,2}$/.test(prefixText)) return null;
  const prefix = Number(prefixText);
  if (prefix > 32) return null;
  const num = (o: number[]) => ((o[0]! << 24) | (o[1]! << 16) | (o[2]! << 8) | o[3]!) >>> 0;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return ((num(ip) & mask) >>> 0) === ((num(n) & mask) >>> 0);
}
