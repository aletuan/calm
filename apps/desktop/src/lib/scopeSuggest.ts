/**
 * One-tap suggestions for the scope form, from the network this Mac is on.
 * Suggestions are offered, never filled in silently: a scope is an
 * attestation, so every address in it is one the user chose (ADR-010).
 */
import type { NetworkBinding } from "./assess";
import { checkAddress, inSubnet, v4 } from "./ipv4";
import type { ScopeForm, TargetRow } from "./scopeForm";

const num = (o: number[]) => ((o[0]! << 24) | (o[1]! << 16) | (o[2]! << 8) | o[3]!) >>> 0;
const dotted = (n: number) => [24, 16, 8, 0].map((s) => (n >>> s) & 255).join(".");
const maskOf = (prefix: number) => (prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0);

function cidr(text: string): { net: number; prefix: number } | null {
  const [a, p] = text.trim().split("/");
  const o = a ? v4(a) : null;
  if (!o || p === undefined || !/^\d{1,2}$/.test(p) || Number(p) > 32) return null;
  return { net: num(o), prefix: Number(p) };
}

/** The router as the admin interface (S01), when the gateway is a private IPv4 address. */
export function routerSuggestion(n: NetworkBinding | null): TargetRow | null {
  if (!n || !v4(n.gateway) || !checkAddress(n.gateway).ok) return null;
  return { address: n.gateway, ports: "80, 443", role: "admin_interface", label: "" };
}

/** This network as a range. Wider than /24 (the scope limit) → the /24 around the gateway. */
export function rangeSuggestion(n: NetworkBinding | null): { cidr: string; narrowed: boolean } | null {
  const s = n?.subnet ? cidr(n.subnet) : null;
  const gw = n ? v4(n.gateway) : null;
  if (!s || !gw) return null;
  const narrowed = s.prefix < 24;
  const prefix = narrowed ? 24 : s.prefix;
  const base = ((narrowed ? num(gw) : s.net) & maskOf(prefix)) >>> 0;
  if (!checkAddress(dotted(base)).ok) return null;
  return { cidr: `${dotted(base)}/${prefix}`, narrowed };
}

/**
 * Is a typed target ("192.168.1.1") or range ("192.168.1.0/24") outside this
 * Mac's subnet? null when either side cannot be read: no warning then.
 */
export function outsideNetwork(text: string, n: NetworkBinding | null): boolean | null {
  const t = text.trim();
  if (!t || !n?.subnet) return null;
  const subnet = cidr(n.subnet);
  if (!subnet) return null;
  if (t.includes("/")) {
    const r = cidr(t);
    if (!r) return null;
    return r.prefix < subnet.prefix || inSubnet(dotted(r.net), n.subnet) === false;
  }
  const inside = inSubnet(t, n.subnet);
  return inside === null ? null : !inside;
}

/** Field placeholders from this network; documentation addresses when it is unknown. */
export function placeholders(n: NetworkBinding | null): { target: string; range: string; exclusion: string } {
  const r = rangeSuggestion(n);
  const router = routerSuggestion(n);
  if (!r || !router) return { target: "192.0.2.1", range: "192.0.2.0/24", exclusion: "192.0.2.50" };
  const c = cidr(r.cidr)!;
  const size = 2 ** (32 - c.prefix);
  return { target: router.address, range: r.cidr, exclusion: dotted(c.net + (size > 51 ? 50 : Math.max(1, size - 2))) };
}

const blank = (t: { address?: string; cidr?: string; ports: string; label: string }) => !(t.address ?? t.cidr ?? "").trim() && !t.ports.trim() && !t.label.trim();

/** Put the router in the first untouched target row, or add it; never twice. */
export function withRouter(f: ScopeForm, router: TargetRow): ScopeForm {
  if (f.targets.some((t) => t.address.trim() === router.address)) return f;
  const i = f.targets.findIndex(blank);
  const targets = i >= 0 ? f.targets.map((t, j) => (j === i ? router : t)) : [...f.targets, router];
  return { ...f, targets };
}

/** Add this network's range (common ports to start from), into an untouched row if there is one; never twice. */
export function withRange(f: ScopeForm, cidr: string): ScopeForm {
  if (f.ranges.some((r) => r.cidr.trim() === cidr)) return f;
  const row = { cidr, ports: "22, 80, 443", label: "" };
  const i = f.ranges.findIndex(blank);
  return { ...f, ranges: i >= 0 ? f.ranges.map((r, j) => (j === i ? row : r)) : [...f.ranges, row] };
}
