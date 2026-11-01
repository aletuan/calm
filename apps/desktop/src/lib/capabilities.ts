/**
 * Capabilities a scope can allow (ADR-011), mirrored from
 * `calm_domain::Capability` and `calm_orchestrator::scope::NSE_ALLOWLIST`.
 * Keep the order and the levels in step with Rust.
 */
import type { MessageKey } from "../i18n/en";
import type { Capability } from "./assess";
import type { ScopeForm } from "./scopeForm";

export const CAPABILITIES: Capability[] = ["tcp_connect", "host_discovery", "reverse_dns", "syn_scan", "service_detection", "os_detection", "nse"];

export const NSE_ALLOWLIST = ["http-headers", "http-title", "ssh-hostkey", "ssl-cert"] as const;
export type NseScript = (typeof NSE_ALLOWLIST)[number];

const L1: Capability[] = ["tcp_connect", "host_discovery", "reverse_dns"];

export const capabilityLevel = (c: Capability): "L1" | "L2" => (L1.includes(c) ? "L1" : "L2");

/** A label inside a sentence: lower case first letter, unless it starts with an acronym ("TCP", "OS"). */
function inSentence(label: string): string {
  const first = label.split(/\s/)[0] ?? "";
  const acronym = first.length > 1 && first === first.toUpperCase() && /\p{L}/u.test(first);
  return acronym ? label : label.charAt(0).toLowerCase() + label.slice(1);
}

/** "TCP connect, SYN scan, dò máy": what the user attests to, in the canonical order. */
export function capsText(caps: Capability[], t: (k: MessageKey) => string): string {
  const ordered = CAPABILITIES.filter((c) => caps.includes(c));
  return ordered.length ? ordered.map((c) => inSentence(t(`capability.${c}` as MessageKey))).join(", ") : t("scope.noneChosen");
}

/** Tick or untick one capability. Unticking NSE drops its scripts, so the draft stays consistent. */
export function toggleCapability(f: ScopeForm, c: Capability): ScopeForm {
  const on = f.capabilities.includes(c);
  const capabilities = on ? f.capabilities.filter((x) => x !== c) : [...f.capabilities, c];
  return { ...f, capabilities, nse_scripts: c === "nse" && on ? [] : f.nse_scripts };
}
