import type { MessageKey } from "../i18n/en";

/**
 * Role icons and edge labels for the topology view. Icons are small line
 * drawings (24 × 24, stroke only) so they read at a glance and stay
 * monochrome: the line style of edges still carries the epistemic status.
 */

export type IconName = "laptop" | "capture" | "wifi" | "router" | "server" | "device" | "cloud" | "unknown";

const ROLE_ICON: Record<string, IconName> = {
  this_mac: "laptop",
  capture_host: "capture",
  access_point_radio: "wifi",
  default_gateway: "router",
  dns_resolver: "server",
  local_peer: "device",
  external_destinations: "cloud",
};

export const roleIcon = (role: string | null | undefined): IconName => ROLE_ICON[role ?? ""] ?? "unknown";

const PATHS: Record<IconName, string> = {
  laptop: '<rect x="4" y="5" width="16" height="11" rx="1.5"/><path d="M2 19h20"/>',
  capture: '<path d="M6 3h8l4 4v14H6z"/><path d="M14 3v4h4"/><path d="M8 14h2l1.5-3 2 6 1.5-3h1"/>',
  wifi: '<path d="M2.5 9a14 14 0 0 1 19 0"/><path d="M5.5 12.5a9.5 9.5 0 0 1 13 0"/><path d="M8.5 16a5 5 0 0 1 7 0"/><circle cx="12" cy="19.5" r="1" fill="currentColor"/>',
  router: '<rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 13V8"/><path d="M17 13V8"/><path d="M7 16.5h.01"/><path d="M10.5 16.5h.01"/><path d="M15 16.5h3"/>',
  server: '<rect x="4" y="4" width="16" height="7" rx="1.5"/><rect x="4" y="13" width="16" height="7" rx="1.5"/><path d="M8 7.5h.01"/><path d="M8 16.5h.01"/><path d="M12 7.5h5"/><path d="M12 16.5h5"/>',
  device: '<rect x="3" y="4" width="18" height="12" rx="1.5"/><path d="M9 20h6"/><path d="M12 16v4"/>',
  cloud: '<path d="M7 18h10.5a4 4 0 0 0 .6-7.95A6 6 0 0 0 6.6 9.6 4.25 4.25 0 0 0 7 18z"/>',
  unknown: '<circle cx="12" cy="12" r="9"/><path d="M9.6 9.5a2.5 2.5 0 0 1 4.8 1c0 1.7-2.4 2-2.4 3.5"/><path d="M12 17h.01"/>',
};

/** A data URI Cytoscape can use as a node background image, drawn in `color`. */
export function iconDataUri(name: IconName, color: string): string {
  const svg =
    `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" ` +
    `stroke="${color}" color="${color}" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">${PATHS[name]}</svg>`;
  return `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;
}

/** Plain-language name of a relation, shown on every edge. */
export const relationKey = (relation: string): MessageKey =>
  (["ASSOCIATED_WITH", "DEFAULT_ROUTE_VIA", "RESOLVES_VIA", "FLOW_OBSERVED"].includes(relation) ? `relation.${relation}` : "relation.other") as MessageKey;
