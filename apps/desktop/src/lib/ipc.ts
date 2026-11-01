import { invoke, isTauri } from "@tauri-apps/api/core";

/** Mirrors `calm_desktop_lib::AppInfo`. */
export interface AppInfo {
  name: string;
  version: string;
  identifier: string;
  schemaVersion: string;
  mode: "passive";
  activeScanningEnabled: boolean;
}

export type EpistemicStatus = "observed" | "validated" | "inferred" | "unverified";
export type LocationAuthorization = "not_determined" | "restricted" | "denied" | "authorized" | "unavailable";

/** Mirrors `calm_domain::Sourced<T>`. `value: null` means not known — never "absent". */
export interface Sourced<T> {
  value: T | null;
  source: string;
  status: EpistemicStatus;
  note: string | null;
}

export interface IpAddress {
  address: string;
  prefix: number | null;
  flags: string[];
}

export interface WifiInfo {
  interface: Sourced<string>;
  ssid: Sourced<string>;
  bssid: Sourced<string>;
  channel: Sourced<number>;
  band: Sourced<string>;
  channel_width: Sourced<string>;
  rssi_dbm: Sourced<number>;
  noise_dbm: Sourced<number>;
  security: Sourced<string>;
  phy_mode: Sourced<string>;
  tx_rate_mbps: Sourced<number>;
  country_code: Sourced<string>;
}

/** Mirrors `calm_domain::NetworkProfile`. */
export interface NetworkProfile {
  schema_version: string;
  observed_at: string;
  location_authorization: LocationAuthorization;
  bundled_app: boolean;
  wifi: WifiInfo;
  hardware_address: Sourced<string>;
  /** Inferred from the IEEE 802 U/L bit (macOS Private Wi-Fi Address). */
  hardware_address_private: Sourced<boolean>;
  ipv4: Sourced<IpAddress[]>;
  ipv6: Sourced<IpAddress[]>;
  ipv6_scope: Sourced<"global" | "unique_local" | "link_local_only">;
  default_gateway: Sourced<string>;
  default_route_interface: Sourced<string>;
  dns_servers: Sourced<string[]>;
  /** Set only by the browser-preview fallback. */
  demo?: boolean;
}

export type RelationType =
  | "ASSOCIATED_WITH"
  | "DEFAULT_ROUTE_VIA"
  | "RESOLVES_VIA"
  | "CONNECTIVITY_CONFIRMED"
  | "FLOW_OBSERVED"
  | "POSSIBLE_MEMBERSHIP"
  | "AFFECTED_BY";
export type Confidence = "low" | "medium" | "high";

/** Mirrors `calm_domain::ObservedIdentifier`. */
export interface ObservedIdentifier {
  kind: string;
  value: string;
  source: string;
  seen_at: string;
}

/** Mirrors `calm_domain::Asset`. */
export interface Asset {
  id: string;
  observed_identifiers: ObservedIdentifier[];
  role_hypothesis: string | null;
  epistemic_status: EpistemicStatus;
  confidence: Confidence;
  evidence_refs: string[];
}

/** Mirrors `calm_domain::TopologyEdge`. */
export interface TopologyEdge {
  source: string;
  target: string;
  relation_type: RelationType;
  epistemic_status: EpistemicStatus;
  confidence: Confidence;
  evidence_ids: string[];
}

export interface GraphSnapshot {
  nodes: Asset[];
  edges: TopologyEdge[];
}

export interface NetworkOverview {
  profile: NetworkProfile;
  graph: GraphSnapshot;
}

export const inTauri = () => isTauri();

const browserFallback: AppInfo = {
  name: "Calm (browser preview)",
  version: "0.1.0",
  identifier: "com.aletuan.calm",
  schemaVersion: "calm-v1alpha1",
  mode: "passive",
  activeScanningEnabled: false,
};

export async function getAppInfo(): Promise<AppInfo> {
  if (!isTauri()) return browserFallback;
  return invoke<AppInfo>("app_info");
}

export async function getLocationStatus(): Promise<LocationAuthorization> {
  if (!isTauri()) return "unavailable";
  return invoke<LocationAuthorization>("location_status");
}

export async function requestLocation(): Promise<boolean> {
  if (!isTauri()) return false;
  return invoke<boolean>("request_location");
}

export async function getNetworkOverview(): Promise<NetworkOverview> {
  if (!isTauri()) return demoOverview();
  return invoke<NetworkOverview>("network_overview");
}

// ---- Browser preview only: clearly labelled sample data (design §6) ----
const o = <T,>(value: T, source: string): Sourced<T> => ({ value, source, status: "observed", note: null });
const u = <T,>(source: string, note: string): Sourced<T> => ({ value: null, source, status: "unverified", note });
const inf = <T,>(value: T, source: string, note: string): Sourced<T> => ({ value, source, status: "inferred", note });

function demoProfile(): NetworkProfile {
  return {
    schema_version: "calm-v1alpha1",
    observed_at: new Date().toISOString(),
    location_authorization: "not_determined",
    bundled_app: false,
    demo: true,
    wifi: {
      interface: o("en0", "corewlan"),
      ssid: u("corewlan", "location_permission_not_granted"),
      bssid: u("corewlan", "location_permission_not_granted"),
      channel: o(4, "corewlan"),
      band: o("2.4 GHz", "corewlan"),
      channel_width: o("20 MHz", "corewlan"),
      rssi_dbm: o(-72, "corewlan"),
      noise_dbm: o(-89, "corewlan"),
      security: o("WPA2 Personal", "corewlan"),
      phy_mode: o("802.11n", "corewlan"),
      tx_rate_mbps: o(43, "corewlan"),
      country_code: o("VN", "corewlan"),
    },
    hardware_address: o("9e:65:00:11:22:33", "ifconfig en0"),
    hardware_address_private: inf(true, "IEEE 802 U/L bit", "locally_administered"),
    ipv4: o([{ address: "192.0.2.108", prefix: 24, flags: [] }], "ifconfig en0"),
    ipv6: o([{ address: "fe80::186c:5366:825e:7217", prefix: 64, flags: ["secured"] }], "ifconfig en0"),
    ipv6_scope: o("link_local_only", "ifconfig en0"),
    default_gateway: o("192.0.2.1", "route -n get default"),
    default_route_interface: o("en0", "route -n get default"),
    dns_servers: o(["198.51.100.53", "192.0.2.1"], "scutil --dns"),
  };
}

function demoOverview(): NetworkOverview {
  const profile = demoProfile();
  const t = profile.observed_at;
  const id = (kind: string, value: string): ObservedIdentifier => ({ kind, value, source: "observed_by_mac", seen_at: t });
  const e = (target: string, relation_type: RelationType, ev: string): TopologyEdge => ({
    source: "this-mac",
    target,
    relation_type,
    epistemic_status: "observed",
    confidence: "high",
    evidence_ids: [ev],
  });
  // Sample traffic-derived elements (shown when "Show traffic" is on).
  const peer = (ip: string): Asset => ({
    id: `ip:${ip}`,
    observed_identifiers: [id("ip", ip)],
    role_hypothesis: "local_peer",
    epistemic_status: "observed",
    confidence: "high",
    evidence_refs: ["capture:flows"],
  });
  const flowPeers = ["192.0.2.50", "192.0.2.77", "fe80::4a5:8b81:c881:1026", "fe80::8d1:74eb:7fa9:2b6"].map(peer);
  const fe = (source: string, target: string): TopologyEdge => ({
    source,
    target,
    relation_type: "FLOW_OBSERVED",
    epistemic_status: "observed",
    confidence: "high",
    evidence_ids: ["capture:flows"],
  });
  const flowEdges: TopologyEdge[] = [
    fe("this-mac", "ip:192.0.2.1"),
    fe("ip:192.0.2.1", "this-mac"),
    fe("this-mac", "external"),
    fe("external", "this-mac"),
    fe("ip:192.0.2.50", "this-mac"),
    fe("this-mac", "ip:192.0.2.77"),
    fe("ip:192.0.2.77", "this-mac"),
    fe("this-mac", "ip:fe80::4a5:8b81:c881:1026"),
    fe("ip:fe80::8d1:74eb:7fa9:2b6", "this-mac"),
  ];
  return {
    profile,
    graph: {
      nodes: [
        ...flowPeers,
        {
          id: "external",
          observed_identifiers: [id("distinct_destinations", "28")],
          role_hypothesis: "external_destinations",
          epistemic_status: "observed",
          confidence: "high",
          evidence_refs: ["capture:flows"],
        },
        {
          id: "this-mac",
          observed_identifiers: [id("mac_address_private", "9e:65:00:11:22:33"), id("ipv4", "192.0.2.108")],
          role_hypothesis: "this_mac",
          epistemic_status: "observed",
          confidence: "high",
          evidence_refs: ["profile:ifconfig"],
        },
        {
          id: "ap:unidentified",
          observed_identifiers: [],
          role_hypothesis: "access_point_radio",
          epistemic_status: "unverified",
          confidence: "low",
          evidence_refs: ["profile:corewlan"],
        },
        {
          id: "ip:192.0.2.1",
          observed_identifiers: [id("ipv4", "192.0.2.1")],
          role_hypothesis: "default_gateway",
          epistemic_status: "observed",
          confidence: "high",
          evidence_refs: ["profile:route", "profile:scutil-dns"],
        },
        {
          id: "ip:198.51.100.53",
          observed_identifiers: [id("ip", "198.51.100.53")],
          role_hypothesis: "dns_resolver",
          epistemic_status: "observed",
          confidence: "high",
          evidence_refs: ["profile:scutil-dns"],
        },
      ],
      edges: [
        e("ap:unidentified", "ASSOCIATED_WITH", "profile:corewlan"),
        e("ip:192.0.2.1", "DEFAULT_ROUTE_VIA", "profile:route"),
        e("ip:198.51.100.53", "RESOLVES_VIA", "profile:scutil-dns"),
        e("ip:192.0.2.1", "RESOLVES_VIA", "profile:scutil-dns"),
        ...flowEdges,
      ],
    },
  };
}

// ---- Capture (M1.3) ----

export type Availability =
  | { state: "ready" }
  | { state: "permission_denied"; detail: string }
  | { state: "no_interface"; detail: string }
  | { state: "error"; detail: string };

export interface CaptureProbe {
  interface: string | null;
  availability: Availability;
}

export type Transport = "tcp" | "udp" | "icmp" | "icmpv6" | "arp" | { other: number };

export interface Flow {
  key: { transport: Transport; local: string; local_port: number | null; remote: string; remote_port: number | null };
  direction: "outbound" | "inbound" | "heard";
  origin: "local_interface" | "local_broadcast" | "imported";
  initiated_by: "local" | "remote" | "unknown";
  packets_out: number;
  packets_in: number;
  bytes_out: number;
  bytes_in: number;
  first_seen_ms: number;
  last_seen_ms: number;
}

export interface SeriesPoint {
  t: number;
  bytes_in: number;
  bytes_out: number;
  packets: number;
}

export interface CaptureView {
  running: boolean;
  interface: string;
  started_at_ms: number;
  elapsed_ms: number;
  snaplen: number;
  stats: { received: number; dropped: number; if_dropped: number; error: string | null };
  snapshot: {
    flows: Flow[];
    total_flows: number;
    total_packets: number;
    total_bytes: number;
    evicted_flows: number;
    unparsed_frames: number;
    series: SeriesPoint[];
    /** Per-minute sums for seconds older than the per-second window (long captures). */
    series_minutes?: SeriesPoint[];
    dropped_minutes?: number;
  };
  /** Browser preview only. */
  demo?: boolean;
}

let demoStart: number | null = null;
/** Like the app, a stopped capture keeps its flows until the next start. */
let demoLast: CaptureView | null = null;

export async function captureProbe(): Promise<CaptureProbe> {
  if (!isTauri()) return { interface: "en0", availability: { state: "ready" } };
  return invoke<CaptureProbe>("capture_probe");
}

export async function captureStart(): Promise<CaptureView> {
  if (!isTauri()) {
    demoStart = Date.now();
    return demoCapture(true);
  }
  return invoke<CaptureView>("capture_start");
}

export async function captureStop(): Promise<CaptureView | null> {
  if (!isTauri()) {
    const v = demoCapture(false);
    demoStart = null;
    demoLast = v;
    return v;
  }
  return invoke<CaptureView | null>("capture_stop");
}

export async function captureView(): Promise<CaptureView | null> {
  if (!isTauri()) return demoStart ? demoCapture(true) : null;
  return invoke<CaptureView | null>("capture_view");
}

function demoCapture(running: boolean): CaptureView {
  const now = Date.now();
  const start = demoStart ?? now;
  const secs = Math.max(1, Math.floor((now - start) / 1000)) + 90;
  const series: SeriesPoint[] = Array.from({ length: Math.min(secs, 120) }, (_, i) => {
    const t = Math.floor(now / 1000) - (Math.min(secs, 120) - 1 - i);
    // One large burst every ~90 s, so the preview shows the cut axis (▲).
    const wave = 1 + Math.sin(t / 7) * 0.6 + (t % 23 === 0 ? 3 : 0) + (t % 89 === 0 ? 120 : 0);
    return { t, bytes_in: Math.round(18000 * wave), bytes_out: Math.round(4200 * wave), packets: Math.round(30 * wave) };
  });
  const mk = (remote: string, rport: number | null, transport: Transport, dir: Flow["direction"], bin: number, bout: number, origin: Flow["origin"] = "local_interface"): Flow => ({
    key: { transport, local: dir === "heard" ? "192.0.2.255" : "192.0.2.108", local_port: dir === "heard" ? rport : 50000 + (bin % 999), remote, remote_port: rport },
    direction: dir,
    origin,
    initiated_by: dir === "outbound" && transport === "tcp" ? "local" : "unknown",
    packets_out: Math.round(bout / 600),
    packets_in: Math.round(bin / 900),
    bytes_out: bout,
    bytes_in: bin,
    first_seen_ms: start,
    last_seen_ms: now - (bin % 7000),
  });
  const flows = [
    mk("203.0.113.20", 443, "tcp", "outbound", 1_840_000, 96_000),
    mk("198.51.100.53", 53, "udp", "outbound", 22_400, 9_800),
    mk("203.0.113.88", 443, "udp", "outbound", 640_000, 41_000),
    mk("192.0.2.1", 53, "udp", "outbound", 3_100, 1_400),
    mk("192.0.2.50", 5353, "udp", "heard", 2_900, 0, "local_broadcast"),
    mk("192.0.2.77", null, "arp", "heard", 420, 0, "local_broadcast"),
  ];
  const total = flows.reduce((a, f) => a + f.bytes_in + f.bytes_out, 0);
  return {
    running,
    interface: "en0",
    started_at_ms: start,
    elapsed_ms: now - start,
    snaplen: 96,
    stats: { received: 3210, dropped: 0, if_dropped: 0, error: null },
    snapshot: { flows, total_flows: flows.length, total_packets: 3210, total_bytes: total, evicted_flows: 0, unparsed_frames: 4, series },
    demo: true,
  };
}

// ---- PCAP/PCAPNG import (M1.4) ----

export interface ReadError {
  offset: number;
  reason:
    | { kind: "not_a_capture" }
    | { kind: "truncated" }
    | { kind: "bad_length"; declared: number }
    | { kind: "length_mismatch" }
    | { kind: "unknown_interface"; id: number }
    | { kind: "bad_capture_length" }
    | { kind: "io"; detail: string };
}

/** Mirrors `calm_flow_engine::import::ImportSummary`. */
export interface ImportSummary {
  format: "pcap" | "pcap_nanos" | "pcapng";
  frames: number;
  ethernet_frames: number;
  unsupported_link_frames: number;
  linktypes: number[];
  untimed_frames: number;
  first_ts_ms: number | null;
  last_ts_ms: number | null;
  /** Reading stopped early; everything before `offset` is used. */
  error: ReadError | null;
  /** Capture host inside the file — inferred, never a fact. */
  vantage: { mac: string | null; addresses: string[]; involved_frames: number; unicast_frames: number };
}

export interface ImportView {
  file_name: string;
  size_bytes: number;
  sha256: string;
  imported_at_ms: number;
  summary: ImportSummary;
  snapshot: CaptureView["snapshot"];
  graph: GraphSnapshot;
  /** Browser preview only. */
  demo?: boolean;
}

export type ImportError =
  | { kind: "cancelled" }
  | { kind: "too_large"; size_bytes: number; limit_bytes: number }
  | { kind: "unreadable"; detail: string }
  | { kind: "not_a_capture" };

let demoImport: ImportView | null = null;

/** Opens the native file picker (Rust side) and replays the chosen file. */
export async function importPick(): Promise<ImportView> {
  if (!isTauri()) {
    demoImport = demoImportView();
    return demoImport;
  }
  return invoke<ImportView>("import_pick");
}

export async function importView(): Promise<ImportView | null> {
  if (!isTauri()) return demoImport;
  return invoke<ImportView | null>("import_view");
}

export async function importClear(): Promise<void> {
  if (!isTauri()) {
    demoImport = null;
    return;
  }
  await invoke("import_clear");
}

/** Browser preview: the shape of `fixtures/pcap/guest-sample.pcapng` (documentation addresses). */
function demoImportView(): ImportView {
  const t0 = 1_793_437_200_000;
  const seen = new Date(t0).toISOString();
  const id = (kind: string, value: string): ObservedIdentifier => ({ kind, value, source: "imported_sensor", seen_at: seen });
  const node = (aid: string, role: string, ids: ObservedIdentifier[], status: EpistemicStatus, ev: string[], confidence: Confidence = "high"): Asset => ({
    id: aid,
    observed_identifiers: ids,
    role_hypothesis: role,
    epistemic_status: status,
    confidence,
    evidence_refs: ev,
  });
  const fe = (source: string, target: string): TopologyEdge => ({
    source,
    target,
    relation_type: "FLOW_OBSERVED",
    epistemic_status: "observed",
    confidence: "high",
    evidence_ids: ["import:flows"],
  });
  const H = "capture-host";
  const mk = (transport: Transport, local: string, lport: number | null, remote: string, rport: number | null, direction: Flow["direction"], initiated_by: Flow["initiated_by"], p: [number, number], b: [number, number], first: number, last: number): Flow => ({
    key: { transport, local, local_port: lport, remote, remote_port: rport },
    direction,
    origin: "imported",
    initiated_by,
    packets_out: p[0],
    packets_in: p[1],
    bytes_out: b[0],
    bytes_in: b[1],
    first_seen_ms: t0 + first,
    last_seen_ms: t0 + last,
  });
  const flows: Flow[] = [
    mk("tcp", "192.0.2.108", 50100, "203.0.113.10", 443, "outbound", "local", [22, 21], [1188, 29134], 2000, 11620),
    mk("udp", "192.0.2.108", 51000, "203.0.113.20", 443, "outbound", "unknown", [10, 10], [12420, 12920], 4000, 6750),
    mk("tcp", "2001:db8:1::108", 50300, "2001:db8:ffff::443", 443, "outbound", "local", [1, 5], [74, 6370], 8000, 8900),
    mk("tcp", "192.0.2.108", 50200, "203.0.113.11", 443, "inbound", "unknown", [6, 6], [324, 3924], 3000, 8010),
    mk("tcp", "192.0.2.108", 22, "192.0.2.105", 51515, "inbound", "remote", [5, 5], [1070, 630], 20000, 20450),
    mk("tcp", "192.0.2.108", 50400, "192.0.2.100", 8009, "outbound", "local", [1, 2], [54, 408], 15000, 15200),
    mk("udp", "224.0.0.251", 5353, "192.0.2.107", 5353, "heard", "unknown", [0, 1], [0, 202], 30500, 30500),
    mk("udp", "ff02::fb", 5353, "fe80::d", 5353, "heard", "unknown", [0, 1], [0, 202], 40000, 40000),
    mk("udp", "fe80::108", 5353, "fe80::a", 5353, "inbound", "unknown", [1, 1], [142, 142], 16000, 16010),
    mk("udp", "192.0.2.108", 53000, "198.51.100.53", 53, "outbound", "unknown", [1, 1], [82, 162], 1000, 1025),
  ];
  const series: SeriesPoint[] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 15, 16, 20, 30, 40, 50, 59].map((s) => ({
    t: t0 / 1000 + s,
    bytes_in: s >= 2 && s <= 11 ? 3000 + (s % 3) * 900 : 160,
    bytes_out: s >= 4 && s <= 6 ? 4200 : 120,
    packets: 6,
  }));
  return {
    file_name: "guest-sample.pcapng",
    size_bytes: 12948,
    sha256: "demo0000000000000000000000000000000000000000000000000000000000ff",
    imported_at_ms: Date.now(),
    demo: true,
    summary: {
      format: "pcapng",
      frames: 113,
      ethernet_frames: 113,
      unsupported_link_frames: 0,
      linktypes: [1],
      untimed_frames: 0,
      first_ts_ms: t0,
      last_ts_ms: t0 + 59_030,
      error: null,
      vantage: { mac: "02:ca:1d:00:01:08", addresses: ["192.0.2.108", "2001:db8:1::108", "fe80::108"], involved_frames: 108, unicast_frames: 112 },
    },
    snapshot: { flows, total_flows: 17, total_packets: 112, total_bytes: 70612, evicted_flows: 0, unparsed_frames: 1, series },
    graph: {
      nodes: [
        node(H, "capture_host", [id("mac_address_private", "02:ca:1d:00:01:08"), id("ipv4", "192.0.2.108"), id("ipv6", "2001:db8:1::108"), id("ipv6", "fe80::108")], "inferred", ["import:vantage"], "medium"),
        node("ip:192.0.2.1", "default_gateway", [id("ipv4", "192.0.2.1"), id("ipv6", "fe80::1"), id("mac_address_private", "02:ca:1d:00:00:01")], "inferred", ["import:forwarding", "import:flows"], "medium"),
        node("ip:192.0.2.100", "local_peer", [id("ipv4", "192.0.2.100"), id("ipv6", "fe80::a"), id("mac_address_private", "02:ca:1d:00:01:00")], "observed", ["import:flows", "import:link-binding"]),
        node("ip:192.0.2.105", "local_peer", [id("ipv4", "192.0.2.105"), id("mac_address_private", "02:ca:1d:00:01:05")], "observed", ["import:flows"]),
        node("ip:192.0.2.107", "local_peer", [id("ipv4", "192.0.2.107"), id("mac_address_private", "02:ca:1d:00:01:07")], "observed", ["import:flows"]),
        node("ip:fe80::d", "local_peer", [id("ipv6", "fe80::d"), id("mac_address_private", "02:ca:1d:00:0d:0d")], "observed", ["import:flows"]),
        node("external", "external_destinations", [id("distinct_destinations", "5")], "observed", ["import:flows"]),
      ],
      edges: [
        fe(H, "ip:192.0.2.1"),
        fe("ip:192.0.2.1", H),
        fe(H, "ip:192.0.2.100"),
        fe("ip:192.0.2.100", H),
        fe(H, "ip:192.0.2.105"),
        fe("ip:192.0.2.105", H),
        fe("ip:192.0.2.107", H),
        fe("ip:fe80::d", H),
        fe(H, "external"),
        fe("external", H),
      ],
    },
  };
}

// ---- Session storage (M1.5) ----

export interface SessionMeta {
  name: string;
  site: string;
  operator: string;
  authorization_ref: string;
  notes: string;
}

export interface SessionInput {
  meta: SessionMeta;
  /** null keeps the session until the user deletes it. */
  retention_days: number | null;
}

export interface SessionSummary {
  id: string;
  meta: SessionMeta;
  created_at_ms: number;
  updated_at_ms: number;
  retention_days: number | null;
  snapshot_count: number;
  stored_bytes: number;
}

export type SnapshotKind = "live" | "import";

export interface SnapshotSummary {
  id: string;
  session_id: string;
  kind: SnapshotKind;
  label: string;
  created_at_ms: number;
  size_bytes: number;
}

export type StoreError =
  | { kind: "key_unavailable"; detail: string }
  | { kind: "key_mismatch" }
  | { kind: "not_found" }
  | { kind: "corrupt"; detail: string }
  | { kind: "unsupported_schema"; detail: number }
  | { kind: "db"; detail: string }
  | { kind: "io"; detail: string };

export interface StoreStatus {
  state: "ready" | "closed" | "error";
  error: StoreError | null;
  path: string | null;
  purged_on_open: number;
  active_session: SessionSummary | null;
}

export interface LiveView {
  profile: NetworkProfile;
  graph: GraphSnapshot;
  capture: CaptureView | null;
}

/** A saved snapshot opened for viewing: exactly one of `live` / `import`. */
export interface RecordedView {
  snapshot: SnapshotSummary;
  live: LiveView | null;
  import: ImportView | null;
}

import { DemoStore } from "./demoStore";
import { importLabel, liveLabel } from "./labels";

const demoStore = new DemoStore(() => Date.now());

/** Browser preview: the active demo session, for the simulated M2 checks. */
export const demoActiveSessionId = (): string | null => demoStore.active()?.id ?? null;

function storeErr(e: unknown): never {
  throw (e as { kind?: string })?.kind ? e : { kind: "io", detail: String(e) };
}

export async function storeOpen(): Promise<StoreStatus> {
  if (!isTauri()) {
    const purged = demoStore.purge();
    return { state: "ready", error: null, path: "(browser preview — in memory)", purged_on_open: purged, active_session: demoStore.active() };
  }
  return invoke<StoreStatus>("store_open");
}

export async function storeSetAside(): Promise<StoreStatus> {
  if (!isTauri()) return storeOpen();
  return invoke<StoreStatus>("store_set_aside_unreadable");
}

export async function sessionList(): Promise<SessionSummary[]> {
  if (!isTauri()) return demoStore.list();
  return invoke<SessionSummary[]>("session_list").catch(storeErr);
}

export async function sessionCreate(input: SessionInput): Promise<SessionSummary> {
  if (!isTauri()) return demoStore.create(input);
  return invoke<SessionSummary>("session_create", { input }).catch(storeErr);
}

export async function sessionDelete(id: string): Promise<void> {
  if (!isTauri()) return demoStore.remove(id);
  return invoke<void>("session_delete", { id }).catch(storeErr);
}

export async function sessionActivate(id: string | null): Promise<SessionSummary | null> {
  if (!isTauri()) return demoStore.activate(id);
  return invoke<SessionSummary | null>("session_activate", { id }).catch(storeErr);
}

export async function snapshotList(sessionId: string): Promise<SnapshotSummary[]> {
  if (!isTauri()) return demoStore.snapshots(sessionId);
  return invoke<SnapshotSummary[]>("snapshot_list", { sessionId }).catch(storeErr);
}

export async function snapshotSaveLive(label?: string): Promise<SnapshotSummary> {
  if (!isTauri()) {
    const o = demoOverview();
    const c = demoStart ? demoCapture(false) : demoLast;
    const name = liveLabel(c ? { flows: c.snapshot.total_flows, elapsedMs: c.elapsed_ms } : null);
    return demoStore.save("live", label || name, { profile: o.profile, graph: o.graph, capture: c });
  }
  return invoke<SnapshotSummary>("snapshot_save_live", { label: label ?? null }).catch(storeErr);
}

export async function snapshotSaveImport(label?: string): Promise<SnapshotSummary> {
  if (!isTauri()) {
    if (!demoImport) throw { kind: "not_found" } as StoreError;
    return demoStore.save("import", label || importLabel(demoImport.file_name), demoImport);
  }
  return invoke<SnapshotSummary>("snapshot_save_import", { label: label ?? null }).catch(storeErr);
}

export async function snapshotOpen(id: string): Promise<RecordedView> {
  if (!isTauri()) {
    const { summary, payload } = demoStore.open(id);
    return summary.kind === "live"
      ? { snapshot: summary, live: payload as LiveView, import: null }
      : { snapshot: summary, live: null, import: payload as ImportView };
  }
  return invoke<RecordedView>("snapshot_open", { id }).catch(storeErr);
}

export async function snapshotDelete(id: string): Promise<void> {
  if (!isTauri()) return demoStore.removeSnapshot(id);
  return invoke<void>("snapshot_delete", { id }).catch(storeErr);
}

// ---- Node ↔ flows and time window (M1: FR-005, timeline) ----

/** Mirrors `calm_flow_engine::select::FlowFilter`. */
export type FlowFilter =
  | { kind: "all" }
  | { kind: "remotes"; addresses: string[] }
  | { kind: "external_except"; known: string[] };

/** Half-open window `[from_ms, to_ms)`, Unix ms. */
export interface TimeWindow {
  from_ms: number;
  to_ms: number;
}

export interface FlowSelection {
  flows: Flow[];
  total: number;
  bytes: number;
  packets: number;
}

export interface GraphView {
  graph: GraphSnapshot;
  span: [number, number] | null;
  flows_in_window: number;
  flows_total: number;
}

/** Which data to read: this Mac, the imported file, or a saved snapshot. */
export type SourceRef = { kind: "live" } | { kind: "imported" } | { kind: "saved"; snapshot_id: string };

import { previewFlows, previewGraphView } from "./previewSource";

export async function graphView(source: SourceRef, window: TimeWindow | null): Promise<GraphView> {
  if (!isTauri()) return previewGraphView(source, window);
  return invoke<GraphView>("graph_view", { source, window });
}

export async function flowsFor(source: SourceRef, filter: FlowFilter, window: TimeWindow | null): Promise<FlowSelection> {
  if (!isTauri()) return previewFlows(source, filter, window);
  return invoke<FlowSelection>("flows_for", { source, filter, window });
}

/** Preview helpers need the demo data; exported for previewSource only. */
export const previewData = {
  overview: () => demoOverview(),
  capture: () => (demoStart ? demoCapture(true) : demoLast),
  imported: () => demoImport,
  saved: (id: string) => {
    try {
      return demoStore.open(id);
    } catch {
      return null;
    }
  },
};

/** Tells the shell whether to save the running capture on Stop or quit. */
export async function captureSetAutosave(enabled: boolean): Promise<void> {
  if (!isTauri()) return;
  await invoke("capture_set_autosave", { enabled });
}
