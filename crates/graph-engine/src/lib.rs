//! Evidence-based graph (ADR-003). Every node and edge links to provenance; no
//! physical topology or VLAN is ever inferred from IP similarity alone.
//!
//! M1.1: configuration facts from the network profile. M1.3: `FLOW_OBSERVED`
//! from local capture. M1.4: dual-stack merge on Ethernet address, and a
//! separate graph for imported capture files (never mixed with this Mac's).

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use calm_domain::{
    Asset, Confidence, EpistemicStatus, NetworkProfile, ObservedIdentifier, Provenance,
    RelationType, TopologyEdge,
};
use calm_flow_engine::import::ImportSummary;
use calm_flow_engine::{AddressBinding, Direction, Flow, Transport};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GraphSnapshot {
    pub nodes: Vec<Asset>,
    pub edges: Vec<TopologyEdge>,
}

impl GraphSnapshot {
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty() && self.edges.is_empty()
    }
}

pub const THIS_MAC: &str = "this-mac";
pub const EV_WIFI: &str = "profile:corewlan";
pub const EV_ROUTE: &str = "profile:route";
pub const EV_DNS: &str = "profile:scutil-dns";
pub const EV_IFCONFIG: &str = "profile:ifconfig";

fn ident(kind: &str, value: &str, p: &NetworkProfile) -> ObservedIdentifier {
    ObservedIdentifier {
        kind: kind.to_owned(),
        value: value.to_owned(),
        source: Provenance::ObservedByMac,
        seen_at: p.observed_at,
    }
}

fn edge(source: &str, target: &str, rel: RelationType, ev: &str) -> TopologyEdge {
    TopologyEdge {
        source: source.to_owned(),
        target: target.to_owned(),
        relation_type: rel,
        epistemic_status: EpistemicStatus::Observed,
        confidence: Confidence::High,
        evidence_ids: vec![ev.to_owned()],
    }
}

/// Builds the configuration-level graph seen from this Mac.
///
/// Rules (ADR-003, AT-05, AT-06):
/// - The AP radio (BSSID) and the default gateway are separate nodes, and no
///   edge between them is drawn: their relation is unknown from a guest Mac.
/// - If the Mac is associated but the BSSID is hidden (no Location permission),
///   the AP node exists as `unverified`; the association edge stays `observed`.
/// - Assets are merged only on an identical identifier (same IP), never by
///   similarity.
pub fn from_profile(p: &NetworkProfile) -> GraphSnapshot {
    let mut g = GraphSnapshot::default();

    // This Mac
    let mut mac_ids = Vec::new();
    if let Some(e) = &p.hardware_address.value {
        // A private (randomized) address is not a stable identity across networks.
        let kind = if p.hardware_address_private.value == Some(true) {
            "mac_address_private"
        } else {
            "mac_address"
        };
        mac_ids.push(ident(kind, e, p));
    }
    for a in p.ipv4.value.iter().flatten() {
        mac_ids.push(ident("ipv4", &a.address, p));
    }
    for a in p.ipv6.value.iter().flatten() {
        mac_ids.push(ident("ipv6", &a.address, p));
    }
    g.nodes.push(Asset {
        id: THIS_MAC.to_owned(),
        observed_identifiers: mac_ids,
        role_hypothesis: Some("this_mac".to_owned()),
        epistemic_status: EpistemicStatus::Observed,
        confidence: Confidence::High,
        evidence_refs: vec![EV_IFCONFIG.to_owned()],
    });

    // Access point radio (association from interface metadata)
    let associated = p.wifi.channel.value.is_some() || p.wifi.bssid.value.is_some();
    if associated {
        let (id, status, conf, mut ids) = match &p.wifi.bssid.value {
            Some(b) => (
                format!("bssid:{b}"),
                EpistemicStatus::Observed,
                Confidence::High,
                vec![ident("bssid", b, p)],
            ),
            None => (
                "ap:unidentified".to_owned(),
                EpistemicStatus::Unverified,
                Confidence::Low,
                vec![],
            ),
        };
        if let Some(s) = &p.wifi.ssid.value {
            ids.push(ident("ssid", s, p));
        }
        g.nodes.push(Asset {
            id: id.clone(),
            observed_identifiers: ids,
            role_hypothesis: Some("access_point_radio".to_owned()),
            epistemic_status: status,
            confidence: conf,
            evidence_refs: vec![EV_WIFI.to_owned()],
        });
        g.edges
            .push(edge(THIS_MAC, &id, RelationType::AssociatedWith, EV_WIFI));
    }

    // Default gateway (routing configuration)
    let gw_id = p
        .default_gateway
        .value
        .as_ref()
        .map(|ip| format!("ip:{ip}"));
    if let (Some(id), Some(ip)) = (&gw_id, &p.default_gateway.value) {
        g.nodes.push(Asset {
            id: id.clone(),
            observed_identifiers: vec![ident("ipv4", ip, p)],
            role_hypothesis: Some("default_gateway".to_owned()),
            epistemic_status: EpistemicStatus::Observed,
            confidence: Confidence::High,
            evidence_refs: vec![EV_ROUTE.to_owned()],
        });
        g.edges
            .push(edge(THIS_MAC, id, RelationType::DefaultRouteVia, EV_ROUTE));
    }

    // DNS resolvers (configuration). Same IP as an existing node => same asset.
    for ip in p.dns_servers.value.iter().flatten() {
        let id = format!("ip:{ip}");
        if let Some(existing) = g.nodes.iter_mut().find(|n| n.id == id) {
            existing.evidence_refs.push(EV_DNS.to_owned());
        } else {
            g.nodes.push(Asset {
                id: id.clone(),
                observed_identifiers: vec![ident("ip", ip, p)],
                role_hypothesis: Some("dns_resolver".to_owned()),
                epistemic_status: EpistemicStatus::Observed,
                confidence: Confidence::High,
                evidence_refs: vec![EV_DNS.to_owned()],
            });
        }
        g.edges
            .push(edge(THIS_MAC, &id, RelationType::ResolvesVia, EV_DNS));
    }

    g
}

pub const EV_FLOWS: &str = "capture:flows";
/// Source IP seen with a source MAC: evidence for merging dual-stack peers.
pub const EV_LINK: &str = "capture:link-binding";
pub const EXTERNAL: &str = "external";

pub const CAPTURE_HOST: &str = "capture-host";
pub const EV_IMPORT_FLOWS: &str = "import:flows";
pub const EV_IMPORT_LINK: &str = "import:link-binding";
pub const EV_IMPORT_VANTAGE: &str = "import:vantage";
pub const EV_IMPORT_FORWARDING: &str = "import:forwarding";

fn in_local_segment(ip: &IpAddr, p: &NetworkProfile) -> bool {
    match ip {
        IpAddr::V4(v4) => p.ipv4.value.iter().flatten().any(|a| {
            let (Ok(mine), Some(prefix)) = (a.address.parse::<std::net::Ipv4Addr>(), a.prefix)
            else {
                return false;
            };
            let prefix = u32::from(prefix.min(32));
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(mine) & mask) == (u32::from(*v4) & mask)
        }),
        IpAddr::V6(v6) => is_link_local_v6(v6),
    }
}

fn is_link_local_v6(v6: &std::net::Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xffc0) == 0xfe80
}

fn is_group_or_unspecified(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_broadcast() || v4.is_multicast() || v4.is_unspecified() || v4.octets()[3] == 255
        }
        IpAddr::V6(v6) => v6.is_multicast() || v6.is_unspecified(),
    }
}

fn mac_kind(mac: &str) -> &'static str {
    // U/L bit set: locally administered (randomized / private) address.
    let first = mac
        .get(0..2)
        .and_then(|h| u8::from_str_radix(h, 16).ok())
        .unwrap_or(0);
    if first & 0x02 != 0 {
        "mac_address_private"
    } else {
        "mac_address"
    }
}

fn ip_kind(ip: &IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(_) => "ipv4",
        IpAddr::V6(_) => "ipv6",
    }
}

/// How one data source (live capture or an imported file) attaches flows.
struct FlowSource<'a> {
    center: &'a str,
    own: BTreeSet<IpAddr>,
    provenance: Provenance,
    seen_at: OffsetDateTime,
    ev_flows: &'a str,
    ev_link: &'a str,
}

/// On-link addresses bound to exactly one MAC, grouped by that MAC. An address
/// seen with two MACs is a conflict (or spoofing) and is never merged.
fn mac_groups(
    bindings: &[AddressBinding],
    on_link: &dyn Fn(&IpAddr) -> bool,
    own: &BTreeSet<IpAddr>,
) -> BTreeMap<IpAddr, (String, Vec<IpAddr>)> {
    let mut ip_macs: BTreeMap<IpAddr, BTreeSet<&str>> = BTreeMap::new();
    for b in bindings {
        if on_link(&b.ip) && !own.contains(&b.ip) && !is_group_or_unspecified(&b.ip) {
            ip_macs.entry(b.ip).or_default().insert(&b.mac);
        }
    }
    let mut by_mac: BTreeMap<&str, Vec<IpAddr>> = BTreeMap::new();
    for (ip, macs) in &ip_macs {
        if macs.len() == 1 {
            if let Some(m) = macs.iter().next() {
                by_mac.entry(m).or_default().push(*ip);
            }
        }
    }
    let mut out = BTreeMap::new();
    for (mac, ips) in by_mac {
        for ip in &ips {
            out.insert(*ip, (mac.to_owned(), ips.clone()));
        }
    }
    out
}

fn push_ident(n: &mut Asset, kind: &str, value: &str, src: &FlowSource<'_>) {
    if !n.observed_identifiers.iter().any(|i| i.value == value) {
        n.observed_identifiers.push(ObservedIdentifier {
            kind: kind.to_owned(),
            value: value.to_owned(),
            source: src.provenance,
            seen_at: src.seen_at,
        });
    }
}

fn push_ev(n: &mut Asset, ev: &str) {
    if !n.evidence_refs.iter().any(|e| e == ev) {
        n.evidence_refs.push(ev.to_owned());
    }
}

/// Shared rules for live and imported flows:
/// - a remote already in the graph (gateway, DNS) → edge to that node;
/// - an on-link remote → `local_peer` node; on-link addresses bound to the
///   same single MAC become one node (dual-stack), with the MAC recorded;
/// - anything else → one aggregated `external_destinations` node. The path to
///   it (via the gateway) is routing inference and is not drawn;
/// - broadcast/multicast group addresses are never nodes.
fn attach_flows(
    g: &mut GraphSnapshot,
    src: &FlowSource<'_>,
    on_link: &dyn Fn(&IpAddr) -> bool,
    flows: &[Flow],
    bindings: &[AddressBinding],
) {
    let groups = mac_groups(bindings, on_link, &src.own);
    // Canonical node per MAC group: an existing node if one of its addresses
    // already has one, else the first IPv4, else the first address.
    let mut canonical: BTreeMap<IpAddr, String> = BTreeMap::new();
    for (ip, (_, ips)) in &groups {
        let existing = ips
            .iter()
            .map(|i| format!("ip:{i}"))
            .find(|id| g.nodes.iter().any(|n| &n.id == id));
        let id = existing.unwrap_or_else(|| {
            let pick = ips.iter().find(|i| i.is_ipv4()).unwrap_or(&ips[0]);
            format!("ip:{pick}")
        });
        canonical.insert(*ip, id);
    }

    let mut external = BTreeSet::new();
    let mut edges: BTreeSet<(String, String)> = BTreeSet::new();
    for f in flows {
        let remote = f.key.remote;
        if is_group_or_unspecified(&remote) || src.own.contains(&remote) {
            continue;
        }
        let rs = remote.to_string();
        let plain = format!("ip:{rs}");
        let target = if let Some(id) = canonical.get(&remote) {
            id.clone()
        } else if g.nodes.iter().any(|n| n.id == plain) || on_link(&remote) {
            plain
        } else {
            external.insert(rs.clone());
            EXTERNAL.to_owned()
        };
        if target != EXTERNAL && !g.nodes.iter().any(|n| n.id == target) {
            g.nodes.push(Asset {
                id: target.clone(),
                observed_identifiers: vec![],
                role_hypothesis: Some("local_peer".to_owned()),
                epistemic_status: EpistemicStatus::Observed,
                confidence: Confidence::High,
                evidence_refs: vec![],
            });
        }
        if let Some(n) = g.nodes.iter_mut().find(|n| n.id == target) {
            if target != EXTERNAL {
                push_ident(n, ip_kind(&remote), &rs, src);
                if let Some((mac, ips)) = groups.get(&remote) {
                    for ip in ips {
                        push_ident(n, ip_kind(ip), &ip.to_string(), src);
                    }
                    push_ident(n, mac_kind(mac), mac, src);
                    if ips.len() > 1 {
                        push_ev(n, src.ev_link);
                    }
                }
            }
            push_ev(n, src.ev_flows);
        }
        let pair = match f.direction {
            Direction::Outbound => (src.center.to_owned(), target),
            Direction::Inbound | Direction::Heard => (target, src.center.to_owned()),
        };
        edges.insert(pair);
    }

    if !external.is_empty() {
        g.nodes.push(Asset {
            id: EXTERNAL.to_owned(),
            observed_identifiers: vec![ObservedIdentifier {
                kind: "distinct_destinations".to_owned(),
                value: external.len().to_string(),
                source: src.provenance,
                seen_at: src.seen_at,
            }],
            role_hypothesis: Some("external_destinations".to_owned()),
            epistemic_status: EpistemicStatus::Observed,
            confidence: Confidence::High,
            evidence_refs: vec![src.ev_flows.to_owned()],
        });
    }
    for (s, t) in edges {
        g.edges.push(TopologyEdge {
            source: s,
            target: t,
            relation_type: RelationType::FlowObserved,
            epistemic_status: EpistemicStatus::Observed,
            confidence: Confidence::High,
            evidence_ids: vec![src.ev_flows.to_owned()],
        });
    }
}

/// Adds what local capture observed (M1.3) to the configuration graph, with
/// dual-stack peers merged on their Ethernet address (M1.4).
pub fn add_flows(
    g: &mut GraphSnapshot,
    p: &NetworkProfile,
    flows: &[Flow],
    bindings: &[AddressBinding],
) {
    let own: BTreeSet<IpAddr> = p
        .ipv4
        .value
        .iter()
        .flatten()
        .chain(p.ipv6.value.iter().flatten())
        .filter_map(|a| a.address.parse().ok())
        .collect();
    let src = FlowSource {
        center: THIS_MAC,
        own,
        provenance: Provenance::ObservedByMac,
        seen_at: p.observed_at,
        ev_flows: EV_FLOWS,
        ev_link: EV_LINK,
    };
    attach_flows(g, &src, &|ip| in_local_segment(ip, p), flows, bindings);
}

/// Graph of an imported capture file (M1.4). Nothing here is about this Mac:
/// the centre is the file's capture host, *inferred* as the unicast MAC in
/// most frames, and every identifier carries `imported_sensor` provenance.
///
/// On-link (no prefix is known from a file) means: IPv6 link-local, an IPv4
/// address that sent or answered ARP, or an address whose MAC is not a
/// forwarder. A forwarder is a MAC that sources ≥ 3 addresses not on-link by
/// the first two rules — the router. Its own on-link addresses become one
/// `default_gateway` node, `inferred` from that forwarding pattern.
pub fn from_import(
    summary: &ImportSummary,
    flows: &[Flow],
    bindings: &[AddressBinding],
) -> GraphSnapshot {
    let mut g = GraphSnapshot::default();
    let seen_at = summary
        .first_ts_ms
        .and_then(|ms| OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000).ok())
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    let v = &summary.vantage;
    let own: BTreeSet<IpAddr> = v.addresses.iter().copied().collect();

    let arp_seen: BTreeSet<IpAddr> = flows
        .iter()
        .filter(|f| f.key.transport == Transport::Arp)
        .flat_map(|f| [f.key.remote])
        .collect();
    let strong_on_link = |ip: &IpAddr| match ip {
        IpAddr::V6(v6) => is_link_local_v6(v6),
        IpAddr::V4(_) => arp_seen.contains(ip),
    };
    let mut weak_ips: BTreeMap<&str, BTreeSet<IpAddr>> = BTreeMap::new();
    for b in bindings {
        if !strong_on_link(&b.ip) && !is_group_or_unspecified(&b.ip) {
            weak_ips.entry(&b.mac).or_default().insert(b.ip);
        }
    }
    let forwarders: BTreeSet<String> = weak_ips
        .iter()
        .filter(|(m, ips)| ips.len() >= 3 && Some(**m) != v.mac.as_deref())
        .map(|(m, _)| (*m).to_owned())
        .collect();
    let mut ip_macs: BTreeMap<IpAddr, BTreeSet<&str>> = BTreeMap::new();
    for b in bindings {
        ip_macs.entry(b.ip).or_default().insert(&b.mac);
    }
    let on_link = |ip: &IpAddr| {
        strong_on_link(ip)
            || ip_macs
                .get(ip)
                .is_some_and(|m| m.len() == 1 && m.iter().all(|m| !forwarders.contains(*m)))
    };

    let share = if v.unicast_frames > 0 {
        v.involved_frames as f64 / v.unicast_frames as f64
    } else {
        0.0
    };
    let mut host = Asset {
        id: CAPTURE_HOST.to_owned(),
        observed_identifiers: vec![],
        role_hypothesis: Some("capture_host".to_owned()),
        epistemic_status: EpistemicStatus::Inferred,
        confidence: if share >= 0.9 {
            Confidence::Medium
        } else {
            Confidence::Low
        },
        evidence_refs: vec![EV_IMPORT_VANTAGE.to_owned()],
    };
    let src = FlowSource {
        center: CAPTURE_HOST,
        own,
        provenance: Provenance::ImportedSensor,
        seen_at,
        ev_flows: EV_IMPORT_FLOWS,
        ev_link: EV_IMPORT_LINK,
    };
    if let Some(m) = &v.mac {
        push_ident(&mut host, mac_kind(m), m, &src);
    }
    for a in &v.addresses {
        push_ident(&mut host, ip_kind(a), &a.to_string(), &src);
    }
    g.nodes.push(host);

    // Gateway: the forwarder's own on-link addresses.
    for fw in &forwarders {
        let mut ips: Vec<IpAddr> = bindings
            .iter()
            .filter(|b| &b.mac == fw && strong_on_link(&b.ip))
            .map(|b| b.ip)
            .collect();
        ips.sort();
        let Some(pick) = ips.iter().find(|i| i.is_ipv4()).or(ips.first()) else {
            continue;
        };
        let mut n = Asset {
            id: format!("ip:{pick}"),
            observed_identifiers: vec![],
            role_hypothesis: Some("default_gateway".to_owned()),
            epistemic_status: EpistemicStatus::Inferred,
            confidence: Confidence::Medium,
            evidence_refs: vec![EV_IMPORT_FORWARDING.to_owned()],
        };
        for ip in &ips {
            push_ident(&mut n, ip_kind(ip), &ip.to_string(), &src);
        }
        push_ident(&mut n, mac_kind(fw), fw, &src);
        g.nodes.push(n);
    }

    attach_flows(&mut g, &src, &on_link, flows, bindings);
    g
}

#[cfg(test)]
mod tests {
    use super::*;
    use calm_domain::{IpAddress, LocationAuthorization, Sourced, WifiInfo};
    use time::OffsetDateTime;

    fn s<T>(v: Option<T>) -> Sourced<T> {
        Sourced::from_option(v, "test", "unknown")
    }

    fn profile(bssid: Option<&str>, gw: Option<&str>, dns: &[&str]) -> NetworkProfile {
        NetworkProfile {
            schema_version: "test".into(),
            observed_at: OffsetDateTime::UNIX_EPOCH,
            location_authorization: LocationAuthorization::Authorized,
            bundled_app: true,
            wifi: WifiInfo {
                interface: s(Some("en0".into())),
                ssid: s(bssid.map(|_| "GuestNet".to_owned())),
                bssid: s(bssid.map(str::to_owned)),
                channel: s(Some(4)),
                band: s(Some("2.4 GHz".into())),
                channel_width: s(Some("20 MHz".into())),
                rssi_dbm: s(Some(-72)),
                noise_dbm: s(Some(-89)),
                security: s(Some("WPA2 Personal".into())),
                phy_mode: s(Some("802.11n".into())),
                tx_rate_mbps: s(Some(43.0)),
                country_code: s(Some("VN".into())),
            },
            hardware_address: s(Some("9e:65:00:11:22:33".into())),
            hardware_address_private: Sourced::inferred(true, "test", "locally_administered"),
            ipv4: s(Some(vec![IpAddress {
                address: "192.0.2.108".into(),
                prefix: Some(24),
                flags: vec![],
            }])),
            ipv6: s(None),
            ipv6_scope: s(None),
            default_gateway: s(gw.map(str::to_owned)),
            default_route_interface: s(Some("en0".into())),
            dns_servers: s(Some(dns.iter().map(|d| d.to_string()).collect())),
        }
    }

    #[test]
    fn at06_ap_and_gateway_are_distinct_and_unlinked() {
        let g = from_profile(&profile(Some("a4:2b:b0:11:22:33"), Some("192.0.2.1"), &[]));
        let ap = g
            .nodes
            .iter()
            .find(|n| n.role_hypothesis.as_deref() == Some("access_point_radio"))
            .unwrap();
        let gw = g
            .nodes
            .iter()
            .find(|n| n.role_hypothesis.as_deref() == Some("default_gateway"))
            .unwrap();
        assert_ne!(ap.id, gw.id);
        assert!(
            !g.edges
                .iter()
                .any(|e| (e.source == ap.id && e.target == gw.id)
                    || (e.source == gw.id && e.target == ap.id)),
            "AP↔gateway relation is unknown from a guest Mac and must not be drawn"
        );
    }

    #[test]
    fn at05_only_configuration_edges_from_this_mac() {
        let g = from_profile(&profile(
            Some("a4:2b:b0:11:22:33"),
            Some("192.0.2.1"),
            &["198.51.100.53"],
        ));
        assert!(g.edges.iter().all(|e| e.source == THIS_MAC));
        assert!(g
            .edges
            .iter()
            .all(|e| e.relation_type != RelationType::FlowObserved));
        assert!(g.edges.iter().all(|e| !e.evidence_ids.is_empty()));
        assert!(g.nodes.iter().all(|n| !n.evidence_refs.is_empty()));
    }

    #[test]
    fn hidden_bssid_gives_unverified_ap_but_observed_association() {
        let g = from_profile(&profile(None, Some("192.0.2.1"), &[]));
        let ap = g.nodes.iter().find(|n| n.id == "ap:unidentified").unwrap();
        assert_eq!(ap.epistemic_status, EpistemicStatus::Unverified);
        assert_eq!(ap.confidence, Confidence::Low);
        let assoc = g
            .edges
            .iter()
            .find(|e| e.relation_type == RelationType::AssociatedWith)
            .unwrap();
        assert_eq!(assoc.epistemic_status, EpistemicStatus::Observed);
    }

    #[test]
    fn dns_equal_to_gateway_ip_is_one_asset_with_two_relations() {
        let g = from_profile(&profile(
            None,
            Some("192.0.2.1"),
            &["192.0.2.1", "198.51.100.53"],
        ));
        assert_eq!(g.nodes.iter().filter(|n| n.id == "ip:192.0.2.1").count(), 1);
        let rels: Vec<_> = g
            .edges
            .iter()
            .filter(|e| e.target == "ip:192.0.2.1")
            .map(|e| e.relation_type)
            .collect();
        assert!(
            rels.contains(&RelationType::DefaultRouteVia)
                && rels.contains(&RelationType::ResolvesVia)
        );
        assert_eq!(g.nodes.len(), 4); // mac, ap, gateway/dns, second dns
    }

    #[test]
    fn no_wifi_no_gateway_still_has_this_mac_only() {
        let mut p = profile(None, None, &[]);
        p.wifi.channel = s(None);
        p.dns_servers = s(None);
        let g = from_profile(&p);
        assert_eq!(g.nodes.len(), 1);
        assert!(g.edges.is_empty());
    }
    #[test]
    fn private_mac_is_marked_as_unstable_identifier() {
        let g = from_profile(&profile(None, None, &[]));
        let mac = g.nodes.iter().find(|n| n.id == THIS_MAC).unwrap();
        assert!(mac
            .observed_identifiers
            .iter()
            .any(|i| i.kind == "mac_address_private"));
        assert!(!mac
            .observed_identifiers
            .iter()
            .any(|i| i.kind == "mac_address"));
    }
    fn flow(remote: &str, dir: calm_flow_engine::Direction) -> calm_flow_engine::Flow {
        use calm_flow_engine::*;
        Flow {
            key: FlowKey {
                transport: Transport::Tcp,
                local: "192.0.2.108".parse().unwrap(),
                local_port: Some(50000),
                remote: remote.parse().unwrap(),
                remote_port: Some(443),
            },
            direction: dir,
            origin: CaptureOrigin::LocalInterface,
            initiated_by: Initiator::Unknown,
            packets_out: 1,
            packets_in: 1,
            bytes_out: 60,
            bytes_in: 60,
            first_seen_ms: 0,
            last_seen_ms: 0,
        }
    }

    #[test]
    fn flows_add_peers_external_aggregate_and_skip_groups() {
        use calm_flow_engine::Direction::*;
        let p = profile(None, Some("192.0.2.1"), &["198.51.100.53"]);
        let mut g = from_profile(&p);
        let before = g.nodes.len();
        add_flows(
            &mut g,
            &p,
            &[
                flow("192.0.2.1", Outbound),    // gateway: existing node
                flow("192.0.2.50", Heard),      // local peer heard
                flow("203.0.113.9", Outbound),  // external
                flow("203.0.113.10", Outbound), // external, same aggregate
                flow("192.0.2.255", Heard),     // broadcast group: never a node
                flow("224.0.0.251", Heard),     // mDNS group: never a node
            ],
            &[],
        );
        assert_eq!(
            g.nodes.len(),
            before + 2,
            "one local peer + one external aggregate"
        );
        let peer = g.nodes.iter().find(|n| n.id == "ip:192.0.2.50").unwrap();
        assert_eq!(peer.role_hypothesis.as_deref(), Some("local_peer"));
        let ext = g.nodes.iter().find(|n| n.id == EXTERNAL).unwrap();
        assert_eq!(ext.observed_identifiers[0].value, "2");
        let flows: Vec<_> = g
            .edges
            .iter()
            .filter(|e| e.relation_type == RelationType::FlowObserved)
            .collect();
        assert_eq!(flows.len(), 3);
        assert!(
            flows
                .iter()
                .any(|e| e.source == "ip:192.0.2.50" && e.target == THIS_MAC),
            "heard = peer → Mac"
        );
        assert!(!g
            .nodes
            .iter()
            .any(|n| n.id.contains("255") || n.id.contains("224.0.0.251")));
        // No inferred path through the gateway to the internet.
        assert!(!g
            .edges
            .iter()
            .any(|e| e.source == "ip:192.0.2.1" && e.target == EXTERNAL));
    }

    fn bind(ip: &str, mac: &str) -> AddressBinding {
        AddressBinding {
            ip: ip.parse().unwrap(),
            mac: mac.to_owned(),
            frames: 1,
            first_seen_ms: 0,
            last_seen_ms: 0,
        }
    }

    #[test]
    fn dual_stack_peer_merges_on_same_mac_only() {
        use calm_flow_engine::Direction::*;
        let p = profile(None, Some("192.0.2.1"), &[]);
        let mut g = from_profile(&p);
        add_flows(
            &mut g,
            &p,
            &[
                flow("192.0.2.100", Outbound),
                flow("fe80::a", Inbound),
                flow("192.0.2.105", Outbound),
                flow("fe80::b", Inbound),
                flow("fe80::1", Heard),         // gateway's link-local
                flow("203.0.113.10", Outbound), // off-link, router MAC
            ],
            &[
                bind("192.0.2.100", "02:00:00:00:01:00"),
                bind("fe80::a", "02:00:00:00:01:00"),
                bind("192.0.2.105", "02:00:00:00:01:05"),
                bind("fe80::b", "02:00:00:00:0b:0b"), // different MAC: separate
                bind("192.0.2.1", "02:00:00:00:00:01"),
                bind("fe80::1", "02:00:00:00:00:01"),
                bind("203.0.113.10", "02:00:00:00:00:01"),
            ],
        );
        let a = g.nodes.iter().find(|n| n.id == "ip:192.0.2.100").unwrap();
        let vals: Vec<_> = a
            .observed_identifiers
            .iter()
            .map(|i| i.value.as_str())
            .collect();
        assert!(vals.contains(&"fe80::a") && vals.contains(&"02:00:00:00:01:00"));
        assert!(a.evidence_refs.iter().any(|e| e == EV_LINK));
        assert!(!g.nodes.iter().any(|n| n.id == "ip:fe80::a"), "merged");
        assert!(
            g.nodes.iter().any(|n| n.id == "ip:fe80::b"),
            "other MAC stays apart"
        );
        // Gateway absorbs its link-local address; external stays aggregated.
        assert!(!g.nodes.iter().any(|n| n.id == "ip:fe80::1"));
        let gw = g.nodes.iter().find(|n| n.id == "ip:192.0.2.1").unwrap();
        assert!(gw.observed_identifiers.iter().any(|i| i.value == "fe80::1"));
        assert!(!gw
            .observed_identifiers
            .iter()
            .any(|i| i.value == "203.0.113.10"));
        assert!(g
            .edges
            .iter()
            .any(|e| e.source == "ip:192.0.2.100" && e.target == THIS_MAC));
        assert!(g
            .edges
            .iter()
            .any(|e| e.source == THIS_MAC && e.target == "ip:192.0.2.100"));
    }

    #[test]
    fn address_with_two_macs_is_never_merged() {
        use calm_flow_engine::Direction::*;
        let p = profile(None, None, &[]);
        let mut g = from_profile(&p);
        add_flows(
            &mut g,
            &p,
            &[flow("192.0.2.100", Outbound), flow("fe80::a", Inbound)],
            &[
                bind("192.0.2.100", "02:00:00:00:01:00"),
                bind("192.0.2.100", "02:00:00:00:66:66"),
                bind("fe80::a", "02:00:00:00:01:00"),
            ],
        );
        assert!(g.nodes.iter().any(|n| n.id == "ip:192.0.2.100"));
        assert!(g.nodes.iter().any(|n| n.id == "ip:fe80::a"));
    }

    #[test]
    fn imported_fixture_graph() {
        let bytes = include_bytes!("../../../fixtures/pcap/guest-sample.pcapng");
        let r = calm_flow_engine::import::replay_bytes(bytes, 20_000).unwrap();
        let g = from_import(&r.summary, &r.table.all_flows(), &r.table.bindings());

        let host = g.nodes.iter().find(|n| n.id == CAPTURE_HOST).unwrap();
        assert_eq!(host.epistemic_status, EpistemicStatus::Inferred);
        assert!(host
            .observed_identifiers
            .iter()
            .all(|i| i.source == Provenance::ImportedSensor));
        assert!(!g.nodes.iter().any(|n| n.id == THIS_MAC), "never this Mac");

        let gw = g
            .nodes
            .iter()
            .find(|n| n.role_hypothesis.as_deref() == Some("default_gateway"))
            .unwrap();
        assert_eq!(gw.id, "ip:192.0.2.1");
        assert_eq!(gw.epistemic_status, EpistemicStatus::Inferred);
        assert!(gw.observed_identifiers.iter().any(|i| i.value == "fe80::1"));

        let mut peers: Vec<&str> = g
            .nodes
            .iter()
            .filter(|n| n.role_hypothesis.as_deref() == Some("local_peer"))
            .map(|n| n.id.as_str())
            .collect();
        peers.sort_unstable();
        // A merged (v4 + v6), B, C heard, D heard.
        assert_eq!(
            peers,
            [
                "ip:192.0.2.100",
                "ip:192.0.2.105",
                "ip:192.0.2.107",
                "ip:fe80::d"
            ]
        );
        let a = g.nodes.iter().find(|n| n.id == "ip:192.0.2.100").unwrap();
        assert!(a.observed_identifiers.iter().any(|i| i.value == "fe80::a"));

        let ext = g.nodes.iter().find(|n| n.id == EXTERNAL).unwrap();
        // DNS, 203.0.113.10/.11/.20, 2001:db8:ffff::443
        assert_eq!(ext.observed_identifiers[0].value, "5");
        assert!(g.edges.iter().all(|e| e.evidence_ids == [EV_IMPORT_FLOWS]));
        assert!(!g
            .edges
            .iter()
            .any(|e| e.source == gw.id && e.target == EXTERNAL));
        // Heard-only peer: edge points to the host only.
        assert!(g
            .edges
            .iter()
            .any(|e| e.source == "ip:192.0.2.107" && e.target == CAPTURE_HOST));
        assert!(!g
            .edges
            .iter()
            .any(|e| e.source == CAPTURE_HOST && e.target == "ip:192.0.2.107"));
    }

    /// FR-005 consistency: the flows selected for each node, plus those of
    /// the external node, are exactly the graph's non-group flows, each once.
    #[test]
    fn node_flow_selection_partitions_the_flows() {
        use calm_flow_engine::select::{select, FlowFilter};
        let bytes = include_bytes!("../../../fixtures/pcap/guest-sample.pcapng");
        let r = calm_flow_engine::import::replay_bytes(bytes, 20_000).unwrap();
        let flows = r.table.all_flows();
        let g = from_import(&r.summary, &flows, &r.table.bindings());
        let addrs = |n: &Asset| -> Vec<std::net::IpAddr> {
            n.observed_identifiers
                .iter()
                .filter(|i| i.kind.starts_with("ip"))
                .filter_map(|i| i.value.parse().ok())
                .collect()
        };
        let mut counted = 0;
        let mut known = Vec::new();
        for n in g
            .nodes
            .iter()
            .filter(|n| n.id != CAPTURE_HOST && n.id != EXTERNAL)
        {
            let a = addrs(n);
            counted += select(
                &flows,
                &FlowFilter::Remotes {
                    addresses: a.clone(),
                },
                None,
                usize::MAX,
            )
            .total;
            known.extend(a);
        }
        // The host's own addresses are never a remote of its flows.
        known.extend(r.summary.vantage.addresses.iter().copied());
        let external = select(
            &flows,
            &FlowFilter::ExternalExcept { known },
            None,
            usize::MAX,
        );
        let ext_node = g.nodes.iter().find(|n| n.id == EXTERNAL).unwrap();
        let distinct: std::collections::BTreeSet<_> =
            external.flows.iter().map(|f| f.key.remote).collect();
        assert_eq!(
            distinct.len().to_string(),
            ext_node.observed_identifiers[0].value
        );
        let non_group = flows
            .iter()
            .filter(|f| !is_group_or_unspecified(&f.key.remote))
            .count();
        assert_eq!(counted + external.total, non_group);
    }
}
