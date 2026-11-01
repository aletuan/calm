//! Choosing flows for one node of the graph and/or a time window (FR-005).
//! The graph engine maps every non-group remote address either to a node
//! (by its address identifiers) or to the aggregated external node; this
//! module selects flows with the same rule, so "this node's flows" always
//! matches what the graph drew.

use std::collections::HashSet;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::{is_group, Flow};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FlowFilter {
    /// Every flow (the centre node: this Mac or the capture host).
    All,
    /// Flows whose remote is one of these addresses (a node's identifiers).
    Remotes { addresses: Vec<IpAddr> },
    /// Flows whose remote is none of `known` (all addresses that have their
    /// own node) and not a broadcast/multicast group: the external node.
    ExternalExcept { known: Vec<IpAddr> },
}

/// Half-open time window in Unix ms: `[from_ms, to_ms)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeWindow {
    pub from_ms: i64,
    pub to_ms: i64,
}

impl TimeWindow {
    /// A flow is in the window when it was active at some point inside it.
    /// Counts stay whole-flow totals: flows are not split by time.
    pub fn overlaps(&self, f: &Flow) -> bool {
        f.first_seen_ms < self.to_ms && f.last_seen_ms >= self.from_ms
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FlowSelection {
    /// Largest first, at most `limit`.
    pub flows: Vec<Flow>,
    /// Matching flows before the limit.
    pub total: usize,
    pub bytes: u64,
    pub packets: u64,
}

pub fn select(
    flows: &[Flow],
    filter: &FlowFilter,
    window: Option<TimeWindow>,
    limit: usize,
) -> FlowSelection {
    let set = |v: &[IpAddr]| v.iter().copied().collect::<HashSet<IpAddr>>();
    let (remotes, known) = match filter {
        FlowFilter::All => (None, None),
        FlowFilter::Remotes { addresses } => (Some(set(addresses)), None),
        FlowFilter::ExternalExcept { known } => (None, Some(set(known))),
    };
    let mut out: Vec<Flow> = flows
        .iter()
        .filter(|f| window.is_none_or(|w| w.overlaps(f)))
        .filter(|f| remotes.as_ref().is_none_or(|r| r.contains(&f.key.remote)))
        .filter(|f| {
            known.as_ref().is_none_or(|k| {
                !k.contains(&f.key.remote)
                    && !is_group(&f.key.remote)
                    && !f.key.remote.is_unspecified()
            })
        })
        .cloned()
        .collect();
    out.sort_by(|a, b| {
        (b.bytes_in + b.bytes_out)
            .cmp(&(a.bytes_in + a.bytes_out))
            .then(b.last_seen_ms.cmp(&a.last_seen_ms))
    });
    let total = out.len();
    let bytes = out.iter().map(|f| f.bytes_in + f.bytes_out).sum();
    let packets = out.iter().map(|f| f.packets_in + f.packets_out).sum();
    out.truncate(limit);
    FlowSelection {
        flows: out,
        total,
        bytes,
        packets,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CaptureOrigin, Direction, FlowKey, Initiator, Transport};

    fn f(remote: &str, bytes: u64, first: i64, last: i64) -> Flow {
        Flow {
            key: FlowKey {
                transport: Transport::Tcp,
                local: "192.0.2.108".parse().unwrap(),
                local_port: Some(1),
                remote: remote.parse().unwrap(),
                remote_port: Some(443),
            },
            direction: Direction::Outbound,
            origin: CaptureOrigin::LocalInterface,
            initiated_by: Initiator::Unknown,
            packets_out: 1,
            packets_in: 1,
            bytes_out: bytes,
            bytes_in: 0,
            first_seen_ms: first,
            last_seen_ms: last,
        }
    }

    fn ips(v: &[&str]) -> Vec<IpAddr> {
        v.iter().map(|s| s.parse().unwrap()).collect()
    }

    fn sample() -> Vec<Flow> {
        vec![
            f("192.0.2.1", 100, 0, 10_000),        // gateway
            f("192.0.2.100", 50, 2_000, 3_000),    // peer A (v4)
            f("fe80::a", 70, 20_000, 21_000),      // peer A (v6)
            f("203.0.113.10", 900, 5_000, 60_000), // external
            f("198.51.100.53", 30, 1_000, 1_500),  // external (DNS not a node here)
            f("224.0.0.251", 10, 0, 100_000),      // group: never external
        ]
    }

    #[test]
    fn all_is_every_flow_largest_first() {
        let s = select(&sample(), &FlowFilter::All, None, 100);
        assert_eq!(s.total, 6);
        assert_eq!(s.flows[0].key.remote.to_string(), "203.0.113.10");
        assert_eq!(s.bytes, 1160);
    }

    #[test]
    fn a_node_gets_flows_of_all_its_addresses() {
        let s = select(
            &sample(),
            &FlowFilter::Remotes {
                addresses: ips(&["192.0.2.100", "fe80::a"]),
            },
            None,
            100,
        );
        assert_eq!(s.total, 2);
        assert_eq!(s.bytes, 120);
    }

    #[test]
    fn external_is_what_no_node_claims_and_never_a_group() {
        let s = select(
            &sample(),
            &FlowFilter::ExternalExcept {
                known: ips(&["192.0.2.1", "192.0.2.100", "fe80::a"]),
            },
            None,
            100,
        );
        let r: Vec<String> = s.flows.iter().map(|f| f.key.remote.to_string()).collect();
        assert_eq!(r, ["203.0.113.10", "198.51.100.53"]);
    }

    #[test]
    fn window_keeps_flows_active_inside_it() {
        let w = TimeWindow {
            from_ms: 4_000,
            to_ms: 20_000,
        };
        let s = select(&sample(), &FlowFilter::All, Some(w), 100);
        let r: Vec<String> = s.flows.iter().map(|f| f.key.remote.to_string()).collect();
        // gateway (0–10 s), external (5–60 s), group (0–100 s); peer A v6 starts at 20 s exactly: out.
        assert_eq!(r, ["203.0.113.10", "192.0.2.1", "224.0.0.251"]);
        assert!(
            !w.overlaps(&f("192.0.2.100", 1, 2_000, 3_999)),
            "ended before"
        );
        assert!(
            w.overlaps(&f("192.0.2.100", 1, 2_000, 4_000)),
            "touches the start"
        );
    }

    #[test]
    fn limit_keeps_totals() {
        let s = select(&sample(), &FlowFilter::All, None, 2);
        assert_eq!(s.flows.len(), 2);
        assert_eq!(s.total, 6);
        assert_eq!(s.packets, 12);
    }
}
