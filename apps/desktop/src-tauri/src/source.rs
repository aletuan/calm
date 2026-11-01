//! One way to read "the data on screen" — this Mac live, the imported file,
//! or a saved snapshot — and to rebuild its graph or select its flows for a
//! node and/or a time window (FR-005, timeline). Sources never mix.

use calm_domain::NetworkProfile;
use calm_flow_engine::import::ImportSummary;
use calm_flow_engine::select::{select, FlowFilter, FlowSelection, TimeWindow};
use calm_flow_engine::{AddressBinding, Flow};
use calm_graph_engine::GraphSnapshot;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SourceRef {
    Live,
    Imported,
    Saved { snapshot_id: String },
}

pub enum Base {
    /// This Mac: configuration graph plus flows.
    Profile(Box<NetworkProfile>),
    /// An imported file: graph centred on its inferred capture host.
    Import(Box<ImportSummary>),
    /// Flows only (selecting flows needs no profile, so none is collected).
    FlowsOnly,
}

/// Everything needed to rebuild a graph or pick flows, from any source.
pub struct SourceData {
    pub base: Base,
    pub flows: Vec<Flow>,
    pub bindings: Vec<AddressBinding>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GraphView {
    pub graph: GraphSnapshot,
    /// First and last moment any flow was seen (Unix ms), for the time window.
    pub span: Option<(i64, i64)>,
    /// Flows that fell in the window (all flows when there is no window).
    pub flows_in_window: usize,
    pub flows_total: usize,
}

impl SourceData {
    fn in_window(&self, window: Option<TimeWindow>) -> Vec<Flow> {
        self.flows
            .iter()
            .filter(|f| window.is_none_or(|w| w.overlaps(f)))
            .cloned()
            .collect()
    }

    pub fn span(&self) -> Option<(i64, i64)> {
        let first = self.flows.iter().map(|f| f.first_seen_ms).min()?;
        let last = self.flows.iter().map(|f| f.last_seen_ms).max()?;
        Some((first, last))
    }

    /// The graph as the graph engine builds it, from the flows in `window`.
    /// Address bindings are identity evidence and are not time-filtered.
    pub fn graph(&self, window: Option<TimeWindow>) -> GraphView {
        let flows = self.in_window(window);
        let graph = match &self.base {
            Base::Profile(p) => {
                let mut g = calm_graph_engine::from_profile(p);
                calm_graph_engine::add_flows(&mut g, p, &flows, &self.bindings);
                g
            }
            Base::Import(s) => calm_graph_engine::from_import(s, &flows, &self.bindings),
            Base::FlowsOnly => GraphSnapshot::default(),
        };
        GraphView {
            graph,
            span: self.span(),
            flows_in_window: flows.len(),
            flows_total: self.flows.len(),
        }
    }

    pub fn select(
        &self,
        filter: &FlowFilter,
        window: Option<TimeWindow>,
        limit: usize,
    ) -> FlowSelection {
        select(&self.flows, filter, window, limit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use calm_flow_engine::import::replay_bytes;

    const FIXTURE: &[u8] = include_bytes!("../../../../fixtures/pcap/guest-sample.pcapng");
    const T0: i64 = 1_793_437_200_000;

    fn import_data() -> SourceData {
        let r = replay_bytes(FIXTURE, 20_000).unwrap();
        SourceData {
            flows: r.table.all_flows(),
            bindings: r.table.bindings(),
            base: Base::Import(Box::new(r.summary)),
        }
    }

    #[test]
    fn no_window_rebuilds_the_same_graph_as_import() {
        let d = import_data();
        let r = replay_bytes(FIXTURE, 20_000).unwrap();
        let direct =
            calm_graph_engine::from_import(&r.summary, &r.table.all_flows(), &r.table.bindings());
        let v = d.graph(None);
        let ids = |g: &GraphSnapshot| {
            let mut v: Vec<String> = g.nodes.iter().map(|n| n.id.clone()).collect();
            v.sort();
            v
        };
        assert_eq!(ids(&v.graph), ids(&direct));
        assert_eq!(v.graph.edges.len(), direct.edges.len());
        assert_eq!(v.flows_in_window, v.flows_total);
        assert_eq!(v.span, Some((T0, T0 + 59_030)));
    }

    #[test]
    fn a_window_keeps_only_what_happened_in_it() {
        let d = import_data();
        // 15 s – 25 s: peer A (15–16 s) and peer B's SSH (20 s); not the 30 s / 40 s heard peers.
        let w = TimeWindow {
            from_ms: T0 + 15_000,
            to_ms: T0 + 25_000,
        };
        let v = d.graph(Some(w));
        let has = |id: &str| v.graph.nodes.iter().any(|n| n.id == id);
        assert!(has("ip:192.0.2.100"));
        assert!(has("ip:192.0.2.105"));
        assert!(!has("ip:192.0.2.107"), "heard at 30 s, outside the window");
        assert!(!has("ip:fe80::d"), "heard at 40 s, outside the window");
        assert!(v.flows_in_window < v.flows_total);
        // The centre is always there.
        assert!(has(calm_graph_engine::CAPTURE_HOST));
    }

    #[test]
    fn an_empty_window_leaves_only_the_centre() {
        let d = import_data();
        let w = TimeWindow {
            from_ms: T0 - 10_000,
            to_ms: T0 - 5_000,
        };
        let v = d.graph(Some(w));
        assert_eq!(v.flows_in_window, 0);
        assert!(v.graph.edges.is_empty());
    }

    #[test]
    fn flows_can_be_selected_without_a_profile() {
        let mut d = import_data();
        d.base = Base::FlowsOnly;
        assert_eq!(d.select(&FlowFilter::All, None, 5).total, d.flows.len());
        assert!(d.graph(None).graph.is_empty(), "no base, no graph");
    }

    #[test]
    fn selection_uses_the_same_window() {
        let d = import_data();
        let w = TimeWindow {
            from_ms: T0 + 15_000,
            to_ms: T0 + 25_000,
        };
        let a = d.select(
            &FlowFilter::Remotes {
                addresses: vec!["192.0.2.100".parse().unwrap(), "fe80::a".parse().unwrap()],
            },
            Some(w),
            50,
        );
        assert_eq!(a.total, 2);
        let none = d.select(
            &FlowFilter::Remotes {
                addresses: vec!["192.0.2.107".parse().unwrap()],
            },
            Some(w),
            50,
        );
        assert_eq!(none.total, 0);
    }
}
