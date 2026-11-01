//! What a saved snapshot contains (M1.5) and how it is shown again.
//!
//! Records keep every flow (not just the top rows the UI shows), the
//! source-IP↔MAC bindings and the graph as it was, so a later Calm can
//! recompute or compare. Never raw packets (AT-15).

use calm_capture::CaptureView;
use calm_domain::NetworkProfile;
use calm_flow_engine::import::ImportSummary;
use calm_flow_engine::{AddressBinding, FlowSnapshot};
use calm_graph_engine::GraphSnapshot;
use calm_store::SnapshotSummary;
use serde::{Deserialize, Serialize};

use crate::ImportView;

/// This Mac at one moment: profile, graph, and the live capture if any.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveRecord {
    pub profile: NetworkProfile,
    pub graph: GraphSnapshot,
    /// All flows (`snapshot.flows` is complete, not the UI's top rows).
    pub capture: Option<CaptureView>,
    pub bindings: Vec<AddressBinding>,
}

/// An imported file's results. The file itself is not stored; its SHA-256 is.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportRecord {
    pub file_name: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub imported_at_ms: i64,
    pub summary: ImportSummary,
    pub snapshot: FlowSnapshot,
    pub bindings: Vec<AddressBinding>,
    pub graph: GraphSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveView {
    pub profile: NetworkProfile,
    pub graph: GraphSnapshot,
    pub capture: Option<CaptureView>,
}

/// A saved snapshot opened for viewing: exactly one of `live` / `import`.
#[derive(Debug, Clone, Serialize)]
pub struct RecordedView {
    pub snapshot: SnapshotSummary,
    pub live: Option<LiveView>,
    pub import: Option<ImportView>,
}

/// Top `limit` flows by bytes; totals, series and counters stay complete.
pub fn limit_flows(mut s: FlowSnapshot, limit: usize) -> FlowSnapshot {
    s.flows.sort_by(|a, b| {
        (b.bytes_in + b.bytes_out)
            .cmp(&(a.bytes_in + a.bytes_out))
            .then(b.last_seen_ms.cmp(&a.last_seen_ms))
    });
    s.flows.truncate(limit);
    s
}

impl LiveRecord {
    pub fn view(self, limit: usize) -> LiveView {
        LiveView {
            profile: self.profile,
            graph: self.graph,
            capture: self.capture.map(|mut c| {
                c.running = false;
                c.snapshot = limit_flows(c.snapshot, limit);
                c
            }),
        }
    }
}

impl ImportRecord {
    pub fn view(self, limit: usize) -> ImportView {
        ImportView {
            file_name: self.file_name,
            size_bytes: self.size_bytes,
            sha256: self.sha256,
            imported_at_ms: self.imported_at_ms,
            summary: self.summary,
            snapshot: limit_flows(self.snapshot, limit),
            graph: self.graph,
        }
    }
}

/// Default label for a snapshot of this Mac. With a capture it carries the
/// flow count and duration, so two saves of the same session differ.
pub fn live_label(capture: Option<(usize, i64)>) -> String {
    match capture {
        None => "This Mac — network profile".to_owned(),
        Some((flows, elapsed_ms)) => {
            let s = (elapsed_ms.max(0) / 1000) as u64;
            format!(
                "This Mac — {flows} flow{}, {:02}:{:02} capture",
                if flows == 1 { "" } else { "s" },
                s / 60,
                s % 60
            )
        }
    }
}

pub fn import_label(file_name: &str) -> String {
    format!("Imported — {file_name}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use calm_flow_engine::import::replay_bytes;
    use calm_store::{Key, SessionMeta, SnapshotKind, Store};

    const FIXTURE: &[u8] = include_bytes!("../../../../fixtures/pcap/guest-sample.pcapng");

    fn import_record() -> ImportRecord {
        let r = replay_bytes(FIXTURE, 20_000).unwrap();
        let graph =
            calm_graph_engine::from_import(&r.summary, &r.table.all_flows(), &r.table.bindings());
        ImportRecord {
            file_name: "guest-sample.pcapng".into(),
            size_bytes: FIXTURE.len() as u64,
            sha256: "00".repeat(32),
            imported_at_ms: 1,
            snapshot: r.table.snapshot(usize::MAX),
            bindings: r.table.bindings(),
            summary: r.summary,
            graph,
        }
    }

    #[test]
    fn limit_keeps_totals_and_biggest_flows() {
        let rec = import_record();
        let all = rec.snapshot.clone();
        let lim = limit_flows(all.clone(), 3);
        assert_eq!(lim.flows.len(), 3);
        assert_eq!(lim.total_flows, all.total_flows);
        assert_eq!(lim.total_bytes, all.total_bytes);
        assert_eq!(lim.series, all.series);
        let max = all
            .flows
            .iter()
            .map(|f| f.bytes_in + f.bytes_out)
            .max()
            .unwrap();
        assert_eq!(lim.flows[0].bytes_in + lim.flows[0].bytes_out, max);
        assert!(lim
            .flows
            .windows(2)
            .all(|w| w[0].bytes_in + w[0].bytes_out >= w[1].bytes_in + w[1].bytes_out));
    }

    #[test]
    fn import_record_survives_encrypted_store_round_trip() {
        let store = Store::open_in_memory(Key::from_bytes([7; 32])).unwrap();
        let s = store
            .create_session(&SessionMeta::default(), None, 0)
            .unwrap();
        let rec = import_record();
        let flows_before = rec.snapshot.flows.len();
        let snap = store
            .put_snapshot(&s.id, SnapshotKind::Import, "x", &rec, 0)
            .unwrap();
        let (_, back): (_, ImportRecord) = store.get_snapshot(&snap.id).unwrap();
        assert_eq!(
            back.snapshot.flows.len(),
            flows_before,
            "every flow kept, not just the UI rows"
        );
        assert_eq!(back.bindings, rec.bindings);
        assert_eq!(back.summary, rec.summary);
        assert_eq!(back.graph.nodes.len(), rec.graph.nodes.len());
        let v = back.view(5);
        assert_eq!(v.snapshot.flows.len(), 5);
        assert_eq!(v.snapshot.total_flows, rec.snapshot.total_flows);
    }

    #[test]
    fn saved_live_capture_is_never_shown_as_running() {
        let rec = LiveRecord {
            profile: test_profile(),
            graph: GraphSnapshot::default(),
            capture: Some(CaptureView {
                running: true,
                interface: "en0".into(),
                started_at_ms: 1,
                elapsed_ms: 2,
                snaplen: 96,
                stats: Default::default(),
                snapshot: import_record().snapshot,
            }),
            bindings: vec![],
        };
        let v = rec.view(2);
        let c = v.capture.unwrap();
        assert!(!c.running);
        assert_eq!(c.snapshot.flows.len(), 2);
    }

    fn test_profile() -> NetworkProfile {
        let p = include_str!("../../../../fixtures/profile/network-profile.example.json");
        serde_json::from_str(p).expect("profile fixture parses")
    }

    #[test]
    fn live_record_round_trip_keeps_profile() {
        let store = Store::open_in_memory(Key::from_bytes([7; 32])).unwrap();
        let s = store
            .create_session(&SessionMeta::default(), None, 0)
            .unwrap();
        let rec = LiveRecord {
            profile: test_profile(),
            graph: calm_graph_engine::from_profile(&test_profile()),
            capture: None,
            bindings: vec![],
        };
        let snap = store
            .put_snapshot(&s.id, SnapshotKind::Live, "l", &rec, 0)
            .unwrap();
        let (_, back): (_, LiveRecord) = store.get_snapshot(&snap.id).unwrap();
        assert_eq!(back.profile, rec.profile);
        assert_eq!(back.graph.edges.len(), rec.graph.edges.len());
    }

    #[test]
    fn default_labels_tell_snapshots_apart() {
        assert_eq!(live_label(None), "This Mac — network profile");
        assert_eq!(
            live_label(Some((182, 113_000))),
            "This Mac — 182 flows, 01:53 capture"
        );
        assert_eq!(
            live_label(Some((1, 3_725_000))),
            "This Mac — 1 flow, 62:05 capture"
        );
        assert_ne!(
            live_label(Some((182, 113_000))),
            live_label(Some((190, 121_000)))
        );
        assert_eq!(import_label("a.pcapng"), "Imported — a.pcapng");
    }
}
