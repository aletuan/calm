//! Authorized checks in the shell (M2.2–M2.3): preflight, progress, results.
//!
//! The probing itself is `calm_orchestrator::checks::run_checks`; this module
//! holds what the UI sees and how a finished run is stored and audited.

use std::sync::Mutex;

use calm_domain::NetworkBinding;
use calm_orchestrator::checks::{plan, CheckId, ChecksRun};
use calm_orchestrator::probe::{ProbeOutcome, ProbeRecord, StopFlag};
use calm_orchestrator::{in_subnet, same_network};
use calm_store::{AuditAction, SnapshotKind, Store, StoreError};
use serde::Serialize;

use crate::scopes::ScopeView;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PlanItem {
    pub check: CheckId,
    pub target: String,
    pub port: u16,
    pub label: String,
    /// The target is outside this Mac's subnet at grant time: the probe is
    /// routed through the gateway to another segment. Allowed, but said.
    pub outside_subnet: bool,
}

/// What would run, from where, and whether it may.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Preflight {
    pub scope: Option<ScopeView>,
    pub network: Option<NetworkBinding>,
    /// None when there is no scope or the network is unknown.
    pub same_network: Option<bool>,
    pub plan: Vec<PlanItem>,
    /// Lower bound from the rate budget; timeouts can add up to `max_seconds`.
    pub min_seconds: u64,
    pub max_seconds: u64,
    pub ready: bool,
}

pub fn preflight(scope: Option<ScopeView>, network: Option<NetworkBinding>) -> Preflight {
    let Some(view) = scope.filter(ScopeView::usable) else {
        return Preflight {
            scope: None,
            network,
            same_network: None,
            plan: vec![],
            min_seconds: 0,
            max_seconds: 0,
            ready: false,
        };
    };
    let s = &view.scope;
    let items: Vec<PlanItem> = plan(s)
        .into_iter()
        .map(|(check, r)| {
            let target = r.address.to_string();
            let label = s
                .targets
                .iter()
                .find(|t| t.address == target)
                .map(|t| t.label.clone())
                .unwrap_or_default();
            let outside_subnet = s
                .network
                .subnet
                .as_deref()
                .and_then(|n| in_subnet(&target, n))
                == Some(false);
            PlanItem {
                check,
                target,
                port: r.port,
                label,
                outside_subnet,
            }
        })
        .collect();
    let n = items.len() as u64;
    let rate = u64::from(s.budget.max_probes_per_second.max(1));
    let min_seconds = n.saturating_sub(1).div_ceil(rate);
    let max_seconds = min_seconds + (n * u64::from(s.budget.timeout_ms)).div_ceil(1000);
    let same = network.as_ref().map(|now| same_network(&s.network, now));
    let ready = same == Some(true) && !items.is_empty();
    Preflight {
        same_network: same,
        network,
        plan: items,
        min_seconds,
        max_seconds,
        ready,
        scope: Some(view),
    }
}

/// Live progress of the current (or last) run.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Progress {
    pub run_id: String,
    pub running: bool,
    pub done: usize,
    pub total: usize,
    pub last: Option<ProbeRecord>,
    pub stopped: bool,
    pub started_at_ms: i64,
    /// Set when the run could not be stored.
    pub error: Option<String>,
    /// The stored run, once finished.
    pub snapshot_id: Option<String>,
}

#[derive(Default)]
pub struct AssessState {
    pub progress: Mutex<Option<Progress>>,
    pub stop: Mutex<StopFlag>,
}

impl AssessState {
    pub fn running(&self) -> bool {
        self.progress
            .lock()
            .map(|p| p.as_ref().is_some_and(|p| p.running))
            .unwrap_or(false)
    }

    /// A fresh stop flag for a new run.
    pub fn arm(&self) -> StopFlag {
        let f = StopFlag::default();
        if let Ok(mut s) = self.stop.lock() {
            *s = f.clone();
        }
        f
    }

    pub fn emergency_stop(&self) {
        if let Ok(s) = self.stop.lock() {
            s.stop();
        }
    }

    pub fn update(&self, f: impl FnOnce(&mut Progress)) {
        if let Ok(mut p) = self.progress.lock() {
            if let Some(p) = p.as_mut() {
                f(p);
            }
        }
    }
}

/// Store a finished run as a sealed `findings` record and audit every probe
/// decision by run id (never by address).
pub fn record_run(
    store: &Store,
    session_id: &str,
    run: &ChecksRun,
    now_ms: i64,
) -> Result<String, StoreError> {
    for p in &run.probes {
        match p.record.outcome {
            ProbeOutcome::Cancelled => {}
            ProbeOutcome::Denied { .. } => store.audit(
                session_id,
                AuditAction::ProbeDenied,
                &run.id,
                p.record.started_at_ms,
            )?,
            _ => store.audit(
                session_id,
                AuditAction::ProbeAllowed,
                &run.id,
                p.record.started_at_ms,
            )?,
        }
    }
    if run.stopped {
        store.audit(
            session_id,
            AuditAction::EmergencyStop,
            &run.id,
            run.finished_at_ms,
        )?;
    }
    let label = format!("checks {}", &run.id[..run.id.len().min(8)]);
    let snap = store.put_snapshot(session_id, SnapshotKind::Findings, &label, run, now_ms)?;
    store.audit(session_id, AuditAction::ChecksFinished, &run.id, now_ms)?;
    Ok(snap.id)
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StoredRun {
    pub snapshot_id: String,
    pub run: ChecksRun,
}

/// Every stored run of a session, newest first.
pub fn list_runs(store: &Store, session_id: &str) -> Result<Vec<StoredRun>, StoreError> {
    let mut out = Vec::new();
    for s in store.list_snapshots(session_id)? {
        if s.kind == SnapshotKind::Findings {
            let (_, run): (_, ChecksRun) = store.get_snapshot(&s.id)?;
            out.push(StoredRun {
                snapshot_id: s.id,
                run,
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scopes;
    use calm_domain::{FindingStatus, TargetRole};
    use calm_orchestrator::checks::run_checks;
    use calm_orchestrator::probe::{Clock, Connector};
    use calm_orchestrator::scope::{authorize, ScopeDraft, TargetDraft};
    use calm_store::{Key, SessionMeta};
    use std::time::{Duration, Instant};

    const NOW: i64 = 1_800_000_000_000;

    fn net() -> NetworkBinding {
        NetworkBinding {
            gateway: "192.168.68.1".into(),
            subnet: Some("192.168.68.0/22".into()),
            ssid: None,
        }
    }

    fn setup() -> (Store, String, ScopeView) {
        let st = Store::open_in_memory(Key::from_bytes([5; 32])).unwrap();
        let meta = SessionMeta {
            name: "M2".into(),
            site: String::new(),
            operator: "A".into(),
            authorization_ref: String::new(),
            notes: String::new(),
        };
        let sid = st.create_session(&meta, None, NOW).unwrap().id;
        let d = ScopeDraft {
            authorization_reference: "ROE".into(),
            operator: "A".into(),
            granted_by: "O".into(),
            targets: vec![
                TargetDraft {
                    address: "192.168.68.1".into(),
                    ports: vec![80, 443],
                    role: TargetRole::AdminInterface,
                    label: "router".into(),
                },
                TargetDraft {
                    address: "192.168.68.9".into(),
                    ports: vec![22],
                    role: TargetRole::Other,
                    label: String::new(),
                },
            ],
            expires_at_ms: NOW + 3_600_000,
            max_probes_per_second: 5,
            timeout_ms: 3000,
            authorization_confirmed: true,
            vantage: Some(calm_domain::NetworkPosition::Guest),
        };
        let v = scopes::approve(&st, &sid, &d, Some(net()), NOW).unwrap();
        (st, sid, v)
    }

    #[test]
    fn preflight_without_a_usable_scope_is_not_ready() {
        let p = preflight(None, Some(net()));
        assert!(!p.ready && p.plan.is_empty() && p.scope.is_none());
        let (_, _, mut v) = setup();
        v.revoked = true;
        assert!(!preflight(Some(v), Some(net())).ready);
    }

    #[test]
    fn preflight_lists_the_plan_and_time_bounds() {
        let (_, _, v) = setup();
        let p = preflight(Some(v), Some(net()));
        assert!(p.ready);
        assert_eq!(p.same_network, Some(true));
        let items: Vec<_> = p
            .plan
            .iter()
            .map(|i| (i.check, i.target.as_str(), i.port, i.label.as_str()))
            .collect();
        assert_eq!(
            items,
            vec![
                (CheckId::S01, "192.168.68.1", 80, "router"),
                (CheckId::S01, "192.168.68.1", 443, "router")
            ]
        );
        assert_eq!((p.min_seconds, p.max_seconds), (1, 7));
        assert!(p.plan.iter().all(|i| !i.outside_subnet));
    }

    #[test]
    fn preflight_marks_targets_outside_the_subnet() {
        let (_, _, mut v) = setup();
        v.scope.targets[0].address = "192.168.1.1".into();
        let p = preflight(Some(v.clone()), Some(net()));
        assert!(p.plan.iter().all(|i| i.outside_subnet));
        assert!(p.ready, "outside the subnet is allowed, only flagged");
        v.scope.network.subnet = None;
        let p = preflight(Some(v), Some(net()));
        assert!(
            p.plan.iter().all(|i| !i.outside_subnet),
            "unknown subnet: no claim"
        );
    }

    #[test]
    fn preflight_on_another_network_is_not_ready() {
        let (_, _, v) = setup();
        let other = NetworkBinding {
            gateway: "10.0.0.1".into(),
            ..net()
        };
        let p = preflight(Some(v.clone()), Some(other));
        assert_eq!((p.same_network, p.ready), (Some(false), false));
        let p = preflight(Some(v), None);
        assert_eq!((p.same_network, p.ready), (None, false));
    }

    struct Net;
    impl Connector for Net {
        fn connect(&self, a: std::net::SocketAddr, _: Duration) -> std::io::Result<()> {
            if a.port() == 443 {
                Ok(())
            } else {
                Err(std::io::ErrorKind::ConnectionRefused.into())
            }
        }
    }
    struct Fixed;
    impl Clock for Fixed {
        fn now_ms(&self) -> i64 {
            NOW + 5
        }
        fn elapsed_ms(&self, _: Instant) -> u64 {
            0
        }
        fn sleep(&self, _: Duration) {}
    }

    #[test]
    fn a_finished_run_is_stored_sealed_and_audited_by_id() {
        let (st, sid, v) = setup();
        let s = v.scope.clone();
        let run = run_checks(
            "abcdef0123456789".into(),
            &s,
            false,
            |r| authorize(Some(&s), false, r, NOW + 5, Some(&net())),
            &Net,
            &Fixed,
            &StopFlag::default(),
            |_, _, _| {},
        );
        let snap = record_run(&st, &sid, &run, NOW + 10).unwrap();
        let runs = list_runs(&st, &sid).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].snapshot_id, snap);
        assert_eq!(runs[0].run, run);
        let s01 = run
            .results
            .iter()
            .find(|r| r.check == CheckId::S01)
            .unwrap();
        assert_eq!(s01.status, FindingStatus::Fail);
        let ev: Vec<_> = st.events(&sid).unwrap();
        assert_eq!(ev.iter().filter(|e| e.action == "probe_allowed").count(), 2);
        assert!(ev
            .iter()
            .any(|e| e.action == "checks_finished" && e.subject_id == run.id));
        assert!(
            ev.iter().all(|e| !e.subject_id.contains("192.168")),
            "no addresses in the audit trail"
        );
    }

    #[test]
    fn denied_and_stopped_runs_are_audited() {
        let (st, sid, v) = setup();
        let s = v.scope.clone();
        let stop = StopFlag::default();
        let mut n = 0;
        let run = run_checks(
            "run-denied".into(),
            &s,
            false,
            |r| {
                n += 1;
                if n == 1 {
                    // First probe: refused by the engine (network changed).
                    authorize(Some(&s), false, r, NOW + 5, None)
                } else {
                    stop.stop();
                    authorize(Some(&s), false, r, NOW + 5, Some(&net()))
                }
            },
            &Net,
            &Fixed,
            &stop,
            |_, _, _| {},
        );
        assert!(run.stopped);
        record_run(&st, &sid, &run, NOW + 10).unwrap();
        let ev: Vec<_> = st
            .events(&sid)
            .unwrap()
            .into_iter()
            .map(|e| e.action)
            .collect();
        assert!(ev.contains(&"probe_denied".to_string()));
        assert!(ev.contains(&"emergency_stop".to_string()));
    }

    #[test]
    fn progress_and_stop_flag() {
        let a = AssessState::default();
        assert!(!a.running());
        let f = a.arm();
        *a.progress.lock().unwrap() = Some(Progress {
            run_id: "r".into(),
            running: true,
            done: 0,
            total: 2,
            last: None,
            stopped: false,
            started_at_ms: NOW,
            error: None,
            snapshot_id: None,
        });
        assert!(a.running());
        a.update(|p| p.done = 1);
        assert_eq!(a.progress.lock().unwrap().as_ref().unwrap().done, 1);
        a.emergency_stop();
        assert!(f.is_stopped(), "the armed flag is the one stopped");
        let g = a.arm();
        assert!(!g.is_stopped(), "a new run starts clean");
    }
}
