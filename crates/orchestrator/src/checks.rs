//! L1 checks (M2.3): S01 admin interface reachability, N03 POS test endpoint
//! isolation, N01 cooperative client isolation.
//!
//! Each check reads only the probe records of its own targets and returns a
//! bounded conclusion. Rules (methodology §Evidence policy, data model
//! §Status semantics):
//! - A TCP connection proves reachability at L4, never login or compromise (AT-08).
//! - Silence is a pass only towards a listener the user confirmed was running
//!   at test time; otherwise it is inconclusive. A missing receiver is
//!   never a pass (AT-07).
//! - Denied or stopped probes mean "not tested".

use std::collections::BTreeMap;

use calm_domain::{
    Confidence, FindingStatus, NetworkPosition, Scope, Severity, TargetRole, TestLevel,
};
use serde::{Deserialize, Serialize};

use crate::probe::{ProbeOutcome, ProbeRecord};
use crate::scope::ProbeRequest;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CheckId {
    S01,
    N03,
    N01,
}

impl CheckId {
    pub const ALL: [CheckId; 3] = [CheckId::S01, CheckId::N03, CheckId::N01];

    pub fn role(self) -> TargetRole {
        match self {
            CheckId::S01 => TargetRole::AdminInterface,
            CheckId::N03 => TargetRole::PosTest,
            CheckId::N01 => TargetRole::CooperativeReceiver,
        }
    }

    /// Targets of these checks are listeners the user set up (a test POS
    /// endpoint, a receiver on a second device), so silence can mean "blocked".
    fn expects_listener(self) -> bool {
        matches!(self, CheckId::N03 | CheckId::N01)
    }

    fn severity_if_reachable(self) -> Severity {
        match self {
            CheckId::S01 => Severity::Medium,
            CheckId::N03 | CheckId::N01 => Severity::High,
        }
    }
}

/// Why a result is what it is. The UI turns these into sentences.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// A TCP connection was accepted on at least one port.
    Connected,
    /// Every port answered with a reset: nothing reachable there (S01).
    AllRefused,
    /// A reset came back from a listener: packets got through to that host.
    ResetFromListener,
    /// No answer, towards a listener confirmed running: traffic was blocked.
    SilentConfirmedListener,
    /// No answer, and nobody confirmed the listener was up.
    SilentUnconfirmed,
    /// No answer from an admin target: blocked, or the host is off.
    Silent,
    /// The local network stack could not send (no route, other error).
    LocalError,
    /// Probes were refused by the scope engine.
    Denied,
    /// Emergency Stop before the probes ran.
    Stopped,
    /// The scope has no target for this check.
    NoTarget,
}

/// Statements a result makes. Verified ones are backed by probe records;
/// unverified ones are listed so nobody reads more into the result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Claim {
    TcpAccepted,
    TcpReset,
    NoReply,
    ListenerConfirmedByUser,
    LoginOrAuthBypass,
    AccessToManagementData,
    ServiceIdentity,
    ListenerWasRunning,
    BlockedOnOtherPorts,
    BlockedForOtherDevices,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub outcome: ProbeOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckResult {
    pub check: CheckId,
    /// Target address, or None for "no target in scope".
    pub target: Option<String>,
    pub label: String,
    pub status: FindingStatus,
    pub severity: Severity,
    /// How sure the evidence is. `None` when nothing was tested: there is
    /// no evidence to be sure or unsure about.
    pub confidence: Option<Confidence>,
    pub reason: Reason,
    pub ports: Vec<PortResult>,
    pub verified: Vec<Claim>,
    pub unverified: Vec<Claim>,
}

/// The probes for every check, in a fixed order: S01, N03, N01; scope order;
/// ports ascending. Targets with other roles get no probes.
pub fn plan(scope: &Scope) -> Vec<(CheckId, ProbeRequest)> {
    let mut out = Vec::new();
    for check in CheckId::ALL {
        for t in scope.targets.iter().filter(|t| t.role == check.role()) {
            let Ok(address) = t.address.parse() else {
                continue;
            };
            for &port in &t.ports {
                out.push((
                    check,
                    ProbeRequest {
                        address,
                        port,
                        level: TestLevel::L1,
                    },
                ));
            }
        }
    }
    out
}

fn result(
    check: CheckId,
    target: Option<String>,
    label: String,
    ports: Vec<PortResult>,
    receiver_confirmed: bool,
) -> CheckResult {
    use Claim::*;
    let base =
        |status, severity, confidence, reason, verified: Vec<Claim>, unverified: Vec<Claim>| {
            CheckResult {
                check,
                target: target.clone(),
                label: label.clone(),
                status,
                severity,
                confidence: (status != FindingStatus::NotTested).then_some(confidence),
                reason,
                ports: ports.clone(),
                verified,
                unverified,
            }
        };
    let any = |f: fn(&ProbeOutcome) -> bool| ports.iter().any(|p| f(&p.outcome));
    let all =
        |f: fn(&ProbeOutcome) -> bool| !ports.is_empty() && ports.iter().all(|p| f(&p.outcome));
    let connected = |o: &ProbeOutcome| matches!(o, ProbeOutcome::Connected { .. });
    let refused = |o: &ProbeOutcome| matches!(o, ProbeOutcome::Refused { .. });
    let silent = |o: &ProbeOutcome| matches!(o, ProbeOutcome::TimedOut);
    let denied = |o: &ProbeOutcome| matches!(o, ProbeOutcome::Denied { .. });
    let cancelled = |o: &ProbeOutcome| matches!(o, ProbeOutcome::Cancelled);
    let local = |o: &ProbeOutcome| matches!(o, ProbeOutcome::Unreachable { .. });

    let not_reached = match check {
        CheckId::S01 => vec![LoginOrAuthBypass, AccessToManagementData, ServiceIdentity],
        _ => vec![ServiceIdentity],
    };

    if target.is_none() {
        return base(
            FindingStatus::NotTested,
            Severity::Info,
            Confidence::High,
            Reason::NoTarget,
            vec![],
            vec![],
        );
    }
    // Any accepted connection decides, whatever happened on other ports.
    if any(connected) {
        return base(
            FindingStatus::Fail,
            check.severity_if_reachable(),
            Confidence::High,
            Reason::Connected,
            vec![TcpAccepted],
            not_reached,
        );
    }
    if all(denied) {
        return base(
            FindingStatus::NotTested,
            Severity::Info,
            Confidence::High,
            Reason::Denied,
            vec![],
            vec![],
        );
    }
    if any(cancelled) {
        return base(
            FindingStatus::NotTested,
            Severity::Info,
            Confidence::High,
            Reason::Stopped,
            vec![],
            vec![],
        );
    }
    if any(denied) {
        return base(
            FindingStatus::NotTested,
            Severity::Info,
            Confidence::High,
            Reason::Denied,
            vec![],
            vec![],
        );
    }
    if any(local) {
        return base(
            FindingStatus::Inconclusive,
            Severity::Info,
            Confidence::Low,
            Reason::LocalError,
            vec![],
            vec![],
        );
    }
    if check.expects_listener() && any(refused) {
        // A reset from the listener's host: the path is open even if the
        // port is not. (Across segments a firewall can also send resets.)
        let confidence = if check == CheckId::N01 {
            Confidence::Medium
        } else {
            Confidence::Low
        };
        let status = if check == CheckId::N01 {
            FindingStatus::Fail
        } else {
            FindingStatus::Warning
        };
        return base(
            status,
            Severity::Medium,
            confidence,
            Reason::ResetFromListener,
            vec![TcpReset],
            vec![ServiceIdentity],
        );
    }
    if !check.expects_listener() && all(refused) {
        return base(
            FindingStatus::Pass,
            Severity::Info,
            Confidence::Medium,
            Reason::AllRefused,
            vec![TcpReset],
            vec![BlockedOnOtherPorts],
        );
    }
    if check.expects_listener() && all(silent) {
        return if receiver_confirmed {
            base(
                FindingStatus::Pass,
                Severity::Info,
                Confidence::Medium,
                Reason::SilentConfirmedListener,
                vec![NoReply, ListenerConfirmedByUser],
                vec![ListenerWasRunning, BlockedForOtherDevices],
            )
        } else {
            base(
                FindingStatus::Inconclusive,
                Severity::Info,
                Confidence::Low,
                Reason::SilentUnconfirmed,
                vec![NoReply],
                vec![ListenerWasRunning],
            )
        };
    }
    // S01 with silence on some or all ports: blocked, or the host is off.
    base(
        FindingStatus::Inconclusive,
        Severity::Info,
        Confidence::Low,
        Reason::Silent,
        vec![NoReply],
        vec![],
    )
}

/// Results for every check: one per target, or one "no target" result.
pub fn evaluate(
    scope: &Scope,
    records: &[(CheckId, ProbeRecord)],
    receiver_confirmed: bool,
) -> Vec<CheckResult> {
    let mut out = Vec::new();
    for check in CheckId::ALL {
        let targets: Vec<_> = scope
            .targets
            .iter()
            .filter(|t| t.role == check.role())
            .collect();
        if targets.is_empty() {
            out.push(result(
                check,
                None,
                String::new(),
                vec![],
                receiver_confirmed,
            ));
            continue;
        }
        for t in targets {
            let mut by_port: BTreeMap<u16, ProbeOutcome> = BTreeMap::new();
            for (c, r) in records {
                if *c != check {
                    continue;
                }
                let Ok(sa) = r.target.parse::<std::net::SocketAddr>() else {
                    continue;
                };
                if sa.ip().to_string() == t.address {
                    by_port.insert(sa.port(), r.outcome.clone());
                }
            }
            // A planned port without a record was never attempted.
            let ports = t
                .ports
                .iter()
                .map(|&port| PortResult {
                    port,
                    outcome: by_port.remove(&port).unwrap_or(ProbeOutcome::Cancelled),
                })
                .collect();
            out.push(result(
                check,
                Some(t.address.clone()),
                t.label.clone(),
                ports,
                receiver_confirmed,
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::{approve, ScopeDenied, ScopeDraft, TargetDraft};
    use calm_domain::NetworkBinding;

    const NOW: i64 = 1_800_000_000_000;

    fn scope_with(targets: Vec<(&str, Vec<u16>, TargetRole)>) -> Scope {
        let d = ScopeDraft {
            authorization_reference: "ROE".into(),
            operator: "A".into(),
            granted_by: "O".into(),
            targets: targets
                .into_iter()
                .map(|(a, ports, role)| TargetDraft {
                    address: a.into(),
                    ports,
                    role,
                    label: String::new(),
                })
                .collect(),
            expires_at_ms: NOW + 3_600_000,
            max_probes_per_second: 5,
            timeout_ms: 1000,
            authorization_confirmed: true,
            vantage: Some(calm_domain::NetworkPosition::Guest),
            ..Default::default()
        };
        let net = NetworkBinding {
            gateway: "192.168.68.1".into(),
            subnet: None,
            ssid: None,
        };
        approve(&d, "sc".into(), "s".into(), Some(net), NOW).unwrap()
    }

    fn rec(check: CheckId, target: &str, outcome: ProbeOutcome) -> (CheckId, ProbeRecord) {
        (
            check,
            ProbeRecord {
                target: target.into(),
                role: Some(check.role()),
                scope_id: Some("sc".into()),
                started_at_ms: NOW,
                outcome,
            },
        )
    }

    const OK: ProbeOutcome = ProbeOutcome::Connected { rtt_ms: 3 };
    const RST: ProbeOutcome = ProbeOutcome::Refused { rtt_ms: 2 };
    const SILENT: ProbeOutcome = ProbeOutcome::TimedOut;

    fn admin(ports: Vec<u16>) -> Scope {
        scope_with(vec![("192.168.68.1", ports, TargetRole::AdminInterface)])
    }

    fn one(
        scope: &Scope,
        check: CheckId,
        outcomes: &[(u16, ProbeOutcome)],
        confirmed: bool,
    ) -> CheckResult {
        let t = scope
            .targets
            .iter()
            .find(|t| t.role == check.role())
            .unwrap()
            .address
            .clone();
        let recs: Vec<_> = outcomes
            .iter()
            .map(|(p, o)| rec(check, &format!("{t}:{p}"), o.clone()))
            .collect();
        evaluate(scope, &recs, confirmed)
            .into_iter()
            .find(|r| r.check == check && r.target.is_some())
            .unwrap()
    }

    #[test]
    fn plan_covers_each_check_in_order_and_skips_other_roles() {
        let s = scope_with(vec![
            ("10.0.0.9", vec![9999], TargetRole::CooperativeReceiver),
            ("192.168.68.1", vec![443, 80], TargetRole::AdminInterface),
            ("192.168.68.2", vec![22], TargetRole::Other),
            ("10.20.0.5", vec![8443], TargetRole::PosTest),
            ("192.168.68.254", vec![53], TargetRole::Gateway),
        ]);
        let p: Vec<_> = plan(&s)
            .into_iter()
            .map(|(c, r)| (c, format!("{}:{}", r.address, r.port)))
            .collect();
        assert_eq!(
            p,
            vec![
                (CheckId::S01, "192.168.68.1:80".into()),
                (CheckId::S01, "192.168.68.1:443".into()),
                (CheckId::N03, "10.20.0.5:8443".into()),
                (CheckId::N01, "10.0.0.9:9999".into()),
            ]
        );
    }

    #[test]
    fn at08_reaching_an_admin_interface_never_claims_login() {
        let r = one(
            &admin(vec![80, 443]),
            CheckId::S01,
            &[(80, RST), (443, OK)],
            false,
        );
        assert_eq!(r.status, FindingStatus::Fail);
        assert_eq!(r.severity, Severity::Medium);
        assert_eq!(r.confidence, Some(Confidence::High));
        assert_eq!(r.verified, vec![Claim::TcpAccepted]);
        assert!(r.unverified.contains(&Claim::LoginOrAuthBypass));
        assert!(r.unverified.contains(&Claim::AccessToManagementData));
        assert!(!r.verified.contains(&Claim::LoginOrAuthBypass));
    }

    #[test]
    fn s01_resets_on_every_port_pass_for_those_ports_only() {
        let r = one(
            &admin(vec![80, 443]),
            CheckId::S01,
            &[(80, RST), (443, RST)],
            false,
        );
        assert_eq!(
            (r.status, r.confidence, r.reason),
            (
                FindingStatus::Pass,
                Some(Confidence::Medium),
                Reason::AllRefused
            )
        );
        assert_eq!(r.unverified, vec![Claim::BlockedOnOtherPorts]);
    }

    #[test]
    fn s01_silence_is_never_a_pass() {
        for outcomes in [
            vec![(80, SILENT), (443, SILENT)],
            vec![(80, RST), (443, SILENT)],
        ] {
            let r = one(&admin(vec![80, 443]), CheckId::S01, &outcomes, true);
            assert_eq!(r.status, FindingStatus::Inconclusive, "{outcomes:?}");
            assert_eq!(r.reason, Reason::Silent);
        }
    }

    #[test]
    fn at07_no_receiver_means_not_tested_never_pass() {
        let s = admin(vec![443]);
        let all = evaluate(&s, &[], true);
        let n01 = all.iter().find(|r| r.check == CheckId::N01).unwrap();
        assert_eq!(
            (n01.status, n01.reason, n01.target.clone()),
            (FindingStatus::NotTested, Reason::NoTarget, None)
        );
        assert_eq!(n01.confidence, None, "nothing tested: no confidence");
        assert!(all
            .iter()
            .all(|r| r.reason != Reason::NoTarget || !r.status.counts_as_pass()));
    }

    #[test]
    fn at07_silent_receiver_without_confirmation_is_inconclusive() {
        let s = scope_with(vec![(
            "10.0.0.9",
            vec![9999],
            TargetRole::CooperativeReceiver,
        )]);
        let r = one(&s, CheckId::N01, &[(9999, SILENT)], false);
        assert_eq!(
            (r.status, r.reason),
            (FindingStatus::Inconclusive, Reason::SilentUnconfirmed)
        );
        assert_eq!(r.unverified, vec![Claim::ListenerWasRunning]);
    }

    #[test]
    fn n01_confirmed_receiver_silence_is_a_bounded_pass() {
        let s = scope_with(vec![(
            "10.0.0.9",
            vec![9999],
            TargetRole::CooperativeReceiver,
        )]);
        let r = one(&s, CheckId::N01, &[(9999, SILENT)], true);
        assert_eq!(
            (r.status, r.confidence),
            (FindingStatus::Pass, Some(Confidence::Medium))
        );
        assert!(r.verified.contains(&Claim::ListenerConfirmedByUser));
        assert!(
            r.unverified.contains(&Claim::ListenerWasRunning),
            "user said so; we did not see it"
        );
        assert!(r.unverified.contains(&Claim::BlockedForOtherDevices));
    }

    #[test]
    fn n01_reachable_receiver_fails_high() {
        let s = scope_with(vec![(
            "10.0.0.9",
            vec![9999],
            TargetRole::CooperativeReceiver,
        )]);
        let r = one(&s, CheckId::N01, &[(9999, OK)], false);
        assert_eq!(
            (r.status, r.severity, r.confidence),
            (FindingStatus::Fail, Severity::High, Some(Confidence::High))
        );
        let r = one(&s, CheckId::N01, &[(9999, RST)], true);
        assert_eq!(
            (r.status, r.confidence, r.reason),
            (
                FindingStatus::Fail,
                Some(Confidence::Medium),
                Reason::ResetFromListener
            )
        );
    }

    #[test]
    fn n03_reset_is_only_a_warning_across_segments() {
        let s = scope_with(vec![("10.20.0.5", vec![8443], TargetRole::PosTest)]);
        let r = one(&s, CheckId::N03, &[(8443, RST)], true);
        assert_eq!(
            (r.status, r.confidence),
            (FindingStatus::Warning, Some(Confidence::Low))
        );
        let r = one(&s, CheckId::N03, &[(8443, OK)], true);
        assert_eq!(
            (r.status, r.severity),
            (FindingStatus::Fail, Severity::High)
        );
        let r = one(&s, CheckId::N03, &[(8443, SILENT)], true);
        assert_eq!(r.status, FindingStatus::Pass);
    }

    #[test]
    fn denied_stopped_and_local_errors() {
        let s = admin(vec![80, 443]);
        let d = ProbeOutcome::Denied {
            reason: ScopeDenied::NetworkChanged,
        };
        let r = one(
            &s,
            CheckId::S01,
            &[(80, d.clone()), (443, d.clone())],
            false,
        );
        assert_eq!(
            (r.status, r.reason, r.confidence),
            (FindingStatus::NotTested, Reason::Denied, None)
        );
        let r = one(
            &s,
            CheckId::S01,
            &[(80, RST), (443, ProbeOutcome::Cancelled)],
            false,
        );
        assert_eq!(
            (r.status, r.reason),
            (FindingStatus::NotTested, Reason::Stopped)
        );
        let r = one(&s, CheckId::S01, &[(80, RST)], false);
        assert_eq!(
            r.reason,
            Reason::Stopped,
            "a planned port with no record was not attempted"
        );
        let r = one(&s, CheckId::S01, &[(80, RST), (443, d.clone())], false);
        assert_eq!(
            (r.status, r.reason),
            (FindingStatus::NotTested, Reason::Denied),
            "partly denied: not tested"
        );
        let r = one(
            &s,
            CheckId::S01,
            &[
                (80, RST),
                (443, ProbeOutcome::Unreachable { detail: "x".into() }),
            ],
            false,
        );
        assert_eq!(
            (r.status, r.reason),
            (FindingStatus::Inconclusive, Reason::LocalError)
        );
        // ...but a connection already made still decides.
        let r = one(
            &s,
            CheckId::S01,
            &[(80, OK), (443, ProbeOutcome::Cancelled)],
            false,
        );
        assert_eq!(r.status, FindingStatus::Fail);
    }

    #[test]
    fn records_of_another_check_or_target_are_ignored() {
        let s = scope_with(vec![
            ("192.168.68.1", vec![443], TargetRole::AdminInterface),
            ("192.168.68.3", vec![443], TargetRole::AdminInterface),
        ]);
        let recs = vec![
            rec(CheckId::S01, "192.168.68.3:443", OK),
            rec(CheckId::S01, "192.168.68.1:443", RST),
            rec(CheckId::N03, "192.168.68.1:443", OK),
        ];
        let r = evaluate(&s, &recs, false);
        let first = r
            .iter()
            .find(|x| x.target.as_deref() == Some("192.168.68.1"))
            .unwrap();
        assert_eq!(first.status, FindingStatus::Pass);
        let second = r
            .iter()
            .find(|x| x.target.as_deref() == Some("192.168.68.3"))
            .unwrap();
        assert_eq!(second.status, FindingStatus::Fail);
    }

    #[test]
    fn nothing_but_a_pass_counts_as_pass_and_pass_needs_a_reply_or_a_confirmed_listener() {
        // Exhaustive over single-port outcomes for every check.
        let outcomes = [
            OK,
            RST,
            SILENT,
            ProbeOutcome::Cancelled,
            ProbeOutcome::Unreachable { detail: "x".into() },
        ];
        for check in CheckId::ALL {
            let s = scope_with(vec![("10.1.1.1", vec![1], check.role())]);
            for o in &outcomes {
                for confirmed in [false, true] {
                    let r = one(&s, check, &[(1, o.clone())], confirmed);
                    if r.status == FindingStatus::Pass {
                        let replied = matches!(o, ProbeOutcome::Refused { .. });
                        let silent_ok = *o == SILENT && confirmed && check != CheckId::S01;
                        assert!(
                            replied && check == CheckId::S01 || silent_ok,
                            "{check:?} {o:?} {confirmed}"
                        );
                    }
                    if r.status == FindingStatus::Fail {
                        assert!(r
                            .verified
                            .iter()
                            .any(|c| matches!(c, Claim::TcpAccepted | Claim::TcpReset)));
                    }
                }
            }
        }
    }

    #[test]
    fn wire_format() {
        let v = serde_json::to_value(CheckId::N01).unwrap();
        assert_eq!(v, serde_json::json!("N01"));
        let v = serde_json::to_value(Reason::SilentConfirmedListener).unwrap();
        assert_eq!(v, serde_json::json!("silent_confirmed_listener"));
    }
}

/// One probe record, tagged with the check it was planned for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckProbe {
    pub check: CheckId,
    pub record: ProbeRecord,
}

/// Everything one run of the checks produced. Stored as a sealed `findings`
/// record in the session; this is the evidence behind each result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChecksRun {
    pub id: String,
    pub scope_id: String,
    pub started_at_ms: i64,
    pub finished_at_ms: i64,
    /// Emergency Stop was pressed during the run.
    pub stopped: bool,
    /// The user confirmed their listeners (receiver, test POS) were running.
    pub receiver_confirmed: bool,
    /// Where the Mac stood, copied from the scope (`Unknown` in older runs).
    #[serde(default)]
    pub vantage: NetworkPosition,
    pub probes: Vec<CheckProbe>,
    pub results: Vec<CheckResult>,
}

/// Plan, probe and evaluate. `authorize` is asked before every probe.
#[allow(clippy::too_many_arguments)]
pub fn run_checks(
    id: String,
    scope: &Scope,
    receiver_confirmed: bool,
    authorize: impl FnMut(ProbeRequest) -> Result<crate::scope::Grant, crate::scope::ScopeDenied>,
    connector: &dyn crate::probe::Connector,
    clock: &dyn crate::probe::Clock,
    stop: &crate::probe::StopFlag,
    mut progress: impl FnMut(usize, usize, &ProbeRecord),
) -> ChecksRun {
    let planned = plan(scope);
    let requests: Vec<ProbeRequest> = planned.iter().map(|(_, r)| *r).collect();
    let total = requests.len();
    let started_at_ms = clock.now_ms();
    let mut done = 0;
    let records = crate::probe::run(
        &requests,
        scope.budget.max_probes_per_second,
        authorize,
        connector,
        clock,
        stop,
        |r| {
            done += 1;
            progress(done, total, r);
        },
    );
    let tagged: Vec<(CheckId, ProbeRecord)> =
        planned.iter().map(|(c, _)| *c).zip(records).collect();
    let results = evaluate(scope, &tagged, receiver_confirmed);
    ChecksRun {
        id,
        scope_id: scope.id.clone(),
        started_at_ms,
        finished_at_ms: clock.now_ms(),
        stopped: stop.is_stopped(),
        receiver_confirmed,
        vantage: scope.vantage,
        probes: tagged
            .into_iter()
            .map(|(check, record)| CheckProbe { check, record })
            .collect(),
        results,
    }
}

#[cfg(test)]
mod run_tests {
    use super::*;
    use crate::probe::{Clock, Connector, StopFlag};
    use crate::scope::{approve, authorize, ScopeDraft, TargetDraft};
    use calm_domain::NetworkBinding;
    use std::cell::Cell;
    use std::time::{Duration, Instant};

    const NOW: i64 = 1_800_000_000_000;

    struct Net;
    impl Connector for Net {
        fn connect(&self, a: std::net::SocketAddr, _: Duration) -> std::io::Result<()> {
            match a.port() {
                443 => Ok(()),
                _ => Err(std::io::ErrorKind::TimedOut.into()),
            }
        }
    }
    struct Fake(Cell<i64>);
    impl Clock for Fake {
        fn now_ms(&self) -> i64 {
            self.0.get()
        }
        fn elapsed_ms(&self, _: Instant) -> u64 {
            0
        }
        fn sleep(&self, d: Duration) {
            self.0.set(self.0.get() + d.as_millis() as i64)
        }
    }

    #[test]
    fn a_run_keeps_its_evidence_and_results() {
        let net = NetworkBinding {
            gateway: "192.168.68.1".into(),
            subnet: None,
            ssid: None,
        };
        let d = ScopeDraft {
            authorization_reference: "ROE".into(),
            operator: "A".into(),
            granted_by: "O".into(),
            targets: vec![
                TargetDraft {
                    address: "192.168.68.1".into(),
                    ports: vec![443],
                    role: TargetRole::AdminInterface,
                    label: "router".into(),
                },
                TargetDraft {
                    address: "192.168.68.50".into(),
                    ports: vec![9999],
                    role: TargetRole::CooperativeReceiver,
                    label: String::new(),
                },
            ],
            expires_at_ms: NOW + 3_600_000,
            max_probes_per_second: 5,
            timeout_ms: 1000,
            authorization_confirmed: true,
            vantage: Some(calm_domain::NetworkPosition::Guest),
            ..Default::default()
        };
        let scope = approve(&d, "sc".into(), "s".into(), Some(net.clone()), NOW).unwrap();
        let clock = Fake(Cell::new(NOW + 10));
        let mut seen = vec![];
        let run = run_checks(
            "run-1".into(),
            &scope,
            true,
            |r| authorize(Some(&scope), false, r, clock.now_ms(), Some(&net)),
            &Net,
            &clock,
            &StopFlag::default(),
            |done, total, _| seen.push((done, total)),
        );
        assert_eq!(seen, vec![(1, 2), (2, 2)]);
        assert_eq!(run.probes.len(), 2);
        assert_eq!(run.probes[0].check, CheckId::S01);
        assert_eq!(
            (run.started_at_ms, run.finished_at_ms),
            (NOW + 10, NOW + 210)
        );
        assert!(!run.stopped);
        let s01 = run
            .results
            .iter()
            .find(|r| r.check == CheckId::S01)
            .unwrap();
        assert_eq!(
            (s01.status, s01.label.as_str()),
            (FindingStatus::Fail, "router")
        );
        let n01 = run
            .results
            .iter()
            .find(|r| r.check == CheckId::N01)
            .unwrap();
        assert_eq!(n01.status, FindingStatus::Pass);
        let n03 = run
            .results
            .iter()
            .find(|r| r.check == CheckId::N03)
            .unwrap();
        assert_eq!(n03.status, FindingStatus::NotTested);
        assert_eq!(run.vantage, calm_domain::NetworkPosition::Guest);
        let json = serde_json::to_string(&run).unwrap();
        let back: ChecksRun = serde_json::from_str(&json).unwrap();
        assert_eq!(back, run);
        // Runs stored before these fields still read.
        let mut old: serde_json::Value = serde_json::from_str(&json).unwrap();
        old.as_object_mut().unwrap().remove("vantage");
        old["results"][0]["confidence"] = serde_json::json!("high");
        let back: ChecksRun = serde_json::from_value(old).unwrap();
        assert_eq!(back.vantage, calm_domain::NetworkPosition::Unknown);
    }
}
