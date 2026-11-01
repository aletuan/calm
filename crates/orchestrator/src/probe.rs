//! Probe runner (M2.2): TCP connect only, one target at a time.
//!
//! - Every probe is authorized again immediately before it is sent; a denial
//!   is recorded and nothing is sent.
//! - Probes are paced to the scope's budget (probes per second).
//! - A stop flag (Emergency Stop) is checked before each probe and while
//!   waiting; a connect already in flight ends at the latest at its timeout.
//! - A connection that succeeds is closed at once: nothing is sent on it.

use std::io;
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use calm_domain::TargetRole;
use serde::{Deserialize, Serialize};

use crate::scope::{Grant, ProbeRequest, ScopeDenied};

/// What happened to one probe. Kept close to what the network said.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProbeOutcome {
    /// TCP handshake completed: something accepted the connection.
    Connected { rtt_ms: u64 },
    /// The host answered with a reset: reachable, nothing listening there.
    Refused { rtt_ms: u64 },
    /// No answer within the timeout: filtered, dropped or host absent.
    TimedOut,
    /// The local stack reported no route / host unreachable, or another error.
    Unreachable { detail: String },
    /// The scope engine refused; nothing was sent.
    Denied { reason: ScopeDenied },
    /// Emergency Stop before this probe was sent.
    Cancelled,
}

impl ProbeOutcome {
    /// Did packets leave this Mac for this probe?
    pub fn sent(&self) -> bool {
        !matches!(self, ProbeOutcome::Denied { .. } | ProbeOutcome::Cancelled)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeRecord {
    /// "address:port" as requested.
    pub target: String,
    pub role: Option<TargetRole>,
    pub scope_id: Option<String>,
    pub started_at_ms: i64,
    pub outcome: ProbeOutcome,
}

/// Opens (and immediately closes) a TCP connection. A trait so tests can
/// script the network.
pub trait Connector {
    fn connect(&self, addr: SocketAddr, timeout: Duration) -> io::Result<()>;
}

pub struct TcpConnector;

impl Connector for TcpConnector {
    fn connect(&self, addr: SocketAddr, timeout: Duration) -> io::Result<()> {
        let s = TcpStream::connect_timeout(&addr, timeout)?;
        let _ = s.shutdown(std::net::Shutdown::Both);
        Ok(())
    }
}

/// Wall clock and sleeping, injectable for tests.
pub trait Clock {
    fn now_ms(&self) -> i64;
    fn elapsed_ms(&self, since: Instant) -> u64 {
        since.elapsed().as_millis() as u64
    }
    fn sleep(&self, d: Duration);
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }
    fn sleep(&self, d: Duration) {
        std::thread::sleep(d)
    }
}

/// Emergency Stop. Cloned into every job; setting it is permanent for the run.
#[derive(Debug, Clone, Default)]
pub struct StopFlag(Arc<AtomicBool>);

impl StopFlag {
    pub fn stop(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
    pub fn is_stopped(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

pub fn classify(r: io::Result<()>, rtt_ms: u64) -> ProbeOutcome {
    match r {
        Ok(()) => ProbeOutcome::Connected { rtt_ms },
        Err(e) => match e.kind() {
            io::ErrorKind::ConnectionRefused => ProbeOutcome::Refused { rtt_ms },
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => ProbeOutcome::TimedOut,
            io::ErrorKind::HostUnreachable => ProbeOutcome::Unreachable {
                detail: "host_unreachable".into(),
            },
            io::ErrorKind::NetworkUnreachable => ProbeOutcome::Unreachable {
                detail: "network_unreachable".into(),
            },
            _ => ProbeOutcome::Unreachable {
                detail: e.kind().to_string(),
            },
        },
    }
}

/// Wait `d` in short slices so a stop is noticed quickly. Returns false if stopped.
fn wait(clock: &dyn Clock, d: Duration, stop: &StopFlag) -> bool {
    let slice = Duration::from_millis(50);
    let mut left = d;
    while !left.is_zero() {
        if stop.is_stopped() {
            return false;
        }
        let step = left.min(slice);
        clock.sleep(step);
        left = left.saturating_sub(step);
    }
    !stop.is_stopped()
}

/// Run `plan` in order. `authorize` is asked right before each probe.
/// `on_record` sees each record as it is made (progress, audit).
pub fn run(
    plan: &[ProbeRequest],
    probes_per_second: u32,
    mut authorize: impl FnMut(ProbeRequest) -> Result<Grant, ScopeDenied>,
    connector: &dyn Connector,
    clock: &dyn Clock,
    stop: &StopFlag,
    mut on_record: impl FnMut(&ProbeRecord),
) -> Vec<ProbeRecord> {
    let interval = Duration::from_millis(1000 / u64::from(probes_per_second.max(1)));
    let mut out = Vec::with_capacity(plan.len());
    let mut last_sent: Option<Instant> = None;
    for req in plan {
        let target = SocketAddr::new(req.address, req.port).to_string();
        let mut record = |outcome, grant: Option<&Grant>, at| {
            let r = ProbeRecord {
                target: target.clone(),
                role: grant.map(Grant::role),
                scope_id: grant.map(|g| g.scope_id().to_owned()),
                started_at_ms: at,
                outcome,
            };
            on_record(&r);
            out.push(r);
        };
        if let Some(t) = last_sent {
            let since = Duration::from_millis(clock.elapsed_ms(t));
            if since < interval && !wait(clock, interval - since, stop) {
                record(ProbeOutcome::Cancelled, None, clock.now_ms());
                continue;
            }
        }
        if stop.is_stopped() {
            record(ProbeOutcome::Cancelled, None, clock.now_ms());
            continue;
        }
        let grant = match authorize(*req) {
            Ok(g) => g,
            Err(reason) => {
                record(ProbeOutcome::Denied { reason }, None, clock.now_ms());
                continue;
            }
        };
        let at = clock.now_ms();
        let t0 = Instant::now();
        last_sent = Some(t0);
        let res = connector.connect(grant.addr(), grant.timeout());
        let rtt = clock.elapsed_ms(t0);
        record(classify(res, rtt), Some(&grant), at);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::{approve, authorize, ScopeDraft, TargetDraft};
    use calm_domain::{NetworkBinding, Scope, TestLevel};
    use std::cell::{Cell, RefCell};
    use std::net::TcpListener;

    const NOW: i64 = 1_800_000_000_000;

    fn net() -> NetworkBinding {
        NetworkBinding {
            gateway: "192.168.68.1".into(),
            subnet: None,
            ssid: None,
        }
    }

    fn scope() -> Scope {
        let d = ScopeDraft {
            authorization_reference: "ROE".into(),
            operator: "A".into(),
            granted_by: "O".into(),
            targets: vec![
                TargetDraft {
                    address: "192.168.68.1".into(),
                    ports: vec![80, 443],
                    role: TargetRole::AdminInterface,
                    label: String::new(),
                },
                TargetDraft {
                    address: "10.0.0.9".into(),
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
        approve(&d, "sc".into(), "s".into(), Some(net()), NOW).unwrap()
    }

    fn req(a: &str, p: u16) -> ProbeRequest {
        ProbeRequest {
            address: a.parse().unwrap(),
            port: p,
            level: TestLevel::L1,
        }
    }

    /// Scripted network: answers by port, remembers what it was asked.
    struct Script {
        asked: RefCell<Vec<SocketAddr>>,
    }
    impl Script {
        fn new() -> Self {
            Script {
                asked: RefCell::new(vec![]),
            }
        }
    }
    impl Connector for Script {
        fn connect(&self, addr: SocketAddr, _t: Duration) -> io::Result<()> {
            self.asked.borrow_mut().push(addr);
            match addr.port() {
                443 => Ok(()),
                80 => Err(io::ErrorKind::ConnectionRefused.into()),
                9999 => Err(io::ErrorKind::TimedOut.into()),
                _ => Err(io::ErrorKind::HostUnreachable.into()),
            }
        }
    }

    /// Fake time: sleeping advances it; probes take no time.
    struct FakeClock {
        now: Cell<i64>,
        slept: Cell<u64>,
    }
    impl FakeClock {
        fn new() -> Self {
            FakeClock {
                now: Cell::new(NOW + 1),
                slept: Cell::new(0),
            }
        }
    }
    impl Clock for FakeClock {
        fn now_ms(&self) -> i64 {
            self.now.get()
        }
        fn elapsed_ms(&self, _since: Instant) -> u64 {
            0
        }
        fn sleep(&self, d: Duration) {
            self.slept.set(self.slept.get() + d.as_millis() as u64);
            self.now.set(self.now.get() + d.as_millis() as i64);
        }
    }

    fn auth<'a>(
        s: &'a Scope,
        clock: &'a FakeClock,
    ) -> impl FnMut(ProbeRequest) -> Result<Grant, ScopeDenied> + 'a {
        move |r| authorize(Some(s), false, r, clock.now_ms(), Some(&net()))
    }

    #[test]
    fn outcomes_follow_what_the_network_said() {
        let s = scope();
        let clock = FakeClock::new();
        let net_ = Script::new();
        let plan = [
            req("192.168.68.1", 443),
            req("192.168.68.1", 80),
            req("10.0.0.9", 9999),
        ];
        let recs = run(
            &plan,
            5,
            auth(&s, &clock),
            &net_,
            &clock,
            &StopFlag::default(),
            |_| {},
        );
        let kinds: Vec<_> = recs.iter().map(|r| r.outcome.clone()).collect();
        assert_eq!(
            kinds,
            vec![
                ProbeOutcome::Connected { rtt_ms: 0 },
                ProbeOutcome::Refused { rtt_ms: 0 },
                ProbeOutcome::TimedOut
            ]
        );
        assert_eq!(recs[0].role, Some(TargetRole::AdminInterface));
        assert_eq!(recs[2].role, Some(TargetRole::CooperativeReceiver));
        assert_eq!(recs[0].scope_id.as_deref(), Some("sc"));
        assert_eq!(recs[1].target, "192.168.68.1:80");
    }

    #[test]
    fn nat03_out_of_scope_probes_are_never_sent() {
        let s = scope();
        let clock = FakeClock::new();
        let net_ = Script::new();
        let plan = [
            req("192.168.68.2", 443),
            req("192.168.68.1", 22),
            req("8.8.8.8", 443),
            req("192.168.68.1", 443),
        ];
        let recs = run(
            &plan,
            5,
            auth(&s, &clock),
            &net_,
            &clock,
            &StopFlag::default(),
            |_| {},
        );
        assert_eq!(
            *net_.asked.borrow(),
            vec!["192.168.68.1:443".parse::<SocketAddr>().unwrap()]
        );
        assert!(matches!(
            recs[0].outcome,
            ProbeOutcome::Denied {
                reason: ScopeDenied::TargetNotAllowed
            }
        ));
        assert!(matches!(
            recs[1].outcome,
            ProbeOutcome::Denied {
                reason: ScopeDenied::PortNotAllowed
            }
        ));
        assert!(matches!(
            recs[2].outcome,
            ProbeOutcome::Denied {
                reason: ScopeDenied::AddressNotAllowed
            }
        ));
        assert!(!recs[0].outcome.sent() && recs[3].outcome.sent());
    }

    #[test]
    fn authorization_is_asked_before_every_probe() {
        // The scope expires while the run is going: later probes are denied.
        let s = scope();
        let clock = FakeClock::new();
        clock.now.set(s.expires_at_ms - 250);
        let net_ = Script::new();
        let plan = [req("192.168.68.1", 443), req("192.168.68.1", 80)];
        let recs = run(
            &plan,
            4,
            auth(&s, &clock),
            &net_,
            &clock,
            &StopFlag::default(),
            |_| {},
        );
        assert!(recs[0].outcome.sent());
        assert_eq!(
            recs[1].outcome,
            ProbeOutcome::Denied {
                reason: ScopeDenied::Expired
            }
        );
        assert_eq!(net_.asked.borrow().len(), 1);
    }

    #[test]
    fn probes_are_paced_to_the_budget() {
        let s = scope();
        let clock = FakeClock::new();
        let plan = [
            req("192.168.68.1", 443),
            req("192.168.68.1", 80),
            req("10.0.0.9", 9999),
        ];
        run(
            &plan,
            5,
            auth(&s, &clock),
            &Script::new(),
            &clock,
            &StopFlag::default(),
            |_| {},
        );
        assert_eq!(clock.slept.get(), 400, "two gaps of 200 ms at 5/s");
        let clock = FakeClock::new();
        run(
            &plan[..1],
            5,
            auth(&s, &clock),
            &Script::new(),
            &clock,
            &StopFlag::default(),
            |_| {},
        );
        assert_eq!(clock.slept.get(), 0, "no wait before the first probe");
    }

    #[test]
    fn denied_probes_do_not_consume_the_budget() {
        let s = scope();
        let clock = FakeClock::new();
        let plan = [
            req("8.8.8.8", 1),
            req("8.8.8.8", 2),
            req("192.168.68.1", 443),
        ];
        run(
            &plan,
            5,
            auth(&s, &clock),
            &Script::new(),
            &clock,
            &StopFlag::default(),
            |_| {},
        );
        assert_eq!(clock.slept.get(), 0);
    }

    #[test]
    fn at11_emergency_stop_cancels_what_is_left() {
        let s = scope();
        let clock = FakeClock::new();
        let net_ = Script::new();
        let stop = StopFlag::default();
        let plan = [
            req("192.168.68.1", 443),
            req("192.168.68.1", 80),
            req("10.0.0.9", 9999),
        ];
        let mut seen = 0;
        let recs = run(&plan, 5, auth(&s, &clock), &net_, &clock, &stop, |_| {
            seen += 1;
            if seen == 1 {
                stop.stop();
            }
        });
        assert_eq!(net_.asked.borrow().len(), 1);
        assert_eq!(recs.len(), 3, "every planned probe has a record");
        assert!(recs[1..]
            .iter()
            .all(|r| r.outcome == ProbeOutcome::Cancelled));
        assert!(stop.is_stopped());
    }

    #[test]
    fn a_stop_before_the_run_sends_nothing() {
        let s = scope();
        let clock = FakeClock::new();
        let net_ = Script::new();
        let stop = StopFlag::default();
        stop.stop();
        let recs = run(
            &[req("192.168.68.1", 443)],
            5,
            auth(&s, &clock),
            &net_,
            &clock,
            &stop,
            |_| {},
        );
        assert!(net_.asked.borrow().is_empty());
        assert_eq!(recs[0].outcome, ProbeOutcome::Cancelled);
    }

    #[test]
    fn classify_io_errors() {
        use io::ErrorKind::*;
        assert_eq!(classify(Ok(()), 7), ProbeOutcome::Connected { rtt_ms: 7 });
        assert_eq!(
            classify(Err(ConnectionRefused.into()), 3),
            ProbeOutcome::Refused { rtt_ms: 3 }
        );
        assert_eq!(classify(Err(TimedOut.into()), 0), ProbeOutcome::TimedOut);
        assert_eq!(classify(Err(WouldBlock.into()), 0), ProbeOutcome::TimedOut);
        assert_eq!(
            classify(Err(NetworkUnreachable.into()), 0),
            ProbeOutcome::Unreachable {
                detail: "network_unreachable".into()
            }
        );
        assert!(matches!(
            classify(Err(PermissionDenied.into()), 0),
            ProbeOutcome::Unreachable { .. }
        ));
    }

    #[test]
    fn real_tcp_connect_and_refuse_on_loopback() {
        // The connector itself, outside any scope (loopback is never a target).
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let open = l.local_addr().unwrap();
        assert!(TcpConnector.connect(open, Duration::from_secs(2)).is_ok());
        drop(l);
        let r = TcpConnector.connect(open, Duration::from_secs(2));
        assert_eq!(classify(r, 0), ProbeOutcome::Refused { rtt_ms: 0 });
    }

    #[test]
    fn outcome_wire_format() {
        let v = serde_json::to_value(ProbeOutcome::Denied {
            reason: ScopeDenied::Expired,
        })
        .unwrap();
        assert_eq!(
            v,
            serde_json::json!({"kind": "denied", "reason": {"kind": "expired"}})
        );
    }
}
