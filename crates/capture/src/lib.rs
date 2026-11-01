//! Local capture (M1.3). Runs on a background thread in the Calm process with
//! the user's own privileges: BPF access comes from the `calm_bpf` group grant
//! (`scripts/bpf-access.sh`, WP1 S2), never from root.
//!
//! Guarantees:
//! - snaplen 96: headers only; payload bytes never enter the process (AT-15).
//! - promiscuous mode off: only traffic delivered to this interface.
//! - memory only: nothing is written to disk (persistence arrives in M1.5).

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use calm_flow_engine::{parse, AddressBinding, Flow, FlowSnapshot, FlowTable};
use serde::{Deserialize, Serialize};

pub const SNAPLEN: i32 = 96;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Availability {
    /// BPF can be opened by this process.
    Ready,
    /// `/dev/bpf*` not readable by this user: the group grant is missing.
    PermissionDenied {
        detail: String,
    },
    /// Interface missing or not up.
    NoInterface {
        detail: String,
    },
    Error {
        detail: String,
    },
}

fn classify(e: &pcap::Error) -> Availability {
    let detail = e.to_string();
    let lower = detail.to_lowercase();
    if lower.contains("permission denied") || lower.contains("operation not permitted") {
        Availability::PermissionDenied { detail }
    } else if lower.contains("no such device")
        || lower.contains("doesn't exist")
        || lower.contains("not up")
    {
        Availability::NoInterface { detail }
    } else {
        Availability::Error { detail }
    }
}

fn open(iface: &str) -> Result<pcap::Capture<pcap::Active>, pcap::Error> {
    pcap::Capture::from_device(iface)?
        .promisc(false)
        .snaplen(SNAPLEN)
        .timeout(250)
        .immediate_mode(true)
        .open()?
        .setnonblock()
}

/// Opens and immediately closes a capture to see whether `start` would work.
pub fn probe(iface: &str) -> Availability {
    match open(iface) {
        Ok(_) => Availability::Ready,
        Err(e) => classify(&e),
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureStats {
    /// Packets the kernel delivered to the BPF buffer.
    pub received: u32,
    /// Dropped by the kernel because the buffer was full — shown to the user.
    pub dropped: u32,
    pub if_dropped: u32,
    /// Set if the capture loop ended with an error.
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureView {
    pub running: bool,
    pub interface: String,
    pub started_at_ms: i64,
    pub elapsed_ms: i64,
    pub snaplen: i32,
    pub stats: CaptureStats,
    pub snapshot: FlowSnapshot,
}

pub struct Capture {
    iface: String,
    started_at_ms: i64,
    started: Instant,
    stop: Arc<AtomicBool>,
    running: Arc<AtomicBool>,
    table: Arc<Mutex<FlowTable>>,
    stats: Arc<Mutex<CaptureStats>>,
    thread: Option<JoinHandle<()>>,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

impl Capture {
    /// Starts capturing on `iface`. `local` are this Mac's addresses, used to
    /// orient flows (outbound / inbound / heard).
    pub fn start(iface: &str, local: Vec<IpAddr>) -> Result<Capture, Availability> {
        let mut cap = open(iface).map_err(|e| classify(&e))?;
        let stop = Arc::new(AtomicBool::new(false));
        let running = Arc::new(AtomicBool::new(true));
        let table = Arc::new(Mutex::new(FlowTable::new(local)));
        let stats = Arc::new(Mutex::new(CaptureStats::default()));

        let (stop2, running2, table2, stats2) =
            (stop.clone(), running.clone(), table.clone(), stats.clone());
        let thread = std::thread::Builder::new()
            .name("calm-capture".into())
            .spawn(move || {
                let mut last_stats = Instant::now();
                while !stop2.load(Ordering::Relaxed) {
                    match cap.next_packet() {
                        Ok(p) => {
                            // timeval field types differ per OS (tv_usec is i32 on macOS).
                            #[allow(clippy::unnecessary_cast)]
                            let ts_ms = p.header.ts.tv_sec as i64 * 1000
                                + p.header.ts.tv_usec as i64 / 1000;
                            let meta = parse::ethernet(p.data, ts_ms, p.header.len);
                            if let Ok(mut t) = table2.lock() {
                                match meta {
                                    Some(m) => t.ingest(&m),
                                    None => t.record_unparsed(),
                                }
                            }
                        }
                        Err(pcap::Error::TimeoutExpired) => {
                            std::thread::sleep(Duration::from_millis(5))
                        }
                        Err(e) => {
                            if let Ok(mut s) = stats2.lock() {
                                s.error = Some(e.to_string());
                            }
                            break;
                        }
                    }
                    if last_stats.elapsed() >= Duration::from_secs(1) {
                        if let (Ok(st), Ok(mut s)) = (cap.stats(), stats2.lock()) {
                            s.received = st.received;
                            s.dropped = st.dropped;
                            s.if_dropped = st.if_dropped;
                        }
                        last_stats = Instant::now();
                    }
                }
                running2.store(false, Ordering::Relaxed);
            })
            .map_err(|e| Availability::Error {
                detail: e.to_string(),
            })?;

        Ok(Capture {
            iface: iface.to_owned(),
            started_at_ms: now_ms(),
            started: Instant::now(),
            stop,
            running,
            table,
            stats,
            thread: Some(thread),
        })
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Stops the loop and waits for the thread. Flow data stays readable.
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }

    pub fn view(&self, limit: usize) -> CaptureView {
        CaptureView {
            running: self.is_running(),
            interface: self.iface.clone(),
            started_at_ms: self.started_at_ms,
            elapsed_ms: self.started.elapsed().as_millis() as i64,
            snaplen: SNAPLEN,
            stats: self.stats.lock().map(|s| s.clone()).unwrap_or_default(),
            snapshot: self
                .table
                .lock()
                .map(|t| t.snapshot(limit))
                .unwrap_or_default(),
        }
    }

    pub fn all_flows(&self) -> Vec<Flow> {
        self.table.lock().map(|t| t.all_flows()).unwrap_or_default()
    }

    /// Flows and source IP↔MAC bindings from one lock, for graph building.
    pub fn flows_and_bindings(&self) -> (Vec<Flow>, Vec<AddressBinding>) {
        self.table
            .lock()
            .map(|t| (t.all_flows(), t.bindings()))
            .unwrap_or_default()
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_interface_is_reported_not_panicked() {
        match probe("calm-does-not-exist0") {
            Availability::Ready => panic!("cannot be ready"),
            Availability::NoInterface { .. }
            | Availability::Error { .. }
            | Availability::PermissionDenied { .. } => {}
        }
    }

    #[test]
    fn availability_serialises_with_state_tag() {
        let v =
            serde_json::to_value(Availability::PermissionDenied { detail: "x".into() }).unwrap();
        assert_eq!(v["state"], "permission_denied");
    }

    #[test]
    fn errors_are_classified_for_the_ui() {
        let e = |m: &str| classify(&pcap::Error::PcapError(m.into()));
        assert!(matches!(
            e("/dev/bpf0: Permission denied"),
            Availability::PermissionDenied { .. }
        ));
        assert!(matches!(
            e("socket: Operation not permitted"),
            Availability::PermissionDenied { .. }
        ));
        assert!(matches!(
            e("en9: No such device exists"),
            Availability::NoInterface { .. }
        ));
        assert!(matches!(
            e("en9: That device doesn't exist"),
            Availability::NoInterface { .. }
        ));
        assert!(matches!(
            e("en0: interface not up"),
            Availability::NoInterface { .. }
        ));
        assert!(matches!(e("something else"), Availability::Error { .. }));
    }

    #[test]
    fn missing_interface_is_not_ready() {
        assert_ne!(probe("calm-no-such-if0"), Availability::Ready);
        assert!(Capture::start("calm-no-such-if0", vec![]).is_err());
    }

    /// Real capture on loopback. Runs where this user may capture (root in
    /// CI containers, or the calm_bpf group on a Mac); otherwise skipped.
    #[test]
    fn loopback_capture_counts_packets_and_stops() {
        let iface = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        let mut c = match Capture::start(iface, vec!["127.0.0.1".parse().unwrap()]) {
            Ok(c) => c,
            Err(Availability::PermissionDenied { .. }) => {
                eprintln!("skipped: no capture permission for this user");
                return;
            }
            Err(e) => panic!("{e:?}"),
        };
        assert!(c.is_running());
        let rx = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = rx.local_addr().unwrap().port();
        let tx = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        // Wait until the capture sees traffic (BPF needs a moment to attach).
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            tx.send_to(&[0u8; 200], ("127.0.0.1", port)).unwrap();
            std::thread::sleep(Duration::from_millis(20));
            let seen = c
                .all_flows()
                .iter()
                .any(|f| f.key.remote_port == Some(port) || f.key.local_port == Some(port));
            if seen {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(300));
        c.stop();
        assert!(!c.is_running());
        let v = c.view(50);
        assert_eq!(v.snaplen, SNAPLEN);
        assert!(!v.running);
        if cfg!(target_os = "macos") {
            // lo0 is DLT_NULL, not Ethernet: frames are counted as unparsed.
            assert!(v.snapshot.unparsed_frames + v.snapshot.total_packets > 0);
        } else {
            let f = v
                .snapshot
                .flows
                .iter()
                .find(|f| f.key.remote_port == Some(port) || f.key.local_port == Some(port))
                .expect("loopback flow captured");
            assert!(f.bytes_out + f.bytes_in >= 200, "wire length counted");
            let (flows, _) = c.flows_and_bindings();
            assert!(!flows.is_empty());
        }
    }
}
