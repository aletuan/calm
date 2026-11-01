//! WP1 S2 spike. Opens a libpcap capture on one interface with a 96-byte
//! snaplen (headers only, no payload kept), counts packets for N seconds and
//! prints one JSON line. Never prints packet contents.
//!
//! Usage: bpf-probe [--iface en0] [--secs 30] [--label unprivileged]

use std::time::{Duration, Instant};

fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned())
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn main() {
    let label = arg("--label").unwrap_or_else(|| "run".into());
    let secs: u64 = arg("--secs").and_then(|s| s.parse().ok()).unwrap_or(30);
    let iface = arg("--iface").unwrap_or_else(|| "en0".into());
    let sudo = std::env::var("SUDO_USER").is_ok();

    let opened = pcap::Capture::from_device(iface.as_str())
        .and_then(|c| c.promisc(false).snaplen(96).timeout(250).immediate_mode(true).open())
        // Non-blocking so the deadline is honoured even on a silent interface.
        .and_then(|c| c.setnonblock());

    let mut cap = match opened {
        Ok(c) => c,
        Err(e) => {
            println!(
                "{{\"label\":\"{}\",\"iface\":\"{}\",\"via_sudo\":{},\"ok\":false,\"stage\":\"open\",\"error\":\"{}\"}}",
                esc(&label), esc(&iface), sudo, esc(&e.to_string())
            );
            std::process::exit(2);
        }
    };

    let start = Instant::now();
    let deadline = start + Duration::from_secs(secs);
    let (mut pkts, mut bytes, mut max_caplen) = (0u64, 0u64, 0u32);
    let mut err: Option<String> = None;
    while Instant::now() < deadline {
        match cap.next_packet() {
            Ok(p) => {
                pkts += 1;
                bytes += u64::from(p.header.len);
                max_caplen = max_caplen.max(p.header.caplen);
            }
            Err(pcap::Error::TimeoutExpired) => std::thread::sleep(Duration::from_millis(2)),
            Err(e) => {
                err = Some(e.to_string());
                break;
            }
        }
    }
    let elapsed = start.elapsed().as_secs_f64();
    let (recv, drop, ifdrop) = cap
        .stats()
        .map(|s| (s.received, s.dropped, s.if_dropped))
        .unwrap_or((0, 0, 0));
    println!(
        "{{\"label\":\"{}\",\"iface\":\"{}\",\"via_sudo\":{},\"ok\":{},\"secs\":{:.1},\"packets\":{},\"wire_bytes\":{},\"pps\":{:.0},\"mbps_wire\":{:.2},\"max_caplen\":{},\"stats_received\":{},\"stats_dropped\":{},\"stats_if_dropped\":{},\"error\":{}}}",
        esc(&label), esc(&iface), sudo, err.is_none(), elapsed, pkts, bytes,
        pkts as f64 / elapsed, bytes as f64 * 8.0 / elapsed / 1e6, max_caplen,
        recv, drop, ifdrop,
        err.map(|e| format!("\"{}\"", esc(&e))).unwrap_or_else(|| "null".into())
    );
}
