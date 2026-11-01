//! AT-04: replaying the synthetic fixture yields exactly the golden protocol,
//! time and direction data. AT-16: damaged files are contained.
//!
//! Regenerate the golden file only after reviewing the change:
//!     CALM_BLESS=1 cargo test -p calm-flow-engine --test import_fixture

use std::path::PathBuf;

use calm_flow_engine::import::replay_bytes;
use calm_flow_engine::pcap::ErrorReason;
use calm_flow_engine::{CaptureOrigin, Direction, Initiator, Transport};
use serde_json::{json, Value};

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/pcap")
}

fn golden_view(bytes: &[u8]) -> Value {
    let r = replay_bytes(bytes, 20_000).expect("header readable");
    let s = &r.summary;
    let mut flows = r.table.all_flows();
    flows.sort_by(|a, b| format!("{:?}", a.key).cmp(&format!("{:?}", b.key)));
    let snap = r.table.snapshot(0);
    json!({
        "format": s.format,
        "frames": s.frames,
        "ethernet_frames": s.ethernet_frames,
        "unsupported_link_frames": s.unsupported_link_frames,
        "unparsed_frames": snap.unparsed_frames,
        "first_ts_ms": s.first_ts_ms,
        "last_ts_ms": s.last_ts_ms,
        "error": s.error,
        "vantage": s.vantage,
        "total_packets": snap.total_packets,
        "total_bytes": snap.total_bytes,
        "series_seconds": snap.series.len(),
        "flows": flows.iter().map(|f| json!({
            "transport": f.key.transport,
            "local": format!("{}{}", f.key.local, f.key.local_port.map(|p| format!(":{p}")).unwrap_or_default()),
            "remote": format!("{}{}", f.key.remote, f.key.remote_port.map(|p| format!(":{p}")).unwrap_or_default()),
            "direction": f.direction,
            "initiated_by": f.initiated_by,
            "packets": [f.packets_out, f.packets_in],
            "bytes": [f.bytes_out, f.bytes_in],
            "first_seen_ms": f.first_seen_ms,
            "last_seen_ms": f.last_seen_ms,
        })).collect::<Vec<_>>(),
        "bindings": r.table.bindings().iter().map(|b| json!([b.ip, b.mac, b.frames])).collect::<Vec<_>>(),
    })
}

#[test]
fn at04_fixture_matches_golden() {
    let bytes = std::fs::read(fixtures().join("guest-sample.pcapng")).unwrap();
    let got = golden_view(&bytes);
    let path = fixtures().join("guest-sample.golden.json");
    if std::env::var_os("CALM_BLESS").is_some() {
        std::fs::write(&path, serde_json::to_string_pretty(&got).unwrap() + "\n").unwrap();
    }
    let want: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(
        got, want,
        "replay differs from golden; review, then CALM_BLESS=1"
    );
}

#[test]
fn at04_key_facts_independent_of_golden() {
    let bytes = std::fs::read(fixtures().join("guest-sample.pcapng")).unwrap();
    let r = replay_bytes(&bytes, 20_000).unwrap();
    let s = &r.summary;
    assert_eq!(s.frames, 113);
    assert_eq!(s.vantage.mac.as_deref(), Some("02:ca:1d:00:01:08"));
    let v: Vec<String> = s.vantage.addresses.iter().map(|a| a.to_string()).collect();
    for a in ["192.0.2.108", "fe80::108", "2001:db8:1::108"] {
        assert!(v.contains(&a.to_string()), "vantage has {a}: {v:?}");
    }
    assert_eq!(s.last_ts_ms.unwrap() - s.first_ts_ms.unwrap(), 59_030);
    assert!(s.error.is_none());

    let flows = r.table.all_flows();
    assert!(flows.iter().all(|f| f.origin == CaptureOrigin::Imported));
    let find = |remote: &str, port: Option<u16>| {
        flows
            .iter()
            .find(|f| f.key.remote.to_string() == remote && f.key.remote_port == port)
            .unwrap_or_else(|| panic!("flow to {remote} {port:?}"))
    };
    let web = find("203.0.113.10", Some(443));
    assert_eq!(
        (web.direction, web.initiated_by),
        (Direction::Outbound, Initiator::Local)
    );
    let mid = find("203.0.113.11", Some(443));
    assert_eq!(
        (mid.direction, mid.initiated_by),
        (Direction::Inbound, Initiator::Unknown)
    );
    let ssh = find("192.0.2.105", Some(51515));
    assert_eq!(
        (ssh.direction, ssh.initiated_by),
        (Direction::Inbound, Initiator::Remote)
    );
    let quic = find("203.0.113.20", Some(443));
    assert_eq!(quic.key.transport, Transport::Udp);
    let heard = find("192.0.2.107", Some(5353));
    assert_eq!(heard.direction, Direction::Heard);
    assert_eq!(r.table.snapshot(0).unparsed_frames, 1, "LLDP");

    // Dual-stack evidence: both of peer A's addresses bind to one MAC.
    let b = r.table.bindings();
    let mac_of = |ip: &str| {
        b.iter()
            .filter(|x| x.ip.to_string() == ip)
            .map(|x| x.mac.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(mac_of("192.0.2.100"), mac_of("fe80::a"));
    assert_eq!(mac_of("192.0.2.1"), mac_of("fe80::1"));
}

#[test]
fn at16_truncated_file_is_partial_and_flagged() {
    let bytes = std::fs::read(fixtures().join("guest-sample-truncated.pcapng")).unwrap();
    let r = replay_bytes(&bytes, 20_000).expect("header is intact");
    let e = r.summary.error.as_ref().expect("damage reported");
    assert_eq!(e.reason, ErrorReason::Truncated);
    assert!(r.summary.frames > 0 && r.summary.frames < 113);
    assert!(e.offset as usize <= bytes.len());
}

#[test]
fn at16_not_a_capture_is_rejected() {
    let e = replay_bytes(b"{\"this\": \"is json\"}", 10).err().unwrap();
    assert_eq!(e.reason, ErrorReason::NotACapture);
}

#[test]
fn at16_any_damage_never_panics() {
    let bytes = std::fs::read(fixtures().join("guest-sample.pcapng")).unwrap();
    // Every 7th prefix and a byte flip every 13 bytes across the whole file.
    for n in (0..bytes.len()).step_by(7) {
        let _ = replay_bytes(&bytes[..n], 100);
    }
    for i in (0..bytes.len()).step_by(13) {
        let mut g = bytes.clone();
        g[i] ^= 0xa5;
        let _ = replay_bytes(&g, 100);
    }
}

#[test]
fn import_counts_unsupported_link_types_and_untimed_frames() {
    use calm_flow_engine::pcap::NgWriter;
    // Interface 0 Ethernet (from NgWriter); append a second, 802.11 interface,
    // one packet on it, and a Simple Packet Block (no timestamp).
    let src = std::fs::read(fixtures().join("guest-sample.pcapng")).unwrap();
    let first_frame = {
        let mut r = calm_flow_engine::pcap::Reader::new(&src[..]).unwrap();
        r.next_frame().unwrap().unwrap().data.to_vec()
    };
    let mut w = NgWriter::new(Vec::new(), 1, 96, "en0").unwrap();
    w.packet(1_000_000, &first_frame, first_frame.len() as u32)
        .unwrap();
    let mut out = w.into_inner();
    let block = |out: &mut Vec<u8>, t: u32, body: &[u8]| {
        let mut body = body.to_vec();
        while body.len() % 4 != 0 {
            body.push(0);
        }
        let total = (12 + body.len()) as u32;
        out.extend(t.to_le_bytes());
        out.extend(total.to_le_bytes());
        out.extend(&body);
        out.extend(total.to_le_bytes());
    };
    let mut idb = 105u16.to_le_bytes().to_vec();
    idb.extend([0, 0, 0, 0, 0, 0]);
    block(&mut out, 1, &idb);
    let mut epb = 1u32.to_le_bytes().to_vec();
    epb.extend([0u8; 8]);
    epb.extend(4u32.to_le_bytes());
    epb.extend(4u32.to_le_bytes());
    epb.extend([1, 2, 3, 4]);
    block(&mut out, 6, &epb);
    let mut spb = (first_frame.len() as u32).to_le_bytes().to_vec();
    spb.extend(&first_frame);
    block(&mut out, 3, &spb);

    let r = replay_bytes(&out, 100).unwrap();
    let s = &r.summary;
    assert_eq!(s.frames, 3);
    assert_eq!(s.ethernet_frames, 2);
    assert_eq!(s.unsupported_link_frames, 1);
    assert_eq!(s.linktypes, [1, 105]);
    assert_eq!(s.untimed_frames, 1);
    assert!(s.error.is_none());
}

#[test]
fn opening_the_file_twice_failing_is_an_io_error() {
    let mut calls = 0;
    let e = calm_flow_engine::import::replay(
        || {
            calls += 1;
            Err::<&[u8], _>(std::io::Error::other("gone"))
        },
        10,
    )
    .err()
    .unwrap();
    assert!(matches!(e.reason, ErrorReason::Io { .. }));
}
