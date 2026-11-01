//! PCAP/PCAPNG import and replay (M1.4, FR-003, AT-04, AT-16).
//!
//! An imported file was captured by *some* sensor — not necessarily this Mac,
//! not necessarily this network. Everything derived here carries the
//! `imported` origin, and the capture host inside the file is an inference
//! (the unicast Ethernet address present in most frames), never a fact.
//!
//! Two passes over the file: the first finds the capture host so the second
//! can orient flows (outbound / inbound / heard) relative to it.

use std::collections::HashMap;
use std::io::{self, Read};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::pcap::{ErrorReason, Format, ReadError, Reader, LINKTYPE_ETHERNET};
use crate::{fmt_mac, is_group, mac_is_unicast, parse, FlowTable};

/// The capture host as inferred from the file. Shown as `inferred` with the
/// share of unicast frames that involve it, so a reader can judge it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Vantage {
    pub mac: Option<String>,
    /// Source IPs bound to that MAC, most frequent first (max 16).
    pub addresses: Vec<IpAddr>,
    /// Frames with a unicast Ethernet endpoint that involve the vantage MAC.
    pub involved_frames: u64,
    pub unicast_frames: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImportSummary {
    pub format: Format,
    /// Packet records read (all link types).
    pub frames: u64,
    pub ethernet_frames: u64,
    /// Frames on link types Calm does not decode yet (802.11, loopback…).
    pub unsupported_link_frames: u64,
    pub linktypes: Vec<u16>,
    /// PCAPNG Simple Packet Blocks: no timestamp, the previous one is reused.
    pub untimed_frames: u64,
    pub first_ts_ms: Option<i64>,
    pub last_ts_ms: Option<i64>,
    /// Set when reading stopped early. Everything before `offset` is used.
    pub error: Option<ReadError>,
    pub vantage: Vantage,
}

pub struct Replay {
    pub summary: ImportSummary,
    pub table: FlowTable,
}

const MAX_VANTAGE_ADDRS: usize = 16;
const MAX_MACS: usize = 100_000;

/// Replays a capture file. `open` is called twice (one per pass) and must
/// return the same bytes each time. Fails only when the file header itself is
/// unreadable; any later damage is reported in `summary.error`.
pub fn replay<R, F>(mut open: F, max_flows: usize) -> Result<Replay, ReadError>
where
    R: Read,
    F: FnMut() -> io::Result<R>,
{
    let open_err = |e: io::Error| ReadError {
        offset: 0,
        reason: ErrorReason::Io {
            detail: e.to_string(),
        },
    };

    // Pass 1: capture host.
    let mut reader = Reader::new(open().map_err(open_err)?)?;
    let format = reader.format();
    let mut mac_frames: HashMap<[u8; 6], u64> = HashMap::new();
    let mut mac_ips: HashMap<[u8; 6], HashMap<IpAddr, u64>> = HashMap::new();
    let mut unicast_frames = 0u64;
    let mut error = None;
    loop {
        match reader.next_frame() {
            Ok(Some(f)) => {
                if f.linktype != LINKTYPE_ETHERNET {
                    continue;
                }
                let Some(m) = parse::ethernet(f.data, 0, f.wire_len) else {
                    continue;
                };
                let (Some(s), Some(d)) = (m.src_mac, m.dst_mac) else {
                    continue;
                };
                let (su, du) = (mac_is_unicast(&s), mac_is_unicast(&d));
                if !(su || du) {
                    continue;
                }
                unicast_frames += 1;
                for (mac, uni) in [(s, su), (d, du)] {
                    if uni && (mac_frames.len() < MAX_MACS || mac_frames.contains_key(&mac)) {
                        *mac_frames.entry(mac).or_default() += 1;
                    }
                }
                if su && !is_group(&m.src) && !m.src.is_unspecified() {
                    if let Some(ips) = mac_ips.get_mut(&s) {
                        if ips.len() < 4096 || ips.contains_key(&m.src) {
                            *ips.entry(m.src).or_default() += 1;
                        }
                    } else if mac_ips.len() < MAX_MACS {
                        mac_ips.insert(s, HashMap::from([(m.src, 1)]));
                    }
                }
            }
            Ok(None) => break,
            Err(e) => {
                error = Some(e);
                break;
            }
        }
    }
    // Most-involved MAC; ties broken by address so the result is deterministic.
    let top = mac_frames
        .iter()
        .max_by(|a, b| a.1.cmp(b.1).then(b.0.cmp(a.0)))
        .map(|(m, n)| (*m, *n));
    let vantage = match top {
        Some((mac, n)) => {
            let mut ips: Vec<(IpAddr, u64)> = mac_ips
                .get(&mac)
                .map(|m| m.iter().map(|(ip, c)| (*ip, *c)).collect())
                .unwrap_or_default();
            ips.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            ips.truncate(MAX_VANTAGE_ADDRS);
            Vantage {
                mac: Some(fmt_mac(&mac)),
                addresses: ips.into_iter().map(|(ip, _)| ip).collect(),
                involved_frames: n,
                unicast_frames,
            }
        }
        None => Vantage {
            unicast_frames,
            ..Vantage::default()
        },
    };

    // Pass 2: flows, oriented to the capture host.
    let mut table = FlowTable::new(vantage.addresses.clone())
        .imported()
        .with_limits(max_flows, 86_400);
    let mut reader = Reader::new(open().map_err(open_err)?)?;
    let mut s = ImportSummary {
        format,
        frames: 0,
        ethernet_frames: 0,
        unsupported_link_frames: 0,
        linktypes: Vec::new(),
        untimed_frames: 0,
        first_ts_ms: None,
        last_ts_ms: None,
        error,
        vantage,
    };
    let mut last_ts = 0i64;
    while let Ok(Some(f)) = reader.next_frame() {
        s.frames += 1;
        if !s.linktypes.contains(&f.linktype) && s.linktypes.len() < 32 {
            s.linktypes.push(f.linktype);
        }
        let ts = match f.ts_ms {
            Some(t) => t,
            None => {
                s.untimed_frames += 1;
                last_ts
            }
        };
        last_ts = ts;
        s.first_ts_ms = Some(s.first_ts_ms.map_or(ts, |v| v.min(ts)));
        s.last_ts_ms = Some(s.last_ts_ms.map_or(ts, |v| v.max(ts)));
        if f.linktype != LINKTYPE_ETHERNET {
            s.unsupported_link_frames += 1;
            continue;
        }
        s.ethernet_frames += 1;
        match parse::ethernet(f.data, ts, f.wire_len) {
            Some(m) => table.ingest(&m),
            None => table.record_unparsed(),
        }
    }
    s.linktypes.sort_unstable();
    Ok(Replay { summary: s, table })
}

/// Convenience for in-memory data (tests, small files).
pub fn replay_bytes(bytes: &[u8], max_flows: usize) -> Result<Replay, ReadError> {
    replay(|| Ok(bytes), max_flows)
}
