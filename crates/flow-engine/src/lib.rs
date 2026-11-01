//! Flow engine. Aggregates header metadata into flows and a per-second
//! series. Live capture (M1.3) describes traffic that reached *this Mac's*
//! interface: never a mirror of other clients (R01). Imported files (M1.4)
//! describe what *their* sensor saw and are tagged [`CaptureOrigin::Imported`].

pub mod import;
pub mod parse;
pub mod pcap;
pub mod select;

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

pub use parse::PacketMeta;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Arp,
    Other(u8),
}

/// Where the flow sits relative to this Mac.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// First packet seen was sent by this Mac.
    Outbound,
    /// First packet seen was addressed to this Mac.
    Inbound,
    /// Neither end is this Mac: broadcast/multicast (or stray unicast) that
    /// reached the interface. Proves the sender exists; nothing more.
    Heard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureOrigin {
    /// First-party traffic of this Mac.
    LocalInterface,
    /// Broadcast/multicast that reached this Mac's interface.
    LocalBroadcast,
    /// Imported PCAP/sensor data — external provenance (M1.4).
    Imported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Initiator {
    Local,
    Remote,
    Unknown,
}

/// Flow identity, normalised so both directions land on the same key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowKey {
    pub transport: Transport,
    /// This Mac's address, or the group/broadcast address for `Heard` flows.
    pub local: IpAddr,
    pub local_port: Option<u16>,
    pub remote: IpAddr,
    pub remote_port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Flow {
    pub key: FlowKey,
    pub direction: Direction,
    pub origin: CaptureOrigin,
    pub initiated_by: Initiator,
    pub packets_out: u64,
    pub packets_in: u64,
    pub bytes_out: u64,
    pub bytes_in: u64,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeriesPoint {
    /// Unix seconds.
    pub t: i64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FlowSnapshot {
    pub flows: Vec<Flow>,
    pub total_flows: usize,
    pub total_packets: u64,
    pub total_bytes: u64,
    /// Flows dropped from memory because of the cap. Shown to the user: the
    /// table is then explicitly incomplete.
    pub evicted_flows: u64,
    /// Frames that could not be parsed (not IP/ARP, or malformed).
    pub unparsed_frames: u64,
    pub series: Vec<SeriesPoint>,
    /// Per-minute sums for seconds older than the per-second window, oldest
    /// first (`t` = minute start). Empty for short captures and old records.
    #[serde(default)]
    pub series_minutes: Vec<SeriesPoint>,
    /// Minutes dropped beyond `MAX_MINUTES` (shown: the chart is then partial).
    #[serde(default)]
    pub dropped_minutes: u64,
}

/// One IP address seen as the *source* of frames from one Ethernet address.
/// Evidence that the two belong to the same interface — for on-link senders
/// only: a router forwards off-link traffic under its own MAC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressBinding {
    pub ip: IpAddr,
    pub mac: String,
    pub frames: u64,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
}

pub fn fmt_mac(m: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

/// Unicast, non-zero Ethernet address (group bit clear).
pub fn mac_is_unicast(m: &[u8; 6]) -> bool {
    m[0] & 1 == 0 && m.iter().any(|b| *b != 0)
}

fn is_unicast_ip(ip: &IpAddr) -> bool {
    !is_group(ip) && !ip.is_unspecified()
}

const MAX_BINDINGS: usize = 20_000;
/// Per-minute history kept after the per-second window: 24 h.
pub const MAX_MINUTES: usize = 1440;

fn is_group(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_broadcast() || v4.is_multicast() || v4.octets()[3] == 255,
        IpAddr::V6(v6) => v6.is_multicast(),
    }
}

pub struct FlowTable {
    local: Vec<IpAddr>,
    flows: HashMap<FlowKey, Flow>,
    max_flows: usize,
    evicted: u64,
    unparsed: u64,
    total_packets: u64,
    total_bytes: u64,
    series: VecDeque<SeriesPoint>,
    series_secs: usize,
    minutes: VecDeque<SeriesPoint>,
    dropped_minutes: u64,
    bindings: HashMap<(IpAddr, [u8; 6]), (u64, i64, i64)>,
    imported: bool,
}

impl FlowTable {
    pub fn new(local: Vec<IpAddr>) -> Self {
        Self {
            local,
            flows: HashMap::new(),
            max_flows: 20_000,
            evicted: 0,
            unparsed: 0,
            total_packets: 0,
            total_bytes: 0,
            series: VecDeque::new(),
            series_secs: 600,
            minutes: VecDeque::new(),
            dropped_minutes: 0,
            bindings: HashMap::new(),
            imported: false,
        }
    }

    /// Marks every flow as imported sensor data (not observed by this Mac).
    pub fn imported(mut self) -> Self {
        self.imported = true;
        self
    }

    pub fn with_limits(mut self, max_flows: usize, series_secs: usize) -> Self {
        self.max_flows = max_flows.max(1);
        self.series_secs = series_secs.max(1);
        self
    }

    pub fn record_unparsed(&mut self) {
        self.unparsed += 1;
    }

    fn is_local(&self, ip: &IpAddr) -> bool {
        self.local.contains(ip)
    }

    pub fn ingest(&mut self, m: &PacketMeta) {
        if let Some(mac) = m.src_mac {
            if mac_is_unicast(&mac) && is_unicast_ip(&m.src) {
                let k = (m.src, mac);
                if self.bindings.len() < MAX_BINDINGS || self.bindings.contains_key(&k) {
                    let e = self.bindings.entry(k).or_insert((0, m.ts_ms, m.ts_ms));
                    e.0 += 1;
                    e.1 = e.1.min(m.ts_ms);
                    e.2 = e.2.max(m.ts_ms);
                }
            }
        }
        let (key, outbound, direction, origin) = if self.is_local(&m.src) {
            let k = FlowKey {
                transport: m.transport,
                local: m.src,
                local_port: m.src_port,
                remote: m.dst,
                remote_port: m.dst_port,
            };
            (k, true, Direction::Outbound, CaptureOrigin::LocalInterface)
        } else if self.is_local(&m.dst) {
            let k = FlowKey {
                transport: m.transport,
                local: m.dst,
                local_port: m.dst_port,
                remote: m.src,
                remote_port: m.src_port,
            };
            (k, false, Direction::Inbound, CaptureOrigin::LocalInterface)
        } else {
            // Heard: key on the group address as "local" side, sender as remote.
            let k = FlowKey {
                transport: m.transport,
                local: m.dst,
                local_port: m.dst_port,
                remote: m.src,
                remote_port: m.src_port,
            };
            let origin = if is_group(&m.dst) || m.transport == Transport::Arp {
                CaptureOrigin::LocalBroadcast
            } else {
                CaptureOrigin::LocalInterface
            };
            (k, false, Direction::Heard, origin)
        };

        if !self.flows.contains_key(&key) && self.flows.len() >= self.max_flows {
            if let Some(oldest) = self
                .flows
                .values()
                .min_by_key(|f| f.last_seen_ms)
                .map(|f| f.key.clone())
            {
                self.flows.remove(&oldest);
                self.evicted += 1;
            }
        }

        let origin = if self.imported {
            CaptureOrigin::Imported
        } else {
            origin
        };
        let bytes = u64::from(m.wire_len);
        let f = self.flows.entry(key.clone()).or_insert_with(|| Flow {
            key,
            direction,
            origin,
            initiated_by: Initiator::Unknown,
            packets_out: 0,
            packets_in: 0,
            bytes_out: 0,
            bytes_in: 0,
            first_seen_ms: m.ts_ms,
            last_seen_ms: m.ts_ms,
        });
        if m.tcp_open && f.initiated_by == Initiator::Unknown {
            f.initiated_by = if outbound {
                Initiator::Local
            } else {
                Initiator::Remote
            };
        }
        if outbound {
            f.packets_out += 1;
            f.bytes_out += bytes;
        } else {
            f.packets_in += 1;
            f.bytes_in += bytes;
        }
        f.first_seen_ms = f.first_seen_ms.min(m.ts_ms);
        f.last_seen_ms = f.last_seen_ms.max(m.ts_ms);

        self.total_packets += 1;
        self.total_bytes += bytes;

        let sec = m.ts_ms.div_euclid(1000);
        match self.series.back_mut() {
            Some(p) if p.t == sec => {
                p.packets += 1;
                if outbound {
                    p.bytes_out += bytes
                } else {
                    p.bytes_in += bytes
                }
            }
            Some(p) if p.t > sec => {} // late packet beyond current second: totals only
            _ => {
                self.series.push_back(SeriesPoint {
                    t: sec,
                    bytes_in: if outbound { 0 } else { bytes },
                    bytes_out: if outbound { bytes } else { 0 },
                    packets: 1,
                });
                while self.series.len() > self.series_secs {
                    if let Some(old) = self.series.pop_front() {
                        self.roll_into_minute(old);
                    }
                }
            }
        }
    }

    /// Adds a second that left the per-second window to its minute bucket.
    fn roll_into_minute(&mut self, p: SeriesPoint) {
        let minute = p.t.div_euclid(60) * 60;
        match self.minutes.back_mut() {
            Some(m) if m.t == minute => {
                m.bytes_in += p.bytes_in;
                m.bytes_out += p.bytes_out;
                m.packets += p.packets;
            }
            _ => {
                self.minutes.push_back(SeriesPoint { t: minute, ..p });
                while self.minutes.len() > MAX_MINUTES {
                    self.minutes.pop_front();
                    self.dropped_minutes += 1;
                }
            }
        }
    }

    /// Top `limit` flows by bytes, plus totals and the full series.
    pub fn snapshot(&self, limit: usize) -> FlowSnapshot {
        let mut flows: Vec<Flow> = self.flows.values().cloned().collect();
        flows.sort_by(|a, b| {
            (b.bytes_in + b.bytes_out)
                .cmp(&(a.bytes_in + a.bytes_out))
                .then(b.last_seen_ms.cmp(&a.last_seen_ms))
        });
        flows.truncate(limit);
        FlowSnapshot {
            flows,
            total_flows: self.flows.len(),
            total_packets: self.total_packets,
            total_bytes: self.total_bytes,
            evicted_flows: self.evicted,
            unparsed_frames: self.unparsed,
            series: self.series.iter().copied().collect(),
            series_minutes: self.minutes.iter().copied().collect(),
            dropped_minutes: self.dropped_minutes,
        }
    }

    /// Every flow (for graph building), unsorted.
    pub fn all_flows(&self) -> Vec<Flow> {
        self.flows.values().cloned().collect()
    }

    /// Source IP ↔ source MAC pairs seen, sorted by IP then MAC.
    pub fn bindings(&self) -> Vec<AddressBinding> {
        let mut v: Vec<AddressBinding> = self
            .bindings
            .iter()
            .map(|((ip, mac), (n, a, b))| AddressBinding {
                ip: *ip,
                mac: fmt_mac(mac),
                frames: *n,
                first_seen_ms: *a,
                last_seen_ms: *b,
            })
            .collect();
        v.sort_by(|a, b| a.ip.cmp(&b.ip).then(a.mac.cmp(&b.mac)));
        v
    }
}

#[cfg(test)]
mod tests {
    use super::parse::tests::{tcp_frame, udp_frame};
    use super::*;
    use std::net::Ipv4Addr;

    const ME: [u8; 4] = [192, 0, 2, 108];
    fn me() -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(ME))
    }

    fn feed(t: &mut FlowTable, frame: Vec<u8>, ts: i64) {
        let wire = frame.len() as u32;
        match parse::ethernet(&frame[..frame.len().min(96)], ts, wire) {
            Some(m) => t.ingest(&m),
            None => t.record_unparsed(),
        }
    }

    #[test]
    fn both_directions_merge_into_one_flow_with_initiator() {
        let mut t = FlowTable::new(vec![me()]);
        feed(
            &mut t,
            tcp_frame(ME, [198, 51, 100, 7], 50000, 443, true, 0),
            1_000,
        );
        feed(
            &mut t,
            tcp_frame([198, 51, 100, 7], ME, 443, 50000, false, 1400),
            1_050,
        );
        let s = t.snapshot(10);
        assert_eq!(s.total_flows, 1);
        let f = &s.flows[0];
        assert_eq!(f.direction, Direction::Outbound);
        assert_eq!(f.initiated_by, Initiator::Local);
        assert_eq!((f.packets_out, f.packets_in), (1, 1));
        assert!(
            f.bytes_in > 1400,
            "wire length counted, not truncated length"
        );
        assert_eq!(f.origin, CaptureOrigin::LocalInterface);
    }

    #[test]
    fn broadcast_from_peer_is_heard_not_ours() {
        let mut t = FlowTable::new(vec![me()]);
        feed(
            &mut t,
            udp_frame([192, 0, 2, 50], [192, 0, 2, 255], 137, 137, 50),
            5_000,
        );
        let f = &t.snapshot(10).flows[0];
        assert_eq!(f.direction, Direction::Heard);
        assert_eq!(f.origin, CaptureOrigin::LocalBroadcast);
        assert_eq!(f.key.remote, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)));
        assert_eq!(f.initiated_by, Initiator::Unknown);
    }

    #[test]
    fn series_buckets_per_second() {
        let mut t = FlowTable::new(vec![me()]);
        feed(
            &mut t,
            tcp_frame(ME, [198, 51, 100, 7], 1, 443, false, 100),
            10_100,
        );
        feed(
            &mut t,
            tcp_frame(ME, [198, 51, 100, 7], 1, 443, false, 100),
            10_900,
        );
        feed(
            &mut t,
            tcp_frame([198, 51, 100, 7], ME, 443, 1, false, 100),
            11_200,
        );
        let s = t.snapshot(10);
        assert_eq!(s.series.len(), 2);
        assert_eq!(s.series[0].t, 10);
        assert_eq!(s.series[0].packets, 2);
        assert!(s.series[0].bytes_out > 0 && s.series[0].bytes_in == 0);
        assert!(s.series[1].bytes_in > 0);
    }

    #[test]
    fn seconds_older_than_the_window_roll_into_minutes() {
        // 700 s of traffic, 1 packet per second, window of 600 s.
        let mut t = FlowTable::new(vec![me()]).with_limits(100, 600);
        let start = 1_800_000_000; // a minute boundary (divisible by 60)
        assert_eq!(start % 60, 0);
        for s in 0..700i64 {
            feed(
                &mut t,
                tcp_frame(ME, [198, 51, 100, 7], 1, 443, false, 100),
                (start + s) * 1000,
            );
        }
        let snap = t.snapshot(1);
        assert_eq!(snap.series.len(), 600, "per-second window kept");
        assert_eq!(snap.series[0].t, start + 100);
        // The first 100 s became minutes: 60 s + 40 s.
        let m = &snap.series_minutes;
        assert_eq!(
            m.iter().map(|p| p.t).collect::<Vec<_>>(),
            [start, start + 60]
        );
        assert_eq!(m.iter().map(|p| p.packets).collect::<Vec<_>>(), [60, 40]);
        // Nothing lost: minutes + seconds account for every byte.
        let bytes = |v: &[SeriesPoint]| v.iter().map(|p| p.bytes_out + p.bytes_in).sum::<u64>();
        assert_eq!(bytes(m) + bytes(&snap.series), snap.total_bytes);
    }

    #[test]
    fn minute_history_is_bounded() {
        let mut t = FlowTable::new(vec![me()]).with_limits(10, 1);
        for s in 0..(60 * (MAX_MINUTES as i64 + 5)) {
            feed(
                &mut t,
                tcp_frame(ME, [198, 51, 100, 7], 1, 443, false, 0),
                s * 1000,
            );
        }
        let snap = t.snapshot(0);
        assert_eq!(snap.series_minutes.len(), MAX_MINUTES);
        assert!(snap.dropped_minutes > 0, "dropping old minutes is reported");
    }

    #[test]
    fn cap_evicts_oldest_and_counts_it() {
        let mut t = FlowTable::new(vec![me()]).with_limits(2, 60);
        for (i, port) in [1000u16, 1001, 1002].into_iter().enumerate() {
            feed(
                &mut t,
                tcp_frame(ME, [198, 51, 100, 7], port, 443, false, 10),
                i as i64 * 1000,
            );
        }
        let s = t.snapshot(10);
        assert_eq!(s.total_flows, 2);
        assert_eq!(s.evicted_flows, 1);
        assert!(
            s.flows.iter().all(|f| f.key.local_port != Some(1000)),
            "oldest evicted"
        );
    }

    #[test]
    fn source_bindings_skip_groups_and_imported_marks_origin() {
        let mut t = FlowTable::new(vec![me()]).imported();
        feed(
            &mut t,
            udp_frame([192, 0, 2, 50], [192, 0, 2, 255], 137, 137, 10),
            0,
        );
        feed(
            &mut t,
            udp_frame([0, 0, 0, 0], [255, 255, 255, 255], 68, 67, 10),
            0,
        );
        let b = t.bindings();
        assert_eq!(b.len(), 1, "0.0.0.0 is not an identity");
        assert_eq!(b[0].ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)));
        assert_eq!(b[0].mac, "02:00:00:00:00:01");
        assert!(t
            .snapshot(10)
            .flows
            .iter()
            .all(|f| f.origin == CaptureOrigin::Imported));
    }

    #[test]
    fn unparsable_frames_are_counted() {
        let mut t = FlowTable::new(vec![me()]);
        feed(&mut t, vec![0u8; 10], 0);
        assert_eq!(t.snapshot(1).unparsed_frames, 1);
        assert_eq!(t.snapshot(1).total_packets, 0);
    }
}
