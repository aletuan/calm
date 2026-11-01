//! Generates the synthetic PCAPNG fixtures in `fixtures/pcap/`.
//!
//!     cargo run -p calm-flow-engine --example make_fixture
//!
//! Every address is reserved for documentation: IPv4 RFC 5737 (192.0.2.0/24
//! as the "guest LAN", 198.51.100.0/24 and 203.0.113.0/24 as the Internet),
//! IPv6 RFC 3849 (2001:db8::/32) plus link-local fe80::/10. MAC addresses are
//! locally administered (02:…). No frame comes from a real network.
//!
//! Scenario, 60 s on a guest Wi-Fi, captured on the host (snaplen 96):
//! - host       02:ca:1d:00:01:08  192.0.2.108  fe80::108  2001:db8:1::108
//! - gateway    02:ca:1d:00:00:01  192.0.2.1    fe80::1    (ARP reply, RA)
//! - peer A     02:ca:1d:00:01:00  192.0.2.100  fe80::a    dual-stack, two-way
//! - peer B     02:ca:1d:00:01:05  192.0.2.105             opens SSH to host; host opens 8009
//! - peer C     02:ca:1d:00:01:07  192.0.2.107             heard only (ARP, mDNS)
//! - peer D     02:ca:1d:00:0d:0d  fe80::d                 heard only (mDNS v6)
//! - DNS 198.51.100.53, HTTPS 203.0.113.10/.11, QUIC 203.0.113.20,
//!   IPv6 HTTPS 2001:db8:ffff::443 — all via the gateway MAC
//! - one LLDP frame (not IP) → counted as unparsed

use std::fs;
use std::path::PathBuf;

use calm_flow_engine::pcap::{NgWriter, LINKTYPE_ETHERNET};
use etherparse::{ArpHardwareId, ArpOperation, ArpPacket, EtherType, Icmpv6Type, PacketBuilder};

const BASE_US: u64 = 1_793_437_200 * 1_000_000; // 2026-10-31T09:00:00Z
const SNAP: usize = 96;

const HOST: [u8; 6] = [0x02, 0xca, 0x1d, 0x00, 0x01, 0x08];
const GW: [u8; 6] = [0x02, 0xca, 0x1d, 0x00, 0x00, 0x01];
const PA: [u8; 6] = [0x02, 0xca, 0x1d, 0x00, 0x01, 0x00];
const PB: [u8; 6] = [0x02, 0xca, 0x1d, 0x00, 0x01, 0x05];
const PC: [u8; 6] = [0x02, 0xca, 0x1d, 0x00, 0x01, 0x07];
const PD: [u8; 6] = [0x02, 0xca, 0x1d, 0x00, 0x0d, 0x0d];
const BCAST: [u8; 6] = [0xff; 6];
const MDNS4: [u8; 6] = [0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb];
const MDNS6: [u8; 6] = [0x33, 0x33, 0x00, 0x00, 0x00, 0xfb];
const ALLNODES6: [u8; 6] = [0x33, 0x33, 0x00, 0x00, 0x00, 0x01];

const H4: [u8; 4] = [192, 0, 2, 108];
const G4: [u8; 4] = [192, 0, 2, 1];
const A4: [u8; 4] = [192, 0, 2, 100];
const B4: [u8; 4] = [192, 0, 2, 105];
const C4: [u8; 4] = [192, 0, 2, 107];
const DNS: [u8; 4] = [198, 51, 100, 53];
const WEB1: [u8; 4] = [203, 0, 113, 10];
const WEB2: [u8; 4] = [203, 0, 113, 11];
const QUIC: [u8; 4] = [203, 0, 113, 20];

fn v6(s: &str) -> [u8; 16] {
    s.parse::<std::net::Ipv6Addr>().unwrap().octets()
}

struct Out {
    frames: Vec<(u64, Vec<u8>)>,
}

impl Out {
    fn push(&mut self, ms: u64, frame: Vec<u8>) {
        self.frames.push((BASE_US + ms * 1000, frame));
    }
    #[allow(clippy::too_many_arguments)]
    fn tcp4(
        &mut self,
        ms: u64,
        m: ([u8; 6], [u8; 6]),
        ip: ([u8; 4], [u8; 4]),
        p: (u16, u16),
        syn: bool,
        ack: bool,
        len: usize,
    ) {
        let b = PacketBuilder::ethernet2(m.0, m.1).ipv4(ip.0, ip.1, 64);
        let mut t = b.tcp(p.0, p.1, 1000, 65535);
        if syn {
            t = t.syn();
        }
        if ack {
            t = t.ack(1);
        }
        let mut f = Vec::new();
        t.write(&mut f, &vec![0u8; len]).unwrap();
        self.push(ms, f);
    }
    fn udp4(
        &mut self,
        ms: u64,
        m: ([u8; 6], [u8; 6]),
        ip: ([u8; 4], [u8; 4]),
        p: (u16, u16),
        len: usize,
    ) {
        let mut f = Vec::new();
        PacketBuilder::ethernet2(m.0, m.1)
            .ipv4(ip.0, ip.1, 64)
            .udp(p.0, p.1)
            .write(&mut f, &vec![0u8; len])
            .unwrap();
        self.push(ms, f);
    }
    fn tcp6(
        &mut self,
        ms: u64,
        m: ([u8; 6], [u8; 6]),
        ip: (&str, &str),
        p: (u16, u16),
        syn: bool,
        len: usize,
    ) {
        let b = PacketBuilder::ethernet2(m.0, m.1).ipv6(v6(ip.0), v6(ip.1), 64);
        let t = if syn {
            b.tcp(p.0, p.1, 1, 65535).syn()
        } else {
            b.tcp(p.0, p.1, 1, 65535).ack(1)
        };
        let mut f = Vec::new();
        t.write(&mut f, &vec![0u8; len]).unwrap();
        self.push(ms, f);
    }
    fn udp6(
        &mut self,
        ms: u64,
        m: ([u8; 6], [u8; 6]),
        ip: (&str, &str),
        p: (u16, u16),
        len: usize,
    ) {
        let mut f = Vec::new();
        PacketBuilder::ethernet2(m.0, m.1)
            .ipv6(v6(ip.0), v6(ip.1), 255)
            .udp(p.0, p.1)
            .write(&mut f, &vec![0u8; len])
            .unwrap();
        self.push(ms, f);
    }
    fn arp(
        &mut self,
        ms: u64,
        m: ([u8; 6], [u8; 6]),
        op: ArpOperation,
        sender: ([u8; 6], [u8; 4]),
        target: ([u8; 6], [u8; 4]),
    ) {
        let a = ArpPacket::new(
            ArpHardwareId::ETHERNET,
            EtherType::IPV4,
            op,
            &sender.0,
            &sender.1,
            &target.0,
            &target.1,
        )
        .unwrap();
        let mut f = Vec::new();
        PacketBuilder::ethernet2(m.0, m.1)
            .arp(a)
            .write(&mut f)
            .unwrap();
        self.push(ms, f);
    }
}

fn scenario() -> Vec<(u64, Vec<u8>)> {
    let mut o = Out { frames: Vec::new() };
    use ArpOperation as Op;

    // 0 s: host resolves the gateway; gateway answers (binds 192.0.2.1 to its MAC).
    o.arp(0, (HOST, BCAST), Op::REQUEST, (HOST, H4), ([0; 6], G4));
    o.arp(2, (GW, HOST), Op::REPLY, (GW, G4), (HOST, H4));
    // Router advertisement from fe80::1 (binds the gateway's link-local address).
    let mut ra = Vec::new();
    PacketBuilder::ethernet2(GW, ALLNODES6)
        .ipv6(v6("fe80::1"), v6("ff02::1"), 255)
        .icmpv6(Icmpv6Type::Unknown {
            type_u8: 134,
            code_u8: 0,
            bytes5to8: [64, 0, 7, 8],
        })
        .write(&mut ra, &[0u8; 48])
        .unwrap();
    o.push(5, ra);

    // 1 s: DNS queries and answers.
    for i in 0..3u64 {
        let t = 1000 + i * 400;
        o.udp4(t, (HOST, GW), (H4, DNS), (53000 + i as u16, 53), 40);
        o.udp4(t + 25, (GW, HOST), (DNS, H4), (53, 53000 + i as u16), 120);
    }

    // 2 s: HTTPS to 203.0.113.10, opened by the host (SYN seen).
    o.tcp4(2000, (HOST, GW), (H4, WEB1), (50100, 443), true, false, 0);
    o.tcp4(2030, (GW, HOST), (WEB1, H4), (443, 50100), true, true, 0);
    o.tcp4(2031, (HOST, GW), (H4, WEB1), (50100, 443), false, true, 0);
    for s in 0..20u64 {
        o.tcp4(
            2100 + s * 500,
            (GW, HOST),
            (WEB1, H4),
            (443, 50100),
            false,
            true,
            1400,
        );
        o.tcp4(
            2120 + s * 500,
            (HOST, GW),
            (H4, WEB1),
            (50100, 443),
            false,
            true,
            0,
        );
    }

    // 3 s: mid-connection traffic from 203.0.113.11 (capture started after the
    // handshake): inbound first, opener unknown.
    for s in 0..6u64 {
        o.tcp4(
            3000 + s * 1000,
            (GW, HOST),
            (WEB2, H4),
            (443, 50200),
            false,
            true,
            600,
        );
        o.tcp4(
            3010 + s * 1000,
            (HOST, GW),
            (H4, WEB2),
            (50200, 443),
            false,
            true,
            0,
        );
    }

    // 4 s: QUIC (UDP 443).
    for s in 0..10u64 {
        o.udp4(4000 + s * 300, (HOST, GW), (H4, QUIC), (51000, 443), 1200);
        o.udp4(4050 + s * 300, (GW, HOST), (QUIC, H4), (443, 51000), 1250);
    }

    // 8 s: IPv6 HTTPS via the gateway.
    o.tcp6(
        8000,
        (HOST, GW),
        ("2001:db8:1::108", "2001:db8:ffff::443"),
        (50300, 443),
        true,
        0,
    );
    for s in 0..5u64 {
        o.tcp6(
            8100 + s * 200,
            (GW, HOST),
            ("2001:db8:ffff::443", "2001:db8:1::108"),
            (443, 50300),
            false,
            1200,
        );
    }

    // 10 s: ICMP echo to the gateway.
    let mut f = Vec::new();
    PacketBuilder::ethernet2(HOST, GW)
        .ipv4(H4, G4, 64)
        .icmpv4_echo_request(7, 1)
        .write(&mut f, &[0u8; 56])
        .unwrap();
    o.push(10_000, f);
    let mut f = Vec::new();
    PacketBuilder::ethernet2(GW, HOST)
        .ipv4(G4, H4, 64)
        .icmpv4_echo_reply(7, 1)
        .write(&mut f, &[0u8; 56])
        .unwrap();
    o.push(10_004, f);

    // 15 s: peer A, dual-stack, talks to the host on both families.
    o.tcp4(15_000, (HOST, PA), (H4, A4), (50400, 8009), true, false, 0);
    o.tcp4(15_005, (PA, HOST), (A4, H4), (8009, 50400), true, true, 0);
    o.tcp4(
        15_200,
        (PA, HOST),
        (A4, H4),
        (8009, 50400),
        false,
        true,
        300,
    );
    o.udp6(
        16_000,
        (PA, HOST),
        ("fe80::a", "fe80::108"),
        (5353, 5353),
        80,
    );
    o.udp6(
        16_010,
        (HOST, PA),
        ("fe80::108", "fe80::a"),
        (5353, 5353),
        80,
    );

    // 20 s: peer B opens SSH to the host (remote-initiated).
    o.tcp4(20_000, (PB, HOST), (B4, H4), (51515, 22), true, false, 0);
    o.tcp4(20_001, (HOST, PB), (H4, B4), (22, 51515), true, true, 0);
    for s in 0..4u64 {
        o.tcp4(
            20_100 + s * 100,
            (PB, HOST),
            (B4, H4),
            (51515, 22),
            false,
            true,
            90,
        );
        o.tcp4(
            20_150 + s * 100,
            (HOST, PB),
            (H4, B4),
            (22, 51515),
            false,
            true,
            200,
        );
    }

    // 30 s: peer C only heard: ARP request for the gateway and mDNS.
    o.arp(30_000, (PC, BCAST), Op::REQUEST, (PC, C4), ([0; 6], G4));
    o.udp4(
        30_500,
        (PC, MDNS4),
        (C4, [224, 0, 0, 251]),
        (5353, 5353),
        160,
    );

    // 40 s: peer D only heard over IPv6 mDNS.
    o.udp6(
        40_000,
        (PD, MDNS6),
        ("fe80::d", "ff02::fb"),
        (5353, 5353),
        140,
    );

    // 50 s: LLDP from the gateway (not IP): unparsed.
    let mut lldp = vec![0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e];
    lldp.extend(GW);
    lldp.extend([0x88, 0xcc]);
    lldp.extend([0u8; 40]);
    o.push(50_000, lldp);

    // 59 s: one last DNS exchange so the capture spans ~60 s.
    o.udp4(59_000, (HOST, GW), (H4, DNS), (53010, 53), 40);
    o.udp4(59_030, (GW, HOST), (DNS, H4), (53, 53010), 120);

    o.frames.sort_by_key(|f| f.0);
    o.frames
}

fn main() {
    let dir = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/pcap"));
    fs::create_dir_all(&dir).unwrap();

    let mut w = NgWriter::new(Vec::new(), LINKTYPE_ETHERNET, SNAP as u32, "en0").unwrap();
    for (ts, f) in scenario() {
        w.packet(ts, &f[..f.len().min(SNAP)], f.len() as u32)
            .unwrap();
    }
    let bytes = w.into_inner();
    fs::write(dir.join("guest-sample.pcapng"), &bytes).unwrap();

    // AT-16: cut in the middle of a packet block, two thirds into the file.
    let cut = bytes.len() * 2 / 3 + 5;
    fs::write(dir.join("guest-sample-truncated.pcapng"), &bytes[..cut]).unwrap();

    println!(
        "wrote {} bytes ({} packets) to {}",
        bytes.len(),
        scenario().len(),
        dir.display()
    );
}
