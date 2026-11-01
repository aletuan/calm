//! Header-only parsing of captured Ethernet frames. Input is untrusted and
//! usually truncated by the 96-byte snaplen, so the lax parser is used and any
//! malformed frame yields `None` — never a panic.

use std::net::{IpAddr, Ipv4Addr};

use etherparse::{LaxNetSlice, LaxSlicedPacket, LinkSlice, TransportSlice};

use crate::Transport;

/// What one captured frame tells us. No payload is kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketMeta {
    /// Capture timestamp, Unix milliseconds.
    pub ts_ms: i64,
    /// Original length on the wire (not the truncated capture length).
    pub wire_len: u32,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub transport: Transport,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    /// TCP SYN without ACK: the sender is opening the connection.
    pub tcp_open: bool,
    /// Ethernet source address: binds `src` to a link-layer identity. Only
    /// meaningful for on-link senders (off-link traffic carries the router's).
    pub src_mac: Option<[u8; 6]>,
    pub dst_mac: Option<[u8; 6]>,
}

/// Parses an Ethernet II frame (macOS Wi-Fi in managed mode delivers these).
pub fn ethernet(data: &[u8], ts_ms: i64, wire_len: u32) -> Option<PacketMeta> {
    let p = LaxSlicedPacket::from_ethernet(data).ok()?;
    let (src_mac, dst_mac) = match &p.link {
        Some(LinkSlice::Ethernet2(e)) => (Some(e.source()), Some(e.destination())),
        _ => (None, None),
    };
    let net = p.net?;
    let (src, dst, ip_proto) = match &net {
        LaxNetSlice::Ipv4(v4) => {
            let h = v4.header();
            (
                IpAddr::V4(h.source_addr()),
                IpAddr::V4(h.destination_addr()),
                h.protocol().0,
            )
        }
        LaxNetSlice::Ipv6(v6) => {
            let h = v6.header();
            (
                IpAddr::V6(h.source_addr()),
                IpAddr::V6(h.destination_addr()),
                h.next_header().0,
            )
        }
        LaxNetSlice::Arp(arp) => {
            let s = arp.sender_protocol_addr();
            let t = arp.target_protocol_addr();
            if s.len() != 4 || t.len() != 4 {
                return None;
            }
            return Some(PacketMeta {
                ts_ms,
                wire_len,
                src: IpAddr::V4(Ipv4Addr::new(s[0], s[1], s[2], s[3])),
                dst: IpAddr::V4(Ipv4Addr::new(t[0], t[1], t[2], t[3])),
                transport: Transport::Arp,
                src_port: None,
                dst_port: None,
                tcp_open: false,
                src_mac,
                dst_mac,
            });
        }
    };

    let (transport, src_port, dst_port, tcp_open) = match &p.transport {
        Some(TransportSlice::Tcp(t)) => (
            Transport::Tcp,
            Some(t.source_port()),
            Some(t.destination_port()),
            t.syn() && !t.ack(),
        ),
        Some(TransportSlice::Udp(u)) => (
            Transport::Udp,
            Some(u.source_port()),
            Some(u.destination_port()),
            false,
        ),
        Some(TransportSlice::Icmpv4(_)) => (Transport::Icmp, None, None, false),
        Some(TransportSlice::Icmpv6(_)) => (Transport::Icmpv6, None, None, false),
        None => (Transport::Other(ip_proto), None, None, false),
    };
    Some(PacketMeta {
        ts_ms,
        wire_len,
        src,
        dst,
        transport,
        src_port,
        dst_port,
        tcp_open,
        src_mac,
        dst_mac,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use etherparse::PacketBuilder;

    pub fn tcp_frame(
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
        syn: bool,
        payload: usize,
    ) -> Vec<u8> {
        let b = PacketBuilder::ethernet2([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2]).ipv4(src, dst, 64);
        let b = if syn {
            b.tcp(sport, dport, 1, 1024).syn()
        } else {
            b.tcp(sport, dport, 1, 1024).ack(1)
        };
        let body = vec![0u8; payload];
        let mut out = Vec::new();
        b.write(&mut out, &body).unwrap();
        out
    }

    pub fn udp_frame(
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
        payload: usize,
    ) -> Vec<u8> {
        let b = PacketBuilder::ethernet2([2, 0, 0, 0, 0, 1], [0xff; 6])
            .ipv4(src, dst, 64)
            .udp(sport, dport);
        let mut out = Vec::new();
        b.write(&mut out, &vec![0u8; payload]).unwrap();
        out
    }

    #[test]
    fn parses_tcp_truncated_to_snaplen() {
        let f = tcp_frame([192, 0, 2, 108], [198, 51, 100, 7], 50000, 443, true, 1200);
        let wire = f.len() as u32;
        let m = ethernet(&f[..96], 1000, wire).expect("lax parse of truncated frame");
        assert_eq!(m.src, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 108)));
        assert_eq!(m.dst_port, Some(443));
        assert_eq!(m.transport, Transport::Tcp);
        assert!(m.tcp_open);
        assert_eq!(
            m.wire_len, wire,
            "byte counts use wire length, not capture length"
        );
    }

    #[test]
    fn parses_udp_broadcast() {
        let f = udp_frame([192, 0, 2, 50], [192, 0, 2, 255], 5353, 5353, 40);
        let m = ethernet(&f, 0, f.len() as u32).unwrap();
        assert_eq!(m.transport, Transport::Udp);
        assert_eq!(m.dst, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 255)));
        assert_eq!(m.src_mac, Some([2, 0, 0, 0, 0, 1]));
        assert_eq!(m.dst_mac, Some([0xff; 6]));
    }

    #[test]
    fn garbage_is_none_not_panic() {
        assert!(ethernet(&[], 0, 0).is_none());
        assert!(ethernet(&[0xff; 13], 0, 13).is_none());
        let mut f = tcp_frame([192, 0, 2, 1], [192, 0, 2, 2], 1, 2, false, 10);
        f.truncate(20); // cut inside the IP header
        assert!(ethernet(&f, 0, 60).is_none());
        // Every truncation length of a real frame must be handled without panicking.
        let full = tcp_frame([192, 0, 2, 1], [192, 0, 2, 2], 1, 2, true, 64);
        for n in 0..full.len() {
            let _ = ethernet(&full[..n], 0, full.len() as u32);
        }
    }
}
