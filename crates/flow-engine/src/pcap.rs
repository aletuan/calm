//! Streaming reader for classic PCAP and PCAPNG files (M1.4).
//!
//! The file is untrusted input (AT-16): every length is checked before it is
//! used, nothing is allocated from an unchecked size, and any inconsistency
//! stops the reader with a [`ReadError`] carrying the byte offset. Frames read
//! before the error stay valid, so a damaged file still yields a partial,
//! explicitly incomplete result. This module never panics on file content.
//!
//! Pure Rust on purpose: import does not need libpcap or BPF privileges.

use std::io::{self, Read};

use serde::{Deserialize, Serialize};

/// Hard cap on one block or record. Real Ethernet frames are far smaller; a
/// larger declared length means a corrupted or hostile file.
pub const MAX_BLOCK: usize = 1 << 20;

pub const LINKTYPE_ETHERNET: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    Pcap,
    PcapNanos,
    Pcapng,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadError {
    /// Byte offset of the block or record that could not be read.
    pub offset: u64,
    pub reason: ErrorReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ErrorReason {
    /// Not a PCAP or PCAPNG file (unknown magic number).
    NotACapture,
    /// The file ends in the middle of a header, block or record.
    Truncated,
    /// A declared length is impossible or above [`MAX_BLOCK`].
    BadLength {
        declared: u64,
    },
    /// PCAPNG trailing length differs from the leading one.
    LengthMismatch,
    /// A packet refers to an interface that was never described.
    UnknownInterface {
        id: u32,
    },
    /// Captured length exceeds the space in its block.
    BadCaptureLength,
    Io {
        detail: String,
    },
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} at byte {}", self.reason, self.offset)
    }
}

/// One packet record. `data` borrows the reader's buffer until the next call.
#[derive(Debug)]
pub struct Frame<'a> {
    /// Unix milliseconds. `None` only for PCAPNG Simple Packet Blocks, which
    /// carry no timestamp.
    pub ts_ms: Option<i64>,
    pub linktype: u16,
    /// Original length on the wire.
    pub wire_len: u32,
    pub data: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
struct Interface {
    linktype: u16,
    snaplen: u32,
    /// Timestamp units per second.
    units_per_sec: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Endian {
    Little,
    Big,
}

impl Endian {
    fn u16(self, b: &[u8]) -> u16 {
        let a = [b[0], b[1]];
        match self {
            Endian::Little => u16::from_le_bytes(a),
            Endian::Big => u16::from_be_bytes(a),
        }
    }
    fn u32(self, b: &[u8]) -> u32 {
        let a = [b[0], b[1], b[2], b[3]];
        match self {
            Endian::Little => u32::from_le_bytes(a),
            Endian::Big => u32::from_be_bytes(a),
        }
    }
}

enum Kind {
    Pcap {
        endian: Endian,
        nanos: bool,
        linktype: u16,
    },
    Pcapng {
        endian: Endian,
        interfaces: Vec<Interface>,
    },
}

pub struct Reader<R: Read> {
    inner: R,
    kind: Kind,
    offset: u64,
    buf: Vec<u8>,
    done: bool,
}

/// Reads up to `out.len()` bytes; returns how many were read (short only at EOF).
fn read_full<R: Read>(r: &mut R, out: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < out.len() {
        match r.read(&mut out[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

fn io_err(offset: u64, e: io::Error) -> ReadError {
    ReadError {
        offset,
        reason: ErrorReason::Io {
            detail: e.to_string(),
        },
    }
}

fn err(offset: u64, reason: ErrorReason) -> ReadError {
    ReadError { offset, reason }
}

const PCAP_US: u32 = 0xa1b2_c3d4;
const PCAP_NS: u32 = 0xa1b2_3c4d;
const NG_SHB: u32 = 0x0a0d_0d0a;
const NG_BOM: u32 = 0x1a2b_3c4d;

/// `ticks / units_per_sec` seconds → Unix ms, saturating instead of overflowing.
fn ticks_to_ms(ticks: u64, units_per_sec: u128) -> i64 {
    let ms = u128::from(ticks) * 1000 / units_per_sec.max(1);
    i64::try_from(ms).unwrap_or(i64::MAX)
}

/// PCAPNG `if_tsresol`: MSB clear → 10^-n, set → 2^-n. Out-of-range values
/// fall back to microseconds rather than overflow.
fn tsresol_units(v: u8) -> u128 {
    let n = u32::from(v & 0x7f);
    if v & 0x80 == 0 {
        if n <= 19 {
            10u128.pow(n)
        } else {
            1_000_000
        }
    } else if n <= 63 {
        1u128 << n
    } else {
        1_000_000
    }
}

impl<R: Read> Reader<R> {
    /// Reads and validates the file header. Fails with `NotACapture` for
    /// anything that is not PCAP or PCAPNG.
    pub fn new(mut inner: R) -> Result<Self, ReadError> {
        let mut head = [0u8; 4];
        let n = read_full(&mut inner, &mut head).map_err(|e| io_err(0, e))?;
        if n < 4 {
            return Err(err(0, ErrorReason::NotACapture));
        }
        let le = u32::from_le_bytes(head);
        let be = u32::from_be_bytes(head);
        if le == NG_SHB {
            // SHB type is a palindrome; endianness comes from the byte-order magic.
            let mut r = Reader {
                inner,
                kind: Kind::Pcapng {
                    endian: Endian::Little,
                    interfaces: Vec::new(),
                },
                offset: 0,
                buf: Vec::new(),
                done: false,
            };
            r.read_shb_after_type()?;
            return Ok(r);
        }
        let (endian, nanos) = match (le, be) {
            (PCAP_US, _) => (Endian::Little, false),
            (PCAP_NS, _) => (Endian::Little, true),
            (_, PCAP_US) => (Endian::Big, false),
            (_, PCAP_NS) => (Endian::Big, true),
            _ => return Err(err(0, ErrorReason::NotACapture)),
        };
        let mut rest = [0u8; 20];
        let n = read_full(&mut inner, &mut rest).map_err(|e| io_err(4, e))?;
        if n < 20 {
            return Err(err(0, ErrorReason::Truncated));
        }
        // network field: low 16 bits are the link type (upper bits carry FCS info).
        let linktype = (endian.u32(&rest[16..20]) & 0xffff) as u16;
        Ok(Reader {
            inner,
            kind: Kind::Pcap {
                endian,
                nanos,
                linktype,
            },
            offset: 24,
            buf: Vec::new(),
            done: false,
        })
    }

    pub fn format(&self) -> Format {
        match self.kind {
            Kind::Pcap { nanos: false, .. } => Format::Pcap,
            Kind::Pcap { nanos: true, .. } => Format::PcapNanos,
            Kind::Pcapng { .. } => Format::Pcapng,
        }
    }

    /// Bytes consumed so far.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Section header: the 4 type bytes at `self.offset` are consumed.
    fn read_shb_after_type(&mut self) -> Result<(), ReadError> {
        let start = self.offset;
        let mut h = [0u8; 4];
        let n = read_full(&mut self.inner, &mut h).map_err(|e| io_err(start, e))?;
        if n < 4 {
            return Err(err(start, ErrorReason::Truncated));
        }
        self.finish_shb(start, h)
    }

    /// Reads the rest of a Section Header Block whose type and (raw) length
    /// bytes were consumed. The byte-order magic decides how to read the length.
    fn finish_shb(&mut self, start: u64, len_raw: [u8; 4]) -> Result<(), ReadError> {
        let mut bom = [0u8; 4];
        let n = read_full(&mut self.inner, &mut bom).map_err(|e| io_err(start, e))?;
        if n < 4 {
            return Err(err(start, ErrorReason::Truncated));
        }
        let endian = match (u32::from_le_bytes(bom), u32::from_be_bytes(bom)) {
            (NG_BOM, _) => Endian::Little,
            (_, NG_BOM) => Endian::Big,
            _ => return Err(err(start, ErrorReason::NotACapture)),
        };
        let total = endian.u32(&len_raw) as usize;
        if total < 28 || total % 4 != 0 || total > MAX_BLOCK {
            return Err(err(
                start,
                ErrorReason::BadLength {
                    declared: total as u64,
                },
            ));
        }
        let rest = total - 12;
        self.buf.resize(rest, 0);
        let n = read_full(&mut self.inner, &mut self.buf).map_err(|e| io_err(start, e))?;
        if n < rest {
            return Err(err(start, ErrorReason::Truncated));
        }
        if endian.u32(&self.buf[rest - 4..]) as usize != total {
            return Err(err(start, ErrorReason::LengthMismatch));
        }
        self.offset = start + total as u64;
        self.kind = Kind::Pcapng {
            endian,
            interfaces: Vec::new(),
        };
        Ok(())
    }

    /// Next packet, `Ok(None)` at a clean end of file. After an error the
    /// reader stays finished.
    pub fn next_frame(&mut self) -> Result<Option<Frame<'_>>, ReadError> {
        if self.done {
            return Ok(None);
        }
        let r = match self.kind {
            Kind::Pcap { .. } => self.next_pcap(),
            Kind::Pcapng { .. } => self.next_pcapng(),
        };
        match r {
            Ok(Some(meta)) => {
                let (ts_ms, linktype, wire_len, start, len) = meta;
                Ok(Some(Frame {
                    ts_ms,
                    linktype,
                    wire_len,
                    data: &self.buf[start..start + len],
                }))
            }
            Ok(None) => {
                self.done = true;
                Ok(None)
            }
            Err(e) => {
                self.done = true;
                Err(e)
            }
        }
    }

    /// Returns (ts, linktype, wire_len, data start in buf, data len).
    #[allow(clippy::type_complexity)]
    fn next_pcap(&mut self) -> Result<Option<(Option<i64>, u16, u32, usize, usize)>, ReadError> {
        let Kind::Pcap {
            endian,
            nanos,
            linktype,
        } = self.kind
        else {
            return Ok(None);
        };
        let start = self.offset;
        let mut h = [0u8; 16];
        let n = read_full(&mut self.inner, &mut h).map_err(|e| io_err(start, e))?;
        if n == 0 {
            return Ok(None);
        }
        if n < 16 {
            return Err(err(start, ErrorReason::Truncated));
        }
        let sec = u64::from(endian.u32(&h[0..4]));
        let frac = u64::from(endian.u32(&h[4..8]));
        let incl = endian.u32(&h[8..12]) as usize;
        let orig = endian.u32(&h[12..16]);
        if incl > MAX_BLOCK {
            return Err(err(
                start,
                ErrorReason::BadLength {
                    declared: incl as u64,
                },
            ));
        }
        self.buf.resize(incl, 0);
        let n = read_full(&mut self.inner, &mut self.buf).map_err(|e| io_err(start, e))?;
        if n < incl {
            return Err(err(start, ErrorReason::Truncated));
        }
        self.offset = start + 16 + incl as u64;
        let frac_ms = if nanos {
            frac / 1_000_000
        } else {
            frac / 1_000
        };
        let ts =
            i64::try_from(sec.saturating_mul(1000).saturating_add(frac_ms)).unwrap_or(i64::MAX);
        Ok(Some((Some(ts), linktype, orig.max(incl as u32), 0, incl)))
    }

    #[allow(clippy::type_complexity)]
    fn next_pcapng(&mut self) -> Result<Option<(Option<i64>, u16, u32, usize, usize)>, ReadError> {
        loop {
            let start = self.offset;
            let mut h = [0u8; 8];
            let n = read_full(&mut self.inner, &mut h).map_err(|e| io_err(start, e))?;
            if n == 0 {
                return Ok(None);
            }
            if n < 8 {
                return Err(err(start, ErrorReason::Truncated));
            }
            let Kind::Pcapng { endian, .. } = self.kind else {
                return Ok(None);
            };
            let btype = endian.u32(&h[0..4]);
            if btype == NG_SHB {
                // New section, possibly with another byte order.
                self.finish_shb(start, [h[4], h[5], h[6], h[7]])?;
                continue;
            }
            let total = endian.u32(&h[4..8]) as usize;
            if total < 12 || total % 4 != 0 || total > MAX_BLOCK {
                return Err(err(
                    start,
                    ErrorReason::BadLength {
                        declared: total as u64,
                    },
                ));
            }
            let body_len = total - 12;
            // body + trailing length
            self.buf.resize(body_len + 4, 0);
            let n = read_full(&mut self.inner, &mut self.buf).map_err(|e| io_err(start, e))?;
            if n < body_len + 4 {
                return Err(err(start, ErrorReason::Truncated));
            }
            if endian.u32(&self.buf[body_len..]) as usize != total {
                return Err(err(start, ErrorReason::LengthMismatch));
            }
            self.offset = start + total as u64;

            let Kind::Pcapng {
                endian,
                ref mut interfaces,
            } = self.kind
            else {
                return Ok(None);
            };
            let b = &self.buf[..body_len];
            match btype {
                // Interface Description Block
                1 => {
                    if b.len() < 8 {
                        return Err(err(start, ErrorReason::BadCaptureLength));
                    }
                    let linktype = endian.u16(&b[0..2]);
                    let snaplen = endian.u32(&b[4..8]);
                    let mut units = 1_000_000u128;
                    let mut o = 8;
                    while o + 4 <= b.len() {
                        let code = endian.u16(&b[o..o + 2]);
                        let len = endian.u16(&b[o + 2..o + 4]) as usize;
                        if code == 0 {
                            break;
                        }
                        let vstart = o + 4;
                        if vstart + len > b.len() {
                            break; // malformed options: keep defaults
                        }
                        if code == 9 && len >= 1 {
                            units = tsresol_units(b[vstart]);
                        }
                        o = vstart + len.div_ceil(4) * 4;
                    }
                    if interfaces.len() < 4096 {
                        interfaces.push(Interface {
                            linktype,
                            snaplen,
                            units_per_sec: units,
                        });
                    }
                }
                // Enhanced Packet Block
                6 => {
                    if b.len() < 20 {
                        return Err(err(start, ErrorReason::BadCaptureLength));
                    }
                    let id = endian.u32(&b[0..4]);
                    let ticks =
                        (u64::from(endian.u32(&b[4..8])) << 32) | u64::from(endian.u32(&b[8..12]));
                    let cap = endian.u32(&b[12..16]) as usize;
                    let orig = endian.u32(&b[16..20]);
                    if cap > b.len() - 20 {
                        return Err(err(start, ErrorReason::BadCaptureLength));
                    }
                    let Some(ifc) = interfaces.get(id as usize).copied() else {
                        return Err(err(start, ErrorReason::UnknownInterface { id }));
                    };
                    let ts = ticks_to_ms(ticks, ifc.units_per_sec);
                    return Ok(Some((
                        Some(ts),
                        ifc.linktype,
                        orig.max(cap as u32),
                        20,
                        cap,
                    )));
                }
                // Obsolete Packet Block
                2 => {
                    if b.len() < 20 {
                        return Err(err(start, ErrorReason::BadCaptureLength));
                    }
                    let id = u32::from(endian.u16(&b[0..2]));
                    let ticks =
                        (u64::from(endian.u32(&b[4..8])) << 32) | u64::from(endian.u32(&b[8..12]));
                    let cap = endian.u32(&b[12..16]) as usize;
                    let orig = endian.u32(&b[16..20]);
                    if cap > b.len() - 20 {
                        return Err(err(start, ErrorReason::BadCaptureLength));
                    }
                    let Some(ifc) = interfaces.get(id as usize).copied() else {
                        return Err(err(start, ErrorReason::UnknownInterface { id }));
                    };
                    let ts = ticks_to_ms(ticks, ifc.units_per_sec);
                    return Ok(Some((
                        Some(ts),
                        ifc.linktype,
                        orig.max(cap as u32),
                        20,
                        cap,
                    )));
                }
                // Simple Packet Block: interface 0, no timestamp.
                3 => {
                    if b.len() < 4 {
                        return Err(err(start, ErrorReason::BadCaptureLength));
                    }
                    let Some(ifc) = interfaces.first().copied() else {
                        return Err(err(start, ErrorReason::UnknownInterface { id: 0 }));
                    };
                    let orig = endian.u32(&b[0..4]);
                    let mut cap = (orig as usize).min(b.len() - 4);
                    if ifc.snaplen > 0 {
                        cap = cap.min(ifc.snaplen as usize);
                    }
                    // No timestamp: report it as such; the caller decides (import reuses
                    // the previous one and counts it as untimed).
                    return Ok(Some((None, ifc.linktype, orig, 4, cap)));
                }
                // Statistics, name resolution, custom, decryption secrets…: skipped.
                _ => {}
            }
        }
    }
}

/// Minimal PCAPNG writer (little endian, one interface, microsecond
/// timestamps). Used for fixtures now and session export later.
pub struct NgWriter<W: std::io::Write> {
    out: W,
}

impl<W: std::io::Write> NgWriter<W> {
    pub fn new(mut out: W, linktype: u16, snaplen: u32, if_name: &str) -> io::Result<Self> {
        let mut shb = Vec::new();
        shb.extend(NG_BOM.to_le_bytes());
        shb.extend(1u16.to_le_bytes());
        shb.extend(0u16.to_le_bytes());
        shb.extend((-1i64).to_le_bytes());
        write_block(&mut out, NG_SHB, &shb)?;
        let mut idb = Vec::new();
        idb.extend(linktype.to_le_bytes());
        idb.extend(0u16.to_le_bytes());
        idb.extend(snaplen.to_le_bytes());
        push_option(&mut idb, 2, if_name.as_bytes()); // if_name
        push_option(&mut idb, 9, &[6]); // if_tsresol = 10^-6
        idb.extend([0u8; 4]); // opt_endofopt
        write_block(&mut out, 1, &idb)?;
        Ok(Self { out })
    }

    /// Writes one Enhanced Packet Block. `data` may be shorter than `wire_len`.
    pub fn packet(&mut self, ts_us: u64, data: &[u8], wire_len: u32) -> io::Result<()> {
        let mut b = Vec::with_capacity(20 + data.len() + 3);
        b.extend(0u32.to_le_bytes());
        b.extend(((ts_us >> 32) as u32).to_le_bytes());
        b.extend((ts_us as u32).to_le_bytes());
        b.extend((data.len() as u32).to_le_bytes());
        b.extend(wire_len.max(data.len() as u32).to_le_bytes());
        b.extend(data);
        while b.len() % 4 != 0 {
            b.push(0);
        }
        write_block(&mut self.out, 6, &b)
    }

    pub fn into_inner(self) -> W {
        self.out
    }
}

fn push_option(b: &mut Vec<u8>, code: u16, v: &[u8]) {
    b.extend(code.to_le_bytes());
    b.extend((v.len() as u16).to_le_bytes());
    b.extend(v);
    while b.len() % 4 != 0 {
        b.push(0);
    }
}

fn write_block<W: std::io::Write>(out: &mut W, t: u32, body: &[u8]) -> io::Result<()> {
    let total = (12 + body.len()) as u32;
    out.write_all(&t.to_le_bytes())?;
    out.write_all(&total.to_le_bytes())?;
    out.write_all(body)?;
    out.write_all(&total.to_le_bytes())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Minimal PCAPNG writer for tests (little endian, one Ethernet interface).
    pub fn ng_file(frames: &[(u64, &[u8], u32)], tsresol: Option<u8>) -> Vec<u8> {
        let mut out = Vec::new();
        block(&mut out, NG_SHB, &{
            let mut b = Vec::new();
            b.extend(NG_BOM.to_le_bytes());
            b.extend(1u16.to_le_bytes());
            b.extend(0u16.to_le_bytes());
            b.extend((-1i64).to_le_bytes());
            b
        });
        block(&mut out, 1, &{
            let mut b = Vec::new();
            b.extend(1u16.to_le_bytes());
            b.extend(0u16.to_le_bytes());
            b.extend(0u32.to_le_bytes());
            if let Some(r) = tsresol {
                b.extend(9u16.to_le_bytes());
                b.extend(1u16.to_le_bytes());
                b.extend([r, 0, 0, 0]);
                b.extend([0u8; 4]);
            }
            b
        });
        for (ticks, data, orig) in frames {
            block(&mut out, 6, &{
                let mut b = Vec::new();
                b.extend(0u32.to_le_bytes());
                b.extend(((ticks >> 32) as u32).to_le_bytes());
                b.extend((*ticks as u32).to_le_bytes());
                b.extend((data.len() as u32).to_le_bytes());
                b.extend(orig.to_le_bytes());
                b.extend(*data);
                while b.len() % 4 != 0 {
                    b.push(0);
                }
                b
            });
        }
        out
    }

    pub fn block(out: &mut Vec<u8>, t: u32, body: &[u8]) {
        let total = (12 + body.len()) as u32;
        out.extend(t.to_le_bytes());
        out.extend(total.to_le_bytes());
        out.extend(body);
        out.extend(total.to_le_bytes());
    }

    fn pcap_file(be: bool, nanos: bool, frames: &[(u32, u32, &[u8])]) -> Vec<u8> {
        let w32 = |v: u32| if be { v.to_be_bytes() } else { v.to_le_bytes() };
        let w16 = |v: u16| if be { v.to_be_bytes() } else { v.to_le_bytes() };
        let mut out = Vec::new();
        out.extend(w32(if nanos { PCAP_NS } else { PCAP_US }));
        out.extend(w16(2));
        out.extend(w16(4));
        out.extend(w32(0));
        out.extend(w32(0));
        out.extend(w32(65535));
        out.extend(w32(1));
        for (s, f, d) in frames {
            out.extend(w32(*s));
            out.extend(w32(*f));
            out.extend(w32(d.len() as u32));
            out.extend(w32(d.len() as u32 + 100));
            out.extend(*d);
        }
        out
    }

    type Collected = (Vec<(Option<i64>, u16, u32, Vec<u8>)>, Option<ReadError>);

    fn collect(bytes: &[u8]) -> Collected {
        let mut out = Vec::new();
        let mut r = match Reader::new(bytes) {
            Ok(r) => r,
            Err(e) => return (out, Some(e)),
        };
        loop {
            match r.next_frame() {
                Ok(Some(f)) => out.push((f.ts_ms, f.linktype, f.wire_len, f.data.to_vec())),
                Ok(None) => return (out, None),
                Err(e) => return (out, Some(e)),
            }
        }
    }

    #[test]
    fn pcapng_default_microseconds() {
        let f = ng_file(&[(1_700_000_000_123_456, b"abcdef", 60)], None);
        let (frames, e) = collect(&f);
        assert!(e.is_none());
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].0, Some(1_700_000_000_123));
        assert_eq!(frames[0].1, LINKTYPE_ETHERNET);
        assert_eq!(frames[0].2, 60);
        assert_eq!(frames[0].3, b"abcdef");
    }

    #[test]
    fn pcapng_nanosecond_resolution() {
        let f = ng_file(&[(1_700_000_000_123_456_789, b"x", 1)], Some(9));
        let (frames, _) = collect(&f);
        assert_eq!(frames[0].0, Some(1_700_000_000_123));
    }

    #[test]
    fn classic_pcap_all_variants() {
        for be in [false, true] {
            for nanos in [false, true] {
                let frac = if nanos { 250_000_000 } else { 250_000 };
                let f = pcap_file(be, nanos, &[(1_700_000_000, frac, b"hello")]);
                let mut r = Reader::new(&f[..]).unwrap();
                let fr = r.next_frame().unwrap().unwrap();
                assert_eq!(fr.ts_ms, Some(1_700_000_000_250), "be={be} nanos={nanos}");
                assert_eq!(fr.data, b"hello");
                assert_eq!(fr.wire_len, 105);
                assert!(r.next_frame().unwrap().is_none());
            }
        }
    }

    #[test]
    fn writer_round_trips() {
        let mut w = NgWriter::new(Vec::new(), LINKTYPE_ETHERNET, 96, "en0").unwrap();
        w.packet(1_700_000_000_000_001, b"frame", 1514).unwrap();
        let bytes = w.into_inner();
        let mut r = Reader::new(&bytes[..]).unwrap();
        assert_eq!(r.format(), Format::Pcapng);
        let f = r.next_frame().unwrap().unwrap();
        assert_eq!(f.ts_ms, Some(1_700_000_000_000));
        assert_eq!(f.wire_len, 1514);
        assert_eq!(f.data, b"frame");
    }

    #[test]
    fn not_a_capture() {
        let (_, e) = collect(b"PK\x03\x04 zip file");
        assert_eq!(e.unwrap().reason, ErrorReason::NotACapture);
        let (_, e) = collect(b"");
        assert_eq!(e.unwrap().reason, ErrorReason::NotACapture);
    }

    #[test]
    fn truncated_file_keeps_earlier_frames() {
        let f = ng_file(&[(1, b"one!", 4), (2, b"two!", 4)], None);
        let cut = &f[..f.len() - 6];
        let (frames, e) = collect(cut);
        assert_eq!(frames.len(), 1);
        let e = e.unwrap();
        assert_eq!(e.reason, ErrorReason::Truncated);
        assert!(e.offset > 0);
    }

    #[test]
    fn huge_declared_length_is_rejected_without_allocating() {
        let mut f = ng_file(&[], None);
        f.extend(6u32.to_le_bytes());
        f.extend(0xffff_fff0u32.to_le_bytes());
        let (_, e) = collect(&f);
        assert!(matches!(e.unwrap().reason, ErrorReason::BadLength { .. }));
    }

    #[test]
    fn packet_before_interface_is_an_error() {
        let mut f = Vec::new();
        block(&mut f, NG_SHB, &{
            let mut b = Vec::new();
            b.extend(NG_BOM.to_le_bytes());
            b.extend([1, 0, 0, 0]);
            b.extend((-1i64).to_le_bytes());
            b
        });
        block(&mut f, 6, &[0u8; 20]);
        let (_, e) = collect(&f);
        assert_eq!(e.unwrap().reason, ErrorReason::UnknownInterface { id: 0 });
    }

    #[test]
    fn every_prefix_and_byte_flip_is_contained() {
        let frame = [0xaau8; 60];
        let f = ng_file(
            &[(10, &frame, 60), (20, &frame, 60), (30, &frame, 60)],
            Some(6),
        );
        for n in 0..f.len() {
            let _ = collect(&f[..n]);
        }
        for i in 0..f.len() {
            for v in [0x00u8, 0xff, 0x7f, 0x80] {
                let mut g = f.clone();
                g[i] = v;
                let _ = collect(&g);
            }
        }
        let p = pcap_file(false, false, &[(1, 1, &frame), (2, 2, &frame)]);
        for n in 0..p.len() {
            let _ = collect(&p[..n]);
        }
        for i in 0..p.len() {
            let mut g = p.clone();
            g[i] ^= 0xff;
            let _ = collect(&g);
        }
    }

    /// Block writer with a chosen byte order, for multi-section and big-endian tests.
    struct Ng {
        out: Vec<u8>,
        be: bool,
    }

    impl Ng {
        fn u16(&self, v: u16) -> [u8; 2] {
            if self.be {
                v.to_be_bytes()
            } else {
                v.to_le_bytes()
            }
        }
        fn u32(&self, v: u32) -> [u8; 4] {
            if self.be {
                v.to_be_bytes()
            } else {
                v.to_le_bytes()
            }
        }
        fn block(&mut self, t: u32, body: &[u8]) {
            let mut body = body.to_vec();
            while body.len() % 4 != 0 {
                body.push(0);
            }
            let total = (12 + body.len()) as u32;
            let (a, b) = (self.u32(t), self.u32(total));
            self.out.extend(a);
            self.out.extend(b);
            self.out.extend(&body);
            self.out.extend(b);
        }
        fn section(&mut self, be: bool) {
            self.be = be;
            let mut b = self.u32(NG_BOM).to_vec();
            b.extend(self.u16(1));
            b.extend(self.u16(0));
            b.extend([0xff; 8]);
            self.block(NG_SHB, &b);
        }
        fn idb(&mut self, linktype: u16, snaplen: u32, options: &[u8]) {
            let mut b = self.u16(linktype).to_vec();
            b.extend(self.u16(0));
            b.extend(self.u32(snaplen));
            b.extend(options);
            self.block(1, &b);
        }
        fn epb(&mut self, ifc: u32, ticks: u64, data: &[u8], orig: u32) {
            let mut b = self.u32(ifc).to_vec();
            b.extend(self.u32((ticks >> 32) as u32));
            b.extend(self.u32(ticks as u32));
            b.extend(self.u32(data.len() as u32));
            b.extend(self.u32(orig));
            b.extend(data);
            self.block(6, &b);
        }
        fn opb(&mut self, ifc: u16, ticks: u64, data: &[u8]) {
            let mut b = self.u16(ifc).to_vec();
            b.extend(self.u16(0));
            b.extend(self.u32((ticks >> 32) as u32));
            b.extend(self.u32(ticks as u32));
            b.extend(self.u32(data.len() as u32));
            b.extend(self.u32(data.len() as u32));
            b.extend(data);
            self.block(2, &b);
        }
        fn spb(&mut self, orig: u32, data: &[u8]) {
            let mut b = self.u32(orig).to_vec();
            b.extend(data);
            self.block(3, &b);
        }
    }

    fn ng(be: bool) -> Ng {
        let mut n = Ng {
            out: Vec::new(),
            be,
        };
        n.section(be);
        n
    }

    #[test]
    fn big_endian_section() {
        let mut n = ng(true);
        n.idb(1, 0, &[]);
        n.epb(0, 2_000_000, b"be!", 3);
        let (f, e) = collect(&n.out);
        assert!(e.is_none(), "{e:?}");
        assert_eq!(f[0].0, Some(2_000));
        assert_eq!(f[0].3, b"be!");
    }

    #[test]
    fn new_section_resets_interfaces_and_may_change_byte_order() {
        let mut n = ng(false);
        n.idb(1, 0, &[]);
        n.epb(0, 1_000_000, b"a", 1);
        n.section(true);
        n.idb(105, 0, &[]); // 802.11 in the second section
        n.epb(0, 3_000_000, b"b", 1);
        let (f, e) = collect(&n.out);
        assert!(e.is_none(), "{e:?}");
        assert_eq!((f[0].1, f[1].1), (LINKTYPE_ETHERNET, 105));
        assert_eq!(f[1].0, Some(3_000));
        // An interface id from the previous section is not valid any more.
        let mut n = ng(false);
        n.idb(1, 0, &[]);
        n.idb(1, 0, &[]);
        n.section(false);
        n.idb(1, 0, &[]);
        n.epb(1, 0, b"x", 1);
        assert_eq!(
            collect(&n.out).1.unwrap().reason,
            ErrorReason::UnknownInterface { id: 1 }
        );
    }

    #[test]
    fn obsolete_packet_block() {
        let mut n = ng(false);
        n.idb(1, 0, &[]);
        n.opb(0, 5_000_000, b"old");
        n.opb(3, 0, b"bad");
        let (f, e) = collect(&n.out);
        assert_eq!(f[0].0, Some(5_000));
        assert_eq!(f[0].3, b"old");
        assert_eq!(e.unwrap().reason, ErrorReason::UnknownInterface { id: 3 });
    }

    #[test]
    fn simple_packet_block_has_no_timestamp_and_respects_snaplen() {
        let mut n = ng(false);
        n.idb(1, 4, &[]);
        n.epb(0, 7_000_000, b"ab", 2);
        n.spb(10, b"0123456789");
        let (f, e) = collect(&n.out);
        assert!(e.is_none());
        assert_eq!(f[1].0, None, "no timestamp of its own");
        assert_eq!(f[1].3, b"0123", "cut to the interface snaplen");
        assert_eq!(f[1].2, 10);
        let mut n = ng(false);
        n.spb(1, b"x");
        assert_eq!(
            collect(&n.out).1.unwrap().reason,
            ErrorReason::UnknownInterface { id: 0 }
        );
    }

    #[test]
    fn power_of_two_resolution_and_bad_options() {
        let mut n = ng(false);
        // if_tsresol = 2^-10: 1024 ticks per second.
        n.idb(1, 0, &[9, 0, 1, 0, 0x8a, 0, 0, 0, 0, 0, 0, 0]);
        n.epb(0, 2048, b"x", 1);
        // Option claiming 200 bytes in a short block: ignored, default µs kept.
        n.idb(1, 0, &[9, 0, 200, 0, 3, 0, 0, 0]);
        n.epb(1, 5_000_000, b"y", 1);
        let (f, e) = collect(&n.out);
        assert!(e.is_none(), "{e:?}");
        assert_eq!(f[0].0, Some(2_000));
        assert_eq!(f[1].0, Some(5_000));
    }

    #[test]
    fn short_blocks_are_errors() {
        for (t, len) in [(1u32, 4usize), (6, 8), (2, 8), (3, 0)] {
            let mut n = ng(false);
            if t != 1 {
                n.idb(1, 0, &[]);
            }
            n.block(t, &vec![0u8; len]);
            let r = collect(&n.out).1.map(|e| e.reason);
            assert_eq!(r, Some(ErrorReason::BadCaptureLength), "type {t}");
        }
        // Captured length larger than the block.
        let mut n = ng(false);
        n.idb(1, 0, &[]);
        let mut b = vec![0u8; 20];
        b[12..16].copy_from_slice(&100u32.to_le_bytes());
        n.block(6, &b);
        assert_eq!(
            collect(&n.out).1.unwrap().reason,
            ErrorReason::BadCaptureLength
        );
    }

    #[test]
    fn unknown_blocks_are_skipped() {
        let mut n = ng(false);
        n.idb(1, 0, &[]);
        n.block(5, &[1, 2, 3, 4]); // interface statistics
        n.block(0x0bad, &[]); // custom / unknown
        n.epb(0, 0, b"ok", 2);
        let (f, e) = collect(&n.out);
        assert!(e.is_none());
        assert_eq!(f.len(), 1);
    }

    /// A reader that is interrupted once, then fails with an I/O error.
    struct Flaky {
        data: Vec<u8>,
        pos: usize,
        interrupted: bool,
        fail_at: usize,
    }

    impl Read for Flaky {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(io::ErrorKind::Interrupted.into());
            }
            if self.pos >= self.fail_at {
                return Err(io::Error::other("disk gone"));
            }
            let n = buf
                .len()
                .min(self.fail_at - self.pos)
                .min(self.data.len() - self.pos);
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    #[test]
    fn io_errors_are_reported_with_offset_and_interrupts_retried() {
        let f = ng_file(&[(1, b"abcd", 4), (2, b"efgh", 4)], None);
        let fail_at = f.len() - 10;
        let mut r = Reader::new(Flaky {
            data: f,
            pos: 0,
            interrupted: false,
            fail_at,
        })
        .unwrap();
        assert_eq!(r.format(), Format::Pcapng);
        assert!(r.next_frame().unwrap().is_some());
        let e = r.next_frame().unwrap_err();
        assert!(matches!(e.reason, ErrorReason::Io { .. }));
        assert!(e.to_string().contains("at byte"));
        assert!(r.next_frame().unwrap().is_none(), "finished after an error");
        assert!(r.offset() > 0);
    }

    #[test]
    fn classic_pcap_reports_format_and_offset() {
        let f = pcap_file(false, true, &[(1, 2, b"x")]);
        let mut r = Reader::new(&f[..]).unwrap();
        assert_eq!(r.format(), Format::PcapNanos);
        assert_eq!(r.offset(), 24);
        r.next_frame().unwrap();
        assert_eq!(r.offset(), f.len() as u64);
        let f = pcap_file(true, false, &[]);
        assert_eq!(Reader::new(&f[..]).unwrap().format(), Format::Pcap);
        // Huge record length is refused before allocating.
        let mut f = pcap_file(false, false, &[]);
        f.extend([0u8; 8]);
        f.extend(0xffff_ff00u32.to_le_bytes());
        f.extend(0u32.to_le_bytes());
        assert!(matches!(
            collect(&f).1.unwrap().reason,
            ErrorReason::BadLength { .. }
        ));
    }
}
