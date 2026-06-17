// Copyright (C) 2026 The RustyBGP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.  See the License for the specific language governing
// permissions and limitations under the License.

//! EVPN NLRI (RFC 7432), AFI=25/SAFI=70.
//!
//! Wire format per route entry in MP_REACH_NLRI / MP_UNREACH_NLRI:
//!   1 byte  route type
//!   1 byte  route length (bytes that follow)
//!   N bytes route-type-specific data

use crate::rd::RouteDistinguisher;
use byteorder::ReadBytesExt;
use bytes::BufMut;
use std::fmt;
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Ethernet Segment Identifier (RFC 7432 §5): 10-byte opaque value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Esi(pub [u8; 10]);

impl Esi {
    pub const ZERO: Esi = Esi([0; 10]);
    pub const LEN: usize = 10;

    pub fn decode<R: Read>(r: &mut R) -> io::Result<Self> {
        let mut buf = [0u8; Self::LEN];
        r.read_exact(&mut buf)?;
        Ok(Esi(buf))
    }

    pub fn encode<B: BufMut>(&self, dst: &mut B) {
        dst.put_slice(&self.0);
    }
}

impl fmt::Display for Esi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9]
        )
    }
}

/// EVPN NLRI variants (RFC 7432).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EvpnNlri {
    /// Type-2: MAC/IP Advertisement route (RFC 7432 §7.2).
    MacIpAdvertisement(MacIpAdvertisement),
    /// Type-3: Inclusive Multicast Ethernet Tag route (RFC 7432 §7.3).
    InclusiveMulticastEthernetTag(InclusiveMulticastEthernetTag),
}

impl EvpnNlri {
    const TYPE_MAC_IP: u8 = 2;
    const TYPE_IMET: u8 = 3;

    /// Decode one EVPN route from `r`.  Consumes exactly 2 + route_len bytes.
    pub fn decode<R: Read>(r: &mut R) -> io::Result<Self> {
        let route_type = r.read_u8()?;
        let route_len = r.read_u8()? as usize;
        match route_type {
            Self::TYPE_MAC_IP => {
                MacIpAdvertisement::decode(r, route_len).map(EvpnNlri::MacIpAdvertisement)
            }
            Self::TYPE_IMET => InclusiveMulticastEthernetTag::decode(r, route_len)
                .map(EvpnNlri::InclusiveMulticastEthernetTag),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported EVPN route type {route_type}"),
            )),
        }
    }

    /// Encode: writes [type, len, data].
    pub fn encode<B: BufMut>(&self, dst: &mut B) {
        let mut data = Vec::new();
        match self {
            EvpnNlri::MacIpAdvertisement(n) => {
                n.encode(&mut data);
                dst.put_u8(Self::TYPE_MAC_IP);
            }
            EvpnNlri::InclusiveMulticastEthernetTag(n) => {
                n.encode(&mut data);
                dst.put_u8(Self::TYPE_IMET);
            }
        }
        dst.put_u8(data.len() as u8);
        dst.put_slice(&data);
    }
}

impl fmt::Display for EvpnNlri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvpnNlri::MacIpAdvertisement(n) => n.fmt(f),
            EvpnNlri::InclusiveMulticastEthernetTag(n) => n.fmt(f),
        }
    }
}

fn fmt_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Decode a 3-byte raw EVPN label (upper 24 bits of a 24-bit VNI field).
///
/// EVPN label fields store the VNI/label as a plain 24-bit big-endian integer,
/// not in MPLS wire format (RFC 3032 shifts the label value left by 4 and
/// adds TC and BoS bits). GoBGP and most EVPN implementations use raw encoding.
fn decode_evpn_label(b: &[u8; 3]) -> u32 {
    (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32
}

/// Encode a 24-bit EVPN label as 3 raw bytes (big-endian).
fn encode_evpn_label<B: BufMut>(label: u32, dst: &mut B) {
    dst.put_u8((label >> 16) as u8);
    dst.put_u8((label >> 8) as u8);
    dst.put_u8(label as u8);
}

/// Type-2: MAC/IP Advertisement route (RFC 7432 §7.2).
///
/// Wire layout (route_len bytes):
///   8  RD, 10  ESI, 4  Ethernet Tag (ETag)
///   1  MAC Address Length (always 48), 6  MAC Address
///   1  IP Address Length (0, 32, or 128), *  IP Address (0, 4, or 16 bytes)
///   3  Label1 (24-bit raw big-endian VNI/label)
///   3  Label2 (optional; present when route_len is 3 bytes longer)
///
/// Label fields use raw 24-bit big-endian encoding (not MPLS-shifted),
/// matching GoBGP and most EVPN implementations.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MacIpAdvertisement {
    pub rd: RouteDistinguisher,
    pub esi: Esi,
    pub etag: u32,
    pub mac: [u8; 6],
    pub ip: Option<IpAddr>,
    /// VNI or MPLS label (raw 24-bit value, not MPLS-shifted).
    pub label1: u32,
    /// Optional second label for symmetric IRB (raw 24-bit value).
    pub label2: Option<u32>,
}

impl MacIpAdvertisement {
    const MAC_LEN_BITS: u8 = 48;
    const MIN_LEN: usize = RouteDistinguisher::LEN + Esi::LEN + 4 + 1 + 6 + 1 + 3;

    pub fn decode<R: Read>(r: &mut R, route_len: usize) -> io::Result<Self> {
        let malformed = || io::Error::new(io::ErrorKind::InvalidData, "malformed EVPN Type-2");
        if route_len < Self::MIN_LEN {
            return Err(malformed());
        }

        let mut rd_buf = [0u8; RouteDistinguisher::LEN];
        r.read_exact(&mut rd_buf)?;
        let rd = RouteDistinguisher::decode(&rd_buf)?;

        let esi = Esi::decode(r)?;

        let etag = {
            let mut b = [0u8; 4];
            r.read_exact(&mut b)?;
            u32::from_be_bytes(b)
        };

        let mac_len = r.read_u8()?;
        if mac_len != Self::MAC_LEN_BITS {
            return Err(malformed());
        }
        let mut mac = [0u8; 6];
        r.read_exact(&mut mac)?;

        let ip_len = r.read_u8()?;
        let ip = match ip_len {
            0 => None,
            32 => {
                let mut b = [0u8; 4];
                r.read_exact(&mut b)?;
                Some(IpAddr::V4(Ipv4Addr::from(b)))
            }
            128 => {
                let mut b = [0u8; 16];
                r.read_exact(&mut b)?;
                Some(IpAddr::V6(Ipv6Addr::from(b)))
            }
            _ => return Err(malformed()),
        };

        let ip_bytes = match ip_len {
            0 => 0,
            32 => 4,
            128 => 16,
            _ => unreachable!(),
        };

        let mut l1 = [0u8; 3];
        r.read_exact(&mut l1)?;
        let label1 = decode_evpn_label(&l1);

        // Label2 is present when route_len has 3 more bytes beyond the minimum + IP.
        let expected_with_label2 = Self::MIN_LEN + ip_bytes + 3;
        let label2 = if route_len == expected_with_label2 {
            let mut l2 = [0u8; 3];
            r.read_exact(&mut l2)?;
            Some(decode_evpn_label(&l2))
        } else {
            None
        };

        Ok(MacIpAdvertisement {
            rd,
            esi,
            etag,
            mac,
            ip,
            label1,
            label2,
        })
    }

    pub fn encode<B: BufMut>(&self, dst: &mut B) {
        self.rd.encode(dst);
        self.esi.encode(dst);
        dst.put_u32(self.etag);
        dst.put_u8(Self::MAC_LEN_BITS);
        dst.put_slice(&self.mac);
        match self.ip {
            None => dst.put_u8(0),
            Some(IpAddr::V4(v4)) => {
                dst.put_u8(32);
                dst.put_slice(&v4.octets());
            }
            Some(IpAddr::V6(v6)) => {
                dst.put_u8(128);
                dst.put_slice(&v6.octets());
            }
        }
        encode_evpn_label(self.label1, dst);
        if let Some(l2) = self.label2 {
            encode_evpn_label(l2, dst);
        }
    }
}

impl fmt::Display for MacIpAdvertisement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ip_str = match self.ip {
            None => String::new(),
            Some(ip) => format!("/{ip}"),
        };
        write!(
            f,
            "[type-2][rd {}][etag {}][mac {}{}][label {}]",
            self.rd,
            self.etag,
            fmt_mac(&self.mac),
            ip_str,
            self.label1,
        )
    }
}

/// Type-3: Inclusive Multicast Ethernet Tag route (RFC 7432 §7.3).
///
/// Wire layout (route_len bytes):
///   8  RD, 4  Ethernet Tag (ETag)
///   1  IP Address Length (32 or 128), *  Originating Router IP (4 or 16 bytes)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InclusiveMulticastEthernetTag {
    pub rd: RouteDistinguisher,
    pub etag: u32,
    pub originating_router_ip: IpAddr,
}

impl InclusiveMulticastEthernetTag {
    const MIN_LEN: usize = RouteDistinguisher::LEN + 4 + 1 + 4;

    pub fn decode<R: Read>(r: &mut R, route_len: usize) -> io::Result<Self> {
        let malformed = || io::Error::new(io::ErrorKind::InvalidData, "malformed EVPN Type-3");
        if route_len < Self::MIN_LEN {
            return Err(malformed());
        }

        let mut rd_buf = [0u8; RouteDistinguisher::LEN];
        r.read_exact(&mut rd_buf)?;
        let rd = RouteDistinguisher::decode(&rd_buf)?;

        let etag = {
            let mut b = [0u8; 4];
            r.read_exact(&mut b)?;
            u32::from_be_bytes(b)
        };

        let ip_len = r.read_u8()?;
        let originating_router_ip = match ip_len {
            32 => {
                let mut b = [0u8; 4];
                r.read_exact(&mut b)?;
                IpAddr::V4(Ipv4Addr::from(b))
            }
            128 => {
                let mut b = [0u8; 16];
                r.read_exact(&mut b)?;
                IpAddr::V6(Ipv6Addr::from(b))
            }
            _ => return Err(malformed()),
        };

        Ok(InclusiveMulticastEthernetTag {
            rd,
            etag,
            originating_router_ip,
        })
    }

    pub fn encode<B: BufMut>(&self, dst: &mut B) {
        self.rd.encode(dst);
        dst.put_u32(self.etag);
        match self.originating_router_ip {
            IpAddr::V4(v4) => {
                dst.put_u8(32);
                dst.put_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                dst.put_u8(128);
                dst.put_slice(&v6.octets());
            }
        }
    }
}

impl fmt::Display for InclusiveMulticastEthernetTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[type-3][rd {}][etag {}][ip {}]",
            self.rd, self.etag, self.originating_router_ip,
        )
    }
}

/// Extract the MAC Mobility extended community from a slice of attributes.
///
/// Returns `Some((sequence, sticky))` if the MAC Mobility extended community
/// (RFC 7432 §7.7, type 0x06 subtype 0x00) is present, `None` otherwise.
/// Used for EVPN Type-2 best path selection in the table crate.
pub fn mac_mobility(attrs: &[crate::bgp::Attribute]) -> Option<(u32, bool)> {
    attrs
        .iter()
        .find(|a| a.code() == crate::bgp::Attribute::EXTENDED_COMMUNITY)
        .and_then(|a| a.binary())
        .and_then(|b| {
            b.chunks_exact(8).find_map(|ec| {
                if ec[0] == 0x06 && ec[1] == 0x00 {
                    let sticky = ec[2] & 0x01 != 0;
                    let seq = u32::from_be_bytes([ec[4], ec[5], ec[6], ec[7]]);
                    Some((seq, sticky))
                } else {
                    None
                }
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn rd_two_octet(admin: u16, assigned: u32) -> RouteDistinguisher {
        RouteDistinguisher::TwoOctetAs { admin, assigned }
    }

    fn rd_four_octet(admin: u32, assigned: u16) -> RouteDistinguisher {
        RouteDistinguisher::FourOctetAs { admin, assigned }
    }

    fn roundtrip(nlri: &EvpnNlri) -> EvpnNlri {
        let mut buf = Vec::new();
        nlri.encode(&mut buf);
        let mut c = Cursor::new(&buf);
        EvpnNlri::decode(&mut c).unwrap()
    }

    // -----------------------------------------------------------------------
    // Roundtrip tests
    // -----------------------------------------------------------------------

    #[test]
    fn type2_mac_only_roundtrip() {
        let nlri = EvpnNlri::MacIpAdvertisement(MacIpAdvertisement {
            rd: rd_two_octet(100, 200),
            esi: Esi::ZERO,
            etag: 0,
            mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            ip: None,
            label1: 100,
            label2: None,
        });
        assert_eq!(roundtrip(&nlri), nlri);
    }

    #[test]
    fn type2_mac_ipv4_roundtrip() {
        let nlri = EvpnNlri::MacIpAdvertisement(MacIpAdvertisement {
            rd: rd_two_octet(65000, 1),
            esi: Esi::ZERO,
            etag: 10,
            mac: [0xaa, 0xbb, 0xcc, 0x00, 0x01, 0x02],
            ip: Some("192.168.1.1".parse().unwrap()),
            label1: 10000,
            label2: None,
        });
        assert_eq!(roundtrip(&nlri), nlri);
    }

    #[test]
    fn type2_mac_ipv6_roundtrip() {
        let nlri = EvpnNlri::MacIpAdvertisement(MacIpAdvertisement {
            rd: rd_two_octet(65000, 1),
            esi: Esi::ZERO,
            etag: 0,
            mac: [0xaa, 0xbb, 0xcc, 0x00, 0x01, 0x02],
            ip: Some("2001:db8::1".parse().unwrap()),
            label1: 10000,
            label2: None,
        });
        assert_eq!(roundtrip(&nlri), nlri);
    }

    #[test]
    fn type2_two_labels_roundtrip() {
        let nlri = EvpnNlri::MacIpAdvertisement(MacIpAdvertisement {
            rd: rd_two_octet(65000, 1),
            esi: Esi::ZERO,
            etag: 0,
            mac: [0xaa, 0xbb, 0xcc, 0x00, 0x01, 0x02],
            ip: Some("192.168.1.1".parse().unwrap()),
            label1: 10000,
            label2: Some(20000),
        });
        assert_eq!(roundtrip(&nlri), nlri);
    }

    #[test]
    fn type3_ipv4_roundtrip() {
        let nlri = EvpnNlri::InclusiveMulticastEthernetTag(InclusiveMulticastEthernetTag {
            rd: rd_two_octet(100, 1),
            etag: 0,
            originating_router_ip: "10.0.0.1".parse().unwrap(),
        });
        assert_eq!(roundtrip(&nlri), nlri);
    }

    #[test]
    fn type3_ipv6_roundtrip() {
        let nlri = EvpnNlri::InclusiveMulticastEthernetTag(InclusiveMulticastEthernetTag {
            rd: rd_two_octet(100, 1),
            etag: 0,
            originating_router_ip: "2001:db8::1".parse().unwrap(),
        });
        assert_eq!(roundtrip(&nlri), nlri);
    }

    #[test]
    fn type2_wire_lengths() {
        // MAC-only: RD(8) + ESI(10) + ETag(4) + MacLen(1) + MAC(6) + IpLen(1) + Label1(3) = 33
        let mac_only = MacIpAdvertisement {
            rd: rd_two_octet(100, 1),
            esi: Esi::ZERO,
            etag: 0,
            mac: [0; 6],
            ip: None,
            label1: 100,
            label2: None,
        };
        let mut buf = Vec::new();
        mac_only.encode(&mut buf);
        assert_eq!(buf.len(), 33);

        // MAC+IPv4: 33 + 4 = 37
        let mac_ipv4 = MacIpAdvertisement {
            ip: Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            ..mac_only.clone()
        };
        buf.clear();
        mac_ipv4.encode(&mut buf);
        assert_eq!(buf.len(), 37);

        // MAC+IPv6: 33 + 16 = 49
        let mac_ipv6 = MacIpAdvertisement {
            ip: Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
            ..mac_only.clone()
        };
        buf.clear();
        mac_ipv6.encode(&mut buf);
        assert_eq!(buf.len(), 49);

        // MAC+IPv4+Label2: 37 + 3 = 40
        let mac_ipv4_l2 = MacIpAdvertisement {
            ip: Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            label2: Some(200),
            ..mac_only
        };
        buf.clear();
        mac_ipv4_l2.encode(&mut buf);
        assert_eq!(buf.len(), 40);
    }

    #[test]
    fn type3_wire_lengths() {
        // IPv4: RD(8) + ETag(4) + IpLen(1) + IP(4) = 17
        let imet_v4 = InclusiveMulticastEthernetTag {
            rd: rd_two_octet(100, 1),
            etag: 0,
            originating_router_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        };
        let mut buf = Vec::new();
        imet_v4.encode(&mut buf);
        assert_eq!(buf.len(), 17);

        // IPv6: 8 + 4 + 1 + 16 = 29
        let imet_v6 = InclusiveMulticastEthernetTag {
            originating_router_ip: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            ..imet_v4
        };
        buf.clear();
        imet_v6.encode(&mut buf);
        assert_eq!(buf.len(), 29);
    }

    // -----------------------------------------------------------------------
    // GoBGP wire-format interop tests
    //
    // Test vectors derived from GoBGP (pkg/packet/bgp/bgp.go, bgp_test.go).
    // Labels use raw 24-bit big-endian encoding (not MPLS-shifted).
    // -----------------------------------------------------------------------

    // Type-2: RD=TwoOctetAS(100,100), ESI=zeros, ETag=42,
    //         MAC=aa:bb:cc:dd:ee:ff, no IP, label=200
    // route_len = 33 bytes
    #[rustfmt::skip]
    const GOBGP_TYPE2_MAC_ONLY: &[u8] = &[
        0x02, 0x21,                                     // type=2, len=33
        0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64, // RD TwoOctetAS(100,100)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,             // ESI zeros (first 6)
        0x00, 0x00, 0x00, 0x00,                         // ESI zeros (last 4)
        0x00, 0x00, 0x00, 0x2a,                         // ETag = 42
        0x30,                                           // MAC len = 48
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,             // MAC
        0x00,                                           // IP len = 0
        0x00, 0x00, 0xc8,                               // label = 200 (raw)
    ];

    // Type-2: RD=FourOctetAS(5,6), ESI=zeros, ETag=3,
    //         MAC=01:23:45:67:89:ab, IP=192.2.1.2, label1=3, label2=4
    // route_len = 40 bytes
    #[rustfmt::skip]
    const GOBGP_TYPE2_MAC_IPV4_TWO_LABELS: &[u8] = &[
        0x02, 0x28,                                     // type=2, len=40
        0x00, 0x02, 0x00, 0x00, 0x00, 0x05, 0x00, 0x06, // RD FourOctetAS(5,6)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,             // ESI zeros (first 6)
        0x00, 0x00, 0x00, 0x00,                         // ESI zeros (last 4)
        0x00, 0x00, 0x00, 0x03,                         // ETag = 3
        0x30,                                           // MAC len = 48
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab,             // MAC
        0x20,                                           // IP len = 32
        0xc0, 0x02, 0x01, 0x02,                         // IP = 192.2.1.2
        0x00, 0x00, 0x03,                               // label1 = 3 (raw)
        0x00, 0x00, 0x04,                               // label2 = 4 (raw)
    ];

    // Type-3: RD=FourOctetAS(5,6), ETag=3, IP=192.2.1.2
    // route_len = 17 bytes
    #[rustfmt::skip]
    const GOBGP_TYPE3_IPV4: &[u8] = &[
        0x03, 0x11,                                     // type=3, len=17
        0x00, 0x02, 0x00, 0x00, 0x00, 0x05, 0x00, 0x06, // RD FourOctetAS(5,6)
        0x00, 0x00, 0x00, 0x03,                         // ETag = 3
        0x20,                                           // IP len = 32
        0xc0, 0x02, 0x01, 0x02,                         // IP = 192.2.1.2
    ];

    fn gobgp_decode(bytes: &[u8]) -> EvpnNlri {
        let mut c = Cursor::new(bytes);
        EvpnNlri::decode(&mut c).unwrap()
    }

    #[test]
    fn gobgp_type2_mac_only_decode() {
        let nlri = gobgp_decode(GOBGP_TYPE2_MAC_ONLY);
        let m = match &nlri {
            EvpnNlri::MacIpAdvertisement(m) => m,
            _ => panic!("expected MacIpAdvertisement"),
        };
        assert_eq!(m.rd, rd_two_octet(100, 100));
        assert_eq!(m.esi, Esi::ZERO);
        assert_eq!(m.etag, 42);
        assert_eq!(m.mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(m.ip, None);
        assert_eq!(m.label1, 200);
        assert_eq!(m.label2, None);
    }

    #[test]
    fn gobgp_type2_mac_only_roundtrip() {
        let nlri = gobgp_decode(GOBGP_TYPE2_MAC_ONLY);
        let mut buf = Vec::new();
        nlri.encode(&mut buf);
        assert_eq!(buf, GOBGP_TYPE2_MAC_ONLY);
    }

    #[test]
    fn gobgp_type2_mac_ipv4_two_labels_decode() {
        let nlri = gobgp_decode(GOBGP_TYPE2_MAC_IPV4_TWO_LABELS);
        let m = match &nlri {
            EvpnNlri::MacIpAdvertisement(m) => m,
            _ => panic!("expected MacIpAdvertisement"),
        };
        assert_eq!(m.rd, rd_four_octet(5, 6));
        assert_eq!(m.esi, Esi::ZERO);
        assert_eq!(m.etag, 3);
        assert_eq!(m.mac, [0x01, 0x23, 0x45, 0x67, 0x89, 0xab]);
        assert_eq!(m.ip, Some("192.2.1.2".parse().unwrap()));
        assert_eq!(m.label1, 3);
        assert_eq!(m.label2, Some(4));
    }

    #[test]
    fn gobgp_type2_mac_ipv4_two_labels_roundtrip() {
        let nlri = gobgp_decode(GOBGP_TYPE2_MAC_IPV4_TWO_LABELS);
        let mut buf = Vec::new();
        nlri.encode(&mut buf);
        assert_eq!(buf, GOBGP_TYPE2_MAC_IPV4_TWO_LABELS);
    }

    #[test]
    fn gobgp_type3_ipv4_decode() {
        let nlri = gobgp_decode(GOBGP_TYPE3_IPV4);
        let t = match &nlri {
            EvpnNlri::InclusiveMulticastEthernetTag(t) => t,
            _ => panic!("expected InclusiveMulticastEthernetTag"),
        };
        assert_eq!(t.rd, rd_four_octet(5, 6));
        assert_eq!(t.etag, 3);
        assert_eq!(
            t.originating_router_ip,
            "192.2.1.2".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn gobgp_type3_ipv4_roundtrip() {
        let nlri = gobgp_decode(GOBGP_TYPE3_IPV4);
        let mut buf = Vec::new();
        nlri.encode(&mut buf);
        assert_eq!(buf, GOBGP_TYPE3_IPV4);
    }

    // -----------------------------------------------------------------------
    // MAC Mobility extended community
    // -----------------------------------------------------------------------

    #[test]
    fn mac_mobility_absent() {
        assert_eq!(mac_mobility(&[]), None);
    }

    #[test]
    fn esi_display() {
        let esi = Esi([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a]);
        assert_eq!(esi.to_string(), "01:02:03:04:05:06:07:08:09:0a");
    }
}
