// Copyright (C) 2019-2026 The RustyBGP Authors.
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
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! BGP-MUP SAFI (SAFI=85) route encoding per draft-ietf-bess-mup-safi-00.
//! Implements Architecture Type 1 (3GPP-5G) and route types 1..4.

use crate::bgp::Family;
use crate::error::{BgpError, Error};
use crate::rd::RouteDistinguisher;
use byteorder::{ByteOrder, NetworkEndian};
use bytes::BufMut;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const ARCH_TYPE_3GPP_5G: u8 = 1;

pub const ROUTE_TYPE_INTERWORK_SEGMENT_DISCOVERY: u16 = 1;
pub const ROUTE_TYPE_DIRECT_SEGMENT_DISCOVERY: u16 = 2;
pub const ROUTE_TYPE_TYPE_1_SESSION_TRANSFORMED: u16 = 3;
pub const ROUTE_TYPE_TYPE_2_SESSION_TRANSFORMED: u16 = 4;

/// BGP-MUP Extended Community type (`0x0c`, transitive).
pub const EC_TYPE_MUP: u8 = 0x0c;
/// Sub-type for the Direct-Type Segment Identifier Extended Community.
pub const EC_SUBTYPE_MUP_DIRECT_SEG: u8 = 0x00;

fn malformed() -> Error {
    BgpError::UpdateMalformedAttributeList.into()
}

fn addr_bit_len(family: Family) -> Result<u8, Error> {
    match family.afi() {
        Family::AFI_IP => Ok(32),
        Family::AFI_IP6 => Ok(128),
        _ => Err(malformed()),
    }
}

fn decode_ip(family: Family, bytes: &[u8]) -> Result<IpAddr, Error> {
    match (family.afi(), bytes.len()) {
        (Family::AFI_IP, 4) => Ok(IpAddr::V4(Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))),
        (Family::AFI_IP6, 16) => {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(bytes);
            Ok(IpAddr::V6(Ipv6Addr::from(arr)))
        }
        _ => Err(malformed()),
    }
}

fn decode_prefix(family: Family, bit_len: u8, bytes: &[u8]) -> Result<IpAddr, Error> {
    let max_bits = addr_bit_len(family)?;
    if bit_len > max_bits {
        return Err(malformed());
    }
    let byte_len = bit_len.div_ceil(8) as usize;
    if bytes.len() < byte_len {
        return Err(malformed());
    }
    match family.afi() {
        Family::AFI_IP => {
            let mut arr = [0u8; 4];
            arr[..byte_len].copy_from_slice(&bytes[..byte_len]);
            Ok(IpAddr::V4(Ipv4Addr::from(arr)))
        }
        Family::AFI_IP6 => {
            let mut arr = [0u8; 16];
            arr[..byte_len].copy_from_slice(&bytes[..byte_len]);
            Ok(IpAddr::V6(Ipv6Addr::from(arr)))
        }
        _ => Err(malformed()),
    }
}

fn encode_prefix<B: BufMut>(dst: &mut B, addr: IpAddr, bit_len: u8) {
    let byte_len = bit_len.div_ceil(8) as usize;
    match addr {
        IpAddr::V4(a) => dst.put_slice(&a.octets()[..byte_len.min(4)]),
        IpAddr::V6(a) => dst.put_slice(&a.octets()[..byte_len.min(16)]),
    }
}

fn ip_octets(addr: IpAddr) -> Vec<u8> {
    match addr {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    }
}

/// A single BGP-MUP NLRI, parameterised by address family (IPv4-MUP or IPv6-MUP).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MupNlri {
    InterworkSegmentDiscovery(MupInterworkSegmentDiscoveryRoute),
    DirectSegmentDiscovery(MupDirectSegmentDiscoveryRoute),
    Type1SessionTransformed(MupType1SessionTransformedRoute),
    Type2SessionTransformed(MupType2SessionTransformedRoute),
}

/// Route Type 1: Interwork Segment Discovery Route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MupInterworkSegmentDiscoveryRoute {
    pub rd: RouteDistinguisher,
    pub prefix_addr: IpAddr,
    pub prefix_len: u8,
}

/// Route Type 2: Direct Segment Discovery Route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MupDirectSegmentDiscoveryRoute {
    pub rd: RouteDistinguisher,
    pub address: IpAddr,
}

/// Route Type 3: Type 1 Session Transformed Route (3GPP-5G).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MupType1SessionTransformedRoute {
    pub rd: RouteDistinguisher,
    pub prefix_addr: IpAddr,
    pub prefix_len: u8,
    pub teid: u32,
    pub qfi: u8,
    pub endpoint_address: IpAddr,
    pub source_address: Option<IpAddr>,
}

/// Route Type 4: Type 2 Session Transformed Route (3GPP-5G).
/// `endpoint_address_length` is the total bit length of the endpoint IP
/// and the trailing (possibly truncated) TEID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MupType2SessionTransformedRoute {
    pub rd: RouteDistinguisher,
    pub endpoint_address_length: u8,
    pub endpoint_address: IpAddr,
    pub teid: u32,
}

impl MupNlri {
    /// Decode a single MUP NLRI from `c`, consuming `4 + body_length` bytes.
    /// `len` is the upper bound of bytes remaining in the enclosing buffer.
    pub fn decode<T: io::Read>(family: Family, c: &mut T, len: usize) -> Result<Self, Error> {
        if len < 4 {
            return Err(malformed());
        }
        let mut header = [0u8; 4];
        c.read_exact(&mut header).map_err(|_| malformed())?;
        let arch_type = header[0];
        if arch_type != ARCH_TYPE_3GPP_5G {
            return Err(malformed());
        }
        let route_type = NetworkEndian::read_u16(&header[1..3]);
        let body_len = header[3] as usize;
        if len < 4 + body_len {
            return Err(malformed());
        }
        let mut body = vec![0u8; body_len];
        if body_len > 0 {
            c.read_exact(&mut body).map_err(|_| malformed())?;
        }
        match route_type {
            ROUTE_TYPE_INTERWORK_SEGMENT_DISCOVERY => Ok(MupNlri::InterworkSegmentDiscovery(
                MupInterworkSegmentDiscoveryRoute::decode(family, &body)?,
            )),
            ROUTE_TYPE_DIRECT_SEGMENT_DISCOVERY => Ok(MupNlri::DirectSegmentDiscovery(
                MupDirectSegmentDiscoveryRoute::decode(family, &body)?,
            )),
            ROUTE_TYPE_TYPE_1_SESSION_TRANSFORMED => Ok(MupNlri::Type1SessionTransformed(
                MupType1SessionTransformedRoute::decode(family, &body)?,
            )),
            ROUTE_TYPE_TYPE_2_SESSION_TRANSFORMED => Ok(MupNlri::Type2SessionTransformed(
                MupType2SessionTransformedRoute::decode(family, &body)?,
            )),
            _ => Err(malformed()),
        }
    }

    /// Encode the NLRI (header + body) into `dst` and return the number of bytes written.
    pub fn encode<B: BufMut>(&self, dst: &mut B) -> u16 {
        let (route_type, body) = match self {
            MupNlri::InterworkSegmentDiscovery(r) => {
                (ROUTE_TYPE_INTERWORK_SEGMENT_DISCOVERY, r.serialize())
            }
            MupNlri::DirectSegmentDiscovery(r) => {
                (ROUTE_TYPE_DIRECT_SEGMENT_DISCOVERY, r.serialize())
            }
            MupNlri::Type1SessionTransformed(r) => {
                (ROUTE_TYPE_TYPE_1_SESSION_TRANSFORMED, r.serialize())
            }
            MupNlri::Type2SessionTransformed(r) => {
                (ROUTE_TYPE_TYPE_2_SESSION_TRANSFORMED, r.serialize())
            }
        };
        dst.put_u8(ARCH_TYPE_3GPP_5G);
        dst.put_u16(route_type);
        dst.put_u8(body.len() as u8);
        dst.put_slice(&body);
        (4 + body.len()) as u16
    }

    pub fn route_type(&self) -> u16 {
        match self {
            MupNlri::InterworkSegmentDiscovery(_) => ROUTE_TYPE_INTERWORK_SEGMENT_DISCOVERY,
            MupNlri::DirectSegmentDiscovery(_) => ROUTE_TYPE_DIRECT_SEGMENT_DISCOVERY,
            MupNlri::Type1SessionTransformed(_) => ROUTE_TYPE_TYPE_1_SESSION_TRANSFORMED,
            MupNlri::Type2SessionTransformed(_) => ROUTE_TYPE_TYPE_2_SESSION_TRANSFORMED,
        }
    }
}

impl fmt::Display for MupNlri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MupNlri::InterworkSegmentDiscovery(r) => {
                write!(
                    f,
                    "[type:isd][rd:{}][prefix:{}/{}]",
                    r.rd, r.prefix_addr, r.prefix_len
                )
            }
            MupNlri::DirectSegmentDiscovery(r) => {
                write!(f, "[type:dsd][rd:{}][address:{}]", r.rd, r.address)
            }
            MupNlri::Type1SessionTransformed(r) => {
                write!(
                    f,
                    "[type:t1st][rd:{}][prefix:{}/{}][teid:{}][qfi:{}][endpoint:{}]",
                    r.rd, r.prefix_addr, r.prefix_len, r.teid, r.qfi, r.endpoint_address
                )?;
                if let Some(src) = r.source_address {
                    write!(f, "[source:{}]", src)?;
                }
                Ok(())
            }
            MupNlri::Type2SessionTransformed(r) => write!(
                f,
                "[type:t2st][rd:{}][endpoint-length:{}][endpoint:{}][teid:{}]",
                r.rd, r.endpoint_address_length, r.endpoint_address, r.teid
            ),
        }
    }
}

impl MupInterworkSegmentDiscoveryRoute {
    fn decode(family: Family, data: &[u8]) -> Result<Self, Error> {
        if data.len() < RouteDistinguisher::LEN + 1 {
            return Err(malformed());
        }
        let rd = RouteDistinguisher::decode(&data[..RouteDistinguisher::LEN])?;
        let prefix_len = data[RouteDistinguisher::LEN];
        let byte_len = prefix_len.div_ceil(8) as usize;
        let rest = &data[RouteDistinguisher::LEN + 1..];
        if rest.len() < byte_len {
            return Err(malformed());
        }
        let prefix_addr = decode_prefix(family, prefix_len, rest)?;
        Ok(Self {
            rd,
            prefix_addr,
            prefix_len,
        })
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.rd.encode(&mut buf);
        buf.put_u8(self.prefix_len);
        encode_prefix(&mut buf, self.prefix_addr, self.prefix_len);
        buf
    }
}

impl MupDirectSegmentDiscoveryRoute {
    fn decode(family: Family, data: &[u8]) -> Result<Self, Error> {
        if data.len() < RouteDistinguisher::LEN {
            return Err(malformed());
        }
        let rd = RouteDistinguisher::decode(&data[..RouteDistinguisher::LEN])?;
        let rest = &data[RouteDistinguisher::LEN..];
        let address = decode_ip(family, rest)?;
        Ok(Self { rd, address })
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.rd.encode(&mut buf);
        buf.extend_from_slice(&ip_octets(self.address));
        buf
    }
}

impl MupType1SessionTransformedRoute {
    fn decode(family: Family, data: &[u8]) -> Result<Self, Error> {
        let rd_end = RouteDistinguisher::LEN;
        if data.len() < rd_end + 1 {
            return Err(malformed());
        }
        let rd = RouteDistinguisher::decode(&data[..rd_end])?;
        let prefix_len = data[rd_end];
        let prefix_bytes = prefix_len.div_ceil(8) as usize;
        let after_prefix = rd_end + 1 + prefix_bytes;
        if data.len() < after_prefix + 4 + 1 + 1 {
            return Err(malformed());
        }
        let prefix_addr = decode_prefix(family, prefix_len, &data[rd_end + 1..])?;
        let teid = NetworkEndian::read_u32(&data[after_prefix..after_prefix + 4]);
        let qfi = data[after_prefix + 4];
        let ea_len = data[after_prefix + 5];
        let max_bits = addr_bit_len(family)?;
        if ea_len != max_bits {
            return Err(malformed());
        }
        let ea_bytes = (ea_len / 8) as usize;
        let ea_start = after_prefix + 6;
        if data.len() < ea_start + ea_bytes + 1 {
            return Err(malformed());
        }
        let endpoint_address = decode_ip(family, &data[ea_start..ea_start + ea_bytes])?;
        let sa_len_pos = ea_start + ea_bytes;
        let sa_len = data[sa_len_pos];
        let source_address = if sa_len == 0 {
            None
        } else {
            if sa_len != max_bits {
                return Err(malformed());
            }
            let sa_bytes = (sa_len / 8) as usize;
            let sa_start = sa_len_pos + 1;
            if data.len() < sa_start + sa_bytes {
                return Err(malformed());
            }
            Some(decode_ip(family, &data[sa_start..sa_start + sa_bytes])?)
        };
        Ok(Self {
            rd,
            prefix_addr,
            prefix_len,
            teid,
            qfi,
            endpoint_address,
            source_address,
        })
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.rd.encode(&mut buf);
        buf.put_u8(self.prefix_len);
        encode_prefix(&mut buf, self.prefix_addr, self.prefix_len);
        buf.put_u32(self.teid);
        buf.put_u8(self.qfi);
        let ea_bits = match self.endpoint_address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        buf.put_u8(ea_bits);
        buf.extend_from_slice(&ip_octets(self.endpoint_address));
        match self.source_address {
            None => buf.put_u8(0),
            Some(sa) => {
                let bits = match sa {
                    IpAddr::V4(_) => 32,
                    IpAddr::V6(_) => 128,
                };
                buf.put_u8(bits);
                buf.extend_from_slice(&ip_octets(sa));
            }
        }
        buf
    }
}

impl MupType2SessionTransformedRoute {
    fn decode(family: Family, data: &[u8]) -> Result<Self, Error> {
        let rd_end = RouteDistinguisher::LEN;
        if data.len() < rd_end + 1 {
            return Err(malformed());
        }
        let rd = RouteDistinguisher::decode(&data[..rd_end])?;
        let ea_len = data[rd_end];
        let ip_bits = addr_bit_len(family)?;
        if ea_len < ip_bits || ea_len > ip_bits + 32 {
            return Err(malformed());
        }
        let ip_bytes = (ip_bits / 8) as usize;
        let ip_start = rd_end + 1;
        if data.len() < ip_start + ip_bytes {
            return Err(malformed());
        }
        let endpoint_address = decode_ip(family, &data[ip_start..ip_start + ip_bytes])?;
        let teid_bits = ea_len - ip_bits;
        let teid_bytes = teid_bits.div_ceil(8) as usize;
        let teid_start = ip_start + ip_bytes;
        if data.len() < teid_start + teid_bytes {
            return Err(malformed());
        }
        let mut teid_buf = [0u8; 4];
        teid_buf[..teid_bytes].copy_from_slice(&data[teid_start..teid_start + teid_bytes]);
        let teid = NetworkEndian::read_u32(&teid_buf);
        Ok(Self {
            rd,
            endpoint_address_length: ea_len,
            endpoint_address,
            teid,
        })
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.rd.encode(&mut buf);
        buf.put_u8(self.endpoint_address_length);
        buf.extend_from_slice(&ip_octets(self.endpoint_address));
        let ip_bits = match self.endpoint_address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let teid_bits = self.endpoint_address_length.saturating_sub(ip_bits);
        let teid_bytes = teid_bits.div_ceil(8) as usize;
        let teid_be = self.teid.to_be_bytes();
        buf.extend_from_slice(&teid_be[..teid_bytes]);
        buf
    }
}

/// BGP-MUP Extended Community (draft-ietf-bess-mup-safi §3.2). 8 octets on
/// the wire: `[type=0x0c][sub_type][segment_id2:2][segment_id4:4]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MupExtended {
    pub sub_type: u8,
    pub segment_id2: u16,
    pub segment_id4: u32,
}

impl MupExtended {
    pub const LEN: usize = 8;

    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        if data.len() != Self::LEN {
            return Err(malformed());
        }
        if data[0] != EC_TYPE_MUP {
            return Err(malformed());
        }
        Ok(Self {
            sub_type: data[1],
            segment_id2: NetworkEndian::read_u16(&data[2..4]),
            segment_id4: NetworkEndian::read_u32(&data[4..8]),
        })
    }

    pub fn encode<B: BufMut>(&self, dst: &mut B) {
        dst.put_u8(EC_TYPE_MUP);
        dst.put_u8(self.sub_type);
        dst.put_u16(self.segment_id2);
        dst.put_u32(self.segment_id4);
    }
}

impl fmt::Display for MupExtended {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.segment_id2, self.segment_id4)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn rd() -> RouteDistinguisher {
        RouteDistinguisher::TwoOctetAs {
            admin: 100,
            assigned: 200,
        }
    }

    fn roundtrip(family: Family, nlri: MupNlri) {
        let mut buf = Vec::new();
        nlri.encode(&mut buf);
        let len = buf.len();
        let mut c = Cursor::new(buf);
        let decoded = MupNlri::decode(family, &mut c, len).unwrap();
        assert_eq!(decoded, nlri);
        assert_eq!(c.position(), len as u64);
    }

    #[test]
    fn isd_ipv4_roundtrip() {
        roundtrip(
            Family::IPV4_MUP,
            MupNlri::InterworkSegmentDiscovery(MupInterworkSegmentDiscoveryRoute {
                rd: rd(),
                prefix_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                prefix_len: 24,
            }),
        );
    }

    #[test]
    fn isd_ipv6_roundtrip() {
        roundtrip(
            Family::IPV6_MUP,
            MupNlri::InterworkSegmentDiscovery(MupInterworkSegmentDiscoveryRoute {
                rd: rd(),
                prefix_addr: IpAddr::V6("2001:db8::".parse().unwrap()),
                prefix_len: 32,
            }),
        );
    }

    #[test]
    fn dsd_ipv4_roundtrip() {
        roundtrip(
            Family::IPV4_MUP,
            MupNlri::DirectSegmentDiscovery(MupDirectSegmentDiscoveryRoute {
                rd: rd(),
                address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            }),
        );
    }

    #[test]
    fn dsd_ipv6_roundtrip() {
        roundtrip(
            Family::IPV6_MUP,
            MupNlri::DirectSegmentDiscovery(MupDirectSegmentDiscoveryRoute {
                rd: rd(),
                address: IpAddr::V6("2001:db8::1".parse().unwrap()),
            }),
        );
    }

    #[test]
    fn t1st_ipv4_with_source() {
        roundtrip(
            Family::IPV4_MUP,
            MupNlri::Type1SessionTransformed(MupType1SessionTransformedRoute {
                rd: rd(),
                prefix_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
                prefix_len: 32,
                teid: 12345,
                qfi: 9,
                endpoint_address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                source_address: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            }),
        );
    }

    #[test]
    fn t1st_ipv4_without_source() {
        roundtrip(
            Family::IPV4_MUP,
            MupNlri::Type1SessionTransformed(MupType1SessionTransformedRoute {
                rd: rd(),
                prefix_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
                prefix_len: 32,
                teid: 12345,
                qfi: 9,
                endpoint_address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                source_address: None,
            }),
        );
    }

    #[test]
    fn t1st_ipv6_with_source() {
        roundtrip(
            Family::IPV6_MUP,
            MupNlri::Type1SessionTransformed(MupType1SessionTransformedRoute {
                rd: rd(),
                prefix_addr: IpAddr::V6("2001:db8::1".parse().unwrap()),
                prefix_len: 128,
                teid: 42,
                qfi: 5,
                endpoint_address: IpAddr::V6("2001:db8::2".parse().unwrap()),
                source_address: Some(IpAddr::V6("2001:db8::3".parse().unwrap())),
            }),
        );
    }

    #[test]
    fn t2st_ipv4_full_teid() {
        // endpoint length = 32 (IP) + 32 (TEID) = 64 bits
        roundtrip(
            Family::IPV4_MUP,
            MupNlri::Type2SessionTransformed(MupType2SessionTransformedRoute {
                rd: rd(),
                endpoint_address_length: 64,
                endpoint_address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                teid: 0xDEADBEEF,
            }),
        );
    }

    #[test]
    fn t2st_ipv4_truncated_teid() {
        // endpoint length = 32 (IP) + 16 (TEID upper bits) = 48 bits
        // teid = 0xAABB0000 encoded as [0xaa, 0xbb]
        roundtrip(
            Family::IPV4_MUP,
            MupNlri::Type2SessionTransformed(MupType2SessionTransformedRoute {
                rd: rd(),
                endpoint_address_length: 48,
                endpoint_address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                teid: 0xAABB_0000,
            }),
        );
    }

    #[test]
    fn t2st_ipv4_no_teid() {
        roundtrip(
            Family::IPV4_MUP,
            MupNlri::Type2SessionTransformed(MupType2SessionTransformedRoute {
                rd: rd(),
                endpoint_address_length: 32,
                endpoint_address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                teid: 0,
            }),
        );
    }

    #[test]
    fn t2st_ipv6_full_teid() {
        roundtrip(
            Family::IPV6_MUP,
            MupNlri::Type2SessionTransformed(MupType2SessionTransformedRoute {
                rd: rd(),
                endpoint_address_length: 160,
                endpoint_address: IpAddr::V6("2001:db8::1".parse().unwrap()),
                teid: 0x01020304,
            }),
        );
    }

    fn decode_slice(family: Family, data: &[u8]) -> Result<MupNlri, Error> {
        let len = data.len();
        let mut c = Cursor::new(data);
        MupNlri::decode(family, &mut c, len)
    }

    #[test]
    fn decode_rejects_wrong_arch_type() {
        assert!(decode_slice(Family::IPV4_MUP, &[0x02u8, 0x00, 0x01, 0x00]).is_err());
    }

    #[test]
    fn decode_rejects_unknown_route_type() {
        assert!(decode_slice(Family::IPV4_MUP, &[0x01u8, 0x00, 0x05, 0x00]).is_err());
    }

    #[test]
    fn decode_rejects_truncated() {
        // header claims length=10 but body is empty
        assert!(decode_slice(Family::IPV4_MUP, &[0x01u8, 0x00, 0x01, 0x0a]).is_err());
    }

    #[test]
    fn mup_extended_roundtrip() {
        let ec = MupExtended {
            sub_type: EC_SUBTYPE_MUP_DIRECT_SEG,
            segment_id2: 10,
            segment_id4: 20,
        };
        let mut buf = Vec::new();
        ec.encode(&mut buf);
        assert_eq!(buf.len(), MupExtended::LEN);
        assert_eq!(buf, vec![0x0c, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x14]);
        assert_eq!(MupExtended::decode(&buf).unwrap(), ec);
    }

    #[test]
    fn mup_extended_rejects_wrong_type() {
        let bad = [0x06u8, 0x00, 0, 0, 0, 0, 0, 0];
        assert!(MupExtended::decode(&bad).is_err());
    }

    #[test]
    fn isd_ipv4_wire_format() {
        // Arch=1, RT=1, Len=13 => RD(8)+PLen(1)+Prefix(3 bytes for /24)
        let nlri = MupNlri::InterworkSegmentDiscovery(MupInterworkSegmentDiscoveryRoute {
            rd: RouteDistinguisher::TwoOctetAs {
                admin: 100,
                assigned: 200,
            },
            prefix_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            prefix_len: 24,
        });
        let mut buf = Vec::new();
        nlri.encode(&mut buf);
        // header(4) + RD(8) + PLen(1) + prefix(3) = 16
        assert_eq!(buf.len(), 16);
        assert_eq!(buf[0], 0x01); // arch 3gpp-5g
        assert_eq!(&buf[1..3], &[0x00, 0x01]); // route type 1
        assert_eq!(buf[3], 12); // body length
        // RD TwoOctetAs 100:200
        assert_eq!(
            &buf[4..12],
            &[0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8]
        );
        assert_eq!(buf[12], 24); // prefix len bits
        assert_eq!(&buf[13..16], &[10, 0, 0]);
    }
}
