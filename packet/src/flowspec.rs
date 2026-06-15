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

//! BGP Flowspec NLRI (RFC 8955 IPv4, RFC 8956 IPv6), AFI=1/SAFI=133 and AFI=2/SAFI=133.
//!
//! Wire format per NLRI:
//!   1 byte  length (or 2 bytes if >= 240: first byte = 0xF0 | high_nibble)
//!   [type (1 byte) + type-specific data] ...
//!
//! Prefix components (type 1=DstPrefix, 2=SrcPrefix):
//!   IPv4: 1-byte prefix_len + ceil(prefix_len/8) addr bytes
//!   IPv6: 1-byte prefix_len + 1-byte offset + ceil(prefix_len/8) addr bytes
//!
//! Operator-value components (types 3-12, type 13 for IPv6 FlowLabel):
//!   [op_byte + value (1/2/4/8 bytes)] ...  (end-of-list when op_byte bit 7 is set)
//!   Op byte: end(7) | and(6) | len(5-4) | lt(2) | gt(1) | eq(0)

use crate::bgp::{Ipv4Net, Ipv6Net};
use byteorder::{BigEndian, ReadBytesExt};
use bytes::BufMut;
use std::fmt;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

fn malformed() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "malformed Flowspec NLRI")
}

/// Operator byte for numeric and bitmask Flowspec components.
///
/// The wire length bits (5-4) are stripped on decode and recomputed from
/// `value` on encode, so `bits` always has bits 5-4 == 0.
#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub struct Op {
    /// End(7), AND(6), comparison(2-0) flags; length bits always zero.
    pub bits: u8,
    pub value: u64,
}

impl Op {
    /// End-of-list: this is the last operator in the component.
    pub const END: u8 = 0x80;
    /// AND: combine with the preceding operator using AND (default is OR).
    pub const AND: u8 = 0x40;
    /// Numeric comparison flags (bits 2-0).
    pub const LT: u8 = 0x04;
    pub const GT: u8 = 0x02;
    pub const EQ: u8 = 0x01;
    pub const GT_EQ: u8 = Self::GT | Self::EQ;
    pub const LT_EQ: u8 = Self::LT | Self::EQ;
    /// Bitmask operator flags (types TcpFlags, Fragment).
    pub const MATCH: u8 = 0x01;
    pub const NOT: u8 = 0x02;

    pub fn is_end(self) -> bool {
        self.bits & Self::END != 0
    }

    fn len_order(value: u64) -> u8 {
        if value <= 0xFF {
            0
        } else if value <= 0xFFFF {
            1
        } else if value <= 0xFFFF_FFFF {
            2
        } else {
            3
        }
    }

    pub fn decode<R: io::Read>(r: &mut R) -> io::Result<Self> {
        let raw = r.read_u8()?;
        let order = (raw >> 4) & 0x3;
        let bits = raw & 0b1100_1111; // strip length bits 5-4
        let value = match order {
            0 => r.read_u8()? as u64,
            1 => r.read_u16::<BigEndian>()? as u64,
            2 => r.read_u32::<BigEndian>()? as u64,
            _ => r.read_u64::<BigEndian>()?,
        };
        Ok(Op { bits, value })
    }

    pub fn encode<B: BufMut>(self, dst: &mut B) -> usize {
        let order = Self::len_order(self.value);
        dst.put_u8(self.bits | (order << 4));
        match order {
            0 => {
                dst.put_u8(self.value as u8);
                2
            }
            1 => {
                dst.put_u16(self.value as u16);
                3
            }
            2 => {
                dst.put_u32(self.value as u32);
                5
            }
            _ => {
                dst.put_u64(self.value);
                9
            }
        }
    }
}

fn decode_ops<R: io::Read>(r: &mut R) -> io::Result<Vec<Op>> {
    let mut ops = Vec::new();
    loop {
        let op = Op::decode(r)?;
        let end = op.is_end();
        ops.push(op);
        if end {
            break;
        }
    }
    Ok(ops)
}

fn encode_ops<B: BufMut>(ops: &[Op], dst: &mut B) -> usize {
    ops.iter().map(|&op| op.encode(dst)).sum()
}

fn decode_ipv4_prefix<R: io::Read>(r: &mut R) -> io::Result<Ipv4Net> {
    let prefix_bits = r.read_u8()?;
    if prefix_bits > 32 {
        return Err(malformed());
    }
    let prefix_bytes = prefix_bits.div_ceil(8) as usize;
    let mut addr = [0u8; 4];
    for b in addr.iter_mut().take(prefix_bytes) {
        *b = r.read_u8()?;
    }
    Ok(Ipv4Net {
        addr: Ipv4Addr::from(addr),
        mask: prefix_bits,
    })
}

fn encode_ipv4_prefix<B: BufMut>(net: &Ipv4Net, type_byte: u8, dst: &mut B) -> usize {
    let prefix_bytes = net.mask.div_ceil(8) as usize;
    dst.put_u8(type_byte);
    dst.put_u8(net.mask);
    for i in 0..prefix_bytes {
        dst.put_u8(net.addr.octets()[i]);
    }
    2 + prefix_bytes
}

fn decode_ipv6_prefix<R: io::Read>(r: &mut R) -> io::Result<(Ipv6Net, u8)> {
    let prefix_bits = r.read_u8()?;
    if prefix_bits > 128 {
        return Err(malformed());
    }
    let offset = r.read_u8()?;
    let prefix_bytes = prefix_bits.div_ceil(8) as usize;
    let mut addr = [0u8; 16];
    for b in addr.iter_mut().take(prefix_bytes) {
        *b = r.read_u8()?;
    }
    Ok((
        Ipv6Net {
            addr: Ipv6Addr::from(addr),
            mask: prefix_bits,
        },
        offset,
    ))
}

fn encode_ipv6_prefix<B: BufMut>(net: &Ipv6Net, offset: u8, type_byte: u8, dst: &mut B) -> usize {
    let prefix_bytes = net.mask.div_ceil(8) as usize;
    dst.put_u8(type_byte);
    dst.put_u8(net.mask);
    dst.put_u8(offset);
    for i in 0..prefix_bytes {
        dst.put_u8(net.addr.octets()[i]);
    }
    3 + prefix_bytes
}

fn read_nlri_len<R: io::Read>(r: &mut R) -> io::Result<(usize, usize)> {
    let first = r.read_u8()?;
    if first < 0xF0 {
        Ok((first as usize, 1))
    } else {
        let second = r.read_u8()?;
        let len = ((first as usize & 0x0F) << 8) | second as usize;
        Ok((len, 2))
    }
}

fn write_nlri_len<B: BufMut>(len: usize, dst: &mut B) {
    if len < 0xF0 {
        dst.put_u8(len as u8);
    } else {
        dst.put_u8(0xF0 | ((len >> 8) as u8));
        dst.put_u8((len & 0xFF) as u8);
    }
}

/// Flowspec component for IPv4 unicast (RFC 8955, types 1-12).
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub enum FlowspecV4Component {
    DstPrefix(Ipv4Net),
    SrcPrefix(Ipv4Net),
    Protocol(Vec<Op>),
    Port(Vec<Op>),
    DstPort(Vec<Op>),
    SrcPort(Vec<Op>),
    IcmpType(Vec<Op>),
    IcmpCode(Vec<Op>),
    TcpFlags(Vec<Op>),
    PacketLen(Vec<Op>),
    Dscp(Vec<Op>),
    Fragment(Vec<Op>),
}

impl FlowspecV4Component {
    fn decode<R: io::Read>(r: &mut R) -> io::Result<Self> {
        match r.read_u8()? {
            1 => Ok(FlowspecV4Component::DstPrefix(decode_ipv4_prefix(r)?)),
            2 => Ok(FlowspecV4Component::SrcPrefix(decode_ipv4_prefix(r)?)),
            3 => Ok(FlowspecV4Component::Protocol(decode_ops(r)?)),
            4 => Ok(FlowspecV4Component::Port(decode_ops(r)?)),
            5 => Ok(FlowspecV4Component::DstPort(decode_ops(r)?)),
            6 => Ok(FlowspecV4Component::SrcPort(decode_ops(r)?)),
            7 => Ok(FlowspecV4Component::IcmpType(decode_ops(r)?)),
            8 => Ok(FlowspecV4Component::IcmpCode(decode_ops(r)?)),
            9 => Ok(FlowspecV4Component::TcpFlags(decode_ops(r)?)),
            10 => Ok(FlowspecV4Component::PacketLen(decode_ops(r)?)),
            11 => Ok(FlowspecV4Component::Dscp(decode_ops(r)?)),
            12 => Ok(FlowspecV4Component::Fragment(decode_ops(r)?)),
            t => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown flowspec v4 component type {t}"),
            )),
        }
    }

    fn encode<B: BufMut>(&self, dst: &mut B) -> usize {
        match self {
            FlowspecV4Component::DstPrefix(net) => encode_ipv4_prefix(net, 1, dst),
            FlowspecV4Component::SrcPrefix(net) => encode_ipv4_prefix(net, 2, dst),
            FlowspecV4Component::Protocol(ops) => {
                dst.put_u8(3);
                1 + encode_ops(ops, dst)
            }
            FlowspecV4Component::Port(ops) => {
                dst.put_u8(4);
                1 + encode_ops(ops, dst)
            }
            FlowspecV4Component::DstPort(ops) => {
                dst.put_u8(5);
                1 + encode_ops(ops, dst)
            }
            FlowspecV4Component::SrcPort(ops) => {
                dst.put_u8(6);
                1 + encode_ops(ops, dst)
            }
            FlowspecV4Component::IcmpType(ops) => {
                dst.put_u8(7);
                1 + encode_ops(ops, dst)
            }
            FlowspecV4Component::IcmpCode(ops) => {
                dst.put_u8(8);
                1 + encode_ops(ops, dst)
            }
            FlowspecV4Component::TcpFlags(ops) => {
                dst.put_u8(9);
                1 + encode_ops(ops, dst)
            }
            FlowspecV4Component::PacketLen(ops) => {
                dst.put_u8(10);
                1 + encode_ops(ops, dst)
            }
            FlowspecV4Component::Dscp(ops) => {
                dst.put_u8(11);
                1 + encode_ops(ops, dst)
            }
            FlowspecV4Component::Fragment(ops) => {
                dst.put_u8(12);
                1 + encode_ops(ops, dst)
            }
        }
    }
}

/// Flowspec component for IPv6 unicast (RFC 8956, types 1-13).
///
/// Types 1/2 carry an `offset` field (absent in IPv4).
/// Type 3 is Next Header (equivalent to Protocol in IPv4).
/// Type 13 is Flow Label (IPv6-only).
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub enum FlowspecV6Component {
    DstPrefix { prefix: Ipv6Net, offset: u8 },
    SrcPrefix { prefix: Ipv6Net, offset: u8 },
    NextHeader(Vec<Op>),
    Port(Vec<Op>),
    DstPort(Vec<Op>),
    SrcPort(Vec<Op>),
    IcmpType(Vec<Op>),
    IcmpCode(Vec<Op>),
    TcpFlags(Vec<Op>),
    PacketLen(Vec<Op>),
    Dscp(Vec<Op>),
    Fragment(Vec<Op>),
    FlowLabel(Vec<Op>),
}

impl FlowspecV6Component {
    fn decode<R: io::Read>(r: &mut R) -> io::Result<Self> {
        match r.read_u8()? {
            1 => {
                let (prefix, offset) = decode_ipv6_prefix(r)?;
                Ok(FlowspecV6Component::DstPrefix { prefix, offset })
            }
            2 => {
                let (prefix, offset) = decode_ipv6_prefix(r)?;
                Ok(FlowspecV6Component::SrcPrefix { prefix, offset })
            }
            3 => Ok(FlowspecV6Component::NextHeader(decode_ops(r)?)),
            4 => Ok(FlowspecV6Component::Port(decode_ops(r)?)),
            5 => Ok(FlowspecV6Component::DstPort(decode_ops(r)?)),
            6 => Ok(FlowspecV6Component::SrcPort(decode_ops(r)?)),
            7 => Ok(FlowspecV6Component::IcmpType(decode_ops(r)?)),
            8 => Ok(FlowspecV6Component::IcmpCode(decode_ops(r)?)),
            9 => Ok(FlowspecV6Component::TcpFlags(decode_ops(r)?)),
            10 => Ok(FlowspecV6Component::PacketLen(decode_ops(r)?)),
            11 => Ok(FlowspecV6Component::Dscp(decode_ops(r)?)),
            12 => Ok(FlowspecV6Component::Fragment(decode_ops(r)?)),
            13 => Ok(FlowspecV6Component::FlowLabel(decode_ops(r)?)),
            t => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown flowspec v6 component type {t}"),
            )),
        }
    }

    fn encode<B: BufMut>(&self, dst: &mut B) -> usize {
        match self {
            FlowspecV6Component::DstPrefix { prefix, offset } => {
                encode_ipv6_prefix(prefix, *offset, 1, dst)
            }
            FlowspecV6Component::SrcPrefix { prefix, offset } => {
                encode_ipv6_prefix(prefix, *offset, 2, dst)
            }
            FlowspecV6Component::NextHeader(ops) => {
                dst.put_u8(3);
                1 + encode_ops(ops, dst)
            }
            FlowspecV6Component::Port(ops) => {
                dst.put_u8(4);
                1 + encode_ops(ops, dst)
            }
            FlowspecV6Component::DstPort(ops) => {
                dst.put_u8(5);
                1 + encode_ops(ops, dst)
            }
            FlowspecV6Component::SrcPort(ops) => {
                dst.put_u8(6);
                1 + encode_ops(ops, dst)
            }
            FlowspecV6Component::IcmpType(ops) => {
                dst.put_u8(7);
                1 + encode_ops(ops, dst)
            }
            FlowspecV6Component::IcmpCode(ops) => {
                dst.put_u8(8);
                1 + encode_ops(ops, dst)
            }
            FlowspecV6Component::TcpFlags(ops) => {
                dst.put_u8(9);
                1 + encode_ops(ops, dst)
            }
            FlowspecV6Component::PacketLen(ops) => {
                dst.put_u8(10);
                1 + encode_ops(ops, dst)
            }
            FlowspecV6Component::Dscp(ops) => {
                dst.put_u8(11);
                1 + encode_ops(ops, dst)
            }
            FlowspecV6Component::Fragment(ops) => {
                dst.put_u8(12);
                1 + encode_ops(ops, dst)
            }
            FlowspecV6Component::FlowLabel(ops) => {
                dst.put_u8(13);
                1 + encode_ops(ops, dst)
            }
        }
    }
}

/// Flowspec IPv4 unicast NLRI (AFI=1, SAFI=133).
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct FlowspecV4Nlri {
    pub components: Vec<FlowspecV4Component>,
}

impl FlowspecV4Nlri {
    pub fn decode<R: io::Read>(r: &mut R, len: usize) -> io::Result<Self> {
        if len < 1 {
            return Err(malformed());
        }
        let (nlri_len, hdr) = read_nlri_len(r)?;
        if nlri_len + hdr > len {
            return Err(malformed());
        }
        let mut buf = vec![0u8; nlri_len];
        r.read_exact(&mut buf)?;
        let mut c = io::Cursor::new(&buf);
        let mut components = Vec::new();
        while (c.position() as usize) < nlri_len {
            components.push(FlowspecV4Component::decode(&mut c)?);
        }
        Ok(FlowspecV4Nlri { components })
    }

    pub fn encode<B: BufMut>(&self, dst: &mut B) {
        let mut body = Vec::new();
        for comp in &self.components {
            comp.encode(&mut body);
        }
        write_nlri_len(body.len(), dst);
        dst.put_slice(&body);
    }
}

/// Flowspec IPv6 unicast NLRI (AFI=2, SAFI=133).
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct FlowspecV6Nlri {
    pub components: Vec<FlowspecV6Component>,
}

impl FlowspecV6Nlri {
    pub fn decode<R: io::Read>(r: &mut R, len: usize) -> io::Result<Self> {
        if len < 1 {
            return Err(malformed());
        }
        let (nlri_len, hdr) = read_nlri_len(r)?;
        if nlri_len + hdr > len {
            return Err(malformed());
        }
        let mut buf = vec![0u8; nlri_len];
        r.read_exact(&mut buf)?;
        let mut c = io::Cursor::new(&buf);
        let mut components = Vec::new();
        while (c.position() as usize) < nlri_len {
            components.push(FlowspecV6Component::decode(&mut c)?);
        }
        Ok(FlowspecV6Nlri { components })
    }

    pub fn encode<B: BufMut>(&self, dst: &mut B) {
        let mut body = Vec::new();
        for comp in &self.components {
            comp.encode(&mut body);
        }
        write_nlri_len(body.len(), dst);
        dst.put_slice(&body);
    }
}

impl fmt::Display for FlowspecV4Nlri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "flowspec-v4[{}]", self.components.len())
    }
}

impl fmt::Display for FlowspecV6Nlri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "flowspec-v6[{}]", self.components.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // Test vectors generated by packet/tests/fixtures/gen/flowspec_nlri (GoBGP v4.6.0).

    // IPv4 Flowspec: DstPrefix=10.0.1.0/24
    const V4_DST_PREFIX: &[u8] = &[0x05, 0x01, 0x18, 0x0a, 0x00, 0x01];

    // IPv4 Flowspec: DstPrefix=10.0.1.0/24, Protocol=TCP(6), DstPort=80
    const V4_DST_PREFIX_PROTO_TCP_PORT_80: &[u8] = &[
        0x0b, 0x01, 0x18, 0x0a, 0x00, 0x01, 0x03, 0x81, 0x06, 0x05, 0x81, 0x50,
    ];

    // IPv4 Flowspec: DstPort >= 1024 AND <= 65535
    const V4_DST_PORT_RANGE: &[u8] = &[0x07, 0x05, 0x13, 0x04, 0x00, 0xd5, 0xff, 0xff];

    // IPv6 Flowspec: DstPrefix=2001:db8::/32, offset=0
    const V6_DST_PREFIX_NO_OFFSET: &[u8] = &[0x07, 0x01, 0x20, 0x00, 0x20, 0x01, 0x0d, 0xb8];

    // IPv6 Flowspec: DstPrefix=2001:db8::/32, offset=16
    const V6_DST_PREFIX_WITH_OFFSET: &[u8] = &[0x07, 0x01, 0x20, 0x10, 0x20, 0x01, 0x0d, 0xb8];

    // IPv6 Flowspec: NextHeader=TCP(6), FlowLabel=100
    const V6_NEXT_HEADER_TCP_FLOW_LABEL_100: &[u8] = &[0x06, 0x03, 0x81, 0x06, 0x0d, 0x81, 0x64];

    #[test]
    fn v4_dst_prefix_roundtrip() {
        let mut c = Cursor::new(V4_DST_PREFIX);
        let nlri = FlowspecV4Nlri::decode(&mut c, V4_DST_PREFIX.len()).unwrap();
        assert_eq!(nlri.components.len(), 1);
        let FlowspecV4Component::DstPrefix(net) = &nlri.components[0] else {
            panic!("expected DstPrefix");
        };
        assert_eq!(net.addr, "10.0.1.0".parse::<Ipv4Addr>().unwrap());
        assert_eq!(net.mask, 24);
        let mut buf = Vec::new();
        nlri.encode(&mut buf);
        assert_eq!(buf, V4_DST_PREFIX);
    }

    #[test]
    fn v4_compound_rule_roundtrip() {
        let mut c = Cursor::new(V4_DST_PREFIX_PROTO_TCP_PORT_80);
        let nlri = FlowspecV4Nlri::decode(&mut c, V4_DST_PREFIX_PROTO_TCP_PORT_80.len()).unwrap();
        assert_eq!(nlri.components.len(), 3);
        let FlowspecV4Component::DstPrefix(net) = &nlri.components[0] else {
            panic!("expected DstPrefix");
        };
        assert_eq!(net.mask, 24);
        let FlowspecV4Component::Protocol(ops) = &nlri.components[1] else {
            panic!("expected Protocol");
        };
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].value, 6);
        assert!(ops[0].is_end());
        let FlowspecV4Component::DstPort(ops) = &nlri.components[2] else {
            panic!("expected DstPort");
        };
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].value, 80);
        assert!(ops[0].is_end());
        let mut buf = Vec::new();
        nlri.encode(&mut buf);
        assert_eq!(buf, V4_DST_PREFIX_PROTO_TCP_PORT_80);
    }

    #[test]
    fn v4_dst_port_range_roundtrip() {
        let mut c = Cursor::new(V4_DST_PORT_RANGE);
        let nlri = FlowspecV4Nlri::decode(&mut c, V4_DST_PORT_RANGE.len()).unwrap();
        assert_eq!(nlri.components.len(), 1);
        let FlowspecV4Component::DstPort(ops) = &nlri.components[0] else {
            panic!("expected DstPort");
        };
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[0].bits & Op::GT_EQ, Op::GT_EQ);
        assert_eq!(ops[0].value, 1024);
        assert_eq!(ops[1].bits & Op::LT_EQ, Op::LT_EQ);
        assert_eq!(ops[1].bits & Op::AND, Op::AND);
        assert!(ops[1].is_end());
        assert_eq!(ops[1].value, 65535);
        let mut buf = Vec::new();
        nlri.encode(&mut buf);
        assert_eq!(buf, V4_DST_PORT_RANGE);
    }

    #[test]
    fn v6_dst_prefix_no_offset_roundtrip() {
        let mut c = Cursor::new(V6_DST_PREFIX_NO_OFFSET);
        let nlri = FlowspecV6Nlri::decode(&mut c, V6_DST_PREFIX_NO_OFFSET.len()).unwrap();
        assert_eq!(nlri.components.len(), 1);
        let FlowspecV6Component::DstPrefix { prefix, offset } = &nlri.components[0] else {
            panic!("expected DstPrefix");
        };
        assert_eq!(prefix.addr, "2001:db8::".parse::<Ipv6Addr>().unwrap());
        assert_eq!(prefix.mask, 32);
        assert_eq!(*offset, 0);
        let mut buf = Vec::new();
        nlri.encode(&mut buf);
        assert_eq!(buf, V6_DST_PREFIX_NO_OFFSET);
    }

    #[test]
    fn v6_dst_prefix_with_offset_roundtrip() {
        let mut c = Cursor::new(V6_DST_PREFIX_WITH_OFFSET);
        let nlri = FlowspecV6Nlri::decode(&mut c, V6_DST_PREFIX_WITH_OFFSET.len()).unwrap();
        let FlowspecV6Component::DstPrefix { prefix, offset } = &nlri.components[0] else {
            panic!("expected DstPrefix");
        };
        assert_eq!(prefix.mask, 32);
        assert_eq!(*offset, 16);
        let mut buf = Vec::new();
        nlri.encode(&mut buf);
        assert_eq!(buf, V6_DST_PREFIX_WITH_OFFSET);
    }

    #[test]
    fn v6_next_header_flow_label_roundtrip() {
        let mut c = Cursor::new(V6_NEXT_HEADER_TCP_FLOW_LABEL_100);
        let nlri = FlowspecV6Nlri::decode(&mut c, V6_NEXT_HEADER_TCP_FLOW_LABEL_100.len()).unwrap();
        assert_eq!(nlri.components.len(), 2);
        let FlowspecV6Component::NextHeader(ops) = &nlri.components[0] else {
            panic!("expected NextHeader");
        };
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].value, 6);
        let FlowspecV6Component::FlowLabel(ops) = &nlri.components[1] else {
            panic!("expected FlowLabel");
        };
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].value, 100);
        let mut buf = Vec::new();
        nlri.encode(&mut buf);
        assert_eq!(buf, V6_NEXT_HEADER_TCP_FLOW_LABEL_100);
    }
}
