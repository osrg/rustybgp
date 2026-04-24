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

//! BGP Prefix SID Attribute (RFC 8669, path attribute type 40).
//!
//! Known TLVs, sub-TLVs, and sub-sub-TLVs are parsed into typed
//! variants; everything else is preserved as `Unknown { type, value }`
//! so the attribute round-trips byte-for-byte regardless of the
//! specific TLV mix an originator chose.

use crate::error::{BgpError, Error};
use byteorder::{NetworkEndian, ReadBytesExt};
use bytes::BufMut;
use std::io::{self, Cursor, Read};
use std::net::Ipv6Addr;

fn malformed() -> Error {
    BgpError::UpdateMalformedAttributeList.into()
}

/// Read a `[type: 1][length: 2 BE]` header plus `length` bytes of value.
/// Returns the type byte and the (owned) value bytes, and advances `c`.
fn read_tlv_header<T: io::Read>(c: &mut T) -> Result<(u8, Vec<u8>), Error> {
    let type_id = c.read_u8().map_err(|_| malformed())?;
    let len = c.read_u16::<NetworkEndian>().map_err(|_| malformed())? as usize;
    let mut value = vec![0u8; len];
    c.read_exact(&mut value).map_err(|_| malformed())?;
    Ok((type_id, value))
}

fn write_tlv<B: BufMut>(dst: &mut B, type_id: u8, value: &[u8]) {
    dst.put_u8(type_id);
    dst.put_u16(value.len() as u16);
    dst.put_slice(value);
}

/// The decoded Prefix SID attribute value (everything after the path
/// attribute header).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PrefixSid {
    pub tlvs: Vec<PrefixSidTlv>,
}

/// Top-level Prefix SID TLV. Unknown TLV types are preserved verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PrefixSidTlv {
    Srv6L3Service(Srv6ServiceTlv),
    Srv6L2Service(Srv6ServiceTlv),
    Unknown { type_id: u8, value: Vec<u8> },
}

/// Payload shared by SRv6 L3/L2 Service TLVs: a reserved byte followed
/// by zero or more service sub-TLVs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Srv6ServiceTlv {
    pub reserved: u8,
    pub sub_tlvs: Vec<Srv6ServiceSubTlv>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Srv6ServiceSubTlv {
    Information(Srv6InformationSubTlv),
    Unknown { type_id: u8, value: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Srv6InformationSubTlv {
    pub sid: Ipv6Addr,
    pub flags: u8,
    pub endpoint_behavior: u16,
    pub sub_sub_tlvs: Vec<Srv6ServiceDataSubSubTlv>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Srv6ServiceDataSubSubTlv {
    Structure(Srv6SidStructureSubSubTlv),
    Unknown { type_id: u8, value: Vec<u8> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Srv6SidStructureSubSubTlv {
    pub locator_block_length: u8,
    pub locator_node_length: u8,
    pub function_length: u8,
    pub argument_length: u8,
    pub transposition_length: u8,
    pub transposition_offset: u8,
}

impl PrefixSid {
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut c = Cursor::new(data);
        let total = data.len() as u64;
        let mut tlvs = Vec::new();
        while c.position() < total {
            let (type_id, value) = read_tlv_header(&mut c)?;
            tlvs.push(PrefixSidTlv::decode(type_id, &value)?);
        }
        Ok(PrefixSid { tlvs })
    }

    pub fn encode<B: BufMut>(&self, dst: &mut B) {
        for tlv in &self.tlvs {
            tlv.encode(dst);
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut v = Vec::new();
        self.encode(&mut v);
        v
    }
}

impl PrefixSidTlv {
    /// TLV type for SRv6 L3 Service (RFC 9252 §2).
    pub const TLV_SRV6_L3_SERVICE: u8 = 5;
    /// TLV type for SRv6 L2 Service.
    pub const TLV_SRV6_L2_SERVICE: u8 = 6;

    fn decode(type_id: u8, value: &[u8]) -> Result<Self, Error> {
        match type_id {
            Self::TLV_SRV6_L3_SERVICE => {
                Ok(PrefixSidTlv::Srv6L3Service(Srv6ServiceTlv::decode(value)?))
            }
            Self::TLV_SRV6_L2_SERVICE => {
                Ok(PrefixSidTlv::Srv6L2Service(Srv6ServiceTlv::decode(value)?))
            }
            _ => Ok(PrefixSidTlv::Unknown {
                type_id,
                value: value.to_vec(),
            }),
        }
    }

    fn encode<B: BufMut>(&self, dst: &mut B) {
        match self {
            PrefixSidTlv::Srv6L3Service(t) => {
                write_tlv(dst, Self::TLV_SRV6_L3_SERVICE, &t.to_vec())
            }
            PrefixSidTlv::Srv6L2Service(t) => {
                write_tlv(dst, Self::TLV_SRV6_L2_SERVICE, &t.to_vec())
            }
            PrefixSidTlv::Unknown { type_id, value } => write_tlv(dst, *type_id, value),
        }
    }
}

impl Srv6ServiceTlv {
    fn decode(data: &[u8]) -> Result<Self, Error> {
        if data.is_empty() {
            return Err(malformed());
        }
        let mut c = Cursor::new(data);
        let total = data.len() as u64;
        let reserved = c.read_u8().map_err(|_| malformed())?;
        let mut sub_tlvs = Vec::new();
        while c.position() < total {
            let (type_id, value) = read_tlv_header(&mut c)?;
            sub_tlvs.push(Srv6ServiceSubTlv::decode(type_id, &value)?);
        }
        Ok(Srv6ServiceTlv { reserved, sub_tlvs })
    }

    fn to_vec(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.put_u8(self.reserved);
        for sub in &self.sub_tlvs {
            sub.encode(&mut v);
        }
        v
    }
}

impl Srv6ServiceSubTlv {
    /// Sub-TLV type for SRv6 SID Information (RFC 9252 §3.1).
    pub const SUBTLV_SRV6_INFORMATION: u8 = 1;

    fn decode(type_id: u8, value: &[u8]) -> Result<Self, Error> {
        match type_id {
            Self::SUBTLV_SRV6_INFORMATION => Ok(Srv6ServiceSubTlv::Information(
                Srv6InformationSubTlv::decode(value)?,
            )),
            _ => Ok(Srv6ServiceSubTlv::Unknown {
                type_id,
                value: value.to_vec(),
            }),
        }
    }

    fn encode<B: BufMut>(&self, dst: &mut B) {
        match self {
            Srv6ServiceSubTlv::Information(info) => {
                write_tlv(dst, Self::SUBTLV_SRV6_INFORMATION, &info.to_vec())
            }
            Srv6ServiceSubTlv::Unknown { type_id, value } => write_tlv(dst, *type_id, value),
        }
    }
}

impl Srv6InformationSubTlv {
    /// Fixed prefix length before any sub-sub-TLVs:
    /// Reserved(1) + SID(16) + Flags(1) + Endpoint Behavior(2) + Reserved(1) = 21 bytes.
    const FIXED_LEN: usize = 21;

    fn decode(data: &[u8]) -> Result<Self, Error> {
        if data.len() < Self::FIXED_LEN {
            return Err(malformed());
        }
        let mut c = Cursor::new(data);
        let total = data.len() as u64;
        let _reserved = c.read_u8().map_err(|_| malformed())?;
        let mut sid_bytes = [0u8; 16];
        c.read_exact(&mut sid_bytes).map_err(|_| malformed())?;
        let sid = Ipv6Addr::from(sid_bytes);
        let flags = c.read_u8().map_err(|_| malformed())?;
        let endpoint_behavior = c.read_u16::<NetworkEndian>().map_err(|_| malformed())?;
        let _reserved = c.read_u8().map_err(|_| malformed())?;
        let mut sub_sub_tlvs = Vec::new();
        while c.position() < total {
            let (type_id, value) = read_tlv_header(&mut c)?;
            sub_sub_tlvs.push(Srv6ServiceDataSubSubTlv::decode(type_id, &value)?);
        }
        Ok(Srv6InformationSubTlv {
            sid,
            flags,
            endpoint_behavior,
            sub_sub_tlvs,
        })
    }

    fn to_vec(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(Self::FIXED_LEN);
        v.put_u8(0); // Reserved
        v.extend_from_slice(&self.sid.octets());
        v.put_u8(self.flags);
        v.put_u16(self.endpoint_behavior);
        v.put_u8(0); // Reserved
        for sub in &self.sub_sub_tlvs {
            sub.encode(&mut v);
        }
        v
    }
}

impl Srv6ServiceDataSubSubTlv {
    /// Sub-Sub-TLV type for SRv6 SID Structure (RFC 9252 §3.2.1).
    pub const SUBSUBTLV_SRV6_SID_STRUCTURE: u8 = 1;

    fn decode(type_id: u8, value: &[u8]) -> Result<Self, Error> {
        match type_id {
            Self::SUBSUBTLV_SRV6_SID_STRUCTURE => Ok(Srv6ServiceDataSubSubTlv::Structure(
                Srv6SidStructureSubSubTlv::decode(value)?,
            )),
            _ => Ok(Srv6ServiceDataSubSubTlv::Unknown {
                type_id,
                value: value.to_vec(),
            }),
        }
    }

    fn encode<B: BufMut>(&self, dst: &mut B) {
        match self {
            Srv6ServiceDataSubSubTlv::Structure(s) => {
                write_tlv(dst, Self::SUBSUBTLV_SRV6_SID_STRUCTURE, &(*s).to_vec())
            }
            Srv6ServiceDataSubSubTlv::Unknown { type_id, value } => write_tlv(dst, *type_id, value),
        }
    }
}

impl Srv6SidStructureSubSubTlv {
    /// Fixed 6-octet value (RFC 9252 §3.2.1).
    pub const LEN: usize = 6;

    fn decode(data: &[u8]) -> Result<Self, Error> {
        if data.len() < Self::LEN {
            return Err(malformed());
        }
        let mut c = Cursor::new(data);
        Ok(Srv6SidStructureSubSubTlv {
            locator_block_length: c.read_u8().map_err(|_| malformed())?,
            locator_node_length: c.read_u8().map_err(|_| malformed())?,
            function_length: c.read_u8().map_err(|_| malformed())?,
            argument_length: c.read_u8().map_err(|_| malformed())?,
            transposition_length: c.read_u8().map_err(|_| malformed())?,
            transposition_offset: c.read_u8().map_err(|_| malformed())?,
        })
    }

    fn to_vec(self) -> Vec<u8> {
        vec![
            self.locator_block_length,
            self.locator_node_length,
            self.function_length,
            self.argument_length,
            self.transposition_length,
            self.transposition_offset,
        ]
    }
}

#[test]
fn empty_attribute_roundtrip() {
    let sid = PrefixSid { tlvs: Vec::new() };
    let bytes = sid.to_vec();
    assert!(bytes.is_empty());
    assert_eq!(PrefixSid::decode(&bytes).unwrap(), sid);
}

#[test]
fn unknown_tlv_passthrough() {
    let sid = PrefixSid {
        tlvs: vec![PrefixSidTlv::Unknown {
            type_id: 99,
            value: vec![0x01, 0x02, 0x03],
        }],
    };
    let bytes = sid.to_vec();
    assert_eq!(bytes, vec![99, 0x00, 0x03, 0x01, 0x02, 0x03]);
    assert_eq!(PrefixSid::decode(&bytes).unwrap(), sid);
}

#[test]
fn srv6_l3_service_roundtrip() {
    let sid = PrefixSid {
        tlvs: vec![PrefixSidTlv::Srv6L3Service(Srv6ServiceTlv {
            reserved: 0,
            sub_tlvs: vec![Srv6ServiceSubTlv::Information(Srv6InformationSubTlv {
                sid: "2001:0:5:3::".parse().unwrap(),
                flags: 0,
                endpoint_behavior: 19, // End.DT4
                sub_sub_tlvs: vec![Srv6ServiceDataSubSubTlv::Structure(
                    Srv6SidStructureSubSubTlv {
                        locator_block_length: 40,
                        locator_node_length: 24,
                        function_length: 16,
                        argument_length: 0,
                        transposition_length: 16,
                        transposition_offset: 64,
                    },
                )],
            })],
        })],
    };
    let bytes = sid.to_vec();
    assert_eq!(PrefixSid::decode(&bytes).unwrap(), sid);
}

#[test]
fn srv6_l3_service_wire_format() {
    // Known-good byte sequence from RFC 9252 examples / gobgp
    // prefix_sid_test.go: SRv6 L3 Service TLV with Information sub-TLV
    // (SID 2001:0:5:3::, End.DT4, SID Structure 40/24/16/0/16/64).
    // Attribute value only; path-attribute header is omitted.
    let expected: Vec<u8> = vec![
        // TLV: type=5, length=34
        0x05, 0x00, 0x22, // SRv6 L3 Service TLV value
        0x00, // Reserved
        // Sub-TLV: type=1, length=30
        0x01, 0x00, 0x1e, // SRv6 Information sub-TLV value
        0x00, // Reserved
        0x20, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x03, // SID bytes 0..8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SID bytes 8..16
        0x00, // Flags
        0x00, 0x13, // Endpoint Behavior 19
        0x00, // Reserved
        // Sub-Sub-TLV: type=1, length=6
        0x01, 0x00, 0x06, // SRv6 SID Structure
        0x28, 0x18, 0x10, 0x00, 0x10, 0x40,
    ];
    let decoded = PrefixSid::decode(&expected).unwrap();
    assert_eq!(decoded.to_vec(), expected);
    match &decoded.tlvs[0] {
        PrefixSidTlv::Srv6L3Service(t) => match &t.sub_tlvs[0] {
            Srv6ServiceSubTlv::Information(i) => {
                assert_eq!(i.sid, "2001:0:5:3::".parse::<Ipv6Addr>().unwrap());
                assert_eq!(i.endpoint_behavior, 19);
                match &i.sub_sub_tlvs[0] {
                    Srv6ServiceDataSubSubTlv::Structure(s) => {
                        assert_eq!(s.locator_block_length, 40);
                        assert_eq!(s.locator_node_length, 24);
                        assert_eq!(s.function_length, 16);
                        assert_eq!(s.argument_length, 0);
                        assert_eq!(s.transposition_length, 16);
                        assert_eq!(s.transposition_offset, 64);
                    }
                    _ => panic!("expected Structure sub-sub-tlv"),
                }
            }
            _ => panic!("expected Information sub-tlv"),
        },
        _ => panic!("expected Srv6L3Service"),
    }
}

#[test]
fn unknown_sub_tlv_skipped_as_unknown() {
    // L3 Service with Reserved + unknown sub-TLV type 0xff (length 3).
    let bytes: Vec<u8> = vec![
        0x05, 0x00, 0x07, // TLV type=5, length=7
        0x00, // Reserved
        0xff, 0x00, 0x03, 0x01, 0x02, 0x03,
    ];
    let decoded = PrefixSid::decode(&bytes).unwrap();
    assert_eq!(decoded.to_vec(), bytes);
    match &decoded.tlvs[0] {
        PrefixSidTlv::Srv6L3Service(t) => match &t.sub_tlvs[0] {
            Srv6ServiceSubTlv::Unknown { type_id, value } => {
                assert_eq!(*type_id, 0xff);
                assert_eq!(value, &vec![0x01, 0x02, 0x03]);
            }
            _ => panic!("expected Unknown sub-tlv"),
        },
        _ => panic!("expected L3 Service"),
    }
}

#[test]
fn decode_rejects_truncated_tlv_header() {
    assert!(PrefixSid::decode(&[0x05, 0x00]).is_err());
}

#[test]
fn decode_rejects_truncated_tlv_value() {
    // type=5, length=10, but only 2 bytes of value follow
    assert!(PrefixSid::decode(&[0x05, 0x00, 0x0a, 0x00, 0x00]).is_err());
}

#[test]
fn decode_rejects_information_sub_tlv_too_short() {
    // L3 Service with an Information sub-TLV whose value is shorter than FIXED_LEN.
    let bytes: Vec<u8> = vec![
        0x05, 0x00, 0x07, 0x00, // TLV type=5, length=7, reserved
        0x01, 0x00, 0x03, 0x00, 0x00, 0x00, // Information sub-TLV with 3-byte value
    ];
    assert!(PrefixSid::decode(&bytes).is_err());
}

#[test]
fn decode_rejects_sid_structure_too_short() {
    // Information sub-TLV with a Sub-Sub-TLV type=1 whose length is 3 instead of 6.
    let bytes: Vec<u8> = vec![
        0x05, 0x00, 0x1f, // TLV type=5, length=31
        0x00, // Reserved
        0x01, 0x00, 0x1b, // Sub-TLV type=1, length=27
        0x00, // Reserved
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    // SID
        0x00, // Flags
        0x00, 0x00, // Endpoint
        0x00, // Reserved
        0x01, 0x00, 0x03, 0x01, 0x02, 0x03, // Bogus SID Structure len=3
    ];
    assert!(PrefixSid::decode(&bytes).is_err());
}
