// Copyright (C) 2024 The RustyBGP Authors.
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

//! BGP Link State (BGP-LS) NLRI and attribute encoding/decoding.
//!
//! Implements the base BGP-LS specification (RFC 9552) and the BGP-LS
//! attribute (Type 29).

use byteorder::{NetworkEndian, ReadBytesExt};
use bytes::BufMut;
use std::fmt;
use std::io::{Cursor, Read};
use std::net::{Ipv4Addr, Ipv6Addr};

// ---------------------------------------------------------------------------
// NLRI type constants (RFC 9552 §2.1)
// ---------------------------------------------------------------------------

pub const NLRI_TYPE_NODE: u16 = 1;
pub const NLRI_TYPE_LINK: u16 = 2;
pub const NLRI_TYPE_PREFIX_V4: u16 = 3;
pub const NLRI_TYPE_PREFIX_V6: u16 = 4;
pub const NLRI_TYPE_SRV6_SID: u16 = 6;

// ---------------------------------------------------------------------------
// Protocol-ID constants (RFC 9552 §3.2)
// ---------------------------------------------------------------------------

pub const PROTOCOL_ISIS_L1: u8 = 1;
pub const PROTOCOL_ISIS_L2: u8 = 2;
pub const PROTOCOL_OSPF_V2: u8 = 3;
pub const PROTOCOL_DIRECT: u8 = 4;
pub const PROTOCOL_STATIC: u8 = 5;
pub const PROTOCOL_OSPF_V3: u8 = 6;
pub const PROTOCOL_BGP: u8 = 7;

// ---------------------------------------------------------------------------
// Descriptor TLV type codes (RFC 9552 §3.2)
// ---------------------------------------------------------------------------

const TLV_LOCAL_NODE_DESC: u16 = 256;
const TLV_REMOTE_NODE_DESC: u16 = 257;
const TLV_LINK_ID: u16 = 258;
const TLV_IPV4_INTERFACE_ADDR: u16 = 259;
const TLV_IPV4_NEIGHBOR_ADDR: u16 = 260;
const TLV_IPV6_INTERFACE_ADDR: u16 = 261;
const TLV_IPV6_NEIGHBOR_ADDR: u16 = 262;
const TLV_MULTI_TOPO_ID: u16 = 263;
const TLV_OSPF_ROUTE_TYPE: u16 = 264;
const TLV_IP_REACH_INFO: u16 = 265;

// Node descriptor sub-TLV type codes (RFC 9552 §3.2.1)
const TLV_AS: u16 = 512;
const TLV_BGP_LS_ID: u16 = 513;
const TLV_OSPF_AREA: u16 = 514;
const TLV_IGP_ROUTER_ID: u16 = 515;
const TLV_BGP_ROUTER_ID: u16 = 516; // RFC 9086
const TLV_BGP_CONFEDERATION_MEMBER: u16 = 517; // RFC 9086

// ---------------------------------------------------------------------------
// BGP-LS Attribute TLV type codes (RFC 9552 §3.3, RFC 9085, RFC 9086)
// ---------------------------------------------------------------------------

// Node Attribute TLVs (RFC 9552)
pub const TLV_NODE_FLAG_BITS: u16 = 1024;
pub const TLV_OPAQUE_NODE_ATTR: u16 = 1025;
pub const TLV_NODE_NAME: u16 = 1026;
pub const TLV_ISIS_AREA: u16 = 1027;
pub const TLV_IPV4_LOCAL_ROUTER_ID: u16 = 1028;
pub const TLV_IPV6_LOCAL_ROUTER_ID: u16 = 1029;
pub const TLV_IPV4_REMOTE_ROUTER_ID: u16 = 1030;
pub const TLV_IPV6_REMOTE_ROUTER_ID: u16 = 1031;
// Node SR Attribute TLVs (RFC 9085 §2.1)
pub const TLV_SR_CAPABILITIES: u16 = 1034;
pub const TLV_SR_ALGORITHM: u16 = 1035;
pub const TLV_SR_LOCAL_BLOCK: u16 = 1036;
// Link Attribute TLVs (RFC 9552)
pub const TLV_ADMIN_GROUP: u16 = 1088;
pub const TLV_MAX_LINK_BANDWIDTH: u16 = 1089;
pub const TLV_MAX_RESERVABLE_BANDWIDTH: u16 = 1090;
pub const TLV_UNRESERVED_BANDWIDTH: u16 = 1091;
pub const TLV_TE_DEFAULT_METRIC: u16 = 1092;
pub const TLV_IGP_METRIC: u16 = 1095;
pub const TLV_SRLG: u16 = 1096;
pub const TLV_OPAQUE_LINK_ATTR: u16 = 1097;
pub const TLV_LINK_NAME: u16 = 1098;
// Link SR Attribute TLVs (RFC 9085 §2.2, RFC 9086 §4)
pub const TLV_ADJ_SID: u16 = 1099;
pub const TLV_PEER_NODE_SID: u16 = 1101;
pub const TLV_PEER_ADJ_SID: u16 = 1102;
pub const TLV_PEER_SET_SID: u16 = 1103;
// Prefix Attribute TLVs (RFC 9552)
pub const TLV_IGP_FLAGS: u16 = 1152;
pub const TLV_OPAQUE_PREFIX_ATTR: u16 = 1157;
// Prefix SR Attribute TLVs (RFC 9085 §2.3)
pub const TLV_PREFIX_SID: u16 = 1158;

// ---------------------------------------------------------------------------
// Low-level TLV I/O helpers
// ---------------------------------------------------------------------------

fn read_tlv(c: &mut Cursor<&[u8]>) -> Option<(u16, Vec<u8>)> {
    let tlv_type = c.read_u16::<NetworkEndian>().ok()?;
    let tlv_len = c.read_u16::<NetworkEndian>().ok()? as usize;
    let pos = c.position() as usize;
    let buf = *c.get_ref();
    if pos + tlv_len > buf.len() {
        return None;
    }
    let value = buf[pos..pos + tlv_len].to_vec();
    c.set_position((pos + tlv_len) as u64);
    Some((tlv_type, value))
}

fn write_tlv<B: BufMut>(dst: &mut B, tlv_type: u16, value: &[u8]) {
    dst.put_u16(tlv_type);
    dst.put_u16(value.len() as u16);
    dst.put_slice(value);
}

// ---------------------------------------------------------------------------
// NodeDescriptor
// ---------------------------------------------------------------------------

/// Local or remote node descriptor (RFC 9552 §3.2.1).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct NodeDescriptor {
    pub asn: Option<u32>,
    pub bgp_ls_id: Option<u32>,
    pub ospf_area_id: Option<u32>,
    /// Raw bytes: 4 bytes for OSPF, 6 or 7 bytes for IS-IS.
    pub igp_router_id: Option<Vec<u8>>,
    pub bgp_router_id: Option<[u8; 4]>,
    pub bgp_confederation_member: Option<u32>,
}

impl NodeDescriptor {
    fn decode(data: &[u8]) -> Self {
        let mut nd = NodeDescriptor::default();
        let mut c = Cursor::new(data);
        while (c.position() as usize) < data.len() {
            let Some((tlv_type, value)) = read_tlv(&mut c) else {
                break;
            };
            match tlv_type {
                TLV_AS if value.len() >= 4 => {
                    nd.asn = Some(u32::from_be_bytes(value[..4].try_into().unwrap()));
                }
                TLV_BGP_LS_ID if value.len() >= 4 => {
                    nd.bgp_ls_id = Some(u32::from_be_bytes(value[..4].try_into().unwrap()));
                }
                TLV_OSPF_AREA if value.len() >= 4 => {
                    nd.ospf_area_id = Some(u32::from_be_bytes(value[..4].try_into().unwrap()));
                }
                TLV_IGP_ROUTER_ID => {
                    nd.igp_router_id = Some(value);
                }
                TLV_BGP_ROUTER_ID if value.len() >= 4 => {
                    nd.bgp_router_id = Some(value[..4].try_into().unwrap());
                }
                TLV_BGP_CONFEDERATION_MEMBER if value.len() >= 4 => {
                    nd.bgp_confederation_member =
                        Some(u32::from_be_bytes(value[..4].try_into().unwrap()));
                }
                _ => {}
            }
        }
        nd
    }

    fn encode<B: BufMut>(&self, dst: &mut B, container_type: u16) {
        let mut body = Vec::new();
        if let Some(asn) = self.asn {
            write_tlv(&mut body, TLV_AS, &asn.to_be_bytes());
        }
        if let Some(id) = self.bgp_ls_id {
            write_tlv(&mut body, TLV_BGP_LS_ID, &id.to_be_bytes());
        }
        if let Some(area) = self.ospf_area_id {
            write_tlv(&mut body, TLV_OSPF_AREA, &area.to_be_bytes());
        }
        if let Some(ref rid) = self.igp_router_id {
            write_tlv(&mut body, TLV_IGP_ROUTER_ID, rid);
        }
        if let Some(rid) = self.bgp_router_id {
            write_tlv(&mut body, TLV_BGP_ROUTER_ID, &rid);
        }
        if let Some(member) = self.bgp_confederation_member {
            write_tlv(
                &mut body,
                TLV_BGP_CONFEDERATION_MEMBER,
                &member.to_be_bytes(),
            );
        }
        write_tlv(dst, container_type, &body);
    }
}

// ---------------------------------------------------------------------------
// Link Descriptor TLVs
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum LinkDescTlv {
    LinkId { local: u32, remote: u32 },
    Ipv4InterfaceAddr([u8; 4]),
    Ipv4NeighborAddr([u8; 4]),
    Ipv6InterfaceAddr([u8; 16]),
    Ipv6NeighborAddr([u8; 16]),
    MultiTopoId(Vec<u16>),
    Unknown { tlv_type: u16, value: Vec<u8> },
}

fn decode_link_desc_tlvs(data: &[u8]) -> Vec<LinkDescTlv> {
    let mut tlvs = Vec::new();
    let mut c = Cursor::new(data);
    while (c.position() as usize) < data.len() {
        let Some((tlv_type, value)) = read_tlv(&mut c) else {
            break;
        };
        let tlv = match tlv_type {
            TLV_LINK_ID if value.len() >= 8 => LinkDescTlv::LinkId {
                local: u32::from_be_bytes(value[..4].try_into().unwrap()),
                remote: u32::from_be_bytes(value[4..8].try_into().unwrap()),
            },
            TLV_IPV4_INTERFACE_ADDR if value.len() >= 4 => {
                LinkDescTlv::Ipv4InterfaceAddr(value[..4].try_into().unwrap())
            }
            TLV_IPV4_NEIGHBOR_ADDR if value.len() >= 4 => {
                LinkDescTlv::Ipv4NeighborAddr(value[..4].try_into().unwrap())
            }
            TLV_IPV6_INTERFACE_ADDR if value.len() >= 16 => {
                LinkDescTlv::Ipv6InterfaceAddr(value[..16].try_into().unwrap())
            }
            TLV_IPV6_NEIGHBOR_ADDR if value.len() >= 16 => {
                LinkDescTlv::Ipv6NeighborAddr(value[..16].try_into().unwrap())
            }
            TLV_MULTI_TOPO_ID => {
                let ids = value
                    .chunks_exact(2)
                    .map(|b| u16::from_be_bytes([b[0], b[1]]) & 0x0fff)
                    .collect();
                LinkDescTlv::MultiTopoId(ids)
            }
            _ => LinkDescTlv::Unknown { tlv_type, value },
        };
        tlvs.push(tlv);
    }
    tlvs
}

fn encode_link_desc_tlvs<B: BufMut>(tlvs: &[LinkDescTlv], dst: &mut B) {
    for tlv in tlvs {
        match tlv {
            LinkDescTlv::LinkId { local, remote } => {
                let mut v = [0u8; 8];
                v[..4].copy_from_slice(&local.to_be_bytes());
                v[4..].copy_from_slice(&remote.to_be_bytes());
                write_tlv(dst, TLV_LINK_ID, &v);
            }
            LinkDescTlv::Ipv4InterfaceAddr(a) => write_tlv(dst, TLV_IPV4_INTERFACE_ADDR, a),
            LinkDescTlv::Ipv4NeighborAddr(a) => write_tlv(dst, TLV_IPV4_NEIGHBOR_ADDR, a),
            LinkDescTlv::Ipv6InterfaceAddr(a) => write_tlv(dst, TLV_IPV6_INTERFACE_ADDR, a),
            LinkDescTlv::Ipv6NeighborAddr(a) => write_tlv(dst, TLV_IPV6_NEIGHBOR_ADDR, a),
            LinkDescTlv::MultiTopoId(ids) => {
                let v: Vec<u8> = ids.iter().flat_map(|id| id.to_be_bytes()).collect();
                write_tlv(dst, TLV_MULTI_TOPO_ID, &v);
            }
            LinkDescTlv::Unknown { tlv_type, value } => write_tlv(dst, *tlv_type, value),
        }
    }
}

// ---------------------------------------------------------------------------
// Prefix Descriptor TLVs
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PrefixDescTlv {
    MultiTopoId(Vec<u16>),
    OspfRouteType(u8),
    /// `prefix_len` in bits; `addr` holds ceil(prefix_len/8) bytes.
    IpReachability {
        prefix_len: u8,
        addr: Vec<u8>,
    },
    Unknown {
        tlv_type: u16,
        value: Vec<u8>,
    },
}

fn decode_prefix_desc_tlvs(data: &[u8]) -> Vec<PrefixDescTlv> {
    let mut tlvs = Vec::new();
    let mut c = Cursor::new(data);
    while (c.position() as usize) < data.len() {
        let Some((tlv_type, value)) = read_tlv(&mut c) else {
            break;
        };
        let tlv = match tlv_type {
            TLV_MULTI_TOPO_ID => {
                let ids = value
                    .chunks_exact(2)
                    .map(|b| u16::from_be_bytes([b[0], b[1]]) & 0x0fff)
                    .collect();
                PrefixDescTlv::MultiTopoId(ids)
            }
            TLV_OSPF_ROUTE_TYPE if !value.is_empty() => PrefixDescTlv::OspfRouteType(value[0]),
            TLV_IP_REACH_INFO if !value.is_empty() => {
                let prefix_len = value[0];
                let byte_len = prefix_len.div_ceil(8) as usize;
                let addr = if byte_len < value.len() {
                    value[1..1 + byte_len].to_vec()
                } else {
                    value[1..].to_vec()
                };
                PrefixDescTlv::IpReachability { prefix_len, addr }
            }
            _ => PrefixDescTlv::Unknown { tlv_type, value },
        };
        tlvs.push(tlv);
    }
    tlvs
}

fn encode_prefix_desc_tlvs<B: BufMut>(tlvs: &[PrefixDescTlv], dst: &mut B) {
    for tlv in tlvs {
        match tlv {
            PrefixDescTlv::MultiTopoId(ids) => {
                let v: Vec<u8> = ids.iter().flat_map(|id| id.to_be_bytes()).collect();
                write_tlv(dst, TLV_MULTI_TOPO_ID, &v);
            }
            PrefixDescTlv::OspfRouteType(t) => write_tlv(dst, TLV_OSPF_ROUTE_TYPE, &[*t]),
            PrefixDescTlv::IpReachability { prefix_len, addr } => {
                let mut v = vec![*prefix_len];
                v.extend_from_slice(addr);
                write_tlv(dst, TLV_IP_REACH_INFO, &v);
            }
            PrefixDescTlv::Unknown { tlv_type, value } => write_tlv(dst, *tlv_type, value),
        }
    }
}

// ---------------------------------------------------------------------------
// BGP-LS NLRI structs
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BgpLsNodeNlri {
    pub protocol_id: u8,
    pub identifier: u64,
    pub local_node: NodeDescriptor,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BgpLsLinkNlri {
    pub protocol_id: u8,
    pub identifier: u64,
    pub local_node: NodeDescriptor,
    pub remote_node: NodeDescriptor,
    pub link_desc: Vec<LinkDescTlv>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BgpLsPrefixNlri {
    pub protocol_id: u8,
    pub identifier: u64,
    pub local_node: NodeDescriptor,
    pub prefix_desc: Vec<PrefixDescTlv>,
}

/// BGP-LS NLRI (RFC 9552, AFI=16388, SAFI=71).
///
/// Unknown NLRI types (e.g., SRv6 SID before Phase 3 support) are stored in
/// `Unknown` so the wire bytes are consumed without dropping the peer session.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum BgpLsNlri {
    Node(BgpLsNodeNlri),
    Link(BgpLsLinkNlri),
    PrefixV4(BgpLsPrefixNlri),
    PrefixV6(BgpLsPrefixNlri),
    Unknown { nlri_type: u16, body: Vec<u8> },
}

impl BgpLsNlri {
    /// Decode one BGP-LS NLRI from `c`.
    /// Reads: Type(2) + Length(2) + Body(Length).
    pub fn decode<R: Read + ReadBytesExt>(c: &mut R) -> Option<Self> {
        let nlri_type = c.read_u16::<NetworkEndian>().ok()?;
        let nlri_len = c.read_u16::<NetworkEndian>().ok()? as usize;
        let mut body = vec![0u8; nlri_len];
        c.read_exact(&mut body).ok()?;

        if body.len() < 9 {
            return Some(BgpLsNlri::Unknown { nlri_type, body });
        }
        let protocol_id = body[0];
        let identifier = u64::from_be_bytes(body[1..9].try_into().ok()?);
        let rest = &body[9..];

        match nlri_type {
            NLRI_TYPE_NODE => {
                let local_node = decode_node_desc_container(rest)?;
                Some(BgpLsNlri::Node(BgpLsNodeNlri {
                    protocol_id,
                    identifier,
                    local_node,
                }))
            }
            NLRI_TYPE_LINK => {
                let (local_node, after_local) = decode_node_desc_and_rest(rest)?;
                let (remote_node, link_rest) = decode_node_desc_and_rest(after_local)?;
                let link_desc = decode_link_desc_tlvs(link_rest);
                Some(BgpLsNlri::Link(BgpLsLinkNlri {
                    protocol_id,
                    identifier,
                    local_node,
                    remote_node,
                    link_desc,
                }))
            }
            NLRI_TYPE_PREFIX_V4 => {
                let (local_node, prefix_rest) = decode_node_desc_and_rest(rest)?;
                let prefix_desc = decode_prefix_desc_tlvs(prefix_rest);
                Some(BgpLsNlri::PrefixV4(BgpLsPrefixNlri {
                    protocol_id,
                    identifier,
                    local_node,
                    prefix_desc,
                }))
            }
            NLRI_TYPE_PREFIX_V6 => {
                let (local_node, prefix_rest) = decode_node_desc_and_rest(rest)?;
                let prefix_desc = decode_prefix_desc_tlvs(prefix_rest);
                Some(BgpLsNlri::PrefixV6(BgpLsPrefixNlri {
                    protocol_id,
                    identifier,
                    local_node,
                    prefix_desc,
                }))
            }
            _ => Some(BgpLsNlri::Unknown { nlri_type, body }),
        }
    }

    /// Encode this NLRI: Type(2) + Length(2) + Body.
    pub fn encode<B: BufMut>(&self, dst: &mut B) {
        let mut body = Vec::new();
        match self {
            BgpLsNlri::Node(n) => {
                body.push(n.protocol_id);
                body.extend_from_slice(&n.identifier.to_be_bytes());
                n.local_node.encode(&mut body, TLV_LOCAL_NODE_DESC);
                write_tlv_header(dst, NLRI_TYPE_NODE, &body);
            }
            BgpLsNlri::Link(n) => {
                body.push(n.protocol_id);
                body.extend_from_slice(&n.identifier.to_be_bytes());
                n.local_node.encode(&mut body, TLV_LOCAL_NODE_DESC);
                n.remote_node.encode(&mut body, TLV_REMOTE_NODE_DESC);
                encode_link_desc_tlvs(&n.link_desc, &mut body);
                write_tlv_header(dst, NLRI_TYPE_LINK, &body);
            }
            BgpLsNlri::PrefixV4(n) => {
                body.push(n.protocol_id);
                body.extend_from_slice(&n.identifier.to_be_bytes());
                n.local_node.encode(&mut body, TLV_LOCAL_NODE_DESC);
                encode_prefix_desc_tlvs(&n.prefix_desc, &mut body);
                write_tlv_header(dst, NLRI_TYPE_PREFIX_V4, &body);
            }
            BgpLsNlri::PrefixV6(n) => {
                body.push(n.protocol_id);
                body.extend_from_slice(&n.identifier.to_be_bytes());
                n.local_node.encode(&mut body, TLV_LOCAL_NODE_DESC);
                encode_prefix_desc_tlvs(&n.prefix_desc, &mut body);
                write_tlv_header(dst, NLRI_TYPE_PREFIX_V6, &body);
            }
            BgpLsNlri::Unknown { nlri_type, body: b } => {
                write_tlv_header(dst, *nlri_type, b);
            }
        }
    }
}

/// Write a 2-byte type + 2-byte length + body (the NLRI framing).
fn write_tlv_header<B: BufMut>(dst: &mut B, nlri_type: u16, body: &[u8]) {
    dst.put_u16(nlri_type);
    dst.put_u16(body.len() as u16);
    dst.put_slice(body);
}

/// Parse a Local or Remote Node Descriptor container TLV and return the
/// inner `NodeDescriptor`.  The container TLV must be the first TLV in `data`.
fn decode_node_desc_container(data: &[u8]) -> Option<NodeDescriptor> {
    let mut c = Cursor::new(data);
    let (tlv_type, value) = read_tlv(&mut c)?;
    if tlv_type != TLV_LOCAL_NODE_DESC && tlv_type != TLV_REMOTE_NODE_DESC {
        return None;
    }
    Some(NodeDescriptor::decode(&value))
}

/// Parse a node descriptor container from the front of `data`, returning the
/// `NodeDescriptor` and the remaining bytes after the container TLV.
fn decode_node_desc_and_rest(data: &[u8]) -> Option<(NodeDescriptor, &[u8])> {
    let mut c = Cursor::new(data);
    let (tlv_type, value) = read_tlv(&mut c)?;
    if tlv_type != TLV_LOCAL_NODE_DESC && tlv_type != TLV_REMOTE_NODE_DESC {
        return None;
    }
    let consumed = c.position() as usize;
    Some((NodeDescriptor::decode(&value), &data[consumed..]))
}

impl fmt::Display for BgpLsNlri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BgpLsNlri::Node(n) => {
                write!(f, "bgp-ls:node:proto={}:id={}", n.protocol_id, n.identifier)
            }
            BgpLsNlri::Link(n) => {
                write!(f, "bgp-ls:link:proto={}:id={}", n.protocol_id, n.identifier)
            }
            BgpLsNlri::PrefixV4(n) => write!(
                f,
                "bgp-ls:prefix-v4:proto={}:id={}",
                n.protocol_id, n.identifier
            ),
            BgpLsNlri::PrefixV6(n) => write!(
                f,
                "bgp-ls:prefix-v6:proto={}:id={}",
                n.protocol_id, n.identifier
            ),
            BgpLsNlri::Unknown { nlri_type, .. } => write!(f, "bgp-ls:unknown:{}", nlri_type),
        }
    }
}

// ---------------------------------------------------------------------------
// BGP-LS Attribute (Type 29) TLVs
// ---------------------------------------------------------------------------

/// A contiguous SID/label range [begin, end] (inclusive) from SR Capabilities
/// or SR Local Block TLVs (RFC 9085 §2.1.2).
#[derive(Clone, Debug, PartialEq)]
pub struct SrRange {
    pub begin: u32,
    pub end: u32,
}

/// Parsed representation of a single BGP-LS Attribute TLV (Type 29).
///
/// `f32` fields (bandwidth) are not Hash/Eq; this type is only used for
/// parsing and gRPC conversion, never as a map key.
#[derive(Clone, Debug, PartialEq)]
pub enum LsTlv {
    // Node Attribute TLVs (RFC 9552)
    NodeFlagBits(u8),
    OpaqueNodeAttr(Vec<u8>),
    NodeName(String),
    IsisArea(Vec<u8>),
    Ipv4LocalRouterId(Ipv4Addr),
    Ipv6LocalRouterId(Ipv6Addr),
    Ipv4RemoteRouterId(Ipv4Addr),
    Ipv6RemoteRouterId(Ipv6Addr),
    // Node SR Attribute TLVs (RFC 9085 §2.1)
    SrCapabilities {
        ipv4_supported: bool,
        ipv6_supported: bool,
        ranges: Vec<SrRange>,
    },
    SrAlgorithms(Vec<u8>),
    SrLocalBlock {
        ranges: Vec<SrRange>,
    },
    // Link Attribute TLVs (RFC 9552)
    AdminGroup(u32),
    MaxLinkBandwidth(f32),
    MaxReservableBandwidth(f32),
    UnreservedBandwidth([u32; 8]), // stored as IEEE 754 bit patterns to allow Eq
    TeDefaultMetric(u32),
    IgpMetric(u32),
    Srlg(Vec<u32>),
    OpaqueLinkAttr(Vec<u8>),
    LinkName(String),
    // Link SR Attribute TLVs (RFC 9085 §2.2)
    AdjSid {
        flags: u8,
        weight: u8,
        sid: u32,
    },
    // BGP-EPE Peer SID TLVs (RFC 9086 §4)
    PeerNodeSid {
        flags: u8,
        weight: u8,
        sid: u32,
    },
    PeerAdjSid {
        flags: u8,
        weight: u8,
        sid: u32,
    },
    PeerSetSid {
        flags: u8,
        weight: u8,
        sid: u32,
    },
    // Prefix Attribute TLVs (RFC 9552)
    IgpFlags(u8),
    OpaquePrefixAttr(Vec<u8>),
    // Prefix SR Attribute TLVs (RFC 9085 §2.3)
    PrefixSid {
        flags: u8,
        algorithm: u8,
        sid: u32,
    },
    // Unknown / future TLVs
    Unknown {
        tlv_type: u16,
        value: Vec<u8>,
    },
}

impl LsTlv {
    /// Access `UnreservedBandwidth` values as `f32`.
    pub fn unreserved_bandwidth_f32(bits: &[u32; 8]) -> [f32; 8] {
        bits.map(f32::from_bits)
    }
}

/// Decode the SID value from a 3-byte (label) or 4-byte (index) field.
///
/// 3-byte encoding: 20-bit label packed into the top 20 bits (right-shift 4).
/// 4-byte encoding: 32-bit index, big-endian.
fn decode_sid_value(b: &[u8]) -> u32 {
    match b.len() {
        3 => {
            let raw = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
            raw >> 4
        }
        l if l >= 4 => u32::from_be_bytes(b[..4].try_into().unwrap()),
        _ => 0,
    }
}

/// Decode SR Capability / SRLB range entries from the body that follows the
/// 2-byte Flags+Reserved header of TLV 1034 or 1036 (RFC 9085 §2.1.2).
///
/// Each range entry is: RangeSize(3 bytes) + SID/Label Sub-TLV(type1+len1+value3/4).
fn decode_sr_ranges(data: &[u8]) -> Vec<SrRange> {
    let mut ranges = Vec::new();
    let mut pos = 0;
    while pos + 5 <= data.len() {
        // Range Size: 24-bit big-endian
        let range_size =
            ((data[pos] as u32) << 16) | ((data[pos + 1] as u32) << 8) | (data[pos + 2] as u32);
        pos += 3;

        // SID/Label Sub-TLV: Type(1) + Len(1) + Value(3 or 4)
        if pos + 2 > data.len() {
            break;
        }
        let sub_type = data[pos];
        let sub_len = data[pos + 1] as usize;
        pos += 2;
        if pos + sub_len > data.len() {
            break;
        }
        let sid_bytes = &data[pos..pos + sub_len];
        pos += sub_len;

        if sub_type != 1 || (sub_len != 3 && sub_len != 4) {
            continue;
        }
        let begin = decode_sid_value(sid_bytes);
        ranges.push(SrRange {
            begin,
            end: begin + range_size.saturating_sub(1),
        });
    }
    ranges
}

/// Decode Flags(1) + Weight(1) + Reserved(2) + SID(3 or 4 bytes) used by
/// Adj-SID (1099) and Peer-*-SID (1101-1103) TLVs (RFC 9085/9086).
fn decode_sid_tlv(value: &[u8]) -> Option<(u8, u8, u32)> {
    if value.len() < 7 {
        return None;
    }
    let flags = value[0];
    let weight = value[1];
    // bytes 2-3 are Reserved
    let sid = decode_sid_value(&value[4..]);
    Some((flags, weight, sid))
}

/// Parse all BGP-LS Attribute TLVs from the attribute value bytes (Type 29).
pub fn parse_ls_attr(data: &[u8]) -> Vec<LsTlv> {
    let mut tlvs = Vec::new();
    let mut c = Cursor::new(data);
    while (c.position() as usize) < data.len() {
        let Some((tlv_type, value)) = read_tlv(&mut c) else {
            break;
        };
        let tlv = match tlv_type {
            TLV_NODE_FLAG_BITS if !value.is_empty() => LsTlv::NodeFlagBits(value[0]),
            TLV_OPAQUE_NODE_ATTR => LsTlv::OpaqueNodeAttr(value),
            TLV_NODE_NAME => LsTlv::NodeName(String::from_utf8_lossy(&value).into_owned()),
            TLV_ISIS_AREA => LsTlv::IsisArea(value),
            TLV_IPV4_LOCAL_ROUTER_ID if value.len() >= 4 => {
                LsTlv::Ipv4LocalRouterId(Ipv4Addr::from(<[u8; 4]>::try_from(&value[..4]).unwrap()))
            }
            TLV_IPV6_LOCAL_ROUTER_ID if value.len() >= 16 => LsTlv::Ipv6LocalRouterId(
                Ipv6Addr::from(<[u8; 16]>::try_from(&value[..16]).unwrap()),
            ),
            TLV_IPV4_REMOTE_ROUTER_ID if value.len() >= 4 => {
                LsTlv::Ipv4RemoteRouterId(Ipv4Addr::from(<[u8; 4]>::try_from(&value[..4]).unwrap()))
            }
            TLV_IPV6_REMOTE_ROUTER_ID if value.len() >= 16 => LsTlv::Ipv6RemoteRouterId(
                Ipv6Addr::from(<[u8; 16]>::try_from(&value[..16]).unwrap()),
            ),
            // SR Capabilities (RFC 9085 §2.1.2): Flags(1)+Reserved(1)+Ranges
            TLV_SR_CAPABILITIES if value.len() >= 2 => {
                let flags = value[0];
                LsTlv::SrCapabilities {
                    ipv4_supported: flags & 0x80 != 0,
                    ipv6_supported: flags & 0x40 != 0,
                    ranges: decode_sr_ranges(&value[2..]),
                }
            }
            TLV_SR_ALGORITHM => LsTlv::SrAlgorithms(value),
            // SR Local Block (RFC 9085 §2.1.4): Flags(1)+Reserved(1)+Ranges
            TLV_SR_LOCAL_BLOCK if value.len() >= 2 => LsTlv::SrLocalBlock {
                ranges: decode_sr_ranges(&value[2..]),
            },
            TLV_ADMIN_GROUP if value.len() >= 4 => {
                LsTlv::AdminGroup(u32::from_be_bytes(value[..4].try_into().unwrap()))
            }
            TLV_MAX_LINK_BANDWIDTH if value.len() >= 4 => LsTlv::MaxLinkBandwidth(f32::from_bits(
                u32::from_be_bytes(value[..4].try_into().unwrap()),
            )),
            TLV_MAX_RESERVABLE_BANDWIDTH if value.len() >= 4 => LsTlv::MaxReservableBandwidth(
                f32::from_bits(u32::from_be_bytes(value[..4].try_into().unwrap())),
            ),
            TLV_UNRESERVED_BANDWIDTH if value.len() >= 32 => {
                let mut bw = [0u32; 8];
                for (i, chunk) in value[..32].chunks_exact(4).enumerate() {
                    bw[i] = u32::from_be_bytes(chunk.try_into().unwrap());
                }
                LsTlv::UnreservedBandwidth(bw)
            }
            TLV_TE_DEFAULT_METRIC if value.len() >= 4 => {
                LsTlv::TeDefaultMetric(u32::from_be_bytes(value[..4].try_into().unwrap()))
            }
            TLV_IGP_METRIC if !value.is_empty() => {
                // 1, 2, or 3 bytes depending on protocol
                let metric = match value.len() {
                    1 => value[0] as u32,
                    2 => u16::from_be_bytes([value[0], value[1]]) as u32,
                    _ => {
                        let mut b = [0u8; 4];
                        let len = value.len().min(3);
                        b[4 - len..].copy_from_slice(&value[..len]);
                        u32::from_be_bytes(b)
                    }
                };
                LsTlv::IgpMetric(metric)
            }
            TLV_SRLG => {
                let srlgs = value
                    .chunks_exact(4)
                    .map(|b| u32::from_be_bytes(b.try_into().unwrap()))
                    .collect();
                LsTlv::Srlg(srlgs)
            }
            TLV_OPAQUE_LINK_ATTR => LsTlv::OpaqueLinkAttr(value),
            TLV_LINK_NAME => LsTlv::LinkName(String::from_utf8_lossy(&value).into_owned()),
            // Adj-SID (RFC 9085 §2.2.1): Flags+Weight+Reserved(2)+SID
            TLV_ADJ_SID => {
                if let Some((flags, weight, sid)) = decode_sid_tlv(&value) {
                    LsTlv::AdjSid { flags, weight, sid }
                } else {
                    LsTlv::Unknown { tlv_type, value }
                }
            }
            // BGP-EPE Peer SIDs (RFC 9086 §4): same wire format as Adj-SID
            TLV_PEER_NODE_SID => {
                if let Some((flags, weight, sid)) = decode_sid_tlv(&value) {
                    LsTlv::PeerNodeSid { flags, weight, sid }
                } else {
                    LsTlv::Unknown { tlv_type, value }
                }
            }
            TLV_PEER_ADJ_SID => {
                if let Some((flags, weight, sid)) = decode_sid_tlv(&value) {
                    LsTlv::PeerAdjSid { flags, weight, sid }
                } else {
                    LsTlv::Unknown { tlv_type, value }
                }
            }
            TLV_PEER_SET_SID => {
                if let Some((flags, weight, sid)) = decode_sid_tlv(&value) {
                    LsTlv::PeerSetSid { flags, weight, sid }
                } else {
                    LsTlv::Unknown { tlv_type, value }
                }
            }
            TLV_IGP_FLAGS if !value.is_empty() => LsTlv::IgpFlags(value[0]),
            TLV_OPAQUE_PREFIX_ATTR => LsTlv::OpaquePrefixAttr(value),
            // Prefix-SID (RFC 9085 §2.3.1): Flags(1)+Algorithm(1)+Reserved(2)+SID
            TLV_PREFIX_SID if value.len() >= 7 => {
                let flags = value[0];
                let algorithm = value[1];
                // bytes 2-3 are Reserved
                let sid = decode_sid_value(&value[4..]);
                LsTlv::PrefixSid {
                    flags,
                    algorithm,
                    sid,
                }
            }
            _ => LsTlv::Unknown { tlv_type, value },
        };
        tlvs.push(tlv);
    }
    tlvs
}

// ---------------------------------------------------------------------------
// Utility: IGP Router-ID formatting (for gRPC conversion)
// ---------------------------------------------------------------------------

/// Format a raw IGP Router-ID byte slice as a human-readable string.
///
/// - 4 bytes: OSPF Router-ID, formatted as dotted-decimal IPv4.
/// - 6 bytes: IS-IS non-pseudonode (system ID), formatted as "xxxx.xxxx.xxxx".
/// - 7 bytes: IS-IS pseudonode (system ID + pseudonode number).
pub fn format_igp_router_id(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => Ipv4Addr::from(<[u8; 4]>::try_from(bytes).unwrap()).to_string(),
        6 => format!(
            "{:02x}{:02x}.{:02x}{:02x}.{:02x}{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        ),
        7 => format!(
            "{:02x}{:02x}.{:02x}{:02x}.{:02x}{:02x}.{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6]
        ),
        _ => bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(""),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node_nlri() -> BgpLsNlri {
        BgpLsNlri::Node(BgpLsNodeNlri {
            protocol_id: PROTOCOL_ISIS_L1,
            identifier: 42,
            local_node: NodeDescriptor {
                asn: Some(65001),
                bgp_ls_id: Some(1),
                ospf_area_id: None,
                igp_router_id: Some(vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06]),
                bgp_router_id: None,
                bgp_confederation_member: None,
            },
        })
    }

    #[test]
    fn node_nlri_roundtrip() {
        let original = make_node_nlri();
        let mut buf = Vec::new();
        original.encode(&mut buf);

        let mut c = Cursor::new(buf.as_slice());
        let decoded = BgpLsNlri::decode(&mut c).expect("decode failed");
        assert_eq!(original, decoded);
    }

    #[test]
    fn link_nlri_roundtrip() {
        let original = BgpLsNlri::Link(BgpLsLinkNlri {
            protocol_id: PROTOCOL_OSPF_V2,
            identifier: 0,
            local_node: NodeDescriptor {
                asn: Some(65001),
                igp_router_id: Some(vec![10, 0, 0, 1]),
                ..Default::default()
            },
            remote_node: NodeDescriptor {
                asn: Some(65001),
                igp_router_id: Some(vec![10, 0, 0, 2]),
                ..Default::default()
            },
            link_desc: vec![
                LinkDescTlv::Ipv4InterfaceAddr([192, 168, 1, 1]),
                LinkDescTlv::Ipv4NeighborAddr([192, 168, 1, 2]),
            ],
        });
        let mut buf = Vec::new();
        original.encode(&mut buf);
        let mut c = Cursor::new(buf.as_slice());
        let decoded = BgpLsNlri::decode(&mut c).expect("decode failed");
        assert_eq!(original, decoded);
    }

    #[test]
    fn prefix_v4_nlri_roundtrip() {
        let original = BgpLsNlri::PrefixV4(BgpLsPrefixNlri {
            protocol_id: PROTOCOL_OSPF_V2,
            identifier: 0,
            local_node: NodeDescriptor {
                asn: Some(65001),
                igp_router_id: Some(vec![10, 0, 0, 1]),
                ..Default::default()
            },
            prefix_desc: vec![PrefixDescTlv::IpReachability {
                prefix_len: 24,
                addr: vec![192, 168, 1],
            }],
        });
        let mut buf = Vec::new();
        original.encode(&mut buf);
        let mut c = Cursor::new(buf.as_slice());
        let decoded = BgpLsNlri::decode(&mut c).expect("decode failed");
        assert_eq!(original, decoded);
    }

    #[test]
    fn unknown_nlri_type_preserved() {
        let original = BgpLsNlri::Unknown {
            nlri_type: 99,
            body: vec![1, 2, 3, 4],
        };
        let mut buf = Vec::new();
        original.encode(&mut buf);
        let mut c = Cursor::new(buf.as_slice());
        let decoded = BgpLsNlri::decode(&mut c).expect("decode failed");
        assert_eq!(original, decoded);
    }

    #[test]
    fn ls_attr_node_name_roundtrip() {
        // Build a BGP-LS attribute with NodeName TLV
        let mut attr_bytes = Vec::new();
        write_tlv(&mut attr_bytes, TLV_NODE_NAME, b"router1");
        write_tlv(&mut attr_bytes, TLV_IPV4_LOCAL_ROUTER_ID, &[10, 0, 0, 1]);

        let tlvs = parse_ls_attr(&attr_bytes);
        assert_eq!(tlvs.len(), 2);
        assert_eq!(tlvs[0], LsTlv::NodeName("router1".to_string()));
        assert!(matches!(tlvs[1], LsTlv::Ipv4LocalRouterId(_)));
    }

    #[test]
    fn ls_attr_link_bandwidth() {
        let bw: f32 = 1_000_000_000.0;
        let mut attr_bytes = Vec::new();
        write_tlv(
            &mut attr_bytes,
            TLV_MAX_LINK_BANDWIDTH,
            &bw.to_bits().to_be_bytes(),
        );

        let tlvs = parse_ls_attr(&attr_bytes);
        assert_eq!(tlvs.len(), 1);
        if let LsTlv::MaxLinkBandwidth(v) = tlvs[0] {
            assert!((v - bw).abs() < 1.0);
        } else {
            panic!("wrong TLV type");
        }
    }

    #[test]
    fn igp_router_id_format() {
        // OSPF: 4 bytes -> dotted decimal
        assert_eq!(format_igp_router_id(&[10, 0, 0, 1]), "10.0.0.1");
        // IS-IS non-pseudonode: 6 bytes
        assert_eq!(
            format_igp_router_id(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]),
            "0102.0304.0506"
        );
    }
}
