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

// SRv6 SID NLRI descriptor TLV (RFC 9514 §3.1)
const TLV_SRV6_SID_INFO: u16 = 518;

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
// SRv6 Attribute TLVs (RFC 9514, RFC 9086 §5)
pub const TLV_SRV6_PEER_NODE_SID: u16 = 1104;
pub const TLV_SRV6_END_X_SID: u16 = 1106;
// SRv6 SID Structure sub-TLV (RFC 9514 §5.3.2, embedded in SRv6 attribute TLVs)
pub const TLV_SRV6_SID_STRUCTURE: u16 = 1252;
// Link Performance Measurement TLVs (RFC 8571)
pub const TLV_UNIDIRECTIONAL_LINK_DELAY: u16 = 1114;
pub const TLV_MIN_MAX_UNIDIRECTIONAL_LINK_DELAY: u16 = 1115;
pub const TLV_UNIDIRECTIONAL_DELAY_VARIATION: u16 = 1116;
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

/// SRv6 SID NLRI (RFC 9514 §3, NLRI type 6).
///
/// Each `sids[i]` pairs with `multi_topo_ids[i]`; the two vecs have the same
/// length.  A missing Multi-Topology ID field is represented as 0.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BgpLsSrv6SidNlri {
    pub protocol_id: u8,
    pub identifier: u64,
    pub local_node: NodeDescriptor,
    pub sids: Vec<[u8; 16]>,
    pub multi_topo_ids: Vec<u16>,
}

/// BGP-LS NLRI (RFC 9552, AFI=16388, SAFI=71).
///
/// Unknown NLRI types are stored in
/// `Unknown` so the wire bytes are consumed without dropping the peer session.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum BgpLsNlri {
    Node(BgpLsNodeNlri),
    Link(BgpLsLinkNlri),
    PrefixV4(BgpLsPrefixNlri),
    PrefixV6(BgpLsPrefixNlri),
    Srv6Sid(BgpLsSrv6SidNlri),
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
            NLRI_TYPE_SRV6_SID => {
                let (local_node, after_local) = decode_node_desc_and_rest(rest)?;
                let mut sids: Vec<[u8; 16]> = Vec::new();
                let mut multi_topo_ids: Vec<u16> = Vec::new();
                let mut c = Cursor::new(after_local);
                while (c.position() as usize) < after_local.len() {
                    let Some((tlv_type, value)) = read_tlv(&mut c) else {
                        break;
                    };
                    match tlv_type {
                        TLV_SRV6_SID_INFO if value.len() >= 20 => {
                            // Multi-Topo-ID(2) + Reserved(2) + SID(16)
                            let mt_id = u16::from_be_bytes([value[0], value[1]]);
                            let sid: [u8; 16] = value[4..20].try_into().ok()?;
                            multi_topo_ids.push(mt_id);
                            sids.push(sid);
                        }
                        TLV_MULTI_TOPO_ID => {
                            for chunk in value.chunks_exact(2) {
                                multi_topo_ids.push(u16::from_be_bytes(chunk.try_into().unwrap()));
                            }
                        }
                        _ => {}
                    }
                }
                Some(BgpLsNlri::Srv6Sid(BgpLsSrv6SidNlri {
                    protocol_id,
                    identifier,
                    local_node,
                    sids,
                    multi_topo_ids,
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
            BgpLsNlri::Srv6Sid(n) => {
                body.push(n.protocol_id);
                body.extend_from_slice(&n.identifier.to_be_bytes());
                n.local_node.encode(&mut body, TLV_LOCAL_NODE_DESC);
                for (i, sid) in n.sids.iter().enumerate() {
                    let mt_id = n.multi_topo_ids.get(i).copied().unwrap_or(0);
                    let mut tlv_value = [0u8; 20];
                    tlv_value[0..2].copy_from_slice(&mt_id.to_be_bytes());
                    // bytes 2-3: Reserved
                    tlv_value[4..20].copy_from_slice(sid);
                    write_tlv(&mut body, TLV_SRV6_SID_INFO, &tlv_value);
                }
                write_tlv_header(dst, NLRI_TYPE_SRV6_SID, &body);
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
            BgpLsNlri::Srv6Sid(n) => {
                write!(
                    f,
                    "bgp-ls:srv6-sid:proto={}:id={}",
                    n.protocol_id, n.identifier
                )
            }
            BgpLsNlri::Unknown { nlri_type, .. } => write!(f, "bgp-ls:unknown:{}", nlri_type),
        }
    }
}

// ---------------------------------------------------------------------------
// BGP-LS Attribute (Type 29) TLVs
// ---------------------------------------------------------------------------

/// SRv6 SID Structure (RFC 9514 §5.3.2): bit-lengths of the four SID fields.
#[derive(Clone, Debug, PartialEq)]
pub struct SrSidStructure {
    pub lb_len: u8,
    pub ln_len: u8,
    pub fn_len: u8,
    pub arg_len: u8,
}

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
    // Link Performance Measurement TLVs (RFC 8571)
    UnidirectionalLinkDelay {
        anomalous: bool,
        delay_us: u32,
    },
    MinMaxUnidirectionalLinkDelay {
        anomalous: bool,
        min_us: u32,
        max_us: u32,
    },
    UnidirectionalDelayVariation(u32),
    // SRv6 Attribute TLVs (RFC 9514, RFC 9086 §5)
    Srv6EndXSid {
        endpoint_behavior: u16,
        flags: u8,
        algorithm: u8,
        weight: u8,
        sids: Vec<[u8; 16]>,
        sid_structure: Option<SrSidStructure>,
    },
    Srv6PeerNodeSid {
        flags: u8,
        weight: u8,
        peer_as: u32,
        peer_bgp_id: [u8; 4],
        sid: [u8; 16],
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

    /// Encode this TLV into wire format (type + length + value).
    pub fn encode(&self, dst: &mut Vec<u8>) {
        fn sid_bytes(sid: u32, v_flag: bool) -> Vec<u8> {
            if v_flag {
                // 3-byte label: 20-bit value in top 20 bits of 24-bit field
                let raw = sid << 4;
                vec![(raw >> 16) as u8, (raw >> 8) as u8, raw as u8]
            } else {
                sid.to_be_bytes().to_vec()
            }
        }

        fn sid_tlv_body(flags: u8, weight: u8, sid: u32) -> Vec<u8> {
            let mut body = vec![flags, weight, 0, 0];
            body.extend_from_slice(&sid_bytes(sid, flags & 0x80 != 0));
            body
        }

        fn range_bytes(ranges: &[SrRange]) -> Vec<u8> {
            let mut buf = Vec::new();
            for r in ranges {
                let size = r.end.saturating_sub(r.begin) + 1;
                buf.push((size >> 16) as u8);
                buf.push((size >> 8) as u8);
                buf.push(size as u8);
                // SID/Label sub-TLV: type=1, len=3, 3-byte label encoding
                let raw = r.begin << 4;
                buf.extend_from_slice(&[1, 3, (raw >> 16) as u8, (raw >> 8) as u8, raw as u8]);
            }
            buf
        }

        match self {
            LsTlv::NodeFlagBits(f) => write_tlv(dst, TLV_NODE_FLAG_BITS, &[*f]),
            LsTlv::OpaqueNodeAttr(v) => write_tlv(dst, TLV_OPAQUE_NODE_ATTR, v),
            LsTlv::NodeName(s) => write_tlv(dst, TLV_NODE_NAME, s.as_bytes()),
            LsTlv::IsisArea(v) => write_tlv(dst, TLV_ISIS_AREA, v),
            LsTlv::Ipv4LocalRouterId(a) => write_tlv(dst, TLV_IPV4_LOCAL_ROUTER_ID, &a.octets()),
            LsTlv::Ipv6LocalRouterId(a) => write_tlv(dst, TLV_IPV6_LOCAL_ROUTER_ID, &a.octets()),
            LsTlv::Ipv4RemoteRouterId(a) => write_tlv(dst, TLV_IPV4_REMOTE_ROUTER_ID, &a.octets()),
            LsTlv::Ipv6RemoteRouterId(a) => write_tlv(dst, TLV_IPV6_REMOTE_ROUTER_ID, &a.octets()),
            LsTlv::SrCapabilities {
                ipv4_supported,
                ipv6_supported,
                ranges,
            } => {
                let mut body = Vec::new();
                let mut flags = 0u8;
                if *ipv4_supported {
                    flags |= 0x80;
                }
                if *ipv6_supported {
                    flags |= 0x40;
                }
                body.push(flags);
                body.push(0); // reserved
                body.extend_from_slice(&range_bytes(ranges));
                write_tlv(dst, TLV_SR_CAPABILITIES, &body);
            }
            LsTlv::SrAlgorithms(v) => write_tlv(dst, TLV_SR_ALGORITHM, v),
            LsTlv::SrLocalBlock { ranges } => {
                let mut body = vec![0u8, 0u8]; // flags + reserved
                body.extend_from_slice(&range_bytes(ranges));
                write_tlv(dst, TLV_SR_LOCAL_BLOCK, &body);
            }
            LsTlv::AdminGroup(g) => write_tlv(dst, TLV_ADMIN_GROUP, &g.to_be_bytes()),
            LsTlv::MaxLinkBandwidth(b) => {
                write_tlv(dst, TLV_MAX_LINK_BANDWIDTH, &b.to_bits().to_be_bytes())
            }
            LsTlv::MaxReservableBandwidth(b) => write_tlv(
                dst,
                TLV_MAX_RESERVABLE_BANDWIDTH,
                &b.to_bits().to_be_bytes(),
            ),
            LsTlv::UnreservedBandwidth(bits) => {
                let mut body = [0u8; 32];
                for (i, &b) in bits.iter().enumerate() {
                    body[i * 4..(i + 1) * 4].copy_from_slice(&b.to_be_bytes());
                }
                write_tlv(dst, TLV_UNRESERVED_BANDWIDTH, &body);
            }
            LsTlv::TeDefaultMetric(m) => write_tlv(dst, TLV_TE_DEFAULT_METRIC, &m.to_be_bytes()),
            LsTlv::IgpMetric(m) => {
                // Re-encode in the shortest form that round-trips faithfully.
                if *m <= 0xff {
                    write_tlv(dst, TLV_IGP_METRIC, &[*m as u8]);
                } else if *m <= 0xffff {
                    write_tlv(dst, TLV_IGP_METRIC, &(*m as u16).to_be_bytes());
                } else {
                    write_tlv(dst, TLV_IGP_METRIC, &m.to_be_bytes()[1..]);
                }
            }
            LsTlv::Srlg(v) => {
                let body: Vec<u8> = v.iter().flat_map(|s| s.to_be_bytes()).collect();
                write_tlv(dst, TLV_SRLG, &body);
            }
            LsTlv::OpaqueLinkAttr(v) => write_tlv(dst, TLV_OPAQUE_LINK_ATTR, v),
            LsTlv::LinkName(s) => write_tlv(dst, TLV_LINK_NAME, s.as_bytes()),
            LsTlv::AdjSid { flags, weight, sid } => {
                write_tlv(dst, TLV_ADJ_SID, &sid_tlv_body(*flags, *weight, *sid))
            }
            LsTlv::PeerNodeSid { flags, weight, sid } => {
                write_tlv(dst, TLV_PEER_NODE_SID, &sid_tlv_body(*flags, *weight, *sid))
            }
            LsTlv::PeerAdjSid { flags, weight, sid } => {
                write_tlv(dst, TLV_PEER_ADJ_SID, &sid_tlv_body(*flags, *weight, *sid))
            }
            LsTlv::PeerSetSid { flags, weight, sid } => {
                write_tlv(dst, TLV_PEER_SET_SID, &sid_tlv_body(*flags, *weight, *sid))
            }
            LsTlv::IgpFlags(f) => write_tlv(dst, TLV_IGP_FLAGS, &[*f]),
            LsTlv::OpaquePrefixAttr(v) => write_tlv(dst, TLV_OPAQUE_PREFIX_ATTR, v),
            LsTlv::PrefixSid {
                flags,
                algorithm,
                sid,
            } => {
                let mut body = vec![*flags, *algorithm, 0, 0];
                body.extend_from_slice(&sid_bytes(*sid, flags & 0x80 != 0));
                write_tlv(dst, TLV_PREFIX_SID, &body);
            }
            LsTlv::UnidirectionalLinkDelay {
                anomalous,
                delay_us,
            } => {
                let a: u8 = if *anomalous { 0x80 } else { 0 };
                write_tlv(
                    dst,
                    TLV_UNIDIRECTIONAL_LINK_DELAY,
                    &[
                        a,
                        (delay_us >> 16) as u8,
                        (delay_us >> 8) as u8,
                        *delay_us as u8,
                    ],
                );
            }
            LsTlv::MinMaxUnidirectionalLinkDelay {
                anomalous,
                min_us,
                max_us,
            } => {
                let a: u8 = if *anomalous { 0x80 } else { 0 };
                write_tlv(
                    dst,
                    TLV_MIN_MAX_UNIDIRECTIONAL_LINK_DELAY,
                    &[
                        a,
                        (min_us >> 16) as u8,
                        (min_us >> 8) as u8,
                        *min_us as u8,
                        0, // Reserved
                        (max_us >> 16) as u8,
                        (max_us >> 8) as u8,
                        *max_us as u8,
                    ],
                );
            }
            LsTlv::UnidirectionalDelayVariation(v) => {
                write_tlv(
                    dst,
                    TLV_UNIDIRECTIONAL_DELAY_VARIATION,
                    &[0, (v >> 16) as u8, (v >> 8) as u8, *v as u8],
                );
            }
            LsTlv::Srv6EndXSid {
                endpoint_behavior,
                flags,
                algorithm,
                weight,
                sids,
                sid_structure,
            } => {
                let mut body = Vec::new();
                body.extend_from_slice(&endpoint_behavior.to_be_bytes());
                body.push(*flags);
                body.push(*algorithm);
                body.push(*weight);
                body.push(0); // Reserved
                for sid in sids {
                    body.extend_from_slice(sid);
                }
                if let Some(s) = sid_structure {
                    // Sub-TLV: type(2) + len(2) + value(4)
                    body.extend_from_slice(&TLV_SRV6_SID_STRUCTURE.to_be_bytes());
                    body.extend_from_slice(&4u16.to_be_bytes());
                    body.extend_from_slice(&[s.lb_len, s.ln_len, s.fn_len, s.arg_len]);
                }
                write_tlv(dst, TLV_SRV6_END_X_SID, &body);
            }
            LsTlv::Srv6PeerNodeSid {
                flags,
                weight,
                peer_as,
                peer_bgp_id,
                sid,
            } => {
                let mut body = Vec::new();
                body.push(*flags);
                body.push(*weight);
                body.extend_from_slice(&[0u8; 2]); // Reserved
                body.extend_from_slice(&peer_as.to_be_bytes());
                body.extend_from_slice(peer_bgp_id);
                body.extend_from_slice(sid);
                write_tlv(dst, TLV_SRV6_PEER_NODE_SID, &body);
            }
            LsTlv::Unknown { tlv_type, value } => write_tlv(dst, *tlv_type, value),
        }
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
            // Unidirectional Link Delay (RFC 8571 §2.1): A(1bit)+Rsv(7bit)+Delay(24bit)
            TLV_UNIDIRECTIONAL_LINK_DELAY if value.len() >= 4 => {
                let anomalous = value[0] & 0x80 != 0;
                let delay_us =
                    ((value[1] as u32) << 16) | ((value[2] as u32) << 8) | (value[3] as u32);
                LsTlv::UnidirectionalLinkDelay {
                    anomalous,
                    delay_us,
                }
            }
            // Min/Max Unidirectional Link Delay (RFC 8571 §2.2): A+Rsv+Min(24bit)+Rsv+Max(24bit)
            TLV_MIN_MAX_UNIDIRECTIONAL_LINK_DELAY if value.len() >= 8 => {
                let anomalous = value[0] & 0x80 != 0;
                let min_us =
                    ((value[1] as u32) << 16) | ((value[2] as u32) << 8) | (value[3] as u32);
                // value[4]: Reserved
                let max_us =
                    ((value[5] as u32) << 16) | ((value[6] as u32) << 8) | (value[7] as u32);
                LsTlv::MinMaxUnidirectionalLinkDelay {
                    anomalous,
                    min_us,
                    max_us,
                }
            }
            // Unidirectional Delay Variation (RFC 8571 §2.3): Reserved(8bit)+Variation(24bit)
            TLV_UNIDIRECTIONAL_DELAY_VARIATION if value.len() >= 4 => {
                let variation =
                    ((value[1] as u32) << 16) | ((value[2] as u32) << 8) | (value[3] as u32);
                LsTlv::UnidirectionalDelayVariation(variation)
            }
            // SRv6 End.X SID (RFC 9514 §5.1): header(6) + SID(s)(16 each) + sub-TLVs
            TLV_SRV6_END_X_SID if value.len() >= 6 => {
                let endpoint_behavior = u16::from_be_bytes([value[0], value[1]]);
                let flags = value[2];
                let algorithm = value[3];
                let weight = value[4];
                // value[5]: Reserved
                let mut pos = 6;
                let mut sids: Vec<[u8; 16]> = Vec::new();
                // Greedily consume 16-byte SIDs; any short tail is sub-TLVs.
                while pos + 16 <= value.len() {
                    sids.push(value[pos..pos + 16].try_into().unwrap());
                    pos += 16;
                }
                // Parse remaining bytes as sub-TLVs (type(2)+len(2)+value).
                let mut sid_structure = None;
                while pos + 4 <= value.len() {
                    let sub_type = u16::from_be_bytes([value[pos], value[pos + 1]]);
                    let sub_len = u16::from_be_bytes([value[pos + 2], value[pos + 3]]) as usize;
                    pos += 4;
                    if pos + sub_len > value.len() {
                        break;
                    }
                    let sub_val = &value[pos..pos + sub_len];
                    pos += sub_len;
                    if sub_type == TLV_SRV6_SID_STRUCTURE && sub_len >= 4 {
                        sid_structure = Some(SrSidStructure {
                            lb_len: sub_val[0],
                            ln_len: sub_val[1],
                            fn_len: sub_val[2],
                            arg_len: sub_val[3],
                        });
                    }
                }
                LsTlv::Srv6EndXSid {
                    endpoint_behavior,
                    flags,
                    algorithm,
                    weight,
                    sids,
                    sid_structure,
                }
            }
            // SRv6 BGP Peer Node SID (RFC 9086 §5): Flags(1)+Weight(1)+Rsv(2)+PeerAS(4)+PeerID(4)+SID(16)
            TLV_SRV6_PEER_NODE_SID if value.len() >= 28 => {
                let flags = value[0];
                let weight = value[1];
                // value[2-3]: Reserved
                let peer_as = u32::from_be_bytes(value[4..8].try_into().unwrap());
                let peer_bgp_id: [u8; 4] = value[8..12].try_into().unwrap();
                let sid: [u8; 16] = value[12..28].try_into().unwrap();
                LsTlv::Srv6PeerNodeSid {
                    flags,
                    weight,
                    peer_as,
                    peer_bgp_id,
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

    // -----------------------------------------------------------------------
    // GoBGP wire-format tests
    // Generated by packet/tests/fixtures/gen/bgp_ls/main.go (GoBGP v4.6.0).
    // -----------------------------------------------------------------------

    // Node NLRI: IS-IS L1, identifier=42, ASN=65001, IGP-Router-ID=0102.0304.0506
    const GOBGP_NODE_NLRI: &[u8] = &[
        0x00, 0x01, 0x00, 0x27, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x01, 0x00,
        0x00, 0x1a, 0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xfd, 0xe9, 0x02, 0x01, 0x00, 0x04, 0x00,
        0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    ];

    // Link NLRI: IS-IS L2, local ASN=65001 0102.0304.0506, remote ASN=65002 0102.0304.0507,
    //           link if=10.0.1.1 nb=10.0.1.2
    const GOBGP_LINK_NLRI: &[u8] = &[
        0x00, 0x02, 0x00, 0x55, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x1a, 0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xfd, 0xe9, 0x02, 0x01, 0x00, 0x04, 0x00,
        0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x01, 0x01,
        0x00, 0x1a, 0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xfd, 0xea, 0x02, 0x01, 0x00, 0x04, 0x00,
        0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x07, 0x01, 0x03,
        0x00, 0x04, 0x0a, 0x00, 0x01, 0x01, 0x01, 0x04, 0x00, 0x04, 0x0a, 0x00, 0x01, 0x02,
    ];

    // PrefixV4 NLRI: OSPF v2, ASN=65001, OSPF router-ID=10.0.0.1, prefix=192.168.1.0/24
    const GOBGP_PREFIX_V4_NLRI: &[u8] = &[
        0x00, 0x03, 0x00, 0x35, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x20, 0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xfd, 0xe9, 0x02, 0x01, 0x00, 0x04, 0x00,
        0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x04,
        0x0a, 0x00, 0x00, 0x01, 0x01, 0x09, 0x00, 0x04, 0x18, 0xc0, 0xa8, 0x01,
    ];

    // PrefixV6 NLRI: IS-IS L2, ASN=65001, router-ID=0102.0304.0506, prefix=2001:db8::/32
    const GOBGP_PREFIX_V6_NLRI: &[u8] = &[
        0x00, 0x04, 0x00, 0x30, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x1a, 0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xfd, 0xe9, 0x02, 0x01, 0x00, 0x04, 0x00,
        0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x01, 0x09,
        0x00, 0x05, 0x20, 0x20, 0x01, 0x0d, 0xb8,
    ];

    // NodeFlagBits: Overload+External+Router
    const GOBGP_TLV_NODE_FLAG_BITS: &[u8] = &[0x04, 0x00, 0x00, 0x01, 0xa8];

    // OpaqueNodeAttr: [0x01, 0x02, 0x03]
    const GOBGP_TLV_OPAQUE_NODE_ATTR: &[u8] = &[0x04, 0x01, 0x00, 0x03, 0x01, 0x02, 0x03];

    // NodeName: "router1"
    const GOBGP_TLV_NODE_NAME: &[u8] = &[
        0x04, 0x02, 0x00, 0x07, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x31,
    ];

    // IsisArea: [0x47, 0x00, 0x01]
    const GOBGP_TLV_ISIS_AREA: &[u8] = &[0x04, 0x03, 0x00, 0x03, 0x47, 0x00, 0x01];

    // Ipv4LocalRouterId: 10.0.0.1
    const GOBGP_TLV_IPV4_LOCAL_ROUTER_ID: &[u8] = &[0x04, 0x04, 0x00, 0x04, 0x0a, 0x00, 0x00, 0x01];

    // Ipv6LocalRouterId: 2001:db8::1
    const GOBGP_TLV_IPV6_LOCAL_ROUTER_ID: &[u8] = &[
        0x04, 0x05, 0x00, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01,
    ];

    // Ipv4RemoteRouterId: 10.0.0.2
    const GOBGP_TLV_IPV4_REMOTE_ROUTER_ID: &[u8] =
        &[0x04, 0x06, 0x00, 0x04, 0x0a, 0x00, 0x00, 0x02];

    // Ipv6RemoteRouterId: 2001:db8::2
    const GOBGP_TLV_IPV6_REMOTE_ROUTER_ID: &[u8] = &[
        0x04, 0x07, 0x00, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x02,
    ];

    // SrAlgorithms: [0, 1]
    const GOBGP_TLV_SR_ALGORITHM: &[u8] = &[0x04, 0x0b, 0x00, 0x02, 0x00, 0x01];

    // AdminGroup: 0x000000FF
    const GOBGP_TLV_ADMIN_GROUP: &[u8] = &[0x04, 0x40, 0x00, 0x04, 0x00, 0x00, 0x00, 0xff];

    // MaxLinkBandwidth: 1e9 bps (IEEE 754: 0x4e6e6b28)
    const GOBGP_TLV_MAX_LINK_BANDWIDTH: &[u8] = &[0x04, 0x41, 0x00, 0x04, 0x4e, 0x6e, 0x6b, 0x28];

    // MaxReservableBandwidth: 1e9 bps
    const GOBGP_TLV_MAX_RESERVABLE_BANDWIDTH: &[u8] =
        &[0x04, 0x42, 0x00, 0x04, 0x4e, 0x6e, 0x6b, 0x28];

    // UnreservedBandwidth: 8x 1e9 bps
    const GOBGP_TLV_UNRESERVED_BANDWIDTH: &[u8] = &[
        0x04, 0x43, 0x00, 0x20, 0x4e, 0x6e, 0x6b, 0x28, 0x4e, 0x6e, 0x6b, 0x28, 0x4e, 0x6e, 0x6b,
        0x28, 0x4e, 0x6e, 0x6b, 0x28, 0x4e, 0x6e, 0x6b, 0x28, 0x4e, 0x6e, 0x6b, 0x28, 0x4e, 0x6e,
        0x6b, 0x28, 0x4e, 0x6e, 0x6b, 0x28,
    ];

    // TeDefaultMetric: 100
    const GOBGP_TLV_TE_DEFAULT_METRIC: &[u8] = &[0x04, 0x44, 0x00, 0x04, 0x00, 0x00, 0x00, 0x64];

    // IgpMetric: 100000 (3-byte encoding; value > 0xffff ensures RustyBGP also uses 3 bytes)
    const GOBGP_TLV_IGP_METRIC: &[u8] = &[0x04, 0x47, 0x00, 0x03, 0x01, 0x86, 0xa0];

    // Srlg: [0x1000, 0x2000]
    const GOBGP_TLV_SRLG: &[u8] = &[
        0x04, 0x48, 0x00, 0x08, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x20, 0x00,
    ];

    // OpaqueLinkAttr: [0xAB, 0xCD]
    const GOBGP_TLV_OPAQUE_LINK_ATTR: &[u8] = &[0x04, 0x49, 0x00, 0x02, 0xab, 0xcd];

    // LinkName: "eth0"
    const GOBGP_TLV_LINK_NAME: &[u8] = &[0x04, 0x4a, 0x00, 0x04, 0x65, 0x74, 0x68, 0x30];

    // AdjSid: L-flag=1, V-flag=0 (4-byte index), SID=100500
    const GOBGP_TLV_ADJ_SID: &[u8] = &[
        0x04, 0x4b, 0x00, 0x08, 0x40, 0x00, 0x00, 0x00, 0x00, 0x01, 0x88, 0x94,
    ];

    // PeerNodeSid: L-flag=1, V-flag=0 (4-byte index), SID=100500
    const GOBGP_TLV_PEER_NODE_SID: &[u8] = &[
        0x04, 0x4d, 0x00, 0x08, 0x40, 0x00, 0x00, 0x00, 0x00, 0x01, 0x88, 0x94,
    ];

    // PeerAdjSid: L-flag=1, V-flag=0 (4-byte index), SID=100500
    // Constructed with correct type 1102 (GoBGP's NewLsTLVPeerAdjacencySID uses wrong type 1099).
    const GOBGP_TLV_PEER_ADJ_SID: &[u8] = &[
        0x04, 0x4e, 0x00, 0x08, 0x40, 0x00, 0x00, 0x00, 0x00, 0x01, 0x88, 0x94,
    ];

    // PeerSetSid: L-flag=1, V-flag=0 (4-byte index), SID=100500
    const GOBGP_TLV_PEER_SET_SID: &[u8] = &[
        0x04, 0x4f, 0x00, 0x08, 0x40, 0x00, 0x00, 0x00, 0x00, 0x01, 0x88, 0x94,
    ];

    // Srv6EndXSid: EP=57 (End.X), weight=100, SID=fd00::1, SID structure=32/16/16/0
    const GOBGP_TLV_SRV6_END_X_SID: &[u8] = &[
        0x04, 0x52, 0x00, 0x1e, 0x00, 0x39, 0x00, 0x00, 0x64, 0x00, 0xfd, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x04, 0xe4, 0x00, 0x04,
        0x20, 0x10, 0x10, 0x00,
    ];

    // UnidirectionalLinkDelay: 1000 us, not anomalous
    const GOBGP_TLV_UNIDIRECTIONAL_LINK_DELAY: &[u8] =
        &[0x04, 0x5a, 0x00, 0x04, 0x00, 0x00, 0x03, 0xe8];

    // MinMaxUnidirectionalLinkDelay: min=500us max=2000us, not anomalous
    const GOBGP_TLV_MIN_MAX_UNIDIRECTIONAL_LINK_DELAY: &[u8] = &[
        0x04, 0x5b, 0x00, 0x08, 0x00, 0x00, 0x01, 0xf4, 0x00, 0x00, 0x07, 0xd0,
    ];

    // UnidirectionalDelayVariation: 100 us
    const GOBGP_TLV_UNIDIRECTIONAL_DELAY_VARIATION: &[u8] =
        &[0x04, 0x5c, 0x00, 0x04, 0x00, 0x00, 0x00, 0x64];

    // IgpFlags: Down=true, NoUnicast=true
    const GOBGP_TLV_IGP_FLAGS: &[u8] = &[0x04, 0x80, 0x00, 0x01, 0xc0];

    // OpaquePrefixAttr: [0xDE, 0xAD, 0xBE]
    const GOBGP_TLV_OPAQUE_PREFIX_ATTR: &[u8] = &[0x04, 0x85, 0x00, 0x03, 0xde, 0xad, 0xbe];

    // PrefixSid: V-flag=0 (4-byte index), algorithm=0, SID=100500
    const GOBGP_TLV_PREFIX_SID: &[u8] = &[
        0x04, 0x86, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x88, 0x94,
    ];

    // Parse `bytes` as a BGP-LS attribute TLV slice, assert exactly one TLV decodes,
    // re-encode it, and assert the bytes round-trip unchanged.  Returns the decoded TLV.
    fn assert_tlv_roundtrip(bytes: &[u8]) -> LsTlv {
        let tlvs = parse_ls_attr(bytes);
        assert_eq!(tlvs.len(), 1);
        let mut buf = Vec::new();
        tlvs[0].encode(&mut buf);
        assert_eq!(buf, bytes);
        tlvs.into_iter().next().unwrap()
    }

    // Decode `bytes` as a BGP-LS NLRI, re-encode, assert bytes unchanged.
    fn assert_nlri_roundtrip(bytes: &[u8]) -> BgpLsNlri {
        let mut c = Cursor::new(bytes);
        let nlri = BgpLsNlri::decode(&mut c).expect("decode failed");
        let mut buf = Vec::new();
        nlri.encode(&mut buf);
        assert_eq!(buf, bytes);
        nlri
    }

    #[test]
    fn gobgp_node_nlri() {
        let nlri = assert_nlri_roundtrip(GOBGP_NODE_NLRI);
        let BgpLsNlri::Node(n) = nlri else {
            panic!("wrong variant")
        };
        assert_eq!(n.protocol_id, PROTOCOL_ISIS_L1);
        assert_eq!(n.identifier, 42);
        assert_eq!(n.local_node.asn, Some(65001));
        assert_eq!(n.local_node.bgp_ls_id, Some(0));
        assert_eq!(
            n.local_node.igp_router_id.as_deref(),
            Some(&[0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06][..])
        );
    }

    #[test]
    fn gobgp_link_nlri() {
        let nlri = assert_nlri_roundtrip(GOBGP_LINK_NLRI);
        let BgpLsNlri::Link(n) = nlri else {
            panic!("wrong variant")
        };
        assert_eq!(n.protocol_id, PROTOCOL_ISIS_L2);
        assert_eq!(n.identifier, 0);
        assert_eq!(n.local_node.asn, Some(65001));
        assert_eq!(n.remote_node.asn, Some(65002));
        assert_eq!(
            n.remote_node.igp_router_id.as_deref(),
            Some(&[0x01u8, 0x02, 0x03, 0x04, 0x05, 0x07][..])
        );
        assert_eq!(
            n.link_desc,
            vec![
                LinkDescTlv::Ipv4InterfaceAddr([10, 0, 1, 1]),
                LinkDescTlv::Ipv4NeighborAddr([10, 0, 1, 2]),
            ]
        );
    }

    #[test]
    fn gobgp_prefix_v4_nlri() {
        let nlri = assert_nlri_roundtrip(GOBGP_PREFIX_V4_NLRI);
        let BgpLsNlri::PrefixV4(n) = nlri else {
            panic!("wrong variant")
        };
        assert_eq!(n.protocol_id, PROTOCOL_OSPF_V2);
        assert_eq!(n.local_node.asn, Some(65001));
        assert_eq!(n.local_node.ospf_area_id, Some(0));
        assert_eq!(
            n.local_node.igp_router_id.as_deref(),
            Some(&[10u8, 0, 0, 1][..])
        );
        assert_eq!(
            n.prefix_desc,
            vec![PrefixDescTlv::IpReachability {
                prefix_len: 24,
                addr: vec![192, 168, 1],
            }]
        );
    }

    #[test]
    fn gobgp_prefix_v6_nlri() {
        let nlri = assert_nlri_roundtrip(GOBGP_PREFIX_V6_NLRI);
        let BgpLsNlri::PrefixV6(n) = nlri else {
            panic!("wrong variant")
        };
        assert_eq!(n.protocol_id, PROTOCOL_ISIS_L2);
        assert_eq!(n.local_node.asn, Some(65001));
        assert_eq!(
            n.prefix_desc,
            vec![PrefixDescTlv::IpReachability {
                prefix_len: 32,
                addr: vec![0x20, 0x01, 0x0d, 0xb8],
            }]
        );
    }

    #[test]
    fn gobgp_tlv_node_flag_bits() {
        let tlv = assert_tlv_roundtrip(GOBGP_TLV_NODE_FLAG_BITS);
        assert_eq!(tlv, LsTlv::NodeFlagBits(0xa8));
    }

    #[test]
    fn gobgp_tlv_opaque_node_attr() {
        let tlv = assert_tlv_roundtrip(GOBGP_TLV_OPAQUE_NODE_ATTR);
        assert_eq!(tlv, LsTlv::OpaqueNodeAttr(vec![0x01, 0x02, 0x03]));
    }

    #[test]
    fn gobgp_tlv_node_name() {
        let tlv = assert_tlv_roundtrip(GOBGP_TLV_NODE_NAME);
        assert_eq!(tlv, LsTlv::NodeName("router1".to_string()));
    }

    #[test]
    fn gobgp_tlv_isis_area() {
        let tlv = assert_tlv_roundtrip(GOBGP_TLV_ISIS_AREA);
        assert_eq!(tlv, LsTlv::IsisArea(vec![0x47, 0x00, 0x01]));
    }

    #[test]
    fn gobgp_tlv_ipv4_local_router_id() {
        let tlv = assert_tlv_roundtrip(GOBGP_TLV_IPV4_LOCAL_ROUTER_ID);
        assert_eq!(tlv, LsTlv::Ipv4LocalRouterId(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn gobgp_tlv_ipv6_local_router_id() {
        let tlv = assert_tlv_roundtrip(GOBGP_TLV_IPV6_LOCAL_ROUTER_ID);
        assert_eq!(
            tlv,
            LsTlv::Ipv6LocalRouterId("2001:db8::1".parse::<Ipv6Addr>().unwrap())
        );
    }

    #[test]
    fn gobgp_tlv_ipv4_remote_router_id() {
        let tlv = assert_tlv_roundtrip(GOBGP_TLV_IPV4_REMOTE_ROUTER_ID);
        assert_eq!(tlv, LsTlv::Ipv4RemoteRouterId(Ipv4Addr::new(10, 0, 0, 2)));
    }

    #[test]
    fn gobgp_tlv_ipv6_remote_router_id() {
        let tlv = assert_tlv_roundtrip(GOBGP_TLV_IPV6_REMOTE_ROUTER_ID);
        assert_eq!(
            tlv,
            LsTlv::Ipv6RemoteRouterId("2001:db8::2".parse::<Ipv6Addr>().unwrap())
        );
    }

    #[test]
    fn gobgp_tlv_sr_algorithm() {
        let tlv = assert_tlv_roundtrip(GOBGP_TLV_SR_ALGORITHM);
        assert_eq!(tlv, LsTlv::SrAlgorithms(vec![0, 1]));
    }

    #[test]
    fn gobgp_tlv_admin_group() {
        let tlv = assert_tlv_roundtrip(GOBGP_TLV_ADMIN_GROUP);
        assert_eq!(tlv, LsTlv::AdminGroup(0xFF));
    }

    #[test]
    fn gobgp_tlv_max_link_bandwidth() {
        let tlv = assert_tlv_roundtrip(GOBGP_TLV_MAX_LINK_BANDWIDTH);
        assert_eq!(tlv, LsTlv::MaxLinkBandwidth(f32::from_bits(0x4e6e_6b28)));
    }

    #[test]
    fn gobgp_tlv_max_reservable_bandwidth() {
        let tlv = assert_tlv_roundtrip(GOBGP_TLV_MAX_RESERVABLE_BANDWIDTH);
        assert_eq!(
            tlv,
            LsTlv::MaxReservableBandwidth(f32::from_bits(0x4e6e_6b28))
        );
    }

    #[test]
    fn gobgp_tlv_unreserved_bandwidth() {
        let tlv = assert_tlv_roundtrip(GOBGP_TLV_UNRESERVED_BANDWIDTH);
        assert_eq!(tlv, LsTlv::UnreservedBandwidth([0x4e6e_6b28u32; 8]));
    }

    #[test]
    fn gobgp_tlv_te_default_metric() {
        let tlv = assert_tlv_roundtrip(GOBGP_TLV_TE_DEFAULT_METRIC);
        assert_eq!(tlv, LsTlv::TeDefaultMetric(100));
    }

    #[test]
    fn gobgp_tlv_igp_metric() {
        let tlv = assert_tlv_roundtrip(GOBGP_TLV_IGP_METRIC);
        assert_eq!(tlv, LsTlv::IgpMetric(100000));
    }

    #[test]
    fn gobgp_tlv_srlg() {
        let tlv = assert_tlv_roundtrip(GOBGP_TLV_SRLG);
        assert_eq!(tlv, LsTlv::Srlg(vec![0x1000, 0x2000]));
    }

    #[test]
    fn gobgp_tlv_opaque_link_attr() {
        let tlv = assert_tlv_roundtrip(GOBGP_TLV_OPAQUE_LINK_ATTR);
        assert_eq!(tlv, LsTlv::OpaqueLinkAttr(vec![0xAB, 0xCD]));
    }

    #[test]
    fn gobgp_tlv_link_name() {
        let tlv = assert_tlv_roundtrip(GOBGP_TLV_LINK_NAME);
        assert_eq!(tlv, LsTlv::LinkName("eth0".to_string()));
    }

    #[test]
    fn gobgp_tlv_adj_sid() {
        let tlv = assert_tlv_roundtrip(GOBGP_TLV_ADJ_SID);
        assert_eq!(
            tlv,
            LsTlv::AdjSid {
                flags: 0x40,
                weight: 0,
                sid: 100500,
            }
        );
    }

    #[test]
    fn gobgp_tlv_peer_node_sid() {
        let tlv = assert_tlv_roundtrip(GOBGP_TLV_PEER_NODE_SID);
        assert_eq!(
            tlv,
            LsTlv::PeerNodeSid {
                flags: 0x40,
                weight: 0,
                sid: 100500,
            }
        );
    }

    #[test]
    fn gobgp_tlv_peer_adj_sid() {
        let tlv = assert_tlv_roundtrip(GOBGP_TLV_PEER_ADJ_SID);
        assert_eq!(
            tlv,
            LsTlv::PeerAdjSid {
                flags: 0x40,
                weight: 0,
                sid: 100500,
            }
        );
    }

    #[test]
    fn gobgp_tlv_peer_set_sid() {
        let tlv = assert_tlv_roundtrip(GOBGP_TLV_PEER_SET_SID);
        assert_eq!(
            tlv,
            LsTlv::PeerSetSid {
                flags: 0x40,
                weight: 0,
                sid: 100500,
            }
        );
    }

    #[test]
    fn gobgp_tlv_srv6_end_x_sid() {
        let tlv = assert_tlv_roundtrip(GOBGP_TLV_SRV6_END_X_SID);
        assert_eq!(
            tlv,
            LsTlv::Srv6EndXSid {
                endpoint_behavior: 57,
                flags: 0,
                algorithm: 0,
                weight: 100,
                sids: vec![[
                    0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x01
                ]],
                sid_structure: Some(SrSidStructure {
                    lb_len: 32,
                    ln_len: 16,
                    fn_len: 16,
                    arg_len: 0,
                }),
            }
        );
    }

    #[test]
    fn gobgp_tlv_unidirectional_link_delay() {
        let tlv = assert_tlv_roundtrip(GOBGP_TLV_UNIDIRECTIONAL_LINK_DELAY);
        assert_eq!(
            tlv,
            LsTlv::UnidirectionalLinkDelay {
                anomalous: false,
                delay_us: 1000,
            }
        );
    }

    #[test]
    fn gobgp_tlv_min_max_unidirectional_link_delay() {
        let tlv = assert_tlv_roundtrip(GOBGP_TLV_MIN_MAX_UNIDIRECTIONAL_LINK_DELAY);
        assert_eq!(
            tlv,
            LsTlv::MinMaxUnidirectionalLinkDelay {
                anomalous: false,
                min_us: 500,
                max_us: 2000,
            }
        );
    }

    #[test]
    fn gobgp_tlv_unidirectional_delay_variation() {
        let tlv = assert_tlv_roundtrip(GOBGP_TLV_UNIDIRECTIONAL_DELAY_VARIATION);
        assert_eq!(tlv, LsTlv::UnidirectionalDelayVariation(100));
    }

    #[test]
    fn gobgp_tlv_igp_flags() {
        let tlv = assert_tlv_roundtrip(GOBGP_TLV_IGP_FLAGS);
        assert_eq!(tlv, LsTlv::IgpFlags(0xc0));
    }

    #[test]
    fn gobgp_tlv_opaque_prefix_attr() {
        let tlv = assert_tlv_roundtrip(GOBGP_TLV_OPAQUE_PREFIX_ATTR);
        assert_eq!(tlv, LsTlv::OpaquePrefixAttr(vec![0xde, 0xad, 0xbe]));
    }

    #[test]
    fn gobgp_tlv_prefix_sid() {
        let tlv = assert_tlv_roundtrip(GOBGP_TLV_PREFIX_SID);
        assert_eq!(
            tlv,
            LsTlv::PrefixSid {
                flags: 0,
                algorithm: 0,
                sid: 100500,
            }
        );
    }

    // RFC 7752 §3.2.3.2 permits prefix-length 0 (default route 0.0.0.0/0 or
    // ::/0).  GoBGP rejected it until PR #3458 fixed two guards that treated
    // prefix-length 0 as invalid; these tests confirm RustyBGP handles it
    // correctly by exercising encode -> decode roundtrips for both AFIs.
    #[test]
    fn ip_reachability_prefix_len_zero_v4() {
        let original = BgpLsNlri::PrefixV4(BgpLsPrefixNlri {
            protocol_id: PROTOCOL_OSPF_V2,
            identifier: 0,
            local_node: NodeDescriptor {
                asn: Some(65001),
                igp_router_id: Some(vec![10, 0, 0, 1]),
                ..Default::default()
            },
            prefix_desc: vec![PrefixDescTlv::IpReachability {
                prefix_len: 0,
                addr: vec![],
            }],
        });
        let mut buf = Vec::new();
        original.encode(&mut buf);
        let mut c = Cursor::new(buf.as_slice());
        let decoded = BgpLsNlri::decode(&mut c).expect("decode failed");
        assert_eq!(original, decoded);
    }

    #[test]
    fn ip_reachability_prefix_len_zero_v6() {
        let original = BgpLsNlri::PrefixV6(BgpLsPrefixNlri {
            protocol_id: PROTOCOL_ISIS_L2,
            identifier: 0,
            local_node: NodeDescriptor {
                asn: Some(65001),
                igp_router_id: Some(vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06]),
                ..Default::default()
            },
            prefix_desc: vec![PrefixDescTlv::IpReachability {
                prefix_len: 0,
                addr: vec![],
            }],
        });
        let mut buf = Vec::new();
        original.encode(&mut buf);
        let mut c = Cursor::new(buf.as_slice());
        let decoded = BgpLsNlri::decode(&mut c).expect("decode failed");
        assert_eq!(original, decoded);
    }
}
