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
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! BGP Tunnel Encapsulation Attribute (RFC 9012) with SR Policy (RFC 9830).
//!
//! TLV format: 2-byte type + 2-byte length + N bytes value.
//! Sub-TLV header (RFC 9012 §3.1 / GoBGP): type(1) + length(1 or 2) + value.
//! Types < 128 use a 1-byte length; types >= 128 use a 2-byte length.

use byteorder::{NetworkEndian, ReadBytesExt};
use std::io::Cursor;
use std::net::Ipv6Addr;

pub const TUNNEL_TYPE_SR_POLICY: u16 = 15;

// SR Policy Candidate Path sub-TLV types (RFC 9830 §2.4)
const SUBTLV_PREFERENCE: u8 = 12;
const SUBTLV_BINDING_SID: u8 = 13;
const SUBTLV_ENLP: u8 = 14;
const SUBTLV_PRIORITY: u8 = 15;
const SUBTLV_SRV6_BINDING_SID: u8 = 20;
const SUBTLV_SEGMENT_LIST: u8 = 128;
const SUBTLV_CANDIDATE_PATH_NAME: u8 = 129;
const SUBTLV_POLICY_NAME: u8 = 130;

// Sub-sub-TLV types within Segment List (RFC 9830 §2.4.7)
const SEGSUB_WEIGHT: u8 = 9;
const SEGSUB_TYPE_A: u8 = 1;
const SEGSUB_TYPE_B: u8 = 13;

/// One entry in the BGP Tunnel Encapsulation Attribute.
#[derive(Clone, Debug, PartialEq)]
pub struct TunnelEncapTlv {
    pub tunnel_type: u16,
    pub value: TunnelEncapValue,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TunnelEncapValue {
    /// Tunnel Type 15: SR Policy Candidate Path (RFC 9830).
    SrPolicy(SrPolicyCandidatePath),
    /// Any other tunnel type: raw value bytes.
    Unknown(Vec<u8>),
}

/// SR Policy Candidate Path (RFC 9830 §2.4).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SrPolicyCandidatePath {
    /// Sub-TLV 12: Preference.
    pub preference: Option<SrPolicyPreference>,
    /// Sub-TLV 13: SR-MPLS or SRv6 Binding SID (discriminated by length).
    pub binding_sid: Option<SrPolicyBindingSid>,
    /// Sub-TLV 20: SRv6 Binding SID with endpoint behavior structure.
    pub srv6_binding_sid: Option<SrPolicySrv6BindingSid>,
    /// Sub-TLV 14: Explicit NULL Label Policy.
    pub enlp: Option<SrPolicyEnlp>,
    /// Sub-TLV 15: Priority.
    pub priority: Option<u8>,
    /// Sub-TLV 128: Segment Lists (multiple are allowed).
    pub segment_lists: Vec<SrPolicySegmentList>,
    /// Sub-TLV 129: Candidate Path Name.
    pub candidate_path_name: Option<String>,
    /// Sub-TLV 130: Policy Name.
    pub policy_name: Option<String>,
}

/// SR Policy Preference (sub-TLV 12, RFC 9830 §2.4.1).
///
/// Wire: flags(1) + reserved(1) + preference(4) = 6 bytes.
#[derive(Clone, Debug, PartialEq)]
pub struct SrPolicyPreference {
    pub flags: u8,
    pub preference: u32,
}

/// SR Policy Binding SID (sub-TLV 13, RFC 9830 §2.4.3).
///
/// Wire (MPLS): flags(1) + reserved(1) + label_stack_entry(4) = 6 bytes.
/// Wire (SRv6): flags(1) + reserved(1) + SID(16) = 18 bytes.
#[derive(Clone, Debug, PartialEq)]
pub enum SrPolicyBindingSid {
    /// SR-MPLS BSID: 20-bit label value (stored in bits [31:12] of a u32).
    Mpls { flags: u8, label: u32 },
    /// SRv6 BSID without endpoint behavior structure.
    Srv6 { flags: u8, sid: Ipv6Addr },
}

/// SRv6 Binding SID with endpoint behavior (sub-TLV 20, RFC 9830 §2.4.4).
///
/// Wire: flags(1) + reserved(1) + SID(16) + behavior(2) + block_len(1) +
///       node_len(1) + func_len(1) + arg_len(1) = 24 bytes.
#[derive(Clone, Debug, PartialEq)]
pub struct SrPolicySrv6BindingSid {
    pub flags: u8,
    pub sid: Ipv6Addr,
    pub endpoint_behavior: SRv6EndpointBehavior,
}

/// SRv6 Endpoint Behavior Structure (RFC 9830 §2.4.4).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SRv6EndpointBehavior {
    pub behavior: u16,
    pub block_len: u8,
    pub node_len: u8,
    pub func_len: u8,
    pub arg_len: u8,
}

/// Explicit NULL Label Policy (sub-TLV 14, RFC 9830 §2.4.5).
///
/// Wire: flags(1) + reserved(1) + enlp_type(1) = 3 bytes.
#[derive(Clone, Debug, PartialEq)]
pub struct SrPolicyEnlp {
    pub flags: u8,
    pub enlp_type: u8,
}

/// Segment List (sub-TLV 128, RFC 9830 §2.4.7).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SrPolicySegmentList {
    pub weight: Option<SrWeight>,
    pub segments: Vec<SrSegment>,
}

/// Segment List weight (sub-sub-TLV 9).
///
/// Wire: flags(1) + reserved(1) + weight(4) = 6 bytes.
#[derive(Clone, Debug, PartialEq)]
pub struct SrWeight {
    pub flags: u8,
    pub weight: u32,
}

/// One segment in a Segment List.
#[derive(Clone, Debug, PartialEq)]
pub enum SrSegment {
    /// Segment Type A: SR-MPLS label (sub-sub-TLV 1, RFC 9830 §2.5.1).
    ///
    /// Wire: flags(1) + reserved(1) + label_stack_entry(4) = 6 bytes.
    /// `label` is the 20-bit label value (bits [31:12] of the stack entry).
    TypeA { flags: u8, label: u32 },
    /// Segment Type B: SRv6 SID (sub-sub-TLV 13, RFC 9830 §2.5.2).
    ///
    /// Wire: flags(1) + reserved(1) + SID(16) + optional behavior(6) = 18 or 24 bytes.
    /// Endpoint behavior is present when the A-flag (0x40) in flags is set.
    TypeB {
        flags: u8,
        sid: Ipv6Addr,
        endpoint_behavior: Option<SRv6EndpointBehavior>,
    },
}

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

/// Decode all TLVs from the raw Tunnel Encapsulation Attribute value bytes.
pub fn decode(data: &[u8]) -> Vec<TunnelEncapTlv> {
    let mut tlvs = Vec::new();
    let mut c = Cursor::new(data);
    while (c.position() as usize) < data.len() {
        let Ok(tunnel_type) = c.read_u16::<NetworkEndian>() else {
            break;
        };
        let Ok(len) = c.read_u16::<NetworkEndian>() else {
            break;
        };
        let pos = c.position() as usize;
        let end = pos + len as usize;
        if end > data.len() {
            break;
        }
        let value_bytes = &data[pos..end];
        c.set_position(end as u64);

        let value = if tunnel_type == TUNNEL_TYPE_SR_POLICY {
            TunnelEncapValue::SrPolicy(decode_sr_policy(value_bytes))
        } else {
            TunnelEncapValue::Unknown(value_bytes.to_vec())
        };
        tlvs.push(TunnelEncapTlv { tunnel_type, value });
    }
    tlvs
}

fn decode_sr_policy(data: &[u8]) -> SrPolicyCandidatePath {
    let mut cp = SrPolicyCandidatePath::default();
    let mut c = Cursor::new(data);
    while (c.position() as usize) < data.len() {
        let Ok(sub_type) = c.read_u8() else { break };
        // Types >= 128 use a 2-byte length field; types < 128 use 1-byte.
        let sub_len: usize = if sub_type >= 128 {
            let Ok(n) = c.read_u16::<NetworkEndian>() else {
                break;
            };
            n as usize
        } else {
            let Ok(n) = c.read_u8() else { break };
            n as usize
        };
        let pos = c.position() as usize;
        let end = pos + sub_len;
        if end > data.len() {
            break;
        }
        let body = &data[pos..end];
        c.set_position(end as u64);

        match sub_type {
            SUBTLV_PREFERENCE => {
                // Wire: flags(1) + reserved(1) + preference(4) = 6 bytes
                if body.len() >= 6 {
                    cp.preference = Some(SrPolicyPreference {
                        flags: body[0],
                        preference: u32::from_be_bytes(body[2..6].try_into().unwrap()),
                    });
                }
            }
            SUBTLV_BINDING_SID => match body.len() {
                6 => {
                    let flags = body[0];
                    // body[1] is reserved
                    let label = u32::from_be_bytes(body[2..6].try_into().unwrap()) >> 12;
                    cp.binding_sid = Some(SrPolicyBindingSid::Mpls { flags, label });
                }
                18 => {
                    let flags = body[0];
                    // body[1] is reserved
                    let sid = decode_ipv6(&body[2..18]);
                    cp.binding_sid = Some(SrPolicyBindingSid::Srv6 { flags, sid });
                }
                _ => {}
            },
            SUBTLV_SRV6_BINDING_SID => {
                if body.len() >= 24 {
                    let flags = body[0];
                    // body[1] is reserved
                    let sid = decode_ipv6(&body[2..18]);
                    let behavior = u16::from_be_bytes(body[18..20].try_into().unwrap());
                    cp.srv6_binding_sid = Some(SrPolicySrv6BindingSid {
                        flags,
                        sid,
                        endpoint_behavior: SRv6EndpointBehavior {
                            behavior,
                            block_len: body[20],
                            node_len: body[21],
                            func_len: body[22],
                            arg_len: body[23],
                        },
                    });
                }
            }
            SUBTLV_ENLP => {
                // Wire: flags(1) + reserved(1) + enlp_type(1) = 3 bytes
                if body.len() >= 3 {
                    cp.enlp = Some(SrPolicyEnlp {
                        flags: body[0],
                        enlp_type: body[2],
                    });
                }
            }
            SUBTLV_PRIORITY => {
                if !body.is_empty() {
                    cp.priority = Some(body[0]);
                }
            }
            SUBTLV_SEGMENT_LIST => {
                if !body.is_empty() {
                    // body[0] = reserved
                    let sl = decode_segment_list(&body[1..]);
                    cp.segment_lists.push(sl);
                }
            }
            SUBTLV_CANDIDATE_PATH_NAME => {
                // body[0] = flags; body[1..] = name bytes
                cp.candidate_path_name = body
                    .get(1..)
                    .and_then(|b| std::str::from_utf8(b).ok())
                    .map(str::to_owned);
            }
            SUBTLV_POLICY_NAME => {
                // body[0] = flags; body[1..] = name bytes
                cp.policy_name = body
                    .get(1..)
                    .and_then(|b| std::str::from_utf8(b).ok())
                    .map(str::to_owned);
            }
            _ => {}
        }
    }
    cp
}

fn decode_segment_list(data: &[u8]) -> SrPolicySegmentList {
    let mut sl = SrPolicySegmentList::default();
    let mut c = Cursor::new(data);
    while (c.position() as usize) < data.len() {
        let Ok(seg_type) = c.read_u8() else { break };
        let Ok(seg_len) = c.read_u8() else { break };
        let pos = c.position() as usize;
        let end = pos + seg_len as usize;
        if end > data.len() {
            break;
        }
        let body = &data[pos..end];
        c.set_position(end as u64);

        match seg_type {
            SEGSUB_WEIGHT => {
                // Wire: flags(1) + reserved(1) + weight(4) = 6 bytes
                if body.len() >= 6 {
                    sl.weight = Some(SrWeight {
                        flags: body[0],
                        weight: u32::from_be_bytes(body[2..6].try_into().unwrap()),
                    });
                }
            }
            SEGSUB_TYPE_A => {
                if body.len() >= 6 {
                    let flags = body[0];
                    // body[1] reserved
                    let entry = u32::from_be_bytes(body[2..6].try_into().unwrap());
                    let label = entry >> 12;
                    sl.segments.push(SrSegment::TypeA { flags, label });
                }
            }
            SEGSUB_TYPE_B if body.len() >= 18 => {
                let flags = body[0];
                // body[1] reserved
                let sid = decode_ipv6(&body[2..18]);
                // A-flag (0x40) indicates endpoint behavior is present.
                // EBS wire: behavior(2) + reserved(2) + block_len(1) + node_len(1) + func_len(1) + arg_len(1)
                let endpoint_behavior = if flags & 0x40 != 0 && body.len() >= 26 {
                    Some(SRv6EndpointBehavior {
                        behavior: u16::from_be_bytes(body[18..20].try_into().unwrap()),
                        block_len: body[22],
                        node_len: body[23],
                        func_len: body[24],
                        arg_len: body[25],
                    })
                } else {
                    None
                };
                sl.segments.push(SrSegment::TypeB {
                    flags,
                    sid,
                    endpoint_behavior,
                });
            }
            _ => {}
        }
    }
    sl
}

fn decode_ipv6(b: &[u8]) -> Ipv6Addr {
    let arr: [u8; 16] = b[..16].try_into().unwrap();
    Ipv6Addr::from(arr)
}

// ---------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------

/// Encode all TLVs into a byte buffer (the attribute value bytes).
pub fn encode(tlvs: &[TunnelEncapTlv]) -> Vec<u8> {
    let mut buf = Vec::new();
    for tlv in tlvs {
        let value = match &tlv.value {
            TunnelEncapValue::SrPolicy(cp) => encode_sr_policy(cp),
            TunnelEncapValue::Unknown(b) => b.clone(),
        };
        buf.extend_from_slice(&tlv.tunnel_type.to_be_bytes());
        buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
        buf.extend_from_slice(&value);
    }
    buf
}

fn encode_sr_policy(cp: &SrPolicyCandidatePath) -> Vec<u8> {
    let mut buf = Vec::new();

    if let Some(pref) = &cp.preference {
        let body = encode_preference(pref);
        push_subtlv(&mut buf, SUBTLV_PREFERENCE, &body);
    }
    if let Some(bsid) = &cp.binding_sid {
        let body = encode_binding_sid(bsid);
        push_subtlv(&mut buf, SUBTLV_BINDING_SID, &body);
    }
    if let Some(bsid) = &cp.srv6_binding_sid {
        let body = encode_srv6_binding_sid(bsid);
        push_subtlv(&mut buf, SUBTLV_SRV6_BINDING_SID, &body);
    }
    if let Some(enlp) = &cp.enlp {
        // Wire: flags(1) + reserved(1) + enlp_type(1) = 3 bytes
        let body = [enlp.flags, 0, enlp.enlp_type];
        push_subtlv(&mut buf, SUBTLV_ENLP, &body);
    }
    if let Some(pri) = cp.priority {
        push_subtlv(&mut buf, SUBTLV_PRIORITY, &[pri, 0]);
    }
    if let Some(name) = &cp.candidate_path_name {
        // Wire: flags(1) + name bytes
        let mut body = vec![0u8]; // flags
        body.extend_from_slice(name.as_bytes());
        push_subtlv(&mut buf, SUBTLV_CANDIDATE_PATH_NAME, &body);
    }
    if let Some(name) = &cp.policy_name {
        // Wire: flags(1) + name bytes
        let mut body = vec![0u8]; // flags
        body.extend_from_slice(name.as_bytes());
        push_subtlv(&mut buf, SUBTLV_POLICY_NAME, &body);
    }
    for sl in &cp.segment_lists {
        let body = encode_segment_list(sl);
        push_subtlv(&mut buf, SUBTLV_SEGMENT_LIST, &body);
    }

    buf
}

fn encode_preference(pref: &SrPolicyPreference) -> Vec<u8> {
    // Wire: flags(1) + reserved(1) + preference(4) = 6 bytes
    let mut b = Vec::with_capacity(6);
    b.push(pref.flags);
    b.push(0); // reserved
    b.extend_from_slice(&pref.preference.to_be_bytes());
    b
}

fn encode_binding_sid(bsid: &SrPolicyBindingSid) -> Vec<u8> {
    match bsid {
        SrPolicyBindingSid::Mpls { flags, label } => {
            let mut b = Vec::with_capacity(6);
            b.push(*flags);
            b.push(0); // reserved
            b.extend_from_slice(&(label << 12).to_be_bytes());
            b
        }
        SrPolicyBindingSid::Srv6 { flags, sid } => {
            let mut b = Vec::with_capacity(18);
            b.push(*flags);
            b.push(0); // reserved
            b.extend_from_slice(&sid.octets());
            b
        }
    }
}

fn encode_srv6_binding_sid(bsid: &SrPolicySrv6BindingSid) -> Vec<u8> {
    let mut b = Vec::with_capacity(24);
    b.push(bsid.flags);
    b.push(0); // reserved
    b.extend_from_slice(&bsid.sid.octets());
    b.extend_from_slice(&bsid.endpoint_behavior.behavior.to_be_bytes());
    b.push(bsid.endpoint_behavior.block_len);
    b.push(bsid.endpoint_behavior.node_len);
    b.push(bsid.endpoint_behavior.func_len);
    b.push(bsid.endpoint_behavior.arg_len);
    b
}

fn encode_segment_list(sl: &SrPolicySegmentList) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(0); // reserved

    if let Some(w) = &sl.weight {
        // Wire: flags(1) + reserved(1) + weight(4) = 6 bytes
        let mut body = Vec::with_capacity(6);
        body.push(w.flags);
        body.push(0); // reserved
        body.extend_from_slice(&w.weight.to_be_bytes());
        push_subtlv(&mut buf, SEGSUB_WEIGHT, &body);
    }
    for seg in &sl.segments {
        match seg {
            SrSegment::TypeA { flags, label } => {
                let mut body = Vec::with_capacity(6);
                body.push(*flags);
                body.push(0); // reserved
                body.extend_from_slice(&(label << 12).to_be_bytes());
                push_subtlv(&mut buf, SEGSUB_TYPE_A, &body);
            }
            SrSegment::TypeB {
                flags,
                sid,
                endpoint_behavior,
            } => {
                let mut body = Vec::with_capacity(24);
                body.push(*flags);
                body.push(0); // reserved
                body.extend_from_slice(&sid.octets());
                if let Some(eb) = endpoint_behavior {
                    // EBS wire: behavior(2) + reserved(2) + block_len(1) + node_len(1) + func_len(1) + arg_len(1)
                    body.extend_from_slice(&eb.behavior.to_be_bytes());
                    body.push(0); // EBS reserved
                    body.push(0); // EBS reserved
                    body.push(eb.block_len);
                    body.push(eb.node_len);
                    body.push(eb.func_len);
                    body.push(eb.arg_len);
                }
                push_subtlv(&mut buf, SEGSUB_TYPE_B, &body);
            }
        }
    }
    buf
}

fn push_subtlv(buf: &mut Vec<u8>, sub_type: u8, body: &[u8]) {
    buf.push(sub_type);
    // Types >= 128 use a 2-byte length field; types < 128 use 1-byte.
    if sub_type >= 128 {
        buf.extend_from_slice(&(body.len() as u16).to_be_bytes());
    } else {
        buf.push(body.len() as u8);
    }
    buf.extend_from_slice(body);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    // GoBGP-generated test vectors (packet/tests/fixtures/gen/sr_policy_nlri/main.go).
    // Each constant is the raw attribute value bytes (TLV payload only, no BGP
    // path attribute header) as serialised by GoBGP v4.6.0.

    // TunnelEncap: type=15 (SR Policy), preference=100
    const GOBGP_PREF100: &[u8] = &[
        0x00, 0x0f, 0x00, 0x08, 0x0c, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64,
    ];

    // TunnelEncap: type=15, preference=200, MPLS BSID=16001, segment list weight=1, TypeA label=16001
    const GOBGP_PREF200_BSID_SEGLIST_TYPEA: &[u8] = &[
        0x00, 0x0f, 0x00, 0x24, 0x0c, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc8, 0x0d, 0x06, 0x00,
        0x00, 0x03, 0xe8, 0x10, 0x00, 0x80, 0x00, 0x11, 0x00, 0x09, 0x06, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x01, 0x06, 0x00, 0x00, 0x03, 0xe8, 0x10, 0x00,
    ];

    // TunnelEncap: type=15, preference=10, ENLP type 1, priority=100
    const GOBGP_ENLP_PRIORITY: &[u8] = &[
        0x00, 0x0f, 0x00, 0x11, 0x0c, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x0e, 0x03, 0x00,
        0x00, 0x01, 0x0f, 0x02, 0x64, 0x00,
    ];

    // TunnelEncap: type=15, preference=200, SRv6 binding SID fd00::1
    const GOBGP_SRV6_BSID: &[u8] = &[
        0x00, 0x0f, 0x00, 0x1c, 0x0c, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc8, 0x0d, 0x12, 0x00,
        0x00, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01,
    ];

    // TunnelEncap: type=15, preference=100, TypeB SID=2001:db8::1 with EBS (End, 32/16/16/0)
    const GOBGP_TYPEB_EBS: &[u8] = &[
        0x00, 0x0f, 0x00, 0x28, 0x0c, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x80, 0x00, 0x1d,
        0x00, 0x0d, 0x1a, 0x40, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x20, 0x10, 0x10, 0x00,
    ];

    // TunnelEncap: type=15, preference=50, candidate path name="test-policy", TypeB SID=2001:db8::1
    const GOBGP_PREF50_CPNAME_TYPEB: &[u8] = &[
        0x00, 0x0f, 0x00, 0x37, 0x0c, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x32, 0x81, 0x00, 0x0c,
        0x00, 0x74, 0x65, 0x73, 0x74, 0x2d, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x80, 0x00, 0x1d,
        0x00, 0x09, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0d, 0x12, 0x00, 0x00, 0x20, 0x01,
        0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];

    fn sr_policy_tlv(cp: SrPolicyCandidatePath) -> TunnelEncapTlv {
        TunnelEncapTlv {
            tunnel_type: TUNNEL_TYPE_SR_POLICY,
            value: TunnelEncapValue::SrPolicy(cp),
        }
    }

    // --- GoBGP wire-format compatibility tests ---

    #[test]
    fn gobgp_decode_pref100() {
        let tlvs = decode(GOBGP_PREF100);
        assert_eq!(tlvs.len(), 1);
        let TunnelEncapValue::SrPolicy(ref cp) = tlvs[0].value else {
            panic!("expected SrPolicy");
        };
        assert_eq!(
            cp.preference,
            Some(SrPolicyPreference {
                flags: 0,
                preference: 100
            })
        );
        assert!(cp.binding_sid.is_none());
        assert!(cp.segment_lists.is_empty());
    }

    #[test]
    fn gobgp_encode_pref100() {
        let cp = SrPolicyCandidatePath {
            preference: Some(SrPolicyPreference {
                flags: 0,
                preference: 100,
            }),
            ..Default::default()
        };
        let encoded = encode(&[sr_policy_tlv(cp)]);
        assert_eq!(encoded, GOBGP_PREF100);
    }

    #[test]
    fn gobgp_decode_pref200_bsid_seglist_typea() {
        let tlvs = decode(GOBGP_PREF200_BSID_SEGLIST_TYPEA);
        assert_eq!(tlvs.len(), 1);
        let TunnelEncapValue::SrPolicy(ref cp) = tlvs[0].value else {
            panic!("expected SrPolicy");
        };
        assert_eq!(
            cp.preference,
            Some(SrPolicyPreference {
                flags: 0,
                preference: 200
            })
        );
        assert_eq!(
            cp.binding_sid,
            Some(SrPolicyBindingSid::Mpls {
                flags: 0,
                label: 16001
            })
        );
        assert_eq!(cp.segment_lists.len(), 1);
        let sl = &cp.segment_lists[0];
        assert_eq!(
            sl.weight,
            Some(SrWeight {
                flags: 0,
                weight: 1
            })
        );
        assert_eq!(sl.segments.len(), 1);
        assert_eq!(
            sl.segments[0],
            SrSegment::TypeA {
                flags: 0,
                label: 16001
            }
        );
    }

    #[test]
    fn gobgp_encode_pref200_bsid_seglist_typea() {
        let cp = SrPolicyCandidatePath {
            preference: Some(SrPolicyPreference {
                flags: 0,
                preference: 200,
            }),
            binding_sid: Some(SrPolicyBindingSid::Mpls {
                flags: 0,
                label: 16001,
            }),
            segment_lists: vec![SrPolicySegmentList {
                weight: Some(SrWeight {
                    flags: 0,
                    weight: 1,
                }),
                segments: vec![SrSegment::TypeA {
                    flags: 0,
                    label: 16001,
                }],
            }],
            ..Default::default()
        };
        let encoded = encode(&[sr_policy_tlv(cp)]);
        assert_eq!(encoded, GOBGP_PREF200_BSID_SEGLIST_TYPEA);
    }

    #[test]
    fn gobgp_decode_pref50_cpname_typeb() {
        let tlvs = decode(GOBGP_PREF50_CPNAME_TYPEB);
        assert_eq!(tlvs.len(), 1);
        let TunnelEncapValue::SrPolicy(ref cp) = tlvs[0].value else {
            panic!("expected SrPolicy");
        };
        assert_eq!(
            cp.preference,
            Some(SrPolicyPreference {
                flags: 0,
                preference: 50
            })
        );
        assert_eq!(cp.candidate_path_name, Some("test-policy".to_string()));
        assert_eq!(cp.segment_lists.len(), 1);
        let sl = &cp.segment_lists[0];
        assert_eq!(
            sl.weight,
            Some(SrWeight {
                flags: 0,
                weight: 1
            })
        );
        assert_eq!(sl.segments.len(), 1);
        assert_eq!(
            sl.segments[0],
            SrSegment::TypeB {
                flags: 0,
                sid: Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
                endpoint_behavior: None,
            }
        );
    }

    #[test]
    fn gobgp_encode_pref50_cpname_typeb() {
        let cp = SrPolicyCandidatePath {
            preference: Some(SrPolicyPreference {
                flags: 0,
                preference: 50,
            }),
            candidate_path_name: Some("test-policy".to_string()),
            segment_lists: vec![SrPolicySegmentList {
                weight: Some(SrWeight {
                    flags: 0,
                    weight: 1,
                }),
                segments: vec![SrSegment::TypeB {
                    flags: 0,
                    sid: Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
                    endpoint_behavior: None,
                }],
            }],
            ..Default::default()
        };
        let encoded = encode(&[sr_policy_tlv(cp)]);
        assert_eq!(encoded, GOBGP_PREF50_CPNAME_TYPEB);
    }

    #[test]
    fn gobgp_decode_enlp_priority() {
        let tlvs = decode(GOBGP_ENLP_PRIORITY);
        assert_eq!(tlvs.len(), 1);
        let TunnelEncapValue::SrPolicy(ref cp) = tlvs[0].value else {
            panic!("expected SrPolicy");
        };
        assert_eq!(
            cp.preference,
            Some(SrPolicyPreference {
                flags: 0,
                preference: 10
            })
        );
        assert_eq!(
            cp.enlp,
            Some(SrPolicyEnlp {
                flags: 0,
                enlp_type: 1
            })
        );
        assert_eq!(cp.priority, Some(100));
    }

    #[test]
    fn gobgp_encode_enlp_priority() {
        let cp = SrPolicyCandidatePath {
            preference: Some(SrPolicyPreference {
                flags: 0,
                preference: 10,
            }),
            enlp: Some(SrPolicyEnlp {
                flags: 0,
                enlp_type: 1,
            }),
            priority: Some(100),
            ..Default::default()
        };
        let encoded = encode(&[sr_policy_tlv(cp)]);
        assert_eq!(encoded, GOBGP_ENLP_PRIORITY);
    }

    #[test]
    fn gobgp_decode_srv6_bsid() {
        let tlvs = decode(GOBGP_SRV6_BSID);
        assert_eq!(tlvs.len(), 1);
        let TunnelEncapValue::SrPolicy(ref cp) = tlvs[0].value else {
            panic!("expected SrPolicy");
        };
        assert_eq!(
            cp.preference,
            Some(SrPolicyPreference {
                flags: 0,
                preference: 200
            })
        );
        assert_eq!(
            cp.binding_sid,
            Some(SrPolicyBindingSid::Srv6 {
                flags: 0,
                sid: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1),
            })
        );
    }

    #[test]
    fn gobgp_encode_srv6_bsid() {
        let cp = SrPolicyCandidatePath {
            preference: Some(SrPolicyPreference {
                flags: 0,
                preference: 200,
            }),
            binding_sid: Some(SrPolicyBindingSid::Srv6 {
                flags: 0,
                sid: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1),
            }),
            ..Default::default()
        };
        let encoded = encode(&[sr_policy_tlv(cp)]);
        assert_eq!(encoded, GOBGP_SRV6_BSID);
    }

    #[test]
    fn gobgp_decode_typeb_ebs() {
        let tlvs = decode(GOBGP_TYPEB_EBS);
        assert_eq!(tlvs.len(), 1);
        let TunnelEncapValue::SrPolicy(ref cp) = tlvs[0].value else {
            panic!("expected SrPolicy");
        };
        assert_eq!(
            cp.preference,
            Some(SrPolicyPreference {
                flags: 0,
                preference: 100
            })
        );
        assert_eq!(cp.segment_lists.len(), 1);
        let sl = &cp.segment_lists[0];
        assert_eq!(sl.segments.len(), 1);
        assert_eq!(
            sl.segments[0],
            SrSegment::TypeB {
                flags: 0x40,
                sid: Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
                endpoint_behavior: Some(SRv6EndpointBehavior {
                    behavior: 1,
                    block_len: 32,
                    node_len: 16,
                    func_len: 16,
                    arg_len: 0,
                }),
            }
        );
    }

    #[test]
    fn gobgp_encode_typeb_ebs() {
        let cp = SrPolicyCandidatePath {
            preference: Some(SrPolicyPreference {
                flags: 0,
                preference: 100,
            }),
            segment_lists: vec![SrPolicySegmentList {
                weight: None,
                segments: vec![SrSegment::TypeB {
                    flags: 0x40,
                    sid: Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
                    endpoint_behavior: Some(SRv6EndpointBehavior {
                        behavior: 1,
                        block_len: 32,
                        node_len: 16,
                        func_len: 16,
                        arg_len: 0,
                    }),
                }],
            }],
            ..Default::default()
        };
        let encoded = encode(&[sr_policy_tlv(cp)]);
        assert_eq!(encoded, GOBGP_TYPEB_EBS);
    }

    // --- Internal roundtrip tests ---

    #[test]
    fn roundtrip_preference() {
        let cp = SrPolicyCandidatePath {
            preference: Some(SrPolicyPreference {
                flags: 0,
                preference: 100,
            }),
            ..Default::default()
        };
        let tlvs = vec![sr_policy_tlv(cp)];
        let encoded = encode(&tlvs);
        let decoded = decode(&encoded);
        assert_eq!(decoded, tlvs);
    }

    #[test]
    fn roundtrip_binding_sid_mpls() {
        let cp = SrPolicyCandidatePath {
            binding_sid: Some(SrPolicyBindingSid::Mpls {
                flags: 0,
                label: 1000,
            }),
            ..Default::default()
        };
        let tlvs = vec![sr_policy_tlv(cp)];
        let encoded = encode(&tlvs);
        let decoded = decode(&encoded);
        assert_eq!(decoded, tlvs);
    }

    #[test]
    fn roundtrip_binding_sid_srv6() {
        let cp = SrPolicyCandidatePath {
            binding_sid: Some(SrPolicyBindingSid::Srv6 {
                flags: 0,
                sid: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1),
            }),
            ..Default::default()
        };
        let tlvs = vec![sr_policy_tlv(cp)];
        let encoded = encode(&tlvs);
        let decoded = decode(&encoded);
        assert_eq!(decoded, tlvs);
    }

    #[test]
    fn roundtrip_srv6_binding_sid_with_behavior() {
        let cp = SrPolicyCandidatePath {
            srv6_binding_sid: Some(SrPolicySrv6BindingSid {
                flags: 0,
                sid: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
                endpoint_behavior: SRv6EndpointBehavior {
                    behavior: 0x0013, // End.DT4
                    block_len: 32,
                    node_len: 16,
                    func_len: 16,
                    arg_len: 0,
                },
            }),
            ..Default::default()
        };
        let tlvs = vec![sr_policy_tlv(cp)];
        let encoded = encode(&tlvs);
        let decoded = decode(&encoded);
        assert_eq!(decoded, tlvs);
    }

    #[test]
    fn roundtrip_enlp_and_priority() {
        let cp = SrPolicyCandidatePath {
            enlp: Some(SrPolicyEnlp {
                flags: 0,
                enlp_type: 2,
            }),
            priority: Some(10),
            ..Default::default()
        };
        let tlvs = vec![sr_policy_tlv(cp)];
        let encoded = encode(&tlvs);
        let decoded = decode(&encoded);
        assert_eq!(decoded, tlvs);
    }

    #[test]
    fn roundtrip_segment_list_type_a() {
        let cp = SrPolicyCandidatePath {
            segment_lists: vec![SrPolicySegmentList {
                weight: Some(SrWeight {
                    flags: 0,
                    weight: 1,
                }),
                segments: vec![
                    SrSegment::TypeA {
                        flags: 0,
                        label: 16000,
                    },
                    SrSegment::TypeA {
                        flags: 0,
                        label: 16001,
                    },
                ],
            }],
            ..Default::default()
        };
        let tlvs = vec![sr_policy_tlv(cp)];
        let encoded = encode(&tlvs);
        let decoded = decode(&encoded);
        assert_eq!(decoded, tlvs);
    }

    #[test]
    fn roundtrip_segment_list_type_b_no_behavior() {
        let cp = SrPolicyCandidatePath {
            segment_lists: vec![SrPolicySegmentList {
                weight: None,
                segments: vec![SrSegment::TypeB {
                    flags: 0,
                    sid: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 3),
                    endpoint_behavior: None,
                }],
            }],
            ..Default::default()
        };
        let tlvs = vec![sr_policy_tlv(cp)];
        let encoded = encode(&tlvs);
        let decoded = decode(&encoded);
        assert_eq!(decoded, tlvs);
    }

    #[test]
    fn roundtrip_segment_list_type_b_with_behavior() {
        let cp = SrPolicyCandidatePath {
            segment_lists: vec![SrPolicySegmentList {
                weight: None,
                segments: vec![SrSegment::TypeB {
                    // A-flag (0x40) = endpoint_behavior present
                    flags: 0x40,
                    sid: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 4),
                    endpoint_behavior: Some(SRv6EndpointBehavior {
                        behavior: 0x0001, // End
                        block_len: 32,
                        node_len: 16,
                        func_len: 16,
                        arg_len: 0,
                    }),
                }],
            }],
            ..Default::default()
        };
        let tlvs = vec![sr_policy_tlv(cp)];
        let encoded = encode(&tlvs);
        let decoded = decode(&encoded);
        assert_eq!(decoded, tlvs);
    }

    #[test]
    fn roundtrip_candidate_path_name() {
        let cp = SrPolicyCandidatePath {
            candidate_path_name: Some("test-path".to_string()),
            policy_name: Some("my-policy".to_string()),
            ..Default::default()
        };
        let tlvs = vec![sr_policy_tlv(cp)];
        let encoded = encode(&tlvs);
        let decoded = decode(&encoded);
        assert_eq!(decoded, tlvs);
    }

    #[test]
    fn roundtrip_unknown_tunnel_type() {
        let tlvs = vec![TunnelEncapTlv {
            tunnel_type: 99,
            value: TunnelEncapValue::Unknown(vec![0x01, 0x02, 0x03]),
        }];
        let encoded = encode(&tlvs);
        let decoded = decode(&encoded);
        assert_eq!(decoded, tlvs);
    }

    #[test]
    fn roundtrip_full_candidate_path() {
        let cp = SrPolicyCandidatePath {
            preference: Some(SrPolicyPreference {
                flags: 0,
                preference: 200,
            }),
            binding_sid: Some(SrPolicyBindingSid::Mpls {
                flags: 0,
                label: 2000,
            }),
            priority: Some(5),
            segment_lists: vec![SrPolicySegmentList {
                weight: Some(SrWeight {
                    flags: 0,
                    weight: 1,
                }),
                segments: vec![
                    SrSegment::TypeA {
                        flags: 0,
                        label: 16100,
                    },
                    SrSegment::TypeA {
                        flags: 0,
                        label: 16200,
                    },
                ],
            }],
            candidate_path_name: Some("cp1".to_string()),
            ..Default::default()
        };
        let tlvs = vec![sr_policy_tlv(cp)];
        let encoded = encode(&tlvs);
        let decoded = decode(&encoded);
        assert_eq!(decoded, tlvs);
    }
}
