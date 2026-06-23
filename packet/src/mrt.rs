// Copyright (C) 2022 The RustyBGP Authors.
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

use byteorder::{NetworkEndian, WriteBytesExt};
use bytes::{BufMut, BytesMut};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::SystemTime;
use tokio_util::codec::{Decoder, Encoder};

use crate::bgp;
use crate::error::Error;

struct Header {
    timestamp: u32,
    code: u16,
    subtype: u16,
    len: u32,
}

impl Header {
    const SUBTYPE_AS4: u16 = 4;
    const SUBTYPE_AS4_ADDPATH: u16 = 8;

    fn encode(&self, dst: &mut BytesMut) -> Result<(), Error> {
        dst.put_u32(self.timestamp);
        dst.put_u16(self.code);
        dst.put_u16(self.subtype);
        dst.put_u32(self.len);
        Ok(())
    }
}

#[derive(Clone)]
pub struct MpHeader {
    remote_asn: u32,
    local_asn: u32,
    interface_idx: u16,
    remote_addr: IpAddr,
    local_addr: IpAddr,
    is_asn4: bool,
}

impl MpHeader {
    pub fn new(
        remote_asn: u32,
        local_asn: u32,
        interface_idx: u16,
        remote_addr: IpAddr,
        local_addr: IpAddr,
        is_asn4: bool,
    ) -> Self {
        MpHeader {
            remote_asn,
            local_asn,
            interface_idx,
            remote_addr,
            local_addr,
            is_asn4,
        }
    }

    fn encode(&self, c: &mut BytesMut) -> Result<(), Error> {
        if self.is_asn4 {
            c.put_u32(self.remote_asn);
            c.put_u32(self.local_asn);
        } else {
            c.put_u16(self.remote_asn as u16);
            c.put_u16(self.local_asn as u16);
        }
        c.put_u16(self.interface_idx);
        match self.remote_addr {
            IpAddr::V4(addr) => {
                c.put_u16(bgp::Family::IPV4.afi());
                c.put_slice(&addr.octets());
                if let IpAddr::V4(local) = self.local_addr {
                    c.put_slice(&local.octets());
                }
            }
            IpAddr::V6(addr) => {
                c.put_u16(bgp::Family::IPV6.afi());
                c.put_slice(&addr.octets());
                if let IpAddr::V6(local) = self.local_addr {
                    c.put_slice(&local.octets());
                }
            }
        }
        Ok(())
    }
}

#[allow(dead_code)]
pub enum Message {
    Mp {
        header: MpHeader,
        body: bgp::Message,
        addpath: bool,
    },
}

pub struct MrtCodec {
    codec: bgp::PeerCodec,
}

impl Default for MrtCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl MrtCodec {
    pub fn new() -> Self {
        MrtCodec {
            codec: bgp::PeerCodec::new(),
        }
    }
}

impl Encoder<&Message> for MrtCodec {
    type Error = Error;

    fn encode(&mut self, item: &Message, dst: &mut BytesMut) -> Result<(), Error> {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        match item {
            Message::Mp {
                header,
                body,
                addpath,
            } => {
                let family = match body {
                    bgp::Message::Update(bgp::Update::Reach { family, .. }) => Some(*family),
                    bgp::Message::Update(bgp::Update::Unreach { family, .. }) => Some(*family),
                    bgp::Message::Update(bgp::Update::EndOfRib(family)) => Some(*family),
                    _ => None,
                };
                if let Some(family) = family {
                    self.codec.set_family(
                        family,
                        bgp::FamilyState {
                            addpath_tx: *addpath,
                            ..Default::default()
                        },
                    );
                }
                let subtype = if *addpath {
                    Header::SUBTYPE_AS4_ADDPATH
                } else {
                    Header::SUBTYPE_AS4
                };

                let h = Header {
                    timestamp,
                    code: 16,
                    subtype,
                    len: 0,
                };
                h.encode(dst).unwrap();
                let pos = dst.len();

                header.encode(dst).unwrap();
                let mut buf = bytes::BytesMut::with_capacity(4096);
                self.codec.encode_to(body, &mut buf).unwrap();
                dst.put_slice(buf.as_ref());
                let len = dst.len() - pos;
                (&mut dst.as_mut()[(pos - 4)..])
                    .write_u32::<NetworkEndian>(len as u32)
                    .unwrap();
            }
        }
        Ok(())
    }
}

impl Decoder for MrtCodec {
    type Item = Message;
    type Error = Error;

    fn decode(&mut self, _src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        Ok(None)
    }
}

// --- TABLE_DUMP_V2 (RFC 6396) encoder ---

const TABLE_DUMP_V2: u16 = 13;
const SUBTYPE_PEER_INDEX_TABLE: u16 = 1;
const SUBTYPE_RIB_IPV4_UNICAST: u16 = 2;
const SUBTYPE_RIB_IPV6_UNICAST: u16 = 4;

pub struct PeerEntry {
    pub bgp_id: Ipv4Addr,
    pub addr: IpAddr,
    pub asn: u32,
}

pub struct RibEntry {
    pub peer_index: u16,
    pub originated: u32,
    pub nexthop: Option<bgp::Nexthop>,
    pub attrs: Arc<Vec<bgp::Attribute>>,
}

pub enum TableDumpRecord {
    PeerIndexTable {
        router_id: Ipv4Addr,
        peers: Vec<PeerEntry>,
    },
    RibIpv4Unicast {
        seq: u32,
        prefix: bgp::Nlri,
        entries: Vec<RibEntry>,
    },
    RibIpv6Unicast {
        seq: u32,
        prefix: bgp::Nlri,
        entries: Vec<RibEntry>,
    },
}

/// Encode one MRT TABLE_DUMP_V2 record into `dst`.
///
/// `timestamp` is the Unix seconds value written into the 4-byte MRT header
/// field. Callers pass `SystemTime::now()` in production; tests pass a fixed
/// value so the output is deterministic.
pub fn encode_table_dump(
    timestamp: u32,
    record: &TableDumpRecord,
    dst: &mut BytesMut,
) -> Result<(), Error> {
    match record {
        TableDumpRecord::PeerIndexTable { router_id, peers } => {
            write_mrt_record(
                dst,
                timestamp,
                TABLE_DUMP_V2,
                SUBTYPE_PEER_INDEX_TABLE,
                |dst| {
                    dst.put_slice(&router_id.octets());
                    dst.put_u16(0); // view name length = 0
                    dst.put_u16(peers.len() as u16);
                    for peer in peers {
                        // type byte: bit 0 = IPv6 address; bit 1 = 4-octet AS
                        let type_byte: u8 = match peer.addr {
                            IpAddr::V4(_) => 0x02,
                            IpAddr::V6(_) => 0x03,
                        };
                        dst.put_u8(type_byte);
                        dst.put_slice(&peer.bgp_id.octets());
                        match peer.addr {
                            IpAddr::V4(a) => dst.put_slice(&a.octets()),
                            IpAddr::V6(a) => dst.put_slice(&a.octets()),
                        }
                        dst.put_u32(peer.asn);
                    }
                },
            );
        }
        TableDumpRecord::RibIpv4Unicast {
            seq,
            prefix,
            entries,
        } => {
            write_mrt_record(
                dst,
                timestamp,
                TABLE_DUMP_V2,
                SUBTYPE_RIB_IPV4_UNICAST,
                |dst| {
                    dst.put_u32(*seq);
                    // IPv4 unicast: no AFI/SAFI prefix (implied by subtype)
                    prefix.encode(dst).unwrap();
                    write_rib_entries(dst, entries, false);
                },
            );
        }
        TableDumpRecord::RibIpv6Unicast {
            seq,
            prefix,
            entries,
        } => {
            write_mrt_record(
                dst,
                timestamp,
                TABLE_DUMP_V2,
                SUBTYPE_RIB_IPV6_UNICAST,
                |dst| {
                    dst.put_u32(*seq);
                    // RFC 6396 §4.3.2: AFI/SAFI are implicit from the subtype; omit them.
                    prefix.encode(dst).unwrap();
                    write_rib_entries(dst, entries, true);
                },
            );
        }
    }
    Ok(())
}

/// Write a complete MRT record: 12-byte header + body produced by `body_fn`.
fn write_mrt_record(
    dst: &mut BytesMut,
    timestamp: u32,
    code: u16,
    subtype: u16,
    body_fn: impl FnOnce(&mut BytesMut),
) {
    dst.put_u32(timestamp);
    dst.put_u16(code);
    dst.put_u16(subtype);
    let len_offset = dst.len();
    dst.put_u32(0); // length placeholder
    let body_start = dst.len();
    body_fn(dst);
    let body_len = (dst.len() - body_start) as u32;
    (&mut dst.as_mut()[len_offset..len_offset + 4])
        .write_u32::<NetworkEndian>(body_len)
        .unwrap();
}

/// Write the entry-count field followed by all RIB entries.
fn write_rib_entries(dst: &mut BytesMut, entries: &[RibEntry], ipv6: bool) {
    dst.put_u16(entries.len() as u16);
    for entry in entries {
        dst.put_u16(entry.peer_index);
        dst.put_u32(entry.originated);
        let attr_len_offset = dst.len();
        dst.put_u16(0); // attribute length placeholder
        let attr_start = dst.len();
        for attr in entry.attrs.iter() {
            attr.encode_wire(dst);
        }
        if let Some(nh) = &entry.nexthop {
            if ipv6 {
                encode_mrt_mp_reach_ipv6(nh, dst);
            } else {
                encode_nexthop_attr(nh, dst);
            }
        }
        let attr_len = (dst.len() - attr_start) as u16;
        (&mut dst.as_mut()[attr_len_offset..attr_len_offset + 2])
            .write_u16::<NetworkEndian>(attr_len)
            .unwrap();
    }
}

/// Encode a BGP NEXT_HOP attribute (type 3) for an IPv4 RIB entry.
fn encode_nexthop_attr(nexthop: &bgp::Nexthop, dst: &mut BytesMut) {
    let nh_bytes = nexthop.to_bytes();
    dst.put_u8(bgp::Attribute::FLAG_TRANSITIVE);
    dst.put_u8(bgp::Attribute::NEXTHOP);
    dst.put_u8(nh_bytes.len() as u8);
    dst.put_slice(&nh_bytes);
}

/// Encode MP_REACH_NLRI for an IPv6 RIB entry in MRT format (RFC 6396 §4.3.2):
/// only the nexthop is written; AFI/SAFI and NLRI are omitted.
fn encode_mrt_mp_reach_ipv6(nexthop: &bgp::Nexthop, dst: &mut BytesMut) {
    let nh_bytes = nexthop.to_bytes();
    // flags = optional, non-transitive (0x80); no extended-length since value <= 255
    dst.put_u8(bgp::Attribute::FLAG_OPTIONAL);
    dst.put_u8(bgp::Attribute::MP_REACH);
    dst.put_u8((1 + nh_bytes.len()) as u8); // nexthop_len field + nexthop bytes
    dst.put_u8(nh_bytes.len() as u8);
    dst.put_slice(&nh_bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;
    use std::str::FromStr;

    const FIXED_TS: u32 = 1_000_000_000;

    // PEER_INDEX_TABLE: collector=1.1.1.1, peer=[AS65001 10.0.0.1]
    const GOBGP_PEER_INDEX_TABLE: &[u8] = &[
        0x3b, 0x9a, 0xca, 0x00, 0x00, 0x0d, 0x00, 0x01, 0x00, 0x00, 0x00, 0x15, 0x01, 0x01, 0x01,
        0x01, 0x00, 0x00, 0x00, 0x01, 0x02, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x01, 0x00,
        0x00, 0xfd, 0xe9,
    ];

    // RIB_IPV4_UNICAST: seq=0, 10.0.0.0/24, ORIGIN=IGP AS_PATH=[65001] NEXTHOP=192.168.1.1
    const GOBGP_RIB_IPV4_UNICAST: &[u8] = &[
        0x3b, 0x9a, 0xca, 0x00, 0x00, 0x0d, 0x00, 0x02, 0x00, 0x00, 0x00, 0x26, 0x00, 0x00, 0x00,
        0x00, 0x18, 0x0a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x3b, 0x9a, 0xca, 0x00, 0x00, 0x14,
        0x40, 0x01, 0x01, 0x00, 0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xfd, 0xe9, 0x40, 0x03,
        0x04, 0xc0, 0xa8, 0x01, 0x01,
    ];

    // RIB_IPV6_UNICAST: seq=1, 2001:db8::/32, ORIGIN=IGP AS_PATH=[65001] nexthop=2001:db8::1
    const GOBGP_RIB_IPV6_UNICAST: &[u8] = &[
        0x3b, 0x9a, 0xca, 0x00, 0x00, 0x0d, 0x00, 0x04, 0x00, 0x00, 0x00, 0x37, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x02, 0x01, 0x20, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, 0x3b, 0x9a,
        0xca, 0x00, 0x00, 0x21, 0x40, 0x01, 0x01, 0x00, 0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00,
        0xfd, 0xe9, 0x80, 0x0e, 0x11, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];

    fn make_attrs_origin_aspath() -> Arc<Vec<bgp::Attribute>> {
        // AS_PATH binary: SEQ(0x02), count(1), AS65001(4 bytes big-endian)
        let as_path_bin = vec![0x02u8, 0x01, 0x00, 0x00, 0xfd, 0xe9];
        Arc::new(vec![
            bgp::Attribute::new_with_value(bgp::Attribute::ORIGIN, 0u32).unwrap(),
            bgp::Attribute::new_with_bin(bgp::Attribute::AS_PATH, as_path_bin).unwrap(),
        ])
    }

    #[test]
    fn table_dump_peer_index_table_matches_gobgp() {
        let mut buf = BytesMut::new();
        encode_table_dump(
            FIXED_TS,
            &TableDumpRecord::PeerIndexTable {
                router_id: Ipv4Addr::new(1, 1, 1, 1),
                peers: vec![PeerEntry {
                    bgp_id: Ipv4Addr::new(10, 0, 0, 1),
                    addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    asn: 65001,
                }],
            },
            &mut buf,
        )
        .unwrap();
        assert_eq!(&buf[..], GOBGP_PEER_INDEX_TABLE);
    }

    #[test]
    fn table_dump_rib_ipv4_unicast_matches_gobgp() {
        let prefix: bgp::Nlri = "10.0.0.0/24".parse().unwrap();
        let mut buf = BytesMut::new();
        encode_table_dump(
            FIXED_TS,
            &TableDumpRecord::RibIpv4Unicast {
                seq: 0,
                prefix,
                entries: vec![RibEntry {
                    peer_index: 0,
                    originated: FIXED_TS,
                    nexthop: Some(bgp::Nexthop::V4(Ipv4Addr::new(192, 168, 1, 1))),
                    attrs: make_attrs_origin_aspath(),
                }],
            },
            &mut buf,
        )
        .unwrap();
        assert_eq!(&buf[..], GOBGP_RIB_IPV4_UNICAST);
    }

    // GoBGP adds AFI/SAFI to RIB_IPV6_UNICAST body even though RFC 6396 §4.3.2
    // says they are implicit from the subtype.  Our encoder follows the RFC, so
    // this test is ignored rather than deleted to document the divergence.
    #[test]
    #[ignore = "GoBGP deviates from RFC 6396: adds AFI/SAFI to RIB_IPV6_UNICAST body"]
    fn table_dump_rib_ipv6_unicast_matches_gobgp() {
        let prefix: bgp::Nlri = "2001:db8::/32".parse().unwrap();
        let nexthop = bgp::Nexthop::V6(Ipv6Addr::from_str("2001:db8::1").unwrap());
        let mut buf = BytesMut::new();
        encode_table_dump(
            FIXED_TS,
            &TableDumpRecord::RibIpv6Unicast {
                seq: 1,
                prefix,
                entries: vec![RibEntry {
                    peer_index: 0,
                    originated: FIXED_TS,
                    nexthop: Some(nexthop),
                    attrs: make_attrs_origin_aspath(),
                }],
            },
            &mut buf,
        )
        .unwrap();
        assert_eq!(&buf[..], GOBGP_RIB_IPV6_UNICAST);
    }

    // RFC 6396 §4.3.2 compliant encoding: no AFI/SAFI in body (body len = 52 = 0x34).
    // GoBGP adds 3 extra bytes (AFI=2, SAFI=1) making its body 55 bytes.
    const RFC_RIB_IPV6_UNICAST: &[u8] = &[
        0x3b, 0x9a, 0xca, 0x00, 0x00, 0x0d, 0x00, 0x04, 0x00, 0x00, 0x00, 0x34, // header
        0x00, 0x00, 0x00, 0x01, // seq = 1
        0x20, 0x20, 0x01, 0x0d, 0xb8, // prefix_len=32, prefix=2001:db8::
        0x00, 0x01, // entry count = 1
        0x00, 0x00, // peer_index = 0
        0x3b, 0x9a, 0xca, 0x00, // originated = 1000000000
        0x00, 0x21, // attr_len = 33
        0x40, 0x01, 0x01, 0x00, // ORIGIN = IGP
        0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xfd, 0xe9, // AS_PATH = [65001]
        0x80, 0x0e, 0x11, // MP_REACH_NLRI: optional, type=14, len=17
        0x10, // nexthop_len = 16
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, // nexthop = 2001:db8::1
    ];

    #[test]
    fn table_dump_rib_ipv6_unicast_rfc_compliant() {
        let prefix: bgp::Nlri = "2001:db8::/32".parse().unwrap();
        let nexthop = bgp::Nexthop::V6(Ipv6Addr::from_str("2001:db8::1").unwrap());
        let mut buf = BytesMut::new();
        encode_table_dump(
            FIXED_TS,
            &TableDumpRecord::RibIpv6Unicast {
                seq: 1,
                prefix,
                entries: vec![RibEntry {
                    peer_index: 0,
                    originated: FIXED_TS,
                    nexthop: Some(nexthop),
                    attrs: make_attrs_origin_aspath(),
                }],
            },
            &mut buf,
        )
        .unwrap();
        assert_eq!(&buf[..], RFC_RIB_IPV6_UNICAST);
    }
}
