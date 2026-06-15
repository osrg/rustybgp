// Copyright (C) 2019-2024 The RustyBGP Authors.
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

use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use rustybgp_packet::{
    Family, IpNet, Nlri, bgp::Attribute, bgp::Capability, bgp::Ipv4Net, bgp::Ipv6Net, bgp_ls,
    flowspec, mup, prefix_sid, rd::RouteDistinguisher,
};

use regex::Regex;
use uuid::Uuid;

use crate::api;
use crate::config;
use crate::error::Error;

pub(crate) fn family_to_api(f: Family) -> api::Family {
    api::Family {
        afi: f.afi() as i32,
        safi: f.safi() as i32,
    }
}

fn ops_to_api(ops: &[flowspec::Op]) -> Vec<api::FlowSpecComponentItem> {
    ops.iter()
        .map(|op| api::FlowSpecComponentItem {
            op: op.bits as u32,
            value: op.value,
        })
        .collect()
}

fn flowspec_v4_to_rules(components: &[flowspec::FlowspecV4Component]) -> Vec<api::FlowSpecRule> {
    use flowspec::FlowspecV4Component as C;
    components
        .iter()
        .map(|c| {
            let rule = match c {
                C::DstPrefix(net) => api::flow_spec_rule::Rule::IpPrefix(api::FlowSpecIpPrefix {
                    r#type: 1,
                    prefix_len: net.mask as u32,
                    prefix: net.addr.to_string(),
                    offset: 0,
                }),
                C::SrcPrefix(net) => api::flow_spec_rule::Rule::IpPrefix(api::FlowSpecIpPrefix {
                    r#type: 2,
                    prefix_len: net.mask as u32,
                    prefix: net.addr.to_string(),
                    offset: 0,
                }),
                C::Protocol(ops) => api::flow_spec_rule::Rule::Component(api::FlowSpecComponent {
                    r#type: 3,
                    items: ops_to_api(ops),
                }),
                C::Port(ops) => api::flow_spec_rule::Rule::Component(api::FlowSpecComponent {
                    r#type: 4,
                    items: ops_to_api(ops),
                }),
                C::DstPort(ops) => api::flow_spec_rule::Rule::Component(api::FlowSpecComponent {
                    r#type: 5,
                    items: ops_to_api(ops),
                }),
                C::SrcPort(ops) => api::flow_spec_rule::Rule::Component(api::FlowSpecComponent {
                    r#type: 6,
                    items: ops_to_api(ops),
                }),
                C::IcmpType(ops) => api::flow_spec_rule::Rule::Component(api::FlowSpecComponent {
                    r#type: 7,
                    items: ops_to_api(ops),
                }),
                C::IcmpCode(ops) => api::flow_spec_rule::Rule::Component(api::FlowSpecComponent {
                    r#type: 8,
                    items: ops_to_api(ops),
                }),
                C::TcpFlags(ops) => api::flow_spec_rule::Rule::Component(api::FlowSpecComponent {
                    r#type: 9,
                    items: ops_to_api(ops),
                }),
                C::PacketLen(ops) => api::flow_spec_rule::Rule::Component(api::FlowSpecComponent {
                    r#type: 10,
                    items: ops_to_api(ops),
                }),
                C::Dscp(ops) => api::flow_spec_rule::Rule::Component(api::FlowSpecComponent {
                    r#type: 11,
                    items: ops_to_api(ops),
                }),
                C::Fragment(ops) => api::flow_spec_rule::Rule::Component(api::FlowSpecComponent {
                    r#type: 12,
                    items: ops_to_api(ops),
                }),
            };
            api::FlowSpecRule { rule: Some(rule) }
        })
        .collect()
}

fn flowspec_v6_to_rules(components: &[flowspec::FlowspecV6Component]) -> Vec<api::FlowSpecRule> {
    use flowspec::FlowspecV6Component as C;
    components
        .iter()
        .map(|c| {
            let rule = match c {
                C::DstPrefix { prefix, offset } => {
                    api::flow_spec_rule::Rule::IpPrefix(api::FlowSpecIpPrefix {
                        r#type: 1,
                        prefix_len: prefix.mask as u32,
                        prefix: prefix.addr.to_string(),
                        offset: *offset as u32,
                    })
                }
                C::SrcPrefix { prefix, offset } => {
                    api::flow_spec_rule::Rule::IpPrefix(api::FlowSpecIpPrefix {
                        r#type: 2,
                        prefix_len: prefix.mask as u32,
                        prefix: prefix.addr.to_string(),
                        offset: *offset as u32,
                    })
                }
                C::NextHeader(ops) => {
                    api::flow_spec_rule::Rule::Component(api::FlowSpecComponent {
                        r#type: 3,
                        items: ops_to_api(ops),
                    })
                }
                C::Port(ops) => api::flow_spec_rule::Rule::Component(api::FlowSpecComponent {
                    r#type: 4,
                    items: ops_to_api(ops),
                }),
                C::DstPort(ops) => api::flow_spec_rule::Rule::Component(api::FlowSpecComponent {
                    r#type: 5,
                    items: ops_to_api(ops),
                }),
                C::SrcPort(ops) => api::flow_spec_rule::Rule::Component(api::FlowSpecComponent {
                    r#type: 6,
                    items: ops_to_api(ops),
                }),
                C::IcmpType(ops) => api::flow_spec_rule::Rule::Component(api::FlowSpecComponent {
                    r#type: 7,
                    items: ops_to_api(ops),
                }),
                C::IcmpCode(ops) => api::flow_spec_rule::Rule::Component(api::FlowSpecComponent {
                    r#type: 8,
                    items: ops_to_api(ops),
                }),
                C::TcpFlags(ops) => api::flow_spec_rule::Rule::Component(api::FlowSpecComponent {
                    r#type: 9,
                    items: ops_to_api(ops),
                }),
                C::PacketLen(ops) => api::flow_spec_rule::Rule::Component(api::FlowSpecComponent {
                    r#type: 10,
                    items: ops_to_api(ops),
                }),
                C::Dscp(ops) => api::flow_spec_rule::Rule::Component(api::FlowSpecComponent {
                    r#type: 11,
                    items: ops_to_api(ops),
                }),
                C::Fragment(ops) => api::flow_spec_rule::Rule::Component(api::FlowSpecComponent {
                    r#type: 12,
                    items: ops_to_api(ops),
                }),
                C::FlowLabel(ops) => api::flow_spec_rule::Rule::Component(api::FlowSpecComponent {
                    r#type: 13,
                    items: ops_to_api(ops),
                }),
            };
            api::FlowSpecRule { rule: Some(rule) }
        })
        .collect()
}

pub(crate) fn nlri_to_api(f: &Nlri) -> api::Nlri {
    match f {
        Nlri::V4(n) => api::Nlri {
            nlri: Some(api::nlri::Nlri::Prefix(api::IpAddressPrefix {
                prefix: n.addr.to_string(),
                prefix_len: n.mask as u32,
            })),
        },
        Nlri::V6(n) => api::Nlri {
            nlri: Some(api::nlri::Nlri::Prefix(api::IpAddressPrefix {
                prefix: n.addr.to_string(),
                prefix_len: n.mask as u32,
            })),
        },
        Nlri::Mup(m) => api::Nlri {
            nlri: Some(mup_nlri_to_api(m)),
        },
        Nlri::VpnV4(n) => api::Nlri {
            nlri: Some(api::nlri::Nlri::LabeledVpnIpPrefix(
                api::LabeledVpnipAddressPrefix {
                    labels: n.labels.labels().iter().map(|l| l.value()).collect(),
                    rd: Some(rd_to_api(&n.rd)),
                    prefix_len: n.prefix.mask as u32,
                    prefix: n.prefix.addr.to_string(),
                },
            )),
        },
        Nlri::VpnV6(n) => api::Nlri {
            nlri: Some(api::nlri::Nlri::LabeledVpnIpPrefix(
                api::LabeledVpnipAddressPrefix {
                    labels: n.labels.labels().iter().map(|l| l.value()).collect(),
                    rd: Some(rd_to_api(&n.rd)),
                    prefix_len: n.prefix.mask as u32,
                    prefix: n.prefix.addr.to_string(),
                },
            )),
        },
        Nlri::LabeledV4(n) => api::Nlri {
            nlri: Some(api::nlri::Nlri::LabeledPrefix(
                api::LabeledIpAddressPrefix {
                    labels: n.labels.labels().iter().map(|l| l.value()).collect(),
                    prefix_len: n.prefix.mask as u32,
                    prefix: n.prefix.addr.to_string(),
                },
            )),
        },
        Nlri::LabeledV6(n) => api::Nlri {
            nlri: Some(api::nlri::Nlri::LabeledPrefix(
                api::LabeledIpAddressPrefix {
                    labels: n.labels.labels().iter().map(|l| l.value()).collect(),
                    prefix_len: n.prefix.mask as u32,
                    prefix: n.prefix.addr.to_string(),
                },
            )),
        },
        Nlri::FlowspecV4(n) => api::Nlri {
            nlri: Some(api::nlri::Nlri::FlowSpec(api::FlowSpecNlri {
                rules: flowspec_v4_to_rules(&n.components),
            })),
        },
        Nlri::FlowspecV6(n) => api::Nlri {
            nlri: Some(api::nlri::Nlri::FlowSpec(api::FlowSpecNlri {
                rules: flowspec_v6_to_rules(&n.components),
            })),
        },
        Nlri::FlowspecVpnV4(n) => api::Nlri {
            nlri: Some(api::nlri::Nlri::VpnFlowSpec(api::VpnFlowSpecNlri {
                rd: Some(rd_to_api(&n.rd)),
                rules: flowspec_v4_to_rules(&n.components),
            })),
        },
        Nlri::FlowspecVpnV6(n) => api::Nlri {
            nlri: Some(api::nlri::Nlri::VpnFlowSpec(api::VpnFlowSpecNlri {
                rd: Some(rd_to_api(&n.rd)),
                rules: flowspec_v6_to_rules(&n.components),
            })),
        },
        Nlri::Ls(n) => api::Nlri {
            nlri: Some(api::nlri::Nlri::LsAddrPrefix(ls_nlri_to_api(n))),
        },
    }
}

fn mup_nlri_to_api(m: &mup::MupNlri) -> api::nlri::Nlri {
    match m {
        mup::MupNlri::InterworkSegmentDiscovery(r) => {
            api::nlri::Nlri::MupInterworkSegmentDiscovery(api::MupInterworkSegmentDiscoveryRoute {
                rd: Some(rd_to_api(&r.rd)),
                prefix: format!("{}/{}", r.prefix_addr, r.prefix_len),
            })
        }
        mup::MupNlri::DirectSegmentDiscovery(r) => {
            api::nlri::Nlri::MupDirectSegmentDiscovery(api::MupDirectSegmentDiscoveryRoute {
                rd: Some(rd_to_api(&r.rd)),
                address: r.address.to_string(),
            })
        }
        mup::MupNlri::Type1SessionTransformed(r) => {
            let ea_len = match r.endpoint_address {
                std::net::IpAddr::V4(_) => 32,
                std::net::IpAddr::V6(_) => 128,
            };
            let (sa_len, sa_str) = match r.source_address {
                None => (0u32, String::new()),
                Some(std::net::IpAddr::V4(a)) => (32, a.to_string()),
                Some(std::net::IpAddr::V6(a)) => (128, a.to_string()),
            };
            #[allow(deprecated)]
            api::nlri::Nlri::MupType1SessionTransformed(api::MupType1SessionTransformedRoute {
                rd: Some(rd_to_api(&r.rd)),
                prefix_length: 0,
                prefix: format!("{}/{}", r.prefix_addr, r.prefix_len),
                teid: r.teid,
                qfi: r.qfi as u32,
                endpoint_address_length: ea_len,
                endpoint_address: r.endpoint_address.to_string(),
                source_address_length: sa_len,
                source_address: sa_str,
            })
        }
        mup::MupNlri::Type2SessionTransformed(r) => {
            api::nlri::Nlri::MupType2SessionTransformed(api::MupType2SessionTransformedRoute {
                rd: Some(rd_to_api(&r.rd)),
                endpoint_address_length: r.endpoint_address_length as u32,
                endpoint_address: r.endpoint_address.to_string(),
                teid: r.teid,
            })
        }
    }
}

fn node_desc_to_api(nd: &bgp_ls::NodeDescriptor) -> api::LsNodeDescriptor {
    api::LsNodeDescriptor {
        asn: nd.asn.unwrap_or(0),
        bgp_ls_id: nd.bgp_ls_id.unwrap_or(0),
        ospf_area_id: nd.ospf_area_id.unwrap_or(0),
        pseudonode: nd.igp_router_id.as_ref().is_some_and(|r| r.len() == 7),
        igp_router_id: nd
            .igp_router_id
            .as_ref()
            .map_or(String::new(), |r| bgp_ls::format_igp_router_id(r)),
        bgp_router_id: nd
            .bgp_router_id
            .map_or(String::new(), |r| Ipv4Addr::from(r).to_string()),
        bgp_confederation_member: nd.bgp_confederation_member.unwrap_or(0),
    }
}

fn link_desc_to_api(ld: &[bgp_ls::LinkDescTlv]) -> api::LsLinkDescriptor {
    let mut link_local_id = 0u32;
    let mut link_remote_id = 0u32;
    let mut interface_addr_ipv4 = String::new();
    let mut neighbor_addr_ipv4 = String::new();
    let mut interface_addr_ipv6 = String::new();
    let mut neighbor_addr_ipv6 = String::new();
    for tlv in ld {
        match tlv {
            bgp_ls::LinkDescTlv::LinkId { local, remote } => {
                link_local_id = *local;
                link_remote_id = *remote;
            }
            bgp_ls::LinkDescTlv::Ipv4InterfaceAddr(a) => {
                interface_addr_ipv4 = Ipv4Addr::from(*a).to_string();
            }
            bgp_ls::LinkDescTlv::Ipv4NeighborAddr(a) => {
                neighbor_addr_ipv4 = Ipv4Addr::from(*a).to_string();
            }
            bgp_ls::LinkDescTlv::Ipv6InterfaceAddr(a) => {
                interface_addr_ipv6 = Ipv6Addr::from(*a).to_string();
            }
            bgp_ls::LinkDescTlv::Ipv6NeighborAddr(a) => {
                neighbor_addr_ipv6 = Ipv6Addr::from(*a).to_string();
            }
            _ => {}
        }
    }
    api::LsLinkDescriptor {
        link_local_id,
        link_remote_id,
        interface_addr_ipv4,
        neighbor_addr_ipv4,
        interface_addr_ipv6,
        neighbor_addr_ipv6,
    }
}

fn prefix_desc_to_api(pd: &[bgp_ls::PrefixDescTlv], is_ipv6: bool) -> api::LsPrefixDescriptor {
    let mut ip_reachability = Vec::new();
    let mut ospf_route_type = 0i32;
    for tlv in pd {
        match tlv {
            bgp_ls::PrefixDescTlv::IpReachability { prefix_len, addr } => {
                let addr_str = if is_ipv6 {
                    let mut bytes = [0u8; 16];
                    let n = addr.len().min(16);
                    bytes[..n].copy_from_slice(&addr[..n]);
                    Ipv6Addr::from(bytes).to_string()
                } else {
                    let mut bytes = [0u8; 4];
                    let n = addr.len().min(4);
                    bytes[..n].copy_from_slice(&addr[..n]);
                    Ipv4Addr::from(bytes).to_string()
                };
                ip_reachability.push(format!("{}/{}", addr_str, prefix_len));
            }
            bgp_ls::PrefixDescTlv::OspfRouteType(t) => {
                ospf_route_type = *t as i32;
            }
            _ => {}
        }
    }
    api::LsPrefixDescriptor {
        ip_reachability,
        ospf_route_type,
    }
}

fn ls_nlri_to_api(n: &bgp_ls::BgpLsNlri) -> api::LsAddrPrefix {
    use api::ls_addr_prefix::LsNlri;
    use api::ls_addr_prefix::ls_nlri::Nlri as LsNlriOneof;
    let (nlri_type, protocol_id, identifier, nlri) = match n {
        bgp_ls::BgpLsNlri::Node(n) => (
            api::LsNlriType::Node as i32,
            n.protocol_id as i32,
            n.identifier,
            Some(LsNlri {
                nlri: Some(LsNlriOneof::Node(api::LsNodeNlri {
                    local_node: Some(node_desc_to_api(&n.local_node)),
                })),
            }),
        ),
        bgp_ls::BgpLsNlri::Link(n) => (
            api::LsNlriType::Link as i32,
            n.protocol_id as i32,
            n.identifier,
            Some(LsNlri {
                nlri: Some(LsNlriOneof::Link(api::LsLinkNlri {
                    local_node: Some(node_desc_to_api(&n.local_node)),
                    remote_node: Some(node_desc_to_api(&n.remote_node)),
                    link_descriptor: Some(link_desc_to_api(&n.link_desc)),
                })),
            }),
        ),
        bgp_ls::BgpLsNlri::PrefixV4(n) => (
            api::LsNlriType::PrefixV4 as i32,
            n.protocol_id as i32,
            n.identifier,
            Some(LsNlri {
                nlri: Some(LsNlriOneof::PrefixV4(api::LsPrefixV4nlri {
                    local_node: Some(node_desc_to_api(&n.local_node)),
                    prefix_descriptor: Some(prefix_desc_to_api(&n.prefix_desc, false)),
                })),
            }),
        ),
        bgp_ls::BgpLsNlri::PrefixV6(n) => (
            api::LsNlriType::PrefixV6 as i32,
            n.protocol_id as i32,
            n.identifier,
            Some(LsNlri {
                nlri: Some(LsNlriOneof::PrefixV6(api::LsPrefixV6nlri {
                    local_node: Some(node_desc_to_api(&n.local_node)),
                    prefix_descriptor: Some(prefix_desc_to_api(&n.prefix_desc, true)),
                })),
            }),
        ),
        bgp_ls::BgpLsNlri::Unknown { .. } => (api::LsNlriType::Unspecified as i32, 0, 0, None),
    };
    api::LsAddrPrefix {
        r#type: nlri_type,
        nlri,
        length: 0,
        protocol_id,
        identifier,
    }
}

fn node_desc_from_api(nd: &api::LsNodeDescriptor) -> Result<bgp_ls::NodeDescriptor, Error> {
    let igp_router_id = if nd.igp_router_id.is_empty() {
        None
    } else {
        Some(parse_igp_router_id(&nd.igp_router_id)?)
    };
    let bgp_router_id = if nd.bgp_router_id.is_empty() {
        None
    } else {
        let addr: Ipv4Addr = nd
            .bgp_router_id
            .parse()
            .map_err(|e| Error::InvalidArgument(format!("invalid bgp_router_id: {}", e)))?;
        Some(addr.octets())
    };
    Ok(bgp_ls::NodeDescriptor {
        asn: if nd.asn == 0 { None } else { Some(nd.asn) },
        bgp_ls_id: if nd.bgp_ls_id == 0 {
            None
        } else {
            Some(nd.bgp_ls_id)
        },
        ospf_area_id: if nd.ospf_area_id == 0 {
            None
        } else {
            Some(nd.ospf_area_id)
        },
        igp_router_id,
        bgp_router_id,
        bgp_confederation_member: if nd.bgp_confederation_member == 0 {
            None
        } else {
            Some(nd.bgp_confederation_member)
        },
    })
}

fn parse_igp_router_id(s: &str) -> Result<Vec<u8>, Error> {
    if let Ok(addr) = s.parse::<Ipv4Addr>() {
        return Ok(addr.octets().to_vec());
    }
    // IS-IS system ID: "xxxx.xxxx.xxxx" (6 bytes) or "xxxx.xxxx.xxxx.xx" (7 bytes)
    let parts: Vec<&str> = s.split('.').collect();
    match parts.len() {
        3 => {
            let mut bytes = Vec::with_capacity(6);
            for part in &parts {
                if part.len() != 4 {
                    return Err(Error::InvalidArgument(format!(
                        "invalid igp_router_id: {}",
                        s
                    )));
                }
                let val = u16::from_str_radix(part, 16)
                    .map_err(|_| Error::InvalidArgument(format!("invalid igp_router_id: {}", s)))?;
                bytes.extend_from_slice(&val.to_be_bytes());
            }
            Ok(bytes)
        }
        4 => {
            let mut bytes = Vec::with_capacity(7);
            for (i, part) in parts.iter().enumerate() {
                if i < 3 {
                    if part.len() != 4 {
                        return Err(Error::InvalidArgument(format!(
                            "invalid igp_router_id: {}",
                            s
                        )));
                    }
                    let val = u16::from_str_radix(part, 16).map_err(|_| {
                        Error::InvalidArgument(format!("invalid igp_router_id: {}", s))
                    })?;
                    bytes.extend_from_slice(&val.to_be_bytes());
                } else {
                    if part.len() != 2 {
                        return Err(Error::InvalidArgument(format!(
                            "invalid igp_router_id: {}",
                            s
                        )));
                    }
                    let val = u8::from_str_radix(part, 16).map_err(|_| {
                        Error::InvalidArgument(format!("invalid igp_router_id: {}", s))
                    })?;
                    bytes.push(val);
                }
            }
            Ok(bytes)
        }
        _ => Err(Error::InvalidArgument(format!(
            "invalid igp_router_id: {}",
            s
        ))),
    }
}

fn link_desc_from_api(ld: &api::LsLinkDescriptor) -> Vec<bgp_ls::LinkDescTlv> {
    let mut tlvs = Vec::new();
    if ld.link_local_id != 0 || ld.link_remote_id != 0 {
        tlvs.push(bgp_ls::LinkDescTlv::LinkId {
            local: ld.link_local_id,
            remote: ld.link_remote_id,
        });
    }
    if !ld.interface_addr_ipv4.is_empty()
        && let Ok(addr) = ld.interface_addr_ipv4.parse::<Ipv4Addr>()
    {
        tlvs.push(bgp_ls::LinkDescTlv::Ipv4InterfaceAddr(addr.octets()));
    }
    if !ld.neighbor_addr_ipv4.is_empty()
        && let Ok(addr) = ld.neighbor_addr_ipv4.parse::<Ipv4Addr>()
    {
        tlvs.push(bgp_ls::LinkDescTlv::Ipv4NeighborAddr(addr.octets()));
    }
    if !ld.interface_addr_ipv6.is_empty()
        && let Ok(addr) = ld.interface_addr_ipv6.parse::<Ipv6Addr>()
    {
        tlvs.push(bgp_ls::LinkDescTlv::Ipv6InterfaceAddr(addr.octets()));
    }
    if !ld.neighbor_addr_ipv6.is_empty()
        && let Ok(addr) = ld.neighbor_addr_ipv6.parse::<Ipv6Addr>()
    {
        tlvs.push(bgp_ls::LinkDescTlv::Ipv6NeighborAddr(addr.octets()));
    }
    tlvs
}

fn prefix_desc_from_api(pd: &api::LsPrefixDescriptor, is_ipv6: bool) -> Vec<bgp_ls::PrefixDescTlv> {
    let mut tlvs = Vec::new();
    if pd.ospf_route_type != 0 {
        tlvs.push(bgp_ls::PrefixDescTlv::OspfRouteType(
            pd.ospf_route_type as u8,
        ));
    }
    for s in &pd.ip_reachability {
        let Some((addr_str, len_str)) = s.rsplit_once('/') else {
            continue;
        };
        let Ok(prefix_len) = len_str.parse::<u8>() else {
            continue;
        };
        let octets: Option<Vec<u8>> = if is_ipv6 {
            addr_str
                .parse::<Ipv6Addr>()
                .ok()
                .map(|a| a.octets().to_vec())
        } else {
            addr_str
                .parse::<Ipv4Addr>()
                .ok()
                .map(|a| a.octets().to_vec())
        };
        let Some(full_addr) = octets else {
            continue;
        };
        let byte_len = prefix_len.div_ceil(8) as usize;
        let addr = full_addr[..byte_len.min(full_addr.len())].to_vec();
        tlvs.push(bgp_ls::PrefixDescTlv::IpReachability { prefix_len, addr });
    }
    tlvs
}

fn ls_nlri_from_api(a: api::LsAddrPrefix) -> Result<Nlri, Error> {
    use api::ls_addr_prefix::ls_nlri::Nlri as LsNlriOneof;
    let protocol_id = a.protocol_id as u8;
    let identifier = a.identifier;
    let nlri_inner = a.nlri.and_then(|n| n.nlri);
    let bgp_ls_nlri =
        match nlri_inner {
            Some(LsNlriOneof::Node(n)) => {
                let local_node =
                    node_desc_from_api(n.local_node.as_ref().ok_or_else(|| {
                        Error::InvalidArgument("missing local_node".to_string())
                    })?)?;
                bgp_ls::BgpLsNlri::Node(bgp_ls::BgpLsNodeNlri {
                    protocol_id,
                    identifier,
                    local_node,
                })
            }
            Some(LsNlriOneof::Link(n)) => {
                let local_node =
                    node_desc_from_api(n.local_node.as_ref().ok_or_else(|| {
                        Error::InvalidArgument("missing local_node".to_string())
                    })?)?;
                let remote_node =
                    node_desc_from_api(n.remote_node.as_ref().ok_or_else(|| {
                        Error::InvalidArgument("missing remote_node".to_string())
                    })?)?;
                let link_desc = n
                    .link_descriptor
                    .as_ref()
                    .map(link_desc_from_api)
                    .unwrap_or_default();
                bgp_ls::BgpLsNlri::Link(bgp_ls::BgpLsLinkNlri {
                    protocol_id,
                    identifier,
                    local_node,
                    remote_node,
                    link_desc,
                })
            }
            Some(LsNlriOneof::PrefixV4(n)) => {
                let local_node =
                    node_desc_from_api(n.local_node.as_ref().ok_or_else(|| {
                        Error::InvalidArgument("missing local_node".to_string())
                    })?)?;
                let prefix_desc = n
                    .prefix_descriptor
                    .as_ref()
                    .map(|pd| prefix_desc_from_api(pd, false))
                    .unwrap_or_default();
                bgp_ls::BgpLsNlri::PrefixV4(bgp_ls::BgpLsPrefixNlri {
                    protocol_id,
                    identifier,
                    local_node,
                    prefix_desc,
                })
            }
            Some(LsNlriOneof::PrefixV6(n)) => {
                let local_node =
                    node_desc_from_api(n.local_node.as_ref().ok_or_else(|| {
                        Error::InvalidArgument("missing local_node".to_string())
                    })?)?;
                let prefix_desc = n
                    .prefix_descriptor
                    .as_ref()
                    .map(|pd| prefix_desc_from_api(pd, true))
                    .unwrap_or_default();
                bgp_ls::BgpLsNlri::PrefixV6(bgp_ls::BgpLsPrefixNlri {
                    protocol_id,
                    identifier,
                    local_node,
                    prefix_desc,
                })
            }
            _ => bgp_ls::BgpLsNlri::Unknown {
                nlri_type: a.r#type as u16,
                body: Vec::new(),
            },
        };
    Ok(Nlri::Ls(bgp_ls_nlri))
}

/// Convert an `api::RouteTarget` to its 8-byte wire representation.
///
/// Rejects any RT whose sub_type is not 0x02 (Route Target) to prevent
/// callers from silently injecting non-RT extended communities into VRFs.
pub(crate) fn rt_from_api(rt: &api::RouteTarget) -> Result<[u8; 8], Error> {
    use api::route_target::Rt;
    let mut buf = [0u8; 8];
    match rt
        .rt
        .as_ref()
        .ok_or_else(|| Error::InvalidArgument("missing route target".to_string()))?
    {
        Rt::TwoOctetAsSpecific(r) => {
            if r.sub_type != 2 {
                return Err(Error::InvalidArgument(format!(
                    "route target sub_type must be 2, got {}",
                    r.sub_type
                )));
            }
            if r.asn > u16::MAX as u32 {
                return Err(Error::InvalidArgument(format!(
                    "two-octet RT ASN out of range: {}",
                    r.asn
                )));
            }
            buf[0] = 0x00;
            buf[1] = 0x02;
            buf[2..4].copy_from_slice(&(r.asn as u16).to_be_bytes());
            buf[4..8].copy_from_slice(&r.local_admin.to_be_bytes());
        }
        Rt::Ipv4AddressSpecific(r) => {
            if r.sub_type != 2 {
                return Err(Error::InvalidArgument(format!(
                    "route target sub_type must be 2, got {}",
                    r.sub_type
                )));
            }
            if r.local_admin > u16::MAX as u32 {
                return Err(Error::InvalidArgument(format!(
                    "IPv4 RT local_admin out of range: {}",
                    r.local_admin
                )));
            }
            let addr: Ipv4Addr = r
                .address
                .parse()
                .map_err(|e| Error::InvalidArgument(format!("invalid RT IPv4 address: {e}")))?;
            buf[0] = 0x01;
            buf[1] = 0x02;
            buf[2..6].copy_from_slice(&addr.octets());
            buf[6..8].copy_from_slice(&(r.local_admin as u16).to_be_bytes());
        }
        Rt::FourOctetAsSpecific(r) => {
            if r.sub_type != 2 {
                return Err(Error::InvalidArgument(format!(
                    "route target sub_type must be 2, got {}",
                    r.sub_type
                )));
            }
            if r.local_admin > u16::MAX as u32 {
                return Err(Error::InvalidArgument(format!(
                    "four-octet RT local_admin out of range: {}",
                    r.local_admin
                )));
            }
            buf[0] = 0x02;
            buf[1] = 0x02;
            buf[2..6].copy_from_slice(&r.asn.to_be_bytes());
            buf[6..8].copy_from_slice(&(r.local_admin as u16).to_be_bytes());
        }
    }
    Ok(buf)
}

/// Convert an 8-byte RT wire value back to `api::RouteTarget`.
fn rt_to_api(rt: &[u8; 8]) -> api::RouteTarget {
    use api::route_target::Rt;
    let rt_val = match rt[0] {
        0x00 => Rt::TwoOctetAsSpecific(api::TwoOctetAsSpecificExtended {
            is_transitive: true,
            sub_type: rt[1] as u32,
            asn: u16::from_be_bytes([rt[2], rt[3]]) as u32,
            local_admin: u32::from_be_bytes([rt[4], rt[5], rt[6], rt[7]]),
        }),
        0x01 => Rt::Ipv4AddressSpecific(api::IPv4AddressSpecificExtended {
            is_transitive: true,
            sub_type: rt[1] as u32,
            address: Ipv4Addr::new(rt[2], rt[3], rt[4], rt[5]).to_string(),
            local_admin: u16::from_be_bytes([rt[6], rt[7]]) as u32,
        }),
        _ => Rt::FourOctetAsSpecific(api::FourOctetAsSpecificExtended {
            is_transitive: true,
            sub_type: rt[1] as u32,
            asn: u32::from_be_bytes([rt[2], rt[3], rt[4], rt[5]]),
            local_admin: u16::from_be_bytes([rt[6], rt[7]]) as u32,
        }),
    };
    api::RouteTarget { rt: Some(rt_val) }
}

pub(crate) fn vrf_to_api(vrf: &rustybgp_table::Vrf) -> api::Vrf {
    api::Vrf {
        name: vrf.name.clone(),
        rd: Some(rd_to_api(&vrf.rd)),
        import_rt: vrf.import_rt.iter().map(rt_to_api).collect(),
        export_rt: vrf.export_rt.iter().map(rt_to_api).collect(),
        id: vrf.id,
    }
}

fn rd_to_api(rd: &RouteDistinguisher) -> api::RouteDistinguisher {
    let v = match *rd {
        RouteDistinguisher::TwoOctetAs { admin, assigned } => {
            api::route_distinguisher::Rd::TwoOctetAsn(api::RouteDistinguisherTwoOctetAsn {
                admin: admin as u32,
                assigned,
            })
        }
        RouteDistinguisher::Ipv4 { admin, assigned } => {
            api::route_distinguisher::Rd::IpAddress(api::RouteDistinguisherIpAddress {
                admin: admin.to_string(),
                assigned: assigned as u32,
            })
        }
        RouteDistinguisher::FourOctetAs { admin, assigned } => {
            api::route_distinguisher::Rd::FourOctetAsn(api::RouteDistinguisherFourOctetAsn {
                admin,
                assigned: assigned as u32,
            })
        }
    };
    api::RouteDistinguisher { rd: Some(v) }
}

pub(crate) fn rd_from_api(rd: &api::RouteDistinguisher) -> Result<RouteDistinguisher, Error> {
    let inner = rd
        .rd
        .as_ref()
        .ok_or_else(|| Error::InvalidArgument("missing route distinguisher".to_string()))?;
    match inner {
        api::route_distinguisher::Rd::TwoOctetAsn(r) => {
            if r.admin > u16::MAX as u32 {
                return Err(Error::InvalidArgument(format!(
                    "two-octet RD admin out of range: {}",
                    r.admin
                )));
            }
            Ok(RouteDistinguisher::TwoOctetAs {
                admin: r.admin as u16,
                assigned: r.assigned,
            })
        }
        api::route_distinguisher::Rd::IpAddress(r) => {
            let admin = r
                .admin
                .parse::<Ipv4Addr>()
                .map_err(|e| Error::InvalidArgument(format!("invalid RD IPv4 admin: {}", e)))?;
            if r.assigned > u16::MAX as u32 {
                return Err(Error::InvalidArgument(format!(
                    "ipv4 RD assigned out of range: {}",
                    r.assigned
                )));
            }
            Ok(RouteDistinguisher::Ipv4 {
                admin,
                assigned: r.assigned as u16,
            })
        }
        api::route_distinguisher::Rd::FourOctetAsn(r) => {
            if r.assigned > u16::MAX as u32 {
                return Err(Error::InvalidArgument(format!(
                    "four-octet RD assigned out of range: {}",
                    r.assigned
                )));
            }
            Ok(RouteDistinguisher::FourOctetAs {
                admin: r.admin,
                assigned: r.assigned as u16,
            })
        }
    }
}

pub(crate) fn capability_to_api(cap: &Capability) -> api::Capability {
    match cap {
        Capability::MultiProtocol(family) => api::Capability {
            cap: Some(api::capability::Cap::MultiProtocol(
                api::MultiProtocolCapability {
                    family: Some(family_to_api(*family)),
                },
            )),
        },
        Capability::RouteRefresh => api::Capability {
            cap: Some(api::capability::Cap::RouteRefresh(
                api::RouteRefreshCapability {},
            )),
        },
        Capability::ExtendedMessage => api::Capability {
            cap: Some(api::capability::Cap::ExtendedMessage(
                api::ExtendedMessageCapability {},
            )),
        },
        Capability::ExtendedNexthop(v) => api::Capability {
            cap: Some(api::capability::Cap::ExtendedNexthop(
                api::ExtendedNexthopCapability {
                    tuples: v
                        .iter()
                        .map(|(family, afi)| api::ExtendedNexthopCapabilityTuple {
                            nlri_family: Some(family_to_api(*family)),
                            nexthop_family: Some(api::Family {
                                afi: *afi as i32,
                                safi: 1, // SAFI_UNICAST
                            }),
                        })
                        .collect(),
                },
            )),
        },
        Capability::GracefulRestart {
            flags,
            restart_time,
            families,
        } => api::Capability {
            cap: Some(api::capability::Cap::GracefulRestart(
                api::GracefulRestartCapability {
                    flags: *flags as u32,
                    time: *restart_time as u32,
                    tuples: families
                        .iter()
                        .map(|(family, flags)| api::GracefulRestartCapabilityTuple {
                            flags: *flags as u32,
                            family: Some(family_to_api(*family)),
                        })
                        .collect(),
                },
            )),
        },
        Capability::FourOctetAsNumber(asn) => api::Capability {
            cap: Some(api::capability::Cap::FourOctetAsn(
                api::FourOctetAsnCapability { asn: *asn },
            )),
        },
        Capability::AddPath(v) => api::Capability {
            cap: Some(api::capability::Cap::AddPath(api::AddPathCapability {
                tuples: v
                    .iter()
                    .map(|(family, mode)| api::AddPathCapabilityTuple {
                        family: Some(family_to_api(*family)),
                        mode: *mode as i32,
                    })
                    .collect(),
            })),
        },
        Capability::EnhancedRouteRefresh => api::Capability {
            cap: Some(api::capability::Cap::EnhancedRouteRefresh(
                api::EnhancedRouteRefreshCapability {},
            )),
        },
        Capability::LongLivedGracefulRestart(v) => api::Capability {
            cap: Some(api::capability::Cap::LongLivedGracefulRestart(
                api::LongLivedGracefulRestartCapability {
                    tuples: v
                        .iter()
                        .map(
                            |(family, flags, time)| api::LongLivedGracefulRestartCapabilityTuple {
                                family: Some(family_to_api(*family)),
                                flags: *flags as u32,
                                time: *time,
                            },
                        )
                        .collect(),
                },
            )),
        },
        Capability::Fqdn { hostname, domain } => api::Capability {
            cap: Some(api::capability::Cap::Fqdn(api::FqdnCapability {
                host_name: hostname.to_string(),
                domain_name: domain.to_string(),
            })),
        },
        Capability::Unknown { code, bin } => api::Capability {
            cap: Some(api::capability::Cap::Unknown(api::UnknownCapability {
                code: (*code as u32),
                value: bin.to_owned(),
            })),
        },
    }
}

pub(crate) fn attr_to_api(a: &Attribute) -> api::Attribute {
    match a.code() {
        Attribute::ORIGIN => api::Attribute {
            attr: Some(api::attribute::Attr::Origin(api::OriginAttribute {
                origin: a.value().unwrap(),
            })),
        },
        Attribute::AS_PATH => {
            let mut c = Cursor::new(a.binary().unwrap());
            let mut segments = Vec::new();
            while c.position() < c.get_ref().len() as u64 {
                let code = c.read_u8().unwrap();
                let n = c.read_u8().unwrap();
                let mut nums = Vec::new();
                for _ in 0..n {
                    nums.push(c.read_u32::<NetworkEndian>().unwrap());
                }
                segments.push(api::AsSegment {
                    r#type: code as i32,
                    numbers: nums,
                });
            }
            api::Attribute {
                attr: Some(api::attribute::Attr::AsPath(api::AsPathAttribute {
                    segments,
                })),
            }
        }
        Attribute::NEXTHOP => {
            let buf = a.binary().unwrap();
            let buflen = buf.len();
            let mut c = Cursor::new(buf);
            let next_hop = if buflen == 16 {
                Ipv6Addr::from(c.read_u128::<NetworkEndian>().unwrap()).to_string()
            } else {
                Ipv4Addr::from(c.read_u32::<NetworkEndian>().unwrap()).to_string()
            };
            api::Attribute {
                attr: Some(api::attribute::Attr::NextHop(api::NextHopAttribute {
                    next_hop,
                })),
            }
        }
        Attribute::MULTI_EXIT_DESC => api::Attribute {
            attr: Some(api::attribute::Attr::MultiExitDisc(
                api::MultiExitDiscAttribute {
                    med: a.value().unwrap(),
                },
            )),
        },
        Attribute::LOCAL_PREF => api::Attribute {
            attr: Some(api::attribute::Attr::LocalPref(api::LocalPrefAttribute {
                local_pref: a.value().unwrap(),
            })),
        },
        Attribute::ATOMIC_AGGREGATE => api::Attribute {
            attr: Some(api::attribute::Attr::AtomicAggregate(
                api::AtomicAggregateAttribute {},
            )),
        },
        Attribute::AGGREGATOR => {
            let mut c = Cursor::new(a.binary().unwrap());
            let (asn, addr) = match c.get_ref().len() {
                6 => (
                    c.read_u16::<NetworkEndian>().unwrap() as u32,
                    Ipv4Addr::from(c.read_u32::<NetworkEndian>().unwrap()),
                ),
                8 => (
                    c.read_u32::<NetworkEndian>().unwrap(),
                    Ipv4Addr::from(c.read_u32::<NetworkEndian>().unwrap()),
                ),
                _ => unreachable!("corrupted"),
            };
            api::Attribute {
                attr: Some(api::attribute::Attr::Aggregator(api::AggregatorAttribute {
                    asn,
                    address: addr.to_string(),
                })),
            }
        }
        Attribute::COMMUNITY => {
            let buf = a.binary().unwrap();
            let count = buf.len() / 4;
            let mut c = Cursor::new(buf);
            let mut values = Vec::with_capacity(count);
            for _ in 0..count {
                values.push(c.read_u32::<NetworkEndian>().unwrap());
            }
            api::Attribute {
                attr: Some(api::attribute::Attr::Communities(
                    api::CommunitiesAttribute {
                        communities: values,
                    },
                )),
            }
        }
        Attribute::ORIGINATOR_ID => api::Attribute {
            attr: Some(api::attribute::Attr::OriginatorId(
                api::OriginatorIdAttribute {
                    id: Ipv4Addr::from(a.value().unwrap()).to_string(),
                },
            )),
        },
        Attribute::CLUSTER_LIST => {
            let mut c = Cursor::new(a.binary().unwrap());
            let mut ids = Vec::new();
            for _ in 0..c.get_ref().len() / 4 {
                ids.push(Ipv4Addr::from(c.read_u32::<NetworkEndian>().unwrap()).to_string());
            }
            api::Attribute {
                attr: Some(api::attribute::Attr::ClusterList(
                    api::ClusterListAttribute { ids },
                )),
            }
        }
        Attribute::LARGE_COMMUNITY => {
            let mut c = Cursor::new(a.binary().unwrap());
            let mut v = Vec::new();
            for _ in 0..c.get_ref().len() / 12 {
                let global_admin = c.read_u32::<NetworkEndian>().unwrap();
                let local_data1 = c.read_u32::<NetworkEndian>().unwrap();
                let local_data2 = c.read_u32::<NetworkEndian>().unwrap();
                v.push(api::LargeCommunity {
                    global_admin,
                    local_data1,
                    local_data2,
                });
            }
            api::Attribute {
                attr: Some(api::attribute::Attr::LargeCommunities(
                    api::LargeCommunitiesAttribute { communities: v },
                )),
            }
        }
        Attribute::EXTENDED_COMMUNITY => {
            let mut c = Cursor::new(a.binary().unwrap());
            let count = c.get_ref().len() / 8;
            let mut communities = Vec::with_capacity(count);
            for _ in 0..count {
                communities.push(read_extcom(&mut c));
            }
            api::Attribute {
                attr: Some(api::attribute::Attr::ExtendedCommunities(
                    api::ExtendedCommunitiesAttribute { communities },
                )),
            }
        }
        Attribute::PREFIX_SID => match prefix_sid::PrefixSid::decode(a.binary().unwrap()) {
            Ok(sid) => api::Attribute {
                attr: Some(api::attribute::Attr::PrefixSid(prefix_sid_to_api(&sid))),
            },
            Err(_) => api::Attribute {
                attr: Some(api::attribute::Attr::Unknown(api::UnknownAttribute {
                    flags: a.flags() as u32,
                    r#type: a.code() as u32,
                    value: a.binary().unwrap().to_owned(),
                })),
            },
        },
        _ => api::Attribute {
            attr: Some(api::attribute::Attr::Unknown(api::UnknownAttribute {
                flags: a.flags() as u32,
                r#type: a.code() as u32,
                value: a.binary().unwrap().to_owned(),
            })),
        },
    }
}

/// Type byte category masks (RFC 4360 §2, RFC 5668 §2, RFC 7153 §2).
const EXTCOM_TYPE_NON_TRANSITIVE: u8 = 0x40;
const EXTCOM_TYPE_TWO_OCTET_AS: u8 = 0x00;
const EXTCOM_TYPE_IPV4_ADDRESS: u8 = 0x01;
const EXTCOM_TYPE_FOUR_OCTET_AS: u8 = 0x02;
/// Generic Transitive Experimental Use (RFC 7153 §4): sub-types 0x06-0x09 are Flowspec actions.
const EXTCOM_TYPE_GENERIC_TRANSITIVE: u8 = 0x80;
const EXTCOM_TYPE_GENERIC_TRANSITIVE_IPV4: u8 = 0x81;
const EXTCOM_TYPE_GENERIC_TRANSITIVE_4OCTET_AS: u8 = 0x82;

fn read_extcom(c: &mut Cursor<&Vec<u8>>) -> api::ExtendedCommunity {
    let start = c.position() as usize;
    let type_high = c.read_u8().unwrap();
    let is_transitive = type_high & EXTCOM_TYPE_NON_TRANSITIVE == 0;
    let category = type_high & !EXTCOM_TYPE_NON_TRANSITIVE;
    let sub_type = c.read_u8().unwrap();
    let extcom = match category {
        EXTCOM_TYPE_TWO_OCTET_AS => {
            let asn = c.read_u16::<NetworkEndian>().unwrap() as u32;
            let local_admin = c.read_u32::<NetworkEndian>().unwrap();
            api::extended_community::Extcom::TwoOctetAsSpecific(api::TwoOctetAsSpecificExtended {
                is_transitive,
                sub_type: sub_type as u32,
                asn,
                local_admin,
            })
        }
        EXTCOM_TYPE_IPV4_ADDRESS => {
            let addr = Ipv4Addr::from(c.read_u32::<NetworkEndian>().unwrap());
            let local_admin = c.read_u16::<NetworkEndian>().unwrap() as u32;
            api::extended_community::Extcom::Ipv4AddressSpecific(api::IPv4AddressSpecificExtended {
                is_transitive,
                sub_type: sub_type as u32,
                address: addr.to_string(),
                local_admin,
            })
        }
        EXTCOM_TYPE_FOUR_OCTET_AS => {
            let asn = c.read_u32::<NetworkEndian>().unwrap();
            let local_admin = c.read_u16::<NetworkEndian>().unwrap() as u32;
            api::extended_community::Extcom::FourOctetAsSpecific(api::FourOctetAsSpecificExtended {
                is_transitive,
                sub_type: sub_type as u32,
                asn,
                local_admin,
            })
        }
        mup::EC_TYPE_MUP => {
            let segment_id2 = c.read_u16::<NetworkEndian>().unwrap() as u32;
            let segment_id4 = c.read_u32::<NetworkEndian>().unwrap();
            api::extended_community::Extcom::Mup(api::MupExtended {
                sub_type: sub_type as u32,
                segment_id2,
                segment_id4,
            })
        }
        EXTCOM_TYPE_GENERIC_TRANSITIVE => match sub_type {
            0x06 => {
                let asn = c.read_u16::<NetworkEndian>().unwrap() as u32;
                let rate = f32::from_bits(c.read_u32::<NetworkEndian>().unwrap());
                api::extended_community::Extcom::TrafficRate(api::TrafficRateExtended { asn, rate })
            }
            0x07 => {
                for _ in 0..5 {
                    c.read_u8().unwrap();
                }
                let flags = c.read_u8().unwrap();
                api::extended_community::Extcom::TrafficAction(api::TrafficActionExtended {
                    terminal: flags & 0x01 != 0,
                    sample: flags & 0x02 != 0,
                })
            }
            0x08 => {
                let asn = c.read_u16::<NetworkEndian>().unwrap() as u32;
                let local_admin = c.read_u32::<NetworkEndian>().unwrap();
                api::extended_community::Extcom::RedirectTwoOctetAsSpecific(
                    api::RedirectTwoOctetAsSpecificExtended { asn, local_admin },
                )
            }
            0x09 => {
                for _ in 0..5 {
                    c.read_u8().unwrap();
                }
                let dscp = c.read_u8().unwrap() as u32 & 0x3F;
                api::extended_community::Extcom::TrafficRemark(api::TrafficRemarkExtended { dscp })
            }
            _ => {
                let buf = c.get_ref();
                let value = buf[start..start + 8].to_vec();
                c.set_position((start + 8) as u64);
                api::extended_community::Extcom::Unknown(api::UnknownExtended {
                    r#type: type_high as u32,
                    value,
                })
            }
        },
        EXTCOM_TYPE_GENERIC_TRANSITIVE_IPV4 => match sub_type {
            0x08 => {
                let addr = Ipv4Addr::from(c.read_u32::<NetworkEndian>().unwrap());
                let local_admin = c.read_u16::<NetworkEndian>().unwrap() as u32;
                api::extended_community::Extcom::RedirectIpv4AddressSpecific(
                    api::RedirectIPv4AddressSpecificExtended {
                        address: addr.to_string(),
                        local_admin,
                    },
                )
            }
            _ => {
                let buf = c.get_ref();
                let value = buf[start..start + 8].to_vec();
                c.set_position((start + 8) as u64);
                api::extended_community::Extcom::Unknown(api::UnknownExtended {
                    r#type: type_high as u32,
                    value,
                })
            }
        },
        EXTCOM_TYPE_GENERIC_TRANSITIVE_4OCTET_AS => match sub_type {
            0x08 => {
                let asn = c.read_u32::<NetworkEndian>().unwrap();
                let local_admin = c.read_u16::<NetworkEndian>().unwrap() as u32;
                api::extended_community::Extcom::RedirectFourOctetAsSpecific(
                    api::RedirectFourOctetAsSpecificExtended { asn, local_admin },
                )
            }
            _ => {
                let buf = c.get_ref();
                let value = buf[start..start + 8].to_vec();
                c.set_position((start + 8) as u64);
                api::extended_community::Extcom::Unknown(api::UnknownExtended {
                    r#type: type_high as u32,
                    value,
                })
            }
        },
        _ => {
            // Copy the full 8-byte chunk so the unknown extcom round-trips.
            let buf = c.get_ref();
            let value = buf[start..start + 8].to_vec();
            c.set_position((start + 8) as u64);
            api::extended_community::Extcom::Unknown(api::UnknownExtended {
                r#type: type_high as u32,
                value,
            })
        }
    };
    api::ExtendedCommunity {
        extcom: Some(extcom),
    }
}

fn write_extcom(c: &mut Cursor<Vec<u8>>, com: api::ExtendedCommunity) -> Result<(), Error> {
    let inner = com
        .extcom
        .ok_or_else(|| Error::InvalidArgument("missing extcom oneof".to_string()))?;
    let transitive_bit = |is_transitive: bool| {
        if is_transitive {
            0
        } else {
            EXTCOM_TYPE_NON_TRANSITIVE
        }
    };
    match inner {
        api::extended_community::Extcom::TwoOctetAsSpecific(t) => {
            c.write_u8(EXTCOM_TYPE_TWO_OCTET_AS | transitive_bit(t.is_transitive))
                .unwrap();
            c.write_u8(ensure_u8("sub_type", t.sub_type)?).unwrap();
            c.write_u16::<NetworkEndian>(ensure_u16("asn", t.asn)?)
                .unwrap();
            c.write_u32::<NetworkEndian>(t.local_admin).unwrap();
        }
        api::extended_community::Extcom::Ipv4AddressSpecific(t) => {
            c.write_u8(EXTCOM_TYPE_IPV4_ADDRESS | transitive_bit(t.is_transitive))
                .unwrap();
            c.write_u8(ensure_u8("sub_type", t.sub_type)?).unwrap();
            let addr: Ipv4Addr = t
                .address
                .parse()
                .map_err(|e| Error::InvalidArgument(format!("invalid extcom address: {}", e)))?;
            c.write_u32::<NetworkEndian>(addr.into()).unwrap();
            c.write_u16::<NetworkEndian>(ensure_u16("local_admin", t.local_admin)?)
                .unwrap();
        }
        api::extended_community::Extcom::FourOctetAsSpecific(t) => {
            c.write_u8(EXTCOM_TYPE_FOUR_OCTET_AS | transitive_bit(t.is_transitive))
                .unwrap();
            c.write_u8(ensure_u8("sub_type", t.sub_type)?).unwrap();
            c.write_u32::<NetworkEndian>(t.asn).unwrap();
            c.write_u16::<NetworkEndian>(ensure_u16("local_admin", t.local_admin)?)
                .unwrap();
        }
        api::extended_community::Extcom::Mup(m) => {
            let mup_ec = mup::MupExtended {
                sub_type: ensure_u8("sub_type", m.sub_type)?,
                segment_id2: ensure_u16("segment_id2", m.segment_id2)?,
                segment_id4: m.segment_id4,
            };
            let mut buf = bytes::BytesMut::with_capacity(mup::MupExtended::LEN);
            mup_ec.encode(&mut buf);
            c.write_all(&buf).unwrap();
        }
        api::extended_community::Extcom::Unknown(u) => {
            if u.value.len() != 8 {
                return Err(Error::InvalidArgument(format!(
                    "extended community must be 8 bytes, got {}",
                    u.value.len()
                )));
            }
            c.write_all(&u.value).unwrap();
        }
        api::extended_community::Extcom::TrafficRate(t) => {
            c.write_u8(EXTCOM_TYPE_GENERIC_TRANSITIVE).unwrap();
            c.write_u8(0x06).unwrap();
            c.write_u16::<NetworkEndian>(ensure_u16("asn", t.asn)?)
                .unwrap();
            c.write_u32::<NetworkEndian>(t.rate.to_bits()).unwrap();
        }
        api::extended_community::Extcom::TrafficAction(t) => {
            c.write_u8(EXTCOM_TYPE_GENERIC_TRANSITIVE).unwrap();
            c.write_u8(0x07).unwrap();
            for _ in 0..5 {
                c.write_u8(0).unwrap();
            }
            let flags = u8::from(t.terminal) | (u8::from(t.sample) << 1);
            c.write_u8(flags).unwrap();
        }
        api::extended_community::Extcom::RedirectTwoOctetAsSpecific(t) => {
            c.write_u8(EXTCOM_TYPE_GENERIC_TRANSITIVE).unwrap();
            c.write_u8(0x08).unwrap();
            c.write_u16::<NetworkEndian>(ensure_u16("asn", t.asn)?)
                .unwrap();
            c.write_u32::<NetworkEndian>(t.local_admin).unwrap();
        }
        api::extended_community::Extcom::TrafficRemark(t) => {
            c.write_u8(EXTCOM_TYPE_GENERIC_TRANSITIVE).unwrap();
            c.write_u8(0x09).unwrap();
            for _ in 0..5 {
                c.write_u8(0).unwrap();
            }
            c.write_u8(ensure_u8("dscp", t.dscp & 0x3F)?).unwrap();
        }
        api::extended_community::Extcom::RedirectIpv4AddressSpecific(t) => {
            c.write_u8(EXTCOM_TYPE_GENERIC_TRANSITIVE_IPV4).unwrap();
            c.write_u8(0x08).unwrap();
            let addr: Ipv4Addr = t
                .address
                .parse()
                .map_err(|e| Error::InvalidArgument(format!("invalid extcom address: {}", e)))?;
            c.write_u32::<NetworkEndian>(addr.into()).unwrap();
            c.write_u16::<NetworkEndian>(ensure_u16("local_admin", t.local_admin)?)
                .unwrap();
        }
        api::extended_community::Extcom::RedirectFourOctetAsSpecific(t) => {
            c.write_u8(EXTCOM_TYPE_GENERIC_TRANSITIVE_4OCTET_AS)
                .unwrap();
            c.write_u8(0x08).unwrap();
            c.write_u32::<NetworkEndian>(t.asn).unwrap();
            c.write_u16::<NetworkEndian>(ensure_u16("local_admin", t.local_admin)?)
                .unwrap();
        }
        _ => {
            return Err(Error::InvalidArgument(
                "extended community variant not supported".to_string(),
            ));
        }
    }
    Ok(())
}

fn ensure_u8(name: &str, v: u32) -> Result<u8, Error> {
    if v > u8::MAX as u32 {
        Err(Error::InvalidArgument(format!(
            "{} out of range: {}",
            name, v
        )))
    } else {
        Ok(v as u8)
    }
}

fn ensure_u16(name: &str, v: u32) -> Result<u16, Error> {
    if v > u16::MAX as u32 {
        Err(Error::InvalidArgument(format!(
            "{} out of range: {}",
            name, v
        )))
    } else {
        Ok(v as u16)
    }
}

pub(crate) fn family_from_api(f: &api::Family) -> Family {
    Family::new((f.afi as u32) << 16 | f.safi as u32)
}

pub(crate) fn family_from_config(f: &config::generate::AfiSafiType) -> Result<Family, ()> {
    match f {
        config::generate::AfiSafiType::Ipv4Unicast => Ok(Family::IPV4),
        config::generate::AfiSafiType::Ipv6Unicast => Ok(Family::IPV6),
        config::generate::AfiSafiType::Ipv4Multicast => Ok(Family::IPV4_MC),
        config::generate::AfiSafiType::Ipv6Multicast => Ok(Family::IPV6_MC),
        config::generate::AfiSafiType::Ipv4LabelledUnicast => Ok(Family::IPV4_MPLS),
        config::generate::AfiSafiType::Ipv6LabelledUnicast => Ok(Family::IPV6_MPLS),
        config::generate::AfiSafiType::Ipv4Mup => Ok(Family::IPV4_MUP),
        config::generate::AfiSafiType::Ipv6Mup => Ok(Family::IPV6_MUP),
        config::generate::AfiSafiType::Ipv4Flowspec => Ok(Family::IPV4_FLOWSPEC),
        config::generate::AfiSafiType::Ipv6Flowspec => Ok(Family::IPV6_FLOWSPEC),
        config::generate::AfiSafiType::L3VpnIpv4Flowspec => Ok(Family::IPV4_FLOWSPEC_VPN),
        config::generate::AfiSafiType::L3VpnIpv6Flowspec => Ok(Family::IPV6_FLOWSPEC_VPN),
        _ => Err(()),
    }
}

fn items_to_ops(items: Vec<api::FlowSpecComponentItem>) -> Vec<flowspec::Op> {
    items
        .into_iter()
        .map(|item| flowspec::Op {
            bits: item.op as u8,
            value: item.value,
        })
        .collect()
}

fn rules_to_v4_components(
    rules: Vec<api::FlowSpecRule>,
) -> Result<Vec<flowspec::FlowspecV4Component>, Error> {
    use flowspec::FlowspecV4Component as C;
    rules
        .into_iter()
        .map(|rule| {
            match rule
                .rule
                .ok_or_else(|| Error::InvalidArgument("missing flowspec rule".to_string()))?
            {
                api::flow_spec_rule::Rule::IpPrefix(p) => {
                    let addr: std::net::Ipv4Addr = p.prefix.parse().map_err(|e| {
                        Error::InvalidArgument(format!("invalid flowspec prefix: {}", e))
                    })?;
                    let net = Ipv4Net {
                        addr,
                        mask: p.prefix_len as u8,
                    };
                    match p.r#type {
                        1 => Ok(C::DstPrefix(net)),
                        2 => Ok(C::SrcPrefix(net)),
                        t => Err(Error::InvalidArgument(format!(
                            "unknown flowspec prefix type: {}",
                            t
                        ))),
                    }
                }
                api::flow_spec_rule::Rule::Component(c) => {
                    let ops = items_to_ops(c.items);
                    match c.r#type {
                        3 => Ok(C::Protocol(ops)),
                        4 => Ok(C::Port(ops)),
                        5 => Ok(C::DstPort(ops)),
                        6 => Ok(C::SrcPort(ops)),
                        7 => Ok(C::IcmpType(ops)),
                        8 => Ok(C::IcmpCode(ops)),
                        9 => Ok(C::TcpFlags(ops)),
                        10 => Ok(C::PacketLen(ops)),
                        11 => Ok(C::Dscp(ops)),
                        12 => Ok(C::Fragment(ops)),
                        t => Err(Error::InvalidArgument(format!(
                            "unknown flowspec component type: {}",
                            t
                        ))),
                    }
                }
                api::flow_spec_rule::Rule::Mac(_) => Err(Error::InvalidArgument(
                    "MAC rule not supported for IPv4 Flowspec".to_string(),
                )),
            }
        })
        .collect()
}

fn rules_to_v6_components(
    rules: Vec<api::FlowSpecRule>,
) -> Result<Vec<flowspec::FlowspecV6Component>, Error> {
    use flowspec::FlowspecV6Component as C;
    rules
        .into_iter()
        .map(|rule| {
            match rule
                .rule
                .ok_or_else(|| Error::InvalidArgument("missing flowspec rule".to_string()))?
            {
                api::flow_spec_rule::Rule::IpPrefix(p) => {
                    let addr: std::net::Ipv6Addr = p.prefix.parse().map_err(|e| {
                        Error::InvalidArgument(format!("invalid flowspec prefix: {}", e))
                    })?;
                    let prefix = Ipv6Net {
                        addr,
                        mask: p.prefix_len as u8,
                    };
                    let offset = p.offset as u8;
                    match p.r#type {
                        1 => Ok(C::DstPrefix { prefix, offset }),
                        2 => Ok(C::SrcPrefix { prefix, offset }),
                        t => Err(Error::InvalidArgument(format!(
                            "unknown flowspec prefix type: {}",
                            t
                        ))),
                    }
                }
                api::flow_spec_rule::Rule::Component(c) => {
                    let ops = items_to_ops(c.items);
                    match c.r#type {
                        3 => Ok(C::NextHeader(ops)),
                        4 => Ok(C::Port(ops)),
                        5 => Ok(C::DstPort(ops)),
                        6 => Ok(C::SrcPort(ops)),
                        7 => Ok(C::IcmpType(ops)),
                        8 => Ok(C::IcmpCode(ops)),
                        9 => Ok(C::TcpFlags(ops)),
                        10 => Ok(C::PacketLen(ops)),
                        11 => Ok(C::Dscp(ops)),
                        12 => Ok(C::Fragment(ops)),
                        13 => Ok(C::FlowLabel(ops)),
                        t => Err(Error::InvalidArgument(format!(
                            "unknown flowspec component type: {}",
                            t
                        ))),
                    }
                }
                api::flow_spec_rule::Rule::Mac(_) => Err(Error::InvalidArgument(
                    "MAC rule not supported for IPv6 Flowspec".to_string(),
                )),
            }
        })
        .collect()
}

pub(crate) fn net_from_api(n: api::Nlri, family: Family) -> Result<Nlri, Error> {
    match n.nlri {
        Some(api::nlri::Nlri::Prefix(p)) => {
            Nlri::from_str(&format!("{}/{}", p.prefix, p.prefix_len))
                .map_err(|e| Error::InvalidArgument(e.to_string()))
        }
        Some(api::nlri::Nlri::MupInterworkSegmentDiscovery(r)) => {
            let rd = rd_from_api(
                r.rd.as_ref()
                    .ok_or_else(|| Error::InvalidArgument("missing rd".to_string()))?,
            )?;
            let (addr, bits) = parse_prefix(&r.prefix)?;
            Ok(Nlri::Mup(mup::MupNlri::InterworkSegmentDiscovery(
                mup::MupInterworkSegmentDiscoveryRoute {
                    rd,
                    prefix_addr: addr,
                    prefix_len: bits,
                },
            )))
        }
        Some(api::nlri::Nlri::MupDirectSegmentDiscovery(r)) => {
            let rd = rd_from_api(
                r.rd.as_ref()
                    .ok_or_else(|| Error::InvalidArgument("missing rd".to_string()))?,
            )?;
            let address = r
                .address
                .parse::<std::net::IpAddr>()
                .map_err(|e| Error::InvalidArgument(format!("invalid mup address: {}", e)))?;
            Ok(Nlri::Mup(mup::MupNlri::DirectSegmentDiscovery(
                mup::MupDirectSegmentDiscoveryRoute { rd, address },
            )))
        }
        Some(api::nlri::Nlri::MupType1SessionTransformed(r)) => {
            let rd = rd_from_api(
                r.rd.as_ref()
                    .ok_or_else(|| Error::InvalidArgument("missing rd".to_string()))?,
            )?;
            let (prefix_addr, prefix_len) = parse_prefix(&r.prefix)?;
            let endpoint_address = r
                .endpoint_address
                .parse::<std::net::IpAddr>()
                .map_err(|e| Error::InvalidArgument(format!("invalid mup endpoint: {}", e)))?;
            let source_address =
                if r.source_address_length == 0 || r.source_address.is_empty() {
                    None
                } else {
                    Some(r.source_address.parse::<std::net::IpAddr>().map_err(|e| {
                        Error::InvalidArgument(format!("invalid mup source: {}", e))
                    })?)
                };
            if r.qfi > u8::MAX as u32 {
                return Err(Error::InvalidArgument(format!(
                    "qfi out of range: {}",
                    r.qfi
                )));
            }
            Ok(Nlri::Mup(mup::MupNlri::Type1SessionTransformed(
                mup::MupType1SessionTransformedRoute {
                    rd,
                    prefix_addr,
                    prefix_len,
                    teid: r.teid,
                    qfi: r.qfi as u8,
                    endpoint_address,
                    source_address,
                },
            )))
        }
        Some(api::nlri::Nlri::MupType2SessionTransformed(r)) => {
            let rd = rd_from_api(
                r.rd.as_ref()
                    .ok_or_else(|| Error::InvalidArgument("missing rd".to_string()))?,
            )?;
            let endpoint_address = r
                .endpoint_address
                .parse::<std::net::IpAddr>()
                .map_err(|e| Error::InvalidArgument(format!("invalid mup endpoint: {}", e)))?;
            if r.endpoint_address_length > u8::MAX as u32 {
                return Err(Error::InvalidArgument(format!(
                    "endpoint_address_length out of range: {}",
                    r.endpoint_address_length
                )));
            }
            Ok(Nlri::Mup(mup::MupNlri::Type2SessionTransformed(
                mup::MupType2SessionTransformedRoute {
                    rd,
                    endpoint_address_length: r.endpoint_address_length as u8,
                    endpoint_address,
                    teid: r.teid,
                },
            )))
        }
        Some(api::nlri::Nlri::FlowSpec(n)) => match family {
            Family::IPV4_FLOWSPEC => Ok(Nlri::FlowspecV4(flowspec::FlowspecV4Nlri {
                components: rules_to_v4_components(n.rules)?,
            })),
            Family::IPV6_FLOWSPEC => Ok(Nlri::FlowspecV6(flowspec::FlowspecV6Nlri {
                components: rules_to_v6_components(n.rules)?,
            })),
            _ => Err(Error::InvalidArgument(
                "family mismatch for FlowSpec NLRI".to_string(),
            )),
        },
        Some(api::nlri::Nlri::VpnFlowSpec(n)) => {
            let rd = rd_from_api(
                n.rd.as_ref()
                    .ok_or_else(|| Error::InvalidArgument("missing rd".to_string()))?,
            )?;
            match family {
                Family::IPV4_FLOWSPEC_VPN => Ok(Nlri::FlowspecVpnV4(flowspec::FlowspecVpnV4Nlri {
                    rd,
                    components: rules_to_v4_components(n.rules)?,
                })),
                Family::IPV6_FLOWSPEC_VPN => Ok(Nlri::FlowspecVpnV6(flowspec::FlowspecVpnV6Nlri {
                    rd,
                    components: rules_to_v6_components(n.rules)?,
                })),
                _ => Err(Error::InvalidArgument(
                    "family mismatch for VPN FlowSpec NLRI".to_string(),
                )),
            }
        }
        Some(api::nlri::Nlri::LsAddrPrefix(n)) => ls_nlri_from_api(n),
        _ => Err(Error::InvalidArgument("invalid NLRI".to_string())),
    }
}

fn parse_prefix(s: &str) -> Result<(std::net::IpAddr, u8), Error> {
    let (addr_str, len_str) = s
        .rsplit_once('/')
        .ok_or_else(|| Error::InvalidArgument(format!("missing prefix length: {}", s)))?;
    let addr = addr_str
        .parse::<std::net::IpAddr>()
        .map_err(|e| Error::InvalidArgument(format!("invalid prefix: {}", e)))?;
    let len: u8 = len_str
        .parse()
        .map_err(|e| Error::InvalidArgument(format!("invalid prefix length: {}", e)))?;
    Ok((addr, len))
}

pub(crate) fn attr_from_api(a: api::Attribute) -> Result<Attribute, Error> {
    let attr = a
        .attr
        .ok_or(Error::InvalidArgument("missing attribute".to_string()))?;

    match attr {
        api::attribute::Attr::Unknown(u) => Attribute::new_with_bin(u.r#type as u8, u.value)
            .ok_or(Error::InvalidArgument("unknown attribute type".to_string())),
        api::attribute::Attr::Origin(o) => Attribute::new_with_value(Attribute::ORIGIN, o.origin)
            .ok_or(Error::InvalidArgument("unsupported attribute".to_string())),
        api::attribute::Attr::AsPath(p) => {
            let mut c = Cursor::new(Vec::new());
            for s in p.segments {
                let _ = c.write_u8(s.r#type as u8);
                let _ = c.write_u8(s.numbers.len() as u8);
                for n in s.numbers {
                    c.write_u32::<NetworkEndian>(n).unwrap();
                }
            }
            Attribute::new_with_bin(Attribute::AS_PATH, c.into_inner())
                .ok_or(Error::InvalidArgument("unsupported attribute".to_string()))
        }
        api::attribute::Attr::NextHop(nh) => {
            let mut c = Cursor::new(Vec::new());
            if let Ok(addr) = Ipv4Addr::from_str(&nh.next_hop) {
                c.write_u32::<NetworkEndian>(addr.into()).unwrap();
            } else if let Ok(addr) = Ipv6Addr::from_str(&nh.next_hop) {
                c.write_u128::<NetworkEndian>(addr.into()).unwrap();
            }
            Attribute::new_with_bin(Attribute::NEXTHOP, c.into_inner())
                .ok_or(Error::InvalidArgument("unsupported attribute".to_string()))
        }
        api::attribute::Attr::MultiExitDisc(m) => {
            Attribute::new_with_value(Attribute::MULTI_EXIT_DESC, m.med)
                .ok_or(Error::InvalidArgument("unsupported attribute".to_string()))
        }
        api::attribute::Attr::LocalPref(l) => {
            Attribute::new_with_value(Attribute::LOCAL_PREF, l.local_pref)
                .ok_or(Error::InvalidArgument("unsupported attribute".to_string()))
        }
        api::attribute::Attr::AtomicAggregate(_) => {
            Ok(Attribute::new_with_bin(Attribute::ATOMIC_AGGREGATE, Vec::new()).unwrap())
        }
        api::attribute::Attr::Aggregator(ag) => {
            let mut c = Cursor::new(Vec::new());
            let addr = Ipv4Addr::from_str(&ag.address)
                .map_err(|e| Error::InvalidArgument(e.to_string()))?;
            c.write_u32::<NetworkEndian>(ag.asn).unwrap();
            c.write_u32::<NetworkEndian>(addr.into()).unwrap();
            Attribute::new_with_bin(Attribute::AGGREGATOR, c.into_inner())
                .ok_or(Error::InvalidArgument("unsupported attribute".to_string()))
        }
        api::attribute::Attr::Communities(cm) => {
            let mut c = Cursor::new(Vec::new());
            for v in cm.communities {
                c.write_u32::<NetworkEndian>(v).unwrap();
            }
            Attribute::new_with_bin(Attribute::COMMUNITY, c.into_inner())
                .ok_or(Error::InvalidArgument("unsupported attribute".to_string()))
        }
        api::attribute::Attr::OriginatorId(o) => {
            let addr =
                Ipv4Addr::from_str(&o.id).map_err(|e| Error::InvalidArgument(e.to_string()))?;
            Attribute::new_with_value(Attribute::ORIGINATOR_ID, addr.into())
                .ok_or(Error::InvalidArgument("unsupported attribute".to_string()))
        }
        api::attribute::Attr::ClusterList(cl) => {
            let mut c = Cursor::new(Vec::new());
            for id in cl.ids {
                let addr =
                    Ipv4Addr::from_str(&id).map_err(|e| Error::InvalidArgument(e.to_string()))?;
                c.write_u32::<NetworkEndian>(addr.into()).unwrap();
            }
            Attribute::new_with_bin(Attribute::CLUSTER_LIST, c.into_inner())
                .ok_or(Error::InvalidArgument("unsupported attribute".to_string()))
        }
        api::attribute::Attr::LargeCommunities(lc) => {
            let mut c = Cursor::new(Vec::new());
            for v in lc.communities {
                c.write_u32::<NetworkEndian>(v.global_admin).unwrap();
                c.write_u32::<NetworkEndian>(v.local_data1).unwrap();
                c.write_u32::<NetworkEndian>(v.local_data2).unwrap();
            }
            Attribute::new_with_bin(Attribute::LARGE_COMMUNITY, c.into_inner())
                .ok_or(Error::InvalidArgument("unsupported attribute".to_string()))
        }
        api::attribute::Attr::MpReach(m) => {
            let family = m
                .family
                .ok_or_else(|| Error::InvalidArgument("mp_reach missing family".to_string()))?;
            let nh_str = m.next_hops.first().ok_or_else(|| {
                Error::InvalidArgument("mp_reach must carry at least one nexthop".to_string())
            })?;
            let mut nh_bytes = Vec::with_capacity(16);
            if let Ok(v4) = nh_str.parse::<Ipv4Addr>() {
                nh_bytes.extend_from_slice(&v4.octets());
            } else if let Ok(v6) = nh_str.parse::<Ipv6Addr>() {
                nh_bytes.extend_from_slice(&v6.octets());
            } else {
                return Err(Error::InvalidArgument(format!(
                    "invalid mp_reach nexthop: {}",
                    nh_str
                )));
            }
            // Binary layout consumed by event.rs:
            //   [AFI:2][SAFI:1][NH_LEN:1][nexthop:NH_LEN][reserved:1]
            // NLRI bytes are intentionally omitted here; the daemon uses
            // `path.nlri` to carry NLRI and only reads the nexthop from the
            // MP_REACH attribute.
            let mut c = Cursor::new(Vec::with_capacity(5 + nh_bytes.len()));
            c.write_u16::<NetworkEndian>(family.afi as u16).unwrap();
            c.write_u8(family.safi as u8).unwrap();
            c.write_u8(nh_bytes.len() as u8).unwrap();
            c.write_all(&nh_bytes)
                .map_err(|e| Error::InvalidArgument(format!("mp_reach write: {}", e)))?;
            c.write_u8(0).unwrap(); // reserved
            Attribute::new_with_bin(Attribute::MP_REACH, c.into_inner())
                .ok_or(Error::InvalidArgument("unsupported attribute".to_string()))
        }
        api::attribute::Attr::ExtendedCommunities(ec) => {
            let mut c = Cursor::new(Vec::with_capacity(ec.communities.len() * 8));
            for com in ec.communities {
                write_extcom(&mut c, com)?;
            }
            Attribute::new_with_bin(Attribute::EXTENDED_COMMUNITY, c.into_inner())
                .ok_or(Error::InvalidArgument("unsupported attribute".to_string()))
        }
        api::attribute::Attr::PrefixSid(p) => {
            let sid = prefix_sid_from_api(p)?;
            Attribute::new_with_bin(Attribute::PREFIX_SID, sid.to_vec())
                .ok_or(Error::InvalidArgument("unsupported attribute".to_string()))
        }
        _ => Err(Error::InvalidArgument(
            "attribute conversion not implemented".to_string(),
        )),
    }
}

fn prefix_sid_to_api(sid: &prefix_sid::PrefixSid) -> api::PrefixSid {
    let tlvs = sid
        .tlvs
        .iter()
        .filter_map(|tlv| match tlv {
            prefix_sid::PrefixSidTlv::Srv6L3Service(t) => Some(api::prefix_sid::Tlv {
                tlv: Some(api::prefix_sid::tlv::Tlv::L3Service(
                    api::SRv6L3ServiceTlv {
                        sub_tlvs: srv6_service_sub_tlvs_to_api(&t.sub_tlvs),
                    },
                )),
            }),
            prefix_sid::PrefixSidTlv::Srv6L2Service(t) => Some(api::prefix_sid::Tlv {
                tlv: Some(api::prefix_sid::tlv::Tlv::L2Service(
                    api::SRv6L2ServiceTlv {
                        sub_tlvs: srv6_service_sub_tlvs_to_api(&t.sub_tlvs),
                    },
                )),
            }),
            // Unknown TLVs are not represented in the proto; drop them for
            // the typed gRPC view. They still round-trip on the wire because
            // the daemon keeps the original attribute bytes.
            prefix_sid::PrefixSidTlv::Unknown { .. } => None,
        })
        .collect();
    api::PrefixSid { tlvs }
}

fn srv6_service_sub_tlvs_to_api(
    subs: &[prefix_sid::Srv6ServiceSubTlv],
) -> std::collections::HashMap<u32, api::SRv6SubTlVs> {
    let mut map = std::collections::HashMap::new();
    for sub in subs {
        if let prefix_sid::Srv6ServiceSubTlv::Information(info) = sub {
            let entry = map
                .entry(prefix_sid::Srv6ServiceSubTlv::SUBTLV_SRV6_INFORMATION as u32)
                .or_insert(api::SRv6SubTlVs { tlvs: Vec::new() });
            entry.tlvs.push(api::SRv6SubTlv {
                tlv: Some(api::s_rv6_sub_tlv::Tlv::Information(
                    api::SRv6InformationSubTlv {
                        sid: info.sid.octets().to_vec(),
                        flags: Some(api::SRv6SidFlags { flag_1: false }),
                        endpoint_behavior: info.endpoint_behavior as u32,
                        sub_sub_tlvs: srv6_service_sub_sub_tlvs_to_api(&info.sub_sub_tlvs),
                    },
                )),
            });
        }
    }
    map
}

fn srv6_service_sub_sub_tlvs_to_api(
    subs: &[prefix_sid::Srv6ServiceDataSubSubTlv],
) -> std::collections::HashMap<u32, api::SRv6SubSubTlVs> {
    let mut map = std::collections::HashMap::new();
    for sub in subs {
        if let prefix_sid::Srv6ServiceDataSubSubTlv::Structure(s) = sub {
            let entry = map
                .entry(prefix_sid::Srv6ServiceDataSubSubTlv::SUBSUBTLV_SRV6_SID_STRUCTURE as u32)
                .or_insert(api::SRv6SubSubTlVs { tlvs: Vec::new() });
            entry.tlvs.push(api::SRv6SubSubTlv {
                tlv: Some(api::s_rv6_sub_sub_tlv::Tlv::Structure(
                    api::SRv6StructureSubSubTlv {
                        locator_block_length: s.locator_block_length as u32,
                        locator_node_length: s.locator_node_length as u32,
                        function_length: s.function_length as u32,
                        argument_length: s.argument_length as u32,
                        transposition_length: s.transposition_length as u32,
                        transposition_offset: s.transposition_offset as u32,
                    },
                )),
            });
        }
    }
    map
}

fn prefix_sid_from_api(p: api::PrefixSid) -> Result<prefix_sid::PrefixSid, Error> {
    let mut tlvs = Vec::with_capacity(p.tlvs.len());
    for tlv in p.tlvs {
        let inner = tlv
            .tlv
            .ok_or_else(|| Error::InvalidArgument("empty prefix_sid tlv oneof".to_string()))?;
        match inner {
            api::prefix_sid::tlv::Tlv::L3Service(t) => {
                tlvs.push(prefix_sid::PrefixSidTlv::Srv6L3Service(
                    prefix_sid::Srv6ServiceTlv {
                        reserved: 0,
                        sub_tlvs: srv6_service_sub_tlvs_from_api(t.sub_tlvs)?,
                    },
                ));
            }
            api::prefix_sid::tlv::Tlv::L2Service(t) => {
                tlvs.push(prefix_sid::PrefixSidTlv::Srv6L2Service(
                    prefix_sid::Srv6ServiceTlv {
                        reserved: 0,
                        sub_tlvs: srv6_service_sub_tlvs_from_api(t.sub_tlvs)?,
                    },
                ));
            }
        }
    }
    Ok(prefix_sid::PrefixSid { tlvs })
}

fn srv6_service_sub_tlvs_from_api(
    map: std::collections::HashMap<u32, api::SRv6SubTlVs>,
) -> Result<Vec<prefix_sid::Srv6ServiceSubTlv>, Error> {
    let mut out = Vec::new();
    for (_key, sub_tlvs) in map {
        for sub in sub_tlvs.tlvs {
            let inner = sub
                .tlv
                .ok_or_else(|| Error::InvalidArgument("empty srv6 sub_tlv".to_string()))?;
            match inner {
                api::s_rv6_sub_tlv::Tlv::Information(info) => {
                    if info.sid.len() != 16 {
                        return Err(Error::InvalidArgument(format!(
                            "SRv6 SID must be 16 bytes, got {}",
                            info.sid.len()
                        )));
                    }
                    let mut sid_bytes = [0u8; 16];
                    sid_bytes.copy_from_slice(&info.sid);
                    if info.endpoint_behavior > u16::MAX as u32 {
                        return Err(Error::InvalidArgument(format!(
                            "endpoint_behavior out of range: {}",
                            info.endpoint_behavior
                        )));
                    }
                    out.push(prefix_sid::Srv6ServiceSubTlv::Information(
                        prefix_sid::Srv6InformationSubTlv {
                            sid: sid_bytes.into(),
                            flags: 0,
                            endpoint_behavior: info.endpoint_behavior as u16,
                            sub_sub_tlvs: srv6_service_sub_sub_tlvs_from_api(info.sub_sub_tlvs)?,
                        },
                    ));
                }
            }
        }
    }
    Ok(out)
}

fn srv6_service_sub_sub_tlvs_from_api(
    map: std::collections::HashMap<u32, api::SRv6SubSubTlVs>,
) -> Result<Vec<prefix_sid::Srv6ServiceDataSubSubTlv>, Error> {
    let mut out = Vec::new();
    for (_key, sub_sub_tlvs) in map {
        for sub in sub_sub_tlvs.tlvs {
            let inner = sub
                .tlv
                .ok_or_else(|| Error::InvalidArgument("empty srv6 sub_sub_tlv".to_string()))?;
            match inner {
                api::s_rv6_sub_sub_tlv::Tlv::Structure(s) => {
                    let ensure_u8 = |name: &str, v: u32| -> Result<u8, Error> {
                        if v > u8::MAX as u32 {
                            Err(Error::InvalidArgument(format!(
                                "{} out of range: {}",
                                name, v
                            )))
                        } else {
                            Ok(v as u8)
                        }
                    };
                    out.push(prefix_sid::Srv6ServiceDataSubSubTlv::Structure(
                        prefix_sid::Srv6SidStructureSubSubTlv {
                            locator_block_length: ensure_u8(
                                "locator_block_length",
                                s.locator_block_length,
                            )?,
                            locator_node_length: ensure_u8(
                                "locator_node_length",
                                s.locator_node_length,
                            )?,
                            function_length: ensure_u8("function_length", s.function_length)?,
                            argument_length: ensure_u8("argument_length", s.argument_length)?,
                            transposition_length: ensure_u8(
                                "transposition_length",
                                s.transposition_length,
                            )?,
                            transposition_offset: ensure_u8(
                                "transposition_offset",
                                s.transposition_offset,
                            )?,
                        },
                    ));
                }
            }
        }
    }
    Ok(out)
}

pub(crate) fn statement_to_api(my: &rustybgp_table::Statement) -> api::Statement {
    use rustybgp_table::{Comparison, Condition, RouteType, RpkiValidationState};
    let mut s = api::Statement {
        name: my.name.to_string(),
        conditions: None,
        actions: None,
    };
    let mut conditions = api::Conditions {
        rpki_result: -1, // hack for gobgp cli
        ..Default::default()
    };

    for condition in &my.conditions {
        match condition {
            Condition::Prefix(name, opt, _set) => {
                conditions.prefix_set = Some(api::MatchSet {
                    name: name.clone(),
                    r#type: match_option_to_i32(opt),
                });
            }
            Condition::Neighbor(name, opt, _set) => {
                conditions.neighbor_set = Some(api::MatchSet {
                    name: name.clone(),
                    r#type: match_option_to_i32(opt),
                });
            }
            Condition::AsPath(name, opt, _set) => {
                conditions.as_path_set = Some(api::MatchSet {
                    name: name.clone(),
                    r#type: match_option_to_i32(opt),
                });
            }
            Condition::Rpki(v) => {
                conditions.rpki_result = match v {
                    RpkiValidationState::NotFound => api::ValidationState::NotFound as i32,
                    RpkiValidationState::Valid => api::ValidationState::Valid as i32,
                    RpkiValidationState::Invalid => api::ValidationState::Invalid as i32,
                };
            }
            Condition::AsPathLength(t, length) => {
                conditions.as_path_length = Some(api::AsPathLength {
                    r#type: match t {
                        Comparison::Eq => 0,
                        Comparison::Ge => 1,
                        Comparison::Le => 2,
                    },
                    length: *length,
                })
            }
            Condition::LocalPrefEq(val) => {
                conditions.local_pref_eq = Some(api::LocalPrefEq { value: *val });
            }
            Condition::MedEq(val) => {
                conditions.med_eq = Some(api::MedEq { value: *val });
            }
            Condition::Origin(val) => {
                // BGP ORIGIN: 0=IGP, 1=EGP, 2=Incomplete
                // API OriginType: Igp=1, Egp=2, Incomplete=3
                conditions.origin = (*val as i32) + 1;
            }
            Condition::RouteType(rt) => {
                use api::conditions::RouteType as ApiRouteType;
                conditions.route_type = match rt {
                    RouteType::Internal => ApiRouteType::Internal as i32,
                    RouteType::External => ApiRouteType::External as i32,
                    RouteType::Local => ApiRouteType::Local as i32,
                };
            }
            Condition::CommunityCount(cmp, count) => {
                conditions.community_count = Some(api::CommunityCount {
                    r#type: match cmp {
                        Comparison::Eq => 0,
                        Comparison::Ge => 1,
                        Comparison::Le => 2,
                    },
                    count: *count,
                });
            }
            Condition::AfiSafiIn(families) => {
                conditions.afi_safi_in = families.iter().map(|f| family_to_api(*f)).collect();
            }
            Condition::ExtCommunity(name, opt, _set) => {
                conditions.ext_community_set = Some(api::MatchSet {
                    name: name.clone(),
                    r#type: match_option_to_i32(opt),
                });
            }
            Condition::LargeCommunity(name, opt, _set) => {
                conditions.large_community_set = Some(api::MatchSet {
                    name: name.clone(),
                    r#type: match_option_to_i32(opt),
                });
            }
            Condition::Community(name, opt, _set) => {
                conditions.community_set = Some(api::MatchSet {
                    name: name.clone(),
                    r#type: match_option_to_i32(opt),
                });
            }
            Condition::Nexthop(v) => {
                conditions.next_hop_in_list = v.iter().map(|x| x.to_string()).collect();
            }
        }
    }
    s.conditions = Some(conditions);
    let nexthop = my.actions.nexthop.as_ref().map(|nh| {
        use rustybgp_table::NexthopAction;
        match nh {
            NexthopAction::Address(addr) => api::NexthopAction {
                address: addr.to_string(),
                self_: false,
                unchanged: false,
                peer_address: false,
            },
            NexthopAction::PeerSelf => api::NexthopAction {
                address: String::new(),
                self_: true,
                unchanged: false,
                peer_address: false,
            },
            NexthopAction::Unchanged => api::NexthopAction {
                address: String::new(),
                self_: false,
                unchanged: true,
                peer_address: false,
            },
        }
    });
    let actions = &my.actions;
    use rustybgp_table::MedActionType;

    let community = actions.community.as_ref().map(|a| api::CommunityAction {
        r#type: community_action_type_to_i32(&a.action_type),
        communities: a
            .communities
            .iter()
            .map(|&c| format!("{}:{}", c >> 16, c & 0xffff))
            .collect(),
    });

    let local_pref = actions
        .local_pref
        .as_ref()
        .map(|a| api::LocalPrefAction { value: a.value });

    let med = actions.med.as_ref().map(|a| api::MedAction {
        r#type: match a.action_type {
            MedActionType::Mod => api::med_action::Type::Mod as i32,
            MedActionType::Replace => api::med_action::Type::Replace as i32,
        },
        value: a.value,
    });

    let as_prepend = actions.as_prepend.as_ref().map(|a| api::AsPrependAction {
        asn: a.asn,
        repeat: a.repeat,
        use_left_most: a.use_left_most,
    });

    let ext_community = actions
        .ext_community
        .as_ref()
        .map(|a| api::CommunityAction {
            r#type: community_action_type_to_i32(&a.action_type),
            communities: a
                .communities
                .iter()
                .filter_map(ext_community_bytes_to_string)
                .collect(),
        });

    let large_community = actions
        .large_community
        .as_ref()
        .map(|a| api::CommunityAction {
            r#type: community_action_type_to_i32(&a.action_type),
            communities: a
                .communities
                .iter()
                .map(|(ga, ld1, ld2)| format!("{}:{}:{}", ga, ld1, ld2))
                .collect(),
        });

    let origin_action = actions.origin.as_ref().map(|a| api::OriginAction {
        // BGP ORIGIN: 0=IGP, 1=EGP, 2=Incomplete → API OriginType: Igp=1, Egp=2, Incomplete=3
        origin: (a.origin as i32) + 1,
    });

    s.actions = Some(api::Actions {
        route_action: my.disposition.map_or(0, |a| a as i32),
        nexthop,
        community,
        local_pref,
        med,
        as_prepend,
        ext_community,
        large_community,
        origin_action,
    });
    s
}

fn community_action_type_to_i32(t: &rustybgp_table::CommunityActionType) -> i32 {
    use rustybgp_table::CommunityActionType;
    match t {
        CommunityActionType::Add => api::community_action::Type::Add as i32,
        CommunityActionType::Remove => api::community_action::Type::Remove as i32,
        CommunityActionType::Replace => api::community_action::Type::Replace as i32,
    }
}

fn ext_community_bytes_to_string(c: &[u8; 8]) -> Option<String> {
    let prefix = match c[1] {
        0x02 => "rt",
        0x03 => "soo",
        _ => return None,
    };
    match c[0] {
        0x00 => {
            let asn = u16::from_be_bytes([c[2], c[3]]);
            let local = u32::from_be_bytes([c[4], c[5], c[6], c[7]]);
            Some(format!("{}:{}:{}", prefix, asn, local))
        }
        0x01 => {
            let addr = Ipv4Addr::new(c[2], c[3], c[4], c[5]);
            let local = u16::from_be_bytes([c[6], c[7]]);
            Some(format!("{}:{}:{}", prefix, addr, local))
        }
        _ => None,
    }
}

fn match_option_to_i32(opt: &rustybgp_table::MatchOption) -> i32 {
    use rustybgp_table::MatchOption;
    match opt {
        MatchOption::Any => 0,
        MatchOption::All => 1,
        MatchOption::Invert => 2,
    }
}

pub(crate) fn policy_to_api(p: &rustybgp_table::Policy) -> api::Policy {
    api::Policy {
        name: p.name.to_string(),
        statements: p.statements.iter().map(|x| statement_to_api(x)).collect(),
    }
}

pub(crate) fn policy_assignment_to_api(
    pa: &rustybgp_table::PolicyAssignment,
    dir: i32,
) -> api::PolicyAssignment {
    api::PolicyAssignment {
        name: pa.name.to_string(),
        policies: pa.policies.iter().map(|x| policy_to_api(x)).collect(),
        direction: dir,
        default_action: pa.disposition as i32,
    }
}

pub(crate) fn defined_set_to_api(d: rustybgp_table::DefinedSetRef<'_>) -> api::DefinedSet {
    use rustybgp_table::DefinedSetRef;
    match d {
        DefinedSetRef::Prefix(name, set) => api::DefinedSet {
            defined_type: api::DefinedType::Prefix as i32,
            name: name.to_string(),
            list: Vec::new(),
            prefixes: set
                .v4
                .iter()
                .map(|(_, _, v)| api::Prefix {
                    ip_prefix: v.net.to_string(),
                    mask_length_min: v.min_length as u32,
                    mask_length_max: v.max_length as u32,
                })
                .collect(),
        },
        DefinedSetRef::Neighbor(name, set) => api::DefinedSet {
            defined_type: api::DefinedType::Neighbor as i32,
            name: name.to_string(),
            list: set.sets.iter().map(|x| x.to_string()).collect(),
            prefixes: Vec::new(),
        },
        DefinedSetRef::AsPath(name, set) => {
            let mut list: Vec<String> = set.single_sets.iter().map(|x| x.to_string()).collect();
            list.append(&mut set.sets.iter().map(|x| x.to_string()).collect());
            api::DefinedSet {
                defined_type: api::DefinedType::AsPath as i32,
                name: name.to_string(),
                list,
                prefixes: Vec::new(),
            }
        }
        DefinedSetRef::Community(name, set) => api::DefinedSet {
            defined_type: api::DefinedType::Community as i32,
            name: name.to_string(),
            list: set.sets.iter().map(|x| x.to_string()).collect(),
            prefixes: Vec::new(),
        },
        DefinedSetRef::ExtCommunity(name, set) => api::DefinedSet {
            defined_type: api::DefinedType::ExtCommunity as i32,
            name: name.to_string(),
            list: set.sets.iter().map(|x| x.to_string()).collect(),
            prefixes: Vec::new(),
        },
        DefinedSetRef::LargeCommunity(name, set) => api::DefinedSet {
            defined_type: api::DefinedType::LargeCommunity as i32,
            name: name.to_string(),
            list: set.sets.iter().map(|x| x.to_string()).collect(),
            prefixes: Vec::new(),
        },
    }
}

pub(crate) fn conditions_from_api(
    conditions: Option<api::Conditions>,
) -> Result<Vec<rustybgp_table::ConditionConfig>, rustybgp_table::TableError> {
    use rustybgp_table::{
        Comparison, ConditionConfig, MatchOption, RouteType, RpkiValidationState, TableError,
    };
    use std::net::IpAddr;
    use std::str::FromStr;

    let Some(conditions) = conditions else {
        return Ok(Vec::new());
    };
    let mut v = Vec::new();
    if let Some(m) = conditions.prefix_set {
        v.push(ConditionConfig::PrefixSet(
            m.name,
            MatchOption::try_from(m.r#type)?,
        ));
    }
    if let Some(m) = conditions.neighbor_set {
        v.push(ConditionConfig::NeighborSet(
            m.name,
            MatchOption::try_from(m.r#type)?,
        ));
    }
    if let Some(m) = conditions.as_path_set {
        v.push(ConditionConfig::AsPathSet(
            m.name,
            MatchOption::try_from(m.r#type)?,
        ));
    }
    if let Some(m) = conditions.as_path_length {
        v.push(ConditionConfig::AsPathLength(
            Comparison::from(m.r#type),
            m.length,
        ));
    }
    if let Some(m) = conditions.community_set {
        v.push(ConditionConfig::CommunitySet(
            m.name,
            MatchOption::try_from(m.r#type)?,
        ));
    }
    if let Some(m) = conditions.ext_community_set {
        v.push(ConditionConfig::ExtCommunitySet(
            m.name,
            MatchOption::try_from(m.r#type)?,
        ));
    }
    if let Some(m) = conditions.large_community_set {
        v.push(ConditionConfig::LargeCommunitySet(
            m.name,
            MatchOption::try_from(m.r#type)?,
        ));
    }
    let nexthops: Vec<IpAddr> = conditions
        .next_hop_in_list
        .iter()
        .filter_map(|p| IpAddr::from_str(p).ok())
        .collect();
    if !nexthops.is_empty() {
        if nexthops.len() != conditions.next_hop_in_list.len() {
            return Err(TableError::InvalidArgument(
                "invalid nexthop condition".to_string(),
            ));
        }
        v.push(ConditionConfig::Nexthop(nexthops));
    }
    if conditions.rpki_result != api::ValidationState::None as i32 {
        let s = match api::ValidationState::try_from(conditions.rpki_result) {
            Ok(api::ValidationState::NotFound) => RpkiValidationState::NotFound,
            Ok(api::ValidationState::Valid) => RpkiValidationState::Valid,
            Ok(api::ValidationState::Invalid) => RpkiValidationState::Invalid,
            _ => {
                return Err(TableError::InvalidArgument(
                    "invalid rpki condition".to_string(),
                ));
            }
        };
        v.push(ConditionConfig::Rpki(s));
    }
    if let Some(m) = conditions.local_pref_eq {
        v.push(ConditionConfig::LocalPrefEq(m.value));
    }
    if let Some(m) = conditions.med_eq {
        v.push(ConditionConfig::MedEq(m.value));
    }
    // API OriginType: Igp=1, Egp=2, Incomplete=3; BGP ORIGIN: 0=IGP, 1=EGP, 2=Incomplete
    if conditions.origin != api::OriginType::Unspecified as i32 {
        match api::OriginType::try_from(conditions.origin) {
            Ok(api::OriginType::Igp) => v.push(ConditionConfig::Origin(0)),
            Ok(api::OriginType::Egp) => v.push(ConditionConfig::Origin(1)),
            Ok(api::OriginType::Incomplete) => v.push(ConditionConfig::Origin(2)),
            _ => {
                return Err(TableError::InvalidArgument(
                    "invalid origin condition".to_string(),
                ));
            }
        }
    }
    use api::conditions::RouteType as ApiRouteType;
    match ApiRouteType::try_from(conditions.route_type) {
        Ok(ApiRouteType::Internal) => v.push(ConditionConfig::RouteType(RouteType::Internal)),
        Ok(ApiRouteType::External) => v.push(ConditionConfig::RouteType(RouteType::External)),
        Ok(ApiRouteType::Local) => v.push(ConditionConfig::RouteType(RouteType::Local)),
        _ => {}
    }
    if let Some(m) = conditions.community_count {
        v.push(ConditionConfig::CommunityCount(
            Comparison::from(m.r#type),
            m.count,
        ));
    }
    if !conditions.afi_safi_in.is_empty() {
        let families: Vec<rustybgp_packet::Family> = conditions
            .afi_safi_in
            .iter()
            .map(|f| rustybgp_packet::Family::new((f.afi as u32) << 16 | f.safi as u32))
            .collect();
        v.push(ConditionConfig::AfiSafiIn(families));
    }
    Ok(v)
}

fn parse_community_value(s: &str) -> Option<u32> {
    if let Ok(v) = s.parse::<u32>() {
        return Some(v);
    }
    match s.to_lowercase().as_str() {
        "graceful-shutdown" => return Some(0xffff_0000),
        "accept-own" => return Some(0xffff_0001),
        "llgr-stale" => return Some(0xffff_0006),
        "no-llgr" => return Some(0xffff_0007),
        "blackhole" => return Some(0xffff_029a),
        "no-export" => return Some(0xffff_ff01),
        "no-advertise" => return Some(0xffff_ff02),
        "no-export-subconfed" => return Some(0xffff_ff03),
        "no-peer" => return Some(0xffff_ff04),
        _ => {}
    }
    let parts: Vec<&str> = s.splitn(2, ':').collect();
    if parts.len() == 2 {
        let high: u16 = parts[0].parse().ok()?;
        let low: u16 = parts[1].parse().ok()?;
        return Some(((high as u32) << 16) | low as u32);
    }
    None
}

fn parse_ext_community_value(s: &str) -> Option<[u8; 8]> {
    let (sub_type, rest) = if let Some(r) = s.strip_prefix("rt:") {
        (0x02u8, r)
    } else if let Some(r) = s.strip_prefix("soo:") {
        (0x03u8, r)
    } else {
        return None;
    };
    // Try "ASN:local-admin" with 2-octet ASN
    let parts: Vec<&str> = rest.splitn(2, ':').collect();
    if parts.len() != 2 {
        return None;
    }
    if let Ok(asn) = parts[0].parse::<u16>() {
        let local: u32 = parts[1].parse().ok()?;
        let mut bytes = [0u8; 8];
        bytes[0] = 0x00; // Transitive Two-Octet AS Specific
        bytes[1] = sub_type;
        bytes[2] = (asn >> 8) as u8;
        bytes[3] = asn as u8;
        bytes[4] = (local >> 24) as u8;
        bytes[5] = (local >> 16) as u8;
        bytes[6] = (local >> 8) as u8;
        bytes[7] = local as u8;
        return Some(bytes);
    }
    // Try "IPv4:local-admin"
    if let Ok(addr) = parts[0].parse::<Ipv4Addr>() {
        let local: u16 = parts[1].parse().ok()?;
        let mut bytes = [0u8; 8];
        bytes[0] = 0x01; // Transitive IPv4 Address Specific
        bytes[1] = sub_type;
        let octets = addr.octets();
        bytes[2..6].copy_from_slice(&octets);
        bytes[6] = (local >> 8) as u8;
        bytes[7] = local as u8;
        return Some(bytes);
    }
    None
}

fn ext_community_action_from_api(
    ca: api::CommunityAction,
) -> Option<rustybgp_table::ExtCommunityAction> {
    use rustybgp_table::CommunityActionType;
    let action_type = match api::community_action::Type::try_from(ca.r#type) {
        Ok(api::community_action::Type::Add) => CommunityActionType::Add,
        Ok(api::community_action::Type::Remove) => CommunityActionType::Remove,
        Ok(api::community_action::Type::Replace) => CommunityActionType::Replace,
        _ => return None,
    };
    let communities: Vec<[u8; 8]> = ca
        .communities
        .iter()
        .filter_map(|s| parse_ext_community_value(s))
        .collect();
    Some(rustybgp_table::ExtCommunityAction {
        action_type,
        communities,
    })
}

fn parse_large_community_value(s: &str) -> Option<(u32, u32, u32)> {
    let parts: Vec<&str> = s.splitn(3, ':').collect();
    if parts.len() != 3 {
        return None;
    }
    let ga: u32 = parts[0].parse().ok()?;
    let ld1: u32 = parts[1].parse().ok()?;
    let ld2: u32 = parts[2].parse().ok()?;
    Some((ga, ld1, ld2))
}

fn large_community_action_from_api(
    ca: api::CommunityAction,
) -> Option<rustybgp_table::LargeCommunityAction> {
    use rustybgp_table::CommunityActionType;
    let action_type = match api::community_action::Type::try_from(ca.r#type) {
        Ok(api::community_action::Type::Add) => CommunityActionType::Add,
        Ok(api::community_action::Type::Remove) => CommunityActionType::Remove,
        Ok(api::community_action::Type::Replace) => CommunityActionType::Replace,
        _ => return None,
    };
    let communities: Vec<(u32, u32, u32)> = ca
        .communities
        .iter()
        .filter_map(|s| parse_large_community_value(s))
        .collect();
    Some(rustybgp_table::LargeCommunityAction {
        action_type,
        communities,
    })
}

fn community_action_from_api(ca: api::CommunityAction) -> Option<rustybgp_table::CommunityAction> {
    use rustybgp_table::CommunityActionType;
    let action_type = match api::community_action::Type::try_from(ca.r#type) {
        Ok(api::community_action::Type::Add) => CommunityActionType::Add,
        Ok(api::community_action::Type::Remove) => CommunityActionType::Remove,
        Ok(api::community_action::Type::Replace) => CommunityActionType::Replace,
        _ => return None,
    };
    let communities: Vec<u32> = ca
        .communities
        .iter()
        .filter_map(|s| parse_community_value(s))
        .collect();
    Some(rustybgp_table::CommunityAction {
        action_type,
        communities,
    })
}

pub(crate) fn disposition_from_api(
    actions: Option<api::Actions>,
) -> Result<
    (Option<rustybgp_table::Disposition>, rustybgp_table::Actions),
    rustybgp_table::TableError,
> {
    use rustybgp_table::{Disposition, NexthopAction, TableError};

    let Some(actions) = actions else {
        return Ok((None, rustybgp_table::Actions::default()));
    };

    let disposition = match api::RouteAction::try_from(actions.route_action) {
        Ok(api::RouteAction::Accept) => Some(Disposition::Accept),
        Ok(api::RouteAction::Reject) => Some(Disposition::Reject),
        Ok(_) => None,
        Err(_) => {
            return Err(TableError::InvalidArgument("invalid action".to_string()));
        }
    };

    let nexthop = actions.nexthop.and_then(|nh| {
        if nh.self_ {
            Some(NexthopAction::PeerSelf)
        } else if nh.unchanged {
            Some(NexthopAction::Unchanged)
        } else if !nh.address.is_empty() {
            nh.address
                .parse::<std::net::IpAddr>()
                .ok()
                .map(NexthopAction::Address)
        } else {
            None
        }
    });

    let community = actions.community.and_then(community_action_from_api);

    let local_pref = actions
        .local_pref
        .map(|lp| rustybgp_table::LocalPrefAction { value: lp.value });

    let med = actions.med.and_then(|m| {
        let action_type = match api::med_action::Type::try_from(m.r#type) {
            Ok(api::med_action::Type::Mod) => rustybgp_table::MedActionType::Mod,
            Ok(api::med_action::Type::Replace) => rustybgp_table::MedActionType::Replace,
            _ => return None,
        };
        Some(rustybgp_table::MedAction {
            action_type,
            value: m.value,
        })
    });

    let as_prepend = actions
        .as_prepend
        .map(|ap| rustybgp_table::AsPrependAction {
            asn: ap.asn,
            repeat: ap.repeat,
            use_left_most: ap.use_left_most,
        });

    let ext_community = actions
        .ext_community
        .and_then(ext_community_action_from_api);

    let large_community = actions
        .large_community
        .and_then(large_community_action_from_api);

    let origin = actions.origin_action.and_then(|oa| {
        let origin = match api::OriginType::try_from(oa.origin) {
            Ok(api::OriginType::Igp) => 0u8,
            Ok(api::OriginType::Egp) => 1u8,
            Ok(api::OriginType::Incomplete) => 2u8,
            _ => return None,
        };
        Some(rustybgp_table::OriginAction { origin })
    });

    Ok((
        disposition,
        rustybgp_table::Actions {
            nexthop,
            community,
            local_pref,
            med,
            as_prepend,
            ext_community,
            large_community,
            origin,
        },
    ))
}

pub(crate) fn defined_set_from_api(
    set: api::DefinedSet,
) -> Result<rustybgp_table::DefinedSetConfig, rustybgp_table::TableError> {
    use rustybgp_table::{DefinedSetConfig, PrefixConfig, TableError};

    match api::DefinedType::try_from(set.defined_type) {
        Ok(api::DefinedType::Prefix) => Ok(DefinedSetConfig::Prefix {
            name: set.name,
            prefixes: set
                .prefixes
                .into_iter()
                .map(|p| PrefixConfig {
                    ip_prefix: p.ip_prefix,
                    mask_length_min: p.mask_length_min as u8,
                    mask_length_max: p.mask_length_max as u8,
                })
                .collect(),
        }),
        Ok(api::DefinedType::Neighbor) => Ok(DefinedSetConfig::Neighbor {
            name: set.name,
            neighbors: set.list,
        }),
        Ok(api::DefinedType::AsPath) => Ok(DefinedSetConfig::AsPath {
            name: set.name,
            patterns: set.list,
        }),
        Ok(api::DefinedType::Community) => Ok(DefinedSetConfig::Community {
            name: set.name,
            patterns: set.list,
        }),
        Ok(api::DefinedType::ExtCommunity) => Ok(DefinedSetConfig::ExtCommunity {
            name: set.name,
            patterns: set.list,
        }),
        Ok(api::DefinedType::LargeCommunity) => Ok(DefinedSetConfig::LargeCommunity {
            name: set.name,
            patterns: set.list,
        }),
        _ => Err(TableError::InvalidArgument(
            "unsupported defined set type".to_string(),
        )),
    }
}

pub(crate) fn defined_set_kind_from_api(
    defined_type: i32,
) -> Result<rustybgp_table::DefinedSetKind, rustybgp_table::TableError> {
    use rustybgp_table::{DefinedSetKind, TableError};
    match api::DefinedType::try_from(defined_type) {
        Ok(api::DefinedType::Prefix) => Ok(DefinedSetKind::Prefix),
        Ok(api::DefinedType::Neighbor) => Ok(DefinedSetKind::Neighbor),
        Ok(api::DefinedType::AsPath) => Ok(DefinedSetKind::AsPath),
        Ok(api::DefinedType::Community) => Ok(DefinedSetKind::Community),
        Ok(api::DefinedType::ExtCommunity) => Ok(DefinedSetKind::ExtCommunity),
        Ok(api::DefinedType::LargeCommunity) => Ok(DefinedSetKind::LargeCommunity),
        _ => Err(TableError::InvalidArgument(
            "unsupported defined set type".to_string(),
        )),
    }
}

pub(crate) fn policy_assignment_from_api(
    req: api::PolicyAssignment,
) -> Result<
    (
        String,
        rustybgp_table::PolicyDirection,
        rustybgp_table::Disposition,
        Vec<String>,
    ),
    rustybgp_table::TableError,
> {
    use rustybgp_table::{Disposition, PolicyDirection, TableError};

    let direction = match api::PolicyDirection::try_from(req.direction) {
        Ok(api::PolicyDirection::Import) => PolicyDirection::Import,
        Ok(api::PolicyDirection::Export) => PolicyDirection::Export,
        _ => {
            return Err(TableError::InvalidArgument(
                "invalid policy direction".to_string(),
            ));
        }
    };
    let default_action = match api::RouteAction::try_from(req.default_action) {
        Ok(api::RouteAction::Accept) => Disposition::Accept,
        _ => Disposition::Reject,
    };
    let policy_names: Vec<String> = req.policies.into_iter().map(|p| p.name).collect();
    Ok((req.name, direction, default_action, policy_names))
}

pub(crate) fn routing_table_state_to_api(s: rustybgp_table::TableState) -> api::GetTableResponse {
    api::GetTableResponse {
        num_destination: s.num_destination as u64,
        num_path: s.num_path as u64,
        num_accepted: s.num_accepted as u64,
    }
}

/// Controls which binary-encoded fields are populated in each `api::Path`.
pub(crate) struct PathBinaryFlags {
    /// Populate `nlri_binary` with the BGP wire encoding of the NLRI.
    pub nlri_binary: bool,
    /// Populate `pattrs_binary` with the BGP wire encoding of each attribute.
    pub attr_binary: bool,
    /// When true, clear `nlri` and `pattrs` so only the binary fields are present.
    pub only_binary: bool,
}

pub(crate) fn destination_to_api(
    d: rustybgp_table::DestinationEntry,
    family: Family,
    binary: &PathBinaryFlags,
) -> api::Destination {
    use crate::proto::ToApi;
    api::Destination {
        prefix: d.net.to_string(),
        paths: d
            .paths
            .into_iter()
            .map(|p| api::Path {
                nlri: if binary.only_binary {
                    None
                } else {
                    Some(nlri_to_api(&d.net))
                },
                family: Some(family_to_api(family)),
                identifier: p.remote_path_id,
                age: Some(p.timestamp.to_api()),
                pattrs: if binary.only_binary {
                    vec![]
                } else {
                    p.attr.iter().map(attr_to_api).collect()
                },
                validation: p.validation.map(rpki_validation_to_api),
                stale: p.stale,
                filtered: p.filtered,
                nlri_binary: if binary.nlri_binary {
                    d.net.encode_to_bytes()
                } else {
                    vec![]
                },
                pattrs_binary: if binary.attr_binary {
                    p.attr.iter().map(|a| a.encode_to_bytes()).collect()
                } else {
                    vec![]
                },
                ..Default::default()
            })
            .collect(),
    }
}

pub(crate) fn roa_to_api(net: &IpNet, roa: &rustybgp_table::Roa) -> api::Roa {
    let (prefix, mask) = match net {
        IpNet::V4(net) => (net.addr.to_string(), net.mask),
        IpNet::V6(net) => (net.addr.to_string(), net.mask),
    };
    api::Roa {
        asn: roa.as_number,
        prefixlen: mask as u32,
        maxlen: roa.max_length as u32,
        prefix,
        conf: Some(api::RpkiConf {
            address: roa.source.to_string(),
            remote_port: 0,
        }),
    }
}

fn rpki_validation_to_api(v: rustybgp_table::RpkiValidation) -> api::Validation {
    let mut result = api::Validation {
        state: match v.state {
            rustybgp_table::RpkiValidationState::NotFound => api::ValidationState::NotFound as i32,
            rustybgp_table::RpkiValidationState::Valid => api::ValidationState::Valid as i32,
            rustybgp_table::RpkiValidationState::Invalid => api::ValidationState::Invalid as i32,
        },
        reason: match v.reason {
            rustybgp_table::RpkiValidationReason::None => api::validation::Reason::None as i32,
            rustybgp_table::RpkiValidationReason::Asn => api::validation::Reason::Asn as i32,
            rustybgp_table::RpkiValidationReason::Length => api::validation::Reason::Length as i32,
        },
        matched: Vec::new(),
        unmatched_asn: Vec::new(),
        unmatched_length: Vec::new(),
    };
    result.matched = v
        .matched
        .iter()
        .map(|(net, roa)| roa_to_api(net, roa))
        .collect();
    result.unmatched_asn = v
        .unmatched_asn
        .iter()
        .map(|(net, roa)| roa_to_api(net, roa))
        .collect();
    result.unmatched_length = v
        .unmatched_length
        .iter()
        .map(|(net, roa)| roa_to_api(net, roa))
        .collect();
    result
}

fn prefix_set_to_api(p: &config::PrefixSet) -> Result<api::DefinedSet, Error> {
    let name = p
        .prefix_set_name
        .as_ref()
        .ok_or_else(|| Error::InvalidConfiguration("empty name".to_string()))?
        .to_string();

    let mut prefixes = Vec::new();
    let caps_re = Regex::new(r"^([0-9]+)\.\.([0-9]+)$").unwrap();
    for s in p
        .prefix_list
        .as_ref()
        .ok_or_else(|| Error::InvalidConfiguration("empty prefix list".to_string()))?
    {
        let ip_prefix = s
            .ip_prefix
            .as_ref()
            .ok_or_else(|| Error::InvalidConfiguration("empty prefix".to_string()))?
            .to_string();
        let range = s
            .masklength_range
            .as_ref()
            .ok_or_else(|| Error::InvalidConfiguration("empty mask".to_string()))?;

        let caps = caps_re
            .captures(range)
            .ok_or_else(|| Error::InvalidConfiguration("invalid mask format".to_string()))?;

        if caps.len() != 3 {
            return Err(Error::InvalidConfiguration(
                "invalid prefix mask format".to_string(),
            ));
        }
        let mask_length_min = caps[1]
            .parse()
            .map_err(|_| Error::InvalidConfiguration("invalid mask format".to_string()))?;
        let mask_length_max = caps[2]
            .parse()
            .map_err(|_| Error::InvalidConfiguration("invalid mask format".to_string()))?;
        prefixes.push(api::Prefix {
            ip_prefix,
            mask_length_min,
            mask_length_max,
        });
    }

    Ok(api::DefinedSet {
        defined_type: api::DefinedType::Prefix as i32,
        name,
        list: Vec::new(),
        prefixes,
    })
}

fn bgp_defined_sets_to_api(sets: &config::BgpDefinedSets) -> Result<Vec<api::DefinedSet>, Error> {
    let mut v = Vec::new();
    if let Some(sets) = sets.as_path_sets.as_ref() {
        for set in sets {
            let name = set
                .as_path_set_name
                .as_ref()
                .ok_or_else(|| Error::InvalidConfiguration("empty name".to_string()))?
                .to_string();
            let list = set
                .as_path_list
                .as_ref()
                .ok_or_else(|| Error::InvalidConfiguration("empty as path list".to_string()))?
                .to_vec();
            v.push(api::DefinedSet {
                defined_type: api::DefinedType::AsPath as i32,
                name,
                list,
                prefixes: Vec::new(),
            })
        }
    }
    if let Some(sets) = sets.community_sets.as_ref() {
        for set in sets {
            let name = set
                .community_set_name
                .as_ref()
                .ok_or_else(|| Error::InvalidConfiguration("empty name".to_string()))?
                .to_string();
            let list = set
                .community_list
                .as_ref()
                .map(|l| l.to_vec())
                .unwrap_or_default();
            v.push(api::DefinedSet {
                defined_type: api::DefinedType::Community as i32,
                name,
                list,
                prefixes: Vec::new(),
            })
        }
    }
    if let Some(sets) = sets.ext_community_sets.as_ref() {
        for set in sets {
            let name = set
                .ext_community_set_name
                .as_ref()
                .ok_or_else(|| Error::InvalidConfiguration("empty name".to_string()))?
                .to_string();
            let list = set
                .ext_community_list
                .as_ref()
                .map(|l| l.to_vec())
                .unwrap_or_default();
            v.push(api::DefinedSet {
                defined_type: api::DefinedType::ExtCommunity as i32,
                name,
                list,
                prefixes: Vec::new(),
            })
        }
    }
    if let Some(sets) = sets.large_community_sets.as_ref() {
        for set in sets {
            let name = set
                .large_community_set_name
                .as_ref()
                .ok_or_else(|| Error::InvalidConfiguration("empty name".to_string()))?
                .to_string();
            let list = set
                .large_community_list
                .as_ref()
                .map(|l| l.to_vec())
                .unwrap_or_default();
            v.push(api::DefinedSet {
                defined_type: api::DefinedType::LargeCommunity as i32,
                name,
                list,
                prefixes: Vec::new(),
            })
        }
    }
    Ok(v)
}

fn defined_sets_to_api(sets: &config::DefinedSets) -> Result<Vec<api::DefinedSet>, Error> {
    let mut v = Vec::new();
    if let Some(sets) = &sets.prefix_sets {
        for s in sets {
            v.push(prefix_set_to_api(s)?);
        }
    }
    if let Some(sets) = &sets.neighbor_sets {
        for set in sets {
            let name = set
                .neighbor_set_name
                .as_ref()
                .ok_or_else(|| Error::InvalidConfiguration("empty name".to_string()))?
                .to_string();
            let list = set
                .neighbor_info_list
                .as_ref()
                .map(|l| l.to_vec())
                .unwrap_or_default();
            v.push(api::DefinedSet {
                defined_type: api::DefinedType::Neighbor as i32,
                name,
                list,
                prefixes: Vec::new(),
            });
        }
    }
    if let Some(sets) = &sets.bgp_defined_sets {
        v.append(&mut bgp_defined_sets_to_api(sets)?);
    }
    Ok(v)
}

fn match_set_options_to_i32(o: &config::MatchSetOptionsType) -> i32 {
    match o {
        config::MatchSetOptionsType::Any => 0,
        config::MatchSetOptionsType::All => 1,
        config::MatchSetOptionsType::Invert => 2,
    }
}

fn match_set_options_restricted_to_i32(o: &config::MatchSetOptionsRestrictedType) -> i32 {
    match o {
        config::MatchSetOptionsRestrictedType::Any => 0,
        config::MatchSetOptionsRestrictedType::Invert => 2,
    }
}

fn attribute_comparison_to_i32(c: &config::AttributeComparison) -> i32 {
    match c {
        config::AttributeComparison::AttributeEq => 0,
        config::AttributeComparison::AttributeGe => 1,
        config::AttributeComparison::AttributeLe => 2,
        config::AttributeComparison::Eq => 0,
        config::AttributeComparison::Ge => 1,
        config::AttributeComparison::Le => 2,
    }
}

fn conditions_to_api(c: &config::Conditions) -> Result<api::Conditions, Error> {
    let mut conditions = api::Conditions {
        // rpki_result uses ValidationState::None (= 1) as the "no condition" sentinel.
        // Default::default() gives 0 (Unspecified) which conditions_from_api treats as an error.
        rpki_result: api::ValidationState::None as i32,
        ..Default::default()
    };
    if let Some(set) = c.match_prefix_set.as_ref() {
        let name = set
            .prefix_set
            .as_ref()
            .ok_or_else(|| Error::InvalidConfiguration("empty name".to_string()))?
            .to_string();
        let set_option = set
            .match_set_options
            .as_ref()
            .ok_or_else(|| Error::InvalidConfiguration("empty match option".to_string()))?;
        conditions.prefix_set = Some(api::MatchSet {
            r#type: match_set_options_restricted_to_i32(set_option),
            name,
        });
    }
    if let Some(set) = c.match_neighbor_set.as_ref() {
        let name = set
            .neighbor_set
            .as_ref()
            .ok_or_else(|| Error::InvalidConfiguration("empty name".to_string()))?
            .to_string();
        let set_option = set
            .match_set_options
            .as_ref()
            .ok_or_else(|| Error::InvalidConfiguration("empty match option".to_string()))?;
        conditions.neighbor_set = Some(api::MatchSet {
            r#type: match_set_options_restricted_to_i32(set_option),
            name,
        });
    }
    if let Some(bgp) = c.bgp_conditions.as_ref() {
        if let Some(set) = bgp.match_as_path_set.as_ref() {
            let match_type = match &set.match_set_options {
                Some(v) => match_set_options_to_i32(v),
                None => 0,
            };
            if let Some(name) = &set.as_path_set {
                conditions.as_path_set = Some(api::MatchSet {
                    r#type: match_type,
                    name: name.to_string(),
                });
            }
        }
        if let Some(l) = bgp.as_path_length.as_ref() {
            let op = l.operator.as_ref().ok_or_else(|| {
                Error::InvalidConfiguration("empty as path length operator".to_string())
            })?;
            let length = l
                .value
                .ok_or_else(|| Error::InvalidConfiguration("empty as path length".to_string()))?;
            conditions.as_path_length = Some(api::AsPathLength {
                r#type: attribute_comparison_to_i32(op),
                length,
            });
        }
        if let Some(set) = bgp.match_community_set.as_ref()
            && let Some(name) = &set.community_set
        {
            let match_type = match &set.match_set_options {
                Some(v) => match_set_options_to_i32(v),
                None => 0,
            };
            conditions.community_set = Some(api::MatchSet {
                r#type: match_type,
                name: name.clone(),
            });
        }
        if let Some(set) = bgp.match_ext_community_set.as_ref()
            && let Some(name) = &set.ext_community_set
        {
            let match_type = match &set.match_set_options {
                Some(v) => match_set_options_to_i32(v),
                None => 0,
            };
            conditions.ext_community_set = Some(api::MatchSet {
                r#type: match_type,
                name: name.clone(),
            });
        }
        if let Some(set) = bgp.match_large_community_set.as_ref()
            && let Some(name) = &set.large_community_set
        {
            let match_type = match &set.match_set_options {
                Some(v) => match_set_options_to_i32(v),
                None => 0,
            };
            conditions.large_community_set = Some(api::MatchSet {
                r#type: match_type,
                name: name.clone(),
            });
        }
        if let Some(nexthops) = bgp.next_hop_in_list.as_ref() {
            conditions.next_hop_in_list = nexthops.iter().map(|a| a.to_string()).collect();
        }
        if let Some(rpki) = bgp.rpki_validation_result.as_ref() {
            conditions.rpki_result = match rpki {
                config::RpkiValidationResultType::None => 0,
                config::RpkiValidationResultType::NotFound => api::ValidationState::NotFound as i32,
                config::RpkiValidationResultType::Valid => api::ValidationState::Valid as i32,
                config::RpkiValidationResultType::Invalid => api::ValidationState::Invalid as i32,
            };
        }
        if let Some(rt) = bgp.route_type.as_ref() {
            use api::conditions::RouteType as ApiRouteType;
            conditions.route_type = match rt {
                config::RouteType::None => ApiRouteType::Unspecified as i32,
                config::RouteType::Internal => ApiRouteType::Internal as i32,
                config::RouteType::External => ApiRouteType::External as i32,
                config::RouteType::Local => ApiRouteType::Local as i32,
            };
        }
    }
    Ok(conditions)
}

fn route_disposition_to_i32(r: &config::RouteDisposition) -> i32 {
    match r {
        config::RouteDisposition::None => 0,
        config::RouteDisposition::AcceptRoute => 1,
        config::RouteDisposition::RejectRoute => 2,
    }
}

fn community_option_str_to_i32(opt: Option<&str>) -> Result<i32, Error> {
    match opt {
        Some("add") => Ok(1),
        Some("remove") => Ok(2),
        Some("replace") => Ok(3),
        _ => Err(Error::InvalidConfiguration(
            "missing or invalid community option".to_string(),
        )),
    }
}

fn actions_from_config(a: &config::Actions) -> Result<api::Actions, Error> {
    let route_action = match a.route_disposition.as_ref() {
        Some(r) => route_disposition_to_i32(r),
        None => 0,
    };
    let nexthop = a
        .bgp_actions
        .as_ref()
        .and_then(|ba| ba.set_next_hop.as_ref())
        .map(|nh| {
            let s = nh.as_str();
            api::NexthopAction {
                self_: s == "self",
                unchanged: s == "unchanged",
                address: if s != "self" && s != "unchanged" {
                    s.to_string()
                } else {
                    String::new()
                },
                peer_address: false,
            }
        });

    let mut community = None;
    let mut ext_community = None;
    let mut large_community = None;
    let mut local_pref = None;
    let mut med = None;
    let mut as_prepend = None;
    let mut origin_action = None;

    if let Some(ba) = a.bgp_actions.as_ref() {
        if let Some(sc) = ba.set_community.as_ref() {
            let action_type = community_option_str_to_i32(sc.options.as_deref())?;
            let communities = sc
                .set_community_method
                .as_ref()
                .and_then(|m| m.communities_list.as_ref())
                .cloned()
                .unwrap_or_default();
            community = Some(api::CommunityAction {
                r#type: action_type,
                communities,
            });
        }
        if let Some(sec) = ba.set_ext_community.as_ref() {
            let action_type = community_option_str_to_i32(sec.options.as_deref())?;
            let communities = sec
                .set_ext_community_method
                .as_ref()
                .and_then(|m| m.communities_list.as_ref())
                .cloned()
                .unwrap_or_default();
            ext_community = Some(api::CommunityAction {
                r#type: action_type,
                communities,
            });
        }
        if let Some(slc) = ba.set_large_community.as_ref() {
            let action_type = match slc.options.as_ref() {
                Some(config::BgpSetCommunityOptionType::Add) => 1,
                Some(config::BgpSetCommunityOptionType::Remove) => 2,
                Some(config::BgpSetCommunityOptionType::Replace) => 3,
                None => {
                    return Err(Error::InvalidConfiguration(
                        "missing large community option".to_string(),
                    ));
                }
            };
            let communities = slc
                .set_large_community_method
                .as_ref()
                .and_then(|m| m.communities_list.as_ref())
                .cloned()
                .unwrap_or_default();
            large_community = Some(api::CommunityAction {
                r#type: action_type,
                communities,
            });
        }
        if let Some(lp) = ba.set_local_pref {
            local_pref = Some(api::LocalPrefAction { value: lp });
        }
        if let Some(med_str) = ba.set_med.as_ref() {
            let (med_type, value) = if let Some(s) = med_str.strip_prefix('+') {
                let v: i64 = s
                    .parse()
                    .map_err(|_| Error::InvalidConfiguration("invalid MED value".to_string()))?;
                (1, v)
            } else if med_str.starts_with('-') {
                let v: i64 = med_str
                    .parse()
                    .map_err(|_| Error::InvalidConfiguration("invalid MED value".to_string()))?;
                (1, v)
            } else {
                let v: i64 = med_str
                    .parse()
                    .map_err(|_| Error::InvalidConfiguration("invalid MED value".to_string()))?;
                (2, v)
            };
            med = Some(api::MedAction {
                r#type: med_type,
                value,
            });
        }
        if let Some(ap) = ba.set_as_path_prepend.as_ref() {
            let repeat = ap.repeat_n.unwrap_or(0) as u32;
            let (asn, use_left_most) = match ap.r#as.as_deref() {
                Some("last-as") => (0u32, true),
                Some(s) => (
                    s.parse::<u32>().map_err(|_| {
                        Error::InvalidConfiguration("invalid ASN in as-prepend".to_string())
                    })?,
                    false,
                ),
                None => (0, false),
            };
            as_prepend = Some(api::AsPrependAction {
                asn,
                repeat,
                use_left_most,
            });
        }
        if let Some(origin) = ba.set_route_origin.as_ref() {
            let origin_val = match origin {
                config::BgpOriginAttrType::Igp => api::OriginType::Igp as i32,
                config::BgpOriginAttrType::Egp => api::OriginType::Egp as i32,
                config::BgpOriginAttrType::Incomplete => api::OriginType::Incomplete as i32,
            };
            origin_action = Some(api::OriginAction { origin: origin_val });
        }
    }

    Ok(api::Actions {
        route_action,
        community,
        med,
        as_prepend,
        ext_community,
        nexthop,
        local_pref,
        large_community,
        origin_action,
    })
}

fn statement_from_config(s: &config::Statement) -> Result<api::Statement, Error> {
    let u = Uuid::new_v4().to_string();
    let name = match s.name.as_ref() {
        Some(n) => n.to_string(),
        None => u,
    };
    let conditions = s.conditions.as_ref().map(conditions_to_api).transpose()?;
    let actions = s.actions.as_ref().map(actions_from_config).transpose()?;
    Ok(api::Statement {
        name,
        conditions,
        actions,
    })
}

pub(crate) fn default_policy_type_to_i32(t: &config::DefaultPolicyType) -> i32 {
    match t {
        config::DefaultPolicyType::AcceptRoute => 1,
        config::DefaultPolicyType::RejectRoute => 2,
    }
}

pub(crate) fn load_policy_from_config(
    ptable: &mut rustybgp_table::PolicyTable,
    config: &config::BgpConfig,
) -> Result<(), Error> {
    if let Some(defined_sets) = &config.defined_sets {
        for set in defined_sets_to_api(defined_sets)? {
            ptable.add_defined_set(defined_set_from_api(set)?)?;
        }
    }
    if let Some(policies) = &config.policy_definitions {
        let mut seen = std::collections::HashSet::new();
        for policy in policies {
            if let Some(name) = &policy.name {
                let mut s_names = Vec::new();
                if let Some(statements) = &policy.statements {
                    for s in statements {
                        if let Some(n) = s.name.as_ref()
                            && seen.contains(n)
                        {
                            s_names.push(n.clone());
                            continue;
                        }
                        let stmt = statement_from_config(s)?;
                        let conditions = conditions_from_api(stmt.conditions)?;
                        let (disposition, actions) = disposition_from_api(stmt.actions)?;
                        ptable.add_statement(&stmt.name, conditions, disposition, actions)?;
                        s_names.push(stmt.name.clone());
                        seen.insert(stmt.name);
                    }
                }
                ptable.add_policy(name, s_names)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustybgp_table::NexthopAction;

    // --- RT conversion ---

    fn two_octet_rt_api(asn: u32, local_admin: u32) -> api::RouteTarget {
        api::RouteTarget {
            rt: Some(api::route_target::Rt::TwoOctetAsSpecific(
                api::TwoOctetAsSpecificExtended {
                    is_transitive: true,
                    sub_type: 2,
                    asn,
                    local_admin,
                },
            )),
        }
    }

    fn ipv4_rt_api(addr: &str, local_admin: u32) -> api::RouteTarget {
        api::RouteTarget {
            rt: Some(api::route_target::Rt::Ipv4AddressSpecific(
                api::IPv4AddressSpecificExtended {
                    is_transitive: true,
                    sub_type: 2,
                    address: addr.to_string(),
                    local_admin,
                },
            )),
        }
    }

    fn four_octet_rt_api(asn: u32, local_admin: u32) -> api::RouteTarget {
        api::RouteTarget {
            rt: Some(api::route_target::Rt::FourOctetAsSpecific(
                api::FourOctetAsSpecificExtended {
                    is_transitive: true,
                    sub_type: 2,
                    asn,
                    local_admin,
                },
            )),
        }
    }

    #[test]
    fn rt_from_api_two_octet_as() {
        let rt = rt_from_api(&two_octet_rt_api(65000, 100)).unwrap();
        assert_eq!(rt[0], 0x00);
        assert_eq!(rt[1], 0x02);
        assert_eq!(u16::from_be_bytes([rt[2], rt[3]]), 65000);
        assert_eq!(u32::from_be_bytes([rt[4], rt[5], rt[6], rt[7]]), 100);
    }

    #[test]
    fn rt_from_api_ipv4() {
        let rt = rt_from_api(&ipv4_rt_api("192.0.2.1", 200)).unwrap();
        assert_eq!(rt[0], 0x01);
        assert_eq!(rt[1], 0x02);
        assert_eq!(&rt[2..6], &[192, 0, 2, 1]);
        assert_eq!(u16::from_be_bytes([rt[6], rt[7]]), 200);
    }

    #[test]
    fn rt_from_api_four_octet_as() {
        let rt = rt_from_api(&four_octet_rt_api(4_200_000_000, 7)).unwrap();
        assert_eq!(rt[0], 0x02);
        assert_eq!(rt[1], 0x02);
        assert_eq!(
            u32::from_be_bytes([rt[2], rt[3], rt[4], rt[5]]),
            4_200_000_000
        );
        assert_eq!(u16::from_be_bytes([rt[6], rt[7]]), 7);
    }

    #[test]
    fn rt_from_api_rejects_wrong_sub_type() {
        let rt = api::RouteTarget {
            rt: Some(api::route_target::Rt::TwoOctetAsSpecific(
                api::TwoOctetAsSpecificExtended {
                    is_transitive: true,
                    sub_type: 3, // Route Origin, not Route Target
                    asn: 65000,
                    local_admin: 100,
                },
            )),
        };
        assert!(rt_from_api(&rt).is_err());
    }

    #[test]
    fn rt_from_api_rejects_none() {
        let rt = api::RouteTarget { rt: None };
        assert!(rt_from_api(&rt).is_err());
    }

    #[test]
    fn rt_roundtrip_two_octet() {
        let original = two_octet_rt_api(65000, 100);
        let bytes = rt_from_api(&original).unwrap();
        let back = rt_to_api(&bytes);
        let bytes2 = rt_from_api(&back).unwrap();
        assert_eq!(bytes, bytes2);
    }

    #[test]
    fn rt_roundtrip_ipv4() {
        let original = ipv4_rt_api("10.0.0.1", 42);
        let bytes = rt_from_api(&original).unwrap();
        let back = rt_to_api(&bytes);
        let bytes2 = rt_from_api(&back).unwrap();
        assert_eq!(bytes, bytes2);
    }

    #[test]
    fn rt_roundtrip_four_octet() {
        let original = four_octet_rt_api(4_200_000_000, 7);
        let bytes = rt_from_api(&original).unwrap();
        let back = rt_to_api(&bytes);
        let bytes2 = rt_from_api(&back).unwrap();
        assert_eq!(bytes, bytes2);
    }

    #[test]
    fn nexthop_action_self() {
        let actions = Some(api::Actions {
            nexthop: Some(api::NexthopAction {
                self_: true,
                ..Default::default()
            }),
            ..Default::default()
        });
        let (_, actions) = disposition_from_api(actions).unwrap();
        assert_eq!(actions.nexthop, Some(NexthopAction::PeerSelf));
    }

    #[test]
    fn nexthop_action_unchanged() {
        let actions = Some(api::Actions {
            nexthop: Some(api::NexthopAction {
                unchanged: true,
                ..Default::default()
            }),
            ..Default::default()
        });
        let (_, actions) = disposition_from_api(actions).unwrap();
        assert_eq!(actions.nexthop, Some(NexthopAction::Unchanged));
    }

    #[test]
    fn nexthop_action_address() {
        let actions = Some(api::Actions {
            nexthop: Some(api::NexthopAction {
                address: "10.0.0.1".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        });
        let (_, actions) = disposition_from_api(actions).unwrap();
        assert_eq!(
            actions.nexthop,
            Some(NexthopAction::Address("10.0.0.1".parse().unwrap()))
        );
    }

    #[test]
    fn nexthop_action_address_v6() {
        let actions = Some(api::Actions {
            nexthop: Some(api::NexthopAction {
                address: "2001:db8::1".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        });
        let (_, actions) = disposition_from_api(actions).unwrap();
        assert_eq!(
            actions.nexthop,
            Some(NexthopAction::Address("2001:db8::1".parse().unwrap()))
        );
    }

    #[test]
    fn nexthop_action_none() {
        let actions = Some(api::Actions::default());
        let (_, actions) = disposition_from_api(actions).unwrap();
        assert_eq!(actions.nexthop, None);
    }

    #[test]
    fn nexthop_action_empty_actions() {
        let (_, actions) = disposition_from_api(None).unwrap();
        assert_eq!(actions.nexthop, None);
    }

    // ─── MpReach round-trip ──────────────────────────────────────────────────

    fn mp_reach_api_v4(nh: &str) -> api::Attribute {
        api::Attribute {
            attr: Some(api::attribute::Attr::MpReach(api::MpReachNlriAttribute {
                family: Some(api::Family { afi: 1, safi: 85 }),
                next_hops: vec![nh.to_string()],
                nlris: vec![],
            })),
        }
    }

    #[test]
    fn mp_reach_ipv4_nexthop_builds_binary() {
        let attr = attr_from_api(mp_reach_api_v4("10.0.0.1")).unwrap();
        assert_eq!(attr.code(), Attribute::MP_REACH);
        let b = attr.binary().unwrap();
        // AFI=1, SAFI=85, NH_LEN=4, nexthop=10.0.0.1, reserved=0
        assert_eq!(b, &vec![0x00, 0x01, 0x55, 0x04, 10, 0, 0, 1, 0x00]);
    }

    #[test]
    fn mp_reach_ipv6_nexthop_builds_binary() {
        let api_attr = api::Attribute {
            attr: Some(api::attribute::Attr::MpReach(api::MpReachNlriAttribute {
                family: Some(api::Family { afi: 2, safi: 1 }),
                next_hops: vec!["2001:db8::1".to_string()],
                nlris: vec![],
            })),
        };
        let attr = attr_from_api(api_attr).unwrap();
        let b = attr.binary().unwrap();
        assert_eq!(b[0..3], [0x00, 0x02, 0x01]); // AFI=2, SAFI=1
        assert_eq!(b[3], 16); // NH_LEN=16
        assert_eq!(b.last(), Some(&0x00)); // reserved
    }

    #[test]
    fn mp_reach_rejects_missing_family() {
        let bad = api::Attribute {
            attr: Some(api::attribute::Attr::MpReach(api::MpReachNlriAttribute {
                family: None,
                next_hops: vec!["10.0.0.1".to_string()],
                nlris: vec![],
            })),
        };
        assert!(attr_from_api(bad).is_err());
    }

    #[test]
    fn mp_reach_rejects_empty_nexthops() {
        let bad = api::Attribute {
            attr: Some(api::attribute::Attr::MpReach(api::MpReachNlriAttribute {
                family: Some(api::Family { afi: 1, safi: 1 }),
                next_hops: vec![],
                nlris: vec![],
            })),
        };
        assert!(attr_from_api(bad).is_err());
    }

    #[test]
    fn mp_reach_rejects_invalid_nexthop() {
        let bad = mp_reach_api_v4("not-an-ip");
        assert!(attr_from_api(bad).is_err());
    }

    // ─── Extended Community round-trip ───────────────────────────────────────

    fn roundtrip_extcom(chunk: [u8; 8]) {
        let buf = chunk.to_vec();
        let mut rc = Cursor::new(&buf);
        let api_ec = read_extcom(&mut rc);
        let mut wc = Cursor::new(Vec::new());
        write_extcom(&mut wc, api_ec).unwrap();
        assert_eq!(wc.into_inner(), chunk);
    }

    #[test]
    fn extcom_two_octet_as_route_target() {
        // Transitive Two-Octet AS Specific, sub_type=0x02 (Route Target),
        // AS=10, local=10.
        roundtrip_extcom([0x00, 0x02, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x0a]);
    }

    #[test]
    fn extcom_two_octet_as_route_origin_non_transitive() {
        // Non-Transitive Two-Octet AS Specific, sub_type=0x03 (Route Origin).
        roundtrip_extcom([0x40, 0x03, 0x00, 0x65, 0x00, 0x00, 0x04, 0xd2]);
    }

    #[test]
    fn extcom_ipv4_address_specific() {
        // Transitive IPv4 Address Specific, sub_type=0x02, addr=192.0.2.1,
        // local=100.
        roundtrip_extcom([0x01, 0x02, 192, 0, 2, 1, 0x00, 0x64]);
    }

    #[test]
    fn extcom_four_octet_as_specific() {
        // Transitive Four-Octet AS Specific, sub_type=0x02, AS=4200000000.
        roundtrip_extcom([0x02, 0x02, 0xfa, 0x56, 0xea, 0x00, 0x00, 0x07]);
    }

    #[test]
    fn extcom_unknown_passthrough() {
        // Unknown type (0x06 = EVPN) should survive round-trip as raw bytes.
        roundtrip_extcom([0x06, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn write_extcom_rejects_unknown_wrong_length() {
        let bad = api::ExtendedCommunity {
            extcom: Some(api::extended_community::Extcom::Unknown(
                api::UnknownExtended {
                    r#type: 0x10,
                    value: vec![1, 2, 3],
                },
            )),
        };
        let mut c = Cursor::new(Vec::new());
        assert!(write_extcom(&mut c, bad).is_err());
    }

    #[test]
    fn write_extcom_rejects_out_of_range_sub_type() {
        let bad = api::ExtendedCommunity {
            extcom: Some(api::extended_community::Extcom::TwoOctetAsSpecific(
                api::TwoOctetAsSpecificExtended {
                    is_transitive: true,
                    sub_type: 999,
                    asn: 100,
                    local_admin: 200,
                },
            )),
        };
        let mut c = Cursor::new(Vec::new());
        assert!(write_extcom(&mut c, bad).is_err());
    }

    // ─── Statement Actions roundtrip ─────────────────────────────────────────

    fn actions_roundtrip(api_actions: api::Actions) -> api::Actions {
        let (disposition, actions) =
            disposition_from_api(Some(api_actions)).expect("disposition_from_api failed");
        let stmt = rustybgp_table::Statement {
            name: std::sync::Arc::from("s"),
            conditions: vec![],
            disposition,
            actions,
        };
        statement_to_api(&stmt)
            .actions
            .expect("no actions in output")
    }

    #[test]
    fn actions_roundtrip_community_add() {
        let out = actions_roundtrip(api::Actions {
            community: Some(api::CommunityAction {
                r#type: api::community_action::Type::Add as i32,
                communities: vec!["100:200".to_string()],
            }),
            ..Default::default()
        });
        let c = out.community.expect("community missing");
        assert_eq!(c.r#type, api::community_action::Type::Add as i32);
        assert_eq!(c.communities, vec!["100:200"]);
    }

    #[test]
    fn actions_roundtrip_local_pref() {
        let out = actions_roundtrip(api::Actions {
            local_pref: Some(api::LocalPrefAction { value: 150 }),
            ..Default::default()
        });
        assert_eq!(out.local_pref.expect("local_pref missing").value, 150);
    }

    #[test]
    fn actions_roundtrip_med_mod() {
        let out = actions_roundtrip(api::Actions {
            med: Some(api::MedAction {
                r#type: api::med_action::Type::Mod as i32,
                value: 10,
            }),
            ..Default::default()
        });
        let med = out.med.expect("med missing");
        assert_eq!(med.r#type, api::med_action::Type::Mod as i32);
        assert_eq!(med.value, 10);
    }

    #[test]
    fn actions_roundtrip_med_replace() {
        let out = actions_roundtrip(api::Actions {
            med: Some(api::MedAction {
                r#type: api::med_action::Type::Replace as i32,
                value: 500,
            }),
            ..Default::default()
        });
        let med = out.med.expect("med missing");
        assert_eq!(med.r#type, api::med_action::Type::Replace as i32);
        assert_eq!(med.value, 500);
    }

    #[test]
    fn actions_roundtrip_as_prepend() {
        let out = actions_roundtrip(api::Actions {
            as_prepend: Some(api::AsPrependAction {
                asn: 65001,
                repeat: 3,
                use_left_most: false,
            }),
            ..Default::default()
        });
        let ap = out.as_prepend.expect("as_prepend missing");
        assert_eq!(ap.asn, 65001);
        assert_eq!(ap.repeat, 3);
    }

    #[test]
    fn actions_roundtrip_ext_community_rt() {
        // rt:65001:100  → type 0x00, sub_type 0x02, AS=65001, local=100
        let out = actions_roundtrip(api::Actions {
            ext_community: Some(api::CommunityAction {
                r#type: api::community_action::Type::Add as i32,
                communities: vec!["rt:65001:100".to_string()],
            }),
            ..Default::default()
        });
        let ec = out.ext_community.expect("ext_community missing");
        assert_eq!(ec.r#type, api::community_action::Type::Add as i32);
        assert_eq!(ec.communities, vec!["rt:65001:100"]);
    }

    #[test]
    fn actions_roundtrip_large_community() {
        let out = actions_roundtrip(api::Actions {
            large_community: Some(api::CommunityAction {
                r#type: api::community_action::Type::Replace as i32,
                communities: vec!["65001:1:2".to_string()],
            }),
            ..Default::default()
        });
        let lc = out.large_community.expect("large_community missing");
        assert_eq!(lc.r#type, api::community_action::Type::Replace as i32);
        assert_eq!(lc.communities, vec!["65001:1:2"]);
    }

    #[test]
    fn actions_roundtrip_origin_igp() {
        let out = actions_roundtrip(api::Actions {
            origin_action: Some(api::OriginAction {
                origin: api::OriginType::Igp as i32,
            }),
            ..Default::default()
        });
        assert_eq!(
            out.origin_action.expect("origin_action missing").origin,
            api::OriginType::Igp as i32
        );
    }

    // ─── Statement Conditions roundtrip ──────────────────────────────────────

    // conditions_from_api treats rpki_result==ValidationState::None (=1) as "no RPKI condition".
    // Use this sentinel in every test Conditions to avoid spurious RPKI errors.
    const NO_RPKI: i32 = 1; // api::ValidationState::None

    fn conditions_roundtrip(api_conds: api::Conditions) -> api::Conditions {
        let configs = conditions_from_api(Some(api_conds)).expect("conditions_from_api failed");
        let mut table = rustybgp_table::PolicyTable::new();
        table
            .add_statement("s", configs, None, rustybgp_table::Actions::default())
            .expect("add_statement failed");
        let stmt = table
            .iter_statements("s".to_string())
            .next()
            .expect("statement not found");
        statement_to_api(stmt)
            .conditions
            .expect("no conditions in output")
    }

    #[test]
    fn conditions_roundtrip_local_pref_eq() {
        let out = conditions_roundtrip(api::Conditions {
            local_pref_eq: Some(api::LocalPrefEq { value: 100 }),
            rpki_result: NO_RPKI,
            ..Default::default()
        });
        assert_eq!(out.local_pref_eq.expect("local_pref_eq missing").value, 100);
    }

    #[test]
    fn conditions_roundtrip_med_eq() {
        let out = conditions_roundtrip(api::Conditions {
            med_eq: Some(api::MedEq { value: 200 }),
            rpki_result: NO_RPKI,
            ..Default::default()
        });
        assert_eq!(out.med_eq.expect("med_eq missing").value, 200);
    }

    #[test]
    fn conditions_roundtrip_origin_igp() {
        let out = conditions_roundtrip(api::Conditions {
            origin: api::OriginType::Igp as i32,
            rpki_result: NO_RPKI,
            ..Default::default()
        });
        assert_eq!(out.origin, api::OriginType::Igp as i32);
    }

    #[test]
    fn conditions_roundtrip_route_type_external() {
        use api::conditions::RouteType as ApiRouteType;
        let out = conditions_roundtrip(api::Conditions {
            route_type: ApiRouteType::External as i32,
            rpki_result: NO_RPKI,
            ..Default::default()
        });
        assert_eq!(out.route_type, ApiRouteType::External as i32);
    }

    #[test]
    fn conditions_roundtrip_community_count_ge() {
        let out = conditions_roundtrip(api::Conditions {
            community_count: Some(api::CommunityCount {
                r#type: 1,
                count: 3,
            }), // 1=Ge
            rpki_result: NO_RPKI,
            ..Default::default()
        });
        let cc = out.community_count.expect("community_count missing");
        assert_eq!(cc.r#type, 1);
        assert_eq!(cc.count, 3);
    }

    #[test]
    fn conditions_roundtrip_afi_safi_in() {
        let out = conditions_roundtrip(api::Conditions {
            afi_safi_in: vec![api::Family { afi: 1, safi: 1 }], // IPv4 unicast
            rpki_result: NO_RPKI,
            ..Default::default()
        });
        assert_eq!(out.afi_safi_in.len(), 1);
        assert_eq!(out.afi_safi_in[0].afi, 1);
        assert_eq!(out.afi_safi_in[0].safi, 1);
    }

    fn conditions_roundtrip_with_set(
        set: rustybgp_table::DefinedSetConfig,
        api_conds: api::Conditions,
    ) -> api::Conditions {
        let configs = conditions_from_api(Some(api_conds)).expect("conditions_from_api failed");
        let mut table = rustybgp_table::PolicyTable::new();
        table.add_defined_set(set).expect("add_defined_set failed");
        table
            .add_statement("s", configs, None, rustybgp_table::Actions::default())
            .expect("add_statement failed");
        let stmt = table
            .iter_statements("s".to_string())
            .next()
            .expect("statement not found");
        statement_to_api(stmt)
            .conditions
            .expect("no conditions in output")
    }

    #[test]
    fn conditions_roundtrip_community_set() {
        let out = conditions_roundtrip_with_set(
            rustybgp_table::DefinedSetConfig::Community {
                name: "cs1".to_string(),
                patterns: vec!["100:.*".to_string()],
            },
            api::Conditions {
                community_set: Some(api::MatchSet {
                    name: "cs1".to_string(),
                    r#type: 0, // Any
                }),
                rpki_result: NO_RPKI,
                ..Default::default()
            },
        );
        let ms = out.community_set.expect("community_set missing");
        assert_eq!(ms.name, "cs1");
        assert_eq!(ms.r#type, 0);
    }

    #[test]
    fn conditions_roundtrip_ext_community_set() {
        let out = conditions_roundtrip_with_set(
            rustybgp_table::DefinedSetConfig::ExtCommunity {
                name: "ecs1".to_string(),
                patterns: vec!["rt:65001:.*".to_string()],
            },
            api::Conditions {
                ext_community_set: Some(api::MatchSet {
                    name: "ecs1".to_string(),
                    r#type: 2, // Invert
                }),
                rpki_result: NO_RPKI,
                ..Default::default()
            },
        );
        let ms = out.ext_community_set.expect("ext_community_set missing");
        assert_eq!(ms.name, "ecs1");
        assert_eq!(ms.r#type, 2);
    }

    #[test]
    fn conditions_roundtrip_large_community_set() {
        let out = conditions_roundtrip_with_set(
            rustybgp_table::DefinedSetConfig::LargeCommunity {
                name: "lcs1".to_string(),
                patterns: vec!["65001:1:.*".to_string()],
            },
            api::Conditions {
                large_community_set: Some(api::MatchSet {
                    name: "lcs1".to_string(),
                    r#type: 1, // All
                }),
                rpki_result: NO_RPKI,
                ..Default::default()
            },
        );
        let ms = out
            .large_community_set
            .expect("large_community_set missing");
        assert_eq!(ms.name, "lcs1");
        assert_eq!(ms.r#type, 1);
    }

    // ─── config loading tests (TOML) ─────────────────────────────────────────

    fn make_ptable(toml: &str) -> rustybgp_table::PolicyTable {
        let conf: config::BgpConfig = toml::from_str(toml).expect("invalid TOML");
        let mut ptable = rustybgp_table::PolicyTable::new();
        load_policy_from_config(&mut ptable, &conf).expect("load_policy_from_config failed");
        ptable
    }

    fn first_stmt(ptable: &rustybgp_table::PolicyTable) -> &rustybgp_table::Statement {
        ptable
            .iter_statements("".to_string())
            .next()
            .expect("no statement")
    }

    // ── condition tests ──────────────────────────────────────────────────────

    #[test]
    fn config_prefix_condition() {
        let ptable = make_ptable(
            r#"
[[defined-sets.prefix-sets]]
prefix-set-name = "ps1"

[[defined-sets.prefix-sets.prefix-list]]
ip-prefix = "10.0.0.0/8"
masklength-range = "8..24"

[[policy-definitions]]
name = "p1"

[[policy-definitions.statements]]
name = "s1"

[policy-definitions.statements.conditions.match-prefix-set]
prefix-set = "ps1"
match-set-options = "any"

[policy-definitions.statements.actions]
route-disposition = "accept-route"
"#,
        );
        assert_eq!(ptable.iter_defined_sets().count(), 1);
        let stmt = first_stmt(&ptable);
        assert!(
            stmt.conditions
                .iter()
                .any(|c| matches!(c, rustybgp_table::Condition::Prefix(n, ..) if n == "ps1"))
        );
    }

    #[test]
    fn config_neighbor_condition() {
        let ptable = make_ptable(
            r#"
[[defined-sets.neighbor-sets]]
neighbor-set-name = "ns1"
neighbor-info-list = ["10.0.0.1/32"]

[[policy-definitions]]
name = "p1"

[[policy-definitions.statements]]
name = "s1"

[policy-definitions.statements.conditions.match-neighbor-set]
neighbor-set = "ns1"
match-set-options = "any"

[policy-definitions.statements.actions]
route-disposition = "accept-route"
"#,
        );
        assert_eq!(ptable.iter_defined_sets().count(), 1);
        let stmt = first_stmt(&ptable);
        assert!(
            stmt.conditions
                .iter()
                .any(|c| matches!(c, rustybgp_table::Condition::Neighbor(n, ..) if n == "ns1"))
        );
    }

    #[test]
    fn config_as_path_condition() {
        let ptable = make_ptable(
            r#"
[[defined-sets.bgp-defined-sets.as-path-sets]]
as-path-set-name = "aps1"
as-path-list = ["^65100_"]

[[policy-definitions]]
name = "p1"

[[policy-definitions.statements]]
name = "s1"

[policy-definitions.statements.conditions.bgp-conditions.match-as-path-set]
as-path-set = "aps1"
match-set-options = "any"

[policy-definitions.statements.actions]
route-disposition = "accept-route"
"#,
        );
        assert_eq!(ptable.iter_defined_sets().count(), 1);
        let stmt = first_stmt(&ptable);
        assert!(
            stmt.conditions
                .iter()
                .any(|c| matches!(c, rustybgp_table::Condition::AsPath(n, ..) if n == "aps1"))
        );
    }

    #[test]
    fn config_community_condition() {
        let ptable = make_ptable(
            r#"
[[defined-sets.bgp-defined-sets.community-sets]]
community-set-name = "cs1"
community-list = ["100:200"]

[[policy-definitions]]
name = "p1"

[[policy-definitions.statements]]
name = "s1"

[policy-definitions.statements.conditions.bgp-conditions.match-community-set]
community-set = "cs1"
match-set-options = "any"

[policy-definitions.statements.actions]
route-disposition = "accept-route"
"#,
        );
        assert_eq!(ptable.iter_defined_sets().count(), 1);
        let stmt = first_stmt(&ptable);
        assert!(
            stmt.conditions
                .iter()
                .any(|c| matches!(c, rustybgp_table::Condition::Community(n, ..) if n == "cs1"))
        );
    }

    #[test]
    fn config_ext_community_condition() {
        let ptable = make_ptable(
            r#"
[[defined-sets.bgp-defined-sets.ext-community-sets]]
ext-community-set-name = "ecs1"
ext-community-list = ["rt:65000:100"]

[[policy-definitions]]
name = "p1"

[[policy-definitions.statements]]
name = "s1"

[policy-definitions.statements.conditions.bgp-conditions.match-ext-community-set]
ext-community-set = "ecs1"
match-set-options = "any"

[policy-definitions.statements.actions]
route-disposition = "accept-route"
"#,
        );
        assert_eq!(ptable.iter_defined_sets().count(), 1);
        let stmt = first_stmt(&ptable);
        assert!(
            stmt.conditions.iter().any(
                |c| matches!(c, rustybgp_table::Condition::ExtCommunity(n, ..) if n == "ecs1")
            )
        );
    }

    #[test]
    fn config_large_community_condition() {
        let ptable = make_ptable(
            r#"
[[defined-sets.bgp-defined-sets.large-community-sets]]
large-community-set-name = "lcs1"
large-community-list = ["65000:1:2"]

[[policy-definitions]]
name = "p1"

[[policy-definitions.statements]]
name = "s1"

[policy-definitions.statements.conditions.bgp-conditions.match-large-community-set]
large-community-set = "lcs1"
match-set-options = "any"

[policy-definitions.statements.actions]
route-disposition = "accept-route"
"#,
        );
        assert_eq!(ptable.iter_defined_sets().count(), 1);
        let stmt = first_stmt(&ptable);
        assert!(
            stmt.conditions.iter().any(
                |c| matches!(c, rustybgp_table::Condition::LargeCommunity(n, ..) if n == "lcs1")
            )
        );
    }

    #[test]
    fn config_as_path_length_condition() {
        let ptable = make_ptable(
            r#"
[[policy-definitions]]
name = "p1"

[[policy-definitions.statements]]
name = "s1"

[policy-definitions.statements.conditions.bgp-conditions.as-path-length]
operator = "le"
value = 10

[policy-definitions.statements.actions]
route-disposition = "accept-route"
"#,
        );
        let stmt = first_stmt(&ptable);
        assert!(stmt.conditions.iter().any(
            |c| matches!(c, rustybgp_table::Condition::AsPathLength(cmp, len)
                if matches!(cmp, rustybgp_table::Comparison::Le) && *len == 10)
        ));
    }

    #[test]
    fn config_nexthop_condition() {
        use std::net::IpAddr;
        let ptable = make_ptable(
            r#"
[[policy-definitions]]
name = "p1"

[[policy-definitions.statements]]
name = "s1"

[policy-definitions.statements.conditions.bgp-conditions]
next-hop-in-list = ["10.0.0.1"]

[policy-definitions.statements.actions]
route-disposition = "accept-route"
"#,
        );
        let stmt = first_stmt(&ptable);
        let expected: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(
            stmt.conditions.iter().any(
                |c| matches!(c, rustybgp_table::Condition::Nexthop(v) if v.contains(&expected))
            )
        );
    }

    #[test]
    fn config_rpki_condition() {
        let ptable = make_ptable(
            r#"
[[policy-definitions]]
name = "p1"

[[policy-definitions.statements]]
name = "s1"

[policy-definitions.statements.conditions.bgp-conditions]
rpki-validation-result = "valid"

[policy-definitions.statements.actions]
route-disposition = "accept-route"
"#,
        );
        let stmt = first_stmt(&ptable);
        assert!(
            stmt.conditions
                .iter()
                .any(|c| matches!(c, rustybgp_table::Condition::Rpki(s)
                if *s == rustybgp_table::RpkiValidationState::Valid))
        );
    }

    #[test]
    fn config_route_type_condition() {
        let ptable = make_ptable(
            r#"
[[policy-definitions]]
name = "p1"

[[policy-definitions.statements]]
name = "s1"

[policy-definitions.statements.conditions.bgp-conditions]
route-type = "external"

[policy-definitions.statements.actions]
route-disposition = "accept-route"
"#,
        );
        let stmt = first_stmt(&ptable);
        assert!(
            stmt.conditions
                .iter()
                .any(|c| matches!(c, rustybgp_table::Condition::RouteType(t)
                if matches!(t, rustybgp_table::RouteType::External)))
        );
    }

    // ── action tests ─────────────────────────────────────────────────────────

    #[test]
    fn config_community_action_add() {
        let ptable = make_ptable(
            r#"
[[policy-definitions]]
name = "p1"

[[policy-definitions.statements]]
name = "s1"

[policy-definitions.statements.actions]
route-disposition = "accept-route"
bgp-actions.set-community.options = "add"
bgp-actions.set-community.set-community-method.communities-list = ["100:200"]
"#,
        );
        let stmt = first_stmt(&ptable);
        let action = stmt
            .actions
            .community
            .as_ref()
            .expect("community action missing");
        assert!(matches!(
            action.action_type,
            rustybgp_table::CommunityActionType::Add
        ));
        assert_eq!(action.communities, vec![(100u32 << 16) | 200]);
    }

    #[test]
    fn config_community_action_remove() {
        let ptable = make_ptable(
            r#"
[[policy-definitions]]
name = "p1"

[[policy-definitions.statements]]
name = "s1"

[policy-definitions.statements.actions]
route-disposition = "accept-route"
bgp-actions.set-community.options = "remove"
bgp-actions.set-community.set-community-method.communities-list = ["300:400"]
"#,
        );
        let stmt = first_stmt(&ptable);
        let action = stmt
            .actions
            .community
            .as_ref()
            .expect("community action missing");
        assert!(matches!(
            action.action_type,
            rustybgp_table::CommunityActionType::Remove
        ));
        assert_eq!(action.communities, vec![(300u32 << 16) | 400]);
    }

    #[test]
    fn config_ext_community_action_add() {
        let ptable = make_ptable(
            r#"
[[policy-definitions]]
name = "p1"

[[policy-definitions.statements]]
name = "s1"

[policy-definitions.statements.actions]
route-disposition = "accept-route"
bgp-actions.set-ext-community.options = "add"
bgp-actions.set-ext-community.set-ext-community-method.communities-list = ["rt:65000:100"]
"#,
        );
        let stmt = first_stmt(&ptable);
        let action = stmt
            .actions
            .ext_community
            .as_ref()
            .expect("ext_community action missing");
        assert!(matches!(
            action.action_type,
            rustybgp_table::CommunityActionType::Add
        ));
        // rt:65000:100 -> type=0x00 sub=0x02 asn=65000(0xFDE8) local=100(0x64)
        let expected: [u8; 8] = [0x00, 0x02, 0xFD, 0xE8, 0x00, 0x00, 0x00, 0x64];
        assert_eq!(action.communities, vec![expected]);
    }

    #[test]
    fn config_large_community_action_add() {
        let ptable = make_ptable(
            r#"
[[policy-definitions]]
name = "p1"

[[policy-definitions.statements]]
name = "s1"

[policy-definitions.statements.actions]
route-disposition = "accept-route"
bgp-actions.set-large-community.options = "add"
bgp-actions.set-large-community.set-large-community-method.communities-list = ["65000:1:2"]
"#,
        );
        let stmt = first_stmt(&ptable);
        let action = stmt
            .actions
            .large_community
            .as_ref()
            .expect("large_community action missing");
        assert!(matches!(
            action.action_type,
            rustybgp_table::CommunityActionType::Add
        ));
        assert_eq!(action.communities, vec![(65000u32, 1u32, 2u32)]);
    }

    #[test]
    fn config_local_pref_action() {
        let ptable = make_ptable(
            r#"
[[policy-definitions]]
name = "p1"

[[policy-definitions.statements]]
name = "s1"

[policy-definitions.statements.actions]
route-disposition = "accept-route"
bgp-actions.set-local-pref = 200
"#,
        );
        let stmt = first_stmt(&ptable);
        assert_eq!(
            stmt.actions.local_pref,
            Some(rustybgp_table::LocalPrefAction { value: 200 })
        );
    }

    #[test]
    fn config_med_action_replace() {
        let ptable = make_ptable(
            r#"
[[policy-definitions]]
name = "p1"

[[policy-definitions.statements]]
name = "s1"

[policy-definitions.statements.actions]
route-disposition = "accept-route"
bgp-actions.set-med = "300"
"#,
        );
        let stmt = first_stmt(&ptable);
        let med = stmt.actions.med.as_ref().expect("med action missing");
        assert!(matches!(
            med.action_type,
            rustybgp_table::MedActionType::Replace
        ));
        assert_eq!(med.value, 300);
    }

    #[test]
    fn config_med_action_mod_positive() {
        let ptable = make_ptable(
            r#"
[[policy-definitions]]
name = "p1"

[[policy-definitions.statements]]
name = "s1"

[policy-definitions.statements.actions]
route-disposition = "accept-route"
bgp-actions.set-med = "+50"
"#,
        );
        let stmt = first_stmt(&ptable);
        let med = stmt.actions.med.as_ref().expect("med action missing");
        assert!(matches!(
            med.action_type,
            rustybgp_table::MedActionType::Mod
        ));
        assert_eq!(med.value, 50);
    }

    #[test]
    fn config_med_action_mod_negative() {
        let ptable = make_ptable(
            r#"
[[policy-definitions]]
name = "p1"

[[policy-definitions.statements]]
name = "s1"

[policy-definitions.statements.actions]
route-disposition = "accept-route"
bgp-actions.set-med = "-50"
"#,
        );
        let stmt = first_stmt(&ptable);
        let med = stmt.actions.med.as_ref().expect("med action missing");
        assert!(matches!(
            med.action_type,
            rustybgp_table::MedActionType::Mod
        ));
        assert_eq!(med.value, -50);
    }

    #[test]
    fn config_as_prepend_action() {
        let ptable = make_ptable(
            r#"
[[policy-definitions]]
name = "p1"

[[policy-definitions.statements]]
name = "s1"

[policy-definitions.statements.actions]
route-disposition = "accept-route"
bgp-actions.set-as-path-prepend.repeat-n = 3
bgp-actions.set-as-path-prepend.as = "65001"
"#,
        );
        let stmt = first_stmt(&ptable);
        let ap = stmt
            .actions
            .as_prepend
            .as_ref()
            .expect("as_prepend action missing");
        assert_eq!(ap.asn, 65001);
        assert_eq!(ap.repeat, 3);
        assert!(!ap.use_left_most);
    }

    #[test]
    fn config_as_prepend_last_as() {
        let ptable = make_ptable(
            r#"
[[policy-definitions]]
name = "p1"

[[policy-definitions.statements]]
name = "s1"

[policy-definitions.statements.actions]
route-disposition = "accept-route"
bgp-actions.set-as-path-prepend.repeat-n = 2
bgp-actions.set-as-path-prepend.as = "last-as"
"#,
        );
        let stmt = first_stmt(&ptable);
        let ap = stmt
            .actions
            .as_prepend
            .as_ref()
            .expect("as_prepend action missing");
        assert_eq!(ap.repeat, 2);
        assert!(ap.use_left_most);
    }

    #[test]
    fn config_origin_action_igp() {
        let ptable = make_ptable(
            r#"
[[policy-definitions]]
name = "p1"

[[policy-definitions.statements]]
name = "s1"

[policy-definitions.statements.actions]
route-disposition = "accept-route"
bgp-actions.set-route-origin = "igp"
"#,
        );
        let stmt = first_stmt(&ptable);
        assert_eq!(
            stmt.actions.origin,
            Some(rustybgp_table::OriginAction { origin: 0 })
        );
    }

    #[test]
    fn config_origin_action_egp() {
        let ptable = make_ptable(
            r#"
[[policy-definitions]]
name = "p1"

[[policy-definitions.statements]]
name = "s1"

[policy-definitions.statements.actions]
route-disposition = "accept-route"
bgp-actions.set-route-origin = "egp"
"#,
        );
        let stmt = first_stmt(&ptable);
        assert_eq!(
            stmt.actions.origin,
            Some(rustybgp_table::OriginAction { origin: 1 })
        );
    }

    #[test]
    fn config_nexthop_action_self() {
        use rustybgp_table::NexthopAction;
        let ptable = make_ptable(
            r#"
[[policy-definitions]]
name = "p1"

[[policy-definitions.statements]]
name = "s1"

[policy-definitions.statements.actions]
route-disposition = "accept-route"
bgp-actions.set-next-hop = "self"
"#,
        );
        let stmt = first_stmt(&ptable);
        assert_eq!(stmt.actions.nexthop, Some(NexthopAction::PeerSelf));
    }

    // --- family_from_config ---

    #[test]
    fn family_from_config_known_families() {
        use config::generate::AfiSafiType;
        let cases = [
            (AfiSafiType::Ipv4Unicast, Family::IPV4),
            (AfiSafiType::Ipv6Unicast, Family::IPV6),
            (AfiSafiType::Ipv4Multicast, Family::IPV4_MC),
            (AfiSafiType::Ipv6Multicast, Family::IPV6_MC),
            (AfiSafiType::Ipv4Mup, Family::IPV4_MUP),
            (AfiSafiType::Ipv6Mup, Family::IPV6_MUP),
        ];
        for (input, want) in cases {
            assert_eq!(family_from_config(&input), Ok(want), "{input:?}");
        }
    }

    #[test]
    fn family_from_config_unsupported_returns_err() {
        use config::generate::AfiSafiType;
        assert!(family_from_config(&AfiSafiType::L3VpnIpv4Unicast).is_err());
    }

    // --- Flowspec extended community roundtrips ---

    fn extcom_roundtrip(wire: &[u8; 8]) -> api::ExtendedCommunity {
        let v = wire.to_vec();
        let ec = read_extcom(&mut Cursor::new(&v));
        let mut out = Cursor::new(Vec::with_capacity(8));
        write_extcom(&mut out, ec.clone()).unwrap();
        assert_eq!(
            out.into_inner(),
            wire,
            "write did not reproduce input bytes"
        );
        ec
    }

    #[test]
    fn extcom_traffic_rate_roundtrip() {
        // ASN=65000, rate=100.0 (IEEE 754: 0x42C80000)
        let wire: [u8; 8] = [0x80, 0x06, 0xFD, 0xE8, 0x42, 0xC8, 0x00, 0x00];
        let ec = extcom_roundtrip(&wire);
        let api::extended_community::Extcom::TrafficRate(t) = ec.extcom.unwrap() else {
            panic!("wrong variant");
        };
        assert_eq!(t.asn, 65000);
        assert!((t.rate - 100.0f32).abs() < f32::EPSILON);
    }

    #[test]
    fn extcom_traffic_action_roundtrip() {
        // terminal=true, sample=true -> flags byte 0x03
        let wire: [u8; 8] = [0x80, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03];
        let ec = extcom_roundtrip(&wire);
        let api::extended_community::Extcom::TrafficAction(t) = ec.extcom.unwrap() else {
            panic!("wrong variant");
        };
        assert!(t.terminal);
        assert!(t.sample);
    }

    #[test]
    fn extcom_redirect_two_octet_as_roundtrip() {
        // ASN=65000, local_admin=100
        let wire: [u8; 8] = [0x80, 0x08, 0xFD, 0xE8, 0x00, 0x00, 0x00, 0x64];
        let ec = extcom_roundtrip(&wire);
        let api::extended_community::Extcom::RedirectTwoOctetAsSpecific(t) = ec.extcom.unwrap()
        else {
            panic!("wrong variant");
        };
        assert_eq!(t.asn, 65000);
        assert_eq!(t.local_admin, 100);
    }

    #[test]
    fn extcom_traffic_remark_roundtrip() {
        // DSCP=46 (EF)
        let wire: [u8; 8] = [0x80, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2E];
        let ec = extcom_roundtrip(&wire);
        let api::extended_community::Extcom::TrafficRemark(t) = ec.extcom.unwrap() else {
            panic!("wrong variant");
        };
        assert_eq!(t.dscp, 46);
    }

    #[test]
    fn extcom_redirect_ipv4_roundtrip() {
        // 192.0.2.1, local_admin=200
        let wire: [u8; 8] = [0x81, 0x08, 0xC0, 0x00, 0x02, 0x01, 0x00, 0xC8];
        let ec = extcom_roundtrip(&wire);
        let api::extended_community::Extcom::RedirectIpv4AddressSpecific(t) = ec.extcom.unwrap()
        else {
            panic!("wrong variant");
        };
        assert_eq!(t.address, "192.0.2.1");
        assert_eq!(t.local_admin, 200);
    }

    #[test]
    fn extcom_redirect_four_octet_as_roundtrip() {
        // ASN=131072, local_admin=7
        let wire: [u8; 8] = [0x82, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x07];
        let ec = extcom_roundtrip(&wire);
        let api::extended_community::Extcom::RedirectFourOctetAsSpecific(t) = ec.extcom.unwrap()
        else {
            panic!("wrong variant");
        };
        assert_eq!(t.asn, 131072);
        assert_eq!(t.local_admin, 7);
    }

    // --- Flowspec net_from_api roundtrips ---

    fn make_flowspec_rule_prefix(
        type_num: u32,
        prefix: &str,
        prefix_len: u32,
        offset: u32,
    ) -> api::FlowSpecRule {
        api::FlowSpecRule {
            rule: Some(api::flow_spec_rule::Rule::IpPrefix(api::FlowSpecIpPrefix {
                r#type: type_num,
                prefix_len,
                prefix: prefix.to_string(),
                offset,
            })),
        }
    }

    fn make_flowspec_rule_component(type_num: u32, op: u32, value: u64) -> api::FlowSpecRule {
        api::FlowSpecRule {
            rule: Some(api::flow_spec_rule::Rule::Component(
                api::FlowSpecComponent {
                    r#type: type_num,
                    items: vec![api::FlowSpecComponentItem { op, value }],
                },
            )),
        }
    }

    #[test]
    fn net_from_api_flowspec_v4_roundtrip() {
        let nlri = api::Nlri {
            nlri: Some(api::nlri::Nlri::FlowSpec(api::FlowSpecNlri {
                rules: vec![
                    make_flowspec_rule_prefix(1, "10.0.0.0", 24, 0),
                    make_flowspec_rule_component(6, 0x91, 80), // SrcPort == 80, end
                ],
            })),
        };
        let net = net_from_api(nlri, Family::IPV4_FLOWSPEC).unwrap();
        let Nlri::FlowspecV4(n) = net else {
            panic!("wrong variant")
        };
        assert_eq!(n.components.len(), 2);
        let api_nlri = nlri_to_api(&Nlri::FlowspecV4(n));
        let api::nlri::Nlri::FlowSpec(f) = api_nlri.nlri.unwrap() else {
            panic!()
        };
        assert_eq!(f.rules.len(), 2);
    }

    #[test]
    fn net_from_api_flowspec_v6_roundtrip() {
        let nlri = api::Nlri {
            nlri: Some(api::nlri::Nlri::FlowSpec(api::FlowSpecNlri {
                rules: vec![
                    make_flowspec_rule_prefix(1, "2001:db8::", 32, 0),
                    make_flowspec_rule_component(13, 0x91, 1000), // FlowLabel == 1000, end
                ],
            })),
        };
        let net = net_from_api(nlri, Family::IPV6_FLOWSPEC).unwrap();
        let Nlri::FlowspecV6(n) = net else {
            panic!("wrong variant")
        };
        assert_eq!(n.components.len(), 2);
    }

    #[test]
    fn net_from_api_flowspec_family_mismatch_returns_err() {
        let nlri = api::Nlri {
            nlri: Some(api::nlri::Nlri::FlowSpec(api::FlowSpecNlri {
                rules: vec![],
            })),
        };
        assert!(net_from_api(nlri, Family::IPV4).is_err());
    }
}
