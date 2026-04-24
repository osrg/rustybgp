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
    Family, IpNet, Nlri, bgp::Attribute, bgp::Capability, mup, prefix_sid, rd::RouteDistinguisher,
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

pub(crate) fn rd_to_api(rd: &RouteDistinguisher) -> api::RouteDistinguisher {
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

/// Type byte category masks (RFC 4360 §2, RFC 5668 §2).
const EXTCOM_TYPE_NON_TRANSITIVE: u8 = 0x40;
const EXTCOM_TYPE_TWO_OCTET_AS: u8 = 0x00;
const EXTCOM_TYPE_IPV4_ADDRESS: u8 = 0x01;
const EXTCOM_TYPE_FOUR_OCTET_AS: u8 = 0x02;

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
        api::extended_community::Extcom::Unknown(u) => {
            if u.value.len() != 8 {
                return Err(Error::InvalidArgument(format!(
                    "extended community must be 8 bytes, got {}",
                    u.value.len()
                )));
            }
            c.get_mut().extend_from_slice(&u.value);
            c.set_position(c.position() + 8);
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
        config::generate::AfiSafiType::Ipv4Mup => Ok(Family::IPV4_MUP),
        config::generate::AfiSafiType::Ipv6Mup => Ok(Family::IPV6_MUP),
        _ => Err(()),
    }
}

pub(crate) fn net_from_api(n: api::Nlri) -> Result<Nlri, Error> {
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

pub(crate) fn prefix_sid_to_api(sid: &prefix_sid::PrefixSid) -> api::PrefixSid {
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

pub(crate) fn prefix_sid_from_api(p: api::PrefixSid) -> Result<prefix_sid::PrefixSid, Error> {
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
    use rustybgp_table::{Comparison, Condition, RpkiValidationState};
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
            Condition::Community(name, opt, _set) => {
                conditions.community_set = Some(api::MatchSet {
                    name: name.clone(),
                    r#type: match_option_to_i32(opt),
                });
            }
            Condition::Nexthop(v) => {
                conditions.next_hop_in_list = v.iter().map(|x| x.to_string()).collect();
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
    s.actions = Some(api::Actions {
        route_action: my.disposition.map_or(0, |a| a as i32),
        nexthop,
        ..Default::default()
    });
    s
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
    }
}

pub(crate) fn conditions_from_api(
    conditions: Option<api::Conditions>,
) -> Result<Vec<rustybgp_table::ConditionConfig>, rustybgp_table::TableError> {
    use rustybgp_table::{
        Comparison, ConditionConfig, MatchOption, RpkiValidationState, TableError,
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
    Ok(v)
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

    Ok((disposition, rustybgp_table::Actions { nexthop }))
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

pub(crate) fn routing_table_state_to_api(
    s: rustybgp_table::RoutingTableState,
) -> api::GetTableResponse {
    api::GetTableResponse {
        num_destination: s.num_destination as u64,
        num_path: s.num_path as u64,
        num_accepted: s.num_accepted as u64,
    }
}

pub(crate) fn table_type_from_api(t: api::TableType) -> rustybgp_table::TableType {
    match t {
        api::TableType::AdjIn => rustybgp_table::TableType::AdjIn,
        api::TableType::AdjOut => rustybgp_table::TableType::AdjOut,
        _ => rustybgp_table::TableType::Global,
    }
}

pub(crate) fn destination_to_api(
    d: rustybgp_table::DestinationEntry,
    family: Family,
) -> api::Destination {
    use crate::proto::ToApi;
    api::Destination {
        prefix: d.net.to_string(),
        paths: d
            .paths
            .into_iter()
            .map(|p| api::Path {
                nlri: Some(nlri_to_api(&d.net)),
                family: Some(family_to_api(family)),
                identifier: p.id,
                age: Some(p.timestamp.to_api()),
                pattrs: p.attr.iter().map(attr_to_api).collect(),
                validation: p.validation.map(rpki_validation_to_api),
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

pub(crate) fn rpki_validation_to_api(v: rustybgp_table::RpkiValidation) -> api::Validation {
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
    Ok(v)
}

pub(crate) fn defined_sets_to_api(
    sets: &config::DefinedSets,
) -> Result<Vec<api::DefinedSet>, Error> {
    let mut v = Vec::new();
    if let Some(sets) = &sets.prefix_sets {
        for s in sets {
            v.push(prefix_set_to_api(s)?);
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

    if let Some(set) = c.bgp_conditions.as_ref() {
        if let Some(set) = set.match_as_path_set.as_ref() {
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
        if let Some(l) = set.as_path_length.as_ref() {
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

pub(crate) fn statement_from_config(s: &config::Statement) -> Result<api::Statement, Error> {
    let u = Uuid::new_v4().to_string();
    let name = match s.name.as_ref() {
        Some(n) => n.to_string(),
        None => u,
    };

    let conditions = if let Some(c) = &s.conditions {
        Some(conditions_to_api(c)?)
    } else {
        None
    };

    let actions = s.actions.as_ref().map(|a| {
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
        api::Actions {
            route_action: match a.route_disposition.as_ref() {
                Some(a) => route_disposition_to_i32(a),
                None => 0,
            },
            community: None,
            med: None,
            as_prepend: None,
            ext_community: None,
            nexthop,
            local_pref: None,
            large_community: None,
            origin_action: None,
        }
    });

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

#[cfg(test)]
mod tests {
    use super::*;
    use rustybgp_table::NexthopAction;

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
}
