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
use std::io::Cursor;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use rustybgp_packet::{Family, Nlri, PathNlri, bgp::Attribute, bgp::Capability};

use crate::api;
use crate::config;
use crate::error::Error;

impl From<Family> for api::Family {
    fn from(f: Family) -> Self {
        api::Family {
            afi: f.afi() as i32,
            safi: f.safi() as i32,
        }
    }
}

impl From<&Nlri> for api::Nlri {
    fn from(f: &Nlri) -> Self {
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
        }
    }
}

impl From<&PathNlri> for api::Nlri {
    fn from(p: &PathNlri) -> Self {
        api::Nlri::from(&p.nlri)
    }
}

impl From<&Capability> for api::Capability {
    fn from(cap: &Capability) -> Self {
        match cap {
            Capability::MultiProtocol(family) => api::Capability {
                cap: Some(api::capability::Cap::MultiProtocol(
                    api::MultiProtocolCapability {
                        family: Some(api::Family::from(*family)),
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
                                nlri_family: Some((*family).into()),
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
                                family: Some((*family).into()),
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
                            family: Some((*family).into()),
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
                            .map(|(family, flags, time)| {
                                api::LongLivedGracefulRestartCapabilityTuple {
                                    family: Some((*family).into()),
                                    flags: *flags as u32,
                                    time: *time,
                                }
                            })
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
}

impl From<&Attribute> for api::Attribute {
    fn from(a: &Attribute) -> Self {
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
            _ => api::Attribute {
                attr: Some(api::attribute::Attr::Unknown(api::UnknownAttribute {
                    flags: a.flags() as u32,
                    r#type: a.code() as u32,
                    value: a.binary().unwrap().to_owned(),
                })),
            },
        }
    }
}

pub(crate) fn family_from_api(f: &api::Family) -> Family {
    Family::new((f.afi as u32) << 16 | f.safi as u32)
}

pub(crate) fn family_from_config(f: &config::generate::AfiSafiType) -> Result<Family, ()> {
    match f {
        config::generate::AfiSafiType::Ipv4Unicast => Ok(Family::IPV4),
        config::generate::AfiSafiType::Ipv6Unicast => Ok(Family::IPV6),
        _ => Err(()),
    }
}

pub(crate) fn net_from_api(n: api::Nlri) -> Result<Nlri, Error> {
    match n.nlri {
        Some(api::nlri::Nlri::Prefix(p)) => {
            Nlri::from_str(&format!("{}/{}", p.prefix, p.prefix_len))
                .map_err(|e| Error::InvalidArgument(e.to_string()))
        }
        _ => Err(Error::InvalidArgument("invalid NLRI".to_string())),
    }
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
        _ => Err(Error::InvalidArgument(
            "attribute conversion not implemented".to_string(),
        )),
    }
}
