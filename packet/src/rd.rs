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

use crate::error::{BgpError, Error};
use byteorder::{ByteOrder, NetworkEndian};
use bytes::BufMut;
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

/// Route Distinguisher (RFC 4364 §4.2). Eight-octet identifier that
/// qualifies a VPN address so overlapping customer prefixes stay unique.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteDistinguisher {
    /// Type 0: 2-octet AS : 4-octet assigned number.
    TwoOctetAs { admin: u16, assigned: u32 },
    /// Type 1: 4-octet IPv4 address : 2-octet assigned number.
    Ipv4 { admin: Ipv4Addr, assigned: u16 },
    /// Type 2: 4-octet AS : 2-octet assigned number.
    FourOctetAs { admin: u32, assigned: u16 },
}

impl RouteDistinguisher {
    pub const LEN: usize = 8;

    const TYPE_TWO_OCTET_AS: u16 = 0;
    const TYPE_IPV4: u16 = 1;
    const TYPE_FOUR_OCTET_AS: u16 = 2;

    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let malformed: Error = BgpError::UpdateMalformedAttributeList.into();
        if data.len() != Self::LEN {
            return Err(malformed);
        }
        let rd_type = NetworkEndian::read_u16(&data[0..2]);
        match rd_type {
            Self::TYPE_TWO_OCTET_AS => Ok(RouteDistinguisher::TwoOctetAs {
                admin: NetworkEndian::read_u16(&data[2..4]),
                assigned: NetworkEndian::read_u32(&data[4..8]),
            }),
            Self::TYPE_IPV4 => Ok(RouteDistinguisher::Ipv4 {
                admin: Ipv4Addr::new(data[2], data[3], data[4], data[5]),
                assigned: NetworkEndian::read_u16(&data[6..8]),
            }),
            Self::TYPE_FOUR_OCTET_AS => Ok(RouteDistinguisher::FourOctetAs {
                admin: NetworkEndian::read_u32(&data[2..6]),
                assigned: NetworkEndian::read_u16(&data[6..8]),
            }),
            _ => Err(malformed),
        }
    }

    pub fn encode<B: BufMut>(&self, dst: &mut B) {
        match *self {
            RouteDistinguisher::TwoOctetAs { admin, assigned } => {
                dst.put_u16(Self::TYPE_TWO_OCTET_AS);
                dst.put_u16(admin);
                dst.put_u32(assigned);
            }
            RouteDistinguisher::Ipv4 { admin, assigned } => {
                dst.put_u16(Self::TYPE_IPV4);
                dst.put_slice(&admin.octets());
                dst.put_u16(assigned);
            }
            RouteDistinguisher::FourOctetAs { admin, assigned } => {
                dst.put_u16(Self::TYPE_FOUR_OCTET_AS);
                dst.put_u32(admin);
                dst.put_u16(assigned);
            }
        }
    }
}

impl fmt::Display for RouteDistinguisher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RouteDistinguisher::TwoOctetAs { admin, assigned } => {
                write!(f, "{}:{}", admin, assigned)
            }
            RouteDistinguisher::Ipv4 { admin, assigned } => write!(f, "{}:{}", admin, assigned),
            RouteDistinguisher::FourOctetAs { admin, assigned } => {
                write!(f, "{}:{}", admin, assigned)
            }
        }
    }
}

impl FromStr for RouteDistinguisher {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let malformed = || -> Error { BgpError::UpdateMalformedAttributeList.into() };
        let (admin_str, assigned_str) = s.rsplit_once(':').ok_or_else(malformed)?;
        if let Ok(addr) = admin_str.parse::<Ipv4Addr>() {
            let assigned: u16 = assigned_str.parse().map_err(|_| malformed())?;
            return Ok(RouteDistinguisher::Ipv4 {
                admin: addr,
                assigned,
            });
        }
        let admin: u32 = admin_str.parse().map_err(|_| malformed())?;
        if admin <= u16::MAX as u32 {
            let assigned: u32 = assigned_str.parse().map_err(|_| malformed())?;
            Ok(RouteDistinguisher::TwoOctetAs {
                admin: admin as u16,
                assigned,
            })
        } else {
            let assigned: u16 = assigned_str.parse().map_err(|_| malformed())?;
            Ok(RouteDistinguisher::FourOctetAs { admin, assigned })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(rd: RouteDistinguisher) {
        let mut buf = Vec::with_capacity(RouteDistinguisher::LEN);
        rd.encode(&mut buf);
        assert_eq!(buf.len(), RouteDistinguisher::LEN);
        let decoded = RouteDistinguisher::decode(&buf).unwrap();
        assert_eq!(rd, decoded);
    }

    #[test]
    fn rd_two_octet_as_roundtrip() {
        roundtrip(RouteDistinguisher::TwoOctetAs {
            admin: 65000,
            assigned: 12345,
        });
    }

    #[test]
    fn rd_ipv4_roundtrip() {
        roundtrip(RouteDistinguisher::Ipv4 {
            admin: Ipv4Addr::new(192, 0, 2, 1),
            assigned: 100,
        });
    }

    #[test]
    fn rd_four_octet_as_roundtrip() {
        roundtrip(RouteDistinguisher::FourOctetAs {
            admin: 4_200_000_000,
            assigned: 7,
        });
    }

    #[test]
    fn rd_two_octet_as_wire_format() {
        let rd = RouteDistinguisher::TwoOctetAs {
            admin: 0x00fd,
            assigned: 0x1234_5678,
        };
        let mut buf = Vec::new();
        rd.encode(&mut buf);
        assert_eq!(buf, vec![0x00, 0x00, 0x00, 0xfd, 0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn rd_ipv4_wire_format() {
        let rd = RouteDistinguisher::Ipv4 {
            admin: Ipv4Addr::new(192, 0, 2, 1),
            assigned: 0x00c8,
        };
        let mut buf = Vec::new();
        rd.encode(&mut buf);
        assert_eq!(buf, vec![0x00, 0x01, 192, 0, 2, 1, 0x00, 0xc8]);
    }

    #[test]
    fn rd_four_octet_as_wire_format() {
        let rd = RouteDistinguisher::FourOctetAs {
            admin: 0x1234_5678,
            assigned: 0x00c8,
        };
        let mut buf = Vec::new();
        rd.encode(&mut buf);
        assert_eq!(buf, vec![0x00, 0x02, 0x12, 0x34, 0x56, 0x78, 0x00, 0xc8]);
    }

    #[test]
    fn rd_decode_rejects_unknown_type() {
        assert!(RouteDistinguisher::decode(&[0x00, 0x03, 0, 0, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn rd_decode_rejects_bad_length() {
        assert!(RouteDistinguisher::decode(&[0x00, 0x00, 0, 0, 0, 0, 0]).is_err());
        assert!(RouteDistinguisher::decode(&[0x00, 0x00, 0, 0, 0, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn rd_from_str_two_octet_as() {
        assert_eq!(
            "100:200".parse::<RouteDistinguisher>().unwrap(),
            RouteDistinguisher::TwoOctetAs {
                admin: 100,
                assigned: 200,
            }
        );
    }

    #[test]
    fn rd_from_str_ipv4() {
        assert_eq!(
            "192.0.2.1:100".parse::<RouteDistinguisher>().unwrap(),
            RouteDistinguisher::Ipv4 {
                admin: Ipv4Addr::new(192, 0, 2, 1),
                assigned: 100,
            }
        );
    }

    #[test]
    fn rd_from_str_four_octet_as() {
        assert_eq!(
            "4200000000:7".parse::<RouteDistinguisher>().unwrap(),
            RouteDistinguisher::FourOctetAs {
                admin: 4_200_000_000,
                assigned: 7,
            }
        );
    }

    #[test]
    fn rd_from_str_display_roundtrip() {
        for input in ["100:200", "192.0.2.1:100", "4200000000:7"] {
            let rd: RouteDistinguisher = input.parse().unwrap();
            assert_eq!(rd.to_string(), input);
        }
    }

    #[test]
    fn rd_from_str_rejects_garbage() {
        assert!("".parse::<RouteDistinguisher>().is_err());
        assert!("100".parse::<RouteDistinguisher>().is_err());
        assert!("abc:def".parse::<RouteDistinguisher>().is_err());
        assert!("100:99999999999".parse::<RouteDistinguisher>().is_err());
    }
}
