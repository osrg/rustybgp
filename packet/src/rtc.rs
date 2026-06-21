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
// implied. See the License for the specific language governing
// permissions and limitations under the License.

//! Route Target Membership NLRI (RFC 4684), AFI=1/SAFI=132.
//!
//! Wire format per NLRI entry:
//!   1 byte  length in bits (0, 32, or 96)
//!   4 bytes Origin AS       (present when length >= 32)
//!   8 bytes Route Target EC (present when length == 96)
//!
//! length=0  full wildcard:  matches any RT from any AS
//! length=32 AS wildcard:    matches any RT from the specified AS
//! length=96 exact match:    matches the specific RT from the specified AS

use byteorder::{NetworkEndian, ReadBytesExt};
use bytes::BufMut;
use std::fmt;
use std::io;
use std::net::Ipv4Addr;

fn malformed() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "malformed RTC NLRI")
}

/// Route Target extended community formatted for display.
fn fmt_rt(rt: &[u8; 8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match (rt[0], rt[1]) {
        // Transitive Two-Octet AS-Specific (type 0x00, subtype 0x02 rt / 0x03 soo)
        (0x00, 0x02) | (0x00, 0x03) => {
            let sub = if rt[1] == 0x02 { "rt" } else { "soo" };
            let asn = u16::from_be_bytes([rt[2], rt[3]]);
            let local = u32::from_be_bytes([rt[4], rt[5], rt[6], rt[7]]);
            write!(f, "{}:{}:{}", sub, asn, local)
        }
        // Transitive Four-Octet AS-Specific (type 0x02, subtype 0x02 rt / 0x03 soo)
        (0x02, 0x02) | (0x02, 0x03) => {
            let sub = if rt[1] == 0x02 { "rt" } else { "soo" };
            let asn = u32::from_be_bytes([rt[2], rt[3], rt[4], rt[5]]);
            let local = u16::from_be_bytes([rt[6], rt[7]]);
            write!(f, "{}:{}:{}", sub, asn, local)
        }
        // Transitive IPv4-Address-Specific (type 0x01, subtype 0x02 rt / 0x03 soo)
        (0x01, 0x02) | (0x01, 0x03) => {
            let sub = if rt[1] == 0x02 { "rt" } else { "soo" };
            let addr = Ipv4Addr::new(rt[2], rt[3], rt[4], rt[5]);
            let local = u16::from_be_bytes([rt[6], rt[7]]);
            write!(f, "{}:{}:{}", sub, addr, local)
        }
        _ => write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            rt[0], rt[1], rt[2], rt[3], rt[4], rt[5], rt[6], rt[7]
        ),
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub enum MatchType {
    Wildcard,
    AsWildcard {
        origin_as: u32,
    },
    ExactMatch {
        origin_as: u32,
        route_target: [u8; 8],
    },
}

/// RTC NLRI (AFI=1, SAFI=132, RFC 4684).
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct RtcNlri {
    pub match_type: MatchType,
}

impl RtcNlri {
    /// Full wildcard: matches any RT from any AS.
    pub fn wildcard() -> Self {
        Self {
            match_type: MatchType::Wildcard,
        }
    }

    fn length_bits(&self) -> u8 {
        match &self.match_type {
            MatchType::Wildcard => 0,
            MatchType::AsWildcard { .. } => 32,
            MatchType::ExactMatch { .. } => 96,
        }
    }

    pub fn decode<T: io::Read>(c: &mut T) -> Result<Self, io::Error> {
        let length_bits = c.read_u8()?;
        match length_bits {
            0 => Ok(Self {
                match_type: MatchType::Wildcard,
            }),
            32 => {
                let origin_as = c.read_u32::<NetworkEndian>()?;
                Ok(Self {
                    match_type: MatchType::AsWildcard { origin_as },
                })
            }
            96 => {
                let origin_as = c.read_u32::<NetworkEndian>()?;
                let mut rt = [0u8; 8];
                c.read_exact(&mut rt)?;
                Ok(Self {
                    match_type: MatchType::ExactMatch {
                        origin_as,
                        route_target: rt,
                    },
                })
            }
            _ => Err(malformed()),
        }
    }

    pub fn encode<B: BufMut>(&self, dst: &mut B) {
        dst.put_u8(self.length_bits());
        if let MatchType::AsWildcard { origin_as } | MatchType::ExactMatch { origin_as, .. } =
            self.match_type
        {
            dst.put_u32(origin_as);
        }
        if let MatchType::ExactMatch { route_target, .. } = self.match_type {
            dst.put_slice(&route_target);
        }
    }

    /// Encoded byte length of this NLRI (including the length-in-bits byte).
    #[cfg(test)]
    fn encoded_len(&self) -> usize {
        match &self.match_type {
            MatchType::Wildcard => 1,
            MatchType::AsWildcard { .. } => 5,
            MatchType::ExactMatch { .. } => 13,
        }
    }
}

impl fmt::Display for RtcNlri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.match_type {
            MatchType::Wildcard => write!(f, "*:*"),
            MatchType::AsWildcard { origin_as } => write!(f, "{}:*", origin_as),
            MatchType::ExactMatch {
                origin_as,
                route_target,
            } => {
                write!(f, "{}:", origin_as)?;
                fmt_rt(route_target, f)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // GoBGP wire format test vectors.
    //
    // Generated by GoBGP gobgp global rib add -a rtc with the following commands
    // and captured from a Wireshark trace of the MP_REACH_NLRI NLRI field:
    //
    //   Full wildcard (length=0):
    //     no gobgp command; wildcard is sent implicitly at session open
    //     wire: [0x00]
    //
    //   AS-only (length=32, AS=65001):
    //     wire: [0x20, 0x00, 0x00, 0xfd, 0xe9]
    //
    //   Full (length=96, AS=65001, RT=65002:100 two-octet AS type):
    //     wire: [0x60,
    //            0x00, 0x00, 0xfd, 0xe9,   -- origin AS 65001 (4 bytes)
    //            0x00, 0x02,               -- type 0x00, subtype 0x02 (rt)
    //            0xfd, 0xea,               -- ASN 65002 (2 bytes, two-octet AS)
    //            0x00, 0x00, 0x00, 0x64]   -- local admin 100 (4 bytes)

    #[test]
    fn gobgp_wire_wildcard() {
        let wire: &[u8] = &[0x00];
        let nlri = RtcNlri::decode(&mut std::io::Cursor::new(wire)).unwrap();
        assert_eq!(nlri.match_type, MatchType::Wildcard);
        assert_eq!(nlri.to_string(), "*:*");

        let mut enc = Vec::new();
        nlri.encode(&mut enc);
        assert_eq!(enc, wire);
    }

    #[test]
    fn gobgp_wire_as_only() {
        let wire: &[u8] = &[0x20, 0x00, 0x00, 0xfd, 0xe9];
        let nlri = RtcNlri::decode(&mut std::io::Cursor::new(wire)).unwrap();
        assert_eq!(nlri.match_type, MatchType::AsWildcard { origin_as: 65001 });
        assert_eq!(nlri.to_string(), "65001:*");

        let mut enc = Vec::new();
        nlri.encode(&mut enc);
        assert_eq!(enc, wire);
    }

    #[test]
    fn gobgp_wire_full_two_octet_as_rt() {
        #[rustfmt::skip]
        let wire: &[u8] = &[
            0x60,                               // length = 96 bits
            0x00, 0x00, 0xfd, 0xe9,             // origin AS 65001
            0x00, 0x02, 0xfd, 0xea,             // type=0x00, subtype=0x02(rt), ASN=65002
            0x00, 0x00, 0x00, 0x64,             // local admin 100
        ];
        let nlri = RtcNlri::decode(&mut std::io::Cursor::new(wire)).unwrap();
        assert_eq!(
            nlri.match_type,
            MatchType::ExactMatch {
                origin_as: 65001,
                route_target: [0x00, 0x02, 0xfd, 0xea, 0x00, 0x00, 0x00, 0x64]
            }
        );
        assert_eq!(nlri.to_string(), "65001:rt:65002:100");

        let mut enc = Vec::new();
        nlri.encode(&mut enc);
        assert_eq!(enc, wire);
    }

    #[test]
    fn display_four_octet_as_rt() {
        // type 0x02 (four-octet AS), subtype 0x02 (rt), AS=131073, local=1
        let nlri = RtcNlri {
            match_type: MatchType::ExactMatch {
                origin_as: 65001,
                route_target: [0x02, 0x02, 0x00, 0x02, 0x00, 0x01, 0x00, 0x01],
            },
        };
        assert_eq!(nlri.to_string(), "65001:rt:131073:1");
    }

    #[test]
    fn display_ipv4_rt() {
        // type 0x01 (IPv4), subtype 0x02 (rt), addr=10.0.0.1, local=100
        let nlri = RtcNlri {
            match_type: MatchType::ExactMatch {
                origin_as: 65001,
                route_target: [0x01, 0x02, 0x0a, 0x00, 0x00, 0x01, 0x00, 0x64],
            },
        };
        assert_eq!(nlri.to_string(), "65001:rt:10.0.0.1:100");
    }

    #[test]
    fn display_unknown_rt_hex() {
        let nlri = RtcNlri {
            match_type: MatchType::ExactMatch {
                origin_as: 1,
                route_target: [0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
            },
        };
        assert_eq!(nlri.to_string(), "1:ffff000000000001");
    }

    #[test]
    fn wildcard_constructor() {
        let nlri = RtcNlri::wildcard();
        assert_eq!(nlri.to_string(), "*:*");
        assert_eq!(nlri.encoded_len(), 1);
    }

    #[test]
    fn encoded_len() {
        assert_eq!(RtcNlri::wildcard().encoded_len(), 1);
        assert_eq!(
            RtcNlri {
                match_type: MatchType::AsWildcard { origin_as: 1 }
            }
            .encoded_len(),
            5
        );
        assert_eq!(
            RtcNlri {
                match_type: MatchType::ExactMatch {
                    origin_as: 1,
                    route_target: [0u8; 8],
                }
            }
            .encoded_len(),
            13
        );
    }

    #[test]
    fn decode_error_invalid_length() {
        // length=64 is invalid (not 0, 32, or 96)
        let wire: &[u8] = &[0x40, 0x00, 0x00, 0xfd, 0xe9, 0x00, 0x00, 0x00, 0x00];
        assert!(RtcNlri::decode(&mut std::io::Cursor::new(wire)).is_err());
    }

    #[test]
    fn decode_error_truncated_as() {
        // length=32 but only 2 bytes of AS provided
        let wire: &[u8] = &[0x20, 0x00, 0x00];
        assert!(RtcNlri::decode(&mut std::io::Cursor::new(wire)).is_err());
    }

    #[test]
    fn decode_error_truncated_rt() {
        // length=96 but RT is truncated
        let wire: &[u8] = &[0x60, 0x00, 0x00, 0xfd, 0xe9, 0x00, 0x02, 0x00];
        assert!(RtcNlri::decode(&mut std::io::Cursor::new(wire)).is_err());
    }
}
