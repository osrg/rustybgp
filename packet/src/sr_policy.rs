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

//! SR Policy NLRI encoding/decoding (RFC 9830 §2.1).
//!
//! AFI/SAFI 1/73 (IPv4 endpoint) and 2/73 (IPv6 endpoint).

use byteorder::{NetworkEndian, ReadBytesExt};
use bytes::BufMut;
use std::fmt;
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// NLRI length in bits: Distinguisher(4) + Color(4) + Endpoint(4 or 16)
const IPV4_LENGTH_BITS: u8 = 96;
const IPV6_LENGTH_BITS: u8 = 192;

/// SR Policy NLRI: <Distinguisher, Color, Endpoint> tuple (RFC 9830 §2.1).
///
/// Wire format: 1-byte length (bits) + 4-byte distinguisher + 4-byte color +
/// 4-byte (IPv4) or 16-byte (IPv6) endpoint.
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct SrPolicyNlri {
    pub distinguisher: u32,
    pub color: u32,
    pub endpoint: IpAddr,
}

impl SrPolicyNlri {
    pub fn encode<B: BufMut>(&self, dst: &mut B) {
        match self.endpoint {
            IpAddr::V4(addr) => {
                dst.put_u8(IPV4_LENGTH_BITS);
                dst.put_u32(self.distinguisher);
                dst.put_u32(self.color);
                dst.put_slice(&addr.octets());
            }
            IpAddr::V6(addr) => {
                dst.put_u8(IPV6_LENGTH_BITS);
                dst.put_u32(self.distinguisher);
                dst.put_u32(self.color);
                dst.put_slice(&addr.octets());
            }
        }
    }

    pub fn decode<R: Read + ReadBytesExt>(c: &mut R) -> Result<Self, io::Error> {
        let length_bits = c.read_u8()?;
        let distinguisher = c.read_u32::<NetworkEndian>()?;
        let color = c.read_u32::<NetworkEndian>()?;
        let endpoint = match length_bits {
            IPV4_LENGTH_BITS => {
                let mut b = [0u8; 4];
                c.read_exact(&mut b)?;
                IpAddr::V4(Ipv4Addr::from(b))
            }
            IPV6_LENGTH_BITS => {
                let mut b = [0u8; 16];
                c.read_exact(&mut b)?;
                IpAddr::V6(Ipv6Addr::from(b))
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid SR Policy NLRI length field",
                ));
            }
        };
        Ok(SrPolicyNlri {
            distinguisher,
            color,
            endpoint,
        })
    }
}

impl fmt::Display for SrPolicyNlri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sr-policy:{}:{}:{}",
            self.distinguisher, self.color, self.endpoint
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn roundtrip_ipv4() {
        let nlri = SrPolicyNlri {
            distinguisher: 1,
            color: 100,
            endpoint: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        };
        let mut buf = Vec::new();
        nlri.encode(&mut buf);
        // 1 (length) + 4 (distinguisher) + 4 (color) + 4 (endpoint) = 13
        assert_eq!(buf.len(), 13);
        let decoded = SrPolicyNlri::decode(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(decoded, nlri);
    }

    #[test]
    fn roundtrip_ipv6() {
        let nlri = SrPolicyNlri {
            distinguisher: 2,
            color: 200,
            endpoint: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        };
        let mut buf = Vec::new();
        nlri.encode(&mut buf);
        // 1 (length) + 4 (distinguisher) + 4 (color) + 16 (endpoint) = 25
        assert_eq!(buf.len(), 25);
        let decoded = SrPolicyNlri::decode(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(decoded, nlri);
    }

    #[test]
    fn decode_invalid_length_rejected() {
        // length_bits = 0 is invalid
        let buf = [0u8, 0, 0, 0, 1, 0, 0, 0, 64, 10, 0, 0, 1];
        assert!(SrPolicyNlri::decode(&mut Cursor::new(&buf)).is_err());
    }
}
