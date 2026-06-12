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
// implied.  See the License for the specific language governing
// permissions and limitations under the License.

//! BGP/MPLS IP VPN NLRI (RFC 4364), AFI=1/SAFI=128 (VPNv4) and AFI=2/SAFI=129 (VPNv6).
//!
//! Wire format per NLRI entry:
//!   1 byte  total bit-length = 24 (label) + 64 (RD) + prefix_bits
//!   3 bytes MPLS label (RFC 3032: 20-bit label | 3-bit TC | 1-bit BoS)
//!   8 bytes Route Distinguisher
//!   ceil(prefix_bits/8) bytes IP prefix (significant octets only)

use crate::bgp::{Ipv4Net, Ipv6Net};
use crate::error::{BgpError, Error};
use crate::mpls::MplsLabelStack;
use crate::rd::RouteDistinguisher;
use byteorder::ReadBytesExt;
use bytes::BufMut;
use std::fmt;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

/// RD is always 64 bits on the wire.
const VPN_RD_BITS: u8 = 64;

fn malformed() -> Error {
    BgpError::UpdateMalformedAttributeList.into()
}

/// VPNv4 NLRI (AFI=1, SAFI=128).
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct VpnV4Nlri {
    pub labels: MplsLabelStack,
    pub rd: RouteDistinguisher,
    pub prefix: Ipv4Net,
}

/// VPNv6 NLRI (AFI=2, SAFI=129).
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct VpnV6Nlri {
    pub labels: MplsLabelStack,
    pub rd: RouteDistinguisher,
    pub prefix: Ipv6Net,
}

impl VpnV4Nlri {
    /// Decode a single VPNv4 NLRI from `c`. `len` is the remaining buffer bytes.
    pub fn decode<T: io::Read>(c: &mut T, len: usize) -> Result<Self, Error> {
        // Minimum: 1-byte length + 3-byte label + 8-byte RD
        if len < 1 + 3 + RouteDistinguisher::LEN {
            return Err(malformed());
        }
        let total_bits = c.read_u8()?;
        // At least one label (24 bits) + RD (64 bits) required
        if total_bits < 24 + VPN_RD_BITS {
            return Err(malformed());
        }

        let labels = MplsLabelStack::decode(c)?;
        let label_bits = (labels.encoded_len() * 8) as u8;
        if total_bits < label_bits + VPN_RD_BITS {
            return Err(malformed());
        }
        let prefix_bits = total_bits - label_bits - VPN_RD_BITS;
        if prefix_bits > 32 {
            return Err(malformed());
        }
        let prefix_bytes = prefix_bits.div_ceil(8) as usize;

        let mut rd_buf = [0u8; 8];
        c.read_exact(&mut rd_buf)?;
        let rd = RouteDistinguisher::decode(&rd_buf)?;

        let mut addr = [0u8; 4];
        for b in addr.iter_mut().take(prefix_bytes) {
            *b = c.read_u8()?;
        }

        Ok(VpnV4Nlri {
            labels,
            rd,
            prefix: Ipv4Net {
                addr: Ipv4Addr::from(addr),
                mask: prefix_bits,
            },
        })
    }

    /// Encode to wire format. Returns the number of bytes written.
    pub fn encode<B: BufMut>(&self, dst: &mut B) -> u16 {
        let prefix_bits = self.prefix.mask;
        let prefix_bytes = prefix_bits.div_ceil(8) as usize;
        dst.put_u8((self.labels.encoded_len() * 8) as u8 + VPN_RD_BITS + prefix_bits);
        self.labels.encode(dst);
        self.rd.encode(dst);
        for i in 0..prefix_bytes {
            dst.put_u8(self.prefix.addr.octets()[i]);
        }
        (1 + self.labels.encoded_len() + RouteDistinguisher::LEN + prefix_bytes) as u16
    }
}

impl VpnV6Nlri {
    /// Decode a single VPNv6 NLRI from `c`. `len` is the remaining buffer bytes.
    pub fn decode<T: io::Read>(c: &mut T, len: usize) -> Result<Self, Error> {
        // Minimum: 1-byte length + 3-byte label + 8-byte RD
        if len < 1 + 3 + RouteDistinguisher::LEN {
            return Err(malformed());
        }
        let total_bits = c.read_u8()?;
        // At least one label (24 bits) + RD (64 bits) required
        if total_bits < 24 + VPN_RD_BITS {
            return Err(malformed());
        }

        let labels = MplsLabelStack::decode(c)?;
        let label_bits = (labels.encoded_len() * 8) as u8;
        if total_bits < label_bits + VPN_RD_BITS {
            return Err(malformed());
        }
        let prefix_bits = total_bits - label_bits - VPN_RD_BITS;
        if prefix_bits > 128 {
            return Err(malformed());
        }
        let prefix_bytes = prefix_bits.div_ceil(8) as usize;

        let mut rd_buf = [0u8; 8];
        c.read_exact(&mut rd_buf)?;
        let rd = RouteDistinguisher::decode(&rd_buf)?;

        let mut addr = [0u8; 16];
        for b in addr.iter_mut().take(prefix_bytes) {
            *b = c.read_u8()?;
        }

        Ok(VpnV6Nlri {
            labels,
            rd,
            prefix: Ipv6Net {
                addr: Ipv6Addr::from(addr),
                mask: prefix_bits,
            },
        })
    }

    /// Encode to wire format. Returns the number of bytes written.
    pub fn encode<B: BufMut>(&self, dst: &mut B) -> u16 {
        let prefix_bits = self.prefix.mask;
        let prefix_bytes = prefix_bits.div_ceil(8) as usize;
        dst.put_u8((self.labels.encoded_len() * 8) as u8 + VPN_RD_BITS + prefix_bits);
        self.labels.encode(dst);
        self.rd.encode(dst);
        for i in 0..prefix_bytes {
            dst.put_u8(self.prefix.addr.octets()[i]);
        }
        (1 + self.labels.encoded_len() + RouteDistinguisher::LEN + prefix_bytes) as u16
    }
}

impl fmt::Display for VpnV4Nlri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.rd, self.prefix.addr, self.prefix.mask)
    }
}

impl fmt::Display for VpnV6Nlri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.rd, self.prefix.addr, self.prefix.mask)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpls::MplsLabel;
    use std::io::Cursor;

    fn rd() -> RouteDistinguisher {
        RouteDistinguisher::TwoOctetAs {
            admin: 65000,
            assigned: 100,
        }
    }

    fn single_label(value: u32) -> MplsLabelStack {
        MplsLabelStack::new(vec![MplsLabel::new(value)])
    }

    #[test]
    fn vpnv4_roundtrip() {
        let nlri = VpnV4Nlri {
            labels: single_label(200),
            rd: rd(),
            prefix: Ipv4Net {
                addr: Ipv4Addr::new(10, 0, 1, 0),
                mask: 24,
            },
        };

        let mut buf = Vec::new();
        let written = nlri.encode(&mut buf);
        assert_eq!(written as usize, buf.len());
        // total_bits = 24 (label) + 64 (RD) + 24 (prefix) = 112, bytes: 1 + 3 + 8 + 3 = 15
        assert_eq!(written, 15);

        let mut c = Cursor::new(&buf);
        let decoded = VpnV4Nlri::decode(&mut c, buf.len()).unwrap();
        assert_eq!(decoded.labels.labels().len(), 1);
        assert_eq!(decoded.labels.labels()[0].value(), 200);
        assert_eq!(decoded.rd, rd());
        assert_eq!(decoded.prefix.addr, Ipv4Addr::new(10, 0, 1, 0));
        assert_eq!(decoded.prefix.mask, 24);
    }

    #[test]
    fn vpnv4_label_stack() {
        let nlri = VpnV4Nlri {
            labels: MplsLabelStack::new(vec![MplsLabel::new(100), MplsLabel::new(200)]),
            rd: rd(),
            prefix: Ipv4Net {
                addr: Ipv4Addr::new(10, 0, 1, 0),
                mask: 24,
            },
        };

        let mut buf = Vec::new();
        let written = nlri.encode(&mut buf);
        assert_eq!(written as usize, buf.len());
        // total_bits = 48 (2 labels) + 64 (RD) + 24 (prefix) = 136, bytes: 1 + 6 + 8 + 3 = 18
        assert_eq!(written, 18);

        let mut c = Cursor::new(&buf);
        let decoded = VpnV4Nlri::decode(&mut c, buf.len()).unwrap();
        assert_eq!(decoded.labels.labels().len(), 2);
        assert_eq!(decoded.labels.labels()[0].value(), 100);
        assert_eq!(decoded.labels.labels()[1].value(), 200);
        assert_eq!(decoded.prefix.mask, 24);
    }

    #[test]
    fn vpnv6_roundtrip() {
        let nlri = VpnV6Nlri {
            labels: single_label(300),
            rd: rd(),
            prefix: Ipv6Net {
                addr: "2001:db8::".parse().unwrap(),
                mask: 32,
            },
        };

        let mut buf = Vec::new();
        let written = nlri.encode(&mut buf);
        assert_eq!(written as usize, buf.len());
        // total_bits = 24 (label) + 64 (RD) + 32 (prefix) = 120, bytes: 1 + 3 + 8 + 4 = 16
        assert_eq!(written, 16);

        let mut c = Cursor::new(&buf);
        let decoded = VpnV6Nlri::decode(&mut c, buf.len()).unwrap();
        assert_eq!(decoded.labels.labels().len(), 1);
        assert_eq!(decoded.labels.labels()[0].value(), 300);
        assert_eq!(decoded.rd, rd());
        assert_eq!(
            decoded.prefix.addr,
            "2001:db8::".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(decoded.prefix.mask, 32);
    }

    #[test]
    fn vpnv4_default_route() {
        let nlri = VpnV4Nlri {
            labels: single_label(0),
            rd: rd(),
            prefix: Ipv4Net {
                addr: Ipv4Addr::new(0, 0, 0, 0),
                mask: 0,
            },
        };
        let mut buf = Vec::new();
        nlri.encode(&mut buf);
        let mut c = Cursor::new(&buf);
        let decoded = VpnV4Nlri::decode(&mut c, buf.len()).unwrap();
        assert_eq!(decoded.prefix.mask, 0);
    }
}
