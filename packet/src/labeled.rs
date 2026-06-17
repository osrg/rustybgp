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

//! BGP Labeled Unicast NLRI (RFC 8277), AFI=1/SAFI=4 and AFI=2/SAFI=4.
//!
//! Wire format per NLRI entry (reach):
//!   1 byte  total bit-length = label_bits + prefix_bits
//!   N×3 bytes MPLS label stack (RFC 3032; BoS bit terminates the stack)
//!   ceil(prefix_bits/8) bytes IP prefix (significant octets only)
//!
//! For unreach (RFC 8277 §2.4), the label field is a fixed 24-bit
//! Compatibility field that MUST be ignored on receipt.

use crate::bgp::{Ipv4Net, Ipv6Net};
use crate::mpls::{MplsLabel, MplsLabelStack};
use byteorder::ReadBytesExt;
use bytes::BufMut;
use std::fmt;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

fn malformed() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "malformed labeled unicast NLRI")
}

/// Labeled IPv4 Unicast NLRI (AFI=1, SAFI=4).
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct LabeledV4Nlri {
    pub labels: MplsLabelStack,
    pub prefix: Ipv4Net,
}

/// Labeled IPv6 Unicast NLRI (AFI=2, SAFI=4).
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct LabeledV6Nlri {
    pub labels: MplsLabelStack,
    pub prefix: Ipv6Net,
}

impl LabeledV4Nlri {
    /// Decode a single labeled IPv4 NLRI from `c`.
    ///
    /// `is_reach`: true for MP_REACH_NLRI (BoS-terminated label stack),
    /// false for MP_UNREACH_NLRI (RFC 8277 §2.4: fixed 3-byte compatibility
    /// field, ignored on receipt).
    pub fn decode<T: io::Read>(c: &mut T, len: usize, is_reach: bool) -> Result<Self, io::Error> {
        if len < 1 + 3 {
            return Err(malformed());
        }
        let total_bits = c.read_u8()?;
        if total_bits < 24 {
            return Err(malformed());
        }

        let (labels, label_bits) = if is_reach {
            let stack = MplsLabelStack::decode(c)?;
            let bits = (stack.encoded_len() * 8) as u8;
            (stack, bits)
        } else {
            // Unreach: discard the fixed 3-byte compatibility field.
            let mut buf = [0u8; 3];
            c.read_exact(&mut buf)?;
            (MplsLabelStack::new(vec![MplsLabel::new(0)]), 24)
        };

        if total_bits < label_bits {
            return Err(malformed());
        }
        let prefix_bits = total_bits - label_bits;
        if prefix_bits > 32 {
            return Err(malformed());
        }
        let prefix_bytes = prefix_bits.div_ceil(8) as usize;

        let mut addr = [0u8; 4];
        for b in addr.iter_mut().take(prefix_bytes) {
            *b = c.read_u8()?;
        }

        Ok(LabeledV4Nlri {
            labels,
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
        dst.put_u8((self.labels.encoded_len() * 8) as u8 + prefix_bits);
        self.labels.encode(dst);
        for i in 0..prefix_bytes {
            dst.put_u8(self.prefix.addr.octets()[i]);
        }
        (1 + self.labels.encoded_len() + prefix_bytes) as u16
    }
}

impl LabeledV6Nlri {
    /// Decode a single labeled IPv6 NLRI from `c`.
    ///
    /// `is_reach`: true for MP_REACH_NLRI, false for MP_UNREACH_NLRI.
    /// See `LabeledV4Nlri::decode` for details.
    pub fn decode<T: io::Read>(c: &mut T, len: usize, is_reach: bool) -> Result<Self, io::Error> {
        if len < 1 + 3 {
            return Err(malformed());
        }
        let total_bits = c.read_u8()?;
        if total_bits < 24 {
            return Err(malformed());
        }

        let (labels, label_bits) = if is_reach {
            let stack = MplsLabelStack::decode(c)?;
            let bits = (stack.encoded_len() * 8) as u8;
            (stack, bits)
        } else {
            let mut buf = [0u8; 3];
            c.read_exact(&mut buf)?;
            (MplsLabelStack::new(vec![MplsLabel::new(0)]), 24)
        };

        if total_bits < label_bits {
            return Err(malformed());
        }
        let prefix_bits = total_bits - label_bits;
        if prefix_bits > 128 {
            return Err(malformed());
        }
        let prefix_bytes = prefix_bits.div_ceil(8) as usize;

        let mut addr = [0u8; 16];
        for b in addr.iter_mut().take(prefix_bytes) {
            *b = c.read_u8()?;
        }

        Ok(LabeledV6Nlri {
            labels,
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
        dst.put_u8((self.labels.encoded_len() * 8) as u8 + prefix_bits);
        self.labels.encode(dst);
        for i in 0..prefix_bytes {
            dst.put_u8(self.prefix.addr.octets()[i]);
        }
        (1 + self.labels.encoded_len() + prefix_bytes) as u16
    }
}

impl fmt::Display for LabeledV4Nlri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.prefix.addr, self.prefix.mask)
    }
}

impl fmt::Display for LabeledV6Nlri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.prefix.addr, self.prefix.mask)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpls::MplsLabel;
    use std::io::Cursor;

    // GoBGP-generated test vectors (packet/tests/fixtures/gen/labeled_nlri/main.go).
    // Each constant is the wire encoding of a single NLRI entry including
    // the leading total-bit-length byte.

    // IPv4 single label: label=100, prefix=10.0.1.0/24
    const GOBGP_V4_SINGLE_LABEL: &[u8] = &[0x30, 0x00, 0x06, 0x41, 0x0a, 0x00, 0x01];

    // IPv4 label stack [100, 200]: prefix=10.0.1.0/24
    const GOBGP_V4_LABEL_STACK: &[u8] =
        &[0x48, 0x00, 0x06, 0x40, 0x00, 0x0c, 0x81, 0x0a, 0x00, 0x01];

    // IPv4 host route: label=500, prefix=192.168.1.1/32
    const GOBGP_V4_HOST: &[u8] = &[0x38, 0x00, 0x1f, 0x41, 0xc0, 0xa8, 0x01, 0x01];

    // IPv4 unreach (GoBGP withdraw label 0x800000): prefix=10.0.1.0/24
    const GOBGP_V4_UNREACH: &[u8] = &[0x30, 0x80, 0x00, 0x00, 0x0a, 0x00, 0x01];

    // IPv6 single label: label=300, prefix=2001:db8::/32
    const GOBGP_V6_SINGLE_LABEL: &[u8] = &[0x38, 0x00, 0x12, 0xc1, 0x20, 0x01, 0x0d, 0xb8];

    // IPv6 label stack [100, 200]: prefix=2001:db8::/48
    const GOBGP_V6_LABEL_STACK: &[u8] = &[
        0x60, 0x00, 0x06, 0x40, 0x00, 0x0c, 0x81, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00,
    ];

    #[test]
    fn v4_single_label_roundtrip() {
        let mut c = Cursor::new(GOBGP_V4_SINGLE_LABEL);
        let nlri = LabeledV4Nlri::decode(&mut c, GOBGP_V4_SINGLE_LABEL.len(), true).unwrap();
        assert_eq!(nlri.labels.labels().len(), 1);
        assert_eq!(nlri.labels.labels()[0].value(), 100);
        assert_eq!(nlri.prefix.addr, Ipv4Addr::new(10, 0, 1, 0));
        assert_eq!(nlri.prefix.mask, 24);

        let mut buf = Vec::new();
        nlri.encode(&mut buf);
        assert_eq!(buf, GOBGP_V4_SINGLE_LABEL);
    }

    #[test]
    fn v4_label_stack_roundtrip() {
        let mut c = Cursor::new(GOBGP_V4_LABEL_STACK);
        let nlri = LabeledV4Nlri::decode(&mut c, GOBGP_V4_LABEL_STACK.len(), true).unwrap();
        assert_eq!(nlri.labels.labels().len(), 2);
        assert_eq!(nlri.labels.labels()[0].value(), 100);
        assert_eq!(nlri.labels.labels()[1].value(), 200);
        assert_eq!(nlri.prefix.addr, Ipv4Addr::new(10, 0, 1, 0));
        assert_eq!(nlri.prefix.mask, 24);

        let mut buf = Vec::new();
        nlri.encode(&mut buf);
        assert_eq!(buf, GOBGP_V4_LABEL_STACK);
    }

    #[test]
    fn v4_unreach_ignores_label() {
        // Unreach with RFC 8277 compatibility value 0x800000 (BoS=0).
        // total_bits = 24 + 24 = 48 = 0x30
        let wire: &[u8] = &[0x30, 0x80, 0x00, 0x00, 0x0a, 0x00, 0x01];
        let mut c = Cursor::new(wire);
        let nlri = LabeledV4Nlri::decode(&mut c, wire.len(), false).unwrap();
        // Label value is ignored; prefix must be decoded correctly.
        assert_eq!(nlri.prefix.addr, Ipv4Addr::new(10, 0, 1, 0));
        assert_eq!(nlri.prefix.mask, 24);
    }

    #[test]
    fn v4_unreach_bird_compat_label() {
        // Unreach with BIRD-style 0x000001 (label=0, BoS=1).
        let wire: &[u8] = &[0x30, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x01];
        let mut c = Cursor::new(wire);
        let nlri = LabeledV4Nlri::decode(&mut c, wire.len(), false).unwrap();
        assert_eq!(nlri.prefix.addr, Ipv4Addr::new(10, 0, 1, 0));
        assert_eq!(nlri.prefix.mask, 24);
    }

    #[test]
    fn v6_single_label_roundtrip() {
        let mut c = Cursor::new(GOBGP_V6_SINGLE_LABEL);
        let nlri = LabeledV6Nlri::decode(&mut c, GOBGP_V6_SINGLE_LABEL.len(), true).unwrap();
        assert_eq!(nlri.labels.labels().len(), 1);
        assert_eq!(nlri.labels.labels()[0].value(), 300);
        assert_eq!(nlri.prefix.addr, "2001:db8::".parse::<Ipv6Addr>().unwrap());
        assert_eq!(nlri.prefix.mask, 32);

        let mut buf = Vec::new();
        nlri.encode(&mut buf);
        assert_eq!(buf, GOBGP_V6_SINGLE_LABEL);
    }

    fn assert_v4_roundtrip(bytes: &[u8]) -> LabeledV4Nlri {
        let mut c = Cursor::new(bytes);
        let nlri = LabeledV4Nlri::decode(&mut c, bytes.len(), true).expect("decode failed");
        let mut buf = Vec::new();
        nlri.encode(&mut buf);
        assert_eq!(buf, bytes);
        nlri
    }

    fn assert_v6_roundtrip(bytes: &[u8]) -> LabeledV6Nlri {
        let mut c = Cursor::new(bytes);
        let nlri = LabeledV6Nlri::decode(&mut c, bytes.len(), true).expect("decode failed");
        let mut buf = Vec::new();
        nlri.encode(&mut buf);
        assert_eq!(buf, bytes);
        nlri
    }

    #[test]
    fn gobgp_v4_single_label() {
        let nlri = assert_v4_roundtrip(GOBGP_V4_SINGLE_LABEL);
        assert_eq!(nlri.labels.labels().len(), 1);
        assert_eq!(nlri.labels.labels()[0].value(), 100);
        assert_eq!(nlri.prefix.addr, Ipv4Addr::new(10, 0, 1, 0));
        assert_eq!(nlri.prefix.mask, 24);
    }

    #[test]
    fn gobgp_v4_label_stack() {
        let nlri = assert_v4_roundtrip(GOBGP_V4_LABEL_STACK);
        assert_eq!(nlri.labels.labels().len(), 2);
        assert_eq!(nlri.labels.labels()[0].value(), 100);
        assert_eq!(nlri.labels.labels()[1].value(), 200);
        assert_eq!(nlri.prefix.addr, Ipv4Addr::new(10, 0, 1, 0));
        assert_eq!(nlri.prefix.mask, 24);
    }

    #[test]
    fn gobgp_v4_host() {
        let nlri = assert_v4_roundtrip(GOBGP_V4_HOST);
        assert_eq!(nlri.labels.labels().len(), 1);
        assert_eq!(nlri.labels.labels()[0].value(), 500);
        assert_eq!(nlri.prefix.addr, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(nlri.prefix.mask, 32);
    }

    #[test]
    fn gobgp_v4_unreach() {
        // GoBGP uses 0x800000 as the withdraw label for unreach NLRIs.
        let mut c = Cursor::new(GOBGP_V4_UNREACH);
        let nlri = LabeledV4Nlri::decode(&mut c, GOBGP_V4_UNREACH.len(), false).unwrap();
        assert_eq!(nlri.prefix.addr, Ipv4Addr::new(10, 0, 1, 0));
        assert_eq!(nlri.prefix.mask, 24);
    }

    #[test]
    fn gobgp_v6_single_label() {
        let nlri = assert_v6_roundtrip(GOBGP_V6_SINGLE_LABEL);
        assert_eq!(nlri.labels.labels().len(), 1);
        assert_eq!(nlri.labels.labels()[0].value(), 300);
        assert_eq!(nlri.prefix.addr, "2001:db8::".parse::<Ipv6Addr>().unwrap());
        assert_eq!(nlri.prefix.mask, 32);
    }

    #[test]
    fn gobgp_v6_label_stack() {
        let nlri = assert_v6_roundtrip(GOBGP_V6_LABEL_STACK);
        assert_eq!(nlri.labels.labels().len(), 2);
        assert_eq!(nlri.labels.labels()[0].value(), 100);
        assert_eq!(nlri.labels.labels()[1].value(), 200);
        assert_eq!(nlri.prefix.addr, "2001:db8::".parse::<Ipv6Addr>().unwrap());
        assert_eq!(nlri.prefix.mask, 48);
    }

    #[test]
    fn v4_encode_uses_label_stack() {
        let nlri = LabeledV4Nlri {
            labels: MplsLabelStack::new(vec![MplsLabel::new(0)]),
            prefix: Ipv4Net {
                addr: Ipv4Addr::new(192, 168, 1, 0),
                mask: 24,
            },
        };
        let mut buf = Vec::new();
        nlri.encode(&mut buf);
        // total_bits = 24 + 24 = 0x30; label 0 BoS = 0x000001; prefix = 0xc0 0xa8 0x01
        assert_eq!(buf, &[0x30, 0x00, 0x00, 0x01, 0xc0, 0xa8, 0x01]);
    }
}
