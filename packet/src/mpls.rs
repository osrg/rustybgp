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

use crate::error::{Error, Notification};
use bytes::BufMut;
use std::io;

/// A 20-bit MPLS label (RFC 3032).
///
/// Wire encoding is 3 bytes: 20-bit label | 3-bit TC | 1-bit BoS.
#[derive(PartialEq, Eq, Hash, Clone, Debug, Copy)]
pub struct MplsLabel(u32);

impl MplsLabel {
    /// Implicit NULL label (PHP - Penultimate Hop Popping), value 3.
    pub const IMPLICIT_NULL: Self = Self(3);
    /// Number of bytes in the wire encoding.
    pub const ENCODED_LEN: usize = 3;

    pub fn new(value: u32) -> Self {
        MplsLabel(value & 0x000F_FFFF)
    }

    pub fn value(&self) -> u32 {
        self.0
    }

    pub fn decode(data: &[u8; 3]) -> Self {
        let raw = (data[0] as u32) << 16 | (data[1] as u32) << 8 | data[2] as u32;
        MplsLabel(raw >> 4)
    }

    /// Encode to wire format. `bottom_of_stack` sets the BoS bit.
    pub fn encode<B: BufMut>(&self, dst: &mut B, bottom_of_stack: bool) {
        let raw = (self.0 << 4) | bottom_of_stack as u32;
        dst.put_u8((raw >> 16) as u8);
        dst.put_u8((raw >> 8) as u8);
        dst.put_u8(raw as u8);
    }
}

/// An ordered stack of MPLS labels (RFC 3032 Section 2.1).
///
/// The outermost (top-of-stack) label is first; the innermost (bottom-of-stack)
/// label is last and carries the BoS bit on the wire.
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct MplsLabelStack(Vec<MplsLabel>);

impl MplsLabelStack {
    pub fn new(labels: Vec<MplsLabel>) -> Self {
        MplsLabelStack(labels)
    }

    pub fn labels(&self) -> &[MplsLabel] {
        &self.0
    }

    /// Number of bytes occupied by this stack on the wire.
    pub fn encoded_len(&self) -> usize {
        self.0.len() * MplsLabel::ENCODED_LEN
    }

    /// Decode a label stack from `c`, reading 3-byte labels until BoS=1.
    pub fn decode<T: io::Read>(c: &mut T) -> Result<Self, Error> {
        let mut labels = Vec::new();
        loop {
            let mut buf = [0u8; 3];
            c.read_exact(&mut buf)
                .map_err(|_| Error::from(Notification::UpdateMalformedAttributeList))?;
            let bos = (buf[2] & 1) != 0;
            labels.push(MplsLabel::decode(&buf));
            if bos {
                break;
            }
        }
        Ok(MplsLabelStack(labels))
    }

    /// Encode label stack. The BoS bit is set on the last (innermost) label.
    pub fn encode<B: BufMut>(&self, dst: &mut B) {
        let last = self.0.len().saturating_sub(1);
        for (i, label) in self.0.iter().enumerate() {
            label.encode(dst, i == last);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let label = MplsLabel::new(100);
        let mut buf = Vec::new();
        label.encode(&mut buf, true);
        assert_eq!(buf.len(), 3);
        let decoded = MplsLabel::decode(buf[..3].try_into().unwrap());
        assert_eq!(decoded.value(), 100);
    }

    #[test]
    fn implicit_null() {
        assert_eq!(MplsLabel::IMPLICIT_NULL.value(), 3);
    }

    #[test]
    fn bos_bit() {
        let label = MplsLabel::new(0);
        let mut buf_bos = Vec::new();
        label.encode(&mut buf_bos, true);
        assert_eq!(buf_bos[2] & 1, 1);

        let mut buf_no_bos = Vec::new();
        label.encode(&mut buf_no_bos, false);
        assert_eq!(buf_no_bos[2] & 1, 0);
    }

    #[test]
    fn label_stack_single_roundtrip() {
        let stack = MplsLabelStack::new(vec![MplsLabel::new(100)]);
        let mut buf = Vec::new();
        stack.encode(&mut buf);
        // Single label: BoS must be set
        assert_eq!(buf[2] & 1, 1);
        assert_eq!(buf.len(), 3);

        let mut c = std::io::Cursor::new(&buf);
        let decoded = MplsLabelStack::decode(&mut c).unwrap();
        assert_eq!(decoded.labels().len(), 1);
        assert_eq!(decoded.labels()[0].value(), 100);
    }

    #[test]
    fn label_stack_multi_roundtrip() {
        let stack = MplsLabelStack::new(vec![MplsLabel::new(200), MplsLabel::new(300)]);
        let mut buf = Vec::new();
        stack.encode(&mut buf);
        assert_eq!(buf.len(), 6);
        // First label: BoS clear; second label: BoS set
        assert_eq!(buf[2] & 1, 0);
        assert_eq!(buf[5] & 1, 1);

        let mut c = std::io::Cursor::new(&buf);
        let decoded = MplsLabelStack::decode(&mut c).unwrap();
        assert_eq!(decoded.labels().len(), 2);
        assert_eq!(decoded.labels()[0].value(), 200);
        assert_eq!(decoded.labels()[1].value(), 300);
    }

    #[test]
    fn label_stack_encoded_len() {
        let stack = MplsLabelStack::new(vec![MplsLabel::new(1), MplsLabel::new(2)]);
        assert_eq!(stack.encoded_len(), 6);
    }
}
