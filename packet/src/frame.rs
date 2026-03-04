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

use byteorder::{NetworkEndian, ReadBytesExt};
use bytes::{BufMut, BytesMut};

use crate::bgp;
use crate::error::{BgpError, Error};

/// BGP framing layer: detects message boundaries in a `BytesMut` stream
/// and delegates parsing to the inner `PeerCodec`.
pub struct BgpFramer(pub bgp::PeerCodec);

impl BgpFramer {
    pub fn new(codec: bgp::PeerCodec) -> Self {
        BgpFramer(codec)
    }

    pub fn inner(&self) -> &bgp::PeerCodec {
        &self.0
    }

    pub fn inner_mut(&mut self) -> &mut bgp::PeerCodec {
        &mut self.0
    }

    /// Try to parse one complete BGP message from `src`.
    /// Returns `Ok(None)` if there are not enough bytes yet.
    pub fn try_parse(&mut self, src: &mut BytesMut) -> Result<Option<bgp::Message>, Error> {
        let buffer_len = src.len();
        if buffer_len < bgp::Message::HEADER_LENGTH as usize {
            return Ok(None);
        }
        let message_len = (&src[16..18]).read_u16::<NetworkEndian>().unwrap() as usize;
        if message_len < bgp::Message::HEADER_LENGTH as usize
            || message_len > self.0.max_message_length()
        {
            return Err(BgpError::BadMessageLength {
                data: src[16..18].to_vec(),
            }
            .into());
        }
        if buffer_len < message_len {
            return Ok(None);
        }
        let buf = src.split_to(message_len);
        Ok(Some(self.0.parse_message(&buf)?))
    }

    /// Encode a BGP message into `dst`.
    pub fn encode_to<B: BufMut + AsMut<[u8]>>(
        &mut self,
        msg: &bgp::Message,
        dst: &mut B,
    ) -> Result<(), Error> {
        self.0.encode_to(msg, dst)
    }
}
