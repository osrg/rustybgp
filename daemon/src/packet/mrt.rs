// Copyright (C) 2022 The RustyBGP Authors.
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

use byteorder::{NetworkEndian, WriteBytesExt};
use bytes::{BufMut, BytesMut};
use std::net::IpAddr;
use std::time::SystemTime;
use tokio_util::codec::{Decoder, Encoder};

use crate::error::Error;
use crate::packet::bgp;

struct Header {
    timestamp: u32,
    code: u16,
    subtype: u16,
    len: u32,
}

impl Header {
    const SUBTYPE_AS4: u16 = 4;
    const SUBTYPE_AS4_ADDPATH: u16 = 8;

    fn encode(&self, dst: &mut BytesMut) -> Result<(), Error> {
        dst.put_u32(self.timestamp);
        dst.put_u16(self.code);
        dst.put_u16(self.subtype);
        dst.put_u32(self.len);
        Ok(())
    }
}

pub(crate) struct MpHeader {
    remote_asn: u32,
    local_asn: u32,
    interface_idx: u16,
    remote_addr: IpAddr,
    local_addr: IpAddr,
    is_asn4: bool,
}

impl MpHeader {
    pub(crate) fn new(
        remote_asn: u32,
        local_asn: u32,
        interface_idx: u16,
        remote_addr: IpAddr,
        local_addr: IpAddr,
        is_asn4: bool,
    ) -> Self {
        MpHeader {
            remote_asn,
            local_asn,
            interface_idx,
            remote_addr,
            local_addr,
            is_asn4,
        }
    }

    fn encode(&self, c: &mut BytesMut) -> Result<(), Error> {
        if self.is_asn4 {
            c.put_u32(self.remote_asn);
            c.put_u32(self.local_asn);
        } else {
            c.put_u16(self.remote_asn as u16);
            c.put_u16(self.local_asn as u16);
        }
        c.put_u16(self.interface_idx);
        match self.remote_addr {
            IpAddr::V4(addr) => {
                c.put_u16(bgp::Family::IPV4.afi());
                c.put_slice(&addr.octets());
                if let IpAddr::V4(local) = self.local_addr {
                    c.put_slice(&local.octets());
                }
            }
            IpAddr::V6(addr) => {
                c.put_u16(bgp::Family::IPV6.afi());
                c.put_slice(&addr.octets());
                if let IpAddr::V6(local) = self.local_addr {
                    c.put_slice(&local.octets());
                }
            }
        }
        Ok(())
    }
}

#[allow(dead_code)]
pub(crate) enum Message {
    Mp {
        header: MpHeader,
        body: bgp::Message,
        addpath: bool,
    },
}

pub(crate) struct MrtCodec {
    codec: bgp::BgpCodec,
}

impl MrtCodec {
    pub(crate) fn new() -> Self {
        MrtCodec {
            codec: bgp::BgpCodec::new().keep_aspath(true).keep_nexthop(true),
        }
    }
}

impl Encoder<&Message> for MrtCodec {
    type Error = Error;

    fn encode(&mut self, item: &Message, dst: &mut BytesMut) -> Result<(), Error> {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        match item {
            Message::Mp {
                header,
                body,
                addpath,
            } => {
                if let bgp::Message::Update {
                    reach,
                    unreach,
                    attr: _,
                } = body
                {
                    let family = if let Some((f, _)) = reach {
                        *f
                    } else {
                        unreach.as_ref().unwrap().0
                    };
                    self.codec
                        .channel
                        .insert(family, bgp::Channel::new(family, false, *addpath));
                }
                let subtype = if *addpath {
                    Header::SUBTYPE_AS4_ADDPATH
                } else {
                    Header::SUBTYPE_AS4
                };

                let h = Header {
                    timestamp,
                    code: 16,
                    subtype,
                    len: 0,
                };
                h.encode(dst).unwrap();
                let pos = dst.len();

                header.encode(dst).unwrap();
                let mut buf = bytes::BytesMut::with_capacity(4096);
                self.codec.encode(body, &mut buf).unwrap();
                dst.put_slice(buf.as_ref());
                let len = dst.len() - pos;
                (&mut dst.as_mut()[(pos - 4)..])
                    .write_u32::<NetworkEndian>(len as u32)
                    .unwrap();
            }
        }
        Ok(())
    }
}

impl Decoder for MrtCodec {
    type Item = Message;
    type Error = Error;

    fn decode(&mut self, _src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        Ok(None)
    }
}
