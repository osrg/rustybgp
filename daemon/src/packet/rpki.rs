// Copyright (C) 2020-2021 The RustyBGP Authors.
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
use bytes::{BufMut, BytesMut};
use std::io::Cursor;
use std::net::IpAddr;
use tokio_util::codec::{Decoder, Encoder};

use crate::error::Error;
use crate::packet::IpNet;

pub(crate) struct Prefix {
    pub(crate) net: IpNet,
    pub(crate) flags: u8,
    pub(crate) max_length: u8,
    pub(crate) as_number: u32,
}

#[allow(dead_code)]
pub(crate) enum Message {
    SerialNotify { serial_number: u32 },
    SerialQuery { serial_number: u32 },
    ResetQuery,
    CacheResponse,
    IpPrefix(Prefix),
    EndOfData { serial_number: u32 },
    CacheReset,
    ErrorReport,
}

impl Message {
    pub(crate) const SERIAL_NOTIFY: u8 = 0;
    pub(crate) const SERIAL_QUERY: u8 = 1;
    pub(crate) const RESET_QUERY: u8 = 2;
    pub(crate) const CACHE_RESPONSE: u8 = 3;
    pub(crate) const IPV4_PREFIX: u8 = 4;
    pub(crate) const IPV6_PREFIX: u8 = 6;
    pub(crate) const END_OF_DATA: u8 = 7;
    pub(crate) const CACHE_RESET: u8 = 8;
    pub(crate) const ERROR_REPORT: u8 = 10;

    fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let buf: Vec<u8> = Vec::new();
        let mut c = Cursor::new(buf);

        if let Message::ResetQuery = self {
            c.write_u8(0)?;
            c.write_u8(Message::RESET_QUERY)?;
            c.write_u16::<NetworkEndian>(0)?;
            c.write_u32::<NetworkEndian>(8)?;
        }
        Ok(c.into_inner())
    }

    fn from_bytes(buf: &[u8]) -> Result<(Message, usize), Error> {
        let buflen = buf.len();
        let mut c = Cursor::new(buf);

        let _version = c.read_u8()?;
        let message_type = c.read_u8()?;
        let _session_id = c.read_u16::<NetworkEndian>()?;
        let length = c.read_u32::<NetworkEndian>()? as usize;

        if length > buflen {
            return Err(Error::InvalidMessageFormat {
                code: 0,
                subcode: 0,
                data: buf.to_owned(),
            });
        }

        match message_type {
            Message::SERIAL_NOTIFY => {
                let serial_number = c.read_u32::<NetworkEndian>()?;
                Ok((Message::SerialNotify { serial_number }, length))
            }
            Message::SERIAL_QUERY => {
                let serial_number = c.read_u32::<NetworkEndian>()?;
                Ok((Message::SerialQuery { serial_number }, length))
            }
            Message::RESET_QUERY => Ok((Message::ResetQuery, length)),
            Message::CACHE_RESPONSE => Ok((Message::CacheResponse, length)),
            Message::IPV4_PREFIX => {
                let flags = c.read_u8()?;
                let prefix_len = c.read_u8()?;
                let max_length = c.read_u8()?;
                let _ = c.read_u8()?;
                let mut octets = [0_u8; 4];
                for i in 0..4 {
                    octets[i as usize] = c.read_u8()?;
                }
                let as_number = c.read_u32::<NetworkEndian>()?;
                Ok((
                    Message::IpPrefix(Prefix {
                        net: IpNet::new(IpAddr::from(octets), prefix_len),
                        flags,
                        max_length,
                        as_number,
                    }),
                    length,
                ))
            }
            Message::IPV6_PREFIX => {
                let flags = c.read_u8()?;
                let prefix_len = c.read_u8()?;
                let max_length = c.read_u8()?;
                let _ = c.read_u8()?;
                let mut octets = [0_u8; 16];
                for i in 0..16 {
                    octets[i as usize] = c.read_u8()?;
                }
                let as_number = c.read_u32::<NetworkEndian>()?;
                Ok((
                    Message::IpPrefix(Prefix {
                        net: IpNet::new(IpAddr::from(octets), prefix_len),
                        flags,
                        max_length,
                        as_number,
                    }),
                    length,
                ))
            }
            Message::END_OF_DATA => {
                let serial_number = c.read_u32::<NetworkEndian>()?;
                Ok((Message::EndOfData { serial_number }, length))
            }
            Message::CACHE_RESET => Ok((Message::CacheReset, length)),
            Message::ERROR_REPORT => Ok((Message::ErrorReport, length)),
            _ => Err(Error::InvalidMessageFormat {
                code: 0,
                subcode: 0,
                data: buf.to_owned(),
            }),
        }
    }
}

pub(crate) struct RtrCodec {}

impl RtrCodec {
    pub(crate) fn new() -> Self {
        RtrCodec {}
    }
}

impl Encoder<&Message> for RtrCodec {
    type Error = Error;

    fn encode(&mut self, item: &Message, dst: &mut BytesMut) -> Result<(), Error> {
        let buf = item.to_bytes().unwrap();
        dst.reserve(buf.len());
        dst.put_slice(&buf);
        Ok(())
    }
}

impl Decoder for RtrCodec {
    type Item = Message;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match Message::from_bytes(src) {
            Ok((m, len)) => {
                let _ = src.split_to(len);
                Ok(Some(m))
            }
            Err(_) => Ok(None),
        }
    }
}
