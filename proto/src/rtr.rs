// Copyright (C) 2020 The RustyBGP Authors.
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

use super::bgp::IpNet;
use super::error::Error;
use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use std::io::Cursor;
use std::net::IpAddr;

pub struct CommonHeader {
    pub version: u8,
    pub message_type: u8,
    pub session_id: u16,
    pub lenght: u32,
    pub serial_number: u32,
}

pub struct Prefix {
    pub net: IpNet,
    pub flags: u8,
    pub max_length: u8,
    pub as_number: u32,
}

pub enum Message {
    SerialNotify { serial_number: u32 },
    SerialQuery { serial_number: u32 },
    ResetQuery,
    CacheResponse,
    Ipv4Prefix(Prefix),
    Ipv6Prefix(Prefix),
    EndOfData { serial_number: u32 },
    CacheReset,
    ErrorReport,
}

impl Message {
    pub const SERIAL_NOTIFY: u8 = 0;
    pub const SERIAL_QUERY: u8 = 1;
    pub const RESET_QUERY: u8 = 2;
    pub const CACHE_RESPONSE: u8 = 3;
    pub const IPV4_PREFIX: u8 = 4;
    pub const IPV6_PREFIX: u8 = 6;
    pub const END_OF_DATA: u8 = 7;
    pub const CACHE_RESET: u8 = 8;
    pub const ERROR_REPORT: u8 = 10;

    //const HEADER_LENGTH: u32 = 6;

    pub fn message_type(&self) -> u8 {
        match self {
            Message::SerialNotify { .. } => Message::SERIAL_NOTIFY,
            Message::SerialQuery { .. } => Message::SERIAL_QUERY,
            Message::ResetQuery { .. } => Message::RESET_QUERY,
            Message::CacheResponse => Message::CACHE_RESPONSE,
            Message::Ipv4Prefix(_) => Message::IPV4_PREFIX,
            Message::Ipv6Prefix(_) => Message::IPV6_PREFIX,
            Message::EndOfData { .. } => Message::END_OF_DATA,
            Message::CacheReset => Message::CACHE_RESET,
            Message::ErrorReport => Message::ERROR_REPORT,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
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

    pub fn from_bytes(buf: &[u8]) -> Result<(Message, usize), Error> {
        let buflen = buf.len();
        let mut c = Cursor::new(buf);

        let _version = c.read_u8()?;
        let message_type = c.read_u8()?;
        let _session_id = c.read_u16::<NetworkEndian>()?;
        let length = c.read_u32::<NetworkEndian>()? as usize;

        if length > buflen {
            return Err(Error::InvalidFormat);
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
                    Message::Ipv4Prefix(Prefix {
                        net: IpNet {
                            addr: IpAddr::from(octets),
                            mask: prefix_len,
                        },
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
                    Message::Ipv6Prefix(Prefix {
                        net: IpNet {
                            addr: IpAddr::from(octets),
                            mask: prefix_len,
                        },
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
            _ => Err(Error::InvalidFormat),
        }
    }
}
