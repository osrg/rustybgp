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

use crate::IpNet;
use crate::error::Error;

pub struct Prefix {
    pub net: IpNet,
    pub flags: u8,
    pub max_length: u8,
    pub as_number: u32,
}

#[allow(dead_code)]
pub enum Message {
    SerialNotify {
        session_id: u16,
        serial_number: u32,
    },
    SerialQuery {
        session_id: u16,
        serial_number: u32,
    },
    ResetQuery,
    CacheResponse {
        session_id: u16,
    },
    IpPrefix(Prefix),
    EndOfData {
        session_id: u16,
        serial_number: u32,
        /// Seconds between Serial Queries when the session is up (RFC 8210 v1+; 0 for v0).
        refresh_interval: u32,
        /// Seconds to wait before retrying after a failed Serial Query (RFC 8210 v1+; 0 for v0).
        retry_interval: u32,
        /// Seconds before a router must re-fetch all data if no update received (RFC 8210 v1+; 0 for v0).
        expire_interval: u32,
    },
    CacheReset,
    ErrorReport {
        /// Error code from RFC 8210 section 10.
        error_code: u16,
    },
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

    fn to_bytes(&self, version: u8) -> Result<Vec<u8>, Error> {
        let buf: Vec<u8> = Vec::new();
        let mut c = Cursor::new(buf);
        match self {
            Message::SerialNotify {
                session_id,
                serial_number,
            } => {
                c.write_u8(version)?;
                c.write_u8(Message::SERIAL_NOTIFY)?;
                c.write_u16::<NetworkEndian>(*session_id)?;
                c.write_u32::<NetworkEndian>(12)?;
                c.write_u32::<NetworkEndian>(*serial_number)?;
            }
            Message::ResetQuery => {
                c.write_u8(version)?;
                c.write_u8(Message::RESET_QUERY)?;
                c.write_u16::<NetworkEndian>(0)?;
                c.write_u32::<NetworkEndian>(8)?;
            }
            Message::SerialQuery {
                session_id,
                serial_number,
            } => {
                c.write_u8(version)?;
                c.write_u8(Message::SERIAL_QUERY)?;
                c.write_u16::<NetworkEndian>(*session_id)?;
                c.write_u32::<NetworkEndian>(12)?;
                c.write_u32::<NetworkEndian>(*serial_number)?;
            }
            Message::CacheResponse { session_id } => {
                c.write_u8(version)?;
                c.write_u8(Message::CACHE_RESPONSE)?;
                c.write_u16::<NetworkEndian>(*session_id)?;
                c.write_u32::<NetworkEndian>(8)?;
            }
            Message::IpPrefix(prefix) => match &prefix.net {
                crate::IpNet::V4(net) => {
                    c.write_u8(version)?;
                    c.write_u8(Message::IPV4_PREFIX)?;
                    c.write_u16::<NetworkEndian>(0)?;
                    c.write_u32::<NetworkEndian>(20)?;
                    c.write_u8(prefix.flags)?;
                    c.write_u8(net.mask)?;
                    c.write_u8(prefix.max_length)?;
                    c.write_u8(0)?;
                    for octet in net.addr.octets() {
                        c.write_u8(octet)?;
                    }
                    c.write_u32::<NetworkEndian>(prefix.as_number)?;
                }
                crate::IpNet::V6(net) => {
                    c.write_u8(version)?;
                    c.write_u8(Message::IPV6_PREFIX)?;
                    c.write_u16::<NetworkEndian>(0)?;
                    c.write_u32::<NetworkEndian>(32)?;
                    c.write_u8(prefix.flags)?;
                    c.write_u8(net.mask)?;
                    c.write_u8(prefix.max_length)?;
                    c.write_u8(0)?;
                    for octet in net.addr.octets() {
                        c.write_u8(octet)?;
                    }
                    c.write_u32::<NetworkEndian>(prefix.as_number)?;
                }
            },
            Message::EndOfData {
                session_id,
                serial_number,
                refresh_interval,
                retry_interval,
                expire_interval,
            } => {
                c.write_u8(version)?;
                c.write_u8(Message::END_OF_DATA)?;
                c.write_u16::<NetworkEndian>(*session_id)?;
                if version >= 1 {
                    c.write_u32::<NetworkEndian>(24)?;
                    c.write_u32::<NetworkEndian>(*serial_number)?;
                    c.write_u32::<NetworkEndian>(*refresh_interval)?;
                    c.write_u32::<NetworkEndian>(*retry_interval)?;
                    c.write_u32::<NetworkEndian>(*expire_interval)?;
                } else {
                    c.write_u32::<NetworkEndian>(12)?;
                    c.write_u32::<NetworkEndian>(*serial_number)?;
                }
            }
            Message::CacheReset => {
                c.write_u8(version)?;
                c.write_u8(Message::CACHE_RESET)?;
                c.write_u16::<NetworkEndian>(0)?;
                c.write_u32::<NetworkEndian>(8)?;
            }
            Message::ErrorReport { error_code } => {
                c.write_u8(version)?;
                c.write_u8(Message::ERROR_REPORT)?;
                c.write_u16::<NetworkEndian>(*error_code)?;
                c.write_u32::<NetworkEndian>(8)?;
            }
        }
        Ok(c.into_inner())
    }

    fn from_bytes(buf: &[u8]) -> Result<(Message, usize), Error> {
        let buflen = buf.len();
        let mut c = Cursor::new(buf);

        let version = c.read_u8()?;
        let message_type = c.read_u8()?;
        // For ErrorReport, this field carries the error code instead of session_id.
        let session_id = c.read_u16::<NetworkEndian>()?;
        let length = c.read_u32::<NetworkEndian>()? as usize;

        if length > buflen {
            return Err(Error::InvalidArgument(
                "RPKI message length exceeds buffer".to_string(),
            ));
        }

        match message_type {
            Message::SERIAL_NOTIFY => {
                let serial_number = c.read_u32::<NetworkEndian>()?;
                Ok((
                    Message::SerialNotify {
                        session_id,
                        serial_number,
                    },
                    length,
                ))
            }
            Message::SERIAL_QUERY => {
                let serial_number = c.read_u32::<NetworkEndian>()?;
                Ok((
                    Message::SerialQuery {
                        session_id,
                        serial_number,
                    },
                    length,
                ))
            }
            Message::RESET_QUERY => Ok((Message::ResetQuery, length)),
            Message::CACHE_RESPONSE => Ok((Message::CacheResponse { session_id }, length)),
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
                // RFC 8210 v1 adds three interval fields absent in v0.
                let (refresh_interval, retry_interval, expire_interval) = if version >= 1 {
                    (
                        c.read_u32::<NetworkEndian>()?,
                        c.read_u32::<NetworkEndian>()?,
                        c.read_u32::<NetworkEndian>()?,
                    )
                } else {
                    (0, 0, 0)
                };
                Ok((
                    Message::EndOfData {
                        session_id,
                        serial_number,
                        refresh_interval,
                        retry_interval,
                        expire_interval,
                    },
                    length,
                ))
            }
            Message::CACHE_RESET => Ok((Message::CacheReset, length)),
            // For ErrorReport, bytes 2-3 of the common header carry the error code
            // rather than a session ID (RFC 8210 section 10).
            Message::ERROR_REPORT => Ok((
                Message::ErrorReport {
                    error_code: session_id,
                },
                length,
            )),
            _ => Err(Error::InvalidArgument(format!(
                "unknown RPKI message type: {}",
                message_type
            ))),
        }
    }
}

pub struct RtrCodec {
    /// RTR protocol version used when encoding outgoing messages.
    version: u8,
}

impl Default for RtrCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl RtrCodec {
    /// Creates a codec that encodes outgoing messages as RTR version 1 (RFC 8210).
    pub fn new() -> Self {
        RtrCodec { version: 1 }
    }

    /// Creates a codec that encodes outgoing messages using the given RTR version.
    pub fn with_version(version: u8) -> Self {
        RtrCodec { version }
    }
}

impl Encoder<&Message> for RtrCodec {
    type Error = Error;

    fn encode(&mut self, item: &Message, dst: &mut BytesMut) -> Result<(), Error> {
        let buf = item.to_bytes(self.version)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_util::codec::{Decoder, Encoder};

    fn encode(msg: &Message, version: u8) -> BytesMut {
        let mut codec = RtrCodec::with_version(version);
        let mut buf = BytesMut::new();
        codec.encode(msg, &mut buf).unwrap();
        buf
    }

    fn decode(buf: &mut BytesMut) -> Message {
        let mut codec = RtrCodec::new();
        codec.decode(buf).unwrap().unwrap()
    }

    #[test]
    fn reset_query_v0_roundtrip() {
        let mut buf = encode(&Message::ResetQuery, 0);
        assert_eq!(buf.len(), 8);
        assert_eq!(buf[0], 0); // version
        assert_eq!(buf[1], Message::RESET_QUERY);
        let msg = decode(&mut buf);
        assert!(matches!(msg, Message::ResetQuery));
    }

    #[test]
    fn reset_query_v1_roundtrip() {
        let mut buf = encode(&Message::ResetQuery, 1);
        assert_eq!(buf[0], 1); // version
        assert_eq!(buf[1], Message::RESET_QUERY);
        let msg = decode(&mut buf);
        assert!(matches!(msg, Message::ResetQuery));
    }

    #[test]
    fn serial_query_roundtrip() {
        let msg = Message::SerialQuery {
            session_id: 42,
            serial_number: 12345,
        };
        let mut buf = encode(&msg, 1);
        assert_eq!(buf.len(), 12);
        assert_eq!(buf[0], 1);
        assert_eq!(buf[1], Message::SERIAL_QUERY);
        let decoded = decode(&mut buf);
        match decoded {
            Message::SerialQuery {
                session_id,
                serial_number,
            } => {
                assert_eq!(session_id, 42);
                assert_eq!(serial_number, 12345);
            }
            _ => panic!("unexpected message type"),
        }
    }

    #[test]
    fn cache_response_preserves_session_id() {
        // Craft a raw CacheResponse with session_id = 7.
        let raw: &[u8] = &[1, Message::CACHE_RESPONSE, 0, 7, 0, 0, 0, 8];
        let mut buf = BytesMut::from(raw);
        let msg = decode(&mut buf);
        match msg {
            Message::CacheResponse { session_id } => assert_eq!(session_id, 7),
            _ => panic!("unexpected message type"),
        }
    }

    #[test]
    fn end_of_data_v0_no_intervals() {
        let raw: &[u8] = &[
            0,
            Message::END_OF_DATA,
            0,
            1, // session_id = 1
            0,
            0,
            0,
            12, // length = 12
            0,
            0,
            0,
            99, // serial_number = 99
        ];
        let mut buf = BytesMut::from(raw);
        let msg = decode(&mut buf);
        match msg {
            Message::EndOfData {
                session_id,
                serial_number,
                refresh_interval,
                retry_interval,
                expire_interval,
            } => {
                assert_eq!(session_id, 1);
                assert_eq!(serial_number, 99);
                assert_eq!(refresh_interval, 0);
                assert_eq!(retry_interval, 0);
                assert_eq!(expire_interval, 0);
            }
            _ => panic!("unexpected message type"),
        }
    }

    #[test]
    fn end_of_data_v1_with_intervals() {
        let raw: &[u8] = &[
            1,
            Message::END_OF_DATA,
            0,
            2, // session_id = 2
            0,
            0,
            0,
            24, // length = 24
            0,
            0,
            0,
            55, // serial_number = 55
            0,
            0,
            0,
            30, // refresh = 30
            0,
            0,
            2,
            88, // retry = 600
            0,
            0,
            28,
            32, // expire = 7200
        ];
        let mut buf = BytesMut::from(raw);
        let msg = decode(&mut buf);
        match msg {
            Message::EndOfData {
                session_id,
                serial_number,
                refresh_interval,
                retry_interval,
                expire_interval,
            } => {
                assert_eq!(session_id, 2);
                assert_eq!(serial_number, 55);
                assert_eq!(refresh_interval, 30);
                assert_eq!(retry_interval, 600);
                assert_eq!(expire_interval, 7200);
            }
            _ => panic!("unexpected message type"),
        }
    }

    #[test]
    fn error_report_carries_error_code() {
        let raw: &[u8] = &[
            1,
            Message::ERROR_REPORT,
            0,
            2, // error_code = 2 (No Data Available)
            0,
            0,
            0,
            8, // length = 8 (minimal)
        ];
        let mut buf = BytesMut::from(raw);
        let msg = decode(&mut buf);
        match msg {
            Message::ErrorReport { error_code } => assert_eq!(error_code, 2),
            _ => panic!("unexpected message type"),
        }
    }
}
