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

//! BFD Control Packet (RFC 5880), version 1.
//!
//! Wire format (24 bytes, no authentication):
//!
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |Vers |  Diag   |Sta|P|F|C|A|D|M|  Detect Mult  |    Length     |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                       My Discriminator                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                      Your Discriminator                       |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Desired Min TX Interval                    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                   Required Min RX Interval                    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                 Required Min Echo RX Interval                 |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!
//! Authentication (A flag) and Multipoint (M flag) are not implemented.

use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use std::io;

/// Minimum BFD control packet length (no authentication).
pub const MIN_LEN: usize = 24;

/// BFD protocol version implemented here.
pub const VERSION: u8 = 1;

/// Diagnostic code (RFC 5880 §4.1). 5-bit field; values 9-31 are reserved
/// but valid on the wire, so this is a newtype rather than an enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Diagnostic(pub u8);

impl Diagnostic {
    pub const NO_DIAGNOSTIC: Self = Self(0);
    pub const CONTROL_DETECTION_TIME_EXPIRED: Self = Self(1);
    pub const ECHO_FUNCTION_FAILED: Self = Self(2);
    pub const NEIGHBOR_SIGNALED_SESSION_DOWN: Self = Self(3);
    pub const FORWARDING_PLANE_RESET: Self = Self(4);
    pub const PATH_DOWN: Self = Self(5);
    pub const CONCATENATED_PATH_DOWN: Self = Self(6);
    pub const ADMINISTRATIVELY_DOWN: Self = Self(7);
    pub const REVERSE_CONCATENATED_PATH_DOWN: Self = Self(8);
}

impl std::fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match *self {
            Self::NO_DIAGNOSTIC => "no diagnostic",
            Self::CONTROL_DETECTION_TIME_EXPIRED => "control detection time expired",
            Self::ECHO_FUNCTION_FAILED => "echo function failed",
            Self::NEIGHBOR_SIGNALED_SESSION_DOWN => "neighbor signaled session down",
            Self::FORWARDING_PLANE_RESET => "forwarding plane reset",
            Self::PATH_DOWN => "path down",
            Self::CONCATENATED_PATH_DOWN => "concatenated path down",
            Self::ADMINISTRATIVELY_DOWN => "administratively down",
            Self::REVERSE_CONCATENATED_PATH_DOWN => "reverse concatenated path down",
            Self(n) => return write!(f, "reserved({})", n),
        };
        f.write_str(name)
    }
}

/// Session state (RFC 5880 §4.1). 2-bit field; values 0-3 are exhaustive.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    AdminDown = 0,
    Down = 1,
    Init = 2,
    Up = 3,
}

impl State {
    fn from_u8(v: u8) -> Result<Self, Error> {
        match v {
            0 => Ok(Self::AdminDown),
            1 => Ok(Self::Down),
            2 => Ok(Self::Init),
            3 => Ok(Self::Up),
            _ => Err(Error::InvalidState(v)),
        }
    }
}

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::AdminDown => "AdminDown",
            Self::Down => "Down",
            Self::Init => "Init",
            Self::Up => "Up",
        };
        f.write_str(s)
    }
}

/// BFD decode/encode error.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Buffer shorter than 24 bytes, or buf.len() != length field.
    InvalidLength(usize),
    /// Version field is not 1.
    InvalidVersion(u8),
    /// State field value > 3.
    InvalidState(u8),
    /// Diagnostic field value > 31.
    InvalidDiagnostic(u8),
    /// I/O error during encode.
    Io,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLength(n) => write!(f, "invalid BFD packet length: {}", n),
            Self::InvalidVersion(v) => write!(f, "invalid BFD version: {}", v),
            Self::InvalidState(s) => write!(f, "invalid BFD state: {}", s),
            Self::InvalidDiagnostic(d) => write!(f, "invalid BFD diagnostic: {}", d),
            Self::Io => write!(f, "BFD encode I/O error"),
        }
    }
}

/// BFD Control Packet (RFC 5880 §4.1).
///
/// Authentication (A flag) and Multipoint (M flag) are not implemented.
/// The version field is always encoded as 1; decoding rejects any other value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub diagnostic: Diagnostic,
    pub state: State,
    /// Poll (P) flag: sender requests verification of connectivity/parameters.
    pub poll: bool,
    /// Final (F) flag: response to a packet with the P flag set.
    pub final_: bool,
    /// Control Plane Independent (C) flag: forwarding continues independently
    /// of the control plane.
    pub control_plane_independent: bool,
    /// Demand (D) flag: demand mode active on this system.
    pub demand: bool,
    /// Detection Time Multiplier.
    pub detect_multiplier: u8,
    /// Local discriminator (non-zero).
    pub my_discriminator: u32,
    /// Remote discriminator (0 until the remote system is known).
    pub your_discriminator: u32,
    /// Minimum interval (microseconds) this system would like to use for
    /// sending BFD Control packets.
    pub desired_min_tx_interval: u32,
    /// Minimum interval (microseconds) this system can support for receiving
    /// BFD Control packets.
    pub required_min_rx_interval: u32,
    /// Minimum interval (microseconds) this system can support for receiving
    /// BFD Echo packets (0 to disable echo).
    pub required_min_echo_rx_interval: u32,
}

impl Message {
    /// Decode a BFD Control Packet from a raw byte slice.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < MIN_LEN {
            return Err(Error::InvalidLength(buf.len()));
        }
        let length = buf[3] as usize;
        if buf.len() != length {
            return Err(Error::InvalidLength(buf.len()));
        }

        let version = buf[0] >> 5;
        if version != VERSION {
            return Err(Error::InvalidVersion(version));
        }

        let diag_raw = buf[0] & 0x1f;
        if diag_raw > 31 {
            return Err(Error::InvalidDiagnostic(diag_raw));
        }
        let diagnostic = Diagnostic(diag_raw);

        let state = State::from_u8(buf[1] >> 6)?;
        let poll = (buf[1] >> 5) & 1 != 0;
        let final_ = (buf[1] >> 4) & 1 != 0;
        let control_plane_independent = (buf[1] >> 3) & 1 != 0;
        // A (auth present) bit intentionally ignored: authentication not implemented.
        let demand = (buf[1] >> 1) & 1 != 0;
        // M (multipoint) bit intentionally ignored.

        let detect_multiplier = buf[2];

        let mut c = io::Cursor::new(&buf[4..]);
        let my_discriminator = c.read_u32::<NetworkEndian>().map_err(|_| Error::Io)?;
        let your_discriminator = c.read_u32::<NetworkEndian>().map_err(|_| Error::Io)?;
        let desired_min_tx_interval = c.read_u32::<NetworkEndian>().map_err(|_| Error::Io)?;
        let required_min_rx_interval = c.read_u32::<NetworkEndian>().map_err(|_| Error::Io)?;
        let required_min_echo_rx_interval = c.read_u32::<NetworkEndian>().map_err(|_| Error::Io)?;

        Ok(Self {
            diagnostic,
            state,
            poll,
            final_,
            control_plane_independent,
            demand,
            detect_multiplier,
            my_discriminator,
            your_discriminator,
            desired_min_tx_interval,
            required_min_rx_interval,
            required_min_echo_rx_interval,
        })
    }

    /// Encode this BFD Control Packet into a 24-byte buffer.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.diagnostic.0 > 31 {
            return Err(Error::InvalidDiagnostic(self.diagnostic.0));
        }
        let mut buf: Vec<u8> = Vec::with_capacity(MIN_LEN);
        let mut c = io::Cursor::new(&mut buf);

        let byte0 = (VERSION << 5) | (self.diagnostic.0 & 0x1f);
        let byte1 = ((self.state as u8) << 6)
            | ((self.poll as u8) << 5)
            | ((self.final_ as u8) << 4)
            | ((self.control_plane_independent as u8) << 3)
            | ((self.demand as u8) << 1);

        c.write_u8(byte0).map_err(|_| Error::Io)?;
        c.write_u8(byte1).map_err(|_| Error::Io)?;
        c.write_u8(self.detect_multiplier).map_err(|_| Error::Io)?;
        c.write_u8(MIN_LEN as u8).map_err(|_| Error::Io)?;
        c.write_u32::<NetworkEndian>(self.my_discriminator)
            .map_err(|_| Error::Io)?;
        c.write_u32::<NetworkEndian>(self.your_discriminator)
            .map_err(|_| Error::Io)?;
        c.write_u32::<NetworkEndian>(self.desired_min_tx_interval)
            .map_err(|_| Error::Io)?;
        c.write_u32::<NetworkEndian>(self.required_min_rx_interval)
            .map_err(|_| Error::Io)?;
        c.write_u32::<NetworkEndian>(self.required_min_echo_rx_interval)
            .map_err(|_| Error::Io)?;

        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // GoBGP wire format test vectors (from bfd_test.go).
    //
    // Test_MarshalBinary target:
    //   Version=1, Diagnostic=EchoFunctionFailed(2), State=Up(3),
    //   Poll=false, Final=false, DetectMult=8,
    //   MyDisc=0x4f2fd5f2, YourDisc=0xd67eaedf,
    //   DesiredMinTx=300000, RequiredMinRx=800000, EchoRx=0
    #[rustfmt::skip]
    const GOBGP_MARSHAL: &[u8] = &[
        0x22, 0xc0, 0x08, 0x18,
        0x4f, 0x2f, 0xd5, 0xf2,
        0xd6, 0x7e, 0xae, 0xdf,
        0x00, 0x04, 0x93, 0xe0,
        0x00, 0x0c, 0x35, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];

    // Test_UnmarshalBinary source:
    //   Version=1, Diagnostic=ControlDetectionTimeExpired(1), State=Up(3),
    //   Poll=false, Final=false, DetectMult=3,
    //   MyDisc=0x12345678, YourDisc=0xabcdef12,
    //   DesiredMinTx=100000, RequiredMinRx=200000, EchoRx=0
    #[rustfmt::skip]
    const GOBGP_UNMARSHAL: &[u8] = &[
        0x21, 0xc0, 0x03, 0x18,
        0x12, 0x34, 0x56, 0x78,
        0xab, 0xcd, 0xef, 0x12,
        0x00, 0x01, 0x86, 0xa0,
        0x00, 0x03, 0x0d, 0x40,
        0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn gobgp_encode() {
        let msg = Message {
            diagnostic: Diagnostic::ECHO_FUNCTION_FAILED,
            state: State::Up,
            poll: false,
            final_: false,
            control_plane_independent: false,
            demand: false,
            detect_multiplier: 8,
            my_discriminator: 0x4f2fd5f2,
            your_discriminator: 0xd67eaedf,
            desired_min_tx_interval: 300_000,
            required_min_rx_interval: 800_000,
            required_min_echo_rx_interval: 0,
        };
        assert_eq!(msg.encode().unwrap(), GOBGP_MARSHAL);
    }

    #[test]
    fn gobgp_decode() {
        let msg = Message::decode(GOBGP_UNMARSHAL).unwrap();
        assert_eq!(msg.diagnostic, Diagnostic::CONTROL_DETECTION_TIME_EXPIRED);
        assert_eq!(msg.state, State::Up);
        assert!(!msg.poll);
        assert!(!msg.final_);
        assert_eq!(msg.detect_multiplier, 3);
        assert_eq!(msg.my_discriminator, 0x12345678);
        assert_eq!(msg.your_discriminator, 0xabcdef12);
        assert_eq!(msg.desired_min_tx_interval, 100_000);
        assert_eq!(msg.required_min_rx_interval, 200_000);
        assert_eq!(msg.required_min_echo_rx_interval, 0);
    }

    #[test]
    fn roundtrip() {
        let msg = Message {
            diagnostic: Diagnostic::PATH_DOWN,
            state: State::Init,
            poll: true,
            final_: false,
            control_plane_independent: true,
            demand: false,
            detect_multiplier: 5,
            my_discriminator: 0xdeadbeef,
            your_discriminator: 0xcafebabe,
            desired_min_tx_interval: 50_000,
            required_min_rx_interval: 50_000,
            required_min_echo_rx_interval: 0,
        };
        let encoded = msg.encode().unwrap();
        assert_eq!(encoded.len(), MIN_LEN);
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn poll_final_flags() {
        let msg = Message {
            diagnostic: Diagnostic::NO_DIAGNOSTIC,
            state: State::Up,
            poll: false,
            final_: true,
            control_plane_independent: false,
            demand: false,
            detect_multiplier: 3,
            my_discriminator: 1,
            your_discriminator: 2,
            desired_min_tx_interval: 1_000_000,
            required_min_rx_interval: 1_000_000,
            required_min_echo_rx_interval: 0,
        };
        let encoded = msg.encode().unwrap();
        assert_eq!(encoded.len(), MIN_LEN);
        let decoded = Message::decode(&encoded).unwrap();
        assert!(!decoded.poll);
        assert!(decoded.final_);
    }

    #[test]
    fn demand_flag() {
        let msg = Message {
            diagnostic: Diagnostic::NO_DIAGNOSTIC,
            state: State::Up,
            poll: false,
            final_: false,
            control_plane_independent: false,
            demand: true,
            detect_multiplier: 3,
            my_discriminator: 1,
            your_discriminator: 2,
            desired_min_tx_interval: 1_000_000,
            required_min_rx_interval: 1_000_000,
            required_min_echo_rx_interval: 0,
        };
        let decoded = Message::decode(&msg.encode().unwrap()).unwrap();
        assert!(decoded.demand);
    }

    #[test]
    fn reserved_diagnostic_roundtrip() {
        // Values 9-31 are reserved but must survive encode/decode.
        let msg = Message {
            diagnostic: Diagnostic(9),
            state: State::Down,
            poll: false,
            final_: false,
            control_plane_independent: false,
            demand: false,
            detect_multiplier: 3,
            my_discriminator: 1,
            your_discriminator: 0,
            desired_min_tx_interval: 1_000_000,
            required_min_rx_interval: 1_000_000,
            required_min_echo_rx_interval: 0,
        };
        let decoded = Message::decode(&msg.encode().unwrap()).unwrap();
        assert_eq!(decoded.diagnostic, Diagnostic(9));
    }

    #[test]
    fn error_too_short() {
        assert_eq!(Message::decode(&[0u8; 23]), Err(Error::InvalidLength(23)));
    }

    #[test]
    fn error_length_mismatch() {
        // length field says 0x17 (23) but buffer is 24 bytes
        let mut buf = GOBGP_UNMARSHAL.to_vec();
        buf[3] = 0x17;
        assert_eq!(Message::decode(&buf), Err(Error::InvalidLength(24)));
    }

    #[test]
    fn error_invalid_version() {
        let mut buf = GOBGP_UNMARSHAL.to_vec();
        buf[0] = (2 << 5) | (buf[0] & 0x1f); // version = 2
        assert_eq!(Message::decode(&buf), Err(Error::InvalidVersion(2)));
    }

    #[test]
    fn error_invalid_state() {
        // The state field is 2 bits on the wire, so decode() can never produce
        // a value > 3. Test State::from_u8 directly.
        assert_eq!(State::from_u8(4), Err(Error::InvalidState(4)));
        assert_eq!(State::from_u8(255), Err(Error::InvalidState(255)));
    }

    #[test]
    fn error_invalid_diagnostic_encode() {
        let msg = Message {
            diagnostic: Diagnostic(32), // > 31, invalid
            state: State::Up,
            poll: false,
            final_: false,
            control_plane_independent: false,
            demand: false,
            detect_multiplier: 3,
            my_discriminator: 1,
            your_discriminator: 0,
            desired_min_tx_interval: 1_000_000,
            required_min_rx_interval: 1_000_000,
            required_min_echo_rx_interval: 0,
        };
        assert_eq!(msg.encode(), Err(Error::InvalidDiagnostic(32)));
    }

    #[test]
    fn display_state() {
        assert_eq!(State::AdminDown.to_string(), "AdminDown");
        assert_eq!(State::Down.to_string(), "Down");
        assert_eq!(State::Init.to_string(), "Init");
        assert_eq!(State::Up.to_string(), "Up");
    }

    #[test]
    fn display_diagnostic() {
        assert_eq!(Diagnostic::NO_DIAGNOSTIC.to_string(), "no diagnostic");
        assert_eq!(
            Diagnostic::ECHO_FUNCTION_FAILED.to_string(),
            "echo function failed"
        );
        assert_eq!(Diagnostic(9).to_string(), "reserved(9)");
    }
}
