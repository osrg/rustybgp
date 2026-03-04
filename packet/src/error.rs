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

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("BGP: {0}")]
    Bgp(#[from] BgpError),
    #[error("parse error: {0}")]
    InvalidArgument(String),
    #[error("io error: {0}")]
    StdIoErr(#[from] std::io::Error),
}

/// Typed BGP NOTIFICATION error (RFC 4271 §4.5, RFC 6608 §3, RFC 7313 §5)
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BgpError {
    // Code 1: Message Header Error
    #[error("header error: bad message length")]
    BadMessageLength { data: Vec<u8> },
    #[error("header error: bad message type")]
    BadMessageType { data: Vec<u8> },

    // Code 2: OPEN Message Error
    #[error("open error: malformed")]
    OpenMalformed,
    #[error("open error: unsupported optional parameter")]
    OpenUnsupportedOptionalParameter { data: Vec<u8> },
    #[error("open error: unacceptable hold time")]
    OpenUnacceptableHoldTime { data: Vec<u8> },

    // Code 3: UPDATE Message Error
    #[error("update error: malformed attribute list")]
    UpdateMalformedAttributeList,
    #[error("update error: optional attribute error")]
    UpdateOptionalAttributeError,

    // Code 5: FSM Error
    #[error("FSM error: unexpected state {state}")]
    FsmUnexpectedState { state: u8 },

    // Code 7: ROUTE-REFRESH Message Error
    #[error("route-refresh error: invalid message length")]
    RouteRefreshInvalidLength { data: Vec<u8> },

    // Catch-all for received NOTIFICATION messages
    #[error("notification code={code} subcode={subcode}")]
    Other {
        code: u8,
        subcode: u8,
        data: Vec<u8>,
    },
}

impl BgpError {
    /// Returns the BGP NOTIFICATION error code.
    pub fn notification_code(&self) -> u8 {
        match self {
            Self::BadMessageLength { .. } | Self::BadMessageType { .. } => 1,
            Self::OpenMalformed
            | Self::OpenUnsupportedOptionalParameter { .. }
            | Self::OpenUnacceptableHoldTime { .. } => 2,
            Self::UpdateMalformedAttributeList | Self::UpdateOptionalAttributeError => 3,
            Self::FsmUnexpectedState { .. } => 5,
            Self::RouteRefreshInvalidLength { .. } => 7,
            Self::Other { code, .. } => *code,
        }
    }

    /// Returns the BGP NOTIFICATION subcode.
    pub fn notification_subcode(&self) -> u8 {
        match self {
            Self::BadMessageLength { .. } => 2,
            Self::BadMessageType { .. } => 3,
            Self::OpenMalformed => 0,
            Self::OpenUnsupportedOptionalParameter { .. } => 4,
            Self::OpenUnacceptableHoldTime { .. } => 6,
            Self::UpdateMalformedAttributeList => 1,
            Self::UpdateOptionalAttributeError => 9,
            Self::FsmUnexpectedState { state } => *state,
            Self::RouteRefreshInvalidLength { .. } => 1,
            Self::Other { subcode, .. } => *subcode,
        }
    }

    /// Returns the BGP NOTIFICATION data.
    pub fn notification_data(&self) -> &[u8] {
        match self {
            Self::BadMessageLength { data }
            | Self::BadMessageType { data }
            | Self::OpenUnsupportedOptionalParameter { data }
            | Self::OpenUnacceptableHoldTime { data }
            | Self::RouteRefreshInvalidLength { data }
            | Self::Other { data, .. } => data,
            _ => &[],
        }
    }

    /// Constructs a `BgpError` from a received NOTIFICATION message.
    pub fn from_notification(code: u8, subcode: u8, data: Vec<u8>) -> Self {
        match (code, subcode) {
            (1, 2) => Self::BadMessageLength { data },
            (1, 3) => Self::BadMessageType { data },
            (2, 0) => Self::OpenMalformed,
            (2, 4) => Self::OpenUnsupportedOptionalParameter { data },
            (2, 6) => Self::OpenUnacceptableHoldTime { data },
            (3, 1) => Self::UpdateMalformedAttributeList,
            (3, 9) => Self::UpdateOptionalAttributeError,
            (5, state) => Self::FsmUnexpectedState { state },
            (7, 1) => Self::RouteRefreshInvalidLength { data },
            _ => Self::Other {
                code,
                subcode,
                data,
            },
        }
    }
}
