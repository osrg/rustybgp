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

use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error("bgp server hasn't started yet")]
    NotStarted,
    #[error("must argument is empty")]
    EmptyArgument,
    #[error("argument is incorrect")]
    InvalidArgument(String),
    #[error("entity already exists")]
    AlreadyExists(String),
    #[error("feature isn't supported")]
    Unimplemented,

    #[error("incorrect bgp format {code:?}")]
    InvalidMessageFormat {
        code: u8,
        subcode: u8,
        data: Vec<u8>,
    },
    #[error("std::io::Error")]
    StdIoErr(#[from] std::io::Error),
}

impl From<Error> for tonic::Status {
    fn from(e: Error) -> Self {
        match e {
            Error::NotStarted => tonic::Status::new(tonic::Code::Unavailable, "not started"),
            Error::EmptyArgument => {
                tonic::Status::new(tonic::Code::InvalidArgument, "empty argument")
            }
            Error::InvalidArgument(s) => tonic::Status::new(tonic::Code::InvalidArgument, s),
            Error::AlreadyExists(s) => tonic::Status::new(tonic::Code::AlreadyExists, s),
            Error::Unimplemented => tonic::Status::unimplemented("Not yet implemented"),
            _ => panic!("unsupported error code"),
        }
    }
}
