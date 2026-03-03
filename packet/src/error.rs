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
    #[error("incorrect bgp format {code:?} {subcode:?}")]
    InvalidMessageFormat {
        code: u8,
        subcode: u8,
        data: Vec<u8>,
    },
    #[error("argument is incorrect: {0}")]
    InvalidArgument(String),
    #[error("std::io::Error")]
    StdIoErr(#[from] std::io::Error),
}
