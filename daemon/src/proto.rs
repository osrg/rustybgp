// Copyright (C) 2019-2021 The RustyBGP Authors.
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

use std::time::SystemTime;

const TYPE_URL_PREFACE: &str = "type.googleapis.com/apipb.";

pub(crate) fn to_any<T: prost::Message>(m: T, name: &str) -> prost_types::Any {
    let mut v = Vec::new();
    m.encode(&mut v).unwrap();
    prost_types::Any {
        type_url: format!("{}{}", TYPE_URL_PREFACE, name),
        value: v,
    }
}

pub(crate) fn type_url(t: &str) -> String {
    format!("{}{}", TYPE_URL_PREFACE, t)
}

pub(crate) trait ToApi<T: prost::Message> {
    fn to_api(&self) -> T;
}

impl ToApi<prost_types::Timestamp> for SystemTime {
    fn to_api(&self) -> prost_types::Timestamp {
        let unix = self.duration_since(SystemTime::UNIX_EPOCH).unwrap();
        prost_types::Timestamp {
            seconds: unix.as_secs() as i64,
            nanos: unix.subsec_nanos() as i32,
        }
    }
}
