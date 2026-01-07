// Copyright (C) 2021 The RustyBGP Authors.
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

#[allow(dead_code)]
pub(crate) mod generate;
pub(crate) use self::generate::*;
pub(crate) mod validate;
pub(crate) use self::validate::*;

use std::error::Error;
use std::ffi::OsStr;
use std::path::Path;

pub(crate) fn read_from_file<P: AsRef<Path>>(fname: P) -> Result<BgpConfig, Box<dyn Error>> {
    let contents = std::fs::read_to_string(fname.as_ref())?;
    let conf: BgpConfig = match fname.as_ref().extension().and_then(OsStr::to_str) {
        Some("yaml") | Some("yml") => serde_yaml_bw::from_str(&contents)?,
        _ => toml::from_str(&contents)?,
    };
    conf.validate()?;
    Ok(conf)
}
