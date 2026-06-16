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

pub mod bgp;
pub use self::bgp::Notification;
pub use self::bgp::validate_message;
pub use self::bgp::{
    Attribute, Capability, Family, HoldTime, IpNet, Nlri, Open, ParsedMessage, PathNlri, ReachNlri,
    UnreachNlri, Update,
};
pub use self::error::Error;

pub mod bgp_ls;
pub mod bmp;
pub mod error;
pub mod flowspec;
pub mod labeled;
pub mod mpls;
pub mod mrt;
pub mod mup;
pub mod prefix_sid;
pub mod rd;
pub mod rpki;
pub mod sr_policy;
pub mod tunnel_encap;
pub mod vpn;
