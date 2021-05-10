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

#![recursion_limit = "1024"]
mod api {
    tonic::include_proto!("gobgpapi");
}
mod error;
mod event;
mod net;
mod packet;
mod proto;
mod table;

use clap::{App, Arg};
use std::net::Ipv4Addr;
use std::str::FromStr;

fn main() {
    let args = App::new("rustybgpd")
        .arg(
            Arg::with_name("asn")
                .long("as-number")
                .takes_value(true)
                .help("specify as number"),
        )
        .arg(
            Arg::with_name("id")
                .long("router-id")
                .takes_value(true)
                .help("specify router id"),
        )
        .arg(
            Arg::with_name("collector")
                .long("disable-best")
                .help("disable best path selection"),
        )
        .arg(
            Arg::with_name("any")
                .long("any-peers")
                .help("accept any peers"),
        )
        .get_matches();

    let as_number = if let Some(asn) = args.value_of("asn") {
        asn.parse().unwrap()
    } else {
        0
    };
    let router_id = if let Some(id) = args.value_of("id") {
        Ipv4Addr::from_str(id).unwrap()
    } else {
        Ipv4Addr::new(0, 0, 0, 0)
    };

    println!("Hello, RustyBGPd ({} cpus)!", num_cpus::get());

    event::main(as_number, router_id, args.is_present("any"));
}
