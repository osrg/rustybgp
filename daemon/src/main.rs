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
    #![allow(clippy::all)]
    tonic::include_proto!("apipb");
}
mod auth;
mod config;
mod error;
mod event;
mod packet;
mod proto;
mod table;

use clap::{Arg, Command};
use std::net::Ipv4Addr;
use std::str::FromStr;

fn main() -> Result<(), std::io::Error> {
    if num_cpus::get() < 4 {
        panic!("four local CPUs are necessary at least");
    }
    let args = Command::new("rustybgpd")
        .version(concat!(
            "v",
            env!("CARGO_PKG_VERSION"),
            "-",
            env!("GIT_HASH")
        ))
        .arg(
            Arg::new("config")
                .short('f')
                .long("config-file")
                .action(clap::ArgAction::Set)
                .help("specifying a config file"),
        )
        .arg(
            Arg::new("asn")
                .long("as-number")
                .action(clap::ArgAction::Set)
                .help("specify as number"),
        )
        .arg(
            Arg::new("id")
                .long("router-id")
                .action(clap::ArgAction::Set)
                .help("specify router id"),
        )
        .arg(
            Arg::new("any")
                .long("any-peers")
                .action(clap::ArgAction::SetTrue)
                .help("accept any peers"),
        )
        .get_matches();

    let conf = if let Some(conf) = args.get_one::<String>("config") {
        let conf: config::BgpConfig = config::read_from_file(conf).expect("invalid configuration");
        Some(conf)
    } else {
        let as_number = if let Some(asn) = args.get_one::<String>("asn") {
            asn.parse().unwrap()
        } else {
            0
        };
        let router_id = if let Some(id) = args.get_one::<String>("id") {
            Ipv4Addr::from_str(id).unwrap();
            Some(id.to_string())
        } else {
            if as_number != 0 {
                panic!("both as number and router-id must be specified");
            }
            None
        };
        if as_number != 0 {
            let conf = config::BgpConfig {
                global: Some(config::Global {
                    config: Some(config::GlobalConfig {
                        r#as: Some(as_number),
                        router_id,
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            };
            Some(conf)
        } else {
            None
        }
    };

    println!("Hello, RustyBGPd ({} cpus)!", num_cpus::get());

    event::main(conf, args.contains_id("any"));
    Ok(())
}
