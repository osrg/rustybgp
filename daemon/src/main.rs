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
mod config;
mod error;
mod event;
mod net;
mod packet;
mod proto;
mod table;

use clap::{App, Arg};
use std::net::Ipv4Addr;
use std::str::FromStr;

fn main() -> Result<(), std::io::Error> {
    let args = App::new("rustybgpd")
        .version(format!("v{}-{}", env!("CARGO_PKG_VERSION"), env!("GIT_HASH")).as_str())
        .arg(
            Arg::with_name("config")
                .short("f")
                .long("config-file")
                .takes_value(true)
                .help("specifying a config file"),
        )
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
            Arg::with_name("any")
                .long("any-peers")
                .help("accept any peers"),
        )
        .get_matches();

    let conf = if let Some(conf) = args.value_of("config") {
        let conf: config::Bgp = toml::from_str(&(std::fs::read_to_string(conf)?))?;
        if let Err(e) = conf.validate() {
            panic!("invalid configuraiton {:?}", e);
        }
        Some(conf)
    } else {
        let as_number = if let Some(asn) = args.value_of("asn") {
            asn.parse().unwrap()
        } else {
            0
        };
        let router_id = if let Some(id) = args.value_of("id") {
            Ipv4Addr::from_str(id).unwrap();
            Some(id.to_string())
        } else {
            if as_number != 0 {
                panic!("both as number and router-id must be specified");
            }
            None
        };
        if as_number != 0 {
            let conf = config::Bgp {
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

    event::main(conf, args.is_present("any"));
    Ok(())
}
