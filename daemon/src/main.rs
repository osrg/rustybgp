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
#![warn(unreachable_pub)]
pub(crate) use rustybgp_api as api;
pub(crate) use rustybgp_config as config;
mod auth;
mod bfd;
mod bmp;
mod convert;
mod error;
mod event;
mod fsm;
mod gr;
mod mrt;
mod peer_tx;
mod proto;
mod rpki;
#[allow(dead_code)]
mod rtc;
mod table_manager;
use std::str::FromStr;

use clap::{Arg, Command};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let version: &'static str = concat!("v", env!("CARGO_PKG_VERSION"), "-", env!("GIT_HASH"));
    let args = Command::new("rustybgpd")
        .version(version)
        .arg(
            Arg::new("config")
                .short('f')
                .long("config-file")
                .num_args(1)
                .help("specifying a config file"),
        )
        .arg(
            Arg::new("asn")
                .long("as-number")
                .num_args(1)
                .help("specify as number"),
        )
        .arg(
            Arg::new("id")
                .long("router-id")
                .num_args(1)
                .help("specify router id"),
        )
        .arg(
            Arg::new("any")
                .long("any-peers")
                .action(clap::ArgAction::SetTrue)
                .help("accept any peers"),
        )
        .arg(
            Arg::new("graceful-restart")
                .long("graceful-restart")
                .action(clap::ArgAction::SetTrue)
                .help("set Restart State bit (R) in GR capability; clear after all peers send EOR"),
        )
        .arg(
            Arg::new("api-hosts")
                .long("api-hosts")
                .num_args(1)
                .help("specify the host that the API server listens on (default: 0.0.0.0:50051)"),
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
        let router_id = if let Some(id) = args.get_one::<Ipv4Addr>("id") {
            Some(*id)
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

    log::info!("Hello, RustyBGPd ({} cpus)!", num_cpus::get());

    let api_sockaddr = if let Some(api_hosts) = args.get_one::<String>("api-hosts") {
        SocketAddr::from_str(api_hosts).expect("invalid API host address")
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 50051)
    };

    event::main(
        conf,
        args.get_flag("any"),
        args.get_flag("graceful-restart"),
        api_sockaddr,
    )
    .await;
    Ok(())
}
