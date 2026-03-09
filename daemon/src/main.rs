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
pub(crate) use rustybgp_api as api;
pub(crate) use rustybgp_config as config;
mod auth;
mod convert;
mod error;
mod event;
mod proto;

use clap::{Arg, Command};
use std::net::Ipv4Addr;
use std::str::FromStr;
use tracing::info;
use tracing_subscriber::EnvFilter;

fn main() -> Result<(), std::io::Error> {
    if num_cpus::get() < 4 {
        panic!("four local CPUs are necessary at least");
    }

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
            Arg::new("log-level")
                .short('l')
                .long("log-level")
                .num_args(1)
                .default_value("info")
                .help("log level: emergency, alert, critical, error, warning, notice, info, debug"),
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

    // Map syslog-style level names to tracing filter levels.
    // Syslog levels: emergency(0), alert(1), critical(2), error(3),
    //                warning(4), notice(5), info(6), debug(7)
    let level = args.get_one::<String>("log-level").unwrap();
    let filter = match level.to_lowercase().as_str() {
        "emergency" | "emerg" | "0" => "error",
        "alert" | "1" => "error",
        "critical" | "crit" | "2" => "error",
        "error" | "err" | "3" => "error",
        "warning" | "warn" | "4" => "warn",
        "notice" | "5" => "info",
        "info" | "informational" | "6" => "info",
        "debug" | "7" => "debug",
        "trace" => "trace",
        other => {
            eprintln!("unknown log level '{}', defaulting to info", other);
            "info"
        }
    };

    // RUST_LOG env var takes precedence if set.
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter));

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(true)
        .with_thread_ids(true)
        .init();

    info!(cpus = num_cpus::get(), version = version, "starting RustyBGPd");

    event::main(conf, args.get_flag("any"));
    Ok(())
}
