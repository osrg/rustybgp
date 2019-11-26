// Copyright (C) 2019 The RustyBGP Authors.
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

extern crate clap;

use clap::{App, Arg};

use grpcio::*;
use std::io::prelude::*;
use std::io::Read;
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::SystemTime;

use api;
use proto::bgp;

mod service;

fn main() {
    println!("Hello, RustyBGP!");

    let args = App::new("rustybgp")
        .arg(
            Arg::with_name("any_peer")
                .long("any-peer")
                .help("accept any peers"),
        )
        .get_matches();

    let accept_any = args.is_present("any_peer");

    let (init_tx, init_rx) = mpsc::channel();

    let global = Arc::new(RwLock::new(service::Global::new()));
    let table = Arc::new(RwLock::new(service::Table::new()));
    let env = Arc::new(Environment::new(1));
    let mut server = ServerBuilder::new(env)
        .register_service(api::gobgp_grpc::create_gobgp_api(service::Service::new(
            global.clone(),
            table.clone(),
            init_tx,
        )))
        .bind("127.0.0.1", 50051)
        .build()
        .unwrap();

    server.start();

    for &(ref host, port) in server.bind_addrs() {
        println!("grpc: listening on {}:{}", host, port);
    }

    let _ = init_rx.recv();

    let (sock_tx, sock_rx) = mpsc::channel();

    thread::spawn(move || {
        let listener = TcpListener::bind("[::]:179").unwrap();
        for stream in listener.incoming() {
            let stream = match stream {
                Ok(stream) => stream,
                Err(_) => continue,
            };
            let addr = stream.peer_addr();
            println!("got new connection {:?}", addr);
            if sock_tx.send(stream).is_err() {
                println!("failed to handle new connection {:?}", addr);
            }
        }
    });

    loop {
        let stream = match sock_rx.recv() {
            Ok(stream) => stream,
            Err(_) => continue,
        };

        let g = global.clone();
        let t = table.clone();
        let addr = match stream.peer_addr() {
            Ok(addr) => addr.ip(),
            Err(_) => continue,
        };

        {
            if !g.read().unwrap().peer.contains_key(&addr) && !accept_any {
                println!("peer configuration for {} is not found", addr);
                continue;
            }

            let dynamic = accept_any && !g.read().unwrap().peer.contains_key(&addr);
            if dynamic {
                let peer = &mut global.write().unwrap().peer;
                peer.insert(addr, service::PeerState::new(addr));
            }

            if dynamic || (!accept_any || g.read().unwrap().peer.contains_key(&addr)) {
                thread::spawn(move || {
                    handle_connection(stream, g, t);
                });
            }
        }
    }
}

fn handle_connection(
    mut stream: TcpStream,
    global: Arc<RwLock<service::Global>>,
    table: Arc<RwLock<service::Table>>,
) {
    let addr = match stream.peer_addr() {
        Ok(addr) => addr.ip(),
        Err(_) => {
            return;
        }
    };

    let mut buf = Vec::new();

    let set_state = |state| {
        let peer = &mut global.write().unwrap().peer;
        peer.get_mut(&addr).unwrap().state = state;
    };

    let get_state = || -> bgp::State {
        let peer = &global.read().unwrap().peer;
        peer.get(&addr).unwrap().state
    };

    let remove_peer = || {
        let mut t = table.write().unwrap();
        t.clear(addr);
        let peer = &mut global.write().unwrap().peer;
        peer.remove(&addr);
    };

    {
        let (as_number, router_id) = (|| -> (u32, Ipv4Addr) {
            let global = global.read().unwrap();
            (global.as_number, global.id)
        })();

        let open = bgp::OpenMessage::new(as_number, router_id);
        {
            let peer = &mut global.write().unwrap().peer;
            let mut peer = peer.get_mut(&addr).unwrap();
            peer.local_cap = open
                .get_parameters()
                .into_iter()
                .filter_map(|p| match p {
                    bgp::OpenParam::CapabilityParam(c) => Some(c),
                    _ => None,
                })
                .collect();
        }

        let buf = bgp::Message::Open(open).to_bytes().unwrap();
        if stream.write_all(&buf).is_err() {
            remove_peer();
            return;
        }

        set_state(bgp::State::OpenSent);
    }

    set_state(bgp::State::Active);

    loop {
        let mut b = [0; 4096];
        let n = stream.read(&mut b).unwrap_or(0);
        if n > 0 {
            buf.extend_from_slice(&b[0..n]);
        } else {
            remove_peer();
            println!("{} is disconnected", addr);
            return;
        }

        while let Some(msg) = bgp::Message::from_bytes(&buf).ok() {
            {
                let peer = &mut global.write().unwrap().peer;
                peer.get_mut(&addr).unwrap().counter_rx.sync(&msg);
            }
            let length = msg.length();
            match msg {
                bgp::Message::Open(open) => {
                    {
                        let peer = &mut global.write().unwrap().peer;
                        let peer = peer.get_mut(&addr).unwrap();
                        peer.router_id = open.id;
                        peer.remote_as = open.get_as_number();

                        peer.remote_cap = open
                            .params
                            .into_iter()
                            .filter_map(|p| match p {
                                bgp::OpenParam::CapabilityParam(c) => Some(c),
                                _ => None,
                            })
                            .collect();
                    }
                    set_state(bgp::State::OpenConfirm);
                }
                bgp::Message::Update(update) => {
                    let mut accept: i64 = 0;
                    if update.attrs.len() > 0 {
                        let pa = Arc::new(RwLock::new(service::PathAttr {
                            attrs: update.attrs,
                        }));
                        let mut t = table.write().unwrap();
                        for r in update.routes {
                            if t.insert(
                                bgp::Family::Ipv4Uc,
                                r,
                                stream.peer_addr().unwrap().ip(),
                                pa.clone(),
                            ) {
                                accept += 1;
                            }
                        }
                    }
                    {
                        let mut t = table.write().unwrap();
                        for r in update.withdrawns {
                            if t.remove(bgp::Family::Ipv4Uc, r, stream.peer_addr().unwrap().ip()) {
                                accept -= 1;
                            }
                        }
                    }
                    {
                        let peer = &mut global.write().unwrap().peer;
                        if accept > 0 {
                            peer.get_mut(&addr).unwrap().accepted += accept as u64;
                        } else {
                            peer.get_mut(&addr).unwrap().accepted -= accept.abs() as u64;
                        }
                    }
                }
                bgp::Message::Notification(_) => {
                    remove_peer();
                    return;
                }
                bgp::Message::Keepalive => {
                    let keepalive = bgp::Message::Keepalive;
                    let buf = keepalive.to_bytes().unwrap();
                    if stream.write_all(&buf).is_err() {
                        break;
                    }

                    if get_state() != bgp::State::Established {
                        set_state(bgp::State::Established);

                        let peer = &mut global.write().unwrap().peer;
                        peer.get_mut(&addr).unwrap().uptime = SystemTime::now();
                    }
                }
                bgp::Message::RouteRefresh(m) => println!("{:?}", m.family),
                bgp::Message::Unknown { length: _, code } => {
                    println!("unknown message type {}", code)
                }
            }
            buf = buf.drain(length as usize..).collect();
        }
    }
}
