// Copyright (C) 2026 The RustyBGP Authors.
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
// implied. See the License for the specific language governing
// permissions and limitations under the License.

//! BFD peer stub for e2e testing.
//!
//! Runs the RFC 5880 state machine in active mode (sends BFD Control
//! packets immediately, does not wait for the peer to initiate).
//!
//! State transitions are printed to stdout so the test script can assert:
//!   grep "BFD STATE: Up" <(docker logs bfd-peer)
//!
//! Signal behaviour:
//!   SIGTERM / SIGINT  — exit immediately without sending AdminDown.
//!                       Simulates sudden peer loss; the remote detects a
//!                       timeout rather than an AdminDown notification.
//!   SIGUSR1           — send AdminDown packets for ~500 ms then exit.
//!                       Simulates a graceful administrative shutdown.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use clap::Parser;
use rustybgp_packet::bfd::{Diagnostic, Message, State};
use tokio::net::UdpSocket;
use tokio::time::Instant;

const BFD_PORT: u16 = 3784;
const SRC_PORT_MIN: u16 = 49152;
const SRC_PORT_MAX: u16 = 65535;
// Fixed discriminator for the stub; unique enough for e2e tests.
const MY_DISC: u32 = 0xbfd0_5700;

#[derive(Parser)]
#[command(about = "Minimal BFD peer stub for RustyBGP e2e testing")]
struct Args {
    /// Remote peer IPv4 address
    #[arg(long)]
    remote: Ipv4Addr,

    /// Desired minimum Tx interval in microseconds
    #[arg(long, default_value_t = 300_000)]
    tx_interval: u32,

    /// Required minimum Rx interval in microseconds
    #[arg(long, default_value_t = 300_000)]
    rx_interval: u32,

    /// Detection multiplier
    #[arg(long, default_value_t = 3)]
    detect_mult: u8,
}

// ---------------------------------------------------------------------------
// Socket helpers (mirrors daemon/src/bfd.rs)
// ---------------------------------------------------------------------------

fn create_listen_socket() -> std::io::Result<UdpSocket> {
    let std_sock = std::net::UdpSocket::bind(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        BFD_PORT,
    ))?;

    // GTSM (RFC 5881 §5): kernel drops incoming packets with TTL < 255.
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let val: libc::c_int = 255;
        let ret = unsafe {
            libc::setsockopt(
                std_sock.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_MINTTL,
                std::ptr::addr_of!(val).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            // Non-fatal: GTSM protection disabled (e.g. under QEMU emulation).
            eprintln!(
                "BFD stub: IP_MINTTL setsockopt failed: {} (GTSM disabled)",
                std::io::Error::last_os_error()
            );
        }
    }

    std_sock.set_nonblocking(true)?;
    UdpSocket::from_std(std_sock)
}

fn create_send_socket(remote: Ipv4Addr) -> std::io::Result<UdpSocket> {
    let remote_addr = SocketAddr::new(IpAddr::V4(remote), BFD_PORT);
    for port in SRC_PORT_MIN..=SRC_PORT_MAX {
        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
        let std_sock = match std::net::UdpSocket::bind(bind_addr) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => continue,
            Err(e) => return Err(e),
        };
        std_sock.connect(remote_addr)?;
        std_sock.set_nonblocking(true)?;
        let sock = UdpSocket::from_std(std_sock)?;
        sock.set_ttl(255)?;
        return Ok(sock);
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AddrInUse,
        "no free source port in 49152-65535",
    ))
}

// ---------------------------------------------------------------------------
// RFC 5880 §6.8.6 state machine (same logic as daemon/src/bfd.rs)
// ---------------------------------------------------------------------------

fn next_state(current: State, remote: State) -> State {
    match remote {
        State::AdminDown => State::Down,
        State::Down => match current {
            State::Down => State::Init,
            State::Up => State::Down,
            _ => current,
        },
        State::Init => match current {
            State::Down | State::Init => State::Up,
            _ => current,
        },
        State::Up => match current {
            State::Init => State::Up,
            _ => current,
        },
    }
}

fn is_established(s: State) -> bool {
    matches!(s, State::Init | State::Up)
}

// ---------------------------------------------------------------------------
// Packet helper
// ---------------------------------------------------------------------------

fn make_msg(
    state: State,
    your_disc: u32,
    poll: bool,
    final_: bool,
    detect_mult: u8,
    tx_interval: u32,
    rx_interval: u32,
) -> Message {
    Message {
        diagnostic: Diagnostic::NO_DIAGNOSTIC,
        state,
        poll,
        final_,
        control_plane_independent: false,
        demand: false,
        detect_multiplier: detect_mult,
        my_discriminator: MY_DISC,
        your_discriminator: your_disc,
        desired_min_tx_interval: tx_interval,
        required_min_rx_interval: rx_interval,
        required_min_echo_rx_interval: 0,
    }
}

async fn send(sock: &UdpSocket, msg: &Message) {
    match msg.encode() {
        Ok(b) => {
            if let Err(e) = sock.send(&b).await {
                eprintln!("bfd-stub: send error: {e}");
            }
        }
        Err(e) => eprintln!("bfd-stub: encode error: {e}"),
    }
}

// ---------------------------------------------------------------------------
// sleep helper
// ---------------------------------------------------------------------------

async fn sleep_until_opt(deadline: Option<Instant>) {
    match deadline {
        Some(d) => tokio::time::sleep_until(d).await,
        None => std::future::pending().await,
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let listen_sock = create_listen_socket()?;
    let send_sock = create_send_socket(args.remote)?;

    let tx_dur = Duration::from_micros(args.tx_interval as u64);
    let detect_dur =
        Duration::from_micros(args.detect_mult as u64 * args.rx_interval as u64);

    let mut state = State::Down;
    let mut your_disc: u32 = 0;
    let mut expiry: Option<Instant> = None;
    let mut buf = [0u8; 512];

    let mut tx_ticker = tokio::time::interval(tx_dur);

    let mut sigusr1 = tokio::signal::unix::signal(
        tokio::signal::unix::SignalKind::user_defined1(),
    )?;
    let mut sigterm = tokio::signal::unix::signal(
        tokio::signal::unix::SignalKind::terminate(),
    )?;
    let mut sigint = tokio::signal::unix::signal(
        tokio::signal::unix::SignalKind::interrupt(),
    )?;

    println!(
        "bfd-stub: remote={}:{BFD_PORT} tx={}us rx={}us mult={}",
        args.remote, args.tx_interval, args.rx_interval, args.detect_mult,
    );
    println!("BFD STATE: Down");

    loop {
        tokio::select! {
            result = listen_sock.recv_from(&mut buf) => {
                let (len, src) = result?;

                // Ignore packets from unexpected sources.
                if src.ip() != IpAddr::V4(args.remote) {
                    continue;
                }

                let msg = match Message::decode(&buf[..len]) {
                    Ok(m) => m,
                    Err(_) => continue,
                };

                // RFC 5880 §6.8.6: discard if Your Discriminator is set and
                // doesn't match our local discriminator.
                if msg.your_discriminator != 0 && msg.your_discriminator != MY_DISC {
                    continue;
                }

                your_disc = msg.my_discriminator;
                let new_state = next_state(state, msg.state);

                if new_state != state {
                    println!("BFD STATE: {state} -> {new_state}");
                    state = new_state;
                }

                if is_established(state) {
                    expiry = Some(Instant::now() + detect_dur);
                } else {
                    expiry = None;
                }

                // RFC 5880 §6.5: respond to Poll with Final.
                if msg.poll {
                    send(
                        &send_sock,
                        &make_msg(state, your_disc, false, true,
                                  args.detect_mult, args.tx_interval, args.rx_interval),
                    ).await;
                }
            }

            _ = tx_ticker.tick() => {
                send(
                    &send_sock,
                    &make_msg(state, your_disc, false, false,
                              args.detect_mult, args.tx_interval, args.rx_interval),
                ).await;
            }

            _ = sleep_until_opt(expiry) => {
                if is_established(state) {
                    println!("BFD STATE: {state} -> Down (detection timeout)");
                    state = State::Down;
                    your_disc = 0;
                    expiry = None;
                }
            }

            _ = sigusr1.recv() => {
                // AdminDown: send AdminDown packets briefly then exit.
                // The remote detects AdminDown rather than a timeout.
                println!("BFD STATE: {state} -> AdminDown (SIGUSR1)");
                let deadline = Instant::now() + Duration::from_millis(500);
                while Instant::now() < deadline {
                    send(
                        &send_sock,
                        &make_msg(State::AdminDown, your_disc, false, false,
                                  args.detect_mult, args.tx_interval, args.rx_interval),
                    ).await;
                    tokio::time::sleep(tx_dur).await;
                }
                println!("bfd-stub: AdminDown sent, exiting");
                break;
            }

            _ = sigterm.recv() => {
                // Sudden loss: no AdminDown sent.
                println!("bfd-stub: SIGTERM received, exiting (no AdminDown)");
                break;
            }

            _ = sigint.recv() => {
                println!("bfd-stub: SIGINT received, exiting (no AdminDown)");
                break;
            }
        }
    }

    Ok(())
}
