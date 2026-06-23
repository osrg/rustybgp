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

//! BFD server (RFC 5880 / RFC 5881) — single-hop BFD for BGP peers.
//!
//! Architecture:
//!   - One server task owns a UDP socket on port 3784, dispatches received
//!     packets to per-peer tasks via unbounded channels.
//!   - One peer task per BGP neighbor drives the RFC 5880 state machine,
//!     sends periodic BFD Control packets, and fires the detection timer.
//!   - When a peer session goes Down the peer task sends BfdEvent::SessionDown
//!     to the daemon's event loop via the channel supplied at start time.
//!
//! GTSM (RFC 5881 §5):
//!   - Outgoing packets are sent with TTL = 255 (per-peer send socket).
//!   - On Linux the receive socket uses IP_MINTTL = 255 so the kernel drops
//!     packets with TTL < 255 before they reach userspace.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use rustybgp_packet::bfd::{Diagnostic, Message, State};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::Instant;

/// UDP port for single-hop BFD (RFC 5881).
pub(crate) const BFD_PORT: u16 = 3784;

/// Source port range mandated by RFC 5881 §4.
const SRC_PORT_MIN: u16 = 49152;
const SRC_PORT_MAX: u16 = 65535;

const DEFAULT_TX_US: u32 = 1_000_000;
const DEFAULT_RX_US: u32 = 1_000_000;
const DEFAULT_DETECT_MULT: u8 = 3;

/// Global counter used for discriminator generation.
static DISC_CTR: AtomicU64 = AtomicU64::new(1);

fn next_disc() -> u32 {
    // Wrapping cast: upper bits discarded, 0 excluded by using max(1, …).
    (DISC_CTR.fetch_add(1, Ordering::Relaxed) as u32).max(1)
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Config for one BFD peer session; mirrors api::BfdPeerConfig fields.
#[derive(Clone)]
pub(crate) struct BfdPeerConfig {
    pub desired_min_tx_interval_us: u32,
    pub required_min_rx_interval_us: u32,
    pub detect_multiplier: u8,
    /// Remote UDP port; 0 means use the default (3784).
    pub port: u16,
}

impl Default for BfdPeerConfig {
    fn default() -> Self {
        Self {
            desired_min_tx_interval_us: DEFAULT_TX_US,
            required_min_rx_interval_us: DEFAULT_RX_US,
            detect_multiplier: DEFAULT_DETECT_MULT,
            port: 0,
        }
    }
}

impl BfdPeerConfig {
    fn remote_port(&self) -> u16 {
        if self.port > 0 { self.port } else { BFD_PORT }
    }

    fn tx_interval(&self) -> Duration {
        Duration::from_micros(self.desired_min_tx_interval_us.max(1) as u64)
    }

    fn detect_interval(&self) -> Duration {
        Duration::from_micros(
            self.detect_multiplier as u64 * self.required_min_rx_interval_us.max(1) as u64,
        )
    }
}

/// Events the BFD server sends to the daemon's main event loop.
pub(crate) enum BfdEvent {
    SessionDown { peer_addr: IpAddr },
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

enum BfdRequest {
    AddPeer { addr: IpAddr, config: BfdPeerConfig },
    RemovePeer { addr: IpAddr },
}

#[derive(Clone, Default)]
pub(crate) struct PeerStateSnapshot {
    /// api::BfdSessionState value (i32 so it's FFI-compatible with proto enum).
    pub session_state: i32,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

#[derive(Default)]
struct ServerStats {
    rx_packet: AtomicU64,
    rx_error: AtomicU64,
    invalid_packet: AtomicU64,
    unknown_peer: AtomicU64,
}

struct PeerHandle {
    /// Dropping this sender causes the peer task to exit.
    _rx_tx: mpsc::UnboundedSender<Message>,
}

// ---------------------------------------------------------------------------
// BfdHandle — public API
// ---------------------------------------------------------------------------

/// Handle to the BFD server task.  Cheap to clone; all clones share the same
/// underlying task via the channel.
pub(crate) struct BfdHandle {
    tx: mpsc::UnboundedSender<BfdRequest>,
}

impl BfdHandle {
    /// Spawn the BFD server task and return a handle to it.
    /// `event_tx` receives BfdEvent notifications when sessions change state.
    pub(crate) fn start(event_tx: mpsc::UnboundedSender<BfdEvent>) -> Self {
        let stats = Arc::new(ServerStats::default());
        let peer_states = Arc::new(RwLock::new(HashMap::<IpAddr, PeerStateSnapshot>::new()));
        let (req_tx, req_rx) = mpsc::unbounded_channel();
        tokio::spawn(server_loop(req_rx, event_tx, stats, peer_states));
        BfdHandle { tx: req_tx }
    }

    /// Register a BGP peer for BFD monitoring.  Idempotent: a second call for
    /// the same address is silently ignored by the server task.
    pub(crate) fn add_peer(&self, addr: IpAddr, config: BfdPeerConfig) {
        let _ = self.tx.send(BfdRequest::AddPeer { addr, config });
    }

    /// Deregister a BGP peer.  The peer task is stopped; any in-flight session
    /// is torn down without notifying BGP (the caller is responsible for that).
    pub(crate) fn remove_peer(&self, addr: IpAddr) {
        let _ = self.tx.send(BfdRequest::RemovePeer { addr });
    }
}

// ---------------------------------------------------------------------------
// Server task
// ---------------------------------------------------------------------------

async fn server_loop(
    mut req_rx: mpsc::UnboundedReceiver<BfdRequest>,
    event_tx: mpsc::UnboundedSender<BfdEvent>,
    stats: Arc<ServerStats>,
    peer_states: Arc<RwLock<HashMap<IpAddr, PeerStateSnapshot>>>,
) {
    let socket = match create_listen_socket() {
        Ok(s) => Arc::new(s),
        Err(e) => {
            log::error!("BFD: failed to bind port {BFD_PORT}: {e}");
            return;
        }
    };

    let mut peers: HashMap<IpAddr, PeerHandle> = HashMap::new();
    let mut buf = [0u8; 4096];

    loop {
        tokio::select! {
            req = req_rx.recv() => {
                match req {
                    Some(BfdRequest::AddPeer { addr, config }) => {
                        if peers.contains_key(&addr) {
                            continue;
                        }
                        let disc = next_disc();
                        let (rx_tx, rx_rx) = mpsc::unbounded_channel::<Message>();
                        {
                            let mut ps = peer_states.write().unwrap();
                            ps.insert(addr, PeerStateSnapshot::default());
                        }
                        let peer_states2 = peer_states.clone();
                        let event_tx2 = event_tx.clone();
                        tokio::spawn(peer_loop(
                            addr, config, disc,
                            socket.clone(), rx_rx,
                            event_tx2, peer_states2,
                        ));
                        peers.insert(addr, PeerHandle { _rx_tx: rx_tx });
                        log::info!("BFD: peer {addr} added (disc={disc:#010x})");
                    }
                    Some(BfdRequest::RemovePeer { addr }) => {
                        if peers.remove(&addr).is_some() {
                            peer_states.write().unwrap().remove(&addr);
                            log::info!("BFD: peer {addr} removed");
                        }
                    }
                    None => break,
                }
            }
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, src)) => {
                        stats.rx_packet.fetch_add(1, Ordering::Relaxed);
                        let addr = src.ip();
                        match Message::decode(&buf[..len]) {
                            Ok(msg) => {
                                if let Some(peer) = peers.get(&addr) {
                                    // Channel is bounded only by memory; drop if full.
                                    if peer._rx_tx.send(msg).is_err() {
                                        log::debug!("BFD: rx drop for {addr}");
                                    }
                                } else {
                                    stats.unknown_peer.fetch_add(1, Ordering::Relaxed);
                                    log::debug!("BFD: unknown peer {addr}");
                                }
                            }
                            Err(e) => {
                                stats.invalid_packet.fetch_add(1, Ordering::Relaxed);
                                log::debug!("BFD: invalid packet from {addr}: {e}");
                            }
                        }
                    }
                    Err(e) => {
                        stats.rx_error.fetch_add(1, Ordering::Relaxed);
                        log::warn!("BFD: recv error: {e}");
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Per-peer task
// ---------------------------------------------------------------------------

async fn peer_loop(
    peer_addr: IpAddr,
    config: BfdPeerConfig,
    my_disc: u32,
    server_socket: Arc<UdpSocket>,
    mut rx_rx: mpsc::UnboundedReceiver<Message>,
    event_tx: mpsc::UnboundedSender<BfdEvent>,
    peer_states: Arc<RwLock<HashMap<IpAddr, PeerStateSnapshot>>>,
) {
    let send_socket = match create_send_socket(peer_addr, config.remote_port()) {
        Ok(s) => s,
        Err(e) => {
            log::error!("BFD: send socket for {peer_addr}: {e}");
            return;
        }
    };

    let tx_interval = config.tx_interval();
    let detect_interval = config.detect_interval();
    let ctx = SendCtx {
        send_socket,
        server_socket: &server_socket,
        peer_addr,
        remote_port: config.remote_port(),
        config: &config,
    };

    let mut session_state = State::Down;
    let mut your_disc: u32 = 0;
    let mut rx_count: u64 = 0;
    let mut tx_count: u64 = 0;
    // Detection timer deadline; None while in Down (timer not running).
    let mut expiry: Option<Instant> = None;

    let mut tx_ticker = tokio::time::interval(tx_interval);

    loop {
        tokio::select! {
            msg = rx_rx.recv() => {
                let msg = match msg {
                    Some(m) => m,
                    // Server task dropped our sender → we are deregistered.
                    None => break,
                };

                // RFC 5880 §6.8.6: discard if Your Discriminator is set and
                // doesn't match our local discriminator.
                if msg.your_discriminator != 0 && msg.your_discriminator != my_disc {
                    log::debug!(
                        "BFD: {peer_addr} discriminator mismatch \
                         (expected {my_disc:#010x}, got {:#010x})",
                        msg.your_discriminator
                    );
                    continue;
                }

                rx_count += 1;
                your_disc = msg.my_discriminator;

                let new_state = next_state(session_state, msg.state);

                if new_state != session_state {
                    log::info!(
                        "BFD: {peer_addr} {session_state} -> {new_state} \
                         (remote diag: {})",
                        msg.diagnostic
                    );
                }

                // Notify daemon when session transitions out of Up/Init.
                if is_established(session_state) && !is_established(new_state) {
                    let _ = event_tx.send(BfdEvent::SessionDown { peer_addr });
                    expiry = None;
                } else if is_established(new_state) {
                    // Reset detection timer on every received packet while up.
                    expiry = Some(Instant::now() + detect_interval);
                }

                session_state = new_state;
                write_state(&peer_states, peer_addr, session_state, rx_count, tx_count);

                // Respond to Poll with Final (RFC 5880 §6.5).
                if msg.poll {
                    ctx.send_packet(session_state, my_disc, your_disc, false, true).await;
                    tx_count += 1;
                }
            }
            _ = tx_ticker.tick() => {
                ctx.send_packet(session_state, my_disc, your_disc, false, false).await;
                tx_count += 1;
                write_state(&peer_states, peer_addr, session_state, rx_count, tx_count);
            }
            _ = sleep_until_opt(expiry) => {
                // Detection timeout (RFC 5880 §6.8.4).
                if is_established(session_state) {
                    log::warn!("BFD: {peer_addr} detection timeout");
                    session_state = State::Down;
                    your_disc = 0;
                    expiry = None;
                    let _ = event_tx.send(BfdEvent::SessionDown { peer_addr });
                    write_state(&peer_states, peer_addr, session_state, rx_count, tx_count);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// RFC 5880 §6.8.6 state machine
// ---------------------------------------------------------------------------

fn next_state(current: State, remote: State) -> State {
    match remote {
        // Remote is admin-down: always Down regardless of current state.
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
// Helpers
// ---------------------------------------------------------------------------

fn write_state(
    peer_states: &Arc<RwLock<HashMap<IpAddr, PeerStateSnapshot>>>,
    addr: IpAddr,
    state: State,
    rx_packets: u64,
    tx_packets: u64,
) {
    // api::BfdSessionState numeric values match the proto enum:
    // 0=UNSPECIFIED, 1=UP, 2=DOWN, 3=ADMIN_DOWN, 4=INIT
    let session_state = match state {
        State::AdminDown => 3,
        State::Down => 2,
        State::Init => 4,
        State::Up => 1,
    };
    if let Ok(mut ps) = peer_states.write()
        && let Some(entry) = ps.get_mut(&addr)
    {
        entry.session_state = session_state;
        entry.rx_packets = rx_packets;
        entry.tx_packets = tx_packets;
    }
}

async fn sleep_until_opt(deadline: Option<Instant>) {
    match deadline {
        Some(d) => tokio::time::sleep_until(d).await,
        None => std::future::pending().await,
    }
}

/// Per-peer send context: owns the optional connected socket and holds
/// references to the shared server socket + fixed peer parameters.
struct SendCtx<'a> {
    send_socket: Option<UdpSocket>,
    server_socket: &'a UdpSocket,
    peer_addr: IpAddr,
    remote_port: u16,
    config: &'a BfdPeerConfig,
}

impl SendCtx<'_> {
    async fn send_packet(
        &self,
        state: State,
        my_disc: u32,
        your_disc: u32,
        poll: bool,
        final_: bool,
    ) {
        let msg = Message {
            diagnostic: Diagnostic::NO_DIAGNOSTIC,
            state,
            poll,
            final_,
            control_plane_independent: false,
            demand: false,
            detect_multiplier: self.config.detect_multiplier,
            my_discriminator: my_disc,
            your_discriminator: your_disc,
            desired_min_tx_interval: self.config.desired_min_tx_interval_us,
            required_min_rx_interval: self.config.required_min_rx_interval_us,
            required_min_echo_rx_interval: 0,
        };
        let buf = match msg.encode() {
            Ok(b) => b,
            Err(e) => {
                log::error!("BFD: encode error: {e}");
                return;
            }
        };

        // Prefer the per-peer send socket (TTL=255, RFC-compliant source port).
        // Fall back to server_socket with send_to if the per-peer socket failed.
        if let Some(s) = &self.send_socket {
            if let Err(e) = s.send(&buf).await {
                log::debug!("BFD: send to {}: {e}", self.peer_addr);
            }
        } else {
            let remote = SocketAddr::new(self.peer_addr, self.remote_port);
            if let Err(e) = self.server_socket.send_to(&buf, remote).await {
                log::debug!("BFD: send_to {}: {e}", self.peer_addr);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Socket creation
// ---------------------------------------------------------------------------

fn create_listen_socket() -> std::io::Result<UdpSocket> {
    // Bind on all interfaces, port 3784.
    let std_sock =
        std::net::UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), BFD_PORT))?;

    // GTSM (RFC 5881 §5): drop incoming packets with TTL < 255 in the kernel.
    // IP_MINTTL (Linux ≥ 2.6.34) avoids the cost of checking TTL in userspace.
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
            log::warn!(
                "BFD: IP_MINTTL setsockopt failed: {} (GTSM disabled)",
                std::io::Error::last_os_error()
            );
        }
    }

    std_sock.set_nonblocking(true)?;
    UdpSocket::from_std(std_sock)
}

/// Create a connected UDP socket for sending to one peer.
/// Bound to a random source port in 49152–65535 (RFC 5881 §4).
/// TTL is set to 255 (GTSM, RFC 5881 §5).
fn create_send_socket(peer_addr: IpAddr, remote_port: u16) -> std::io::Result<Option<UdpSocket>> {
    let remote = SocketAddr::new(peer_addr, remote_port);
    let unspecified: IpAddr = match peer_addr {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };

    // Try up to 64 ports in the required range before giving up.
    let base = (next_disc() % (SRC_PORT_MAX - SRC_PORT_MIN + 1) as u32) as u16;
    for i in 0u16..64 {
        let port = SRC_PORT_MIN + (base + i) % (SRC_PORT_MAX - SRC_PORT_MIN + 1);
        let bind_addr = SocketAddr::new(unspecified, port);
        let std_sock = match std::net::UdpSocket::bind(bind_addr) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => continue,
            Err(e) => return Err(e),
        };
        // connect() on a UDP socket just sets the default destination;
        // it's a local syscall, not a network operation.
        std_sock.connect(remote)?;
        std_sock.set_nonblocking(true)?;
        let sock = UdpSocket::from_std(std_sock)?;
        // GTSM: set outgoing TTL to 255.
        sock.set_ttl(255)?;
        return Ok(Some(sock));
    }

    log::warn!(
        "BFD: could not bind a source port in {SRC_PORT_MIN}-{SRC_PORT_MAX} \
         for {peer_addr}; falling back to server socket"
    );
    Ok(None)
}
