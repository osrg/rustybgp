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

//! Pure Sans-IO BGP session state machine.
//!
//! This module contains no async code, no tokio dependencies, and no global
//! state access. It processes [`Input`] events and returns [`Output`] actions
//! that an I/O driver (the `Handler` in `event.rs`) translates into real I/O.

use fnv::FnvHashMap;
use rustybgp_packet::bgp::{self, Capability, Family, HoldTime};

/// Initial hold timer value for OpenSent (RFC 4271 §8.2.2 suggests 4 minutes).
const INITIAL_HOLD_SECS: u64 = 240;

/// BGP session states (RFC 4271 §8.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum State {
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
    Established,
}

impl From<State> for u8 {
    fn from(s: State) -> Self {
        match s {
            State::Idle => 0,
            State::Connect => 1,
            State::Active => 2,
            State::OpenSent => 3,
            State::OpenConfirm => 4,
            State::Established => 5,
        }
    }
}

impl TryFrom<u8> for State {
    type Error = u8;
    fn try_from(v: u8) -> Result<Self, u8> {
        match v {
            0 => Ok(State::Idle),
            1 => Ok(State::Connect),
            2 => Ok(State::Active),
            3 => Ok(State::OpenSent),
            4 => Ok(State::OpenConfirm),
            5 => Ok(State::Established),
            _ => Err(v),
        }
    }
}

/// Events fed into the session FSM.
pub(crate) enum Input {
    /// TCP connection established; start the OPEN exchange.
    /// The bool indicates whether the local speaker is currently the restarting
    /// speaker (R-bit in the GR capability of the OPEN).
    Connected(bool),
    /// A complete BGP message was received from the peer.
    MessageReceived(bgp::Message),
    /// The keepalive timer fired (send direction: we may need to send KEEPALIVE).
    KeepaliveTimerExpired,
    /// The hold timer fired (receive direction: remote has been silent too long).
    HoldTimerExpired,
    /// TCP stream closed or I/O error detected by the driver.
    Disconnected,
    /// Administrative shutdown (disable_peer / shutdown_peer).
    AdminShutdown,
    /// An UPDATE message was sent to the peer; reset the keepalive timer.
    UpdateSent,
}

/// Actions the I/O driver should perform.
pub(crate) enum Output {
    /// Send a BGP message on the wire.
    SendMessage(bgp::Message),
    /// Arm or re-arm the keepalive timer (send direction, seconds).
    SetKeepaliveTimer(u64),
    /// Arm or re-arm the hold timer (receive direction, seconds).
    SetHoldTimer(u64),
    /// Negotiated address-family channels. The driver should configure its
    /// PeerCodec with these.
    ChannelsNegotiated(FnvHashMap<Family, bgp::Channel>),
    /// The session reached Established. The driver should register the peer
    /// as a route source, populate initial routes, etc.
    SessionEstablished {
        remote_asn: u32,
        remote_id: u32,
        remote_holdtime: u16,
        remote_capabilities: Vec<Capability>,
    },
    /// The session is shutting down.
    SessionDown(SessionDownReason),
    /// The FSM state changed. The driver should update any shared state
    /// (e.g., `Arc<PeerState>`).
    StateChanged(State),
    /// Peer requested route refresh for the given family (RFC 2918).
    /// The driver should re-advertise its full RIB-Out for that family.
    RouteRefresh(Family),
}

/// Reason the session is going down.
#[derive(Clone)]
pub(crate) enum SessionDownReason {
    HoldTimerExpired,
    /// Peer sent a NOTIFICATION message.
    RemoteNotification(bgp::Message),
    /// We sent a NOTIFICATION message (e.g. parse error, capability mismatch).
    LocalNotification(bgp::Message),
    FsmError,
    AdminShutdown,
    IoError,
}

/// Pure BGP connection state machine.
///
/// Holds all negotiation state for a single BGP connection. Has no I/O
/// dependencies — processes [`Input`] events and returns [`Output`] actions.
pub(crate) struct Connection {
    state: State,
    local_asn: u32,
    local_router_id: u32,
    local_holdtime: u64,
    local_cap: Vec<Capability>,
    expected_remote_asn: u32,

    // Populated after OPEN received
    remote_asn: u32,
    remote_id: u32,
    remote_holdtime: u16,
    remote_cap: Vec<Capability>,
    negotiated_holdtime: u64,
    keepalive_interval: u64,

    // send_max retained after capability negotiation
    send_max: FnvHashMap<Family, usize>,
}

impl Connection {
    pub(crate) fn new(
        local_asn: u32,
        local_router_id: u32,
        local_cap: Vec<Capability>,
        local_holdtime: u64,
        expected_remote_asn: u32,
        send_max: FnvHashMap<Family, usize>,
    ) -> Self {
        Connection {
            state: State::Idle,
            local_asn,
            local_router_id,
            local_holdtime,
            local_cap,
            expected_remote_asn,
            remote_asn: 0,
            remote_id: 0,
            remote_holdtime: 0,
            remote_cap: Vec::new(),
            negotiated_holdtime: 0,
            keepalive_interval: 0,
            send_max,
        }
    }

    pub(crate) fn state(&self) -> State {
        self.state
    }

    #[cfg(test)]
    pub(crate) fn negotiated_holdtime(&self) -> u64 {
        self.negotiated_holdtime
    }

    pub(crate) fn send_max(&self) -> &FnvHashMap<Family, usize> {
        &self.send_max
    }

    pub(crate) fn remote_id(&self) -> u32 {
        self.remote_id
    }

    /// Process an input event and return actions for the I/O driver.
    pub(crate) fn process(&mut self, input: Input) -> Vec<Output> {
        match input {
            Input::Connected(_) => self.on_connected(),
            Input::MessageReceived(msg) => self.on_message(msg),
            Input::KeepaliveTimerExpired => self.on_keepalive_timer_expired(),
            Input::HoldTimerExpired => self.on_hold_timer_expired(),
            Input::Disconnected => self.on_disconnected(),
            Input::AdminShutdown => self.on_admin_shutdown(),
            Input::UpdateSent => self.on_update_sent(),
        }
    }

    fn on_connected(&mut self) -> Vec<Output> {
        let open = bgp::Message::Open(bgp::Open {
            as_number: self.local_asn,
            holdtime: HoldTime::new(self.local_holdtime as u16).unwrap_or(HoldTime::DISABLED),
            router_id: self.local_router_id,
            capability: self.local_cap.clone(),
        });
        self.state = State::OpenSent;
        let mut out = vec![
            Output::SendMessage(open),
            Output::StateChanged(State::OpenSent),
        ];
        // RFC 4271 §8.2.2: start hold timer with a large value in OpenSent.
        if self.local_holdtime != 0 {
            out.push(Output::SetHoldTimer(INITIAL_HOLD_SECS));
        }
        out
    }

    fn on_message(&mut self, msg: bgp::Message) -> Vec<Output> {
        match msg {
            bgp::Message::Open(open) => self.on_open(open),
            bgp::Message::Keepalive => self.on_keepalive(),
            bgp::Message::Update(_) => self.on_update(),
            bgp::Message::Notification(err) => self.on_notification(err),
            bgp::Message::RouteRefresh { family } => self.on_route_refresh(family),
        }
    }

    fn on_open(&mut self, open: bgp::Open) -> Vec<Output> {
        if self.state != State::OpenSent {
            return vec![
                Output::SendMessage(bgp::Message::Notification(
                    rustybgp_packet::BgpError::FsmUnexpectedState {
                        state: u8::from(self.state),
                    },
                )),
                Output::SessionDown(SessionDownReason::FsmError),
            ];
        }

        let mut out = Vec::new();

        // Validate ASN if pre-configured
        if self.expected_remote_asn != 0 && self.expected_remote_asn != open.as_number {
            out.push(Output::SendMessage(bgp::Message::Notification(
                rustybgp_packet::BgpError::Other {
                    code: 2,
                    subcode: 2,
                    data: vec![],
                },
            )));
            out.push(Output::SessionDown(SessionDownReason::AdminShutdown));
            return out;
        }

        // Store remote parameters
        self.remote_asn = open.as_number;
        self.remote_id = open.router_id;
        self.remote_holdtime = open.holdtime.seconds();
        self.remote_cap = open.capability.clone();

        // Send KEEPALIVE in response to OPEN
        out.push(Output::SendMessage(bgp::Message::Keepalive));

        // Negotiate capabilities
        let channels: FnvHashMap<Family, bgp::Channel> =
            bgp::create_channel(&self.local_cap, &open.capability).collect();

        // Retain send_max only for families where Add-Path TX was negotiated
        self.send_max
            .retain(|f, _| channels.get(f).is_some_and(|c| c.addpath_tx()));

        out.push(Output::ChannelsNegotiated(channels));

        // Negotiate holdtime
        self.negotiated_holdtime = std::cmp::min(self.local_holdtime, self.remote_holdtime as u64);
        if self.negotiated_holdtime != 0 {
            self.keepalive_interval = self.negotiated_holdtime / 3;
            out.push(Output::SetKeepaliveTimer(self.keepalive_interval));
            out.push(Output::SetHoldTimer(self.negotiated_holdtime));
        }

        // Transition to OpenConfirm
        self.state = State::OpenConfirm;
        out.push(Output::StateChanged(State::OpenConfirm));

        out
    }

    fn on_keepalive(&mut self) -> Vec<Output> {
        match self.state {
            State::OpenConfirm => {
                self.state = State::Established;
                vec![
                    Output::SetHoldTimer(self.negotiated_holdtime),
                    Output::SessionEstablished {
                        remote_asn: self.remote_asn,
                        remote_id: self.remote_id,
                        remote_holdtime: self.remote_holdtime,
                        remote_capabilities: std::mem::take(&mut self.remote_cap),
                    },
                    Output::StateChanged(State::Established),
                ]
            }
            State::Established => {
                vec![Output::SetHoldTimer(self.negotiated_holdtime)]
            }
            _ => vec![
                Output::SendMessage(bgp::Message::Notification(
                    rustybgp_packet::BgpError::FsmUnexpectedState {
                        state: u8::from(self.state),
                    },
                )),
                Output::SessionDown(SessionDownReason::FsmError),
            ],
        }
    }

    fn on_update(&mut self) -> Vec<Output> {
        if self.state != State::Established {
            return vec![
                Output::SendMessage(bgp::Message::Notification(
                    rustybgp_packet::BgpError::FsmUnexpectedState {
                        state: u8::from(self.state),
                    },
                )),
                Output::SessionDown(SessionDownReason::FsmError),
            ];
        }
        vec![Output::SetHoldTimer(self.negotiated_holdtime)]
    }

    fn on_notification(&mut self, err: rustybgp_packet::BgpError) -> Vec<Output> {
        vec![Output::SessionDown(SessionDownReason::RemoteNotification(
            bgp::Message::Notification(err),
        ))]
    }

    fn on_route_refresh(&mut self, family: Family) -> Vec<Output> {
        if self.state != State::Established {
            return vec![
                Output::SendMessage(bgp::Message::Notification(
                    rustybgp_packet::BgpError::FsmUnexpectedState {
                        state: u8::from(self.state),
                    },
                )),
                Output::SessionDown(SessionDownReason::FsmError),
            ];
        }
        vec![Output::RouteRefresh(family)]
    }

    fn on_keepalive_timer_expired(&mut self) -> Vec<Output> {
        match self.state {
            State::OpenConfirm | State::Established => vec![
                Output::SendMessage(bgp::Message::Keepalive),
                Output::SetKeepaliveTimer(self.keepalive_interval),
            ],
            _ => Vec::new(),
        }
    }

    fn on_hold_timer_expired(&mut self) -> Vec<Output> {
        match self.state {
            State::OpenSent | State::OpenConfirm | State::Established => {
                vec![Output::SessionDown(SessionDownReason::HoldTimerExpired)]
            }
            _ => Vec::new(),
        }
    }

    fn on_update_sent(&mut self) -> Vec<Output> {
        if self.state == State::Established && self.keepalive_interval > 0 {
            vec![Output::SetKeepaliveTimer(self.keepalive_interval)]
        } else {
            Vec::new()
        }
    }

    fn on_disconnected(&mut self) -> Vec<Output> {
        vec![Output::SessionDown(SessionDownReason::IoError)]
    }

    fn on_admin_shutdown(&mut self) -> Vec<Output> {
        vec![
            Output::SendMessage(bgp::Message::Notification(
                rustybgp_packet::BgpError::Other {
                    code: 6,
                    subcode: 2,
                    data: vec![],
                },
            )),
            Output::SessionDown(SessionDownReason::AdminShutdown),
        ]
    }
}

/// Connection role for collision detection (RFC 4271 §6.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    Active,
    Passive,
}

impl Role {
    fn other(self) -> Self {
        match self {
            Role::Active => Role::Passive,
            Role::Passive => Role::Active,
        }
    }
}

/// Output from PeerFsm, wrapping Connection outputs with role information
/// and collision detection results.
pub(crate) enum PeerFsmOutput {
    /// An output from the Connection for the given role.
    Connection(Role, Output),
    /// The driver should close this session; the FSM rejected the connection.
    CloseConnection,
    /// Passive connection reached OpenConfirm; Driver should stop active
    /// connection attempts (no new TCP connect while passive is progressing).
    StopActiveConnect,
}

/// Manages up to two concurrent Sessions (active + passive) for a single
/// BGP peer. Handles collision detection per RFC 4271 §6.8.
///
/// Pure logic — no async, no I/O.
pub(crate) struct PeerFsm {
    active: Option<Connection>,
    passive: Option<Connection>,
    pub(crate) local_router_id: u32,
    local_asn: u32,
    local_cap: Vec<Capability>,
    local_holdtime: u64,
    expected_remote_asn: u32,
    send_max: FnvHashMap<Family, usize>,
}

impl PeerFsm {
    pub(crate) fn new(
        local_router_id: u32,
        local_asn: u32,
        local_cap: Vec<Capability>,
        local_holdtime: u64,
        expected_remote_asn: u32,
        send_max: FnvHashMap<Family, usize>,
    ) -> Self {
        PeerFsm {
            active: None,
            passive: None,
            local_router_id,
            local_asn,
            local_cap,
            local_holdtime,
            expected_remote_asn,
            send_max,
        }
    }

    /// Close a connection, removing it from its slot.
    pub(crate) fn close_connection(&mut self, role: Role) {
        match role {
            Role::Active => self.active = None,
            Role::Passive => self.passive = None,
        }
    }

    /// Reference to the Connection for the given role.
    pub(crate) fn connection(&self, role: Role) -> Option<&Connection> {
        match role {
            Role::Active => self.active.as_ref(),
            Role::Passive => self.passive.as_ref(),
        }
    }

    /// Current FSM state for the given role, or Idle if no connection exists.
    pub(crate) fn state(&self, role: Role) -> State {
        self.connection(role)
            .map(|s| s.state())
            .unwrap_or(State::Idle)
    }

    /// Mutable reference to the Connection for the given role.
    pub(crate) fn connection_mut(&mut self, role: Role) -> Option<&mut Connection> {
        match role {
            Role::Active => self.active.as_mut(),
            Role::Passive => self.passive.as_mut(),
        }
    }

    /// Process an input for the given role's Connection.
    /// For Input::Connected, creates the Connection if the slot is free or returns
    /// CloseConnection if a Connection for this role already exists.
    /// Includes collision detection: if both Connections reach OpenConfirm,
    /// the loser is sent a CEASE notification and closed.
    pub(crate) fn process(&mut self, role: Role, input: Input) -> Vec<PeerFsmOutput> {
        if let Input::Connected(is_restarting) = input {
            return self.on_connected(role, is_restarting);
        }
        let Some(session) = self.connection_mut(role) else {
            return Vec::new();
        };
        let outputs = session.process(input);

        let entered_open_confirm = outputs
            .iter()
            .any(|o| matches!(o, Output::StateChanged(State::OpenConfirm)));
        let session_down = outputs.iter().any(|o| matches!(o, Output::SessionDown(_)));

        let mut result: Vec<PeerFsmOutput> = outputs
            .into_iter()
            .map(|o| PeerFsmOutput::Connection(role, o))
            .collect();

        if entered_open_confirm {
            if role == Role::Passive {
                result.push(PeerFsmOutput::StopActiveConnect);
            }
            if let Some(collision_outputs) = self.check_collision(role) {
                result.extend(collision_outputs);
            }
        }

        // Auto-clear the session slot and emit StateChanged(Idle) when the
        // session goes down, so the driver always sees a paired SessionDown +
        // StateChanged(Idle) without needing special-case knowledge here.
        if session_down {
            self.close_connection(role);
            result.push(PeerFsmOutput::Connection(
                role,
                Output::StateChanged(State::Idle),
            ));
        }

        result
    }

    /// Handle a new TCP connection for the given role.
    /// Creates a Connection and starts the OPEN exchange, or returns CloseConnection
    /// if a Connection for this role already exists.
    fn on_connected(&mut self, role: Role, is_restarting: bool) -> Vec<PeerFsmOutput> {
        let slot = match role {
            Role::Active => &mut self.active,
            Role::Passive => &mut self.passive,
        };
        if slot.is_some() {
            return vec![PeerFsmOutput::CloseConnection];
        }
        // Apply R-bit (0x8) to the GR capability when the local speaker is
        // the restarting speaker.  local_cap stores caps without R-bit so that
        // no mutation is needed when recovery completes.
        let effective_cap = if is_restarting {
            self.local_cap
                .iter()
                .map(|c| {
                    if let Capability::GracefulRestart {
                        flags,
                        restart_time,
                        families,
                    } = c
                    {
                        Capability::GracefulRestart {
                            flags: flags | 0x8,
                            restart_time: *restart_time,
                            families: families.clone(),
                        }
                    } else {
                        c.clone()
                    }
                })
                .collect()
        } else {
            self.local_cap.clone()
        };
        *slot = Some(Connection::new(
            self.local_asn,
            self.local_router_id,
            effective_cap,
            self.local_holdtime,
            self.expected_remote_asn,
            self.send_max.clone(),
        ));
        let outputs = slot.as_mut().unwrap().process(Input::Connected(false));
        outputs
            .into_iter()
            .map(|o| PeerFsmOutput::Connection(role, o))
            .collect()
    }

    /// RFC 4271 §6.8: determine which role wins a connection collision.
    /// The Active connection wins when local Router ID > remote Router ID,
    /// the Passive connection wins otherwise.
    fn collision_winner(&self, role: Role) -> Role {
        let remote_id = self.connection(role).map(|s| s.remote_id()).unwrap_or(0);
        if self.local_router_id > remote_id {
            Role::Active
        } else {
            Role::Passive
        }
    }

    /// Check for collision when a Connection enters OpenConfirm.
    /// Returns outputs to close the losing connection, or None if no collision.
    fn check_collision(&mut self, role: Role) -> Option<Vec<PeerFsmOutput>> {
        let other_role = role.other();
        let other_state = self.connection(other_role)?.state();

        // Collision only if the other connection is also in OpenConfirm or Established
        if other_state != State::OpenConfirm && other_state != State::Established {
            return None;
        }

        let winner = self.collision_winner(role);
        let loser = winner.other();

        // Send CEASE to the loser via its close channel.
        // CloseConnection is intentionally omitted: the loser shuts itself down
        // upon receiving the CEASE; only the losing role's SendMessage is needed.
        let outputs = vec![PeerFsmOutput::Connection(
            loser,
            Output::SendMessage(bgp::Message::Notification(
                rustybgp_packet::BgpError::Other {
                    code: 6,    // Cease
                    subcode: 7, // Connection Collision Resolution
                    data: vec![],
                },
            )),
        )];

        // Remove the loser's Connection
        self.close_connection(loser);

        Some(outputs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn local_router_id() -> u32 {
        u32::from(Ipv4Addr::new(1, 1, 1, 1))
    }

    fn remote_router_id() -> u32 {
        u32::from(Ipv4Addr::new(2, 2, 2, 2))
    }

    fn basic_connection() -> Connection {
        Connection::new(
            65001,
            local_router_id(),
            vec![Capability::MultiProtocol(Family::IPV4)],
            90,
            65002,
            FnvHashMap::default(),
        )
    }

    fn remote_open(asn: u32, router_id: u32, holdtime: u16) -> bgp::Message {
        bgp::Message::Open(bgp::Open {
            as_number: asn,
            holdtime: HoldTime::new(holdtime).unwrap(),
            router_id,
            capability: vec![Capability::MultiProtocol(Family::IPV4)],
        })
    }

    fn has_output<F: Fn(&Output) -> bool>(outputs: &[Output], pred: F) -> bool {
        outputs.iter().any(pred)
    }

    #[test]
    fn connected_sends_open_and_transitions_to_open_sent() {
        let mut s = basic_connection();
        assert_eq!(s.state(), State::Idle);

        let out = s.process(Input::Connected(false));
        assert_eq!(s.state(), State::OpenSent);
        assert!(has_output(&out, |o| matches!(
            o,
            Output::SendMessage(bgp::Message::Open(_))
        )));
        assert!(has_output(&out, |o| matches!(
            o,
            Output::StateChanged(State::OpenSent)
        )));
    }

    #[test]
    fn open_exchange_reaches_established() {
        let mut s = basic_connection();
        let _ = s.process(Input::Connected(false));
        assert_eq!(s.state(), State::OpenSent);

        // Receive remote OPEN
        let out = s.process(Input::MessageReceived(remote_open(
            65002,
            remote_router_id(),
            60,
        )));
        assert_eq!(s.state(), State::OpenConfirm);
        assert!(has_output(&out, |o| matches!(
            o,
            Output::SendMessage(bgp::Message::Keepalive)
        )));
        assert!(has_output(&out, |o| matches!(
            o,
            Output::ChannelsNegotiated(_)
        )));
        assert!(has_output(&out, |o| matches!(
            o,
            Output::SetKeepaliveTimer(20)
        ))); // min(90,60)/3
        assert!(has_output(&out, |o| matches!(o, Output::SetHoldTimer(60)))); // min(90,60)
        assert!(has_output(&out, |o| matches!(
            o,
            Output::StateChanged(State::OpenConfirm)
        )));

        // Receive KEEPALIVE -> Established
        let out = s.process(Input::MessageReceived(bgp::Message::Keepalive));
        assert_eq!(s.state(), State::Established);
        assert!(has_output(&out, |o| matches!(
            o,
            Output::SessionEstablished { .. }
        )));
        assert!(has_output(&out, |o| matches!(
            o,
            Output::StateChanged(State::Established)
        )));
    }

    #[test]
    fn session_established_carries_remote_peer_info() {
        let mut s = basic_connection();
        let _ = s.process(Input::Connected(false));
        let _ = s.process(Input::MessageReceived(remote_open(
            65002,
            remote_router_id(),
            60,
        )));
        let out = s.process(Input::MessageReceived(bgp::Message::Keepalive));
        let established = out.iter().find_map(|o| {
            if let Output::SessionEstablished {
                remote_asn,
                remote_id,
                remote_holdtime,
                ..
            } = o
            {
                Some((*remote_asn, *remote_id, *remote_holdtime))
            } else {
                None
            }
        });
        assert_eq!(established, Some((65002, remote_router_id(), 60)));
    }

    #[test]
    fn session_down_does_not_include_state_changed() {
        let mut s = basic_connection();
        let _ = s.process(Input::Connected(false));
        let _ = s.process(Input::MessageReceived(remote_open(
            65002,
            remote_router_id(),
            60,
        )));
        let _ = s.process(Input::MessageReceived(bgp::Message::Keepalive));
        assert_eq!(s.state(), State::Established);

        let out = s.process(Input::HoldTimerExpired);
        assert!(has_output(&out, |o| matches!(
            o,
            Output::SessionDown(SessionDownReason::HoldTimerExpired)
        )));
        assert!(!has_output(&out, |o| matches!(o, Output::StateChanged(_))));
    }

    #[test]
    fn admin_shutdown_sends_notification_and_session_down() {
        let mut s = basic_connection();
        let _ = s.process(Input::Connected(false));
        let _ = s.process(Input::MessageReceived(remote_open(
            65002,
            remote_router_id(),
            60,
        )));
        let _ = s.process(Input::MessageReceived(bgp::Message::Keepalive));
        assert_eq!(s.state(), State::Established);

        let out = s.process(Input::AdminShutdown);
        assert!(has_output(&out, |o| matches!(
            o,
            Output::SendMessage(bgp::Message::Notification(_))
        )));
        assert!(has_output(&out, |o| matches!(
            o,
            Output::SessionDown(SessionDownReason::AdminShutdown)
        )));
        assert!(!has_output(&out, |o| matches!(o, Output::StateChanged(_))));
    }

    #[test]
    fn disconnected_produces_session_down_io_error() {
        let mut s = basic_connection();
        let _ = s.process(Input::Connected(false));
        let _ = s.process(Input::MessageReceived(remote_open(
            65002,
            remote_router_id(),
            60,
        )));
        let _ = s.process(Input::MessageReceived(bgp::Message::Keepalive));
        assert_eq!(s.state(), State::Established);

        let out = s.process(Input::Disconnected);
        assert!(has_output(&out, |o| matches!(
            o,
            Output::SessionDown(SessionDownReason::IoError)
        )));
        assert!(!has_output(&out, |o| matches!(o, Output::StateChanged(_))));
    }

    #[test]
    fn asn_mismatch_sends_notification() {
        let mut s = basic_connection();
        let _ = s.process(Input::Connected(false));

        let out = s.process(Input::MessageReceived(remote_open(
            65099,
            remote_router_id(),
            60,
        )));
        assert!(has_output(&out, |o| matches!(
            o,
            Output::SendMessage(bgp::Message::Notification(_))
        )));
        assert!(has_output(&out, |o| matches!(o, Output::SessionDown(_))));
    }

    #[test]
    fn open_in_unexpected_state_sends_fsm_error() {
        let mut s = basic_connection();
        let _ = s.process(Input::Connected(false));
        let _ = s.process(Input::MessageReceived(remote_open(
            65002,
            remote_router_id(),
            60,
        )));
        let _ = s.process(Input::MessageReceived(bgp::Message::Keepalive));
        assert_eq!(s.state(), State::Established);

        // OPEN received in Established → FSM error
        let out = s.process(Input::MessageReceived(remote_open(
            65002,
            remote_router_id(),
            60,
        )));
        assert!(has_output(&out, |o| matches!(
            o,
            Output::SendMessage(bgp::Message::Notification(_))
        )));
        assert!(has_output(&out, |o| matches!(
            o,
            Output::SessionDown(SessionDownReason::FsmError)
        )));
    }

    #[test]
    fn dynamic_peer_accepts_any_asn() {
        let mut s = Connection::new(
            65001,
            local_router_id(),
            vec![Capability::MultiProtocol(Family::IPV4)],
            90,
            0, // accept any
            FnvHashMap::default(),
        );
        let _ = s.process(Input::Connected(false));

        let out = s.process(Input::MessageReceived(remote_open(
            65099,
            remote_router_id(),
            60,
        )));
        assert_eq!(s.state(), State::OpenConfirm);
        assert!(!has_output(&out, |o| matches!(o, Output::SessionDown(_))));
    }

    #[test]
    fn holdtime_negotiation_uses_minimum() {
        let mut s = basic_connection(); // local_holdtime = 90
        let _ = s.process(Input::Connected(false));

        let _ = s.process(Input::MessageReceived(remote_open(
            65002,
            remote_router_id(),
            30,
        )));
        assert_eq!(s.negotiated_holdtime(), 30);
    }

    #[test]
    fn holdtimer_expiry_shuts_down() {
        let mut s = basic_connection();
        let _ = s.process(Input::Connected(false));
        let _ = s.process(Input::MessageReceived(remote_open(
            65002,
            remote_router_id(),
            60,
        )));
        let _ = s.process(Input::MessageReceived(bgp::Message::Keepalive));
        assert_eq!(s.state(), State::Established);

        let out = s.process(Input::HoldTimerExpired);
        assert!(has_output(&out, |o| matches!(
            o,
            Output::SessionDown(SessionDownReason::HoldTimerExpired)
        )));
    }

    #[test]
    fn connected_starts_initial_hold_timer() {
        let mut s = basic_connection();
        let out = s.process(Input::Connected(false));
        assert!(has_output(&out, |o| matches!(
            o,
            Output::SetHoldTimer(INITIAL_HOLD_SECS)
        )));
    }

    #[test]
    fn hold_timer_expired_in_open_sent_shuts_down() {
        let mut s = basic_connection();
        let _ = s.process(Input::Connected(false));
        let out = s.process(Input::HoldTimerExpired);
        assert!(has_output(&out, |o| matches!(
            o,
            Output::SessionDown(SessionDownReason::HoldTimerExpired)
        )));
    }

    #[test]
    fn keepalive_timer_expired_sends_keepalive_and_rearms() {
        let mut s = basic_connection();
        let _ = s.process(Input::Connected(false));
        let _ = s.process(Input::MessageReceived(remote_open(
            65002,
            remote_router_id(),
            60,
        )));
        assert_eq!(s.state(), State::OpenConfirm);

        // RFC 4271 §8.2.2: keepalive timer fires in OpenConfirm → send KEEPALIVE + re-arm
        let out = s.process(Input::KeepaliveTimerExpired);
        assert!(has_output(&out, |o| matches!(
            o,
            Output::SendMessage(bgp::Message::Keepalive)
        )));
        assert!(has_output(&out, |o| matches!(
            o,
            Output::SetKeepaliveTimer(20)
        )));
    }

    #[test]
    fn keepalive_timer_expired_in_established_sends_keepalive_and_rearms() {
        let mut s = basic_connection();
        let _ = s.process(Input::Connected(false));
        let _ = s.process(Input::MessageReceived(remote_open(
            65002,
            remote_router_id(),
            60,
        )));
        let _ = s.process(Input::MessageReceived(bgp::Message::Keepalive));
        assert_eq!(s.state(), State::Established);

        // RFC 4271 §8.2.2: keepalive timer fires in Established → send KEEPALIVE + re-arm
        let out = s.process(Input::KeepaliveTimerExpired);
        assert!(has_output(&out, |o| matches!(
            o,
            Output::SendMessage(bgp::Message::Keepalive)
        )));
        assert!(has_output(&out, |o| matches!(
            o,
            Output::SetKeepaliveTimer(20)
        )));
        assert!(!has_output(&out, |o| matches!(o, Output::SessionDown(_))));
    }

    #[test]
    fn keepalive_timer_expired_in_idle_is_noop() {
        let mut s = basic_connection();
        assert_eq!(s.state(), State::Idle);

        // Timer fires before session is active → silently ignored
        let out = s.process(Input::KeepaliveTimerExpired);
        assert!(out.is_empty());
    }

    #[test]
    fn keepalive_in_established_resets_hold_timer() {
        let mut s = basic_connection();
        let _ = s.process(Input::Connected(false));
        let _ = s.process(Input::MessageReceived(remote_open(
            65002,
            remote_router_id(),
            60,
        )));
        let _ = s.process(Input::MessageReceived(bgp::Message::Keepalive));
        assert_eq!(s.state(), State::Established);

        // KEEPALIVE received → reset hold timer to full negotiated_holdtime
        let out = s.process(Input::MessageReceived(bgp::Message::Keepalive));
        assert!(has_output(&out, |o| matches!(o, Output::SetHoldTimer(60))));
        assert!(!has_output(&out, |o| matches!(o, Output::SessionDown(_))));
    }

    #[test]
    fn update_in_established_resets_hold_timer() {
        let mut s = basic_connection();
        let _ = s.process(Input::Connected(false));
        let _ = s.process(Input::MessageReceived(remote_open(
            65002,
            remote_router_id(),
            60,
        )));
        let _ = s.process(Input::MessageReceived(bgp::Message::Keepalive));
        assert_eq!(s.state(), State::Established);

        // UPDATE received → reset hold timer to full negotiated_holdtime
        let update = bgp::Message::Update(bgp::Update {
            reach: None,
            mp_reach: None,
            unreach: None,
            mp_unreach: None,
            attr: std::sync::Arc::new(Vec::new()),
            nexthop: None,
        });
        let out = s.process(Input::MessageReceived(update));
        assert!(has_output(&out, |o| matches!(o, Output::SetHoldTimer(60))));
        assert!(!has_output(&out, |o| matches!(o, Output::SessionDown(_))));
    }

    #[test]
    fn hold_timer_expired_in_idle_is_noop() {
        let mut s = basic_connection();
        assert_eq!(s.state(), State::Idle);

        // Timer fires before session is active → silently ignored
        let out = s.process(Input::HoldTimerExpired);
        assert!(out.is_empty());
    }

    #[test]
    fn keepalive_in_unexpected_state_sends_fsm_error() {
        let mut s = basic_connection();
        let _ = s.process(Input::Connected(false));
        // State is now OpenSent — KEEPALIVE before OPEN is an FSM error
        let out = s.process(Input::MessageReceived(bgp::Message::Keepalive));
        assert!(has_output(&out, |o| matches!(
            o,
            Output::SendMessage(bgp::Message::Notification(_))
        )));
        assert!(has_output(&out, |o| matches!(
            o,
            Output::SessionDown(SessionDownReason::FsmError)
        )));
    }

    #[test]
    fn route_refresh_in_established_triggers_readvertise() {
        let mut s = basic_connection();
        let _ = s.process(Input::Connected(false));
        let _ = s.process(Input::MessageReceived(remote_open(
            65002,
            remote_router_id(),
            60,
        )));
        let _ = s.process(Input::MessageReceived(bgp::Message::Keepalive));
        assert_eq!(s.state(), State::Established);

        let out = s.process(Input::MessageReceived(bgp::Message::RouteRefresh {
            family: Family::IPV4,
        }));
        assert!(has_output(&out, |o| matches!(
            o,
            Output::RouteRefresh(Family::IPV4)
        )));
        assert!(!has_output(&out, |o| matches!(o, Output::SessionDown(_))));
    }

    #[test]
    fn route_refresh_in_non_established_sends_fsm_error() {
        let mut s = basic_connection();
        let _ = s.process(Input::Connected(false));
        // State is OpenSent
        let out = s.process(Input::MessageReceived(bgp::Message::RouteRefresh {
            family: Family::IPV4,
        }));
        assert!(has_output(&out, |o| matches!(
            o,
            Output::SendMessage(bgp::Message::Notification(_))
        )));
        assert!(has_output(&out, |o| matches!(
            o,
            Output::SessionDown(SessionDownReason::FsmError)
        )));
    }

    #[test]
    fn notification_received_shuts_down() {
        let mut s = basic_connection();
        let _ = s.process(Input::Connected(false));

        let notif = bgp::Message::Notification(rustybgp_packet::BgpError::Other {
            code: 6,
            subcode: 4,
            data: vec![],
        });
        let out = s.process(Input::MessageReceived(notif));
        assert!(has_output(&out, |o| matches!(
            o,
            Output::SessionDown(SessionDownReason::RemoteNotification(_))
        )));
    }

    #[test]
    fn update_in_non_established_shuts_down() {
        let mut s = basic_connection();
        let _ = s.process(Input::Connected(false));
        assert_eq!(s.state(), State::OpenSent);

        let update = bgp::Message::Update(bgp::Update {
            reach: None,
            mp_reach: None,
            unreach: None,
            mp_unreach: None,
            attr: std::sync::Arc::new(Vec::new()),
            nexthop: None,
        });
        let out = s.process(Input::MessageReceived(update));
        assert!(has_output(&out, |o| matches!(o, Output::SessionDown(_))));
    }

    #[test]
    fn update_sent_in_established_resets_keepalive_timer() {
        let mut s = basic_connection();
        let _ = s.process(Input::Connected(false));
        let _ = s.process(Input::MessageReceived(remote_open(
            65002,
            remote_router_id(),
            60,
        )));
        let _ = s.process(Input::MessageReceived(bgp::Message::Keepalive));
        assert_eq!(s.state(), State::Established);

        let out = s.process(Input::UpdateSent);
        assert!(has_output(&out, |o| matches!(
            o,
            Output::SetKeepaliveTimer(20)
        )));
    }

    #[test]
    fn update_sent_in_non_established_is_noop() {
        let mut s = basic_connection();
        let _ = s.process(Input::Connected(false));
        assert_eq!(s.state(), State::OpenSent);

        let out = s.process(Input::UpdateSent);
        assert!(out.is_empty());
    }

    #[test]
    fn admin_shutdown_sends_cease() {
        let mut s = basic_connection();
        let _ = s.process(Input::Connected(false));

        let out = s.process(Input::AdminShutdown);
        assert!(has_output(&out, |o| matches!(
            o,
            Output::SendMessage(bgp::Message::Notification(_))
        )));
        assert!(has_output(&out, |o| matches!(
            o,
            Output::SessionDown(SessionDownReason::AdminShutdown)
        )));
    }

    #[test]
    fn zero_holdtime_disables_timers() {
        let mut s = Connection::new(
            65001,
            local_router_id(),
            vec![Capability::MultiProtocol(Family::IPV4)],
            0, // disabled holdtime
            65002,
            FnvHashMap::default(),
        );
        let _ = s.process(Input::Connected(false));

        let out = s.process(Input::MessageReceived(remote_open(
            65002,
            remote_router_id(),
            60,
        )));
        assert_eq!(s.negotiated_holdtime(), 0);
        assert!(!has_output(&out, |o| matches!(
            o,
            Output::SetKeepaliveTimer(_)
        )));
        assert!(!has_output(&out, |o| matches!(o, Output::SetHoldTimer(_))));
    }

    // --- PeerFsm tests ---

    fn make_peer_fsm(local_id: u32, expected_asn: u32) -> PeerFsm {
        PeerFsm::new(
            local_id,
            65001,
            vec![Capability::MultiProtocol(Family::IPV4)],
            90,
            expected_asn,
            FnvHashMap::default(),
        )
    }

    fn connect(peer: &mut PeerFsm, role: Role) -> Vec<PeerFsmOutput> {
        peer.process(role, Input::Connected(false))
    }

    fn remote_open_msg(asn: u32, router_id: u32) -> bgp::Message {
        bgp::Message::Open(bgp::Open {
            as_number: asn,
            holdtime: HoldTime::new(60).unwrap(),
            router_id,
            capability: vec![Capability::MultiProtocol(Family::IPV4)],
        })
    }

    fn has_peer_output<F: Fn(&PeerFsmOutput) -> bool>(outputs: &[PeerFsmOutput], pred: F) -> bool {
        outputs.iter().any(pred)
    }

    #[test]
    fn peer_fsm_single_active_reaches_established() {
        let mut peer = make_peer_fsm(local_router_id(), 65002);
        connect(&mut peer, Role::Active);

        let out = peer.process(
            Role::Active,
            Input::MessageReceived(remote_open_msg(65002, remote_router_id())),
        );
        assert_eq!(
            peer.connection(Role::Active).unwrap().state(),
            State::OpenConfirm
        );
        assert!(!has_peer_output(&out, |o| matches!(
            o,
            PeerFsmOutput::CloseConnection
        )));

        let out = peer.process(
            Role::Active,
            Input::MessageReceived(bgp::Message::Keepalive),
        );
        assert_eq!(
            peer.connection(Role::Active).unwrap().state(),
            State::Established
        );
        assert!(!has_peer_output(&out, |o| matches!(
            o,
            PeerFsmOutput::CloseConnection
        )));
    }

    #[test]
    fn peer_fsm_single_passive_reaches_established() {
        let mut peer = make_peer_fsm(local_router_id(), 65002);
        connect(&mut peer, Role::Passive);

        peer.process(
            Role::Passive,
            Input::MessageReceived(remote_open_msg(65002, remote_router_id())),
        );
        peer.process(
            Role::Passive,
            Input::MessageReceived(bgp::Message::Keepalive),
        );
        assert_eq!(
            peer.connection(Role::Passive).unwrap().state(),
            State::Established
        );
    }

    #[test]
    fn peer_fsm_passive_open_confirm_emits_stop_active_connect() {
        let mut peer = make_peer_fsm(local_router_id(), 65002);
        connect(&mut peer, Role::Passive);

        // Passive receives OPEN → enters OpenConfirm → StopActiveConnect emitted
        let out = peer.process(
            Role::Passive,
            Input::MessageReceived(remote_open_msg(65002, remote_router_id())),
        );
        assert_eq!(
            peer.connection(Role::Passive).unwrap().state(),
            State::OpenConfirm
        );
        assert!(has_peer_output(&out, |o| matches!(
            o,
            PeerFsmOutput::StopActiveConnect
        )));
    }

    #[test]
    fn peer_fsm_active_open_confirm_does_not_emit_stop_active_connect() {
        let mut peer = make_peer_fsm(local_router_id(), 65002);
        connect(&mut peer, Role::Active);

        // Active receives OPEN → enters OpenConfirm → StopActiveConnect NOT emitted
        let out = peer.process(
            Role::Active,
            Input::MessageReceived(remote_open_msg(65002, remote_router_id())),
        );
        assert_eq!(
            peer.connection(Role::Active).unwrap().state(),
            State::OpenConfirm
        );
        assert!(!has_peer_output(&out, |o| matches!(
            o,
            PeerFsmOutput::StopActiveConnect
        )));
    }

    #[test]
    fn peer_fsm_no_collision_when_only_one_in_open_confirm() {
        let high_id = u32::from(Ipv4Addr::new(10, 0, 0, 1));
        let low_id = u32::from(Ipv4Addr::new(1, 0, 0, 1));

        let mut peer = make_peer_fsm(high_id, 65001);
        connect(&mut peer, Role::Active);
        connect(&mut peer, Role::Passive);

        // Active receives OPEN → OpenConfirm, passive still in OpenSent → no collision
        let out = peer.process(
            Role::Active,
            Input::MessageReceived(remote_open_msg(65001, low_id)),
        );
        assert!(!has_peer_output(&out, |o| matches!(
            o,
            PeerFsmOutput::CloseConnection
        )));
        assert!(peer.connection(Role::Active).is_some());
        assert!(peer.connection(Role::Passive).is_some());
    }

    #[test]
    fn peer_fsm_collision_active_wins_when_local_id_higher() {
        let high_id = u32::from(Ipv4Addr::new(10, 0, 0, 1));
        let low_id = u32::from(Ipv4Addr::new(1, 0, 0, 1));

        let mut peer = make_peer_fsm(high_id, 65001);
        connect(&mut peer, Role::Active);
        connect(&mut peer, Role::Passive);

        // Active → OpenConfirm
        peer.process(
            Role::Active,
            Input::MessageReceived(remote_open_msg(65001, low_id)),
        );

        // Passive → OpenConfirm → collision detected
        let out = peer.process(
            Role::Passive,
            Input::MessageReceived(remote_open_msg(65001, low_id)),
        );

        // local_id > remote_id → active wins → passive gets CEASE and is removed
        assert!(has_peer_output(&out, |o| matches!(
            o,
            PeerFsmOutput::Connection(Role::Passive, Output::SendMessage(_))
        )));
        assert!(peer.connection(Role::Active).is_some());
        assert!(peer.connection(Role::Passive).is_none());
    }

    #[test]
    fn peer_fsm_collision_passive_wins_when_local_id_lower() {
        let high_id = u32::from(Ipv4Addr::new(10, 0, 0, 1));
        let low_id = u32::from(Ipv4Addr::new(1, 0, 0, 1));

        let mut peer = make_peer_fsm(low_id, 65001);
        connect(&mut peer, Role::Active);
        connect(&mut peer, Role::Passive);

        // Active → OpenConfirm
        peer.process(
            Role::Active,
            Input::MessageReceived(remote_open_msg(65001, high_id)),
        );

        // Passive → OpenConfirm → collision detected
        let out = peer.process(
            Role::Passive,
            Input::MessageReceived(remote_open_msg(65001, high_id)),
        );

        // local_id < remote_id → passive wins → active gets CEASE and is removed
        assert!(has_peer_output(&out, |o| matches!(
            o,
            PeerFsmOutput::Connection(Role::Active, Output::SendMessage(_))
        )));
        assert!(peer.connection(Role::Active).is_none());
        assert!(peer.connection(Role::Passive).is_some());
    }

    #[test]
    fn peer_fsm_collision_when_one_already_established() {
        let high_id = u32::from(Ipv4Addr::new(10, 0, 0, 1));
        let low_id = u32::from(Ipv4Addr::new(1, 0, 0, 1));

        let mut peer = make_peer_fsm(high_id, 65001);
        connect(&mut peer, Role::Active);

        // Active reaches Established
        peer.process(
            Role::Active,
            Input::MessageReceived(remote_open_msg(65001, low_id)),
        );
        peer.process(
            Role::Active,
            Input::MessageReceived(bgp::Message::Keepalive),
        );
        assert_eq!(
            peer.connection(Role::Active).unwrap().state(),
            State::Established
        );

        // Passive connects and receives OPEN → OpenConfirm → collision with Established
        connect(&mut peer, Role::Passive);
        let out = peer.process(
            Role::Passive,
            Input::MessageReceived(remote_open_msg(65001, low_id)),
        );

        // local_id > remote_id, active wins → passive gets CEASE and is removed
        assert!(has_peer_output(&out, |o| matches!(
            o,
            PeerFsmOutput::Connection(Role::Passive, Output::SendMessage(_))
        )));
        assert!(peer.connection(Role::Active).is_some());
        assert!(peer.connection(Role::Passive).is_none());
    }

    #[test]
    fn peer_fsm_winner_continues_after_collision() {
        let high_id = u32::from(Ipv4Addr::new(10, 0, 0, 1));
        let low_id = u32::from(Ipv4Addr::new(1, 0, 0, 1));

        let mut peer = make_peer_fsm(high_id, 65001);
        connect(&mut peer, Role::Active);
        connect(&mut peer, Role::Passive);

        // Both reach OpenConfirm → passive closed
        peer.process(
            Role::Active,
            Input::MessageReceived(remote_open_msg(65001, low_id)),
        );
        peer.process(
            Role::Passive,
            Input::MessageReceived(remote_open_msg(65001, low_id)),
        );
        assert!(peer.connection(Role::Passive).is_none());

        // Active continues to Established
        let out = peer.process(
            Role::Active,
            Input::MessageReceived(bgp::Message::Keepalive),
        );
        assert_eq!(
            peer.connection(Role::Active).unwrap().state(),
            State::Established
        );
        assert!(has_peer_output(&out, |o| matches!(
            o,
            PeerFsmOutput::Connection(Role::Active, Output::SessionEstablished { .. })
        )));
    }

    #[test]
    fn peer_fsm_collision_triggered_when_active_enters_open_confirm_second() {
        // Passive reaches OpenConfirm first; collision is triggered when Active
        // subsequently enters OpenConfirm (the reverse order from the other tests).
        let high_id = u32::from(Ipv4Addr::new(10, 0, 0, 1));
        let low_id = u32::from(Ipv4Addr::new(1, 0, 0, 1));

        let mut peer = make_peer_fsm(high_id, 65001);
        connect(&mut peer, Role::Active);
        connect(&mut peer, Role::Passive);

        // Passive → OpenConfirm first; Active still in OpenSent → no collision yet
        let out = peer.process(
            Role::Passive,
            Input::MessageReceived(remote_open_msg(65001, low_id)),
        );
        assert!(!has_peer_output(&out, |o| matches!(
            o,
            PeerFsmOutput::Connection(Role::Active, Output::SendMessage(_))
        )));
        assert_eq!(
            peer.connection(Role::Passive).unwrap().state(),
            State::OpenConfirm
        );

        // Active → OpenConfirm second → collision detected, local_id > remote_id → active wins
        let out = peer.process(
            Role::Active,
            Input::MessageReceived(remote_open_msg(65001, low_id)),
        );
        assert!(has_peer_output(&out, |o| matches!(
            o,
            PeerFsmOutput::Connection(Role::Passive, Output::SendMessage(_))
        )));
        assert!(peer.connection(Role::Active).is_some());
        assert!(peer.connection(Role::Passive).is_none());
    }

    #[test]
    fn peer_fsm_duplicate_role_rejected() {
        let mut peer = make_peer_fsm(local_router_id(), 65002);
        let out = connect(&mut peer, Role::Active);
        assert!(!has_peer_output(&out, |o| matches!(
            o,
            PeerFsmOutput::CloseConnection
        )));
        // Second Connected on same role → CloseConnection returned
        let out = connect(&mut peer, Role::Active);
        assert!(has_peer_output(&out, |o| matches!(
            o,
            PeerFsmOutput::CloseConnection
        )));
    }

    #[test]
    fn peer_fsm_cease_notification_sent_to_loser() {
        let high_id = u32::from(Ipv4Addr::new(10, 0, 0, 1));
        let low_id = u32::from(Ipv4Addr::new(1, 0, 0, 1));

        let mut peer = make_peer_fsm(high_id, 65001);
        connect(&mut peer, Role::Active);
        connect(&mut peer, Role::Passive);

        peer.process(
            Role::Active,
            Input::MessageReceived(remote_open_msg(65001, low_id)),
        );
        let out = peer.process(
            Role::Passive,
            Input::MessageReceived(remote_open_msg(65001, low_id)),
        );

        // CEASE notification (code 6, subcode 7) sent to the loser (passive)
        assert!(has_peer_output(&out, |o| matches!(
            o,
            PeerFsmOutput::Connection(
                Role::Passive,
                Output::SendMessage(bgp::Message::Notification(_))
            )
        )));
    }

    fn reach_established(peer: &mut PeerFsm, role: Role) {
        connect(peer, role);
        peer.process(
            role,
            Input::MessageReceived(remote_open_msg(65002, remote_router_id())),
        );
        peer.process(role, Input::MessageReceived(bgp::Message::Keepalive));
        assert_eq!(peer.connection(role).unwrap().state(), State::Established);
    }

    // After Input::Disconnected the slot is cleared and reconnect succeeds.
    #[test]
    fn disconnected_clears_slot_and_allows_reconnect() {
        let mut peer = make_peer_fsm(local_router_id(), 65002);
        reach_established(&mut peer, Role::Active);

        let out = peer.process(Role::Active, Input::Disconnected);
        assert!(has_peer_output(&out, |o| matches!(
            o,
            PeerFsmOutput::Connection(
                Role::Active,
                Output::SessionDown(SessionDownReason::IoError)
            )
        )));
        assert!(peer.connection(Role::Active).is_none());

        // Reconnect succeeds: OPEN is sent, no CloseConnection.
        let out = peer.process(Role::Active, Input::Connected(false));
        assert!(!has_peer_output(&out, |o| matches!(
            o,
            PeerFsmOutput::CloseConnection
        )));
        assert!(has_peer_output(&out, |o| matches!(
            o,
            PeerFsmOutput::Connection(Role::Active, Output::SendMessage(bgp::Message::Open(_)))
        )));
    }

    // PeerFsm::process() appends StateChanged(Idle) whenever session_down is true,
    // so the driver always sees a paired SessionDown + StateChanged(Idle).
    #[test]
    fn peer_fsm_session_down_emits_state_changed_idle() {
        let mut peer = make_peer_fsm(local_router_id(), 65002);
        reach_established(&mut peer, Role::Active);

        let out = peer.process(Role::Active, Input::Disconnected);
        assert!(has_peer_output(&out, |o| matches!(
            o,
            PeerFsmOutput::Connection(
                Role::Active,
                Output::SessionDown(SessionDownReason::IoError)
            )
        )));
        assert!(has_peer_output(&out, |o| matches!(
            o,
            PeerFsmOutput::Connection(Role::Active, Output::StateChanged(State::Idle))
        )));

        // StateChanged(Idle) must come after SessionDown in the output vec.
        let session_down_pos = out.iter().position(|o| {
            matches!(
                o,
                PeerFsmOutput::Connection(
                    Role::Active,
                    Output::SessionDown(SessionDownReason::IoError)
                )
            )
        });
        let state_changed_pos = out.iter().position(|o| {
            matches!(
                o,
                PeerFsmOutput::Connection(Role::Active, Output::StateChanged(State::Idle))
            )
        });
        assert!(session_down_pos < state_changed_pos);
    }

    #[test]
    fn peer_fsm_admin_shutdown_emits_state_changed_idle() {
        let mut peer = make_peer_fsm(local_router_id(), 65002);
        reach_established(&mut peer, Role::Active);

        let out = peer.process(Role::Active, Input::AdminShutdown);
        assert!(has_peer_output(&out, |o| matches!(
            o,
            PeerFsmOutput::Connection(
                Role::Active,
                Output::SessionDown(SessionDownReason::AdminShutdown)
            )
        )));
        assert!(has_peer_output(&out, |o| matches!(
            o,
            PeerFsmOutput::Connection(Role::Active, Output::StateChanged(State::Idle))
        )));
    }
}
