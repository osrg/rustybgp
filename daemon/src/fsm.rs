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

/// BGP session states (RFC 4271 §8.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
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

/// Events fed into the session FSM.
#[allow(dead_code)]
pub(crate) enum Input {
    /// TCP connection established; start the OPEN exchange.
    Connected,
    /// A complete BGP message was received from the peer.
    MessageReceived(bgp::Message),
    /// The keepalive timer fired.
    KeepaliveTick,
    /// The hold timer check: driver supplies elapsed seconds since last
    /// keepalive/update was received.
    HoldTimerCheck { elapsed_secs: u64 },
    /// Administrative shutdown (e.g., peer deconfigured).
    AdminShutdown,
}

/// Actions the I/O driver should perform.
pub(crate) enum Output {
    /// Send a BGP message on the wire.
    SendMessage(bgp::Message),
    /// Configure the keepalive timer interval (seconds; 0 = disable).
    SetKeepaliveInterval(u64),
    /// Configure the hold timer (seconds; 0 = disable).
    SetHoldTimer(u64),
    /// Renew the hold timer (peer sent keepalive or update).
    RenewHoldTimer,
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
}

/// Reason the session is going down.
#[derive(Clone)]
#[allow(dead_code)]
pub(crate) enum SessionDownReason {
    HoldTimerExpired,
    RemoteNotification(bgp::Message),
    FsmError(State),
    AdminShutdown,
}

/// Pure BGP session state machine.
///
/// Holds all negotiation state for a single BGP connection. Has no I/O
/// dependencies — processes [`Input`] events and returns [`Output`] actions.
pub(crate) struct Session {
    state: State,
    local_asn: u32,
    local_router_id: u32,
    local_holdtime: u64,
    local_cap: Vec<Capability>,
    expected_remote_asn: u32,
    #[allow(dead_code)] // Used in collision detection (future PR)
    is_active: bool,

    // Populated after OPEN received
    remote_asn: u32,
    remote_id: u32,
    remote_holdtime: u16,
    remote_cap: Vec<Capability>,
    negotiated_holdtime: u64,

    // send_max retained after capability negotiation
    send_max: FnvHashMap<Family, usize>,
}

impl Session {
    pub(crate) fn new(
        local_asn: u32,
        local_router_id: u32,
        local_cap: Vec<Capability>,
        local_holdtime: u64,
        expected_remote_asn: u32,
        is_active: bool,
        send_max: FnvHashMap<Family, usize>,
    ) -> Self {
        Session {
            state: State::Idle,
            local_asn,
            local_router_id,
            local_holdtime,
            local_cap,
            expected_remote_asn,
            is_active,
            remote_asn: 0,
            remote_id: 0,
            remote_holdtime: 0,
            remote_cap: Vec::new(),
            negotiated_holdtime: 0,
            send_max,
        }
    }

    #[cfg(test)]
    pub(crate) fn state(&self) -> State {
        self.state
    }

    pub(crate) fn negotiated_holdtime(&self) -> u64 {
        self.negotiated_holdtime
    }

    pub(crate) fn send_max(&self) -> &FnvHashMap<Family, usize> {
        &self.send_max
    }

    /// RFC 4271 §6.8: returns true if THIS connection should be kept
    /// when a collision is detected with the other connection.
    #[allow(dead_code)] // Used in collision detection (future PR)
    pub(crate) fn wins_collision(&self) -> bool {
        if self.local_router_id > self.remote_id {
            self.is_active
        } else {
            !self.is_active
        }
    }

    /// Process an input event and return actions for the I/O driver.
    pub(crate) fn process(&mut self, input: Input) -> Vec<Output> {
        match input {
            Input::Connected => self.on_connected(),
            Input::MessageReceived(msg) => self.on_message(msg),
            Input::KeepaliveTick => self.on_keepalive_tick(),
            Input::HoldTimerCheck { elapsed_secs } => self.on_hold_timer_check(elapsed_secs),
            Input::AdminShutdown => self.on_admin_shutdown(),
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
        vec![
            Output::SendMessage(open),
            Output::StateChanged(State::OpenSent),
        ]
    }

    fn on_message(&mut self, msg: bgp::Message) -> Vec<Output> {
        match msg {
            bgp::Message::Open(open) => self.on_open(open),
            bgp::Message::Keepalive => self.on_keepalive(),
            bgp::Message::Update(_) => self.on_update(),
            bgp::Message::Notification(err) => self.on_notification(err),
            bgp::Message::RouteRefresh { .. } => Vec::new(),
        }
    }

    fn on_open(&mut self, open: bgp::Open) -> Vec<Output> {
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
            let keepalive_interval = self.negotiated_holdtime / 3;
            out.push(Output::SetKeepaliveInterval(keepalive_interval));
            out.push(Output::SetHoldTimer(self.negotiated_holdtime));
        }

        // Transition to OpenConfirm
        self.state = State::OpenConfirm;
        out.push(Output::StateChanged(State::OpenConfirm));

        out
    }

    fn on_keepalive(&mut self) -> Vec<Output> {
        let mut out = vec![Output::RenewHoldTimer];
        if self.state == State::OpenConfirm {
            self.state = State::Established;
            out.push(Output::StateChanged(State::Established));
            out.push(Output::SessionEstablished {
                remote_asn: self.remote_asn,
                remote_id: self.remote_id,
                remote_holdtime: self.remote_holdtime,
                remote_capabilities: std::mem::take(&mut self.remote_cap),
            });
        }
        out
    }

    fn on_update(&mut self) -> Vec<Output> {
        if self.state != State::Established {
            return vec![
                Output::SendMessage(bgp::Message::Notification(
                    rustybgp_packet::BgpError::FsmUnexpectedState {
                        state: u8::from(self.state),
                    },
                )),
                Output::SessionDown(SessionDownReason::FsmError(self.state)),
            ];
        }
        vec![Output::RenewHoldTimer]
    }

    fn on_notification(&mut self, err: rustybgp_packet::BgpError) -> Vec<Output> {
        vec![Output::SessionDown(SessionDownReason::RemoteNotification(
            bgp::Message::Notification(err),
        ))]
    }

    fn on_keepalive_tick(&mut self) -> Vec<Output> {
        if self.state == State::Established {
            vec![Output::SendMessage(bgp::Message::Keepalive)]
        } else {
            Vec::new()
        }
    }

    fn on_hold_timer_check(&mut self, elapsed_secs: u64) -> Vec<Output> {
        if self.negotiated_holdtime != 0 && elapsed_secs > self.negotiated_holdtime + 20 {
            vec![Output::SessionDown(SessionDownReason::HoldTimerExpired)]
        } else {
            Vec::new()
        }
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

    fn basic_session() -> Session {
        Session::new(
            65001,
            local_router_id(),
            vec![Capability::MultiProtocol(Family::IPV4)],
            90,
            65002,
            false,
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
        let mut s = basic_session();
        assert_eq!(s.state(), State::Idle);

        let out = s.process(Input::Connected);
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
        let mut s = basic_session();
        let _ = s.process(Input::Connected);
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
            Output::SetKeepaliveInterval(20)
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
            Output::StateChanged(State::Established)
        )));
        assert!(has_output(&out, |o| matches!(
            o,
            Output::SessionEstablished { .. }
        )));
        assert!(has_output(&out, |o| matches!(o, Output::RenewHoldTimer)));
    }

    #[test]
    fn asn_mismatch_sends_notification() {
        let mut s = basic_session();
        let _ = s.process(Input::Connected);

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
    fn dynamic_peer_accepts_any_asn() {
        let mut s = Session::new(
            65001,
            local_router_id(),
            vec![Capability::MultiProtocol(Family::IPV4)],
            90,
            0, // accept any
            false,
            FnvHashMap::default(),
        );
        let _ = s.process(Input::Connected);

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
        let mut s = basic_session(); // local_holdtime = 90
        let _ = s.process(Input::Connected);

        let _ = s.process(Input::MessageReceived(remote_open(
            65002,
            remote_router_id(),
            30,
        )));
        assert_eq!(s.negotiated_holdtime(), 30);
    }

    #[test]
    fn holdtimer_expiry_shuts_down() {
        let mut s = basic_session();
        let _ = s.process(Input::Connected);
        let _ = s.process(Input::MessageReceived(remote_open(
            65002,
            remote_router_id(),
            60,
        )));
        let _ = s.process(Input::MessageReceived(bgp::Message::Keepalive));
        assert_eq!(s.state(), State::Established);

        // Within tolerance
        let out = s.process(Input::HoldTimerCheck { elapsed_secs: 70 });
        assert!(!has_output(&out, |o| matches!(o, Output::SessionDown(_))));

        // Expired (> negotiated + 20)
        let out = s.process(Input::HoldTimerCheck { elapsed_secs: 81 });
        assert!(has_output(&out, |o| matches!(
            o,
            Output::SessionDown(SessionDownReason::HoldTimerExpired)
        )));
    }

    #[test]
    fn keepalive_tick_only_in_established() {
        let mut s = basic_session();
        let _ = s.process(Input::Connected);

        // OpenSent: no keepalive
        let out = s.process(Input::KeepaliveTick);
        assert!(!has_output(&out, |o| matches!(
            o,
            Output::SendMessage(bgp::Message::Keepalive)
        )));

        let _ = s.process(Input::MessageReceived(remote_open(
            65002,
            remote_router_id(),
            60,
        )));
        let _ = s.process(Input::MessageReceived(bgp::Message::Keepalive));
        assert_eq!(s.state(), State::Established);

        // Established: send keepalive
        let out = s.process(Input::KeepaliveTick);
        assert!(has_output(&out, |o| matches!(
            o,
            Output::SendMessage(bgp::Message::Keepalive)
        )));
    }

    #[test]
    fn notification_received_shuts_down() {
        let mut s = basic_session();
        let _ = s.process(Input::Connected);

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
        let mut s = basic_session();
        let _ = s.process(Input::Connected);
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
    fn collision_active_wins_when_local_id_higher() {
        let high_id = u32::from(Ipv4Addr::new(10, 0, 0, 1));
        let low_id = u32::from(Ipv4Addr::new(1, 0, 0, 1));

        let mut active = Session::new(
            65001,
            high_id,
            vec![],
            90,
            65001,
            true,
            FnvHashMap::default(),
        );
        let _ = active.process(Input::Connected);
        let _ = active.process(Input::MessageReceived(bgp::Message::Open(bgp::Open {
            as_number: 65001,
            holdtime: HoldTime::new(60).unwrap(),
            router_id: low_id,
            capability: vec![],
        })));
        assert!(active.wins_collision());

        let mut passive = Session::new(
            65001,
            high_id,
            vec![],
            90,
            65001,
            false,
            FnvHashMap::default(),
        );
        let _ = passive.process(Input::Connected);
        let _ = passive.process(Input::MessageReceived(bgp::Message::Open(bgp::Open {
            as_number: 65001,
            holdtime: HoldTime::new(60).unwrap(),
            router_id: low_id,
            capability: vec![],
        })));
        assert!(!passive.wins_collision());
    }

    #[test]
    fn collision_passive_wins_when_local_id_lower() {
        let high_id = u32::from(Ipv4Addr::new(10, 0, 0, 1));
        let low_id = u32::from(Ipv4Addr::new(1, 0, 0, 1));

        let mut passive = Session::new(
            65001,
            low_id,
            vec![],
            90,
            65001,
            false,
            FnvHashMap::default(),
        );
        let _ = passive.process(Input::Connected);
        let _ = passive.process(Input::MessageReceived(bgp::Message::Open(bgp::Open {
            as_number: 65001,
            holdtime: HoldTime::new(60).unwrap(),
            router_id: high_id,
            capability: vec![],
        })));
        assert!(passive.wins_collision());

        let mut active = Session::new(
            65001,
            low_id,
            vec![],
            90,
            65001,
            true,
            FnvHashMap::default(),
        );
        let _ = active.process(Input::Connected);
        let _ = active.process(Input::MessageReceived(bgp::Message::Open(bgp::Open {
            as_number: 65001,
            holdtime: HoldTime::new(60).unwrap(),
            router_id: high_id,
            capability: vec![],
        })));
        assert!(!active.wins_collision());
    }

    #[test]
    fn admin_shutdown_sends_cease() {
        let mut s = basic_session();
        let _ = s.process(Input::Connected);

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
        let mut s = Session::new(
            65001,
            local_router_id(),
            vec![Capability::MultiProtocol(Family::IPV4)],
            0, // disabled holdtime
            65002,
            false,
            FnvHashMap::default(),
        );
        let _ = s.process(Input::Connected);

        let out = s.process(Input::MessageReceived(remote_open(
            65002,
            remote_router_id(),
            60,
        )));
        assert_eq!(s.negotiated_holdtime(), 0);
        assert!(!has_output(&out, |o| matches!(
            o,
            Output::SetKeepaliveInterval(_)
        )));
        assert!(!has_output(&out, |o| matches!(o, Output::SetHoldTimer(_))));
    }
}
