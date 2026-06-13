//! Kernel FIB integration via Linux Netlink.
//!
//! # Types
//!
//! Three types cover the two traffic directions:
//!
//! **Kernel → BGP (notification)**
//! - [`KernelRouteEvent`] — async route-change notification produced by the
//!   Netlink multicast subscription in [`Handle::with_route_monitor`].
//!   Delivered spontaneously whenever any process changes the kernel FIB.
//! - [`KernelRoute`] — a single route entry carried inside a
//!   [`KernelRouteEvent`], also returned by point queries such as
//!   `RTM_GETROUTE` (used by nexthop tracking).
//!
//! **BGP → Kernel (command)**
//! - [`KernelRouteChange`] — instruction to install or withdraw a BGP route,
//!   consumed by [`Handle::apply`].  Empty `nexthops` means withdraw;
//!   multiple nexthops install via `RTA_MULTIPATH` (ECMP).

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rustybgp_packet as packet;

use futures::StreamExt;
#[cfg(test)]
use futures::stream::TryStreamExt;
use rtnetlink::packet_core::NetlinkPayload;
use rtnetlink::packet_route::route::RouteMessage;
use rtnetlink::packet_route::route::{RouteAddress, RouteAttribute, RouteFlags, RouteProtocol};
use rtnetlink::packet_route::{AddressFamily, RouteNetlinkMessage};
use rtnetlink::{MulticastGroup, RouteMessageBuilder, RouteNextHopBuilder};

pub use rtnetlink::packet_route::route::RouteProtocol as Protocol;

/// A route change to be applied to the kernel FIB.
///
/// `nexthops` empty means withdraw; non-empty installs (multipath when >1).
pub struct KernelRouteChange {
    pub net: packet::Nlri,
    pub nexthops: Vec<packet::bgp::Nexthop>,
}

/// Convert a GoBGP-style route type string to a `Protocol` value.
///
/// Accepted strings (case-insensitive): "connect", "static", "ospf", "isis",
/// "rip", "eigrp", "bgp", "babel", "zebra".  Returns `None` for unknown types.
pub fn route_type_to_protocol(s: &str) -> Option<Protocol> {
    match s.to_ascii_lowercase().as_str() {
        "connect" => Some(Protocol::Kernel),
        "static" => Some(Protocol::Static),
        "ospf" => Some(Protocol::Ospf),
        "isis" => Some(Protocol::Isis),
        "rip" => Some(Protocol::Rip),
        "eigrp" => Some(Protocol::Eigrp),
        "bgp" => Some(Protocol::Bgp),
        "babel" => Some(Protocol::Babel),
        "zebra" => Some(Protocol::Zebra),
        _ => None,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("netlink: {0}")]
    Rtnetlink(#[from] rtnetlink::Error),
    #[error("mismatched address families for dst and nexthop")]
    FamilyMismatch,
}

/// A route change event from the kernel.
#[derive(Debug, Clone)]
pub enum KernelRouteEvent {
    Add(KernelRoute),
    Delete(KernelRoute),
}

/// A route entry read from the kernel.
#[derive(Debug, Clone)]
pub struct KernelRoute {
    pub dst: IpAddr,
    pub prefix_len: u8,
    pub nexthop: Option<IpAddr>,
    pub metric: u32,
    pub protocol: RouteProtocol,
}

struct Handle {
    inner: rtnetlink::Handle,
}

impl Handle {
    /// Open a netlink connection.
    ///
    /// The returned future must be spawned with `tokio::spawn` to drive the
    /// netlink socket I/O.
    #[cfg(test)]
    fn new() -> Result<(Self, impl Future<Output = ()>), Error> {
        let (connection, handle, _) = rtnetlink::new_connection()?;
        Ok((Self { inner: handle }, connection))
    }

    /// Open a netlink connection with route monitoring.
    ///
    /// Subscribes to IPv4/IPv6 route multicast groups and returns a stream
    /// of `KernelRouteEvent`s for all route changes (including those made by other
    /// processes).
    ///
    /// Typical startup sequence:
    /// 1. Call `with_route_monitor()` to start listening (no events lost)
    /// 2. Call `dump_bgp_routes()` to get current state
    /// 3. Process events from the stream for ongoing changes
    fn with_route_monitor() -> Result<
        (
            Self,
            impl Future<Output = ()>,
            impl futures::Stream<Item = KernelRouteEvent>,
        ),
        Error,
    > {
        let (connection, handle, messages) = rtnetlink::new_multicast_connection(&[
            MulticastGroup::Ipv4Route,
            MulticastGroup::Ipv6Route,
        ])?;
        let stream = messages.filter_map(|(msg, _)| std::future::ready(parse_route_event(msg)));
        Ok((Self { inner: handle }, connection, stream))
    }

    /// Install a BGP route into the kernel FIB.
    ///
    /// Both `dst` and `nexthop` must be the same address family.
    /// The route is tagged with `RTPROT_BGP` (186).
    /// Uses `NLM_F_CREATE | NLM_F_REPLACE` for atomic add-or-replace.
    async fn install(
        &self,
        dst: IpAddr,
        prefix_len: u8,
        nexthop: IpAddr,
        metric: u32,
    ) -> Result<(), Error> {
        match (dst, nexthop) {
            (IpAddr::V4(dst), IpAddr::V4(gw)) => self.install_v4(dst, prefix_len, gw, metric).await,
            (IpAddr::V6(dst), IpAddr::V6(gw)) => self.install_v6(dst, prefix_len, gw, metric).await,
            _ => Err(Error::FamilyMismatch),
        }
    }

    /// Apply a `KernelRouteChange` to the kernel FIB.
    ///
    /// Empty `nexthops` withdraws the route; one nexthop installs a
    /// single-path route; two or more nexthops install via `RTA_MULTIPATH`.
    /// MUP/VPN NLRIs and family mismatches are silently ignored.
    async fn apply(&self, change: &KernelRouteChange) -> Result<(), Error> {
        let (dst, prefix_len) = match change.net {
            packet::Nlri::V4(net) => (IpAddr::V4(net.addr), net.mask),
            packet::Nlri::V6(net) => (IpAddr::V6(net.addr), net.mask),
            packet::Nlri::Mup(_) | packet::Nlri::VpnV4(_) | packet::Nlri::VpnV6(_) => {
                return Ok(());
            }
        };
        if change.nexthops.is_empty() {
            return self.withdraw(dst, prefix_len).await;
        }
        let addrs: Vec<IpAddr> = change.nexthops.iter().map(|nh| nh.addr()).collect();
        let result = if addrs.len() == 1 {
            self.install(dst, prefix_len, addrs[0], 0).await
        } else {
            self.install_ecmp(dst, prefix_len, &addrs).await
        };
        match result {
            Err(Error::FamilyMismatch) => Ok(()),
            other => other,
        }
    }

    /// Install a multipath BGP route into the kernel FIB via `RTA_MULTIPATH`.
    ///
    /// Nexthops with a mismatched address family are silently skipped.
    /// Returns `FamilyMismatch` only when all nexthops are filtered out.
    async fn install_ecmp(
        &self,
        dst: IpAddr,
        prefix_len: u8,
        nexthops: &[IpAddr],
    ) -> Result<(), Error> {
        match dst {
            IpAddr::V4(dst_v4) => {
                let nhs: Vec<_> = nexthops
                    .iter()
                    .filter_map(|&nh| {
                        RouteNextHopBuilder::new_ipv4()
                            .via(nh)
                            .ok()
                            .map(|b| b.build())
                    })
                    .collect();
                if nhs.is_empty() {
                    return Err(Error::FamilyMismatch);
                }
                let msg = RouteMessageBuilder::<Ipv4Addr>::new()
                    .destination_prefix(dst_v4, prefix_len)
                    .protocol(RouteProtocol::Bgp)
                    .multipath(nhs)
                    .build();
                self.inner.route().add(msg).replace().execute().await?;
            }
            IpAddr::V6(dst_v6) => {
                let nhs: Vec<_> = nexthops
                    .iter()
                    .filter_map(|&nh| {
                        RouteNextHopBuilder::new_ipv6()
                            .via(nh)
                            .ok()
                            .map(|b| b.build())
                    })
                    .collect();
                if nhs.is_empty() {
                    return Err(Error::FamilyMismatch);
                }
                let msg = RouteMessageBuilder::<Ipv6Addr>::new()
                    .destination_prefix(dst_v6, prefix_len)
                    .protocol(RouteProtocol::Bgp)
                    .multipath(nhs)
                    .build();
                self.inner.route().add(msg).replace().execute().await?;
            }
        }
        Ok(())
    }

    /// Remove a BGP route from the kernel FIB.
    async fn withdraw(&self, dst: IpAddr, prefix_len: u8) -> Result<(), Error> {
        let msg = match dst {
            IpAddr::V4(addr) => RouteMessageBuilder::<Ipv4Addr>::new()
                .destination_prefix(addr, prefix_len)
                .protocol(RouteProtocol::Bgp)
                .build(),
            IpAddr::V6(addr) => RouteMessageBuilder::<Ipv6Addr>::new()
                .destination_prefix(addr, prefix_len)
                .protocol(RouteProtocol::Bgp)
                .build(),
        };
        self.inner.route().del(msg).execute().await?;
        Ok(())
    }

    /// Dump all routes tagged with `RTPROT_BGP` from the kernel.
    #[cfg(test)]
    async fn dump_bgp_routes(&self) -> Result<Vec<KernelRoute>, Error> {
        let mut routes = Vec::new();

        for family in [AddressFamily::Inet, AddressFamily::Inet6] {
            let mut msg = RouteMessage::default();
            msg.header.address_family = family;
            let mut stream = self.inner.route().get(msg).execute();
            while let Some(msg) = stream.try_next().await? {
                if msg.header.protocol == RouteProtocol::Bgp
                    && let Some(kr) = Self::parse_route(&msg)
                {
                    routes.push(kr);
                }
            }
        }

        Ok(routes)
    }

    /// Query the kernel FIB for a non-BGP route to `addr`.
    ///
    /// Uses `RTM_F_FIB_MATCH` so the kernel returns the actual FIB entry with
    /// its original protocol.  Returns `true` only when an IGP or kernel route
    /// covers `addr`; BGP-learned routes are excluded to prevent circular
    /// reachability (a BGP default route must not make BGP nexthops appear
    /// reachable).
    async fn lookup_route(&self, addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(v4) => {
                let mut msg = RouteMessageBuilder::<Ipv4Addr>::new()
                    .destination_prefix(v4, 32)
                    .build();
                msg.header.flags |= RouteFlags::FibMatch;
                matches!(
                    self.inner.route().get(msg).execute().next().await,
                    Some(Ok(ref r)) if r.header.protocol != RouteProtocol::Bgp
                )
            }
            IpAddr::V6(v6) => {
                let mut msg = RouteMessageBuilder::<Ipv6Addr>::new()
                    .destination_prefix(v6, 128)
                    .build();
                msg.header.flags |= RouteFlags::FibMatch;
                matches!(
                    self.inner.route().get(msg).execute().next().await,
                    Some(Ok(ref r)) if r.header.protocol != RouteProtocol::Bgp
                )
            }
        }
    }

    async fn install_v4(
        &self,
        dst: Ipv4Addr,
        prefix_len: u8,
        nexthop: Ipv4Addr,
        metric: u32,
    ) -> Result<(), Error> {
        let msg = RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(dst, prefix_len)
            .gateway(nexthop)
            .protocol(RouteProtocol::Bgp)
            .priority(metric)
            .build();
        self.inner.route().add(msg).replace().execute().await?;
        Ok(())
    }

    async fn install_v6(
        &self,
        dst: Ipv6Addr,
        prefix_len: u8,
        nexthop: Ipv6Addr,
        metric: u32,
    ) -> Result<(), Error> {
        let msg = RouteMessageBuilder::<Ipv6Addr>::new()
            .destination_prefix(dst, prefix_len)
            .gateway(nexthop)
            .protocol(RouteProtocol::Bgp)
            .priority(metric)
            .build();
        self.inner.route().add(msg).replace().execute().await?;
        Ok(())
    }

    fn parse_route(msg: &RouteMessage) -> Option<KernelRoute> {
        let prefix_len = msg.header.destination_prefix_length;
        let protocol = msg.header.protocol;
        let mut dst = None;
        let mut nexthop = None;
        let mut metric = 0u32;

        for attr in &msg.attributes {
            match attr {
                RouteAttribute::Destination(addr) => {
                    dst = route_address_to_ip(addr);
                }
                RouteAttribute::Gateway(addr) => {
                    nexthop = route_address_to_ip(addr);
                }
                RouteAttribute::Priority(p) => {
                    metric = *p;
                }
                _ => {}
            }
        }

        // Default routes (0.0.0.0/0, ::/0) have no Destination attribute;
        // fall back to the unspecified address for the message's address family.
        let dst = dst.or(match msg.header.address_family {
            AddressFamily::Inet => Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            AddressFamily::Inet6 => Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
            _ => None,
        })?;

        Some(KernelRoute {
            dst,
            prefix_len,
            nexthop,
            metric,
            protocol,
        })
    }
}

/// An event delivered by [`KernelService`] to the daemon event loop.
pub enum KernelEvent {
    Route(KernelRouteEvent),
    /// Nexthop reachability change detected by nexthop tracking.
    NexthopUpdate {
        addr: IpAddr,
        reachable: bool,
    },
}

enum Request {
    Apply(KernelRouteChange),
    RegisterNexthop(IpAddr),
    UnregisterNexthop(IpAddr),
}

/// Shareable sender for submitting kernel FIB changes.
///
/// Obtained from [`KernelService::start`]. Multiple clones can be held
/// concurrently (e.g. from different table shards).
#[derive(Clone)]
pub struct KernelHandle {
    tx: tokio::sync::mpsc::UnboundedSender<Request>,
}

impl KernelHandle {
    /// Schedule a FIB install or withdraw.
    ///
    /// Fire-and-forget: the actual Netlink call happens inside the
    /// [`KernelService`] task. Errors are logged there.
    pub fn apply(&self, change: KernelRouteChange) {
        let _ = self.tx.send(Request::Apply(change));
    }

    /// Register a nexthop address for reachability tracking.
    ///
    /// The service queries the kernel for the current reachability of `addr`
    /// and emits an initial [`KernelEvent::NexthopUpdate`].  Subsequent route
    /// changes that might affect `addr` trigger re-checks.  Multiple
    /// registrations for the same address are reference-counted; call
    /// [`unregister_nexthop`] once per [`register_nexthop`] call.
    pub fn register_nexthop(&self, addr: IpAddr) {
        let _ = self.tx.send(Request::RegisterNexthop(addr));
    }

    /// Release one registration for nexthop tracking.
    ///
    /// When the reference count reaches zero the address is no longer watched
    /// and no further [`KernelEvent::NexthopUpdate`] events will be emitted
    /// for it.
    pub fn unregister_nexthop(&self, addr: IpAddr) {
        let _ = self.tx.send(Request::UnregisterNexthop(addr));
    }
}

/// Lifecycle owner for the kernel integration background task.
///
/// Drop to stop the task. Obtained from [`KernelService::start`].
pub struct KernelService {
    task: tokio::task::JoinHandle<()>,
}

impl KernelService {
    /// Start the kernel integration service.
    ///
    /// Spawns an internal task that drives the Netlink route-monitor socket,
    /// filters route events (skipping BGP-tagged echoes and non-redistributed
    /// protocols), forwards matching events to `event_tx`, and processes
    /// [`KernelHandle::apply`] requests via Netlink.
    ///
    /// Returns `(service, handle)`. The `handle` can be cloned freely; all
    /// clones share the same channel into this service. Drop `service` to stop
    /// the background task.
    pub fn start(
        redistribute: Vec<Protocol>,
        event_tx: tokio::sync::mpsc::UnboundedSender<KernelEvent>,
    ) -> Result<(Self, KernelHandle), Error> {
        let (handle, connection, route_events) = Handle::with_route_monitor()?;
        let (req_tx, req_rx) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(run_service_loop(
            handle,
            connection,
            route_events,
            req_rx,
            event_tx,
            redistribute,
        ));
        Ok((Self { task }, KernelHandle { tx: req_tx }))
    }
}

impl Drop for KernelService {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn run_service_loop(
    handle: Handle,
    connection: impl Future<Output = ()> + Send + 'static,
    mut route_events: impl futures::Stream<Item = KernelRouteEvent> + Unpin + Send,
    mut req_rx: tokio::sync::mpsc::UnboundedReceiver<Request>,
    event_tx: tokio::sync::mpsc::UnboundedSender<KernelEvent>,
    redistribute: Vec<Protocol>,
) {
    use std::collections::HashMap;
    tokio::spawn(connection);
    // nexthop addr -> reference count
    let mut watched: HashMap<IpAddr, u32> = HashMap::new();
    // last known reachability for each watched nexthop
    let mut nexthop_state: HashMap<IpAddr, bool> = HashMap::new();
    loop {
        tokio::select! {
            event = route_events.next() => {
                let Some(event) = event else { break };
                let protocol = match &event {
                    KernelRouteEvent::Add(kr) | KernelRouteEvent::Delete(kr) => kr.protocol,
                };
                // Skip routes we installed ourselves to avoid processing our own echoes.
                if protocol != RouteProtocol::Bgp {
                    // Apply redistribution filter (empty list = accept all protocols).
                    if redistribute.is_empty() || redistribute.contains(&protocol) {
                        let _ = event_tx.send(KernelEvent::Route(event));
                    }
                }
                // Any route change may affect watched nexthop reachability.
                let addrs: Vec<IpAddr> = watched.keys().copied().collect();
                for addr in addrs {
                    let reachable = handle.lookup_route(addr).await;
                    if nexthop_state.get(&addr) != Some(&reachable) {
                        nexthop_state.insert(addr, reachable);
                        let _ = event_tx.send(KernelEvent::NexthopUpdate { addr, reachable });
                    }
                }
            }
            req = req_rx.recv() => {
                let Some(req) = req else { break };
                match req {
                    Request::Apply(change) => {
                        if let Err(e) = handle.apply(&change).await {
                            log::error!("kernel route update failed: {}", e);
                        }
                    }
                    Request::RegisterNexthop(addr) => {
                        let count = watched.entry(addr).or_insert(0);
                        *count += 1;
                        if *count == 1 {
                            // First registration: emit the current reachability state.
                            let reachable = handle.lookup_route(addr).await;
                            nexthop_state.insert(addr, reachable);
                            let _ = event_tx.send(KernelEvent::NexthopUpdate { addr, reachable });
                        }
                    }
                    Request::UnregisterNexthop(addr) => {
                        if let std::collections::hash_map::Entry::Occupied(mut e) =
                            watched.entry(addr)
                        {
                            if *e.get() <= 1 {
                                e.remove();
                                nexthop_state.remove(&addr);
                            } else {
                                *e.get_mut() -= 1;
                            }
                        }
                    }
                }
            }
        }
    }
}

fn parse_route_event(
    msg: rtnetlink::packet_core::NetlinkMessage<RouteNetlinkMessage>,
) -> Option<KernelRouteEvent> {
    match msg.payload {
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(route_msg)) => {
            Handle::parse_route(&route_msg).map(KernelRouteEvent::Add)
        }
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelRoute(route_msg)) => {
            Handle::parse_route(&route_msg).map(KernelRouteEvent::Delete)
        }
        _ => None,
    }
}

fn route_address_to_ip(addr: &RouteAddress) -> Option<IpAddr> {
    match addr {
        RouteAddress::Inet(v4) => Some(IpAddr::V4(*v4)),
        RouteAddress::Inet6(v6) => Some(IpAddr::V6(*v6)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    async fn new_handle() -> Handle {
        let (handle, connection) = Handle::new().unwrap();
        tokio::spawn(connection);
        handle
    }

    fn ip(args: &[&str]) {
        let output = std::process::Command::new("ip")
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "ip {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    #[tokio::test]
    #[ignore = "requires network namespace: sudo unshare -n cargo test -p rustybgp-kernel -- --ignored --test-threads=1"]
    async fn test_install_and_dump_v4() {
        let handle = new_handle().await;

        let dst: IpAddr = "10.0.0.0".parse().unwrap();
        let gw: IpAddr = "127.0.0.1".parse().unwrap();
        handle.install(dst, 24, gw, 100).await.unwrap();

        let routes = handle.dump_bgp_routes().await.unwrap();
        assert!(routes.iter().any(|r| r.dst == dst && r.prefix_len == 24));
    }

    #[tokio::test]
    #[ignore = "requires network namespace"]
    async fn test_install_and_withdraw_v4() {
        let handle = new_handle().await;

        let dst: IpAddr = "10.1.0.0".parse().unwrap();
        let gw: IpAddr = "127.0.0.1".parse().unwrap();
        handle.install(dst, 24, gw, 100).await.unwrap();
        handle.withdraw(dst, 24).await.unwrap();

        let routes = handle.dump_bgp_routes().await.unwrap();
        assert!(!routes.iter().any(|r| r.dst == dst && r.prefix_len == 24));
    }

    #[tokio::test]
    #[ignore = "requires network namespace"]
    async fn test_install_and_dump_v6() {
        let handle = new_handle().await;

        // Create a dummy interface with an IPv6 address so the nexthop
        // is reachable via a non-loopback interface.
        ip(&["link", "add", "dummy0", "type", "dummy"]);
        ip(&["link", "set", "dummy0", "up"]);
        ip(&["addr", "add", "2001:db8::1/64", "dev", "dummy0"]);

        let dst: IpAddr = "2001:db8:1::".parse().unwrap();
        let gw: IpAddr = "2001:db8::2".parse().unwrap();
        handle.install(dst, 48, gw, 100).await.unwrap();

        let routes = handle.dump_bgp_routes().await.unwrap();
        assert!(routes.iter().any(|r| r.dst == dst && r.prefix_len == 48));

        ip(&["link", "del", "dummy0"]);
    }

    #[tokio::test]
    #[ignore = "requires network namespace"]
    async fn test_install_replace_v4() {
        let handle = new_handle().await;

        let dst: IpAddr = "10.2.0.0".parse().unwrap();
        let gw1: IpAddr = "127.0.0.1".parse().unwrap();
        let gw2: IpAddr = "127.0.0.2".parse().unwrap();

        handle.install(dst, 24, gw1, 100).await.unwrap();
        handle.install(dst, 24, gw2, 100).await.unwrap();

        let routes = handle.dump_bgp_routes().await.unwrap();
        let route = routes
            .iter()
            .find(|r| r.dst == dst && r.prefix_len == 24)
            .unwrap();
        assert_eq!(route.nexthop, Some(gw2));
    }

    #[tokio::test]
    #[ignore = "requires network namespace"]
    async fn test_family_mismatch() {
        let handle = new_handle().await;

        let dst: IpAddr = "10.0.0.0".parse().unwrap();
        let gw: IpAddr = "::1".parse().unwrap();
        assert!(matches!(
            handle.install(dst, 24, gw, 100).await,
            Err(Error::FamilyMismatch)
        ));
    }

    #[tokio::test]
    #[ignore = "requires network namespace"]
    async fn test_route_monitor_add() {
        let (handle, connection, mut events) = Handle::with_route_monitor().unwrap();
        tokio::spawn(connection);

        // Add a route externally via `ip route add`
        ip(&[
            "route",
            "add",
            "192.168.99.0/24",
            "via",
            "127.0.0.1",
            "proto",
            "static",
        ]);

        // Receive the event with a timeout
        let event = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while let Some(event) = events.next().await {
                if let KernelRouteEvent::Add(ref kr) = event {
                    let expected: IpAddr = "192.168.99.0".parse().unwrap();
                    if kr.dst == expected && kr.prefix_len == 24 {
                        return event;
                    }
                }
            }
            panic!("no matching route event received");
        })
        .await
        .expect("timed out waiting for route event");

        if let KernelRouteEvent::Add(kr) = event {
            assert_eq!(kr.dst, "192.168.99.0".parse::<IpAddr>().unwrap());
            assert_eq!(kr.prefix_len, 24);
        } else {
            panic!("expected KernelRouteEvent::Add");
        }

        // Verify the static route is NOT in the BGP dump (different protocol)
        let routes = handle.dump_bgp_routes().await.unwrap();
        let expected: IpAddr = "192.168.99.0".parse().unwrap();
        assert!(!routes.iter().any(|r| r.dst == expected));

        ip(&["route", "del", "192.168.99.0/24"]);
    }

    #[tokio::test]
    #[ignore = "requires network namespace"]
    async fn test_route_monitor_delete() {
        let (handle, connection, mut events) = Handle::with_route_monitor().unwrap();
        tokio::spawn(connection);

        // Add and then delete a route
        ip(&[
            "route",
            "add",
            "192.168.100.0/24",
            "via",
            "127.0.0.1",
            "proto",
            "static",
        ]);

        // Drain the Add event
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while let Some(event) = events.next().await {
                if let KernelRouteEvent::Add(ref kr) = event {
                    let expected: IpAddr = "192.168.100.0".parse().unwrap();
                    if kr.dst == expected {
                        return;
                    }
                }
            }
        })
        .await
        .expect("timed out waiting for add event");

        // Now delete
        ip(&["route", "del", "192.168.100.0/24"]);

        let event = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while let Some(event) = events.next().await {
                if let KernelRouteEvent::Delete(ref kr) = event {
                    let expected: IpAddr = "192.168.100.0".parse().unwrap();
                    if kr.dst == expected {
                        return event;
                    }
                }
            }
            panic!("no matching delete event received");
        })
        .await
        .expect("timed out waiting for delete event");

        assert!(matches!(event, KernelRouteEvent::Delete(_)));

        drop(handle);
    }

    // --- route_type_to_protocol unit tests (no network namespace) ---

    #[test]
    fn route_type_to_protocol_known_strings() {
        assert_eq!(route_type_to_protocol("connect"), Some(Protocol::Kernel));
        assert_eq!(route_type_to_protocol("static"), Some(Protocol::Static));
        assert_eq!(route_type_to_protocol("ospf"), Some(Protocol::Ospf));
        assert_eq!(route_type_to_protocol("isis"), Some(Protocol::Isis));
        assert_eq!(route_type_to_protocol("rip"), Some(Protocol::Rip));
        assert_eq!(route_type_to_protocol("eigrp"), Some(Protocol::Eigrp));
        assert_eq!(route_type_to_protocol("bgp"), Some(Protocol::Bgp));
        assert_eq!(route_type_to_protocol("babel"), Some(Protocol::Babel));
        assert_eq!(route_type_to_protocol("zebra"), Some(Protocol::Zebra));
    }

    #[test]
    fn route_type_to_protocol_case_insensitive() {
        assert_eq!(route_type_to_protocol("STATIC"), Some(Protocol::Static));
        assert_eq!(route_type_to_protocol("Ospf"), Some(Protocol::Ospf));
        assert_eq!(route_type_to_protocol("BGP"), Some(Protocol::Bgp));
    }

    #[test]
    fn route_type_to_protocol_unknown_returns_none() {
        assert_eq!(route_type_to_protocol(""), None);
        assert_eq!(route_type_to_protocol("unknown"), None);
        assert_eq!(route_type_to_protocol("rip2"), None);
    }

    // --- Handle::apply / KernelRouteChange tests ---

    #[tokio::test]
    #[ignore = "requires network namespace"]
    async fn test_apply_install_v4() {
        let handle = new_handle().await;
        let net = packet::Nlri::V4(packet::bgp::Ipv4Net {
            addr: "10.6.0.0".parse().unwrap(),
            mask: 24,
        });
        let nh = packet::bgp::Nexthop::V4("127.0.0.1".parse().unwrap());
        handle
            .apply(&KernelRouteChange {
                net,
                nexthops: vec![nh],
            })
            .await
            .unwrap();
        let routes = handle.dump_bgp_routes().await.unwrap();
        let dst: IpAddr = "10.6.0.0".parse().unwrap();
        assert!(routes.iter().any(|r| r.dst == dst && r.prefix_len == 24));
    }

    #[tokio::test]
    #[ignore = "requires network namespace"]
    async fn test_apply_withdraw_v4() {
        let handle = new_handle().await;
        let net = packet::Nlri::V4(packet::bgp::Ipv4Net {
            addr: "10.7.0.0".parse().unwrap(),
            mask: 24,
        });
        let nh = packet::bgp::Nexthop::V4("127.0.0.1".parse().unwrap());
        handle
            .apply(&KernelRouteChange {
                net: net.clone(),
                nexthops: vec![nh],
            })
            .await
            .unwrap();
        handle
            .apply(&KernelRouteChange {
                net,
                nexthops: vec![],
            })
            .await
            .unwrap();
        let routes = handle.dump_bgp_routes().await.unwrap();
        let dst: IpAddr = "10.7.0.0".parse().unwrap();
        assert!(!routes.iter().any(|r| r.dst == dst));
    }

    #[tokio::test]
    #[ignore = "requires network namespace"]
    async fn test_apply_ecmp_v4() {
        let handle = new_handle().await;
        let net = packet::Nlri::V4(packet::bgp::Ipv4Net {
            addr: "10.8.0.0".parse().unwrap(),
            mask: 24,
        });
        let nh1 = packet::bgp::Nexthop::V4("127.0.0.1".parse().unwrap());
        let nh2 = packet::bgp::Nexthop::V4("127.0.0.2".parse().unwrap());
        handle
            .apply(&KernelRouteChange {
                net,
                nexthops: vec![nh1, nh2],
            })
            .await
            .unwrap();
        let routes = handle.dump_bgp_routes().await.unwrap();
        let dst: IpAddr = "10.8.0.0".parse().unwrap();
        assert!(routes.iter().any(|r| r.dst == dst && r.prefix_len == 24));
    }

    #[tokio::test]
    #[ignore = "requires network namespace"]
    async fn test_apply_ecmp_v6() {
        let handle = new_handle().await;
        ip(&["link", "add", "dummy1", "type", "dummy"]);
        ip(&["link", "set", "dummy1", "up"]);
        ip(&["addr", "add", "2001:db8:2::1/64", "dev", "dummy1"]);

        let net = packet::Nlri::V6(packet::bgp::Ipv6Net {
            addr: "2001:db8:3::".parse().unwrap(),
            mask: 48,
        });
        let nh1 = packet::bgp::Nexthop::V6("2001:db8:2::2".parse().unwrap());
        let nh2 = packet::bgp::Nexthop::V6("2001:db8:2::3".parse().unwrap());
        handle
            .apply(&KernelRouteChange {
                net,
                nexthops: vec![nh1, nh2],
            })
            .await
            .unwrap();
        let routes = handle.dump_bgp_routes().await.unwrap();
        let dst: IpAddr = "2001:db8:3::".parse().unwrap();
        assert!(routes.iter().any(|r| r.dst == dst && r.prefix_len == 48));

        ip(&["link", "del", "dummy1"]);
    }

    #[tokio::test]
    #[ignore = "requires network namespace"]
    async fn test_apply_family_mismatch_silenced() {
        let handle = new_handle().await;
        let net = packet::Nlri::V4(packet::bgp::Ipv4Net {
            addr: "10.9.0.0".parse().unwrap(),
            mask: 24,
        });
        // IPv6 nexthop for IPv4 prefix: FamilyMismatch is silenced in apply()
        let nh = packet::bgp::Nexthop::V6("::1".parse().unwrap());
        let result = handle
            .apply(&KernelRouteChange {
                net,
                nexthops: vec![nh],
            })
            .await;
        assert!(
            result.is_ok(),
            "apply() must silence FamilyMismatch: {result:?}"
        );
    }

    // --- Handle::install extras ---

    #[tokio::test]
    #[ignore = "requires network namespace"]
    async fn test_install_default_route_v4() {
        let handle = new_handle().await;
        let dst: IpAddr = "0.0.0.0".parse().unwrap();
        let gw: IpAddr = "127.0.0.1".parse().unwrap();
        handle.install(dst, 0, gw, 0).await.unwrap();
        let routes = handle.dump_bgp_routes().await.unwrap();
        assert!(routes.iter().any(|r| r.dst == dst && r.prefix_len == 0));
    }

    #[tokio::test]
    #[ignore = "requires network namespace"]
    async fn test_install_metric_v4() {
        let handle = new_handle().await;
        let dst: IpAddr = "10.5.0.0".parse().unwrap();
        let gw: IpAddr = "127.0.0.1".parse().unwrap();
        handle.install(dst, 24, gw, 200).await.unwrap();
        let routes = handle.dump_bgp_routes().await.unwrap();
        let route = routes
            .iter()
            .find(|r| r.dst == dst && r.prefix_len == 24)
            .unwrap();
        assert_eq!(route.metric, 200);
    }

    // --- KernelService tests ---

    fn make_service() -> (
        KernelService,
        KernelHandle,
        tokio::sync::mpsc::UnboundedReceiver<KernelEvent>,
    ) {
        let (event_tx, event_rx) = tokio::sync::mpsc::unbounded_channel::<KernelEvent>();
        let (service, handle) = KernelService::start(vec![], event_tx).unwrap();
        (service, handle, event_rx)
    }

    #[tokio::test]
    #[ignore = "requires network namespace"]
    async fn test_service_bgp_echo_filtered() {
        let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel::<KernelEvent>();
        let (service, handle) = KernelService::start(vec![], event_tx).unwrap();

        // Install a BGP route via KernelHandle — its Netlink echo must be filtered
        let net = packet::Nlri::V4(packet::bgp::Ipv4Net {
            addr: "10.20.0.0".parse().unwrap(),
            mask: 24,
        });
        let nh = packet::bgp::Nexthop::V4("127.0.0.1".parse().unwrap());
        handle.apply(KernelRouteChange {
            net,
            nexthops: vec![nh],
        });

        // Wait generously for the Netlink echo to be generated and processed
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Add a sentinel static route to confirm the event channel is working
        ip(&[
            "route",
            "add",
            "10.21.0.0/24",
            "via",
            "127.0.0.1",
            "proto",
            "static",
        ]);

        // Drain events until the sentinel; fail if the BGP echo appears first
        let saw_echo = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let Some(KernelEvent::Route(event)) = event_rx.recv().await else {
                    break false;
                };
                let dst = match &event {
                    KernelRouteEvent::Add(kr) | KernelRouteEvent::Delete(kr) => kr.dst,
                };
                if dst == "10.20.0.0".parse::<IpAddr>().unwrap() {
                    break true; // echo leaked
                }
                if dst == "10.21.0.0".parse::<IpAddr>().unwrap() {
                    break false; // sentinel arrived cleanly
                }
            }
        })
        .await
        .expect("timed out waiting for sentinel event");

        assert!(!saw_echo, "BGP-tagged route must not appear in event_rx");
        ip(&["route", "del", "10.21.0.0/24"]);
        drop(service);
    }

    #[tokio::test]
    #[ignore = "requires network namespace"]
    async fn test_service_redistribute_filter() {
        // Only accept Static; a custom protocol (100) must be filtered out
        let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel::<KernelEvent>();
        let (service, _handle) = KernelService::start(vec![Protocol::Static], event_tx).unwrap();

        ip(&[
            "route",
            "add",
            "10.30.0.0/24",
            "via",
            "127.0.0.1",
            "proto",
            "100",
        ]); // filtered
        ip(&[
            "route",
            "add",
            "10.31.0.0/24",
            "via",
            "127.0.0.1",
            "proto",
            "static",
        ]); // sentinel

        let saw_custom = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let Some(KernelEvent::Route(event)) = event_rx.recv().await else {
                    break false;
                };
                let dst = match &event {
                    KernelRouteEvent::Add(kr) | KernelRouteEvent::Delete(kr) => kr.dst,
                };
                if dst == "10.30.0.0".parse::<IpAddr>().unwrap() {
                    break true; // custom protocol leaked
                }
                if dst == "10.31.0.0".parse::<IpAddr>().unwrap() {
                    break false; // sentinel arrived, custom was filtered
                }
            }
        })
        .await
        .expect("timed out waiting for sentinel event");

        assert!(!saw_custom, "non-redistribute protocol must be filtered");
        ip(&["route", "del", "10.30.0.0/24"]);
        ip(&["route", "del", "10.31.0.0/24"]);
        drop(service);
    }

    #[tokio::test]
    #[ignore = "requires network namespace"]
    async fn test_service_redistributes_all() {
        // Empty redistribute list accepts all non-BGP protocols
        let (service, _handle, mut event_rx) = make_service();

        ip(&[
            "route",
            "add",
            "10.40.0.0/24",
            "via",
            "127.0.0.1",
            "proto",
            "static",
        ]);

        let arrived = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match event_rx.recv().await {
                    Some(KernelEvent::Route(KernelRouteEvent::Add(kr)))
                        if kr.dst == "10.40.0.0".parse::<IpAddr>().unwrap()
                            && kr.prefix_len == 24 =>
                    {
                        break true;
                    }
                    None => break false,
                    _ => continue,
                }
            }
        })
        .await
        .unwrap_or(false);

        assert!(arrived, "static route should arrive on event_rx");
        ip(&["route", "del", "10.40.0.0/24"]);
        drop(service);
    }

    // --- NHT (nexthop tracking) integration tests ---

    #[tokio::test]
    #[ignore = "requires network namespace"]
    async fn test_nht_loopback_reachable() {
        // 127.0.0.1 is always reachable via the local route table.
        let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel::<KernelEvent>();
        let (service, handle) = KernelService::start(vec![], event_tx).unwrap();

        handle.register_nexthop("127.0.0.1".parse().unwrap());

        let reachable = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match event_rx.recv().await {
                    Some(KernelEvent::NexthopUpdate { addr, reachable })
                        if addr == "127.0.0.1".parse::<IpAddr>().unwrap() =>
                    {
                        break reachable;
                    }
                    None => panic!("channel closed"),
                    _ => continue,
                }
            }
        })
        .await
        .expect("timed out waiting for initial NexthopUpdate");

        assert!(reachable, "127.0.0.1 should be reachable via local table");
        drop(service);
    }

    #[tokio::test]
    #[ignore = "requires network namespace"]
    async fn test_nht_unreachable_after_route_delete() {
        // A nexthop is reachable via a static route; deleting that route
        // must trigger NexthopUpdate { reachable: false }.
        ip(&[
            "route",
            "add",
            "10.60.0.0/24",
            "via",
            "127.0.0.1",
            "proto",
            "static",
        ]);

        let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel::<KernelEvent>();
        let (service, handle) = KernelService::start(vec![], event_tx).unwrap();

        let nh: IpAddr = "10.60.0.1".parse().unwrap();
        handle.register_nexthop(nh);

        // Drain the initial reachability event.
        let initially_reachable = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match event_rx.recv().await {
                    Some(KernelEvent::NexthopUpdate { addr, reachable }) if addr == nh => {
                        break reachable;
                    }
                    None => panic!("channel closed"),
                    _ => continue,
                }
            }
        })
        .await
        .expect("timed out waiting for initial NexthopUpdate");
        assert!(
            initially_reachable,
            "10.60.0.1 should be reachable via 10.60.0.0/24"
        );

        // Remove the covering route; the service must detect the change.
        ip(&["route", "del", "10.60.0.0/24"]);

        let now_reachable = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                match event_rx.recv().await {
                    Some(KernelEvent::NexthopUpdate { addr, reachable }) if addr == nh => {
                        break reachable;
                    }
                    None => panic!("channel closed"),
                    _ => continue,
                }
            }
        })
        .await
        .expect("timed out waiting for unreachable NexthopUpdate");
        assert!(
            !now_reachable,
            "10.60.0.1 should become unreachable after route delete"
        );

        drop(service);
    }

    #[tokio::test]
    #[ignore = "requires network namespace"]
    async fn test_nht_reachable_after_route_add() {
        // Register a nexthop with no covering route (unreachable), then add
        // a route and confirm NexthopUpdate { reachable: true } is emitted.
        let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel::<KernelEvent>();
        let (service, handle) = KernelService::start(vec![], event_tx).unwrap();

        let nh: IpAddr = "10.61.0.1".parse().unwrap();
        handle.register_nexthop(nh);

        // Initial state: unreachable.
        let initially_reachable = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match event_rx.recv().await {
                    Some(KernelEvent::NexthopUpdate { addr, reachable }) if addr == nh => {
                        break reachable;
                    }
                    None => panic!("channel closed"),
                    _ => continue,
                }
            }
        })
        .await
        .expect("timed out waiting for initial NexthopUpdate");
        assert!(!initially_reachable, "10.61.0.1 should start unreachable");

        // Add a route that covers the nexthop.
        ip(&[
            "route",
            "add",
            "10.61.0.0/24",
            "via",
            "127.0.0.1",
            "proto",
            "static",
        ]);

        let now_reachable = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                match event_rx.recv().await {
                    Some(KernelEvent::NexthopUpdate { addr, reachable }) if addr == nh => {
                        break reachable;
                    }
                    None => panic!("channel closed"),
                    _ => continue,
                }
            }
        })
        .await
        .expect("timed out waiting for reachable NexthopUpdate");
        assert!(
            now_reachable,
            "10.61.0.1 should become reachable after route add"
        );

        ip(&["route", "del", "10.61.0.0/24"]);
        drop(service);
    }

    #[tokio::test]
    #[ignore = "requires network namespace"]
    async fn test_nht_unregister_stops_tracking() {
        // After unregistering, no further NexthopUpdate events must arrive
        // even when a route to the nexthop changes.
        let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel::<KernelEvent>();
        let (service, handle) = KernelService::start(vec![], event_tx).unwrap();

        let nh: IpAddr = "10.62.0.1".parse().unwrap();
        handle.register_nexthop(nh);

        // Drain the initial event.
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match event_rx.recv().await {
                    Some(KernelEvent::NexthopUpdate { addr, .. }) if addr == nh => break,
                    None => panic!("channel closed"),
                    _ => continue,
                }
            }
        })
        .await
        .expect("timed out waiting for initial NexthopUpdate");

        // Unregister: service must stop tracking this nexthop.
        handle.unregister_nexthop(nh);

        // Add a sentinel static route (different prefix) so the event loop
        // processes at least one more route event after the unregister.
        ip(&[
            "route",
            "add",
            "10.62.1.0/24",
            "via",
            "127.0.0.1",
            "proto",
            "static",
        ]);

        // Drain events until the sentinel route event; fail if a NexthopUpdate
        // for the unregistered nexthop arrives.
        let saw_nht = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match event_rx.recv().await {
                    Some(KernelEvent::NexthopUpdate { addr, .. }) if addr == nh => {
                        break true; // unexpected
                    }
                    Some(KernelEvent::Route(KernelRouteEvent::Add(ref kr)))
                        if kr.dst == "10.62.1.0".parse::<IpAddr>().unwrap() =>
                    {
                        break false; // sentinel arrived cleanly
                    }
                    None => break false,
                    _ => continue,
                }
            }
        })
        .await
        .unwrap_or(false);

        assert!(!saw_nht, "NexthopUpdate must not arrive after unregister");
        ip(&["route", "del", "10.62.1.0/24"]);
        drop(service);
    }

    #[tokio::test]
    #[ignore = "requires network namespace"]
    async fn test_service_drop_closes_channel() {
        let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel::<KernelEvent>();
        let (service, _handle) = KernelService::start(vec![], event_tx).unwrap();
        drop(service); // aborts the task, dropping event_tx inside run_service_loop
        let result = tokio::time::timeout(Duration::from_millis(500), event_rx.recv()).await;
        assert!(
            matches!(result, Ok(None)),
            "channel must close after KernelService is dropped"
        );
    }
}
