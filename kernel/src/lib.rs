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
use rtnetlink::packet_route::route::{RouteAddress, RouteAttribute, RouteProtocol};
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
}

enum Request {
    Apply(KernelRouteChange),
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
    tokio::spawn(connection);
    loop {
        tokio::select! {
            event = route_events.next() => {
                let Some(event) = event else { break };
                let protocol = match &event {
                    KernelRouteEvent::Add(kr) | KernelRouteEvent::Delete(kr) => kr.protocol,
                };
                // Skip routes we installed ourselves to avoid processing our own echoes.
                if protocol == RouteProtocol::Bgp {
                    continue;
                }
                // Apply redistribution filter (empty list = accept all protocols).
                if !redistribute.is_empty() && !redistribute.contains(&protocol) {
                    continue;
                }
                let _ = event_tx.send(KernelEvent::Route(event));
            }
            req = req_rx.recv() => {
                let Some(req) = req else { break };
                match req {
                    Request::Apply(change) => {
                        if let Err(e) = handle.apply(&change).await {
                            log::error!("kernel route update failed: {}", e);
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
}
