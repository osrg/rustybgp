// Copyright (C) 2022 The RustyBGP Authors.
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

use std::io;
use std::net::IpAddr;
use std::os::unix::io::{AsRawFd, RawFd};

#[repr(C)]
struct TcpMd5sig {
    ss_family: u16,
    ss: [u8; 126],
    tcpm_flags: u8,
    tcpm_prefixlen: u8,
    keylen: u16,
    tcpm_ifindex: u32,
    key: [u8; 80],
}

const TCP_MD5SIG_FLAG_IFINDEX: u8 = 2;

impl TcpMd5sig {
    fn new(addr: &IpAddr, password: String, ifindex: u32) -> TcpMd5sig {
        let mut ss = [0; 126];
        let ss_family = match addr {
            std::net::IpAddr::V4(addr) => {
                ss[2..(addr.octets().len() + 2)].clone_from_slice(&addr.octets()[..]);
                libc::AF_INET as u16
            }
            std::net::IpAddr::V6(addr) => {
                ss[6..(addr.octets().len() + 6)].clone_from_slice(&addr.octets()[..]);
                libc::AF_INET6 as u16
            }
        };
        let k = password.into_bytes();
        let keylen = k.len();
        let mut key = [0; 80];
        key[..std::cmp::min(keylen, 80)].clone_from_slice(&k[..std::cmp::min(keylen, 80)]);
        let tcpm_flags = if ifindex != 0 {
            TCP_MD5SIG_FLAG_IFINDEX
        } else {
            0
        };
        TcpMd5sig {
            ss_family,
            ss,
            tcpm_flags,
            tcpm_prefixlen: 0,
            keylen: keylen as u16,
            tcpm_ifindex: ifindex,
            key,
        }
    }
}

/// Maximum TCP-MD5 key length accepted by the kernel (TCP_MD5SIG_MAXKEYLEN).
#[cfg(target_os = "linux")]
const TCP_MD5SIG_MAXKEYLEN: usize = 80;

/// Install (or, with an empty `key`, remove) the RFC 2385 TCP-MD5 key for
/// `addr` on `rawfd`. Errors are returned rather than ignored: a peer with
/// `auth_password` configured must never silently run unauthenticated.
#[cfg(target_os = "linux")]
pub(crate) fn set_md5sig(rawfd: RawFd, addr: &IpAddr, key: &str, ifindex: u32) -> io::Result<()> {
    if key.len() > TCP_MD5SIG_MAXKEYLEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("TCP MD5 key is longer than {TCP_MD5SIG_MAXKEYLEN} bytes"),
        ));
    }
    let s = TcpMd5sig::new(addr, key.to_string(), ifindex);
    let ret = unsafe {
        let ptr: *const TcpMd5sig = &s;
        let len = std::mem::size_of::<TcpMd5sig>() as u32;
        libc::setsockopt(
            rawfd,
            libc::IPPROTO_TCP,
            libc::TCP_MD5SIG_EXT,
            ptr as *const _,
            len,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// use file per target os when you add *bsd support
// for now, let's keep things simple
#[cfg(not(target_os = "linux"))]
pub(crate) fn set_md5sig(
    _rawfd: RawFd,
    _addr: &IpAddr,
    key: &str,
    _ifindex: u32,
) -> io::Result<()> {
    if key.is_empty() {
        return Ok(());
    }
    Err(unsupported("TCP MD5 signatures"))
}

#[cfg(not(target_os = "linux"))]
fn unsupported(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("{what} are only supported on Linux"),
    )
}

/// Whether this platform can enforce TCP-MD5 (`auth_password`) and GTSM
/// (`ttl_security`). Peers configuring either are refused where it can't,
/// rather than running without the protection.
pub(crate) const SUPPORTS_SOCKET_SECURITY: bool = cfg!(target_os = "linux");

/// Resolve a network interface name to its ifindex.
/// Returns 0 if the interface does not exist or the name is empty.
pub(crate) fn ifindex_of(device: &str) -> u32 {
    if device.is_empty() {
        return 0;
    }
    nix::net::if_::if_nametoindex(device).unwrap_or(0)
}

/// Set the minimum acceptable TTL for incoming packets (RFC 5082 GTSM).
/// Packets arriving with TTL < ttl_min are dropped by the kernel.
/// IPv4 uses IP_MINTTL; IPv6 uses IPV6_MINHOPCOUNT.
#[cfg(target_os = "linux")]
pub(crate) fn set_min_ttl(rawfd: RawFd, addr: &IpAddr, ttl_min: u8) -> io::Result<()> {
    let ttl_min = ttl_min as libc::c_int;
    let (level, name) = match addr {
        IpAddr::V4(_) => (libc::IPPROTO_IP, libc::IP_MINTTL),
        IpAddr::V6(_) => (libc::IPPROTO_IPV6, libc::IPV6_MINHOPCOUNT),
    };
    let ret = unsafe {
        libc::setsockopt(
            rawfd,
            level,
            name,
            &ttl_min as *const _ as *const _,
            std::mem::size_of::<libc::c_int>() as u32,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn set_min_ttl(_rawfd: RawFd, _addr: &IpAddr, _ttl_min: u8) -> io::Result<()> {
    Err(unsupported("GTSM minimum TTL checks"))
}

/// Apply GTSM (RFC 5082) to a socket: send with TTL / hop limit 255 and have
/// the kernel drop received segments below `ttl_min`. Must be applied before
/// `connect()` on active sockets so the SYN already carries TTL 255 and the
/// SYN-ACK is subject to the minimum-TTL check.
pub(crate) fn set_gtsm<S: std::os::fd::AsFd>(
    sock: &S,
    addr: &IpAddr,
    ttl_min: u8,
) -> io::Result<()> {
    let s = socket2::SockRef::from(sock);
    match addr {
        IpAddr::V4(_) => s.set_ttl_v4(255)?,
        IpAddr::V6(_) => {
            s.set_unicast_hops_v6(255)?;
            // Also cover IPv4-mapped traffic on a dual-stack socket.
            let _ = s.set_ttl_v4(255);
        }
    }
    set_min_ttl(sock.as_fd().as_raw_fd(), addr, ttl_min)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn set_md5sig_reports_setsockopt_failure() {
        let addr: IpAddr = "192.0.2.1".parse().unwrap();
        // Invalid fd: the kernel error must surface instead of being dropped.
        assert!(set_md5sig(-1, &addr, "secret", 0).is_err());
    }

    #[test]
    fn set_md5sig_rejects_overlong_key() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr: IpAddr = "192.0.2.1".parse().unwrap();
        let err = set_md5sig(l.as_raw_fd(), &addr, &"k".repeat(81), 0).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn set_min_ttl_reports_setsockopt_failure() {
        let v4: IpAddr = "192.0.2.1".parse().unwrap();
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(set_min_ttl(-1, &v4, 254).is_err());
        assert!(set_min_ttl(-1, &v6, 254).is_err());
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        assert!(set_min_ttl(l.as_raw_fd(), &v4, 254).is_ok());
    }

    #[test]
    fn set_gtsm_sets_ttl_255_before_connect() {
        let v4: IpAddr = "192.0.2.1".parse().unwrap();
        let s = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
        set_gtsm(&s, &v4, 254).unwrap();
        assert_eq!(s.ttl_v4().unwrap(), 255);

        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        let s = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::STREAM, None).unwrap();
        set_gtsm(&s, &v6, 254).unwrap();
        assert_eq!(s.unicast_hops_v6().unwrap(), 255);
    }
}
