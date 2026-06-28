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

use std::net::IpAddr;
use std::os::unix::io::RawFd;

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

#[cfg(target_os = "linux")]
pub(crate) fn set_md5sig(rawfd: RawFd, addr: &IpAddr, key: &str, ifindex: u32) {
    let s = TcpMd5sig::new(addr, key.to_string(), ifindex);
    unsafe {
        let ptr: *const TcpMd5sig = &s;
        let len = std::mem::size_of::<TcpMd5sig>() as u32;
        let _ = libc::setsockopt(
            rawfd,
            libc::IPPROTO_TCP,
            libc::TCP_MD5SIG_EXT,
            ptr as *const _,
            len,
        );
    }
}

// use file per target os when you add *bsd support
// for now, let's keep things simple
#[cfg(not(target_os = "linux"))]
pub(crate) fn set_md5sig(_rawfd: RawFd, _addr: &IpAddr, _key: &str, _ifindex: u32) {}

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
pub(crate) fn set_min_ttl(rawfd: RawFd, addr: &IpAddr, ttl_min: u8) {
    let ttl_min = ttl_min as libc::c_int;
    unsafe {
        match addr {
            IpAddr::V4(_) => {
                let _ = libc::setsockopt(
                    rawfd,
                    libc::IPPROTO_IP,
                    libc::IP_MINTTL,
                    &ttl_min as *const _ as *const _,
                    std::mem::size_of::<libc::c_int>() as u32,
                );
            }
            IpAddr::V6(_) => {
                let _ = libc::setsockopt(
                    rawfd,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_MINHOPCOUNT,
                    &ttl_min as *const _ as *const _,
                    std::mem::size_of::<libc::c_int>() as u32,
                );
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn set_min_ttl(_rawfd: RawFd, _addr: &IpAddr, _ttl_min: u8) {}
