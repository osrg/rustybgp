// Copyright (C) 2019-2022 The RustyBGP Authors.
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

use std::net::{IpAddr, SocketAddr};
use std::os::unix::io::RawFd;

pub(crate) fn create_listen_socket(
    addr: String,
    port: u16,
) -> std::io::Result<std::net::TcpListener> {
    let addr: std::net::SocketAddr = format!("{}:{}", addr, port).parse().unwrap();

    let sock = socket2::Socket::new(
        match addr {
            SocketAddr::V4(_) => socket2::Domain::IPV4,
            SocketAddr::V6(_) => socket2::Domain::IPV6,
        },
        socket2::Type::STREAM,
        None,
    )?;
    if addr.is_ipv6() {
        sock.set_only_v6(true)?;
    }

    sock.set_reuse_address(true)?;
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    sock.listen(4096)?;

    Ok(sock.into())
}

#[repr(C)]
struct TcpMd5sig {
    ss_family: u16,
    ss: [u8; 126],
    _pad0: u16,
    keylen: u16,
    _pad1: u32,
    key: [u8; 80],
}

impl TcpMd5sig {
    fn new(addr: &IpAddr, password: String) -> TcpMd5sig {
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
        let k = std::ffi::CString::new(password).unwrap().into_bytes();
        let keylen = k.len();
        let mut key = [0; 80];
        key[..std::cmp::min(keylen, 80)].clone_from_slice(&k[..std::cmp::min(keylen, 80)]);
        TcpMd5sig {
            ss_family,
            ss,
            _pad0: 0,
            keylen: keylen as u16,
            _pad1: 0,
            key,
        }
    }
}

pub(crate) fn set_md5sig(rawfd: RawFd, addr: &IpAddr, key: &str) {
    let s = TcpMd5sig::new(addr, key.to_string());
    unsafe {
        let ptr: *const TcpMd5sig = &s;
        let len = std::mem::size_of::<TcpMd5sig>() as u32;
        let _ = libc::setsockopt(
            rawfd,
            libc::IPPROTO_TCP,
            libc::TCP_MD5SIG,
            ptr as *const _,
            len,
        );
    }
}
