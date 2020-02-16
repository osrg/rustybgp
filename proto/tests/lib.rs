use proto::bgp::*;
use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::net::{IpAddr, Ipv6Addr};

#[test]
fn parse_ipv6_update() {
    let path = env::current_dir().unwrap();
    let filename = path.to_str().unwrap().to_owned() + "/tests/packet/ipv6-update.raw";
    let mut file = File::open(filename).unwrap();
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).unwrap();
    let param = &ParseParam { local_as: 1 };
    let nlri = vec![
        IpNet {
            addr: IpAddr::V6(Ipv6Addr::new(0x2003, 0xde, 0x2016, 0x127, 0, 0, 0, 0)),
            mask: 64,
        },
        IpNet {
            addr: IpAddr::V6(Ipv6Addr::new(0x2003, 0xde, 0x2016, 0x124, 0, 0, 0, 0)),
            mask: 64,
        },
        IpNet {
            addr: IpAddr::V6(Ipv6Addr::new(0x2003, 0xde, 0x2016, 0x128, 0, 0, 0, 0)),
            mask: 63,
        },
        IpNet {
            addr: IpAddr::V6(Ipv6Addr::new(0x2003, 0xde, 0x2016, 0x1ff, 0, 0, 0, 0x12)),
            mask: 127,
        },
    ];
    let msg = Message::from_bytes(param, buf.as_slice()).unwrap();
    match msg {
        Message::Update(update) => {
            for mp_route in &update.mp_routes {
                assert_eq!(nlri.len(), mp_route.0.len());
                for i in 0..mp_route.0.len() {
                    match mp_route.0[i] {
                        Nlri::Ip(n) => {
                            assert_eq!(n, nlri[i]);
                        }
                    }
                }
            }
        }
        _ => assert!(false),
    }
}
