// Copyright (C) 2024 The RustyBGP Authors.
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
// implied.  See the License for the specific language governing
// permissions and limitations under the License.

use futures::{FutureExt, StreamExt};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, SystemTime};
use tokio::io::AsyncWriteExt;
use tokio::time::Instant;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tokio_util::codec::Encoder;
use tokio_util::sync::CancellationToken;

use rustybgp_packet::{Family, bgp, mrt};

use crate::error::Error;
use crate::event::{AdjRibInChange, BgpEvent, TableHandle};

fn adj_rib_in_to_mrt(change: &AdjRibInChange) -> mrt::Message {
    let header = mrt::MpHeader::new(
        change.source.remote_asn,
        change.source.local_asn,
        0,
        change.source.remote_addr,
        change.source.local_addr,
        true,
    );
    let body = if let Some(attrs) = &change.attrs {
        bgp::Message::Update(bgp::Update::Reach {
            family: change.family,
            entries: change.nlris.clone(),
            nexthop: change.nexthop,
            attr: attrs.clone(),
        })
    } else {
        bgp::Message::Update(bgp::Update::Unreach {
            family: change.family,
            entries: change.nlris.clone(),
        })
    };
    mrt::Message::Mp {
        header,
        body,
        addpath: change.addpath,
    }
}

pub(crate) struct MrtDumper {
    pub(crate) filename: String,
    interval: u64,
}

impl MrtDumper {
    pub(crate) fn new(filename: &str, interval: u64) -> Self {
        MrtDumper {
            filename: filename.to_string(),
            interval,
        }
    }

    pub(crate) fn pathname(&self) -> String {
        if self.interval != 0 {
            chrono::Local::now().format(&self.filename).to_string()
        } else {
            self.filename.clone()
        }
    }

    pub(crate) async fn serve(
        &mut self,
        mut file: tokio::fs::File,
        cancel: CancellationToken,
        tables: TableHandle,
    ) -> Result<(), Error> {
        let subscription = tables.subscribe(false);
        let result = self.run_loop(&mut file, subscription.rx, cancel).await;
        tables.unsubscribe(subscription.id);
        result
    }

    pub(crate) async fn serve_table(
        &mut self,
        mut file: tokio::fs::File,
        cancel: CancellationToken,
        tables: TableHandle,
        router_id: Ipv4Addr,
    ) -> Result<(), Error> {
        dump_table(router_id, &tables, &mut file).await?;
        if self.interval == 0 {
            return Ok(());
        }
        let start = Instant::now() + Duration::from_secs(self.interval);
        let mut timer = tokio::time::interval_at(start, Duration::from_secs(self.interval));
        loop {
            tokio::select! {
                _ = timer.tick().fuse() => {
                    file = tokio::fs::File::create(std::path::Path::new(&self.pathname())).await?;
                    dump_table(router_id, &tables, &mut file).await?;
                }
                _ = cancel.cancelled() => return Ok(()),
            }
        }
    }

    async fn run_loop(
        &self,
        file: &mut tokio::fs::File,
        rx: tokio::sync::mpsc::UnboundedReceiver<BgpEvent>,
        cancel: CancellationToken,
    ) -> Result<(), Error> {
        let mut codec = mrt::MrtCodec::new();
        let mut rx = UnboundedReceiverStream::new(rx);
        let interval = if self.interval == 0 {
            60 * 24 * 60 * 365 * 100
        } else {
            self.interval
        };
        let start = Instant::now() + Duration::from_secs(interval);
        let mut timer = tokio::time::interval_at(start, Duration::from_secs(interval));
        loop {
            tokio::select! {
                event = rx.next() => {
                    match event {
                        Some(BgpEvent::AdjRibIn(change)) => {
                            let msg = adj_rib_in_to_mrt(&change);
                            let mut buf = bytes::BytesMut::with_capacity(8192);
                            codec.encode(&msg, &mut buf)?;
                            file.write_all(&buf).await?;
                        }
                        Some(BgpEvent::AdjRibInPost(_))
                        | Some(BgpEvent::AdjRibOutPre(_))
                        | Some(BgpEvent::AdjRibOutPost(_))
                        | Some(BgpEvent::PeerUp(_))
                        | Some(BgpEvent::PeerDown(_))
                        | Some(BgpEvent::LocRib(_))
                        | Some(BgpEvent::EndOfSnapshot) => {}
                        None => return Ok(()),
                    }
                }
                _ = timer.tick().fuse() => {
                    if self.interval != 0 {
                        *file = tokio::fs::File::create(std::path::Path::new(&self.pathname()))
                            .await?;
                    }
                }
                _ = cancel.cancelled() => return Ok(()),
            }
        }
    }
}

pub(crate) async fn dump_table(
    router_id: Ipv4Addr,
    tables: &TableHandle,
    file: &mut tokio::fs::File,
) -> Result<(), Error> {
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;

    let ipv4_changes = tables.collect_loc_rib_paths(Family::IPV4);
    let ipv6_changes = tables.collect_loc_rib_paths(Family::IPV6);

    // Build peer index: one entry per unique remote peer address.
    let mut peer_index: HashMap<IpAddr, u16> = HashMap::new();
    let mut peers: Vec<mrt::PeerEntry> = Vec::new();
    for change in ipv4_changes.iter().chain(ipv6_changes.iter()) {
        for path in change.current_paths.iter() {
            let addr = path.source.remote_addr;
            let next_idx = peers.len() as u16;
            peer_index.entry(addr).or_insert_with(|| {
                peers.push(mrt::PeerEntry {
                    bgp_id: Ipv4Addr::from(path.source.router_id),
                    addr,
                    asn: path.source.remote_asn,
                });
                next_idx
            });
        }
    }

    let mut buf = bytes::BytesMut::with_capacity(4096);
    mrt::encode_table_dump(
        timestamp,
        &mrt::TableDumpRecord::PeerIndexTable { router_id, peers },
        &mut buf,
    )?;
    file.write_all(&buf).await?;

    let mut seq = 0u32;
    for change in &ipv4_changes {
        let entries: Vec<mrt::RibEntry> = change
            .current_paths
            .iter()
            .filter_map(|path| {
                let &idx = peer_index.get(&path.source.remote_addr)?;
                Some(mrt::RibEntry {
                    peer_index: idx,
                    originated: timestamp,
                    nexthop: path.nexthop,
                    attrs: path.attr.clone(),
                })
            })
            .collect();
        if entries.is_empty() {
            continue;
        }
        buf.clear();
        mrt::encode_table_dump(
            timestamp,
            &mrt::TableDumpRecord::RibIpv4Unicast {
                seq,
                prefix: change.net.clone(),
                entries,
            },
            &mut buf,
        )?;
        file.write_all(&buf).await?;
        seq += 1;
    }

    seq = 0;
    for change in &ipv6_changes {
        let entries: Vec<mrt::RibEntry> = change
            .current_paths
            .iter()
            .filter_map(|path| {
                let &idx = peer_index.get(&path.source.remote_addr)?;
                Some(mrt::RibEntry {
                    peer_index: idx,
                    originated: timestamp,
                    nexthop: path.nexthop,
                    attrs: path.attr.clone(),
                })
            })
            .collect();
        if entries.is_empty() {
            continue;
        }
        buf.clear();
        mrt::encode_table_dump(
            timestamp,
            &mrt::TableDumpRecord::RibIpv6Unicast {
                seq,
                prefix: change.net.clone(),
                entries,
            },
            &mut buf,
        )?;
        file.write_all(&buf).await?;
        seq += 1;
    }

    Ok(())
}
