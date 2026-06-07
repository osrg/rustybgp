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
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::time::Instant;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tokio_util::codec::Encoder;

use rustybgp_packet::{self as packet, bgp, mrt};

use crate::error::Error;
use crate::event::{AdjRibInChange, BgpEvent, GlobalHandle, TableHandle};

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
        bgp::Message::Update(bgp::Update {
            reach: Some(packet::bgp::NlriSet {
                family: change.family,
                entries: change.nlris.clone(),
            }),
            mp_reach: None,
            attr: attrs.clone(),
            unreach: None,
            mp_unreach: None,
            nexthop: change.nexthop,
        })
    } else {
        bgp::Message::Update(bgp::Update {
            reach: None,
            mp_reach: None,
            attr: Arc::new(Vec::new()),
            unreach: None,
            mp_unreach: Some(packet::bgp::NlriSet {
                family: change.family,
                entries: change.nlris.clone(),
            }),
            nexthop: None,
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
        global: GlobalHandle,
        tables: TableHandle,
    ) -> Result<(), Error> {
        let subscription = tables.subscribe_live().await;
        let result = self.run_loop(&mut file, subscription.rx).await;
        tables.unsubscribe(subscription.id).await;
        global.write().await.mrt_filenames.remove(&self.filename);
        result
    }

    async fn run_loop(
        &self,
        file: &mut tokio::fs::File,
        rx: tokio::sync::mpsc::UnboundedReceiver<BgpEvent>,
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
                        Some(BgpEvent::PeerUp(_)) | Some(BgpEvent::PeerDown(_)) => {}
                        None => return Ok(()),
                    }
                }
                _ = timer.tick().fuse() => {
                    if self.interval != 0 {
                        *file = tokio::fs::File::create(std::path::Path::new(&self.pathname()))
                            .await?;
                    }
                }
            }
        }
    }
}
