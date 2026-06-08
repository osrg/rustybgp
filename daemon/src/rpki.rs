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

use futures::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU16, AtomicU32, AtomicU64, Ordering};
use std::time::SystemTime;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;
use tokio_util::sync::CancellationToken;

use rustybgp_packet::{self as packet, rpki};
use rustybgp_table as table;

use crate::error::Error;
use crate::event::TableHandle;

#[derive(Default)]
pub(crate) struct RpkiState {
    pub(crate) uptime: AtomicU64,
    pub(crate) downtime: AtomicU64,
    pub(crate) up: AtomicBool,
    pub(crate) session_id: AtomicU16,
    pub(crate) serial: AtomicU32,
    pub(crate) received_ipv4: AtomicI64,
    pub(crate) received_ipv6: AtomicI64,
    pub(crate) serial_notify: AtomicI64,
    pub(crate) cache_reset: AtomicI64,
    pub(crate) cache_response: AtomicI64,
    pub(crate) end_of_data: AtomicI64,
    pub(crate) error: AtomicI64,
    pub(crate) serial_query: AtomicI64,
    pub(crate) reset_query: AtomicI64,
}

impl RpkiState {
    pub(crate) fn update(&self, msg: &rpki::Message) {
        match msg {
            rpki::Message::SerialNotify { .. } => {
                self.serial_notify.fetch_add(1, Ordering::Relaxed);
            }
            rpki::Message::SerialQuery { .. } => {
                let _ = self.serial_query.fetch_add(1, Ordering::Relaxed);
            }
            rpki::Message::ResetQuery => {
                let _ = self.reset_query.fetch_add(1, Ordering::Relaxed);
            }
            rpki::Message::CacheResponse { .. } => {
                let _ = self.cache_response.fetch_add(1, Ordering::Relaxed);
            }
            rpki::Message::IpPrefix(prefix) => match prefix.net {
                packet::IpNet::V4(_) => {
                    let _ = self.received_ipv4.fetch_add(1, Ordering::Relaxed);
                }
                packet::IpNet::V6(_) => {
                    let _ = self.received_ipv6.fetch_add(1, Ordering::Relaxed);
                }
            },
            rpki::Message::EndOfData { .. } => {
                let _ = self.end_of_data.fetch_add(1, Ordering::Relaxed);
            }
            rpki::Message::CacheReset => {
                let _ = self.cache_reset.fetch_add(1, Ordering::Relaxed);
            }
            rpki::Message::ErrorReport { .. } => {
                let _ = self.error.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

pub(crate) struct RpkiClient {
    pub(crate) cancel: CancellationToken,
    pub(crate) state: Arc<RpkiState>,
}

impl RpkiClient {
    pub(crate) fn new() -> Self {
        RpkiClient {
            cancel: CancellationToken::new(),
            state: Arc::new(RpkiState::default()),
        }
    }

    async fn serve(
        stream: TcpStream,
        cancel: CancellationToken,
        state: Arc<RpkiState>,
        tables: TableHandle,
    ) -> Result<(), Error> {
        let remote_addr = stream.peer_addr()?.ip();
        let remote_addr = Arc::new(remote_addr);
        let mut lines = Framed::new(stream, rpki::RtrCodec::new());
        let _ = lines.send(&rpki::Message::ResetQuery).await;
        state.uptime.store(
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            Ordering::Relaxed,
        );
        state.up.store(true, Ordering::Relaxed);
        let mut v = Vec::new();
        let mut end_of_data = false;
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                msg = lines.next() => {
                    let msg = match msg {
                        Some(msg) => match msg {
                            Ok(msg) => msg,
                            Err(_) => break,
                        },
                        None => break,
                    };
                    state.update(&msg);
                    match msg {
                        rpki::Message::CacheResponse { session_id } => {
                            state.session_id.store(session_id, Ordering::Relaxed);
                        }
                        rpki::Message::IpPrefix(prefix) if prefix.flags & 1 > 0 => {
                            let roa = Arc::new(table::Roa::new(
                                prefix.max_length,
                                prefix.as_number,
                                remote_addr.clone(),
                            ));
                            if end_of_data {
                                tables
                                    .rpki_insert(vec![(prefix.net.clone(), roa.clone())])
                                    .await;
                            } else {
                                v.push((prefix.net, roa));
                            }
                        }
                        rpki::Message::EndOfData { serial_number, .. } => {
                            end_of_data = true;
                            state.serial.store(serial_number, Ordering::Relaxed);
                            tables.rpki_reset(remote_addr.clone(), v.to_owned()).await;
                        }
                        _ => {}
                    }
                }
            }
        }
        state.downtime.store(
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            Ordering::Relaxed,
        );
        tables.rpki_drop_all(remote_addr.clone()).await;
        Ok(())
    }

    pub(crate) fn try_connect(
        sockaddr: SocketAddr,
        cancel: CancellationToken,
        state: Arc<RpkiState>,
        tables: TableHandle,
    ) {
        tokio::spawn(async move {
            loop {
                let stream = tokio::select! {
                    r = tokio::time::timeout(
                        tokio::time::Duration::from_secs(5),
                        TcpStream::connect(sockaddr),
                    ) => match r {
                        Ok(Ok(s)) => s,
                        _ => {
                            tokio::select! {
                                _ = tokio::time::sleep(tokio::time::Duration::from_secs(10)) => {}
                                _ = cancel.cancelled() => return,
                            }
                            continue;
                        }
                    },
                    _ = cancel.cancelled() => return,
                };

                tokio::select! {
                    _ = RpkiClient::serve(stream, cancel.clone(), state.clone(), tables.clone()) => {}
                    _ = cancel.cancelled() => return,
                }

                tokio::select! {
                    _ = tokio::time::sleep(tokio::time::Duration::from_secs(10)) => {}
                    _ = cancel.cancelled() => return,
                }
            }
        });
    }
}
