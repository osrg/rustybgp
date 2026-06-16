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
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU16, AtomicU32, AtomicU64, Ordering};
use std::time::SystemTime;
use tokio::net::TcpStream;
use tokio::sync::Notify;
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
    session_id: AtomicU16,
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
    fn update(&self, msg: &rpki::Message) {
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
    pub(crate) disabled: bool,
    pub(crate) soft_reset: Arc<Notify>,
}

impl RpkiClient {
    pub(crate) fn new() -> Self {
        RpkiClient {
            cancel: CancellationToken::new(),
            state: Arc::new(RpkiState::default()),
            disabled: false,
            soft_reset: Arc::new(Notify::new()),
        }
    }

    async fn serve(
        stream: TcpStream,
        cancel: CancellationToken,
        soft_reset: Arc<Notify>,
        state: Arc<RpkiState>,
        tables: TableHandle,
    ) -> Result<(), Error> {
        let remote_addr = Arc::new(stream.peer_addr()?.ip());
        let lines = Framed::new(stream, rpki::RtrCodec::new());
        Self::serve_inner(lines, remote_addr, cancel, soft_reset, state, tables).await
    }

    async fn serve_inner<IO>(
        mut lines: Framed<IO, rpki::RtrCodec>,
        remote_addr: Arc<IpAddr>,
        cancel: CancellationToken,
        soft_reset: Arc<Notify>,
        state: Arc<RpkiState>,
        tables: TableHandle,
    ) -> Result<(), Error>
    where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
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
                _ = soft_reset.notified(), if end_of_data => {
                    let session_id = state.session_id.load(Ordering::Relaxed);
                    let serial_number = state.serial.load(Ordering::Relaxed);
                    state.update(&rpki::Message::SerialQuery { session_id, serial_number });
                    let _ = lines.send(&rpki::Message::SerialQuery { session_id, serial_number }).await;
                }
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
                        rpki::Message::SerialNotify { serial_number, .. }
                            if end_of_data
                                && serial_number != state.serial.load(Ordering::Relaxed) =>
                        {
                            let session_id = state.session_id.load(Ordering::Relaxed);
                            let current_serial = state.serial.load(Ordering::Relaxed);
                            state.update(&rpki::Message::SerialQuery {
                                session_id,
                                serial_number: current_serial,
                            });
                            let _ = lines
                                .send(&rpki::Message::SerialQuery {
                                    session_id,
                                    serial_number: current_serial,
                                })
                                .await;
                        }
                        rpki::Message::CacheResponse { session_id } => {
                            state.session_id.store(session_id, Ordering::Relaxed);
                        }
                        rpki::Message::IpPrefix(prefix) => {
                            let roa = Arc::new(table::Roa::new(
                                prefix.max_length,
                                prefix.as_number,
                                remote_addr.clone(),
                            ));
                            if prefix.flags & 1 > 0 {
                                if end_of_data {
                                    tables
                                        .rpki_insert(vec![(prefix.net.clone(), roa)])
                                        ;
                                } else {
                                    v.push((prefix.net, roa));
                                }
                            } else if end_of_data {
                                tables
                                    .rpki_withdraw(vec![(prefix.net.clone(), roa)])
                                    ;
                            }
                        }
                        rpki::Message::EndOfData { serial_number, .. } => {
                            end_of_data = true;
                            state.serial.store(serial_number, Ordering::Relaxed);
                            tables.rpki_reset(remote_addr.clone(), v.to_owned());
                        }
                        _ => {}
                    }
                }
            }
        }
        state.up.store(false, Ordering::Relaxed);
        state.downtime.store(
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            Ordering::Relaxed,
        );
        tables.rpki_drop_all(remote_addr.clone());
        Ok(())
    }

    pub(crate) fn try_connect(
        sockaddr: SocketAddr,
        cancel: CancellationToken,
        soft_reset: Arc<Notify>,
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
                    _ = RpkiClient::serve(stream, cancel.clone(), soft_reset.clone(), state.clone(), tables.clone()) => {}
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

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{SinkExt, StreamExt};
    use std::net::{IpAddr, Ipv4Addr};
    use tokio_util::codec::Framed;

    use crate::table_manager::TableManager;

    fn make_tables() -> TableHandle {
        Arc::new(TableManager::new(1))
    }

    fn spawn_serve_inner(
        client_io: tokio::io::DuplexStream,
        state: Arc<RpkiState>,
        cancel: CancellationToken,
        soft_reset: Arc<Notify>,
    ) -> tokio::task::JoinHandle<Result<(), Error>> {
        let remote_addr = Arc::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)));
        let framed = Framed::new(client_io, rpki::RtrCodec::new());
        let tables = make_tables();
        tokio::spawn(async move {
            RpkiClient::serve_inner(framed, remote_addr, cancel, soft_reset, state, tables).await
        })
    }

    fn end_of_data(session_id: u16, serial_number: u32) -> rpki::Message {
        rpki::Message::EndOfData {
            session_id,
            serial_number,
            refresh_interval: 0,
            retry_interval: 0,
            expire_interval: 0,
        }
    }

    #[tokio::test]
    async fn sends_reset_query_on_connect() {
        let (client_io, server_io) = tokio::io::duplex(4096);
        let state = Arc::new(RpkiState::default());
        let cancel = CancellationToken::new();
        let soft_reset = Arc::new(Notify::new());

        let handle = spawn_serve_inner(client_io, state, cancel.clone(), soft_reset);

        let mut server = Framed::new(server_io, rpki::RtrCodec::new());
        let msg = server.next().await.unwrap().unwrap();
        assert!(matches!(msg, rpki::Message::ResetQuery));

        cancel.cancel();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn cache_response_stores_session_id() {
        let (client_io, server_io) = tokio::io::duplex(4096);
        let state = Arc::new(RpkiState::default());
        let cancel = CancellationToken::new();
        let soft_reset = Arc::new(Notify::new());

        let handle = spawn_serve_inner(client_io, state.clone(), cancel.clone(), soft_reset);

        let mut server = Framed::new(server_io, rpki::RtrCodec::new());
        let _ = server.next().await.unwrap().unwrap(); // ResetQuery
        server
            .send(&rpki::Message::CacheResponse { session_id: 42 })
            .await
            .unwrap();

        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        assert_eq!(state.session_id.load(Ordering::Relaxed), 42);

        cancel.cancel();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn end_of_data_stores_serial() {
        let (client_io, server_io) = tokio::io::duplex(4096);
        let state = Arc::new(RpkiState::default());
        let cancel = CancellationToken::new();
        let soft_reset = Arc::new(Notify::new());

        let handle = spawn_serve_inner(client_io, state.clone(), cancel.clone(), soft_reset);

        let mut server = Framed::new(server_io, rpki::RtrCodec::new());
        let _ = server.next().await.unwrap().unwrap(); // ResetQuery
        server
            .send(&rpki::Message::CacheResponse { session_id: 1 })
            .await
            .unwrap();
        server.send(&end_of_data(1, 999)).await.unwrap();

        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        assert_eq!(state.serial.load(Ordering::Relaxed), 999);

        cancel.cancel();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn soft_reset_sends_serial_query_after_end_of_data() {
        let (client_io, server_io) = tokio::io::duplex(4096);
        let state = Arc::new(RpkiState::default());
        let cancel = CancellationToken::new();
        let soft_reset = Arc::new(Notify::new());

        let handle =
            spawn_serve_inner(client_io, state.clone(), cancel.clone(), soft_reset.clone());

        let mut server = Framed::new(server_io, rpki::RtrCodec::new());
        let _ = server.next().await.unwrap().unwrap(); // ResetQuery
        server
            .send(&rpki::Message::CacheResponse { session_id: 7 })
            .await
            .unwrap();
        server.send(&end_of_data(7, 100)).await.unwrap();

        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        soft_reset.notify_one();

        let msg = server.next().await.unwrap().unwrap();
        match msg {
            rpki::Message::SerialQuery {
                session_id,
                serial_number,
            } => {
                assert_eq!(session_id, 7);
                assert_eq!(serial_number, 100);
            }
            _ => panic!(
                "expected SerialQuery, got {:?}",
                std::mem::discriminant(&msg)
            ),
        }

        cancel.cancel();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn soft_reset_before_sync_fires_after_end_of_data() {
        let (client_io, server_io) = tokio::io::duplex(4096);
        let state = Arc::new(RpkiState::default());
        let cancel = CancellationToken::new();
        let soft_reset = Arc::new(Notify::new());

        let handle =
            spawn_serve_inner(client_io, state.clone(), cancel.clone(), soft_reset.clone());

        let mut server = Framed::new(server_io, rpki::RtrCodec::new());
        let _ = server.next().await.unwrap().unwrap(); // ResetQuery

        // Notify before the initial sync is complete; the guard (if end_of_data)
        // suppresses the arm until EndOfData is processed.
        soft_reset.notify_one();

        server
            .send(&rpki::Message::CacheResponse { session_id: 3 })
            .await
            .unwrap();
        server.send(&end_of_data(3, 50)).await.unwrap();

        // The stored notification fires once end_of_data becomes true.
        let msg = server.next().await.unwrap().unwrap();
        match msg {
            rpki::Message::SerialQuery {
                session_id,
                serial_number,
            } => {
                assert_eq!(session_id, 3);
                assert_eq!(serial_number, 50);
            }
            _ => panic!(
                "expected SerialQuery, got {:?}",
                std::mem::discriminant(&msg)
            ),
        }

        cancel.cancel();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn state_up_false_after_serve_exits() {
        let (client_io, server_io) = tokio::io::duplex(4096);
        let state = Arc::new(RpkiState::default());
        let cancel = CancellationToken::new();
        let soft_reset = Arc::new(Notify::new());

        let handle = spawn_serve_inner(client_io, state.clone(), cancel, soft_reset);

        let mut server = Framed::new(server_io, rpki::RtrCodec::new());
        let _ = server.next().await.unwrap().unwrap(); // ResetQuery

        // Dropping the server side signals EOF to serve_inner, which exits the loop.
        drop(server);
        handle.await.unwrap().unwrap();

        assert!(!state.up.load(Ordering::Relaxed));
    }
}
