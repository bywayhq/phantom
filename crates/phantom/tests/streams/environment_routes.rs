//! Environment snapshots on WebSocket tunnels and EventSource reconnects.

use std::{
    future::Future,
    io,
    net::{Ipv4Addr, TcpListener as StdListener},
    time::Duration,
};

use tokio::{net::TcpListener, time::timeout};

use crate::support::tls::TestResult;

fn listen() -> TestResult<StdListener> {
    let listener = StdListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

fn untouched(listener: &StdListener) {
    assert!(matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
}

async fn bounded<F: Future<Output = TestResult<()>>>(future: F) -> TestResult<()> {
    timeout(Duration::from_secs(20), future)
        .await
        .map_err(|_| "environment stream test exceeded its deadline")?
}

#[cfg(feature = "websocket")]
mod websocket {
    use std::error::Error;

    use bytes::Bytes;
    use phantom::{EnvironmentProxies, WebSocketMessage};
    use tokio::io::AsyncWriteExt;

    use super::*;
    use crate::support::{
        tls::{TestIdentity, client_builder, read_head},
        websocket::{append_server_frame, header_value, read_client_frame, websocket_accept},
    };

    #[tokio::test]
    async fn ws_uses_http_environment_tunnels_and_no_proxy_bypasses_them() -> TestResult<()> {
        bounded(async {
            let identity = TestIdentity::generate()?;
            for bypass in [false, true] {
                let origin = listen()?;
                let proxy = listen()?;
                let secure_proxy = listen()?;
                let origin_address = origin.local_addr()?;
                let mut values = vec![
                    ("http_proxy", format!("http://{}", proxy.local_addr()?)),
                    ("https_proxy", format!("http://{}", secure_proxy.local_addr()?)),
                ];
                if bypass {
                    values.push(("no_proxy", format!("127.0.0.1:{}", origin_address.port())));
                }
                let snapshot = EnvironmentProxies::from_values(values)?;
                let (peer, unused) = if bypass { (origin, proxy) } else { (proxy, origin) };
                let listener = TcpListener::from_std(peer)?;
                let server = tokio::spawn(async move {
                    let (mut stream, _) = listener.accept().await?;
                    let connect = if bypass {
                        None
                    } else {
                        let head = read_head(&mut stream).await?;
                        stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
                        Some(head)
                    };
                    let opening = read_head(&mut stream).await?;
                    let key = header_value(&opening, "sec-websocket-key").ok_or("missing WebSocket key")?;
                    let accept = websocket_accept(key);
                    let mut reply = format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").into_bytes();
                    append_server_frame(&mut reply, true, 0x9, b"environment");
                    stream.write_all(&reply).await?;
                    stream.flush().await?;
                    let pong = read_client_frame(&mut stream).await?;
                    Ok::<_, Box<dyn Error + Send + Sync>>((connect, opening, pong))
                });
                let client = client_builder(&identity, false).environment_proxies(snapshot).build()?;
                let mut socket = client.websocket(&format!("ws://{origin_address}/events?source=environment"))?.connect().await?;
                assert_eq!(socket.receive().await?, WebSocketMessage::Ping(Bytes::from_static(b"environment")));
                drop(socket);
                let (connect, opening, pong) = server.await??;
                if bypass {
                    assert!(connect.is_none());
                } else {
                    assert!(connect.ok_or("missing CONNECT")?.starts_with(format!("CONNECT {origin_address} HTTP/1.1\r\n").as_bytes()));
                }
                assert!(opening.starts_with(b"GET /events?source=environment HTTP/1.1\r\n"));
                assert_eq!(header_value(&opening, "host"), Some(origin_address.to_string().as_str()));
                assert_eq!(pong.opcode, 0xA);
                assert_eq!(pong.payload, b"environment");
                untouched(&unused);
                untouched(&secure_proxy);
            }
            Ok(())
        }).await
    }
}

#[cfg(feature = "sse")]
mod sse {
    use std::error::Error;

    use phantom::{EnvironmentProxies, HttpProtocol};
    use tokio::io::AsyncWriteExt;

    use super::*;
    use crate::support::tls::{TestIdentity, client_builder, read_head};

    fn header<'a>(head: &'a [u8], name: &str) -> TestResult<Option<&'a str>> {
        Ok(std::str::from_utf8(head)?
            .lines()
            .skip(1)
            .filter_map(|line| line.split_once(':'))
            .find_map(|(field, value)| field.eq_ignore_ascii_case(name).then(|| value.trim())))
    }

    #[tokio::test]
    async fn event_source_initial_and_reconnect_requests_keep_environment_or_bypass_selection()
    -> TestResult<()> {
        bounded(async {
            let identity = TestIdentity::generate()?;
            for bypass in [false, true] {
                let origin = listen()?;
                let proxy = listen()?;
                let address = origin.local_addr()?;
                let url = format!("http://{address}/events?source=environment");
                let mut values = vec![("http_proxy", format!("http://{}", proxy.local_addr()?))];
                if bypass {
                    values.push(("no_proxy", format!("127.0.0.1:{}", address.port())));
                }
                let snapshot = EnvironmentProxies::from_values(values)?;
                let (peer, unused) = if bypass { (origin, proxy) } else { (proxy, origin) };
                let listener = TcpListener::from_std(peer)?;
                let server = tokio::spawn(async move {
                    let mut heads = Vec::new();
                    let event = "retry: 1\nid: first\ndata: one\n\n";
                    let first_reply = format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{event}", event.len());
                    let replies = [first_reply.as_bytes(), &b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"[..]];
                    for reply in replies {
                        let (mut stream, _) = listener.accept().await?;
                        heads.push(read_head(&mut stream).await?);
                        stream.write_all(reply).await?;
                        stream.shutdown().await?;
                    }
                    Ok::<_, Box<dyn Error + Send + Sync>>(heads)
                });
                let client = client_builder(&identity, false).environment_proxies(snapshot).build()?;
                let mut events = client.event_source(HttpProtocol::Http1, &url)?
                    .initial_retry(Duration::from_millis(1))
                    .min_retry(Duration::ZERO)
                    .max_reconnects(1)
                    .connect().await?.into_body();
                let event = events.next_event().await?.ok_or("missing event")?;
                assert_eq!(event.data(), "one");
                assert_eq!(event.id(), "first");
                assert_eq!(events.next_event().await?, None);
                assert_eq!(events.reconnects(), 1);
                assert!(events.is_closed());
                let heads = server.await??;
                let target = if bypass { "/events?source=environment" } else { &url };
                for head in &heads {
                    assert!(head.starts_with(format!("GET {target} HTTP/1.1\r\n").as_bytes()));
                }
                assert_eq!(header(&heads[0], "last-event-id")?, None);
                assert_eq!(header(&heads[1], "last-event-id")?, Some("first"));
                untouched(&unused);
            }
            Ok(())
        }).await
    }
}
