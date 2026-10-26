//! Shutdown closes admission while existing transport owners finish.

use std::{
    future::{Future, poll_fn},
    net::Ipv4Addr,
    task::Poll,
    time::Duration,
};

use bytes::Bytes;
use http::Response;
use phantom::{Client, HttpProtocol, RequestErrorKind};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    time::timeout,
};

use super::peer_completion::{self, Peer};
use crate::support::tls::{self, H1_ALPN, H2_ALPN, TestIdentity, TestResult};

#[tokio::test]
async fn shutdown_preserves_http1_body_and_rejects_clone_requests() -> TestResult<()> {
    active_tcp(HttpProtocol::Http1).await
}

#[tokio::test]
async fn shutdown_preserves_http2_body_and_rejects_clone_requests() -> TestResult<()> {
    active_tcp(HttpProtocol::Http2).await
}

async fn active_tcp(protocol: HttpProtocol) -> TestResult<()> {
    let mut peer = None;
    let result = timeout(Duration::from_secs(10), async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let url = format!("https://{}/", listener.local_addr()?);
        let acceptor = identity.acceptor(if protocol == HttpProtocol::Http1 { H1_ALPN } else { H2_ALPN })?;
        let (release, released) = oneshot::channel();
        peer = Some(Peer::spawn(async move {
            let mut stream = tls::accept_tls(listener, acceptor).await?;
            if protocol == HttpProtocol::Http1 {
                tls::read_head(&mut stream).await?;
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\na").await?;
                released.await?;
                stream.write_all(b"bcd").await?;
                let mut byte = [0];
                assert_eq!(stream.read(&mut byte).await?, 0);
            } else {
                let mut connection = ::http2::server::handshake(stream).await?;
                let (_, mut respond) = connection.accept().await.ok_or("request absent")??;
                let mut body = respond.send_response(Response::builder().status(200).body(())?, false)?;
                body.send_data(Bytes::from_static(b"a"), false)?;
                tokio::select! {
                    result = released => result?,
                    _ = connection.accept() => return Err("active connection closed or reused".into()),
                }
                body.send_data(Bytes::from_static(b"bcd"), true)?;
                drop(body);
                drop(respond);
                poll_fn(|cx| connection.poll_closed(cx)).await?;
            }
            Ok(())
        }));
        let client = tls::client_builder(&identity, protocol == HttpProtocol::Http2).build()?;
        let clone = client.clone();
        let prepared = clone.get_with_protocol(protocol, &url)?;
        let body = client.get_with_protocol(protocol, &url)?.send().await?.into_body();
        let shutdown = client.shutdown();
        tokio::pin!(shutdown);
        assert!(matches!(poll_fn(|cx| Poll::Ready(shutdown.as_mut().poll(cx))).await, Poll::Pending));
        assert!(clone.is_closed());
        let error = prepared.send().await.err().ok_or("closed client sent prepared request")?;
        assert_eq!(error.kind(), RequestErrorKind::ClientClosed);
        release.send(()).map_err(|_| "active body was cancelled")?;
        assert_eq!(body.collect_with_limit(4).await?, "abcd");
        shutdown.await;
        peer_completion::join(&mut peer).await?;
        Ok(())
    }).await.map_err(Into::into).and_then(|result| result);
    peer_completion::finish(result, &mut peer).await
}

#[tokio::test]
async fn shutdown_preserves_http3_body() -> TestResult<()> {
    let mut peer = None;
    let result = timeout(Duration::from_secs(10), async {
        let identity = TestIdentity::generate()?;
        let (address, endpoint) = crate::support::h3::server_endpoint(&identity)?;
        let (release, released) = oneshot::channel();
        peer = Some(Peer::spawn(async move {
            let incoming = endpoint.accept().await.ok_or("endpoint stopped")?.await?;
            let mut connection =
                h3::server::Connection::new(h3_quinn::Connection::new(incoming)).await?;
            let request = connection.accept().await?.ok_or("request absent")?;
            let (_, mut body) = request.resolve_request().await?;
            body.send_response(Response::builder().status(200).body(())?)
                .await?;
            body.send_data(Bytes::from_static(b"a")).await?;
            tokio::select! {
                result = released => result?,
                _ = connection.accept() => return Err("active connection closed or reused".into()),
            }
            body.send_data(Bytes::from_static(b"bcd")).await?;
            body.finish().await?;
            drop(body);
            match connection.accept().await {
                Ok(None) => Ok(()),
                Err(error) if error.is_h3_no_error() => Ok(()),
                Ok(Some(_)) => Err("closed client sent another request".into()),
                Err(error) => Err(error.into()),
            }
        }));
        let client = Client::builder(
            phantom::profile::ClientProfile::new(tls::tls_settings())
                .with_http3(crate::support::h3::client_settings()),
        )
        .add_root_certificate_der(identity.root_der.clone())
        .build()?;
        let body = client
            .get_with_protocol(HttpProtocol::Http3, &format!("https://{address}/"))?
            .send()
            .await?
            .into_body();
        let shutdown = client.shutdown();
        tokio::pin!(shutdown);
        assert!(matches!(
            poll_fn(|cx| Poll::Ready(shutdown.as_mut().poll(cx))).await,
            Poll::Pending
        ));
        release.send(()).map_err(|_| "active body was cancelled")?;
        assert_eq!(body.collect_with_limit(4).await?, "abcd");
        shutdown.await;
        peer_completion::join(&mut peer).await?;
        Ok(())
    })
    .await
    .map_err(Into::into)
    .and_then(|result| result);
    peer_completion::finish(result, &mut peer).await
}

#[tokio::test]
#[cfg(feature = "websocket")]
async fn shutdown_rejects_websocket_openings() -> TestResult<()> {
    let client =
        Client::builder(phantom::profile::ClientProfile::new(tls::tls_settings())).build()?;
    client.shutdown().await;
    let error = client
        .websocket("ws://127.0.0.1:1/")?
        .connect()
        .await
        .err()
        .ok_or("closed client opened a WebSocket")?;
    assert_eq!(error.kind(), phantom::WebSocketErrorKind::ClientClosed);
    Ok(())
}

#[tokio::test]
async fn cancelled_dns_setup_releases_shutdown_waiter() -> TestResult<()> {
    timeout(Duration::from_secs(10), async {
        let entered = std::sync::Arc::new(tokio::sync::Notify::new());
        let signal = entered.clone();
        let resolver = phantom::AddressResolver::from_fn(move |_| {
            let signal = signal.clone();
            async move {
                signal.notify_one();
                std::future::pending::<std::io::Result<Vec<std::net::IpAddr>>>().await
            }
        });
        let client = Client::builder(phantom::profile::ClientProfile::new(tls::tls_settings()))
            .dns_resolver(resolver)
            .build()?;
        let mut request = Box::pin(
            client
                .get_with_protocol(HttpProtocol::Http1, "http://shutdown.phantom.test/")?
                .send(),
        );
        tokio::select! {
            _ = entered.notified() => {},
            _ = &mut request => return Err("request ended before resolver blocked".into()),
        }
        let shutdown = client.shutdown();
        tokio::pin!(shutdown);
        assert!(matches!(
            poll_fn(|cx| Poll::Ready(shutdown.as_mut().poll(cx))).await,
            Poll::Pending
        ));
        drop(request);
        shutdown.await;
        Ok(())
    })
    .await?
}

#[tokio::test]
#[cfg(feature = "websocket")]
async fn shutdown_waits_for_established_websocket() -> TestResult<()> {
    websocket_owner(true).await
}

#[tokio::test]
#[cfg(feature = "websocket")]
async fn shutdown_waits_for_rejected_websocket_response_body() -> TestResult<()> {
    websocket_owner(false).await
}

#[cfg(feature = "websocket")]
async fn websocket_owner(accept: bool) -> TestResult<()> {
    let mut peer = None;
    let result = timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let url = format!("ws://{}/socket", listener.local_addr()?);
        peer = Some(Peer::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let head = tls::read_head(&mut stream).await?;
            if accept {
                let key = crate::support::websocket::header_value(&head, "sec-websocket-key").ok_or("opening key missing")?;
                let accepted = crate::support::websocket::websocket_accept(key);
                stream.write_all(format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accepted}\r\n\r\n").as_bytes()).await?;
            } else {
                stream.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 1\r\n\r\n").await?;
            }
            let mut byte = [0];
            assert_eq!(stream.read(&mut byte).await?, 0);
            Ok(())
        }));
        let client = Client::builder(phantom::profile::ClientProfile::new(tls::tls_settings())).build()?;
        let opening = client.websocket(&url)?.connect().await;
        let (socket, rejection) = if accept {
            (Some(opening?), None)
        } else {
            let error = opening.err().ok_or("rejected opening succeeded")?;
            assert_eq!(error.kind(), phantom::WebSocketErrorKind::HandshakeRejected);
            (None, Some(error))
        };
        let shutdown = client.shutdown();
        tokio::pin!(shutdown);
        assert!(matches!(poll_fn(|cx| Poll::Ready(shutdown.as_mut().poll(cx))).await, Poll::Pending));
        drop((socket, rejection));
        shutdown.await;
        peer_completion::join(&mut peer).await?;
        Ok(())
    }).await.map_err(Into::into).and_then(|result| result);
    peer_completion::finish(result, &mut peer).await
}
