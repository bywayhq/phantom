//! Public close-idle connection ownership and ticket retention.

use std::{future::poll_fn, net::Ipv4Addr, time::Duration};

use btls::ssl::SslAcceptor;
use bytes::Bytes;
use http::Response;
use http_body_util::BodyExt;
use phantom::{Client, HttpProtocol};
use tokio::{io::AsyncReadExt, io::AsyncWriteExt, net::TcpListener, sync::oneshot, time::timeout};

use super::peer_completion::{self, Peer};
use crate::support::tls::{self, H1_ALPN, H2_ALPN, TestIdentity, TestResult};

mod http3;

const DEADLINE: Duration = Duration::from_secs(10);

#[tokio::test]
async fn close_idle_replaces_http1_connections_and_retains_tickets() -> TestResult<()> {
    replaces_idle(HttpProtocol::Http1, false).await
}

#[tokio::test]
async fn close_idle_replaces_http2_connections_and_retains_tickets() -> TestResult<()> {
    replaces_idle(HttpProtocol::Http2, false).await
}

#[tokio::test]
async fn close_idle_replaces_negotiated_http1_connections() -> TestResult<()> {
    replaces_idle(HttpProtocol::Http1, true).await
}

#[tokio::test]
async fn close_idle_replaces_negotiated_http2_connections() -> TestResult<()> {
    replaces_idle(HttpProtocol::Http2, true).await
}

async fn replaces_idle(protocol: HttpProtocol, negotiated: bool) -> TestResult<()> {
    let mut peer = None;
    let result = timeout(DEADLINE, async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let url = format!("https://{}/", listener.local_addr()?);
        let acceptor = identity.acceptor(if protocol == HttpProtocol::Http1 {
            H1_ALPN
        } else {
            H2_ALPN
        })?;
        let (done, finished) = oneshot::channel();
        peer = Some(Peer::spawn(async move {
            for resumed in [false, true] {
                let (tcp, _) = listener.accept().await?;
                let mut stream = tls::accept_tls_stream(tcp, acceptor.clone()).await?;
                if stream.ssl().session_reused() != resumed {
                    return Err("close-idle did not retain the TLS session ticket".into());
                }
                if protocol == HttpProtocol::Http1 {
                    tls::read_head(&mut stream).await?;
                    stream
                        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                        .await?;
                    let mut byte = [0];
                    if stream.read(&mut byte).await? != 0 {
                        return Err("idle HTTP/1 connection received another request".into());
                    }
                } else {
                    let mut connection = ::http2::server::handshake(stream).await?;
                    let (_, mut respond) = connection.accept().await.ok_or("missing request")??;
                    respond.send_response(Response::builder().status(204).body(())?, true)?;
                    drop(respond);
                    poll_fn(|cx| connection.poll_closed(cx)).await?;
                }
            }
            done.send(()).map_err(|_| "caller stopped")?;
            Ok(())
        }));
        let client = tls::test_client(&identity, protocol == HttpProtocol::Http2 || negotiated)?;
        send(&client, protocol, negotiated, &url).await?;
        client.clone().close_idle_connections().await;
        send(&client, protocol, negotiated, &url).await?;
        client.close_idle_connections().await;
        finished.await?;
        peer_completion::join(&mut peer).await?;
        Ok(())
    })
    .await
    .map_err(Into::into)
    .and_then(|r| r);
    peer_completion::finish(result, &mut peer).await
}

#[tokio::test]
async fn close_idle_preserves_http1_active_body_and_reuse() -> TestResult<()> {
    let mut peer = None;
    let result = timeout(DEADLINE, async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let url = format!("https://{}/", listener.local_addr()?);
        let acceptor = identity.acceptor(H1_ALPN)?;
        let (release, released) = oneshot::channel();
        peer = Some(Peer::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let mut stream = tls::accept_tls_stream(tcp, acceptor).await?;
            tls::read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\na")
                .await?;
            released.await?;
            stream.write_all(b"bcd").await?;
            tls::read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            Ok(())
        }));
        let client = tls::test_client(&identity, false)?;
        let body = client
            .get_with_protocol(HttpProtocol::Http1, &url)?
            .send()
            .await?
            .into_body();
        client.close_idle_connections().await;
        release.send(()).map_err(|_| "peer stopped")?;
        if body.collect().await?.to_bytes() != "abcd" {
            return Err("active response body changed".into());
        }
        send(&client, HttpProtocol::Http1, false, &url).await?;
        peer_completion::join(&mut peer).await?;
        Ok(())
    })
    .await
    .map_err(Into::into)
    .and_then(|r| r);
    peer_completion::finish(result, &mut peer).await
}

#[tokio::test]
async fn close_idle_preserves_http2_active_body_and_multiplexing() -> TestResult<()> {
    active_http2(false).await
}

#[tokio::test]
async fn close_idle_preserves_negotiated_http2_active_body() -> TestResult<()> {
    active_http2(true).await
}

async fn active_http2(negotiated: bool) -> TestResult<()> {
    let mut peer = None;
    let result = timeout(DEADLINE, async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let url = format!("https://{}/", listener.local_addr()?);
        let acceptor: SslAcceptor = identity.acceptor(H2_ALPN)?;
        peer = Some(Peer::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let stream = tls::accept_tls_stream(tcp, acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            let (_, mut first) = connection.accept().await.ok_or("missing first request")??;
            let mut body = first.send_response(Response::builder().status(200).body(())?, false)?;
            body.send_data(Bytes::from_static(b"held"), false)?;
            let (_, mut second) = connection
                .accept()
                .await
                .ok_or("active connection closed")??;
            second.send_response(Response::builder().status(204).body(())?, true)?;
            body.send_data(Bytes::from_static(b"-done"), true)?;
            drop(body);
            drop(first);
            drop(second);
            poll_fn(|cx| connection.poll_closed(cx)).await?;
            Ok(())
        }));
        let client = tls::test_client(&identity, true)?;
        let request = if negotiated {
            client.get(&url)?
        } else {
            client.get_with_protocol(HttpProtocol::Http2, &url)?
        };
        let held = request.send().await?.into_body();
        client.clone().close_idle_connections().await;
        send(&client, HttpProtocol::Http2, negotiated, &url).await?;
        if held.collect().await?.to_bytes() != "held-done" {
            return Err("active multiplexed response changed".into());
        }
        drop(client);
        peer_completion::join(&mut peer).await?;
        Ok(())
    })
    .await
    .map_err(Into::into)
    .and_then(|r| r);
    peer_completion::finish(result, &mut peer).await
}

async fn send(
    client: &Client,
    protocol: HttpProtocol,
    negotiated: bool,
    url: &str,
) -> TestResult<()> {
    let request = if negotiated {
        client.get(url)?
    } else {
        client.get_with_protocol(protocol, url)?
    };
    let response = request.send().await?;
    if response.status() != 204 {
        return Err("unexpected response status".into());
    }
    response.into_body().collect().await?;
    Ok(())
}
