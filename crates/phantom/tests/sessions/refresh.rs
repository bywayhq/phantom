//! Refresh selects new connections while existing bodies finish.

use std::{future::poll_fn, net::Ipv4Addr, time::Duration};

use bytes::Bytes;
use http::Response;
use http_body_util::BodyExt;
use phantom::HttpProtocol;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    task::JoinSet,
    time::timeout,
};

use super::peer_completion::{self, Peer};
use crate::support::tls::{self, H1_ALPN, H2_ALPN, TestIdentity, TestResult};

#[tokio::test]
async fn refresh_preserves_http1_body_and_resumes_on_a_new_connection() -> TestResult<()> {
    active_tcp(HttpProtocol::Http1, false).await
}

#[tokio::test]
async fn refresh_preserves_http2_body_and_resumes_on_a_new_connection() -> TestResult<()> {
    active_tcp(HttpProtocol::Http2, false).await
}

#[tokio::test]
async fn refresh_preserves_negotiated_http1_body_and_tickets() -> TestResult<()> {
    active_tcp(HttpProtocol::Http1, true).await
}

#[tokio::test]
async fn refresh_preserves_negotiated_http2_body_and_tickets() -> TestResult<()> {
    active_tcp(HttpProtocol::Http2, true).await
}

#[tokio::test]
async fn refresh_preserves_http3_body_on_its_old_connection() -> TestResult<()> {
    type Connection = h3::server::Connection<h3_quinn::Connection, Bytes>;
    let mut peer = None;
    let result = timeout(Duration::from_secs(10), async {
        let identity = TestIdentity::generate()?;
        let (address, endpoint) = crate::support::h3::server_endpoint(&identity)?;
        let (release, released) = oneshot::channel();
        let (done, finished) = oneshot::channel();
        peer = Some(Peer::spawn(async move {
            let incoming = endpoint.accept().await.ok_or("endpoint stopped")?.await?;
            let mut first = Connection::new(h3_quinn::Connection::new(incoming)).await?;
            let request = first.accept().await?.ok_or("first request absent")?;
            let (_, mut body) = request.resolve_request().await?;
            body.send_response(Response::builder().status(200).body(())?).await?;
            body.send_data(Bytes::from_static(b"held")).await?;
            let mut workers = JoinSet::<TestResult<()>>::new();
            workers.spawn(async move {
                tokio::select! {
                    result = released => result?,
                    _ = first.accept() => return Err("old HTTP/3 connection was reused or closed".into()),
                }
                body.send_data(Bytes::from_static(b"-done")).await?;
                body.finish().await?;
                drop(body);
                match first.accept().await {
                    Ok(None) => Ok(()),
                    Err(error) if error.is_h3_no_error() => Ok(()),
                    Ok(Some(_)) => Err("old HTTP/3 connection was reused".into()),
                    Err(error) => Err(error.into()),
                }
            });
            let incoming = endpoint.accept().await.ok_or("endpoint stopped")?.await?;
            let mut second = Connection::new(h3_quinn::Connection::new(incoming)).await?;
            let request = second.accept().await?.ok_or("replacement request absent")?;
            let (_, mut body) = request.resolve_request().await?;
            body.send_response(Response::builder().status(204).body(())?).await?;
            body.finish().await?;
            finished.await?;
            while let Some(result) = workers.join_next().await {
                result??;
            }
            Ok(())
        }));
        let client = phantom::Client::builder(
            phantom::profile::ClientProfile::new(tls::tls_settings())
                .with_http3(crate::support::h3::client_settings()),
        ).add_root_certificate_der(identity.root_der.clone()).build()?;
        let url = format!("https://{address}/");
        let held = client.get(HttpProtocol::Http3, &url)?.send().await?.into_body();
        client.refresh_connections().await;
        let response = client.get(HttpProtocol::Http3, &url)?.send().await?;
        assert_eq!(response.status(), 204);
        response.into_body().collect().await?;
        release.send(()).map_err(|_| "old body cancelled")?;
        assert_eq!(held.collect().await?.to_bytes(), "held-done");
        drop(client);
        done.send(()).map_err(|_| "peer stopped")?;
        peer_completion::join(&mut peer).await?;
        Ok(())
    })
    .await
    .map_err(Into::into)
    .and_then(|result| result);
    peer_completion::finish(result, &mut peer).await
}

async fn active_tcp(protocol: HttpProtocol, negotiated: bool) -> TestResult<()> {
    let mut peer = None;
    let result = timeout(Duration::from_secs(10), async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let url = format!("https://{}/", listener.local_addr()?);
        let acceptor = identity.acceptor(if protocol == HttpProtocol::Http1 {
            H1_ALPN
        } else {
            H2_ALPN
        })?;
        let (release, released) = oneshot::channel();
        peer = Some(Peer::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let mut first = tls::accept_tls_stream(tcp, acceptor.clone()).await?;
            if first.ssl().session_reused() {
                return Err("first handshake resumed".into());
            }
            let mut workers = JoinSet::<TestResult<()>>::new();
            workers.spawn(async move {
                if protocol == HttpProtocol::Http1 {
                    tls::read_head(&mut first).await?;
                    first.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\na").await?;
                    released.await?;
                    first.write_all(b"bcd").await?;
                    let mut byte = [0];
                    if first.read(&mut byte).await? != 0 {
                        return Err("old HTTP/1 connection was reused".into());
                    }
                } else {
                    let mut connection = ::http2::server::handshake(first).await?;
                    let (_, mut respond) = connection.accept().await.ok_or("first request absent")??;
                    let mut body = respond.send_response(Response::builder().status(200).body(())?, false)?;
                    body.send_data(Bytes::from_static(b"a"), false)?;
                    tokio::select! {
                        result = released => result?,
                        _ = connection.accept() => return Err("old HTTP/2 connection was reused or closed".into()),
                    }
                    body.send_data(Bytes::from_static(b"bcd"), true)?;
                    drop(body);
                    drop(respond);
                    poll_fn(|cx| connection.poll_closed(cx)).await?;
                }
                Ok(())
            });
            let (tcp, _) = listener.accept().await?;
            let mut second = tls::accept_tls_stream(tcp, acceptor).await?;
            if !second.ssl().session_reused() {
                return Err("refresh lost the TLS session cache".into());
            }
            if protocol == HttpProtocol::Http1 {
                tls::read_head(&mut second).await?;
                second.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n").await?;
                let mut byte = [0];
                if second.read(&mut byte).await? != 0 {
                    return Err("unexpected second request".into());
                }
            } else {
                let mut connection = ::http2::server::handshake(second).await?;
                let (_, mut respond) = connection.accept().await.ok_or("replacement request absent")??;
                respond.send_response(Response::builder().status(204).body(())?, true)?;
                drop(respond);
                poll_fn(|cx| connection.poll_closed(cx)).await?;
            }
            while let Some(result) = workers.join_next().await {
                result??;
            }
            Ok(())
        }));
        // Both requests must stay admitted while the first body is held.
        let client = tls::client_builder(&identity, protocol == HttpProtocol::Http2 || negotiated)
            .max_concurrent_http1_requests_per_origin(std::num::NonZeroUsize::new(2).ok_or("zero bound")?)
            .build()?;
        let request = || {
            if negotiated {
                client.get_negotiated(&url)
            } else {
                client.get(protocol, &url)
            }
        };
        let held = request()?.send().await?.into_body();
        client.clone().refresh_connections().await;
        let replacement = request()?.send().await?;
        if replacement.status() != 204 {
            return Err("unexpected replacement status".into());
        }
        replacement.into_body().collect().await?;
        release.send(()).map_err(|_| "old body was cancelled")?;
        if held.collect().await?.to_bytes() != "abcd" {
            return Err("old body changed".into());
        }
        drop(client);
        peer_completion::join(&mut peer).await?;
        Ok(())
    })
    .await
    .map_err(Into::into)
    .and_then(|result| result);
    peer_completion::finish(result, &mut peer).await
}
