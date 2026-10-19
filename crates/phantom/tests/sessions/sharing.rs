//! Forks keep connections and shutdown independent while retaining settings.

use std::{
    future::poll_fn,
    net::{IpAddr, Ipv4Addr},
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use http::Response;
use phantom::{
    AddressResolver, Client, HttpProtocol, RequestErrorKind, RequestTimeouts, ResponseBody,
    SessionSharing, TimeoutPhase,
    profile::{ClientProfile, browser::chrome},
};
use tokio::{io::AsyncWriteExt, net::TcpListener, task::JoinSet, time::timeout};

use super::peer_completion::{self, Peer};
use crate::support::tls::{self, H1_ALPN, H2_ALPN, TestIdentity, TestResult};

#[tokio::test]
async fn fork_uses_its_own_http1_connection_and_shutdown() -> TestResult<()> {
    tcp_pools(HttpProtocol::Http1, false).await
}

#[tokio::test]
async fn fork_uses_its_own_http2_connection_and_shutdown() -> TestResult<()> {
    tcp_pools(HttpProtocol::Http2, false).await
}

#[tokio::test]
async fn fork_uses_its_own_negotiated_http1_connection() -> TestResult<()> {
    tcp_pools(HttpProtocol::Http1, true).await
}

#[tokio::test]
async fn fork_uses_its_own_negotiated_http2_connection() -> TestResult<()> {
    tcp_pools(HttpProtocol::Http2, true).await
}

async fn get(
    client: &Client,
    url: &str,
    protocol: HttpProtocol,
    negotiated: bool,
) -> TestResult<Bytes> {
    let request = if negotiated {
        client.get_negotiated(url)?
    } else {
        client.get(protocol, url)?
    };
    Ok(request
        .send()
        .await?
        .into_body()
        .collect_with_limit(1)
        .await?)
}

async fn hold_saturated(
    client: &Client,
    url: &str,
    protocol: HttpProtocol,
    negotiated: bool,
) -> TestResult<Response<ResponseBody>> {
    let request = || {
        if negotiated {
            client.get_negotiated(url)
        } else {
            client.get(protocol, url)
        }
    };
    let held = request()?.send().await?;
    let error = request()?
        .send()
        .await
        .err()
        .ok_or("source admission was not saturated by the unread body")?;
    assert_eq!(error.kind(), RequestErrorKind::Timeout);
    assert_eq!(error.timeout_phase(), Some(TimeoutPhase::PoolAdmission));
    Ok(held)
}

async fn tcp_pools(protocol: HttpProtocol, negotiated: bool) -> TestResult<()> {
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
        peer = Some(Peer::spawn(async move {
            let mut workers = JoinSet::<TestResult<()>>::new();
            for (id, resumed) in [(b'1', false), (b'2', false), (b'3', true)] {
                let (tcp, _) = listener.accept().await?;
                let acceptor = acceptor.clone();
                workers.spawn(async move {
                    let mut stream = tls::accept_tls_stream(tcp, acceptor).await?;
                    if stream.ssl().session_reused() != resumed {
                        return Err(
                            "fork ticket isolation or source ticket retention failed".into()
                        );
                    }
                    if protocol == HttpProtocol::Http1 {
                        loop {
                            match tls::read_head(&mut stream).await {
                                Ok(_) => {}
                                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                                    break;
                                }
                                Err(error) => return Err(error.into()),
                            }
                            stream
                                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n")
                                .await?;
                            stream.write_all(&[id]).await?;
                        }
                    } else {
                        let mut connection = ::http2::server::handshake(stream).await?;
                        while let Some(request) = connection.accept().await {
                            let (_, mut respond) = request?;
                            let mut body = respond
                                .send_response(Response::builder().status(200).body(())?, false)?;
                            body.send_data(Bytes::copy_from_slice(&[id]), true)?;
                        }
                        poll_fn(|cx| connection.poll_closed(cx)).await?;
                    }
                    Ok(())
                });
            }
            while let Some(result) = workers.join_next().await {
                result??;
            }
            Ok(())
        }));
        let original = tls::client_builder(&identity, true)
            .max_concurrent_http1_requests_per_origin(NonZeroUsize::MIN)
            .max_concurrent_http2_requests_per_origin(NonZeroUsize::MIN)
            .request_timeouts(RequestTimeouts::new().pool_admission(Duration::from_millis(100)))
            .build()?;
        assert_eq!(get(&original, &url, protocol, negotiated).await?, "1");
        let held = hold_saturated(&original, &url, protocol, negotiated).await?;
        let fork = original.fork(SessionSharing::none());
        assert_eq!(get(&fork, &url, protocol, negotiated).await?, "2");
        fork.shutdown().await;
        assert!(!original.is_closed());
        assert_eq!(held.into_body().collect_with_limit(1).await?, "1");
        assert_eq!(get(&original, &url, protocol, negotiated).await?, "1");
        original.close_idle_connections().await;
        assert_eq!(get(&original, &url, protocol, negotiated).await?, "3");
        original.shutdown().await;
        peer_completion::join(&mut peer).await?;
        Ok(())
    })
    .await
    .map_err(Into::into)
    .and_then(|result| result);
    peer_completion::finish(result, &mut peer).await
}

#[tokio::test]
async fn fork_uses_its_own_http3_connection_and_shutdown() -> TestResult<()> {
    type Connection = h3::server::Connection<h3_quinn::Connection, Bytes>;
    let mut peer = None;
    let result = timeout(Duration::from_secs(10), async {
        let identity = TestIdentity::generate()?;
        let (address, endpoint) = crate::support::h3::server_endpoint(&identity)?;
        peer = Some(Peer::spawn(async move {
            let mut workers = JoinSet::<TestResult<()>>::new();
            for id in *b"12" {
                let incoming = endpoint.accept().await.ok_or("endpoint stopped")?.await?;
                workers.spawn(async move {
                    let mut connection =
                        Connection::new(h3_quinn::Connection::new(incoming)).await?;
                    loop {
                        let request = match connection.accept().await {
                            Ok(Some(request)) => request,
                            Ok(None) => break,
                            Err(error) if error.is_h3_no_error() => break,
                            Err(error) => return Err(error.into()),
                        };
                        let (_, mut stream) = request.resolve_request().await?;
                        stream
                            .send_response(Response::builder().status(200).body(())?)
                            .await?;
                        stream.send_data(Bytes::copy_from_slice(&[id])).await?;
                        stream.finish().await?;
                    }
                    Ok(())
                });
            }
            while let Some(result) = workers.join_next().await {
                result??;
            }
            Ok(())
        }));
        let original = Client::builder(
            ClientProfile::new(tls::tls_settings())
                .with_http3(crate::support::h3::client_settings()),
        )
        .add_root_certificate_der(identity.root_der.clone())
        .max_concurrent_http3_requests_per_origin(NonZeroUsize::MIN)
        .request_timeouts(RequestTimeouts::new().pool_admission(Duration::from_millis(100)))
        .build()?;
        let url = format!("https://{address}/");
        assert_eq!(get(&original, &url, HttpProtocol::Http3, false).await?, "1");
        let held = hold_saturated(&original, &url, HttpProtocol::Http3, false).await?;
        let fork = original.fork(SessionSharing::none());
        assert_eq!(get(&fork, &url, HttpProtocol::Http3, false).await?, "2");
        fork.shutdown().await;
        assert!(!original.is_closed());
        assert_eq!(held.into_body().collect_with_limit(1).await?, "1");
        assert_eq!(get(&original, &url, HttpProtocol::Http3, false).await?, "1");
        original.shutdown().await;
        peer_completion::join(&mut peer).await?;
        Ok(())
    })
    .await
    .map_err(Into::into)
    .and_then(|result| result);
    peer_completion::finish(result, &mut peer).await
}

#[tokio::test]
async fn selected_dns_cache_shares_answers_and_clearing_across_independent_connections()
-> TestResult<()> {
    let mut peer = None;
    let result = timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let url = format!("http://fork.example:{}/", listener.local_addr()?.port());
        peer = Some(Peer::spawn(async move {
            for _ in 0..4 {
                let (mut stream, _) = listener.accept().await?;
                tls::read_head(&mut stream).await?;
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx",
                    )
                    .await?;
            }
            Ok(())
        }));
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver = AddressResolver::from_fn({
            let calls = Arc::clone(&calls);
            move |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]) }
            }
        });
        let original = Client::builder(
            ClientProfile::new(chrome::v154_tcp_tls()).with_http1(chrome::v154_http1()),
        )
        .dns_cache(chrome::v154_dns_cache())
        .dns_resolver(resolver)
        .build()?;
        let shared = original.fork(SessionSharing::none().dns(true));
        let isolated = original.fork(SessionSharing::none());
        for client in [&original, &shared] {
            assert_eq!(get(client, &url, HttpProtocol::Http1, false).await?, "x");
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(get(&isolated, &url, HttpProtocol::Http1, false).await?, "x");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        shared.clear_dns_cache();
        assert_eq!(get(&original, &url, HttpProtocol::Http1, false).await?, "x");
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        peer_completion::join(&mut peer).await?;
        Ok(())
    })
    .await
    .map_err(Into::into)
    .and_then(|result| result);
    peer_completion::finish(result, &mut peer).await
}
