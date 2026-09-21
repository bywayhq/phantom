//! Public exact-HTTP/3 connection-setup retries over direct and SOCKS5 routes.

#[allow(dead_code)]
#[path = "support/h3.rs"]
mod h3_support;
#[allow(dead_code)]
#[path = "support/socks5_udp.rs"]
mod socks5_udp_support;
#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;
#[path = "support/tracing.rs"]
mod tracing_support;

use std::{
    future::Future,
    net::{Ipv4Addr, SocketAddr, TcpListener as StdTcpListener},
    num::NonZeroUsize,
    time::Duration,
};

use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::BodyExt;
use phantom::{
    Client, HttpProtocol, RequestErrorKind, ResponseInfo, RetryPolicy, Route, Socks5Proxy,
    profile::ClientProfile,
};
use tokio::{
    net::TcpListener,
    sync::oneshot,
    time::{sleep, timeout},
};
use tracing::instrument::WithSubscriber;

use h3_support::{client_settings, server_endpoint};
use socks5_udp_support::{ObservedSocks5UdpRelay, forward_one_socks5_udp_associate};
use tls_support::{TestIdentity, TestResult, tls_settings};
use tracing_support::OutcomeSubscriber;

// Covers a refused Windows loopback TCP connect (about two seconds) plus the
// retry delay; no assertion depends on this wall-clock window.
const TEST_TIMEOUT: Duration = Duration::from_secs(20);
const RETRY_DELAY: Duration = Duration::from_millis(100);
const TRACE_POLL_INTERVAL: Duration = Duration::from_millis(1);

#[tokio::test]
async fn direct_http3_retries_a_refused_quic_handshake_before_dispatch() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let (origin_address, endpoint) = server_endpoint(&identity)?;
        let (client_done, wait_for_client) = oneshot::channel();
        // The first two handshakes are refused with CONNECTION_REFUSED; only
        // the third is accepted, so exactly one request can reach the origin.
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                endpoint
                    .accept()
                    .await
                    .ok_or("HTTP/3 endpoint closed before a refused handshake")?
                    .refuse();
            }
            let (paths, connection) = serve_http3_requests(&endpoint, 1).await?;
            wait_for_client
                .await
                .map_err(|_| "client stopped before HTTP/3 retry completion")?;
            drop(connection);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(paths)
        });
        let uri = format!("https://{origin_address}/retried");

        let without_retry = h3_client(&identity)?;
        let error = match without_retry.get(HttpProtocol::Http3, &uri)?.send().await {
            Ok(response) => {
                return Err(format!("refused handshake returned {}", response.status()).into());
            }
            Err(error) => error,
        };
        assert_eq!(error.protocol(), Some(HttpProtocol::Http3));
        assert_ne!(error.kind(), RequestErrorKind::Timeout);

        let client = h3_client(&identity)?;
        let response = client
            .get(HttpProtocol::Http3, &uri)?
            .retry_policy(RetryPolicy::connection_failures(
                NonZeroUsize::MIN,
                RETRY_DELAY,
            ))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let info = response_info(&response)?;
        assert_eq!(info.protocol(), HttpProtocol::Http3);
        assert_eq!(info.retries_performed(), 1);
        response.into_body().collect().await?;

        drop(client);
        client_done
            .send(())
            .map_err(|_| "HTTP/3 server stopped before client drop")?;
        assert_eq!(server.await??, ["/retried"]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn socks5_http3_retries_a_refused_proxy_connect_before_association() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let (origin_address, endpoint) = server_endpoint(&identity)?;
        let proxy_address = unused_loopback_address()?;
        let (client_done, wait_for_client) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (paths, connection) = serve_http3_requests(&endpoint, 1).await?;
            wait_for_client
                .await
                .map_err(|_| "client stopped before SOCKS5 HTTP/3 retry completion")?;
            drop(connection);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(paths)
        });

        let route = Route::socks5(Socks5Proxy::new(&format!("socks5://{proxy_address}"))?);
        let client = h3_client_builder(&identity)
            .route(route)
            .retry_policy(RetryPolicy::connection_failures(
                NonZeroUsize::MIN,
                RETRY_DELAY,
            ))
            .build()?;
        let subscriber = OutcomeSubscriber::default();
        let request = client
            .get(
                HttpProtocol::Http3,
                &format!("https://{origin_address}/through-proxy"),
            )?
            .send()
            .with_subscriber(subscriber.dispatch());
        let request = tokio::spawn(request);

        // The proxy starts listening only after the refused TCP connect has
        // been classified, so the successful attempt is a new association.
        wait_for_retry_reason(&subscriber).await?;
        let proxy_listener = TcpListener::bind(proxy_address).await?;
        let proxy = tokio::spawn(forward_one_socks5_udp_associate(
            proxy_listener,
            origin_address,
        ));

        let response = request.await??;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let info = response_info(&response)?;
        assert_eq!(info.protocol(), HttpProtocol::Http3);
        assert_eq!(info.retries_performed(), 1);
        response.into_body().collect().await?;
        assert_eq!(subscriber.retries_performed_for("client.request"), [1]);

        drop(client);
        client_done
            .send(())
            .map_err(|_| "SOCKS5 HTTP/3 server stopped before client drop")?;
        assert_eq!(server.await??, ["/through-proxy"]);
        assert_relayed(&proxy.await??);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn socks5_http3_retries_a_refused_quic_handshake_through_a_fresh_association()
-> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let (origin_address, endpoint) = server_endpoint(&identity)?;
        let (client_done, wait_for_client) = oneshot::channel();
        let server = tokio::spawn(async move {
            endpoint
                .accept()
                .await
                .ok_or("HTTP/3 endpoint closed before the refused handshake")?
                .refuse();
            let (paths, connection) = serve_http3_requests(&endpoint, 1).await?;
            wait_for_client
                .await
                .map_err(|_| "client stopped before SOCKS5 HTTP/3 retry completion")?;
            drop(connection);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(paths)
        });

        // Two handles to one listening socket let the fixture serve the
        // failed association to completion before accepting the retry's.
        let first_listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let proxy_address = first_listener.local_addr()?;
        let second_listener = first_listener.try_clone()?;
        first_listener.set_nonblocking(true)?;
        second_listener.set_nonblocking(true)?;
        let proxy = tokio::spawn(async move {
            let failed = forward_one_socks5_udp_associate(
                TcpListener::from_std(first_listener)?,
                origin_address,
            )
            .await?;
            let retried = forward_one_socks5_udp_associate(
                TcpListener::from_std(second_listener)?,
                origin_address,
            )
            .await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((failed, retried))
        });

        let route = Route::socks5(Socks5Proxy::new(&format!("socks5://{proxy_address}"))?);
        let client = h3_client_builder(&identity)
            .route(route)
            .retry_policy(RetryPolicy::connection_failures(
                NonZeroUsize::MIN,
                RETRY_DELAY,
            ))
            .build()?;
        let response = client
            .get(
                HttpProtocol::Http3,
                &format!("https://{origin_address}/fresh-association"),
            )?
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let info = response_info(&response)?;
        assert_eq!(info.protocol(), HttpProtocol::Http3);
        assert_eq!(info.retries_performed(), 1);
        response.into_body().collect().await?;

        drop(client);
        client_done
            .send(())
            .map_err(|_| "SOCKS5 HTTP/3 server stopped before client drop")?;
        assert_eq!(server.await??, ["/fresh-association"]);
        let (failed, retried) = proxy.await??;
        assert_relayed(&failed);
        assert_relayed(&retried);
        assert_ne!(
            failed.association.relay_address,
            retried.association.relay_address
        );
        Ok(())
    })
    .await
}

/// Serves `count` requests on the next accepted connection and returns the
/// connection so the caller controls when it closes.
async fn serve_http3_requests(
    endpoint: &quinn::Endpoint,
    count: usize,
) -> TestResult<(
    Vec<String>,
    h3::server::Connection<h3_quinn::Connection, Bytes>,
)> {
    let incoming = endpoint
        .accept()
        .await
        .ok_or("HTTP/3 endpoint closed before the accepted handshake")?;
    let connection = incoming.await?;
    let mut connection =
        h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection)).await?;
    let mut paths = Vec::with_capacity(count);
    for _ in 0..count {
        let resolver = connection
            .accept()
            .await?
            .ok_or("HTTP/3 connection closed before request")?;
        let (request, mut stream) = resolver.resolve_request().await?;
        paths.push(request.uri().path().to_owned());
        stream
            .send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(())?,
            )
            .await?;
        stream.finish().await?;
    }
    Ok((paths, connection))
}

fn assert_relayed(observed: &ObservedSocks5UdpRelay) {
    assert_eq!(observed.authentication, None);
    assert!(observed.association.relay_address.ip().is_loopback());
    assert!(observed.client_datagrams > 0);
    assert!(observed.origin_datagrams > 0);
}

fn h3_client_builder(identity: &TestIdentity) -> phantom::ClientBuilder {
    let mut tcp_tls = tls_settings();
    tcp_tls.alpn_protocols = vec![Box::from(&b"http/1.1"[..])];
    let profile = ClientProfile::new(tcp_tls).with_http3(client_settings());
    Client::builder(profile).add_root_certificate_der(identity.root_der.clone())
}

fn h3_client(identity: &TestIdentity) -> TestResult<Client> {
    Ok(h3_client_builder(identity).build()?)
}

fn response_info<B>(response: &Response<B>) -> TestResult<&ResponseInfo> {
    Ok(response
        .extensions()
        .get::<ResponseInfo>()
        .ok_or("response omitted ResponseInfo")?)
}

fn unused_loopback_address() -> TestResult<SocketAddr> {
    let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    drop(listener);
    Ok(address)
}

async fn wait_for_retry_reason(subscriber: &OutcomeSubscriber) -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        loop {
            if subscriber.retry_reasons_for("client.request") == ["connection_setup"] {
                return;
            }
            sleep(TRACE_POLL_INTERVAL).await;
        }
    })
    .await
    .map_err(|_| "request did not report its refused proxy connect")?;
    Ok(())
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "HTTP/3 retry test exceeded its deadline")?
}
