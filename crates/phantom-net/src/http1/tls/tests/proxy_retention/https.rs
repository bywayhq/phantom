//! Actual outer TLS and claimant-owned CONNECT; no OS race timing assertion.
use std::{future::poll_fn, io, pin::Pin, task::Poll};

use btls::ssl::{Ssl, SslAcceptor};
use http_body_util::BodyExt;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
    time::timeout,
};
use tokio_btls::SslStream;

use super::{fields, read_plaintext_head};
use crate::{
    http1::Http1TlsError,
    proxy::{
        HttpBasicCredentials, HttpDigestCredentials, HttpProxyAuthentication, HttpsProxyConnector,
        HttpsProxyProtocol, ProxyCredentialCache, http1_opening::ProxyBinding,
    },
    request::{OriginForm, RequestHeader},
    route::{Endpoint, HttpConnectRoute, ProxyTransport},
    tcp::{AddressFamily, AddressFamilyMemory, SlowerAttempt},
    tls::test_support::{
        TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity, TestResult, TestServerAlpn, loopback_listener,
    },
};

mod failures;
mod tickets;

fn route<'a>(
    port: u16,
    proxy: &'a HttpsProxyConnector,
    fields: &'a [crate::proxy::HttpConnectHeader],
    credentials: Option<HttpProxyAuthentication<'a>>,
) -> HttpConnectRoute<'a> {
    HttpConnectRoute {
        speculative_tls: false,
        proxy: ProxyTransport::Tls {
            endpoint: Endpoint {
                host: "127.0.0.1",
                port,
            },
            server_name: TEST_SERVER_NAME,
            connector: proxy,
        },
        authority: "server.phantom.test:443",
        headers: fields,
        credentials,
    }
}

async fn accept<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    acceptor: &SslAcceptor,
) -> TestResult<SslStream<S>> {
    let mut stream = SslStream::new(Ssl::new(acceptor.context())?, stream)?;
    Pin::new(&mut stream).accept().await?;
    Ok(stream)
}

async fn closed(stream: &mut (impl AsyncRead + Unpin)) -> TestResult<()> {
    let mut byte = [0];
    match stream.read(&mut byte).await {
        Ok(0) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::UnexpectedEof
            ) =>
        {
            Ok(())
        }
        other => Err(format!("expected owned close, got {other:?}").into()),
    }
}

#[tokio::test]
async fn physical_https_opening_records_family_before_outer_tls_and_cancels_owned_handshake()
-> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let connector = super::super::test_connector(&identity)?;
        let proxy = super::super::test_proxy_connector(&identity)?
            .with_tcp_settings(&phantom_profile::browser::firefox::v157_tcp());
        let (address, listener) = loopback_listener().await?;
        let fields = fields("pending", false);
        let route = route(address.port(), &proxy, &fields, None);
        let family = AddressFamilyMemory::default();
        let (opening, slower) = connector.open_http_connect_retaining(route, TEST_SERVER_NAME, &family).await?;
        assert!(slower.is_none());
        assert_eq!(family.family(), Some(AddressFamily::Ipv4));
        let (mut peer, _) = listener.accept().await?;
        let mut byte = [0];
        assert!(matches!(peer.try_read(&mut byte), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
        let mut finish = Box::pin(opening.finish(route));
        let mut record = [0; 5];
        tokio::select! {
            result = &mut finish => return Err(format!("withheld TLS unexpectedly finished: {result:?}").into()),
            result = peer.read_exact(&mut record) => { result?; }
        }
        assert_eq!(record[0], 22, "first emission was not a TLS handshake record");
        drop(finish);
        let mut rest = Vec::new();
        peer.read_to_end(&mut rest).await?;
        assert!(!rest.windows(b"CONNECT ".len()).any(|bytes| bytes == b"CONNECT "));
        Ok(())
    }).await?
}

#[tokio::test]
async fn slower_https_setup_finishes_verified_outer_tls_without_connect_or_origin_tls()
-> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let acceptor = identity.acceptor(TestServerAlpn::Http1)?;
        let connector = super::super::test_connector(&identity)?;
        let proxy = super::super::test_proxy_connector(&identity)?;
        let (address, listener) = loopback_listener().await?;
        let fields = fields("unused", true);
        let credentials = HttpBasicCredentials::new("unused-user", "unused-secret")?;
        let route = route(
            address.port(),
            &proxy,
            &fields,
            Some(HttpProxyAuthentication::Basic(&credentials)),
        );
        let binding = ProxyBinding::new(route, TEST_SERVER_NAME).map_err(Http1TlsError::from)?;
        let attempt = SlowerAttempt::scripted(
            async move { TcpStream::connect(address).await },
            std::time::Duration::ZERO,
            None,
        );
        let slower = connector.slower_proxy_opening(attempt, binding);
        let progress = slower.progress();
        let (quiet, checked) = tokio::sync::oneshot::channel();
        let client = async {
            let opening = slower.finish().await.ok_or("slower outer TLS failed")?;
            assert!(progress.has_connected());
            checked.await?;
            let debug = format!("{opening:?}");
            assert!(!debug.contains("unused-user") && !debug.contains("unused-secret"));
            drop(opening);
            TestResult::Ok(())
        };
        let server = async {
            let (stream, _) = listener.accept().await?;
            let mut tls = accept(stream, &acceptor).await?;
            let mut byte = [0];
            let mut read = ReadBuf::new(&mut byte);
            assert!(
                poll_fn(|cx| Poll::Ready(Pin::new(&mut tls).poll_read(cx, &mut read).is_pending()))
                    .await
            );
            quiet
                .send(())
                .map_err(|()| "slower owner ended before quiet proof")?;
            closed(&mut tls).await
        };
        tokio::try_join!(client, server)?;
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn claimed_https_anonymous_opening_uses_current_fields_and_separate_origin_tls()
-> TestResult<()> {
    claimed(None).await
}

#[tokio::test]
async fn claimed_https_basic_opening_replays_on_the_supplied_outer_tls_socket() -> TestResult<()> {
    claimed(Some(HttpProxyAuthentication::Basic(
        &HttpBasicCredentials::new("user", "secret")?,
    )))
    .await
}

#[tokio::test]
async fn claimed_https_digest_opening_reserves_nonce_one_only_after_claim() -> TestResult<()> {
    claimed(Some(HttpProxyAuthentication::Digest(
        &HttpDigestCredentials::new("user", "secret")?,
    )))
    .await
}

async fn claimed(credentials: Option<HttpProxyAuthentication<'_>>) -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let proxy_identity = TestIdentity::generate()?;
        let origin_identity = TestIdentity::generate()?;
        let outer_acceptor = proxy_identity.acceptor(TestServerAlpn::Http1)?;
        let inner_acceptor = origin_identity.acceptor(TestServerAlpn::Http1)?;
        let connector = super::super::test_connector(&origin_identity)?;
        let proxy = super::super::test_proxy_connector(&proxy_identity)?;
        let (address, listener) = loopback_listener().await?;
        let original = fields("old", credentials.is_some());
        let current = fields("current", credentials.is_some());
        let family = AddressFamilyMemory::default();
        let (opening, _) = connector.open_http_connect_retaining(
            route(address.port(), &proxy, &original, credentials), TEST_SERVER_NAME, &family).await?;
        let client = async {
            let connection = opening.finish(route(address.port(), &proxy, &current, credentials)).await?;
            let response = connection.send_get(OriginForm::parse("/claimed")?,
                vec![RequestHeader::new("Host", TEST_SERVER_NAME)]).await?;
            assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
            TestResult::Ok(())
        };
        let server = async {
            let (stream, _) = listener.accept().await?;
            let mut outer = accept(stream, &outer_acceptor).await?;
            assert_eq!(read_plaintext_head(&mut outer).await?, b"CONNECT server.phantom.test:443 HTTP/1.1\r\nX-Claim: current\r\nhost: server.phantom.test:443\r\n\r\n");
            if let Some(credentials) = credentials {
                let challenge = match credentials {
                    HttpProxyAuthentication::Basic(_) => "Basic realm=\"proxy\"",
                    HttpProxyAuthentication::Digest(_) => "Digest realm=\"proxy\", nonce=\"one\", algorithm=SHA-256, qop=\"auth\"",
                };
                outer.write_all(format!("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: {challenge}\r\nContent-Length: 0\r\n\r\n").as_bytes()).await?;
                let retry = String::from_utf8(read_plaintext_head(&mut outer).await?)?;
                assert!(retry.starts_with("CONNECT server.phantom.test:443 HTTP/1.1\r\nX-Claim: current\r\nhost: server.phantom.test:443\r\nProxy-Authorization: "));
                match credentials {
                    HttpProxyAuthentication::Basic(_) => assert!(retry.ends_with("Basic dXNlcjpzZWNyZXQ=\r\n\r\n")),
                    HttpProxyAuthentication::Digest(_) => {
                        assert!(retry.contains("nc=00000001"));
                        assert!(retry.contains("uri=\"server.phantom.test:443\""));
                    }
                }
            }
            outer.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
            let mut inner = accept(outer, &inner_acceptor).await?;
            assert_eq!(read_plaintext_head(&mut inner).await?, b"GET /claimed HTTP/1.1\r\nHost: server.phantom.test\r\n\r\n");
            inner.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await?;
            TestResult::Ok(())
        };
        tokio::try_join!(client, server)?;
        assert!(poll_fn(|cx| Poll::Ready(listener.poll_accept(cx).is_pending())).await,
            "successful supplied-stream exchange redialed");
        Ok(())
    }).await?
}

#[tokio::test]
async fn changed_https_cache_sni_or_auth_scope_sends_no_outer_tls_or_connect() -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let connector = super::super::test_connector(&identity)?;
        let proxy = super::super::test_proxy_connector(&identity)?.with_isolated_session_cache();
        let fields = fields("bound", false);
        let wrong_credentials = HttpBasicCredentials::new("other", "other")?;
        for part in 0..7 {
            let (address, listener) = loopback_listener().await?;
            let original = route(address.port(), &proxy, &fields, None);
            let (opening, _) = connector
                .open_http_connect_retaining(
                    original,
                    TEST_SERVER_NAME,
                    &AddressFamilyMemory::default(),
                )
                .await?;
            let (mut peer, _) = listener.accept().await?;
            let changed_proxy = match part {
                0 => proxy.with_isolated_session_cache(),
                1 => proxy
                    .clone()
                    .with_proxy_credential_cache(ProxyCredentialCache::new()),
                2 => proxy.clone().with_protocol(HttpsProxyProtocol::Http2),
                _ => proxy.clone(),
            };
            let changed = HttpConnectRoute {
                speculative_tls: false,
                proxy: ProxyTransport::Tls {
                    endpoint: Endpoint {
                        host: if part == 5 {
                            "different.invalid"
                        } else {
                            "127.0.0.1"
                        },
                        port: address.port(),
                    },
                    server_name: if part == 3 {
                        "other.invalid"
                    } else {
                        TEST_SERVER_NAME
                    },
                    connector: &changed_proxy,
                },
                authority: if part == 4 {
                    "other.invalid:443"
                } else {
                    original.authority
                },
                credentials: if part == 6 {
                    Some(HttpProxyAuthentication::Basic(&wrong_credentials))
                } else {
                    original.credentials
                },
                ..original
            };
            assert!(
                matches!(opening.finish(changed).await, Err(Http1TlsError::Connect(error))
                if error.kind() == io::ErrorKind::InvalidInput)
            );
            let mut bytes = Vec::new();
            peer.read_to_end(&mut bytes).await?;
            assert!(bytes.is_empty());
        }
        Ok(())
    })
    .await?
}

#[test]
fn https_opening_context_identity_preserves_exact_clones_and_distinguishes_actual_caches()
-> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let proxy = super::super::test_proxy_connector(&identity)?.with_isolated_session_cache();
    assert!(proxy.same_http1_opening_context(&proxy.clone()));
    assert!(!proxy.same_http1_opening_context(&proxy.with_isolated_session_cache()));
    let cache = ProxyCredentialCache::new();
    let with_auth = proxy.clone().with_proxy_credential_cache(cache.clone());
    assert!(with_auth.same_http1_opening_context(&with_auth.clone()));
    assert!(
        with_auth.same_http1_opening_context(&proxy.clone().with_proxy_credential_cache(cache))
    );
    assert!(!with_auth.same_http1_opening_context(&proxy));
    assert!(!with_auth.same_http1_opening_context(
        &proxy.with_proxy_credential_cache(ProxyCredentialCache::new())
    ));
    Ok(())
}
