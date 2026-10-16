//! Real CONNECT/TLS/GET transitions; all controls require native execution.
use super::super::{bounded_tls_test, read_plaintext_head, test_connector, tls_settings};
use crate::{
    http1::{Http1ProxyOpening, Http1UpgradeOpening, Http1UpgradeOutcome},
    http1_or_2::{Http1Or2ProxyOpening, Http1Or2TlsConnector},
    proxy::HttpConnectHeader,
    request::{OriginForm, RequestHeader},
    route::{
        DirectTlsSetup, Endpoint, Http1Route, Http1Target, HttpConnectRoute, OriginRoute,
        ProxyTransport, TcpRoute,
    },
    tcp::AddressFamilyMemory,
    tls::test_support::{
        TEST_SERVER_NAME, TestIdentity, TestResult, TestServerAlpn, loopback_listener,
    },
};
use http_body_util::BodyExt as _;
use std::{io, pin::Pin, task::Poll};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

enum Opening {
    Exact(Http1ProxyOpening),
    Negotiated(Http1Or2ProxyOpening),
}

impl Opening {
    async fn finish(
        self,
        route: HttpConnectRoute<'_>,
        fields: Vec<RequestHeader>,
    ) -> TestResult<Http1UpgradeOpening> {
        let protocols = [Box::from(&b"http/1.1"[..])];
        let target = OriginForm::parse("/socket")?;
        Ok(match self {
            Self::Exact(opening) => {
                opening
                    .finish_upgrade(route, &protocols, target, fields)
                    .await
            }
            Self::Negotiated(opening) => {
                opening
                    .finish_upgrade(route, &protocols, target, fields)
                    .await
            }
        }?)
    }
}

fn route(port: u16, fields: &[HttpConnectHeader]) -> HttpConnectRoute<'_> {
    HttpConnectRoute {
        proxy: ProxyTransport::Tcp(Endpoint {
            host: "127.0.0.1",
            port,
        }),
        authority: "server.phantom.test:443",
        headers: fields,
        credentials: None,
    }
}

#[tokio::test]
async fn exact_proxy_upgrade_retains_origin_tickets_and_waits_for_its_current_get() -> TestResult<()>
{
    verified(false).await
}

#[tokio::test]
async fn negotiated_proxy_upgrade_uses_websocket_alpn_and_original_origin_tickets() -> TestResult<()>
{
    verified(true).await
}

async fn verified(negotiated: bool) -> TestResult<()> {
    bounded_tls_test(async {
        let identity = TestIdentity::generate()?;
        let acceptor = identity.acceptor(TestServerAlpn::Http1)?;
        let negotiated_connector = Http1Or2TlsConnector::new_with_additional_roots(
            &tls_settings(), &phantom_profile::browser::firefox::v157_http2(), [identity.root_der()])?;
        let exact = if negotiated {
            let derived = negotiated_connector.http1_connector(&tls_settings().alpn_protocols)?;
            let original = negotiated_connector.session_ticket_cache().and_then(|cache| cache.upgrade()).ok_or("no negotiated ticket owner")?;
            let derived_owner = derived.session_ticket_cache().and_then(|cache| cache.upgrade()).ok_or("no derived ticket owner")?;
            assert!(original.same_cache(&derived_owner));
            derived
        } else { test_connector(&identity)? };
        let (warm_address, warm_listener) = loopback_listener().await?;
        tokio::try_join!(async {
            let response = exact.send(Http1Route::Origin(OriginRoute::Tls {
                tcp: TcpRoute::Direct(Endpoint {host: "127.0.0.1", port: warm_address.port()}),
                server_name: TEST_SERVER_NAME, setup: DirectTlsSetup::Default,
            }), http::Method::GET, Http1Target::Origin(OriginForm::parse("/warm")?),
            vec![RequestHeader::new("Host", TEST_SERVER_NAME)], None).await?;
            assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
            TestResult::Ok(())
        }, async {
            let (tcp, _) = warm_listener.accept().await?;
            let mut stream = tokio_btls::SslStream::new(btls::ssl::Ssl::new(acceptor.context())?, tcp)?;
            Pin::new(&mut stream).accept().await?;
            assert!(!stream.ssl().session_reused());
            assert!(read_plaintext_head(&mut stream).await?.starts_with(b"GET /warm "));
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await?;
            TestResult::Ok(())
        })?;
        let (address, listener) = loopback_listener().await?;
        let original = [HttpConnectHeader::authority("Host"), HttpConnectHeader::field(RequestHeader::new("X-Claim", "old"))];
        let current = [HttpConnectHeader::authority("Host"), HttpConnectHeader::field(RequestHeader::new("X-Claim", "current"))];
        let family = AddressFamilyMemory::default();
        let opening = if negotiated {
            let (opening, slower) = negotiated_connector.open_http_connect_retaining(route(address.port(), &original), TEST_SERVER_NAME, &family).await?;
            assert!(slower.is_none()); Opening::Negotiated(opening)
        } else {
            let (opening, slower) = exact.open_http_connect_retaining(route(address.port(), &original), TEST_SERVER_NAME, &family).await?;
            assert!(slower.is_none()); Opening::Exact(opening)
        };
        let (mut tcp, _) = listener.accept().await?;
        let (ready, checked) = tokio::sync::oneshot::channel();
        let caller = async {
            let opening = opening.finish(route(address.port(), &current), vec![RequestHeader::new("Host", TEST_SERVER_NAME), RequestHeader::new("X-Get", "current")]).await?;
            checked.await?;
            let result = opening.send().await?;
            let response = match result { Http1UpgradeOutcome::Rejected(response) => response, _ => return Err("peer rejection became an upgrade".into()) };
            assert_eq!(response.status(), 403);
            assert_eq!(response.into_body().collect().await?.to_bytes(), "no");
            TestResult::Ok(())
        };
        let peer = async {
            assert_eq!(read_plaintext_head(&mut tcp).await?, b"CONNECT server.phantom.test:443 HTTP/1.1\r\nHost: server.phantom.test:443\r\nX-Claim: current\r\n\r\n");
            tcp.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
            let mut stream = tokio_btls::SslStream::new(btls::ssl::Ssl::new(acceptor.context())?, tcp)?;
            Pin::new(&mut stream).accept().await?;
            assert_eq!(stream.ssl().selected_alpn_protocol(), Some(&b"http/1.1"[..]));
            assert!(stream.ssl().session_reused(), "Upgrade lost its original origin ticket cache");
            let mut byte = [0];
            let mut read = Box::pin(stream.read(&mut byte));
            assert!(std::future::poll_fn(|cx| Poll::Ready(read.as_mut().poll(cx).is_pending())).await, "finish sent the GET");
            drop(read);
            ready.send(()).map_err(|()| "Upgrade claimant left")?;
            assert_eq!(read_plaintext_head(&mut stream).await?, b"GET /socket HTTP/1.1\r\nHost: server.phantom.test\r\nX-Get: current\r\n\r\n");
            stream.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\nConnection: close\r\n\r\nno").await?;
            TestResult::Ok(())
        };
        tokio::try_join!(caller, peer)?;
        Ok(())
    }).await
}

#[tokio::test]
async fn invalid_proxy_upgrade_fields_or_binding_close_before_connect() -> TestResult<()> {
    bounded_tls_test(async {
        for changed_binding in [false, true] {
            let identity = TestIdentity::generate()?;
            let connector = test_connector(&identity)?;
            let (address, listener) = loopback_listener().await?;
            let fields = [HttpConnectHeader::authority("Host")];
            let original = route(address.port(), &fields);
            let family = AddressFamilyMemory::default();
            let (opening, _) = connector
                .open_http_connect_retaining(original, TEST_SERVER_NAME, &family)
                .await?;
            let (mut peer, _) = listener.accept().await?;
            let claimed = if changed_binding {
                HttpConnectRoute {
                    authority: "other.test:443",
                    ..original
                }
            } else {
                original
            };
            let value = if changed_binding {
                TEST_SERVER_NAME
            } else {
                "bad\r\nInjected: value"
            };
            assert!(
                opening
                    .finish_upgrade(
                        claimed,
                        &[Box::from(&b"http/1.1"[..])],
                        OriginForm::parse("/")?,
                        vec![RequestHeader::new("Host", value)]
                    )
                    .await
                    .is_err()
            );
            let mut bytes = Vec::new();
            peer.read_to_end(&mut bytes).await?;
            assert!(bytes.is_empty());
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn cancelling_proxy_upgrade_during_connect_closes_without_origin_tls_or_get() -> TestResult<()>
{
    bounded_tls_test(async {
        let identity = TestIdentity::generate()?;
        let connector = test_connector(&identity)?;
        let (address, listener) = loopback_listener().await?;
        let fields = [HttpConnectHeader::authority("Host")];
        let route = route(address.port(), &fields);
        let family = AddressFamilyMemory::default();
        let (opening, _) = connector.open_http_connect_retaining(route, TEST_SERVER_NAME, &family).await?;
        let (mut peer, _) = listener.accept().await?;
        let protocols = [Box::from(&b"http/1.1"[..])];
        let mut finish = Box::pin(opening.finish_upgrade(route, &protocols, OriginForm::parse("/")?, vec![RequestHeader::new("Host", TEST_SERVER_NAME)]));
        let head = tokio::select! {
            result = &mut finish => { drop(result?); return Err("CONNECT finished without proxy response".into()); }
            head = read_plaintext_head(&mut peer) => head?,
        };
        assert!(head.starts_with(b"CONNECT server.phantom.test:443 "));
        drop(finish);
        let mut bytes = Vec::new();
        match peer.read_to_end(&mut bytes).await {
            Ok(_) => {},
            Err(error) if matches!(error.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted | io::ErrorKind::BrokenPipe) => {},
            Err(error) => return Err(error.into()),
        }
        assert!(bytes.is_empty());
        Ok(())
    }).await
}
