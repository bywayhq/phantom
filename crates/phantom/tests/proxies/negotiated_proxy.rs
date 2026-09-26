//! Negotiated HTTP/1.1-or-HTTP/2 requests through HTTP proxy CONNECT tunnels.
//!
//! One CONNECT tunnel carries one origin TLS handshake whose ALPN selects the
//! protocol, as a browser behind a proxy does. The tunnel cannot carry QUIC,
//! so the route learns no Alt-Svc alternative.

use crate::support::h3 as h3_support;
use crate::support::http3_upgrade as http3_upgrade_support;
use crate::support::tls as tls_support;
use crate::support::tunnel_proxy;

use std::{
    future::Future,
    io,
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    num::NonZeroUsize,
    time::Duration,
};

use http::{Response, StatusCode};
use http_body_util::BodyExt;
use phantom::{
    Client, ClientBuilder, ConnectUdpProxy, HttpProtocol, HttpProxy, RequestErrorKind,
    ResponseBody, ResponseInfo, Route,
    profile::{ClientProfile, chromium},
};
use tokio::{io::AsyncWriteExt, net::TcpListener, task::JoinHandle, time::timeout};

// `tunnel_proxy` names the TLS helpers `tls`; the Alt-Svc fixture names them
// `tls_support`.

use h3_support::client_settings;
use http3_upgrade_support::{
    AlternativeBehavior, Http3UpgradeFixture, PlannedResponse, UpgradeScript,
};
use tls_support::{
    H1_ALPN, H2_ALPN, TestIdentity, TestResult, accept_tls_stream, client_builder, read_head,
    tls_settings,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const SECOND_CONNECTION_WINDOW: Duration = Duration::from_millis(100);
/// `alice:secret` in Base64, as the exact-protocol proxy tests send it.
const BASIC_ALICE: &str = "Proxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\n";

#[tokio::test]
async fn plaintext_proxy_tunnel_selects_h2_when_the_origin_offers_it() -> TestResult<()> {
    through_one_tunnel(ProxyLeg::Plaintext, OriginAlpn::Http2).await
}

#[tokio::test]
async fn plaintext_proxy_tunnel_selects_http1_when_the_origin_offers_only_it() -> TestResult<()> {
    through_one_tunnel(ProxyLeg::Plaintext, OriginAlpn::Http1).await
}

#[tokio::test]
async fn tls_proxy_tunnel_selects_h2_when_the_origin_offers_it() -> TestResult<()> {
    through_one_tunnel(ProxyLeg::Tls, OriginAlpn::Http2).await
}

#[tokio::test]
async fn tls_proxy_tunnel_selects_http1_when_the_origin_offers_only_it() -> TestResult<()> {
    through_one_tunnel(ProxyLeg::Tls, OriginAlpn::Http1).await
}

/// The HTTP/2 proxy transport carries the tunnel in an RFC 9113 CONNECT
/// stream; ALPN inside it is still the origin's.
#[tokio::test]
async fn h2_proxy_transport_tunnel_selects_the_origin_protocol() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let proxy_identity = TestIdentity::generate()?;
        let (origin_address, origin_listener) = bind().await?;
        let origin_acceptor = identity.acceptor(H1_ALPN)?;
        // The origin closes after one response, so the CONNECT stream ends
        // before the test runtime drops the proxy connection.
        let origin = tokio::spawn(async move {
            let (tcp, _) = origin_listener.accept().await?;
            let mut stream = accept_tls_stream(tcp, origin_acceptor).await?;
            let selected = stream.ssl().selected_alpn_protocol().map(<[u8]>::to_vec);
            read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await?;
            stream.shutdown().await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(selected)
        });
        let (proxy_address, proxy_listener) = bind().await?;
        let proxy = tokio::spawn(tunnel_proxy::http2_connect(
            proxy_listener,
            proxy_identity.acceptor(H2_ALPN)?,
            origin_address,
        ));
        let client = client_builder(&identity, true)
            .add_proxy_root_certificate_der(proxy_identity.root_der.clone())
            .route(Route::http_proxy(
                HttpProxy::new(&format!("https://{proxy_address}"))?.with_http2_transport()?,
            ))
            .build()?;

        let response = negotiated_get(&client, origin_address, "/h2-proxy").await?;
        assert_eq!(protocol(&response)?, HttpProtocol::Http1);
        assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");

        let record = proxy.await??;
        assert_eq!(
            record.authority.as_deref(),
            Some(origin_address.to_string().as_str())
        );
        assert_eq!(origin.await??.as_deref(), Some(&b"http/1.1"[..]));
        Ok(())
    })
    .await
}

/// A negotiated tunnel answers a Basic challenge exactly as an exact HTTP/2
/// tunnel does: the same anonymous CONNECT, then the same authorized CONNECT on
/// a fresh proxy connection.
#[tokio::test]
async fn plaintext_proxy_basic_challenge_matches_the_exact_request() -> TestResult<()> {
    basic_challenge_matches_exact(ProxyLeg::Plaintext).await
}

#[tokio::test]
async fn tls_proxy_basic_challenge_matches_the_exact_request() -> TestResult<()> {
    basic_challenge_matches_exact(ProxyLeg::Tls).await
}

/// The CONNECT tunnel cannot carry QUIC, so an `h3` advertisement on it is not
/// stored and the next request stays on the pooled TCP connection.
#[tokio::test]
async fn alt_svc_advertisement_on_a_proxy_tunnel_is_not_learned() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let fixture = Http3UpgradeFixture::spawn(
            &identity,
            "127.0.0.1",
            UpgradeScript::new(
                [
                    PlannedResponse::new(StatusCode::OK)
                        .body("origin")
                        .advertise_alternative(),
                    PlannedResponse::new(StatusCode::OK).body("still origin"),
                ],
                AlternativeBehavior::responses([
                    PlannedResponse::new(StatusCode::OK).body("alternative")
                ]),
            ),
        )
        .await?;
        let (proxy_address, proxy_listener) = bind().await?;
        let proxy = tokio::spawn(tunnel_proxy::http1_connect(
            proxy_listener,
            fixture.origin_address(),
        ));
        let client = alt_svc_client(&identity)?
            .route(Route::http_proxy(HttpProxy::new(&format!(
                "http://{proxy_address}"
            ))?))
            .build()?;

        let first = client
            .get_negotiated(&fixture.origin_url("/learn"))?
            .send()
            .await?;
        assert_eq!(protocol(&first)?, HttpProtocol::Http2);
        assert!(
            first.headers().contains_key("alt-svc"),
            "origin did not advertise the alternative"
        );
        assert_eq!(first.into_body().collect().await?.to_bytes(), "origin");

        let second = client
            .get_negotiated(&fixture.origin_url("/after"))?
            .send()
            .await?;
        assert_eq!(protocol(&second)?, HttpProtocol::Http2);
        assert_eq!(
            second.into_body().collect().await?.to_bytes(),
            "still origin"
        );

        proxy.await??;
        drop(client);
        let observed = fixture.finish().await?;
        assert_eq!(observed.origin_connections, 1);
        assert_eq!(observed.origin_request_count, 2);
        assert_eq!(observed.alternative_connections, 0);
        Ok(())
    })
    .await
}

/// A CONNECT-UDP route carries no TLS stream for ALPN, so a negotiated
/// request on it is refused before any proxy I/O.
#[tokio::test]
async fn connect_udp_route_still_refuses_a_negotiated_request() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let proxy = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        proxy.set_nonblocking(true)?;
        let proxy_address = proxy.local_addr()?;
        let client = alt_svc_client(&identity)?.build()?;

        let error = client
            .get_negotiated("https://127.0.0.1:9/refused")?
            .route(Route::connect_udp(ConnectUdpProxy::new(&format!(
                "https://{proxy_address}/.well-known/masque/udp/{{target_host}}/{{target_port}}/"
            ))?))
            .send()
            .await
            .err()
            .ok_or("negotiated request was accepted on a CONNECT-UDP route")?;
        assert_eq!(error.kind(), RequestErrorKind::UnsupportedRoute);
        assert_eq!(error.protocol(), None);
        let mut datagram = [0_u8; 1];
        assert!(matches!(
            proxy.recv_from(&mut datagram),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock
        ));
        Ok(())
    })
    .await
}

/// A negotiated connection opened through one proxy is not reused for the same
/// origin through another proxy.
#[tokio::test]
async fn negotiated_connection_is_not_reused_across_proxy_routes() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let (origin_address, origin) = spawn_origin(&identity, OriginAlpn::Http2, 2).await?;
        let (first_address, first_listener) = bind().await?;
        let (second_address, second_listener) = bind().await?;
        let first_proxy = tokio::spawn(tunnel_proxy::http1_connect(first_listener, origin_address));
        let second_proxy =
            tokio::spawn(tunnel_proxy::http1_connect(second_listener, origin_address));
        let client = client_builder(&identity, true)
            .route(Route::http_proxy(HttpProxy::new(&format!(
                "http://{first_address}"
            ))?))
            .build()?;

        let first = negotiated_get(&client, origin_address, "/first").await?;
        assert_eq!(protocol(&first)?, HttpProtocol::Http2);
        first.into_body().collect().await?;
        let second = client
            .get_negotiated(&format!("https://{origin_address}/second"))?
            .route(Route::http_proxy(HttpProxy::new(&format!(
                "http://{second_address}"
            ))?))
            .send()
            .await?;
        assert_eq!(protocol(&second)?, HttpProtocol::Http2);
        second.into_body().collect().await?;

        let connect = expected_connect(origin_address);
        assert_eq!(first_proxy.await??, connect);
        assert_eq!(second_proxy.await??, connect);
        let served = origin.await??;
        assert_eq!(
            served
                .iter()
                .map(|record| record.request.as_str())
                .collect::<Vec<_>>(),
            ["/first", "/second"]
        );
        Ok(())
    })
    .await
}

/// A proxy that refuses CONNECT fails a negotiated request with the same
/// error category as an exact one, before any origin I/O.
#[tokio::test]
async fn refused_connect_fails_like_the_exact_request() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let origin: SocketAddr = "127.0.0.1:9".parse()?;
        for negotiated in [false, true] {
            let (proxy_address, proxy_listener) = bind().await?;
            let proxy = tokio::spawn(tunnel_proxy::http1_connect_status(proxy_listener, 403));
            let client = client_builder(&identity, true)
                .route(Route::http_proxy(HttpProxy::new(&format!(
                    "http://{proxy_address}"
                ))?))
                .build()?;
            let uri = format!("https://{origin}/refused");
            let request = if negotiated {
                client.get_negotiated(&uri)?
            } else {
                client.get(HttpProtocol::Http2, &uri)?
            };
            let error = request
                .send()
                .await
                .err()
                .ok_or("refused CONNECT was accepted")?;
            assert_eq!(
                error.kind(),
                RequestErrorKind::Proxy,
                "negotiated={negotiated}"
            );
            assert_eq!(proxy.await??, expected_connect(origin));
        }
        Ok(())
    })
    .await
}

/// A failed origin handshake inside the tunnel is terminal: no second tunnel,
/// no second handshake with a different offer, and no other protocol.
#[tokio::test]
async fn failed_origin_handshake_in_the_tunnel_is_not_retried() -> TestResult<()> {
    bounded(async {
        let trusted = TestIdentity::generate()?;
        let untrusted = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = listener.local_addr()?;
        let acceptor = untrusted.acceptor(H2_ALPN)?;
        let origin = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            // The client rejects this certificate, so the handshake fails.
            let _ = accept_tls_stream(tcp, acceptor).await;
            let second = timeout(SECOND_CONNECTION_WINDOW, listener.accept()).await;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(second.is_err())
        });
        let (proxy_address, proxy_listener) = bind().await?;
        let proxy = tokio::spawn(tunnel_proxy::http1_connect(proxy_listener, origin_address));
        let client = client_builder(&trusted, true)
            .route(Route::http_proxy(HttpProxy::new(&format!(
                "http://{proxy_address}"
            ))?))
            .build()?;

        let error = client
            .get_negotiated(&format!("https://{origin_address}/untrusted"))?
            .send()
            .await
            .err()
            .ok_or("negotiated request accepted an untrusted origin")?;
        assert_eq!(error.kind(), RequestErrorKind::Tls);
        assert_eq!(error.protocol(), None);
        assert_eq!(proxy.await??, expected_connect(origin_address));
        assert!(origin.await??, "origin saw a second connection");
        Ok(())
    })
    .await
}

#[derive(Clone, Copy, Debug)]
enum ProxyLeg {
    Plaintext,
    Tls,
}

#[derive(Clone, Copy, Debug)]
enum OriginAlpn {
    Http1,
    Http2,
}

impl OriginAlpn {
    const fn acceptor_alpn(self) -> &'static [u8] {
        match self {
            Self::Http1 => H1_ALPN,
            Self::Http2 => H2_ALPN,
        }
    }

    const fn selected(self) -> &'static [u8] {
        match self {
            Self::Http1 => b"http/1.1",
            Self::Http2 => b"h2",
        }
    }

    const fn protocol(self) -> HttpProtocol {
        match self {
            Self::Http1 => HttpProtocol::Http1,
            Self::Http2 => HttpProtocol::Http2,
        }
    }
}

async fn through_one_tunnel(leg: ProxyLeg, alpn: OriginAlpn) -> TestResult<()> {
    bounded(async move {
        let identity = TestIdentity::generate()?;
        let proxy_identity = TestIdentity::generate()?;
        let (origin_address, origin) = spawn_origin(&identity, alpn, 1).await?;
        let (proxy_address, proxy_listener) = bind().await?;
        let (proxy, builder) = match leg {
            ProxyLeg::Plaintext => (
                tokio::spawn(tunnel_proxy::http1_connect(proxy_listener, origin_address)),
                client_builder(&identity, true).route(Route::http_proxy(HttpProxy::new(
                    &format!("http://{proxy_address}"),
                )?)),
            ),
            ProxyLeg::Tls => (
                tokio::spawn(tunnel_proxy::https1_connect(
                    proxy_listener,
                    proxy_identity.acceptor(H1_ALPN)?,
                    origin_address,
                )),
                client_builder(&identity, true)
                    .add_proxy_root_certificate_der(proxy_identity.root_der.clone())
                    .route(Route::http_proxy(HttpProxy::new(&format!(
                        "https://{proxy_address}"
                    ))?)),
            ),
        };
        let client = builder.build()?;

        let response = negotiated_get(&client, origin_address, "/selected").await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(protocol(&response)?, alpn.protocol());
        response.into_body().collect().await?;

        assert_eq!(proxy.await??, expected_connect(origin_address));
        let [served] = <[OriginRecord; 1]>::try_from(origin.await??)
            .map_err(|_| "origin served an unexpected number of connections")?;
        assert_eq!(served.selected_alpn.as_deref(), Some(alpn.selected()));
        match alpn {
            OriginAlpn::Http1 => assert_eq!(
                served.request,
                format!("GET /selected HTTP/1.1\r\nHost: {origin_address}\r\n\r\n")
            ),
            OriginAlpn::Http2 => assert_eq!(served.request, "/selected"),
        }
        Ok(())
    })
    .await
}

async fn basic_challenge_matches_exact(leg: ProxyLeg) -> TestResult<()> {
    bounded(async move {
        let identity = TestIdentity::generate()?;
        let proxy_identity = TestIdentity::generate()?;
        let (origin_address, origin) = spawn_origin(&identity, OriginAlpn::Http2, 2).await?;

        let mut heads = Vec::new();
        for negotiated in [false, true] {
            let (proxy_address, proxy_listener) = bind().await?;
            let (proxy, builder) = match leg {
                ProxyLeg::Plaintext => (
                    tokio::spawn(tunnel_proxy::http1_challenge_then_connect(
                        proxy_listener,
                        origin_address,
                    )),
                    client_builder(&identity, true).route(Route::http_proxy(
                        HttpProxy::new(&format!("http://{proxy_address}"))?
                            .with_basic_auth("alice", "secret")?,
                    )),
                ),
                ProxyLeg::Tls => (
                    tokio::spawn(tunnel_proxy::https1_challenge_then_connect(
                        proxy_listener,
                        proxy_identity.acceptor(H1_ALPN)?,
                        origin_address,
                    )),
                    client_builder(&identity, true)
                        .add_proxy_root_certificate_der(proxy_identity.root_der.clone())
                        .route(Route::http_proxy(
                            HttpProxy::new(&format!("https://{proxy_address}"))?
                                .with_basic_auth("alice", "secret")?,
                        )),
                ),
            };
            let client = builder.build()?;
            let uri = format!("https://{origin_address}/authenticated");
            let request = if negotiated {
                client.get_negotiated(&uri)?
            } else {
                client.get(HttpProtocol::Http2, &uri)?
            };
            let response = request.send().await?;
            assert_eq!(protocol(&response)?, HttpProtocol::Http2);
            response.into_body().collect().await?;

            let (anonymous, authorized, challenged_reused) = proxy.await??;
            assert!(
                challenged_reused,
                "the replay opened a new proxy connection"
            );
            heads.push((anonymous, authorized));
        }

        let connect = expected_connect(origin_address);
        let authorized = format!(
            "CONNECT {origin_address} HTTP/1.1\r\nHost: {origin_address}\r\n{BASIC_ALICE}\r\n"
        )
        .into_bytes();
        let [
            (exact_anonymous, exact_authorized),
            (anonymous, negotiated_authorized),
        ] = <[(Vec<u8>, Vec<u8>); 2]>::try_from(heads)
            .map_err(|_| "expected one exact and one negotiated tunnel")?;
        assert_eq!(exact_anonymous, connect);
        assert_eq!(exact_authorized, authorized);
        assert_eq!(anonymous, exact_anonymous);
        assert_eq!(negotiated_authorized, exact_authorized);
        assert_eq!(origin.await??.len(), 2);
        Ok(())
    })
    .await
}

/// What one origin connection observed.
struct OriginRecord {
    selected_alpn: Option<Vec<u8>>,
    /// The HTTP/1.1 request head, or the HTTP/2 `:path`.
    request: String,
}

/// Serves `connections` TLS connections with one request each, then reports
/// whether a further connection arrived.
async fn spawn_origin(
    identity: &TestIdentity,
    alpn: OriginAlpn,
    connections: usize,
) -> TestResult<(SocketAddr, JoinHandle<TestResult<Vec<OriginRecord>>>)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = identity.acceptor(alpn.acceptor_alpn())?;
    let task = tokio::spawn(async move {
        let mut records = Vec::new();
        let mut open = Vec::new();
        for _ in 0..connections {
            let (tcp, _) = listener.accept().await?;
            let mut stream = accept_tls_stream(tcp, acceptor.clone()).await?;
            let selected_alpn = stream.ssl().selected_alpn_protocol().map(<[u8]>::to_vec);
            let request = match alpn {
                OriginAlpn::Http1 => {
                    let head = read_head(&mut stream).await?;
                    stream
                        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                        .await?;
                    stream.flush().await?;
                    open.push(tokio::spawn(async move {
                        // Hold the connection open for reuse until the client leaves.
                        let mut rest = Vec::new();
                        let _ = tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut rest).await;
                    }));
                    String::from_utf8(head)?
                }
                OriginAlpn::Http2 => {
                    let mut connection = ::http2::server::handshake(stream).await?;
                    let (request, mut respond) = connection
                        .accept()
                        .await
                        .ok_or("connection closed before the negotiated request")??;
                    respond.send_response(
                        Response::builder()
                            .status(StatusCode::NO_CONTENT)
                            .body(())?,
                        true,
                    )?;
                    let path = request.uri().path().to_owned();
                    open.push(tokio::spawn(async move {
                        while let Some(Ok(_)) = connection.accept().await {}
                    }));
                    path
                }
            };
            records.push(OriginRecord {
                selected_alpn,
                request,
            });
        }
        if timeout(SECOND_CONNECTION_WINDOW, listener.accept())
            .await
            .is_ok()
        {
            return Err("origin saw an unexpected extra connection".into());
        }
        Ok(records)
    });
    Ok((address, task))
}

fn expected_connect(origin: SocketAddr) -> Vec<u8> {
    format!("CONNECT {origin} HTTP/1.1\r\nHost: {origin}\r\n\r\n").into_bytes()
}

async fn negotiated_get(
    client: &Client,
    origin: SocketAddr,
    path: &str,
) -> TestResult<Response<ResponseBody>> {
    Ok(client
        .get_negotiated(&format!("https://{origin}{path}"))?
        .send()
        .await?)
}

/// A client whose profile negotiates H1 or H2 and may upgrade to HTTP/3.
fn alt_svc_client(identity: &TestIdentity) -> TestResult<ClientBuilder> {
    let profile = ClientProfile::new(tls_settings())
        .with_http2(chromium::v154_http2())
        .with_http3(client_settings());
    let maximum_origins = NonZeroUsize::new(8).ok_or("Alt-Svc test capacity was zero")?;
    Ok(Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .alt_svc(maximum_origins))
}

fn protocol<B>(response: &Response<B>) -> TestResult<HttpProtocol> {
    response
        .extensions()
        .get::<ResponseInfo>()
        .map(ResponseInfo::protocol)
        .ok_or_else(|| "response omitted protocol metadata".into())
}

async fn bind() -> TestResult<(SocketAddr, TcpListener)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    Ok((listener.local_addr()?, listener))
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "negotiated proxy test exceeded its deadline")?
}
