//! Alt-Svc to HTTP/3 upgrade over a SOCKS5 route.
//!
//! SOCKS5 is the only proxy route that carries both legs of the upgrade: RFC
//! 1928 CONNECT carries the negotiated origin TLS stream that learns the
//! advertisement, and RFC 1928 UDP ASSOCIATE carries QUIC to the advertised
//! alternative. One proxy listener serves both here, as a real proxy does.

#[allow(dead_code)]
#[path = "support/h3.rs"]
mod h3_support;
#[path = "support/http3_upgrade.rs"]
mod http3_upgrade_support;
#[allow(dead_code)]
#[path = "support/socks5_udp.rs"]
mod socks5_udp_support;
#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;

use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    time::Duration,
};

use http::StatusCode;
use http_body_util::BodyExt;
use phantom::{
    Client, ConnectUdpProxy, HttpProtocol, HttpProxy, RequestErrorKind, ResponseInfo, Route,
    Socks5Proxy,
    profile::{ClientProfile, chromium},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::timeout,
};

use h3_support::client_settings;
use http3_upgrade_support::{
    AltSvcAdvertisement, AlternativeBehavior, Http3UpgradeFixture, ObservedRequest,
    PlannedResponse, UpgradeScript,
};
use socks5_udp_support::{
    ObservedSocks5UdpRelay, Socks5UdpScript, Socks5UdpTarget, serve_socks5_udp_associate_stream,
};
use tls_support::{TestIdentity, TestResult, is_peer_gone, tls_settings};

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const ORIGIN_NAME: &str = "127.0.0.1";

#[tokio::test]
async fn local_dns_socks5_request_upgrades_to_http3_through_the_same_proxy() -> TestResult<()> {
    upgrades_through_one_proxy(Socks5Dns::Local, ProxyAuth::None).await
}

/// With `socks5h://` the proxy resolves the origin name, so the CONNECT leg
/// carries a DOMAIN target and no local lookup happens.
#[tokio::test]
async fn remote_dns_socks5_request_upgrades_to_http3_through_the_same_proxy() -> TestResult<()> {
    upgrades_through_one_proxy(Socks5Dns::Remote, ProxyAuth::None).await
}

/// RFC 1929 credentials authenticate both legs: the CONNECT tunnel that learns
/// the advertisement and the UDP association that carries the alternative.
#[tokio::test]
async fn authenticated_socks5_request_upgrades_to_http3_through_the_same_proxy() -> TestResult<()> {
    upgrades_through_one_proxy(
        Socks5Dns::Remote,
        ProxyAuth::UsernamePassword {
            username: PROXY_USERNAME,
            password: PROXY_PASSWORD,
        },
    )
    .await
}

async fn upgrades_through_one_proxy(dns: Socks5Dns, auth: ProxyAuth) -> TestResult<()> {
    bounded(async move {
        let identity =
            TestIdentity::generate_for_ip_and_dns(IpAddr::V4(Ipv4Addr::LOCALHOST), "localhost")?;
        let fixture = Http3UpgradeFixture::spawn(
            &identity,
            "localhost",
            UpgradeScript::new(
                [PlannedResponse::new(StatusCode::OK)
                    .body("origin")
                    .advertise_alternative()],
                AlternativeBehavior::responses([
                    PlannedResponse::new(StatusCode::OK).body("alternative")
                ]),
            )
            .advertisement(AltSvcAdvertisement::default().host(ORIGIN_NAME)),
        )
        .await?;
        let alternative_authority = format!("127.0.0.1:{}", fixture.alternative_address().port());
        let origin_authority = format!("localhost:{}", fixture.origin_address().port());
        let origin_port = fixture.origin_address().port();
        let proxy = Socks5Fixture::spawn(
            fixture.origin_address(),
            fixture.alternative_address(),
            dns,
            auth,
        )
        .await?;
        let client = upgrade_client(&identity)?;

        let first = client
            .get_negotiated(&fixture.origin_url("/learn"))?
            .route(proxy.route()?)
            .send()
            .await?;
        assert_eq!(protocol(&first)?, HttpProtocol::Http2);
        assert_eq!(first.into_body().collect().await?.to_bytes(), "origin");

        let second = client
            .get_negotiated(&fixture.origin_url("/upgrade"))?
            .route(proxy.route()?)
            .send()
            .await?;
        assert_eq!(protocol(&second)?, HttpProtocol::Http3);
        assert_eq!(
            second.into_body().collect().await?.to_bytes(),
            "alternative"
        );

        drop(client);
        let observed = fixture.finish().await?;
        assert_eq!(observed.origin_requests.len(), 1);
        assert_eq!(observed.alternative_requests.len(), 1);
        // The origin keeps its authority and SNI; only the transport moved.
        assert_eq!(
            observed.alternative_requests[0].authority.as_deref(),
            Some(origin_authority.as_str())
        );
        assert_eq!(
            observed.alternative_requests[0].server_name.as_deref(),
            Some("localhost")
        );
        assert_eq!(
            header_values(&observed.alternative_requests[0], "alt-used"),
            [alternative_authority.as_bytes()],
            "the managed attempt carries one canonical explicit-port Alt-Used"
        );
        assert!(header_values(&observed.origin_requests[0], "alt-used").is_empty());

        let (connect, relay) = proxy.finish().await?;
        // Both legs went through the one configured proxy.
        assert_eq!(connect.target.port(), origin_port);
        assert!(relay.client_datagrams > 0);
        assert!(relay.origin_datagrams > 0);

        // The DNS mode decides who resolves the origin name.
        match dns {
            // The client resolved `localhost` itself and sent one address
            // literal; which loopback address it picked is the resolver's
            // choice, so only the form matters here.
            Socks5Dns::Local => match &connect.target {
                ConnectTarget::Literal { host, port } => {
                    assert_eq!(*port, origin_port);
                    assert!(
                        host.parse::<IpAddr>().is_ok_and(|host| host.is_loopback()),
                        "local DNS sent {host:?} instead of a loopback literal"
                    );
                }
                other => return Err(format!("local DNS sent {other:?}").into()),
            },
            Socks5Dns::Remote => assert_eq!(
                connect.target,
                ConnectTarget::Domain {
                    host: "localhost".into(),
                    port: origin_port,
                }
            ),
        }

        // Credentials reach both legs, or neither.
        match auth {
            ProxyAuth::None => {
                assert_eq!(connect.credentials, None);
                assert!(relay.authentication.is_none());
            }
            ProxyAuth::UsernamePassword { username, password } => {
                assert_eq!(
                    connect.credentials,
                    Some((username.to_owned(), password.to_owned()))
                );
                let relay_auth = relay
                    .authentication
                    .as_ref()
                    .ok_or("the UDP association was not authenticated")?;
                assert_eq!(relay_auth.username, username);
                assert_eq!(relay_auth.password, password);
            }
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn negotiated_requests_are_refused_on_routes_that_cannot_carry_quic() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let client = upgrade_client(&identity)?;

        // An HTTP proxy carries only TCP, so a learned `h3` alternative could
        // never be reached over it. A CONNECT-UDP proxy carries only QUIC, so
        // there is no TLS stream for ALPN to select a protocol on. Both are
        // refused before any proxy or origin I/O, and neither falls back.
        let routes = [
            Route::http_proxy(HttpProxy::new("http://127.0.0.1:1")?),
            Route::http_proxy(HttpProxy::new("https://127.0.0.1:1")?),
            Route::http_proxy(HttpProxy::new("https://127.0.0.1:1")?.with_http2_transport()?),
            Route::connect_udp(ConnectUdpProxy::new(
                "https://127.0.0.1:1/.well-known/masque/udp/{target_host}/{target_port}/",
            )?),
        ];
        for route in routes {
            let trace = route.clone();
            let error = client
                .get_negotiated("https://origin.test/refused")?
                .route(route)
                .send()
                .await
                .err()
                .ok_or_else(|| format!("negotiated request was accepted on {trace:?}"))?;
            assert_eq!(
                error.kind(),
                RequestErrorKind::UnsupportedRoute,
                "{trace:?}"
            );
        }
        Ok(())
    })
    .await
}

/// The credentials, if any, that a proxy fixture expects on both legs.
#[derive(Clone, Copy, Eq, PartialEq)]
enum ProxyAuth {
    None,
    UsernamePassword {
        username: &'static str,
        password: &'static str,
    },
}

const PROXY_USERNAME: &str = "alice";
const PROXY_PASSWORD: &str = "a secret";

/// What the client asked the proxy to CONNECT to.
///
/// `socks5://` resolves the origin locally and sends an address literal;
/// `socks5h://` sends the origin name for the proxy to resolve.
#[derive(Debug, Eq, PartialEq)]
enum ConnectTarget {
    Literal { host: String, port: u16 },
    Domain { host: String, port: u16 },
}

impl ConnectTarget {
    fn port(&self) -> u16 {
        match self {
            Self::Literal { port, .. } | Self::Domain { port, .. } => *port,
        }
    }
}

/// What one CONNECT tunnel observed before it started forwarding bytes.
#[derive(Debug, Eq, PartialEq)]
struct ObservedConnect {
    target: ConnectTarget,
    credentials: Option<(String, String)>,
}

/// One SOCKS5 listener serving the negotiated CONNECT tunnel and the
/// alternative's UDP association at the same time.
struct Socks5Fixture {
    address: SocketAddr,
    dns: Socks5Dns,
    auth: ProxyAuth,
    connect: JoinHandle<TestResult<ObservedConnect>>,
    relay: JoinHandle<TestResult<ObservedSocks5UdpRelay>>,
}

/// Which side of the route resolves the origin and alternative names.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Socks5Dns {
    Local,
    Remote,
}

impl Socks5Dns {
    fn scheme(self) -> &'static str {
        match self {
            Self::Local => "socks5",
            Self::Remote => "socks5h",
        }
    }
}

impl Socks5Fixture {
    async fn spawn(
        origin: SocketAddr,
        alternative: SocketAddr,
        dns: Socks5Dns,
        auth: ProxyAuth,
    ) -> TestResult<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (connect_tx, connect_rx) = tokio::sync::oneshot::channel();
        let (relay_tx, relay_rx) = tokio::sync::oneshot::channel();
        let script = match auth {
            ProxyAuth::None => Socks5UdpScript::no_auth(),
            ProxyAuth::UsernamePassword { .. } => Socks5UdpScript::username_password(),
        };

        tokio::spawn(async move {
            let (tunnel, _) = listener.accept().await?;
            let _ = connect_tx.send(tokio::spawn(tunnel_connect(tunnel, origin, auth)));
            let (control, _) = listener.accept().await?;
            // The advertised alternative host is an address literal, so both
            // DNS modes send it to the proxy as an IP target.
            let _ = relay_tx.send(tokio::spawn(serve_socks5_udp_associate_stream(
                control,
                alternative,
                Socks5UdpTarget::Ip(alternative),
                script,
            )));
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        Ok(Self {
            address,
            dns,
            auth,
            connect: tokio::spawn(async move { connect_rx.await?.await? }),
            relay: tokio::spawn(async move { relay_rx.await?.await? }),
        })
    }

    fn route(&self) -> TestResult<Route> {
        let proxy = Socks5Proxy::new(&format!("{}://{}", self.dns.scheme(), self.address))?;
        let proxy = match self.auth {
            ProxyAuth::None => proxy,
            ProxyAuth::UsernamePassword { username, password } => {
                proxy.with_username_password(username, password)?
            }
        };
        Ok(Route::socks5(proxy))
    }

    async fn finish(self) -> TestResult<(ObservedConnect, ObservedSocks5UdpRelay)> {
        Ok((self.connect.await??, self.relay.await??))
    }
}

/// Serves one SOCKS5 CONNECT and tunnels it to `origin`, returning what the
/// client asked for.
///
/// The client closes its pooled connection at the end of the test, which
/// Windows reports as `ConnectionAborted` rather than a clean end of stream,
/// so a vanished peer ends the tunnel normally.
async fn tunnel_connect(
    mut downstream: TcpStream,
    origin: SocketAddr,
    auth: ProxyAuth,
) -> TestResult<ObservedConnect> {
    let credentials = match auth {
        ProxyAuth::None => {
            let mut greeting = [0_u8; 3];
            downstream.read_exact(&mut greeting).await?;
            assert_eq!(greeting, [5, 1, 0], "unexpected SOCKS5 greeting");
            downstream.write_all(&[5, 0]).await?;
            downstream.flush().await?;
            None
        }
        ProxyAuth::UsernamePassword { .. } => {
            let mut greeting = [0_u8; 4];
            downstream.read_exact(&mut greeting).await?;
            assert_eq!(
                greeting,
                [5, 2, 0, 2],
                "unexpected authenticated SOCKS5 greeting"
            );
            downstream.write_all(&[5, 2]).await?;
            downstream.flush().await?;

            let mut version = [0_u8; 1];
            downstream.read_exact(&mut version).await?;
            assert_eq!(version, [1], "unexpected RFC 1929 version");
            let username = read_credential(&mut downstream).await?;
            let password = read_credential(&mut downstream).await?;
            downstream.write_all(&[1, 0]).await?;
            downstream.flush().await?;
            Some((username, password))
        }
    };

    let mut head = [0_u8; 4];
    downstream.read_exact(&mut head).await?;
    assert_eq!(head[..2], [5, 1], "unexpected SOCKS5 CONNECT request");
    let domain = head[3] == 3;
    let mut address = match head[3] {
        1 => vec![0_u8; 4],
        3 => {
            let mut length = [0_u8; 1];
            downstream.read_exact(&mut length).await?;
            vec![0_u8; usize::from(length[0])]
        }
        4 => vec![0_u8; 16],
        other => panic!("unexpected SOCKS5 address type {other}"),
    };
    downstream.read_exact(&mut address).await?;
    let mut port = [0_u8; 2];
    downstream.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);
    let host = if domain {
        String::from_utf8(address)?
    } else if address.len() == 4 {
        IpAddr::from(<[u8; 4]>::try_from(address.as_slice())?).to_string()
    } else {
        IpAddr::from(<[u8; 16]>::try_from(address.as_slice())?).to_string()
    };
    let target = if domain {
        ConnectTarget::Domain { host, port }
    } else {
        ConnectTarget::Literal { host, port }
    };
    let observed = ObservedConnect {
        target,
        credentials,
    };

    let mut upstream = TcpStream::connect(origin).await?;
    downstream
        .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
        .await?;
    downstream.flush().await?;
    match copy_bidirectional(&mut downstream, &mut upstream).await {
        Ok(_) => Ok(observed),
        Err(error) if is_peer_gone(&error) => Ok(observed),
        Err(error) => Err(error.into()),
    }
}

async fn read_credential(stream: &mut TcpStream) -> TestResult<String> {
    let mut length = [0_u8; 1];
    stream.read_exact(&mut length).await?;
    let mut value = vec![0_u8; usize::from(length[0])];
    stream.read_exact(&mut value).await?;
    Ok(String::from_utf8(value)?)
}

fn upgrade_client(identity: &TestIdentity) -> TestResult<Client> {
    let profile = ClientProfile::new(tls_settings())
        .with_http2(chromium::v152_http2())
        .with_http3(client_settings());
    let maximum_origins = NonZeroUsize::new(8).ok_or("Alt-Svc test capacity was zero")?;
    Ok(Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .alt_svc(maximum_origins)
        .build()?)
}

fn protocol<B>(response: &http::Response<B>) -> TestResult<HttpProtocol> {
    response
        .extensions()
        .get::<ResponseInfo>()
        .map(ResponseInfo::protocol)
        .ok_or_else(|| "response omitted protocol metadata".into())
}

fn header_values<'a>(request: &'a ObservedRequest, name: &str) -> Vec<&'a [u8]> {
    request
        .fields
        .iter()
        .filter(|field| field.name == name)
        .map(|field| field.value.as_slice())
        .collect()
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "SOCKS5 Alt-Svc HTTP/3 integration test exceeded its deadline")?
}
