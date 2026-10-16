//! Authentication redials keep operation or bounded-entry physical family state.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use btls::ssl::Ssl;
use bytes::Bytes;
use http::Response;
use phantom_profile::{Http2PseudoHeader as H, browser::firefox};
use tokio::{io::AsyncReadExt, net::TcpListener, time::timeout};
use tokio_btls::SslStream;
use tracing::Span;

use super::super::*;
use crate::{
    host_resolver::{AddressResolver, HostResolver},
    tcp::AddressFamily,
    tls::test_support::{TEST_TIMEOUT, TestIdentity, TestResult, TestServerAlpn},
};

fn request(
    path: &str,
    credentials: &HttpBasicCredentials,
) -> Result<PreparedConnectUdp, HttpConnectError> {
    PreparedConnectUdp::new(
        HttpsProxyProtocol::Http2,
        "proxy.test",
        &OriginForm::parse(path).map_err(|_| HttpConnectError::InvalidAuthority)?,
        &[RequestHeader::new("x-current", "marker")],
        Some(credentials),
    )
}

fn disconnected(error: &::http2::Error) -> bool {
    error.get_io().is_some_and(|error| {
        matches!(
            error.kind(),
            io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::BrokenPipe
        )
    })
}

async fn authentication_redial(pooled: bool) -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate_for_names(&["proxy.test"])?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let other_family = TcpListener::bind((Ipv6Addr::LOCALHOST, port)).await?;
        let lookups = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&lookups);
        let resolver = HostResolver::new().with_resolver(AddressResolver::from_fn(move |host| {
            let index = count.fetch_add(1, Ordering::SeqCst);
            async move {
                if host != "proxy.test" {
                    return Err(io::Error::other("locally resolved a tunnel target"));
                }
                Ok(if index == 0 {
                    vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]
                } else {
                    // A lost family owner selects IPv6 here, which the peer rejects.
                    vec![
                        IpAddr::V6(Ipv6Addr::LOCALHOST),
                        IpAddr::V4(Ipv4Addr::LOCALHOST),
                    ]
                })
            }
        }));
        let mut settings = firefox::v157_http2();
        settings.extended_connect_pseudo_header_order = Some(vec![
            H::Method,
            H::Protocol,
            H::Scheme,
            H::Path,
            H::Authority,
        ]);
        let connector = HttpsProxyConnector::new_with_additional_roots(
            &firefox::v157_tcp_tls(),
            [identity.root_der()],
        )?
        .with_http2_settings(&settings)
        .with_tcp_settings(&firefox::v157_tcp())
        .with_host_resolver(resolver)
        .with_protocol(HttpsProxyProtocol::Http2);
        let credentials = HttpBasicCredentials::new("fixture", "secret")?;
        let fields = [RequestHeader::new("x-current", "marker")];
        let pool = ConnectUdpProxyPool::new();
        let key = PoolKey::http2(
            &connector,
            "proxy.test",
            port,
            "proxy.test",
            &fields,
            Some(&credentials),
        )?;
        let prepared = if pooled {
            Some(connector.prepare_connect_udp_outer(
                &pool,
                "proxy.test",
                port,
                "proxy.test",
                &fields,
                Some(&credentials),
            )?)
        } else {
            None
        };
        let client = async {
            let first_request = request("/first", &credentials)?;
            let mut tunnel = if pooled {
                connector
                    .connect_udp_pooled_tunnel(
                        &pool,
                        key.clone(),
                        prepared.as_ref(),
                        "proxy.test",
                        port,
                        first_request,
                        &Span::none(),
                    )
                    .await?
            } else {
                connector
                    .connect_udp_tunnel(
                        "proxy.test",
                        port,
                        "proxy.test",
                        first_request,
                        &Span::none(),
                    )
                    .await?
            };
            let mut prefix = [0; 2];
            tunnel.read_exact(&mut prefix).await?;
            assert_eq!(&prefix, b"ok");
            drop(tunnel);
            if pooled {
                // A new logical tunnel uses the authenticated outer and its original entry.
                let mut tunnel = connector
                    .connect_udp_pooled_tunnel(
                        &pool,
                        key.clone(),
                        prepared.as_ref(),
                        "proxy.test",
                        port,
                        request("/next", &credentials)?,
                        &Span::none(),
                    )
                    .await?;
                tunnel.read_exact(&mut prefix).await?;
                assert_eq!(&prefix, b"ok");
                drop(tunnel);
                pool.clear();
                let Acquisition::Setup(setup) = pool.acquire(key).await? else {
                    return Err("clear kept a reusable outer".into());
                };
                assert_eq!(setup.family()?.family(), Some(AddressFamily::Ipv4));
                drop(setup);
            }
            assert_eq!(lookups.load(Ordering::SeqCst), 2);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let server = async {
            let acceptor = identity.acceptor(TestServerAlpn::H2)?;
            for round in 0..2 {
                let (socket, _) = tokio::select! {
                    biased;
                    accepted = other_family.accept() => {
                        drop(accepted?);
                        return Err("authentication retry lost the physical proxy family".into());
                    }
                    accepted = listener.accept() => accepted?,
                };
                let mut stream = SslStream::new(Ssl::new(acceptor.context())?, socket)?;
                Pin::new(&mut stream).accept().await?;
                let mut builder = ::http2::server::Builder::new();
                builder.enable_connect_protocol();
                let mut connection = builder.handshake::<_, Bytes>(stream).await?;
                let requests = if pooled && round == 1 { 2 } else { 1 };
                for index in 0..requests {
                    let (request, mut respond) =
                        connection.accept().await.ok_or("missing CONNECT-UDP")??;
                    assert_eq!(request.method(), http::Method::CONNECT);
                    assert_eq!(
                        request.uri().authority().map(|v| v.as_str()),
                        Some("proxy.test")
                    );
                    assert_eq!(
                        request.uri().path(),
                        if index == 0 { "/first" } else { "/next" }
                    );
                    assert_eq!(request.headers()["x-current"], "marker");
                    assert_eq!(request.headers()["capsule-protocol"], "?1");
                    assert_eq!(
                        request
                            .extensions()
                            .get::<::http2::ext::Protocol>()
                            .map(|v| v.as_str()),
                        Some("connect-udp")
                    );
                    assert_eq!(
                        request
                            .headers()
                            .get("proxy-authorization")
                            .map(|v| v.as_bytes()),
                        if round == 0 {
                            None
                        } else {
                            Some(credentials.authorization())
                        }
                    );
                    if round == 0 {
                        drop(
                            respond.send_response(
                                Response::builder()
                                    .status(407)
                                    .header("proxy-authenticate", "Basic realm=\"fixture\"")
                                    .body(())?,
                                true,
                            )?,
                        );
                    } else {
                        let mut send = respond.send_response(Response::new(()), false)?;
                        send.send_data(Bytes::from_static(b"ok"), true)?;
                    }
                    drop(request);
                }
                match connection.accept().await {
                    None => {}
                    Some(Err(error)) if disconnected(&error) => {}
                    Some(Err(error)) => return Err(error.into()),
                    Some(Ok(_)) => return Err("unexpected additional CONNECT-UDP".into()),
                }
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        tokio::try_join!(client, server)?;
        Ok(())
    })
    .await
    .map_err(|_| "CONNECT-UDP authentication ownership exceeded its deadline")?
}

#[tokio::test]
async fn dedicated_authentication_retry_keeps_the_operations_proxy_family() -> TestResult<()> {
    authentication_redial(false).await
}

#[tokio::test]
async fn prepared_shared_authentication_retry_and_next_tunnel_keep_the_entry_family()
-> TestResult<()> {
    authentication_redial(true).await
}
