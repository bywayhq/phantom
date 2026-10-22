//! Socket destination admission through the public client.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use phantom::{
    BuildErrorKind, Client, DestinationPolicy, HttpProtocol, RedirectPolicy, RequestErrorKind,
    RetryPolicy, Route, SessionSharing, Socks5Proxy, TcpConnector,
    profile::{ClientProfile, Http3ClientSettings, browser::chrome},
};
use tokio::{io::AsyncWriteExt, net::TcpListener, time::timeout};

use crate::support::tls::{TestResult, read_head};

const WAIT: Duration = Duration::from_secs(10);
const QUIET: Duration = Duration::from_millis(30);

fn profile() -> ClientProfile {
    ClientProfile::new(chrome::v154_tcp_tls())
        .with_http2(chrome::v154_http2())
        .with_http3(Http3ClientSettings::new(
            chrome::v154_quic_tls(),
            chrome::v154_quic(),
            chrome::v154_http3(),
            chrome::v154_http3_request(),
        ))
}

#[tokio::test]
async fn denial_prevents_tcp_quic_and_fallback_without_spending_retries() -> TestResult<()> {
    let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let udp = phantom_testkit::udp::bind_tokio(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let client = Client::builder(profile())
        .destination_policy(DestinationPolicy::from_fn(move |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            false
        }))
        .retry_policy(
            RetryPolicy::connection_failures(NonZeroUsize::MIN, Duration::ZERO)
                .with_http2_fallback(true),
        )
        .build()?;
    for (protocol, scheme, address) in [
        (HttpProtocol::Http1, "http", tcp.local_addr()?),
        (HttpProtocol::Http2, "http", tcp.local_addr()?),
        (HttpProtocol::Http2, "https", tcp.local_addr()?),
        (HttpProtocol::Http3, "https", udp.local_addr()?),
    ] {
        calls.store(0, Ordering::SeqCst);
        let error = timeout(
            WAIT,
            client
                .get(protocol, &format!("{scheme}://{address}/"))?
                .send(),
        )
        .await?
        .err()
        .ok_or("denied request succeeded")?;
        assert_eq!(error.kind(), RequestErrorKind::DestinationDenied);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(!error.to_string().contains(&address.to_string()));
    }
    calls.store(0, Ordering::SeqCst);
    let error = timeout(
        WAIT,
        client
            .get_negotiated(&format!("https://{}/", tcp.local_addr()?))?
            .send(),
    )
    .await?
    .err()
    .ok_or("denied ALPN request succeeded")?;
    assert_eq!(error.kind(), RequestErrorKind::DestinationDenied);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(timeout(QUIET, tcp.accept()).await.is_err());
    assert!(timeout(QUIET, udp.recv(&mut [0; 2048])).await.is_err());
    Ok(())
}

#[tokio::test]
async fn overrides_keep_allowed_order_and_never_connect_to_denied_candidates() -> TestResult<()> {
    let allowed = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let port = allowed.local_addr()?.port();
    let denied_ip = Ipv4Addr::new(127, 0, 0, 2);
    let denied = TcpListener::bind((denied_ip, port)).await?;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&seen);
    let client = Client::builder(profile())
        .resolve(
            "origin.test",
            [IpAddr::V4(denied_ip), IpAddr::V4(Ipv4Addr::LOCALHOST)],
        )
        .destination_policy(DestinationPolicy::from_fn(move |address| {
            observed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(address);
            address.ip() == Ipv4Addr::LOCALHOST
        }))
        .build()?;
    timeout(WAIT, async {
        let send = async {
            let response = client
                .get(HttpProtocol::Http1, &format!("http://origin.test:{port}/"))?
                .send()
                .await?;
            assert_eq!(response.status(), http::StatusCode::OK);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let peer = async {
            let (mut stream, _) = allowed.accept().await?;
            assert!(
                read_head(&mut stream)
                    .await?
                    .starts_with(b"GET / HTTP/1.1\r\n")
            );
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        tokio::try_join!(send, peer)?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    assert_eq!(
        *seen.lock().map_err(|_| "address observations poisoned")?,
        [
            SocketAddr::from((denied_ip, port)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, port))
        ]
    );
    assert!(timeout(QUIET, denied.accept()).await.is_err());
    Ok(())
}

#[tokio::test]
async fn redirect_destination_is_checked_before_its_connection() -> TestResult<()> {
    let initial = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let initial_address = initial.local_addr()?;
    let denied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let denied_address = denied.local_addr()?;
    let client = Client::builder(profile())
        .destination_policy(DestinationPolicy::from_fn(move |address| {
            address == initial_address
        }))
        .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
        .build()?;
    timeout(WAIT, async {
        let send = async {
            let error = client.get(HttpProtocol::Http1, &format!("http://{initial_address}/"))?.send().await
                .err().ok_or("denied redirect succeeded")?;
            assert_eq!(error.kind(), RequestErrorKind::DestinationDenied);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let peer = async {
            let (mut stream, _) = initial.accept().await?;
            read_head(&mut stream).await?;
            stream.write_all(format!("HTTP/1.1 302 Found\r\nLocation: http://{denied_address}/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        tokio::try_join!(send, peer)?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    }).await??;
    assert!(timeout(QUIET, denied.accept()).await.is_err());
    Ok(())
}

#[tokio::test]
async fn forks_and_restored_sessions_keep_the_receiving_policy() -> TestResult<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let url = format!("http://{}/", listener.local_addr()?);
    let client = Client::builder(profile())
        .destination_policy(DestinationPolicy::from_fn(|_| false))
        .build()?;
    let mut clients = vec![
        client.clone(),
        client.fork(SessionSharing::none()),
        client.fork(SessionSharing::none().dns(true)),
    ];
    #[cfg(feature = "session-snapshot")]
    {
        let unguarded = Client::builder(profile()).build()?;
        let key = [31; 32];
        clients.push(client.restore_session(&unguarded.export_session(&key)?, &key, &[])?);
    }
    for client in clients.drain(..) {
        let error = timeout(WAIT, client.get(HttpProtocol::Http1, &url)?.send())
            .await?
            .err()
            .ok_or("retained policy was bypassed")?;
        assert_eq!(error.kind(), RequestErrorKind::DestinationDenied);
    }
    assert!(timeout(QUIET, listener.accept()).await.is_err());
    Ok(())
}

#[tokio::test]
async fn proxy_and_custom_routes_are_rejected_before_callbacks_or_io() -> TestResult<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let proxy = Route::socks5(Socks5Proxy::new(&format!(
        "socks5h://{}",
        listener.local_addr()?
    ))?);
    let policy = DestinationPolicy::from_fn(|_| panic!("opaque destination reached callback"));
    let error = Client::builder(profile())
        .destination_policy(policy.clone())
        .route(proxy.clone())
        .build()
        .err()
        .ok_or("proxy default accepted")?;
    assert_eq!(error.kind(), BuildErrorKind::InvalidPolicy);
    let error = Client::builder(profile())
        .destination_policy(policy.clone())
        .tcp_connector(TcpConnector::from_fn(|_| async {
            panic!("custom connector polled")
        }))
        .build()
        .err()
        .ok_or("custom connector accepted")?;
    assert_eq!(error.kind(), BuildErrorKind::InvalidPolicy);
    let client = Client::builder(profile())
        .destination_policy(policy)
        .build()?;
    let error = client
        .get(HttpProtocol::Http1, "http://origin.test/")?
        .route(proxy)
        .send()
        .await
        .err()
        .ok_or("proxy override accepted")?;
    assert_eq!(error.kind(), RequestErrorKind::UnsupportedRoute);
    assert!(timeout(QUIET, listener.accept()).await.is_err());
    Ok(())
}

#[tokio::test]
async fn event_source_denial_is_terminal_with_its_typed_request_cause() -> TestResult<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let client = Client::builder(profile())
        .destination_policy(DestinationPolicy::from_fn(move |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            false
        }))
        .build()?;
    let error = timeout(
        WAIT,
        client
            .event_source(
                HttpProtocol::Http1,
                &format!("http://{}/events", listener.local_addr()?),
            )?
            .initial_retry(Duration::ZERO)
            .max_reconnects(3)
            .connect(),
    )
    .await?
    .err()
    .ok_or("denied event source connected")?;
    assert_eq!(error.kind(), phantom::SseErrorKind::Request);
    let cause = std::error::Error::source(&error)
        .and_then(|cause| cause.downcast_ref::<phantom::RequestError>())
        .ok_or("missing request cause")?;
    assert_eq!(cause.kind(), RequestErrorKind::DestinationDenied);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(timeout(QUIET, listener.accept()).await.is_err());
    Ok(())
}

#[cfg(feature = "websocket")]
#[tokio::test]
async fn websocket_denial_keeps_its_kind_and_prevents_handshake_retries() -> TestResult<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let client = Client::builder(profile().with_websocket(chrome::v154_websocket()))
        .destination_policy(DestinationPolicy::from_fn(move |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            false
        }))
        .build()?;
    let error = timeout(
        WAIT,
        client
            .websocket_with_protocol(
                HttpProtocol::Http1,
                &format!("ws://{}/", listener.local_addr()?),
            )?
            .retry_policy(phantom::WebSocketRetryPolicy::connection_failures(
                NonZeroUsize::MIN,
                Duration::ZERO,
            ))
            .connect(),
    )
    .await?
    .err()
    .ok_or("denied WebSocket connected")?;
    assert_eq!(error.kind(), phantom::WebSocketErrorKind::DestinationDenied);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(timeout(QUIET, listener.accept()).await.is_err());
    Ok(())
}

#[tokio::test]
async fn low_level_openings_reject_opaque_routes_before_proxy_or_stream_io() -> TestResult<()> {
    use phantom_net::{
        host_resolver::HostResolver,
        http1::{Http1TlsConnector, Http1TlsError},
        route::{Endpoint, Http1Route, HttpConnectRoute, OriginRoute, ProxyTransport, TcpRoute},
        tcp::AddressFamilyMemory,
    };
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let connector = Http1TlsConnector::new(&chrome::v154_tcp_tls())?.with_host_resolver(
        HostResolver::new().with_destination_policy(DestinationPolicy::from_fn(|_| {
            panic!("opaque route reached policy")
        })),
    );
    let endpoint = Endpoint {
        host: "127.0.0.1",
        port: listener.local_addr()?.port(),
    };
    let family = AddressFamilyMemory::default();
    let error = connector
        .open_http_connect_retaining(
            HttpConnectRoute {
                proxy: ProxyTransport::Tcp(endpoint),
                authority: "origin.test:443",
                headers: &[],
                credentials: None,
                speculative_tls: false,
            },
            "origin.test",
            &family,
        )
        .await
        .err()
        .ok_or("opaque proxy opening succeeded")?;
    let Http1TlsError::Connect(source) = error else {
        return Err("missing proxy rejection cause".into());
    };
    assert_eq!(source.kind(), std::io::ErrorKind::Unsupported);
    assert!(timeout(QUIET, listener.accept()).await.is_err());

    let outer = phantom_net::proxy::HttpsProxyConnector::new(&chrome::v154_tcp_tls())?;
    let error = connector
        .open_https_forward_retaining(
            ProxyTransport::Tls {
                endpoint,
                server_name: "localhost",
                connector: &outer,
            },
            &family,
        )
        .await
        .err()
        .ok_or("opaque retained HTTPS forwarding accepted")?;
    let Http1TlsError::Connect(source) = error else {
        return Err("missing retained HTTPS forwarding rejection cause".into());
    };
    assert_eq!(source.kind(), std::io::ErrorKind::Unsupported);
    assert!(timeout(QUIET, listener.accept()).await.is_err());

    let (stream, _peer) = tokio::io::duplex(1024);
    let error = connector
        .connect(Http1Route::Origin(OriginRoute::Plaintext {
            tcp: TcpRoute::Connected(phantom::ConnectedStream::new(stream)),
            family: None,
        }))
        .await
        .err()
        .ok_or("opaque caller stream accepted")?;
    let Http1TlsError::Connect(source) = error else {
        return Err("missing stream rejection cause".into());
    };
    assert_eq!(source.kind(), std::io::ErrorKind::Unsupported);
    Ok(())
}

#[tokio::test]
async fn denied_alternative_stays_available_while_the_permitted_origin_wins() -> TestResult<()> {
    use crate::support::tls::{H1_ALPN, TestIdentity};
    use phantom::{
        AltSvcBrokenBackoff, AltSvcPolicy, AltSvcRace, AltSvcSnapshot, AltSvcSnapshotEntry,
    };
    let identity = TestIdentity::generate()?;
    let acceptor = identity.acceptor(H1_ALPN)?;
    let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let origin_address = origin.local_addr()?;
    let alternative =
        phantom_testkit::udp::bind_tokio(SocketAddr::from((Ipv4Addr::new(127, 0, 0, 2), 0)))?;
    let alternative_address = alternative.local_addr()?;
    let policy_alternative = alternative_address;
    let denied = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&denied);
    let client = Client::builder(profile())
        .add_root_certificate_der(identity.root_der.clone())
        .destination_policy(DestinationPolicy::from_fn(move |address| {
            if address == policy_alternative {
                observed.fetch_add(1, Ordering::SeqCst);
            }
            address == origin_address
        }))
        .alt_svc(NonZeroUsize::MIN)
        .alt_svc_policy(AltSvcPolicy::race(AltSvcRace::new(
            Duration::ZERO,
            AltSvcBrokenBackoff::CHROMIUM_153,
        )))
        .build()?;
    let url = format!("https://{origin_address}");
    client.import_alt_svc(&AltSvcSnapshot::new(vec![AltSvcSnapshotEntry::new(
        url.clone(),
        policy_alternative.ip().to_string(),
        policy_alternative.port(),
        std::time::SystemTime::now() + Duration::from_secs(120),
    )]))?;
    timeout(WAIT, async {
        let send = async {
            for expected in 1..=2 {
                let response = client.get_negotiated(&format!("{url}/"))?.send().await?;
                assert_eq!(response.status(), http::StatusCode::OK);
                assert_eq!(
                    denied.load(Ordering::SeqCst),
                    expected,
                    "a policy denial must not mark the alternative broken"
                );
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let peer = async {
            for _ in 0..2 {
                let (stream, _) = origin.accept().await?;
                let ssl = btls::ssl::Ssl::new(acceptor.context())?;
                let mut stream = tokio_btls::SslStream::new(ssl, stream)?;
                std::pin::Pin::new(&mut stream).accept().await?;
                read_head(&mut stream).await?;
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await?;
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        tokio::try_join!(send, peer)?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    assert!(
        timeout(QUIET, alternative.recv(&mut [0; 2048]))
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn proxy_outer_connectors_reject_origin_policies_without_using_them() -> TestResult<()> {
    use phantom_net::{
        host_resolver::HostResolver,
        http1::{Http1TlsConnector, Http1TlsError},
        http3::Http3Connector,
        proxy::{HttpConnectError, HttpsProxyConnector, HttpsProxyProtocol},
        request::OriginForm,
        route::{Endpoint, Http1Route, ProxyTransport},
    };
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let resolver = HostResolver::new().with_destination_policy(DestinationPolicy::from_fn(|_| {
        panic!("proxy socket reached origin policy")
    }));
    let outer =
        HttpsProxyConnector::new(&chrome::v154_tcp_tls())?.with_host_resolver(resolver.clone());
    let origin = Http1TlsConnector::new(&chrome::v154_tcp_tls())?;
    let error = timeout(
        WAIT,
        origin.connect(Http1Route::Forward(ProxyTransport::Tls {
            endpoint: Endpoint {
                host: "127.0.0.1",
                port: listener.local_addr()?.port(),
            },
            server_name: "localhost",
            connector: &outer,
        })),
    )
    .await?
    .err()
    .ok_or("guarded proxy outer connected")?;
    let Http1TlsError::Proxy(HttpConnectError::Connect(source)) = error else {
        return Err("missing outer proxy rejection cause".into());
    };
    assert_eq!(source.kind(), std::io::ErrorKind::Unsupported);
    assert!(timeout(QUIET, listener.accept()).await.is_err());

    let path = OriginForm::parse("/.well-known/masque/udp/origin.test/443/")?;
    let error = Http3Connector::validate_connect_udp_over_tcp(
        &outer,
        HttpsProxyProtocol::Http1,
        "localhost:443",
        &path,
        &[],
        None,
    )
    .err()
    .ok_or("guarded TCP outer accepted")?;
    assert_unsupported_io(&error)?;

    let outer = Http3Connector::new(
        &chrome::v154_quic_tls(),
        &chrome::v154_quic(),
        &chrome::v154_http3(),
        &chrome::v154_http3_request(),
    )?
    .with_host_resolver(resolver);
    let error = outer
        .validate_connect_udp("localhost", "localhost:443", &path, &[])
        .err()
        .ok_or("guarded QUIC outer accepted")?;
    assert_unsupported_io(&error)?;
    Ok(())
}

fn assert_unsupported_io(error: &(dyn std::error::Error + 'static)) -> TestResult<()> {
    let mut current = Some(error);
    while let Some(cause) = current {
        if let Some(error) = cause.downcast_ref::<std::io::Error>() {
            assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
            return Ok(());
        }
        current = cause.source();
    }
    Err("missing unsupported I/O cause".into())
}
