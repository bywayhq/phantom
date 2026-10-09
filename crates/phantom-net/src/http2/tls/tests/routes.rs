#[cfg(feature = "https-records")]
use crate::route::ConnectedStream;

use super::*;
use crate::{
    proxy::{HttpBasicCredentials, HttpConnectError, HttpsProxyConnector, HttpsProxyProtocol},
    route::{DirectTlsSetup, Http2Route, OriginRoute},
    tcp::AddressFamilyMemory,
};

fn assert_invalid_route<T>(future: impl Future<Output = Result<T, Http2TlsError>>) {
    let mut future = pin!(future);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(matches!(
        future.as_mut().poll(&mut context),
        std::task::Poll::Ready(Err(Http2TlsError::Connect(error)))
            if error.kind() == std::io::ErrorKind::InvalidInput
    ));
}

#[test]
fn unsupported_origin_modes_fail_without_a_runtime() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let connector = test_connector(&identity)?;
    let family = AddressFamilyMemory::new();
    for operation in 0..3 {
        for plaintext in [true, false] {
            let tcp = TcpRoute::Direct(Endpoint {
                host: "127.0.0.1",
                port: 0,
            });
            let origin = if plaintext {
                OriginRoute::Plaintext { tcp, family: None }
            } else {
                OriginRoute::Tls {
                    tcp,
                    server_name: TEST_SERVER_NAME,
                    setup: DirectTlsSetup::KeepSlower(&family),
                }
            };
            let route = Http2Route::Origin(origin);
            match operation {
                0 => assert_invalid_route(connector.connect(route)),
                1 => assert_invalid_route(connector.send(
                    route,
                    http::Method::GET,
                    TEST_AUTHORITY,
                    OriginForm::parse("/")?,
                    Vec::new(),
                    None,
                )),
                _ => assert_invalid_route(connector.extended_connect(
                    route,
                    TEST_AUTHORITY,
                    OriginForm::parse("/")?,
                    Vec::new(),
                )),
            }
        }
    }
    Ok(())
}

#[cfg(feature = "https-records")]
#[test]
fn ech_on_a_connected_stream_fails_without_polling_lookup_or_stream() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let connector = test_connector(&identity)?;
    for operation in 0..3 {
        let polls = Arc::new(AtomicUsize::new(0));
        let touches = Arc::new(AtomicUsize::new(0));
        let lookup_polls = Arc::clone(&polls);
        let mut lookup = pin!(poll_fn(move |_| {
            lookup_polls.fetch_add(1, Ordering::SeqCst);
            std::task::Poll::Ready(None)
        }));
        let (client, _server) = duplex(128);
        let route = Http2Route::Origin(OriginRoute::Tls {
            tcp: TcpRoute::Connected(ConnectedStream::new(TouchCountingStream::new(
                client,
                Arc::clone(&touches),
            ))),
            server_name: TEST_SERVER_NAME,
            setup: DirectTlsSetup::Ech(lookup.as_mut()),
        });
        match operation {
            0 => assert_invalid_route(connector.connect(route)),
            1 => assert_invalid_route(connector.send(
                route,
                http::Method::GET,
                TEST_AUTHORITY,
                OriginForm::parse("/")?,
                Vec::new(),
                None,
            )),
            _ => assert_invalid_route(connector.extended_connect(
                route,
                TEST_AUTHORITY,
                OriginForm::parse("/")?,
                Vec::new(),
            )),
        }
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(touches.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[test]
fn extended_connect_rejects_forwarding_before_io() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let connector = test_connector(&identity)?;
    let proxy_connector = HttpsProxyConnector::new(&tls_settings())?
        .with_protocol(HttpsProxyProtocol::Http2)
        .with_http2_settings(&v154_http2());
    let route = Http2Route::Forward {
        proxy: ProxyTransport::Tls {
            endpoint: Endpoint {
                host: "127.0.0.1",
                port: 0,
            },
            server_name: TEST_SERVER_NAME,
            connector: &proxy_connector,
        },
        credentials: None,
    };
    assert_invalid_route(connector.extended_connect(
        route,
        TEST_AUTHORITY,
        OriginForm::parse("/")?,
        Vec::new(),
    ));
    Ok(())
}

#[test]
fn forwarding_requires_exact_http2_proxy_configuration_before_io() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let connector = test_connector(&identity)?;
    let proxy_connector = HttpsProxyConnector::new(&tls_settings())?;
    for use_tls in [false, true] {
        for send in [false, true] {
            let endpoint = Endpoint {
                host: "127.0.0.1",
                port: 0,
            };
            let proxy = if use_tls {
                ProxyTransport::Tls {
                    endpoint,
                    server_name: TEST_SERVER_NAME,
                    connector: &proxy_connector,
                }
            } else {
                ProxyTransport::Tcp(endpoint)
            };
            let route = Http2Route::Forward {
                proxy,
                credentials: None,
            };
            let mut context = std::task::Context::from_waker(std::task::Waker::noop());
            let ready = if send {
                let mut future = pin!(connector.send(
                    route,
                    http::Method::GET,
                    TEST_AUTHORITY,
                    OriginForm::parse("/")?,
                    Vec::new(),
                    None,
                ));
                matches!(
                    future.as_mut().poll(&mut context),
                    std::task::Poll::Ready(Err(Http2TlsError::Proxy(
                        HttpConnectError::ForwardingRequiresHttp2
                    )))
                )
            } else {
                let mut future = pin!(connector.connect(route));
                matches!(
                    future.as_mut().poll(&mut context),
                    std::task::Poll::Ready(Err(Http2TlsError::Proxy(
                        HttpConnectError::ForwardingRequiresHttp2
                    )))
                )
            };
            assert!(ready);
        }
    }
    Ok(())
}

#[test]
fn forwarding_validates_requests_before_proxy_setup() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let connector = test_connector(&identity)?;
    let proxy_connector = HttpsProxyConnector::new(&tls_settings())?
        .with_protocol(HttpsProxyProtocol::Http2)
        .with_http2_settings(&v154_http2());
    let mut request = pin!(connector.send(
        Http2Route::Forward {
            proxy: ProxyTransport::Tls {
                endpoint: Endpoint {
                    host: "127.0.0.1",
                    port: 0
                },
                server_name: TEST_SERVER_NAME,
                connector: &proxy_connector,
            },
            credentials: None,
        },
        http::Method::GET,
        "user@example.test",
        OriginForm::parse("/")?,
        Vec::new(),
        None,
    ));
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(matches!(
        request.as_mut().poll(&mut context),
        std::task::Poll::Ready(Err(Http2TlsError::Http2(
            Http2Error::AuthorityContainsUserinfo
        )))
    ));
    Ok(())
}

#[tokio::test]
async fn forwarding_uses_proxy_profile_http_scheme_and_no_automatic_credentials() -> TestResult<()>
{
    bounded_tls_test(async {
        let identity = TestIdentity::generate()?;
        let (address, listener) = loopback_listener().await?;
        let acceptor = identity.acceptor(TestServerAlpn::H2)?;
        let server = tokio::spawn(async move {
            let (stream, _) = accept_tls(listener, acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            let (request, mut respond) = connection
                .accept()
                .await
                .ok_or("forwarding connection closed before request")??;
            let stream_id = respond.stream_id().as_u32();
            let uri = request.uri().clone();
            let authenticated = request.headers().contains_key("proxy-authorization");
            respond.send_response(Response::builder().status(204).body(())?, true)?;
            drop(request);
            drop(respond);
            poll_fn(|cx| connection.poll_closed(cx)).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((stream_id, uri, authenticated))
        });

        let connector = test_connector(&identity)?;
        let mut proxy_settings = v154_http2();
        proxy_settings.streams.first_stream_id = 7;
        let proxy_connector =
            HttpsProxyConnector::new_with_additional_roots(&tls_settings(), [identity.root_der()])?
                .with_protocol(HttpsProxyProtocol::Http2)
                .with_http2_settings(&proxy_settings);
        let credentials = HttpBasicCredentials::new("proxy-user", "proxy-password")?;
        let response = connector
            .send(
                Http2Route::Forward {
                    proxy: ProxyTransport::Tls {
                        endpoint: Endpoint {
                            host: "127.0.0.1",
                            port: address.port(),
                        },
                        server_name: TEST_SERVER_NAME,
                        connector: &proxy_connector,
                    },
                    credentials: Some(&credentials),
                },
                http::Method::GET,
                "forward.example:8080",
                OriginForm::parse("/resource?x=1")?,
                Vec::new(),
                None,
            )
            .await?;
        assert_eq!(response.status(), 204);
        response.into_body().collect().await?;
        let (stream_id, uri, authenticated) = server.await??;
        assert_eq!(stream_id, 7);
        assert_eq!(uri, "http://forward.example:8080/resource?x=1");
        assert!(!authenticated);
        Ok(())
    })
    .await
}
