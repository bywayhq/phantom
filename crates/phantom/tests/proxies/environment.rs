//! Environment snapshots applied to real proxy and origin connections.

use std::{
    error::Error,
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, TcpListener as StdListener},
    num::NonZeroUsize,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use http::Response;
use http_body_util::BodyExt;
use phantom::{
    BuildErrorKind, Client, EnvironmentProxies, HttpProtocol, HttpProxy, RedirectPolicy,
    RequestErrorKind, RequestHeader, Route,
    profile::{ClientProfile, browser::chrome},
};
use phantom_net::proxy::HttpConnectError;
use tokio::{
    io::{AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
    time::timeout,
};

use crate::support::tls::{
    H1_ALPN, H2_ALPN, TestIdentity, TestResult, accept_tls, accept_tls_stream, client_builder,
    read_head, tls_settings,
};

const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

fn listen() -> TestResult<StdListener> {
    let listener = StdListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

fn untouched(listener: &StdListener) {
    assert!(matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
}

fn serve_one(listener: StdListener, reply: Vec<u8>) -> TestResult<JoinHandle<TestResult<Vec<u8>>>> {
    let listener = TcpListener::from_std(listener)?;
    Ok(tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let head = read_head(&mut stream).await?;
        stream.write_all(&reply).await?;
        stream.shutdown().await?;
        Ok(head)
    }))
}

fn proxy_route(listener: &StdListener) -> TestResult<Route> {
    Ok(Route::http_proxy(HttpProxy::new(&format!(
        "http://{}",
        listener.local_addr()?
    ))?))
}

async fn get(client: &Client, url: &str, route: Option<Route>) -> TestResult<()> {
    let mut request = client.get(HttpProtocol::Http1, url)?;
    if let Some(route) = route {
        request = request.route(route);
    }
    let response = request.send().await?;
    assert_eq!(response.status(), 200);
    assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
    Ok(())
}

#[tokio::test]
async fn injected_snapshot_is_owned_and_ambient_settings_are_not_needed() -> TestResult<()> {
    bounded(async {
        let origin = listen()?;
        let proxy = listen()?;
        let proxy_address = proxy.local_addr()?;
        let mut values = vec![("http_proxy".to_owned(), format!("http://{proxy_address}"))];
        let snapshot =
            EnvironmentProxies::from_values(values.iter().map(|(name, value)| (name, value)))?;
        values[0].1 = "invalid replacement".to_owned();
        drop(values);
        let proxy_task = serve_one(proxy, OK.to_vec())?;
        let identity = TestIdentity::generate()?;
        let client = client_builder(&identity, false)
            .environment_proxies(snapshot)
            .build()?;
        let url = format!("http://{}/snapshot?order=%2f", origin.local_addr()?);
        get(&client, &url, None).await?;
        let head = proxy_task.await??;
        assert!(head.starts_with(format!("GET {url} HTTP/1.1\r\n").as_bytes()));
        untouched(&origin);
        Ok(())
    })
    .await
}

#[derive(Clone, Copy, Debug)]
enum Override {
    Inherit,
    Direct,
    Proxy,
}

#[tokio::test]
async fn explicit_request_and_client_routes_win_independently_of_snapshot_setter_order()
-> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        for snapshot_first in [false, true] {
            for client_direct in [false, true] {
                for override_route in [Override::Inherit, Override::Direct, Override::Proxy] {
                    let origin = listen()?;
                    let environment = listen()?;
                    let explicit_client = listen()?;
                    let explicit_request = listen()?;
                    let url = format!("http://{}/precedence", origin.local_addr()?);
                    let snapshot = EnvironmentProxies::from_values([(
                        "http_proxy",
                        format!("http://{}", environment.local_addr()?),
                    )])?;
                    let client_route = if client_direct {
                        Route::Direct
                    } else {
                        proxy_route(&explicit_client)?
                    };
                    let request_route = match override_route {
                        Override::Inherit => None,
                        Override::Direct => Some(Route::Direct),
                        Override::Proxy => Some(proxy_route(&explicit_request)?),
                    };
                    let builder = client_builder(&identity, false);
                    let builder = if snapshot_first {
                        builder.environment_proxies(snapshot).route(client_route)
                    } else {
                        builder.route(client_route).environment_proxies(snapshot)
                    };
                    let client = builder.build()?;
                    let direct = matches!(override_route, Override::Direct)
                        || (matches!(override_route, Override::Inherit) && client_direct);
                    let request_proxy = matches!(override_route, Override::Proxy);
                    let (peer, unused) = if direct {
                        (origin, vec![environment, explicit_client, explicit_request])
                    } else if request_proxy {
                        (explicit_request, vec![origin, environment, explicit_client])
                    } else {
                        (explicit_client, vec![origin, environment, explicit_request])
                    };
                    let server = serve_one(peer, OK.to_vec())?;
                    get(&client, &url, request_route).await?;
                    let head = server.await??;
                    let target = if direct { "/precedence" } else { &url };
                    assert!(
                        head.starts_with(format!("GET {target} HTTP/1.1\r\n").as_bytes()),
                        "{snapshot_first:?} {client_direct:?} {override_route:?}"
                    );
                    for listener in unused {
                        untouched(&listener);
                    }
                }
            }
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn bypass_uses_the_logical_domain_boundary_case_and_effective_port() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        for (host, matches_domain, matches_port) in [
            ("SuB.Example.test.", true, true),
            ("example.test", true, true),
            ("notexample.test", false, true),
            ("example.test", true, false),
        ] {
            let origin = listen()?;
            let other_port = listen()?;
            let proxy = listen()?;
            let address = origin.local_addr()?;
            let rule_port = if matches_port {
                address.port()
            } else {
                other_port.local_addr()?.port()
            };
            let snapshot = EnvironmentProxies::from_values([
                ("http_proxy", format!("http://{}", proxy.local_addr()?)),
                ("no_proxy", format!(".EXAMPLE.test.:{rule_port}")),
            ])?;
            let client = client_builder(&identity, false)
                .environment_proxies(snapshot)
                .resolve(
                    &host.to_ascii_lowercase(),
                    [IpAddr::V4(Ipv4Addr::LOCALHOST)],
                )
                .build()?;
            let direct = matches_domain && matches_port;
            let (peer, unused) = if direct {
                (origin, proxy)
            } else {
                (proxy, origin)
            };
            let server = serve_one(peer, OK.to_vec())?;
            let url = format!("http://{host}:{}/bypass", address.port());
            get(&client, &url, None).await?;
            let head = server.await??;
            if direct {
                assert!(head.starts_with(b"GET /bypass HTTP/1.1\r\n"));
            } else {
                assert!(
                    head.starts_with(
                        format!(
                            "GET http://{}:{}/bypass HTTP/1.1\r\n",
                            host.to_ascii_lowercase(),
                            address.port()
                        )
                        .as_bytes()
                    )
                );
            }
            untouched(&unused);
            untouched(&other_port);
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn redirects_reselect_the_environment_route_in_both_directions() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        for starts_direct in [false, true] {
            let origin = listen()?;
            let proxy = listen()?;
            let direct_url = format!("http://{}/direct", origin.local_addr()?);
            let proxied_url = "http://unresolvable.invalid/proxied";
            let snapshot = EnvironmentProxies::from_values([
                ("http_proxy", format!("http://{}", proxy.local_addr()?)),
                ("no_proxy", "127.0.0.1".to_owned()),
            ])?;
            let (first, second, start, end) = if starts_direct {
                (origin, proxy, direct_url.as_str(), proxied_url)
            } else {
                (proxy, origin, proxied_url, direct_url.as_str())
            };
            let redirect = format!("HTTP/1.1 302 Found\r\nLocation: {end}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            let first_task = serve_one(first, redirect.into_bytes())?;
            let second_task = serve_one(second, OK.to_vec())?;
            let client = client_builder(&identity, false)
                .environment_proxies(snapshot)
                .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
                .build()?;
            get(&client, start, None).await?;
            let initial_head = first_task.await??;
            let final_head = second_task.await??;
            let direct: &[u8] = b"GET /direct HTTP/1.1\r\n";
            let forwarded: &[u8] = b"GET http://unresolvable.invalid/proxied HTTP/1.1\r\n";
            assert!(initial_head.starts_with(if starts_direct { direct } else { forwarded }));
            assert!(final_head.starts_with(if starts_direct { forwarded } else { direct }));
        }
        Ok(())
    }).await
}

#[tokio::test]
async fn rejected_environment_proxy_tunnel_never_connects_to_the_origin_directly() -> TestResult<()>
{
    bounded(async {
        let origin = listen()?;
        let proxy = listen()?;
        let snapshot = EnvironmentProxies::from_values([(
            "https_proxy",
            format!("http://{}", proxy.local_addr()?),
        )])?;
        let server = serve_one(
            proxy,
            b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        )?;
        let identity = TestIdentity::generate()?;
        let client = client_builder(&identity, false)
            .environment_proxies(snapshot)
            .build()?;
        let error = client
            .get(
                HttpProtocol::Http1,
                &format!("https://{}/failure", origin.local_addr()?),
            )?
            .send()
            .await
            .err()
            .ok_or("rejected tunnel succeeded")?;
        assert_eq!(error.kind(), RequestErrorKind::Proxy);
        let head = server.await??;
        assert!(
            head.starts_with(format!("CONNECT {} HTTP/1.1\r\n", origin.local_addr()?).as_bytes())
        );
        untouched(&origin);
        Ok(())
    })
    .await
}

fn field<'a>(head: &'a [u8], name: &str) -> TestResult<Option<&'a str>> {
    Ok(std::str::from_utf8(head)?
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find_map(|(field, value)| field.eq_ignore_ascii_case(name).then(|| value.trim())))
}

#[tokio::test]
async fn environment_credentials_challenge_once_and_remain_partitioned_from_overrides_and_origin()
-> TestResult<()> {
    bounded(async {
        let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = proxy.local_addr()?;
        let marker = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let first_password = format!("{marker:x}-first");
        let second_password = format!("{marker:x}-second");
        let first = std::str::from_utf8(RequestHeader::basic_authorization("alice", &first_password)?.value())?.to_owned();
        let second = std::str::from_utf8(RequestHeader::basic_authorization("bob", &second_password)?.value())?.to_owned();
        let expected = [None, Some(first.clone()), Some(first.clone()), None, Some(second), Some(first), None];
        let snapshot = EnvironmentProxies::from_values([("http_proxy", format!("http://alice:{first_password}@{address}"))])?;
        let alternate = Route::http_proxy(HttpProxy::new(&format!("http://{address}"))?.with_basic_auth("bob", &second_password)?);
        let server = tokio::spawn(async move {
            let mut heads = Vec::new();
            for challenge in [true, false, true, false] {
                let (mut stream, _) = proxy.accept().await?;
                heads.push(read_head(&mut stream).await?);
                if challenge {
                    stream.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=environment\r\nContent-Length: 0\r\n\r\n").await?;
                    heads.push(read_head(&mut stream).await?);
                }
                stream.write_all(OK).await?;
                stream.shutdown().await?;
            }
            Ok::<_, Box<dyn Error + Send + Sync>>(heads)
        });
        let identity = TestIdentity::generate()?;
        let client = client_builder(&identity, false).environment_proxies(snapshot).build()?;
        let url = "http://unresolvable.invalid/auth";
        get(&client, url, None).await?;
        get(&client, url, None).await?;
        get(&client, url, Some(alternate)).await?;
        get(&client, url, None).await?;
        let origin = listen()?;
        let direct_url = format!("http://{}/origin", origin.local_addr()?);
        let origin_server = serve_one(origin, OK.to_vec())?;
        get(&client, &direct_url, Some(Route::Direct)).await?;
        let mut heads = server.await??;
        heads.push(origin_server.await??);
        let actual = heads.iter().map(|head| field(head, "proxy-authorization").map(|value| value.map(str::to_owned))).collect::<TestResult<Vec<_>>>()?;
        assert_eq!(actual, expected);
        assert!(heads.iter().all(|head| field(head, "authorization").is_ok_and(|value| value.is_none())));
        Ok(())
    }).await
}

fn connect_cause(mut error: &(dyn Error + 'static)) -> Option<&HttpConnectError> {
    loop {
        if let Some(cause) = error.downcast_ref() {
            return Some(cause);
        }
        error = error.source()?;
    }
}

#[tokio::test]
async fn h2_only_origin_profile_rejects_the_environment_proxy_h1_alpn_requirement_at_build()
-> TestResult<()> {
    let mut tls = tls_settings();
    tls.alpn_protocols = vec![Box::from(&b"h2"[..])];
    let profile = ClientProfile::new(tls).with_http2(chrome::v154_http2());
    let snapshot = EnvironmentProxies::from_values([("https_proxy", "https://proxy.invalid")])?;
    let error = Client::builder(profile)
        .environment_proxies(snapshot)
        .build()
        .err()
        .ok_or("H2-only proxy fingerprint accepted")?;
    assert_eq!(error.kind(), BuildErrorKind::ProtocolConfiguration);
    assert!(matches!(
        connect_cause(&error),
        Some(HttpConnectError::MissingHttp1Alpn)
    ));
    Ok(())
}

#[tokio::test]
async fn trusted_https_environment_proxy_carries_verified_h2_origin_tls() -> TestResult<()> {
    bounded(async {
        let origin_identity = TestIdentity::generate()?;
        let proxy_identity = TestIdentity::generate()?;
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin_listener.local_addr()?;
        let origin_acceptor = origin_identity.acceptor(H2_ALPN)?;
        let (done, done_rx) = oneshot::channel();
        let origin = tokio::spawn(async move {
            let stream = accept_tls(origin_listener, origin_acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            let (request, mut respond) = connection.accept().await.ok_or("missing tunneled H2 request")??;
            let path = request.uri().path().to_owned();
            let mut body = respond.send_response(Response::new(()), false)?;
            body.send_data(Bytes::from_static(b"verified"), true)?;
            tokio::select! {
                result = done_rx => { result.map_err(|_| "client did not finish H2 response")?; }
                result = connection.accept() => {
                    return Err(format!("H2 connection ended before its response was consumed: {}", result.is_some()).into());
                }
            }
            Ok::<_, Box<dyn Error + Send + Sync>>(path)
        });
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy_acceptor = proxy_identity.acceptor(H1_ALPN)?;
        let proxy = tokio::spawn(async move {
            let mut stream = accept_tls(proxy_listener, proxy_acceptor).await?;
            let connect = read_head(&mut stream).await?;
            let mut target = TcpStream::connect(origin_address).await?;
            stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
            let driver = tokio::spawn(async move { copy_bidirectional(&mut stream, &mut target).await });
            Ok::<_, Box<dyn Error + Send + Sync>>((connect, driver))
        });
        let snapshot = EnvironmentProxies::from_values([("https_proxy", format!("https://{proxy_address}"))])?;
        let client = client_builder(&origin_identity, true)
            .add_proxy_root_certificate_der(proxy_identity.root_der)
            .environment_proxies(snapshot).build()?;
        let response = client.get(HttpProtocol::Http2, &format!("https://{origin_address}/h2"))?.send().await?;
        assert_eq!(response.version(), http::Version::HTTP_2);
        assert_eq!(response.into_body().collect().await?.to_bytes(), "verified");
        done.send(()).map_err(|_| "origin stopped before response finished")?;
        assert_eq!(origin.await??, "/h2");
        let (connect, driver) = proxy.await??;
        assert!(connect.starts_with(format!("CONNECT {origin_address} HTTP/1.1\r\n").as_bytes()));
        driver.abort();
        match driver.await {
            Err(error) if error.is_cancelled() => {}
            Ok(Ok(_)) => {}
            Ok(Err(error)) if matches!(error.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted | io::ErrorKind::BrokenPipe) => {}
            Ok(Err(error)) => return Err(error.into()),
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }).await
}

#[tokio::test]
async fn an_untrusted_https_environment_proxy_is_rejected_without_disabling_verification()
-> TestResult<()> {
    bounded(async {
        let proxy_identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = proxy_identity.acceptor(H1_ALPN)?;
        let proxy = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(accept_tls_stream(tcp, acceptor).await.is_err())
        });
        let snapshot =
            EnvironmentProxies::from_values([("https_proxy", format!("https://{address}"))])?;
        let origin_identity = TestIdentity::generate()?;
        let client = client_builder(&origin_identity, true)
            .environment_proxies(snapshot)
            .build()?;
        let error = client
            .get(HttpProtocol::Http2, "https://unresolvable.invalid/")?
            .send()
            .await
            .err()
            .ok_or("untrusted proxy succeeded")?;
        assert!(matches!(
            connect_cause(&error),
            Some(HttpConnectError::ProxyTls(_))
        ));
        assert!(proxy.await??);
        Ok(())
    })
    .await
}

async fn bounded<F: Future<Output = TestResult<()>>>(future: F) -> TestResult<()> {
    timeout(Duration::from_secs(20), future)
        .await
        .map_err(|_| "environment proxy wire test exceeded its deadline")?
}
