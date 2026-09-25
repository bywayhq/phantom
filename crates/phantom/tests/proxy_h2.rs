//! HTTP/2 transport to HTTPS proxies through the public route API.

#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;

use std::{
    error::Error as StdError,
    future::{Future, poll_fn},
    io,
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use btls::ssl::SslAcceptor;
use bytes::Bytes;
use http::{Method, Response};
use http_body_util::BodyExt;
use phantom::{
    Client, HttpProtocol, HttpProxy, PreparedRequestTemplate, ProxyConfigErrorKind,
    RequestErrorKind, RequestHeader, ResponseInfo, Route,
    profile::{
        ClientProfile, Http2Settings, RequestTemplate, brave, chromium, edge, firefox, opera,
    },
};
use phantom_net::proxy::HttpConnectError;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    time::timeout,
};

use tls_support::{
    H1_ALPN, H2_ALPN, TestIdentity, TestResult, accept_tls, accept_tls_stream, client_builder,
    is_peer_gone, read_head, tls_settings,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(10);

#[test]
fn plaintext_proxy_rejects_h2_transport_configuration() -> TestResult<()> {
    let error = match HttpProxy::new("http://127.0.0.1:8080")?.with_http2_transport() {
        Ok(_) => return Err("plaintext proxy accepted HTTP/2 transport".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), ProxyConfigErrorKind::UnsupportedTransport);
    HttpProxy::new("https://127.0.0.1:8443")?.with_http2_transport()?;
    Ok(())
}

#[tokio::test]
async fn h1_origin_over_h2_proxy_tunnel_completes_request() -> TestResult<()> {
    bounded(async {
        let origin_identity = TestIdentity::generate()?;
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin_listener.local_addr()?;
        let origin_acceptor = origin_identity.acceptor(H1_ALPN)?;
        let origin = tokio::spawn(async move {
            let mut stream = accept_tls(origin_listener, origin_acceptor).await?;
            let request = read_head(&mut stream).await?;
            let mut body = [0_u8; 7];
            stream.read_exact(&mut body).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecure")
                .await?;
            stream.shutdown().await?;
            Ok::<_, Box<dyn StdError + Send + Sync>>((request, body))
        });

        let proxy = H2Proxy::bind().await?;
        let (proxy_uri, proxy_root, acceptor, listener) = proxy.into_parts()?;
        let proxy_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            serve_connect(tcp, &acceptor, Reply::Tunnel(origin_address)).await
        });
        let route = Route::http_proxy(
            HttpProxy::new(&proxy_uri)?
                .header(RequestHeader::new("User-Agent", "phantom-test"))
                .with_http2_transport()?,
        );
        let client = client_builder(&origin_identity, true)
            .add_proxy_root_certificate_der(proxy_root)
            .route(route)
            .build()?;

        let response = client
            .request(
                HttpProtocol::Http1,
                Method::POST,
                &format!("https://{origin_address}/through-h2-proxy"),
            )?
            .body(Bytes::from_static(b"payload"))
            .send()
            .await?;
        assert_eq!(response.status(), 200);
        assert_eq!(response.into_body().collect().await?.to_bytes(), "secure");

        let record = proxy_task.await??;
        assert_eq!(record.authority.as_deref(), Some(origin_address.to_string().as_str()));
        assert_eq!(
            record.fields,
            [("user-agent".to_owned(), b"phantom-test".to_vec())]
        );
        let (request, body) = origin.await??;
        assert_eq!(
            request,
            format!(
                "POST /through-h2-proxy HTTP/1.1\r\nHost: {origin_address}\r\nContent-Length: 7\r\n\r\n"
            )
            .as_bytes()
        );
        assert_eq!(&body, b"payload");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn h2_origin_over_h2_proxy_tunnel_completes_request() -> TestResult<()> {
    bounded(async {
        let origin_identity = TestIdentity::generate()?;
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin_listener.local_addr()?;
        let origin_acceptor = origin_identity.acceptor(H2_ALPN)?;
        let origin = tokio::spawn(async move {
            let stream = accept_tls(origin_listener, origin_acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            let (request, mut respond) = connection
                .accept()
                .await
                .ok_or("origin connection closed before request")??;
            let mut send = respond.send_response(Response::new(()), false)?;
            send.send_data(Bytes::from_static(b"h2-in-h2"), true)?;
            let path = request.uri().path().to_owned();
            drop(request);
            while let Some(result) = connection.accept().await {
                if result.is_err() {
                    break;
                }
            }
            Ok::<_, Box<dyn StdError + Send + Sync>>(path)
        });

        let proxy = H2Proxy::bind().await?;
        let (proxy_uri, proxy_root, acceptor, listener) = proxy.into_parts()?;
        let proxy_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            serve_connect(tcp, &acceptor, Reply::Tunnel(origin_address)).await
        });
        let route = Route::http_proxy(HttpProxy::new(&proxy_uri)?.with_http2_transport()?);
        let client = client_builder(&origin_identity, true)
            .add_proxy_root_certificate_der(proxy_root)
            .route(route)
            .build()?;

        let response = client
            .get(
                HttpProtocol::Http2,
                &format!("https://{origin_address}/nested"),
            )?
            .send()
            .await?;
        assert_eq!(response.into_body().collect().await?.to_bytes(), "h2-in-h2");
        drop(client);

        let record = proxy_task.await??;
        assert_eq!(
            record.authority.as_deref(),
            Some(origin_address.to_string().as_str())
        );
        assert!(record.fields.is_empty(), "{:?}", record.fields);
        assert_eq!(origin.await??, "/nested");
        Ok(())
    })
    .await
}

/// A challenged CONNECT is replayed once, as stream 3 of the proxy
/// connection that carried the `407` on stream 1, as Chrome 154, Edge 153,
/// and Firefox 156 do in the `https-proxy-auth-secure-hostname` captures.
#[tokio::test]
async fn h2_proxy_basic_challenge_replays_once_on_the_challenged_connection() -> TestResult<()> {
    bounded(async {
        let origin_identity = TestIdentity::generate()?;
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin_listener.local_addr()?;
        let origin_acceptor = origin_identity.acceptor(H1_ALPN)?;
        let origin = tokio::spawn(async move {
            let mut stream = accept_tls(origin_listener, origin_acceptor).await?;
            read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await?;
            stream.shutdown().await?;
            Ok::<_, Box<dyn StdError + Send + Sync>>(())
        });

        let proxy = H2Proxy::bind().await?;
        let (proxy_uri, proxy_root, acceptor, listener) = proxy.into_parts()?;
        let proxy_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let records = serve_connects(
                tcp,
                &acceptor,
                vec![Reply::Challenge, Reply::Tunnel(origin_address)],
            )
            .await?;
            let second = timeout(Duration::from_millis(100), listener.accept()).await;
            Ok::<_, Box<dyn StdError + Send + Sync>>((records, second.is_err()))
        });
        let route = Route::http_proxy(
            HttpProxy::new(&proxy_uri)?
                .with_basic_auth("alice", "secret")?
                .with_http2_transport()?,
        );
        let client = client_builder(&origin_identity, true)
            .add_proxy_root_certificate_der(proxy_root)
            .route(route)
            .build()?;

        let response = client
            .get(HttpProtocol::Http1, &format!("https://{origin_address}/"))?
            .send()
            .await?;
        assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");

        let (records, one_connection) = proxy_task.await??;
        assert!(one_connection, "the replay opened a new proxy connection");
        let [challenged, authorized] = records.as_slice() else {
            return Err(format!("expected two CONNECT streams, got {records:?}").into());
        };
        assert_eq!((challenged.stream_id, authorized.stream_id), (1, 3));
        assert!(challenged.fields.is_empty(), "{:?}", challenged.fields);
        assert_eq!(
            authorized.fields,
            [(
                "proxy-authorization".to_owned(),
                b"Basic YWxpY2U6c2VjcmV0".to_vec()
            )]
        );
        origin.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn h2_proxy_rejection_is_typed() -> TestResult<()> {
    bounded(async {
        let origin = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        origin.set_nonblocking(true)?;
        let origin_address = origin.local_addr()?;
        let origin_identity = TestIdentity::generate()?;

        let proxy = H2Proxy::bind().await?;
        let (proxy_uri, proxy_root, acceptor, listener) = proxy.into_parts()?;
        let proxy_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            serve_connect(tcp, &acceptor, Reply::Status(403)).await
        });
        let route = Route::http_proxy(HttpProxy::new(&proxy_uri)?.with_http2_transport()?);
        let client = client_builder(&origin_identity, true)
            .add_proxy_root_certificate_der(proxy_root)
            .route(route)
            .build()?;

        let error = match client
            .get(HttpProtocol::Http2, &format!("https://{origin_address}/"))?
            .send()
            .await
        {
            Ok(_) => return Err("rejected HTTP/2 CONNECT succeeded".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), RequestErrorKind::Proxy);
        assert!(matches!(
            connect_error(&error),
            Some(HttpConnectError::Rejected { status: 403 })
        ));
        proxy_task.await??;
        assert!(matches!(
            origin.accept(),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock
        ));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn default_https_proxy_transport_remains_http1() -> TestResult<()> {
    bounded(async {
        let origin_identity = TestIdentity::generate()?;
        let proxy = H2Proxy::bind().await?;
        let (proxy_uri, proxy_root, acceptor, listener) = proxy.into_parts()?;
        let proxy_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let mut stream = accept_tls_stream(tcp, acceptor).await?;
            let mut byte = [0_u8; 1];
            let read = timeout(Duration::from_millis(250), stream.read(&mut byte)).await;
            Ok::<_, Box<dyn StdError + Send + Sync>>(match read {
                Ok(Ok(count)) => count == 0,
                Ok(Err(error)) => is_peer_gone(&error),
                Err(_) => false,
            })
        });
        // The profile offers `h2, http/1.1`; the proxy selects `h2`.
        let route = Route::http_proxy(HttpProxy::new(&proxy_uri)?);
        let client = client_builder(&origin_identity, true)
            .add_proxy_root_certificate_der(proxy_root)
            .route(route)
            .build()?;

        let error = match client
            .get(HttpProtocol::Http1, "https://127.0.0.1:9/")?
            .send()
            .await
        {
            Ok(_) => return Err("default HTTPS proxy transport accepted h2".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), RequestErrorKind::Proxy);
        assert!(matches!(
            connect_error(&error),
            Some(HttpConnectError::UnsupportedAlpn { selected }) if selected.as_ref() == b"h2"
        ));
        assert!(
            proxy_task.await??,
            "HTTP/1.1 CONNECT bytes reached the h2 proxy"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn h2_proxy_transport_rejects_http1_selection_without_fallback() -> TestResult<()> {
    bounded(async {
        let origin_identity = TestIdentity::generate()?;
        let proxy_identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = listener.local_addr()?;
        let acceptor = proxy_identity.acceptor(H1_ALPN)?;
        let proxy_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let mut stream = accept_tls_stream(tcp, acceptor).await?;
            let mut byte = [0_u8; 1];
            let read = timeout(Duration::from_millis(250), stream.read(&mut byte)).await;
            Ok::<_, Box<dyn StdError + Send + Sync>>(match read {
                Ok(Ok(count)) => count == 0,
                Ok(Err(error)) => is_peer_gone(&error),
                Err(_) => false,
            })
        });
        let route = Route::http_proxy(
            HttpProxy::new(&format!("https://{proxy_address}"))?.with_http2_transport()?,
        );
        let client = client_builder(&origin_identity, true)
            .add_proxy_root_certificate_der(proxy_identity.root_der.clone())
            .route(route)
            .build()?;

        let error = match client
            .get(HttpProtocol::Http2, "https://127.0.0.1:9/")?
            .send()
            .await
        {
            Ok(_) => return Err("HTTP/2 proxy transport fell back to HTTP/1.1".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), RequestErrorKind::Proxy);
        assert!(matches!(
            connect_error(&error),
            Some(HttpConnectError::UnsupportedAlpn { selected }) if selected.as_ref() == b"http/1.1"
        ));
        assert!(
            proxy_task.await??,
            "HTTP/1.1 CONNECT bytes reached the proxy"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn exact_http1_plaintext_request_over_h2_proxy_is_rejected_before_io() -> TestResult<()> {
    let origin_identity = TestIdentity::generate()?;
    let proxy = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    proxy.set_nonblocking(true)?;
    let proxy_address = proxy.local_addr()?;
    let route = Route::http_proxy(
        HttpProxy::new(&format!("https://{proxy_address}"))?.with_http2_transport()?,
    );
    let client = client_builder(&origin_identity, true)
        .route(route)
        .build()?;

    // The proxy speaks HTTP/2, so an exact HTTP/1.1 request cannot reach it
    // as HTTP/1.1; it is refused rather than sent as HTTP/2.
    let error = match client
        .get(HttpProtocol::Http1, "http://origin.invalid/")?
        .send()
        .await
    {
        Ok(_) => return Err("exact HTTP/1.1 request was sent over HTTP/2 transport".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), RequestErrorKind::UnsupportedRoute);
    assert_eq!(error.protocol(), Some(HttpProtocol::Http1));
    assert!(matches!(
        proxy.accept(),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock
    ));
    Ok(())
}

#[tokio::test]
async fn h2_forwarding_answers_a_challenge_on_the_same_connection_then_sends_credentials_first()
-> TestResult<()> {
    bounded(async {
        let origin_identity = TestIdentity::generate()?;
        let proxy = H2Proxy::bind().await?;
        let (proxy_uri, proxy_root, acceptor, listener) = proxy.into_parts()?;
        let proxy_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let record = serve_forwarded_statuses(tcp, &acceptor, &[407, 200, 200]).await?;
            let second = timeout(Duration::from_millis(100), listener.accept()).await;
            Ok::<_, Box<dyn StdError + Send + Sync>>((record, second.is_err()))
        });
        let route = Route::http_proxy(
            HttpProxy::new(&proxy_uri)?
                .with_basic_auth("alice", "secret")?
                .with_http2_transport()?,
        );
        let client = client_builder(&origin_identity, true)
            .add_proxy_root_certificate_der(proxy_root)
            .route(route)
            .build()?;

        for path in ["/first", "/second"] {
            let response = client
                .get(
                    HttpProtocol::Http2,
                    &format!("http://origin.test:8080{path}"),
                )?
                .send()
                .await?;
            assert_eq!(response.status(), 200);
            assert_eq!(
                response.into_body().collect().await?.to_bytes(),
                "forwarded"
            );
        }

        let (record, had_one_proxy_connection) = proxy_task.await??;
        assert!(had_one_proxy_connection);
        let credentials = (
            "proxy-authorization".to_owned(),
            b"Basic YWxpY2U6c2VjcmV0".to_vec(),
        );
        let fields: Vec<_> = record
            .requests
            .iter()
            .map(|request| (request.path.as_str(), request.fields.clone()))
            .collect();
        assert_eq!(
            fields,
            [
                ("/first", Vec::new()),
                ("/first", vec![credentials.clone()]),
                ("/second", vec![credentials]),
            ]
        );
        // The replay and the remembered request carry `proxy-authorization`
        // as a never-indexed literal (0x10 prefix) naming static entry 49,
        // so the credentials never enter either HPACK dynamic table.
        let blocks = header_blocks(&record.client_wire)?;
        assert_eq!(blocks.len(), 3);
        assert!(!hpack_representations(blocks[0])?.contains(&(Representation::NeverIndexed, 49)));
        for block in &blocks[1..] {
            let representations = hpack_representations(block)?;
            assert!(representations.contains(&(Representation::NeverIndexed, 49)));
            assert!(
                representations
                    .iter()
                    .all(|&(kind, index)| index != 49 || kind == Representation::NeverIndexed)
            );
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn h2_forwarding_fails_after_a_second_challenge() -> TestResult<()> {
    bounded(async {
        let origin_identity = TestIdentity::generate()?;
        let proxy = H2Proxy::bind().await?;
        let (proxy_uri, proxy_root, acceptor, listener) = proxy.into_parts()?;
        let proxy_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            serve_forwarded_statuses(tcp, &acceptor, &[407, 407]).await
        });
        let route = Route::http_proxy(
            HttpProxy::new(&proxy_uri)?
                .with_basic_auth("alice", "secret")?
                .with_http2_transport()?,
        );
        let client = client_builder(&origin_identity, true)
            .add_proxy_root_certificate_der(proxy_root)
            .route(route)
            .build()?;

        let error = match client
            .get(HttpProtocol::Http2, "http://origin.test:8080/")?
            .send()
            .await
        {
            Ok(_) => return Err("a second HTTP/2 forwarding challenge was accepted".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), RequestErrorKind::Proxy);
        assert_eq!(error.protocol(), Some(HttpProtocol::Http2));
        assert!(matches!(
            connect_error(&error),
            Some(HttpConnectError::AuthenticationRejected)
        ));
        assert!(!format!("{error:?}").contains("YWxpY2U6c2VjcmV0"));
        assert_eq!(proxy_task.await??.requests.len(), 2);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn h2_proxy_tunnels_send_remembered_credentials_on_the_first_connect() -> TestResult<()> {
    bounded(async {
        let origin_identity = TestIdentity::generate()?;
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin_listener.local_addr()?;
        let origin_acceptor = origin_identity.acceptor(H1_ALPN)?;
        let origin = tokio::spawn(async move {
            for _ in 0..2 {
                let (tcp, _) = origin_listener.accept().await?;
                let mut stream = accept_tls_stream(tcp, origin_acceptor.clone()).await?;
                read_head(&mut stream).await?;
                // Closing each connection makes the next request open a new
                // tunnel.
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok",
                    )
                    .await?;
                stream.shutdown().await?;
            }
            Ok::<_, Box<dyn StdError + Send + Sync>>(())
        });

        let proxy = H2Proxy::bind().await?;
        let (proxy_uri, proxy_root, acceptor, listener) = proxy.into_parts()?;
        let proxy_task = tokio::spawn(async move {
            let mut records = Vec::new();
            // The first tunnel's replay shares its challenged connection.
            for replies in [
                vec![Reply::Challenge, Reply::Tunnel(origin_address)],
                vec![Reply::Tunnel(origin_address)],
            ] {
                let (tcp, _) = listener.accept().await?;
                records.extend(serve_connects(tcp, &acceptor, replies).await?);
            }
            let third = timeout(Duration::from_millis(100), listener.accept()).await;
            Ok::<_, Box<dyn StdError + Send + Sync>>((records, third.is_err()))
        });
        let route = Route::http_proxy(
            HttpProxy::new(&proxy_uri)?
                .with_basic_auth("alice", "secret")?
                .with_http2_transport()?,
        );
        let client = client_builder(&origin_identity, true)
            .add_proxy_root_certificate_der(proxy_root)
            .route(route)
            .build()?;

        for _ in 0..2 {
            let response = client
                .get(HttpProtocol::Http1, &format!("https://{origin_address}/"))?
                .send()
                .await?;
            assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
        }

        let (records, no_third_connection) = proxy_task.await??;
        assert!(no_third_connection);
        let streams: Vec<u32> = records.iter().map(|record| record.stream_id).collect();
        assert_eq!(streams, [1, 3, 1]);
        let credentials = vec![(
            "proxy-authorization".to_owned(),
            b"Basic YWxpY2U6c2VjcmV0".to_vec(),
        )];
        assert!(records[0].fields.is_empty());
        assert_eq!(records[1].fields, credentials);
        assert_eq!(records[2].fields, credentials);
        origin.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn chromium_forwards_http_over_h2_proxy_with_the_captured_pseudo_order() -> TestResult<()> {
    // fixtures/proxy/{chrome,edge}/*/https-proxy-*.txt: every forwarded
    // request's pseudo-fields.
    assert_h2_forwarding(
        chromium::v154_http2(),
        &[":method", ":authority", ":scheme", ":path"],
    )
    .await
}

#[tokio::test]
async fn firefox_forwards_http_over_h2_proxy_with_the_captured_pseudo_order() -> TestResult<()> {
    // fixtures/proxy/firefox/156.0/*/https-proxy-*.txt.
    assert_h2_forwarding(
        firefox::v156_http2(),
        &[":method", ":path", ":authority", ":scheme"],
    )
    .await
}

macro_rules! proxy_fixture {
    ($browser:literal, $scenario:literal) => {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/proxy/",
            $browser,
            "/windows-11-26200/",
            $scenario,
            ".txt"
        ))
    };
}

/// Returns the ordinary field names of every client HEADERS block of run 0
/// that carries `:scheme`, which leaves out CONNECT, ordered by proxy
/// connection and then by block.
fn captured_forwarded_blocks(fixture: &str) -> TestResult<Vec<Vec<String>>> {
    captured_blocks(fixture, true)
}

/// Returns the ordinary field names of the run-0 client HEADERS blocks that
/// carry `:scheme` (`forwarded`) or do not (CONNECT), ordered by proxy
/// connection and then by block.
fn captured_blocks(fixture: &str, forwarded: bool) -> TestResult<Vec<Vec<String>>> {
    Ok(captured_h2_blocks(fixture)?
        .into_iter()
        .filter(|block| block.pseudo.contains_key(":scheme") == forwarded)
        .map(|block| block.names)
        .collect())
}

/// One run-0 client HEADERS block of a `phantom-proxy-route-v1` capture.
struct CapturedBlock {
    /// Pseudo-field values; a redacted value is never a pseudo-field.
    pseudo: std::collections::BTreeMap<String, String>,
    /// Ordinary field names in order.
    names: Vec<String>,
}

/// Returns every run-0 client HEADERS block that the capture kept, ordered
/// by proxy connection and then by block.
fn captured_h2_blocks(fixture: &str) -> TestResult<Vec<CapturedBlock>> {
    let values: std::collections::BTreeMap<&str, &str> = fixture
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect();
    let mut keys = Vec::new();
    for key in values.keys() {
        let Some(rest) = key
            .strip_prefix("run_0_connection_")
            .and_then(|rest| rest.strip_suffix("_field_count"))
        else {
            continue;
        };
        let (connection, block) = rest
            .split_once("_headers_")
            .ok_or("unexpected field-count key")?;
        keys.push((connection.parse::<usize>()?, block.parse::<usize>()?));
    }
    keys.sort_unstable();
    let decode = |hex: &str| -> TestResult<String> {
        if hex == "none" {
            return Ok(String::new());
        }
        let bytes = (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(String::from_utf8(bytes)?)
    };
    let mut blocks = Vec::new();
    for (connection, block) in keys {
        let prefix = format!("run_0_connection_{connection}_headers_{block}");
        let count: usize = values
            .get(format!("{prefix}_field_count").as_str())
            .ok_or("capture omitted a field count")?
            .parse()?;
        let mut pseudo = std::collections::BTreeMap::new();
        let mut names = Vec::new();
        for index in 0..count {
            let record = values
                .get(format!("{prefix}_field_{index}").as_str())
                .ok_or("capture omitted a field")?;
            let attribute = |name: &str| {
                record
                    .split(',')
                    .find_map(|item| item.strip_prefix(name)?.strip_prefix(':'))
                    .ok_or_else(|| format!("capture field omitted {name}"))
            };
            if attribute("repr")? == "size-update" {
                continue;
            }
            let name = decode(attribute("name_hex")?)?;
            if name.starts_with(':') {
                pseudo.insert(name, decode(attribute("value_hex")?)?);
            } else {
                names.push(name);
            }
        }
        blocks.push(CapturedBlock { pseudo, names });
    }
    Ok(blocks)
}

/// Returns the names of the first captured CONNECT to port `port` that
/// carries `proxy-authorization`, or that carries none.
fn captured_connect(fixture: &str, port: &str, credential: bool) -> TestResult<Vec<String>> {
    captured_h2_blocks(fixture)?
        .into_iter()
        .find(|block| {
            block.pseudo.get(":method").map(String::as_str) == Some("CONNECT")
                && block
                    .pseudo
                    .get(":authority")
                    .is_some_and(|authority| authority.ends_with(&format!(":{port}")))
                && block.names.iter().any(|name| name == "proxy-authorization") == credential
        })
        .map(|block| block.names)
        .ok_or_else(|| format!("capture has no CONNECT to port {port}").into())
}

/// One browser's label, H2 settings, navigation and fetch templates, two
/// proxy route captures, and the caller fields its templates need.
type ForwardingCase = (
    &'static str,
    Http2Settings,
    RequestTemplate,
    RequestTemplate,
    &'static str,
    &'static str,
    &'static [(&'static str, &'static str)],
);

/// A navigation challenged by an HTTP/2 proxy and its replay place
/// `proxy-authorization` where Chrome 154, Edge 153, Brave 154, Opera 135,
/// and Firefox 156 do in
/// the `https-proxy-auth-hostname` captures, and a no-store `fetch()` that
/// sends remembered credentials first places it where they do in the
/// `https-proxy-auth-nostore-hostname` captures. Every run of each agrees.
/// The field stays a never-indexed literal on static name 49.
#[tokio::test]
async fn h2_forwarding_places_proxy_credentials_as_captured() -> TestResult<()> {
    const EDGE_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36 Edg/153.0.0.0";
    const BRAVE_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36";
    const OPERA_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36 OPR/135.0.0.0";
    let cases: [ForwardingCase; 5] = [
        (
            "chrome",
            chromium::v154_http2(),
            chromium::v154_windows_navigation_template(),
            chromium::v154_windows_fetch_no_store_template(),
            proxy_fixture!("chrome/154.0.8037.58", "https-proxy-auth-hostname"),
            proxy_fixture!("chrome/154.0.8037.58", "https-proxy-auth-nostore-hostname"),
            &[],
        ),
        (
            "edge",
            chromium::v154_http2(),
            edge::v153_windows_navigation_template(),
            edge::v153_windows_fetch_no_store_template(),
            proxy_fixture!("edge/153.0.4234.48", "https-proxy-auth-hostname"),
            proxy_fixture!("edge/153.0.4234.48", "https-proxy-auth-nostore-hostname"),
            &[("user-agent", EDGE_UA)],
        ),
        (
            "brave",
            chromium::v154_http2(),
            brave::v154_windows_navigation_template(),
            brave::v154_windows_fetch_no_store_template(),
            proxy_fixture!("brave/154.1.96.59", "https-proxy-auth-hostname"),
            proxy_fixture!("brave/154.1.96.59", "https-proxy-auth-nostore-hostname"),
            &[
                ("user-agent", BRAVE_UA),
                ("accept-language", "en-US,en;q=0.7"),
            ],
        ),
        (
            "opera",
            chromium::v154_http2(),
            opera::v135_windows_navigation_template(),
            opera::v135_windows_fetch_no_store_template(),
            proxy_fixture!("opera/135.0.5973.92", "https-proxy-auth-hostname"),
            proxy_fixture!("opera/135.0.5973.92", "https-proxy-auth-nostore-hostname"),
            &[("user-agent", OPERA_UA)],
        ),
        (
            "firefox",
            firefox::v156_http2(),
            firefox::v156_windows_navigation_template(),
            firefox::v156_windows_fetch_no_store_template(),
            proxy_fixture!("firefox/156.0", "https-proxy-auth-hostname"),
            proxy_fixture!("firefox/156.0", "https-proxy-auth-nostore-hostname"),
            &[],
        ),
    ];
    for (label, http2, navigation, fetch, fixture, nostore, caller_fields) in cases {
        let captured = captured_forwarded_blocks(fixture)?;
        let [challenged, replay, _] = captured.as_slice() else {
            return Err(format!("{label}: expected three forwarded requests").into());
        };
        let remembered = captured_h2_blocks(nostore)?
            .into_iter()
            .find(|block| {
                block
                    .pseudo
                    .get(":path")
                    .is_some_and(|path| path.starts_with("/done"))
            })
            .map(|block| block.names)
            .ok_or("capture has no remembered no-store fetch")?;
        bounded(async {
            let proxy = H2Proxy::bind().await?;
            let (proxy_uri, proxy_root, acceptor, listener) = proxy.into_parts()?;
            let proxy_task = tokio::spawn(async move {
                let (tcp, _) = listener.accept().await?;
                serve_forwarded_statuses(tcp, &acceptor, &[407, 200, 200]).await
            });
            let route = Route::http_proxy(
                HttpProxy::new(&proxy_uri)?
                    .with_basic_auth("alice", "secret")?
                    .with_http2_transport()?,
            );
            let client = Client::builder(ClientProfile::new(tls_settings()).with_http2(http2))
                .add_proxy_root_certificate_der(proxy_root)
                .route(route)
                .build()?;
            for (path, template, referer) in [
                ("/page", navigation, None),
                ("/done", fetch, Some("http://origin.test:8080/page")),
            ] {
                let mut caller: Vec<RequestHeader> = caller_fields
                    .iter()
                    .map(|(name, value)| RequestHeader::new(*name, *value))
                    .collect();
                caller.extend(referer.map(|value| RequestHeader::new("referer", value)));
                let response = client
                    .get(
                        HttpProtocol::Http2,
                        &format!("http://origin.test:8080{path}"),
                    )?
                    .template(&PreparedRequestTemplate::new(template)?)
                    .headers(caller)
                    .send()
                    .await?;
                assert_eq!(response.status(), 200, "{label} {path}");
                response.into_body().collect().await?;
            }
            let record = proxy_task.await??;
            let names: Vec<Vec<String>> = record
                .requests
                .iter()
                .map(|request| {
                    request
                        .fields
                        .iter()
                        .map(|(name, _)| name.clone())
                        .collect()
                })
                .collect();
            assert_eq!(names[0], *challenged, "{label} challenged");
            assert_eq!(names[1], *replay, "{label} replay");
            assert_eq!(names[2], remembered, "{label} remembered");
            // A template slot does not change the HPACK form: never indexed,
            // naming static entry 49.
            let blocks = header_blocks(&record.client_wire)?;
            assert_eq!(blocks.len(), 3, "{label}");
            for block in &blocks[1..] {
                let representations = hpack_representations(block)?;
                assert!(
                    representations.contains(&(Representation::NeverIndexed, 49)),
                    "{label}"
                );
                assert!(
                    representations
                        .iter()
                        .all(|&(kind, index)| index != 49 || kind == Representation::NeverIndexed),
                    "{label}"
                );
            }
            Ok(())
        })
        .await?;
    }
    Ok(())
}

/// The profile's CONNECT fields on an HTTP/2 proxy for an `https://`
/// tunnel: anonymous, challenged, and on the replay after a `407`, compared
/// with the `https://` CONNECTs of the `https-proxy-secure-hostname` and
/// `https-proxy-auth-secure-hostname` captures of Chrome 154, Edge 153,
/// Brave 154, Opera 135, and Firefox 156.
#[tokio::test]
async fn h2_connect_sends_the_captured_profile_fields() -> TestResult<()> {
    let cases = [
        (
            "chrome",
            chromium::v154_proxy_connect(),
            chromium::v154_windows_navigation_template(),
            proxy_fixture!("chrome/154.0.8037.58", "https-proxy-secure-hostname"),
            proxy_fixture!("chrome/154.0.8037.58", "https-proxy-auth-secure-hostname"),
        ),
        (
            "edge",
            chromium::v154_proxy_connect(),
            chromium::v154_windows_navigation_template(),
            proxy_fixture!("edge/153.0.4234.48", "https-proxy-secure-hostname"),
            proxy_fixture!("edge/153.0.4234.48", "https-proxy-auth-secure-hostname"),
        ),
        (
            "brave",
            chromium::v154_proxy_connect(),
            chromium::v154_windows_navigation_template(),
            proxy_fixture!("brave/154.1.96.59", "https-proxy-secure-hostname"),
            proxy_fixture!("brave/154.1.96.59", "https-proxy-auth-secure-hostname"),
        ),
        (
            "opera",
            chromium::v154_proxy_connect(),
            chromium::v154_windows_navigation_template(),
            proxy_fixture!("opera/135.0.5973.92", "https-proxy-secure-hostname"),
            proxy_fixture!("opera/135.0.5973.92", "https-proxy-auth-secure-hostname"),
        ),
        (
            "firefox",
            firefox::v156_proxy_connect(),
            firefox::v156_windows_navigation_template(),
            proxy_fixture!("firefox/156.0", "https-proxy-secure-hostname"),
            proxy_fixture!("firefox/156.0", "https-proxy-auth-secure-hostname"),
        ),
    ];
    for (label, connect, navigation, anonymous, authenticated) in cases {
        let expected_anonymous = captured_connect(anonymous, "443", false)?;
        let expected_challenged = captured_connect(authenticated, "443", false)?;
        let expected_replay = captured_connect(authenticated, "443", true)?;
        let user_agent = navigation
            .http2_fields
            .iter()
            .find(|field| field.name() == Some("user-agent"))
            .and_then(|field| field.default_value(true))
            .ok_or("template has no user-agent")?
            .as_bytes()
            .to_vec();
        let template = PreparedRequestTemplate::new(navigation)?;
        for credentials in [false, true] {
            bounded(async {
                let origin_identity = TestIdentity::generate()?;
                let proxy = H2Proxy::bind().await?;
                let (proxy_uri, proxy_root, acceptor, listener) = proxy.into_parts()?;
                let proxy_task = tokio::spawn(async move {
                    let replies = if credentials {
                        vec![Reply::Challenge, Reply::Status(502)]
                    } else {
                        vec![Reply::Status(502)]
                    };
                    let (tcp, _) = listener.accept().await?;
                    serve_connects(tcp, &acceptor, replies).await
                });
                let mut proxy = HttpProxy::new(&proxy_uri)?;
                if credentials {
                    proxy = proxy.with_basic_auth("alice", "secret")?;
                }
                let client = Client::builder(
                    ClientProfile::new(tls_settings())
                        .with_http2(if label == "firefox" {
                            firefox::v156_http2()
                        } else {
                            chromium::v154_http2()
                        })
                        .with_proxy_connect(connect.clone()),
                )
                .add_root_certificate_der(origin_identity.root_der.clone())
                .add_proxy_root_certificate_der(proxy_root)
                .route(Route::http_proxy(proxy.with_http2_transport()?))
                .build()?;
                let _ = client
                    .get(HttpProtocol::Http2, "https://origin.test/page")?
                    .template(&template)
                    .send()
                    .await;
                let records = proxy_task.await??;
                let names = |index: usize| -> Vec<String> {
                    records[index]
                        .fields
                        .iter()
                        .map(|(name, _)| name.clone())
                        .collect()
                };
                if credentials {
                    assert_eq!(names(0), expected_challenged, "{label} challenged");
                    assert_eq!(names(1), expected_replay, "{label} replay");
                } else {
                    assert_eq!(names(0), expected_anonymous, "{label} anonymous");
                }
                assert_eq!(records[0].fields[0].1, user_agent, "{label}");
                Ok(())
            })
            .await?;
        }
    }
    Ok(())
}

/// The profile's CONNECT recipe decides what the client sends on the
/// challenged stream before the replay: Chrome 154 and Edge 153 end it, and
/// Firefox 156 leaves it open, as in the `https-proxy-auth-secure-hostname`
/// captures.
#[tokio::test]
async fn h2_connect_closes_the_challenged_stream_as_the_profile_does() -> TestResult<()> {
    for (label, connect, http2, ends) in [
        (
            "chromium",
            chromium::v154_proxy_connect(),
            chromium::v154_http2(),
            true,
        ),
        (
            "firefox",
            firefox::v156_proxy_connect(),
            firefox::v156_http2(),
            false,
        ),
    ] {
        bounded(async {
            let proxy = H2Proxy::bind().await?;
            let (proxy_uri, proxy_root, acceptor, listener) = proxy.into_parts()?;
            let proxy_task = tokio::spawn(async move {
                let (tcp, _) = listener.accept().await?;
                serve_connects(tcp, &acceptor, vec![Reply::Challenge, Reply::Status(502)]).await
            });
            let client = Client::builder(
                ClientProfile::new(tls_settings())
                    .with_http2(http2)
                    .with_proxy_connect(connect),
            )
            .add_proxy_root_certificate_der(proxy_root)
            .route(Route::http_proxy(
                HttpProxy::new(&proxy_uri)?
                    .with_basic_auth("alice", "secret")?
                    .with_http2_transport()?,
            ))
            .build()?;
            let _ = client
                .get(HttpProtocol::Http2, "https://origin.test/page")?
                .send()
                .await;
            let records = proxy_task.await??;
            let streams: Vec<u32> = records.iter().map(|record| record.stream_id).collect();
            assert_eq!(streams, [1, 3], "{label}");
            assert_eq!(records[0].ended_before_next, Some(ends), "{label}");
            Ok(())
        })
        .await?;
    }
    Ok(())
}

/// A `wss://` tunnel on an HTTP/2 proxy sends the profile's CONNECT fields
/// with the opening's `User-Agent`, as the `wss://` CONNECT of each
/// browser's `https-proxy-secure-hostname` capture does.
#[cfg(feature = "websocket")]
#[tokio::test]
async fn h2_wss_connect_sends_the_captured_profile_fields() -> TestResult<()> {
    let cases = [
        (
            chromium::v154_proxy_connect(),
            proxy_fixture!("chrome/154.0.8037.58", "https-proxy-secure-hostname"),
        ),
        (
            chromium::v154_proxy_connect(),
            proxy_fixture!("edge/153.0.4234.48", "https-proxy-secure-hostname"),
        ),
        (
            chromium::v154_proxy_connect(),
            proxy_fixture!("brave/154.1.96.59", "https-proxy-secure-hostname"),
        ),
        (
            chromium::v154_proxy_connect(),
            proxy_fixture!("opera/135.0.5973.92", "https-proxy-secure-hostname"),
        ),
        (
            firefox::v156_proxy_connect(),
            proxy_fixture!("firefox/156.0", "https-proxy-secure-hostname"),
        ),
    ];
    for (connect, fixture) in cases {
        let expected = captured_connect(fixture, "8443", false)?;
        bounded(async {
            let proxy = H2Proxy::bind().await?;
            let (proxy_uri, proxy_root, acceptor, listener) = proxy.into_parts()?;
            let proxy_task = tokio::spawn(async move {
                let (tcp, _) = listener.accept().await?;
                serve_connect(tcp, &acceptor, Reply::Status(502)).await
            });
            let client = Client::builder(
                ClientProfile::new(tls_settings())
                    .with_http2(chromium::v154_http2())
                    .with_proxy_connect(connect.clone()),
            )
            .add_proxy_root_certificate_der(proxy_root)
            .route(Route::http_proxy(
                HttpProxy::new(&proxy_uri)?.with_http2_transport()?,
            ))
            .build()?;
            let _ = client
                .websocket("wss://origin.test:8443/tls")?
                .header(RequestHeader::new("User-Agent", "opening-agent"))
                .connect()
                .await;
            let record = proxy_task.await??;
            let names: Vec<String> = record.fields.iter().map(|(name, _)| name.clone()).collect();
            assert_eq!(names, expected);
            assert_eq!(record.fields[0].1, b"opening-agent");
            Ok(())
        })
        .await?;
    }
    Ok(())
}

/// A no-store `fetch()` challenged by an HTTP/2 proxy and its replay on the
/// same connection, compared with the `https-proxy-auth-nostore-hostname`
/// capture of each browser, and a navigation with the remembered
/// credentials, compared with the `https-proxy-auth-remembered-hostname`
/// capture.
/// Firefox places `proxy-authorization` before `te` on the replayed
/// `fetch()` and after `accept-encoding` on the remembered navigation.
#[tokio::test]
async fn h2_remembered_navigation_and_fetch_replay_place_credentials_as_captured() -> TestResult<()>
{
    const EDGE_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36 Edg/153.0.0.0";
    const BRAVE_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
(KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36";
    const OPERA_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
(KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36 OPR/135.0.0.0";
    let cases: [ForwardingCase; 5] = [
        (
            "chrome",
            chromium::v154_http2(),
            chromium::v154_windows_navigation_template(),
            chromium::v154_windows_fetch_no_store_template(),
            proxy_fixture!(
                "chrome/154.0.8037.58",
                "https-proxy-auth-remembered-hostname"
            ),
            proxy_fixture!("chrome/154.0.8037.58", "https-proxy-auth-nostore-hostname"),
            &[],
        ),
        (
            "edge",
            chromium::v154_http2(),
            edge::v153_windows_navigation_template(),
            edge::v153_windows_fetch_no_store_template(),
            proxy_fixture!("edge/153.0.4234.48", "https-proxy-auth-remembered-hostname"),
            proxy_fixture!("edge/153.0.4234.48", "https-proxy-auth-nostore-hostname"),
            &[("user-agent", EDGE_UA)],
        ),
        (
            "brave",
            chromium::v154_http2(),
            brave::v154_windows_navigation_template(),
            brave::v154_windows_fetch_no_store_template(),
            proxy_fixture!("brave/154.1.96.59", "https-proxy-auth-remembered-hostname"),
            proxy_fixture!("brave/154.1.96.59", "https-proxy-auth-nostore-hostname"),
            &[
                ("user-agent", BRAVE_UA),
                ("accept-language", "en-US,en;q=0.7"),
            ],
        ),
        (
            "opera",
            chromium::v154_http2(),
            opera::v135_windows_navigation_template(),
            opera::v135_windows_fetch_no_store_template(),
            proxy_fixture!(
                "opera/135.0.5973.92",
                "https-proxy-auth-remembered-hostname"
            ),
            proxy_fixture!("opera/135.0.5973.92", "https-proxy-auth-nostore-hostname"),
            &[("user-agent", OPERA_UA)],
        ),
        (
            "firefox",
            firefox::v156_http2(),
            firefox::v156_windows_navigation_template(),
            firefox::v156_windows_fetch_no_store_template(),
            proxy_fixture!("firefox/156.0", "https-proxy-auth-remembered-hostname"),
            proxy_fixture!("firefox/156.0", "https-proxy-auth-nostore-hostname"),
            &[],
        ),
    ];
    for (label, http2, navigation, fetch, fixture, nostore, caller_fields) in cases {
        let blocks = captured_h2_blocks(fixture)?;
        let nostore = captured_h2_blocks(nostore)?;
        let find = |path: &str, credential: bool| -> TestResult<Vec<String>> {
            let blocks = if path == "/probe" { &nostore } else { &blocks };
            blocks
                .iter()
                .find(|block| {
                    block
                        .pseudo
                        .get(":path")
                        .is_some_and(|value| value.starts_with(path))
                        && block.names.iter().any(|name| name == "proxy-authorization")
                            == credential
                })
                .map(|block| block.names.clone())
                .ok_or_else(|| format!("{label}: capture has no {path} request").into())
        };
        let expected = [
            find("/probe", false)?,
            find("/probe", true)?,
            find("/page", true)?,
        ];
        bounded(async {
            let proxy = H2Proxy::bind().await?;
            let (proxy_uri, proxy_root, acceptor, listener) = proxy.into_parts()?;
            let proxy_task = tokio::spawn(async move {
                let (tcp, _) = listener.accept().await?;
                serve_forwarded_statuses(tcp, &acceptor, &[407, 200, 200]).await
            });
            let route = Route::http_proxy(
                HttpProxy::new(&proxy_uri)?
                    .with_basic_auth("alice", "secret")?
                    .with_http2_transport()?,
            );
            let client = Client::builder(ClientProfile::new(tls_settings()).with_http2(http2))
                .add_proxy_root_certificate_der(proxy_root)
                .route(route)
                .build()?;
            for (path, template, referer) in [
                ("/probe", fetch, Some("http://origin.test:8080/page")),
                ("/page", navigation, None),
            ] {
                let mut caller: Vec<RequestHeader> = caller_fields
                    .iter()
                    .map(|(name, value)| RequestHeader::new(*name, *value))
                    .collect();
                caller.extend(referer.map(|value| RequestHeader::new("referer", value)));
                let response = client
                    .get(
                        HttpProtocol::Http2,
                        &format!("http://origin.test:8080{path}"),
                    )?
                    .template(&PreparedRequestTemplate::new(template)?)
                    .headers(caller)
                    .send()
                    .await?;
                assert_eq!(response.status(), 200, "{label} {path}");
                response.into_body().collect().await?;
            }
            let record = proxy_task.await??;
            let names: Vec<Vec<String>> = record
                .requests
                .iter()
                .map(|request| {
                    request
                        .fields
                        .iter()
                        .map(|(name, _)| name.clone())
                        .collect()
                })
                .collect();
            assert_eq!(names, expected, "{label}");
            Ok(())
        })
        .await?;
    }
    Ok(())
}

/// Sends an exact H2 and a negotiated `http://` request through an HTTP/2
/// proxy and checks what the proxy received.
///
/// Both requests share one proxy connection, carry `:scheme` `http` and the
/// origin in `:authority`, and report HTTP/2. The first HEADERS block's
/// pseudo-fields follow `pseudo_order`.
async fn assert_h2_forwarding(http2: Http2Settings, pseudo_order: &[&str]) -> TestResult<()> {
    bounded(async {
        let origin_identity = TestIdentity::generate()?;
        let proxy = H2Proxy::bind().await?;
        let (proxy_uri, proxy_root, acceptor, listener) = proxy.into_parts()?;
        let proxy_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let record = serve_forwarded(tcp, &acceptor, 2).await?;
            let second = timeout(Duration::from_millis(100), listener.accept()).await;
            Ok::<_, Box<dyn StdError + Send + Sync>>((record, second.is_err()))
        });
        let route = Route::http_proxy(HttpProxy::new(&proxy_uri)?.with_http2_transport()?);
        let client = Client::builder(ClientProfile::new(tls_settings()).with_http2(http2))
            .add_root_certificate_der(origin_identity.root_der.clone())
            .add_proxy_root_certificate_der(proxy_root)
            .route(route)
            .build()?;

        let exact = client
            .get(HttpProtocol::Http2, "http://origin.test:8080/page?run=1")?
            .header(RequestHeader::new("user-agent", "phantom-test"))
            .send()
            .await?;
        assert_eq!(
            exact
                .extensions()
                .get::<ResponseInfo>()
                .map(ResponseInfo::protocol),
            Some(HttpProtocol::Http2)
        );
        assert_eq!(exact.into_body().collect().await?.to_bytes(), "forwarded");
        let negotiated = client
            .get_negotiated("http://origin.test:8080/done")?
            .send()
            .await?;
        assert_eq!(
            negotiated
                .extensions()
                .get::<ResponseInfo>()
                .map(ResponseInfo::protocol),
            Some(HttpProtocol::Http2)
        );
        assert_eq!(
            negotiated.into_body().collect().await?.to_bytes(),
            "forwarded"
        );

        let (record, had_one_proxy_connection) = proxy_task.await??;
        assert!(had_one_proxy_connection);
        assert_eq!(record.alpn.as_deref(), Some(b"h2".as_slice()));
        assert_eq!(
            record.requests,
            [
                ForwardedRequest {
                    method: "GET".to_owned(),
                    scheme: Some("http".to_owned()),
                    authority: Some("origin.test:8080".to_owned()),
                    path: "/page?run=1".to_owned(),
                    fields: vec![("user-agent".to_owned(), b"phantom-test".to_vec())],
                },
                ForwardedRequest {
                    method: "GET".to_owned(),
                    scheme: Some("http".to_owned()),
                    authority: Some("origin.test:8080".to_owned()),
                    path: "/done".to_owned(),
                    fields: Vec::new(),
                },
            ]
        );
        assert_eq!(first_pseudo_order(&record.client_wire)?, pseudo_order);
        Ok(())
    })
    .await
}

#[derive(Debug, Eq, PartialEq)]
struct ForwardedRequest {
    method: String,
    scheme: Option<String>,
    authority: Option<String>,
    path: String,
    fields: Vec<(String, Vec<u8>)>,
}

struct ForwardRecord {
    alpn: Option<Vec<u8>>,
    requests: Vec<ForwardedRequest>,
    client_wire: Vec<u8>,
}

/// Serves `count` forwarded requests on one HTTP/2 proxy connection, answering
/// each as the origin with `200` and `forwarded`, and keeps every byte the
/// client sent.
async fn serve_forwarded(
    tcp: TcpStream,
    acceptor: &SslAcceptor,
    count: usize,
) -> TestResult<ForwardRecord> {
    serve_forwarded_statuses(tcp, acceptor, &vec![200; count]).await
}

/// Serves one forwarded request per status on one HTTP/2 proxy connection.
///
/// A `407` carries a Basic challenge and no body; any other status is
/// answered as the origin with `forwarded`.
async fn serve_forwarded_statuses(
    tcp: TcpStream,
    acceptor: &SslAcceptor,
    statuses: &[u16],
) -> TestResult<ForwardRecord> {
    let count = statuses.len();
    let stream = accept_tls_stream(tcp, acceptor.clone()).await?;
    let alpn = stream.ssl().selected_alpn_protocol().map(<[u8]>::to_vec);
    let client_wire = Arc::new(Mutex::new(Vec::new()));
    let recording = Recording {
        inner: stream,
        wire: Arc::clone(&client_wire),
    };
    let mut connection = ::http2::server::handshake(recording).await?;
    let mut requests = Vec::with_capacity(count);
    for &status in statuses {
        let (request, mut respond) = connection
            .accept()
            .await
            .ok_or("proxy connection closed before a forwarded request")??;
        requests.push(ForwardedRequest {
            method: request.method().to_string(),
            scheme: request.uri().scheme_str().map(ToOwned::to_owned),
            authority: request.uri().authority().map(ToString::to_string),
            path: request
                .uri()
                .path_and_query()
                .map_or_else(String::new, ToString::to_string),
            fields: request
                .extensions()
                .get::<::http2::ext::OrderedHeaders>()
                .ok_or("missing ordered request fields")?
                .as_slice()
                .iter()
                .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
                .collect(),
        });
        if status == 407 {
            let response = Response::builder()
                .status(407)
                .header("proxy-authenticate", "Basic realm=\"forward\"")
                .body(())?;
            respond.send_response(response, true)?;
            continue;
        }
        let response = Response::builder().status(status).body(())?;
        let mut send = respond.send_response(response, false)?;
        send.send_data(Bytes::from_static(b"forwarded"), true)?;
    }
    tokio::spawn(async move { while let Some(Ok(_)) = connection.accept().await {} });
    let client_wire = client_wire
        .lock()
        .map_err(|_| "client wire lock was poisoned")?
        .clone();
    Ok(ForwardRecord {
        alpn,
        requests,
        client_wire,
    })
}

/// Returns the pseudo-field names of the first client HEADERS block.
///
/// The block is the connection's first, so its HPACK dynamic table is empty
/// and every pseudo-field name comes from a static index.
fn first_pseudo_order(wire: &[u8]) -> TestResult<Vec<&'static str>> {
    let blocks = header_blocks(wire)?;
    pseudo_names(blocks.first().ok_or("client sent no HEADERS")?)
}

/// Returns every client HEADERS block, in order.
fn header_blocks(wire: &[u8]) -> TestResult<Vec<&[u8]>> {
    const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    if !wire.starts_with(PREFACE) {
        return Err("client omitted the HTTP/2 preface".into());
    }
    let mut offset = PREFACE.len();
    let mut blocks = Vec::new();
    while let Some(head) = wire.get(offset..offset + 9) {
        let length =
            (usize::from(head[0]) << 16) | (usize::from(head[1]) << 8) | usize::from(head[2]);
        let payload = wire
            .get(offset + 9..offset + 9 + length)
            .ok_or("truncated HTTP/2 frame")?;
        offset += 9 + length;
        let (kind, flags) = (head[3], head[4]);
        if kind != 1 {
            continue;
        }
        if flags & 0x08 != 0 || flags & 0x04 == 0 {
            return Err("test decoder supports only unpadded single-frame HEADERS".into());
        }
        blocks.push(if flags & 0x20 != 0 {
            &payload[5..]
        } else {
            payload
        });
    }
    Ok(blocks)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Representation {
    Indexed,
    IncrementalIndexing,
    WithoutIndexing,
    NeverIndexed,
}

/// Returns each field representation of an HPACK block with its name index
/// (0 for a literal name); a table size update is skipped.
fn hpack_representations(block: &[u8]) -> TestResult<Vec<(Representation, usize)>> {
    let mut cursor = 0;
    let mut fields = Vec::new();
    while let Some(&first) = block.get(cursor) {
        let (kind, prefix) = match first {
            byte if byte & 0x80 != 0 => (Representation::Indexed, 7),
            byte if byte & 0xc0 == 0x40 => (Representation::IncrementalIndexing, 6),
            byte if byte & 0xe0 == 0x20 => {
                hpack_integer(block, &mut cursor, 5)?;
                continue;
            }
            byte if byte & 0xf0 == 0x10 => (Representation::NeverIndexed, 4),
            _ => (Representation::WithoutIndexing, 4),
        };
        let index = hpack_integer(block, &mut cursor, prefix)?;
        if kind != Representation::Indexed {
            if index == 0 {
                skip_hpack_string(block, &mut cursor)?;
            }
            skip_hpack_string(block, &mut cursor)?;
        }
        fields.push((kind, index));
    }
    Ok(fields)
}

fn skip_hpack_string(block: &[u8], cursor: &mut usize) -> TestResult<()> {
    let length = hpack_integer(block, cursor, 7)?;
    *cursor += length;
    if *cursor > block.len() {
        return Err("HPACK string is truncated".into());
    }
    Ok(())
}

fn pseudo_names(block: &[u8]) -> TestResult<Vec<&'static str>> {
    let mut cursor = 0;
    let mut names = Vec::new();
    while let Some(&first) = block.get(cursor) {
        if first & 0xe0 == 0x20 {
            hpack_integer(block, &mut cursor, 5)?;
            continue;
        }
        let (indexed, prefix) = if first & 0x80 != 0 {
            (true, 7)
        } else if first & 0xc0 == 0x40 {
            (false, 6)
        } else {
            (false, 4)
        };
        let index = hpack_integer(block, &mut cursor, prefix)?;
        let name = match index {
            1 => ":authority",
            2 | 3 => ":method",
            4 | 5 => ":path",
            6 | 7 => ":scheme",
            _ => return Ok(names),
        };
        if !indexed {
            let length = hpack_integer(block, &mut cursor, 7)?;
            cursor += length;
        }
        names.push(name);
    }
    Ok(names)
}

fn hpack_integer(block: &[u8], cursor: &mut usize, prefix_bits: u8) -> TestResult<usize> {
    let mask = (1_u8 << prefix_bits) - 1;
    let first = *block.get(*cursor).ok_or("HPACK integer is truncated")?;
    *cursor += 1;
    let mut value = usize::from(first & mask);
    if value < usize::from(mask) {
        return Ok(value);
    }
    let mut shift = 0;
    loop {
        let byte = *block.get(*cursor).ok_or("HPACK integer is truncated")?;
        *cursor += 1;
        value += usize::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
}

/// A byte stream that keeps a copy of everything read from it.
struct Recording<S> {
    inner: S,
    wire: Arc<Mutex<Vec<u8>>>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Recording<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(context, buffer);
        if let Ok(mut wire) = self.wire.lock() {
            wire.extend_from_slice(&buffer.filled()[before..]);
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Recording<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

struct H2Proxy {
    identity: TestIdentity,
    listener: TcpListener,
    address: SocketAddr,
}

impl H2Proxy {
    async fn bind() -> TestResult<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        Ok(Self {
            identity: TestIdentity::generate()?,
            listener,
            address,
        })
    }

    fn into_parts(self) -> TestResult<(String, Vec<u8>, SslAcceptor, TcpListener)> {
        let acceptor = self.identity.acceptor(H2_ALPN)?;
        Ok((
            format!("https://{}", self.address),
            self.identity.root_der.clone(),
            acceptor,
            self.listener,
        ))
    }
}

enum Reply {
    Tunnel(SocketAddr),
    Challenge,
    Status(u16),
}

#[derive(Debug)]
struct ConnectRecord {
    stream_id: u32,
    authority: Option<String>,
    fields: Vec<(String, Vec<u8>)>,
    later_requests: usize,
    /// For a challenged CONNECT, whether the client had ended its stream
    /// when its next CONNECT arrived.
    ended_before_next: Option<bool>,
}

/// Serves one HTTP/2 proxy connection with one CONNECT exchange.
async fn serve_connect(
    tcp: TcpStream,
    acceptor: &SslAcceptor,
    reply: Reply,
) -> TestResult<ConnectRecord> {
    serve_connects(tcp, acceptor, vec![reply])
        .await?
        .pop()
        .ok_or_else(|| "no CONNECT was served".into())
}

/// Serves one HTTP/2 proxy connection, answering one CONNECT stream per
/// reply, in order.
///
/// After a final rejection, every later request on the connection is counted
/// in the last record until the client closes it. The HTTP/2 server rejects
/// `:scheme` or `:path` in a classic CONNECT, so every recorded request used
/// the two-field pseudo-header form.
async fn serve_connects(
    tcp: TcpStream,
    acceptor: &SslAcceptor,
    replies: Vec<Reply>,
) -> TestResult<Vec<ConnectRecord>> {
    let stream = accept_tls_stream(tcp, acceptor.clone()).await?;
    let mut connection = ::http2::server::handshake(stream).await?;
    let mut records: Vec<ConnectRecord> = Vec::with_capacity(replies.len());
    let mut tunneled = false;
    // Challenged request bodies stay open, so a client that leaves its side
    // open is not reset by the proxy.
    let mut challenged: Vec<::http2::RecvStream> = Vec::new();
    let mut pending_challenge: Option<(usize, ::http2::RecvStream)> = None;
    for reply in replies {
        let (request, mut respond) = connection
            .accept()
            .await
            .ok_or("proxy connection closed before CONNECT")??;
        if let Some((index, mut body)) = pending_challenge.take() {
            records[index].ended_before_next = Some(has_ended(&mut body));
            challenged.push(body);
        }
        if request.method() != Method::CONNECT {
            return Err("proxy received a non-CONNECT request".into());
        }
        records.push(ConnectRecord {
            stream_id: respond.stream_id().as_u32(),
            authority: request.uri().authority().map(ToString::to_string),
            fields: request
                .extensions()
                .get::<::http2::ext::OrderedHeaders>()
                .ok_or("missing ordered CONNECT fields")?
                .as_slice()
                .iter()
                .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
                .collect(),
            later_requests: 0,
            ended_before_next: None,
        });
        tunneled = matches!(reply, Reply::Tunnel(_));
        match reply {
            Reply::Tunnel(origin) => {
                let send = respond.send_response(Response::new(()), false)?;
                let upstream = TcpStream::connect(origin).await?;
                spawn_relay(request.into_body(), send, upstream);
            }
            Reply::Challenge | Reply::Status(_) => {
                let mut response = Response::builder().status(match reply {
                    Reply::Status(status) => status,
                    _ => 407,
                });
                if matches!(reply, Reply::Challenge) {
                    response = response.header("proxy-authenticate", "Basic realm=\"proxy\"");
                }
                respond.send_response(response.body(())?, true)?;
                if matches!(reply, Reply::Challenge) {
                    pending_challenge = Some((records.len() - 1, request.into_body()));
                }
            }
        }
    }
    if tunneled {
        tokio::spawn(async move {
            let _challenged = (challenged, pending_challenge);
            while let Some(result) = connection.accept().await {
                if result.is_err() {
                    break;
                }
            }
        });
        return Ok(records);
    }
    while let Some(result) = connection.accept().await {
        if result.is_err() {
            break;
        }
        if let Some(record) = records.last_mut() {
            record.later_requests += 1;
        }
    }
    Ok(records)
}

/// Reports whether the client has ended a request body, from the frames
/// the connection has already processed, without waiting.
fn has_ended(body: &mut ::http2::RecvStream) -> bool {
    let mut context = Context::from_waker(std::task::Waker::noop());
    loop {
        match body.poll_data(&mut context) {
            Poll::Ready(Some(Ok(_))) => {}
            Poll::Ready(None) => return true,
            Poll::Ready(Some(Err(_))) | Poll::Pending => return false,
        }
    }
}

fn spawn_relay(
    mut downstream: ::http2::RecvStream,
    mut send: ::http2::SendStream<Bytes>,
    upstream: TcpStream,
) {
    let (mut read, mut write) = upstream.into_split();
    tokio::spawn(async move {
        while let Some(Ok(chunk)) = downstream.data().await {
            let _ = downstream.flow_control().release_capacity(chunk.len());
            if write.write_all(&chunk).await.is_err() {
                return;
            }
        }
        let _ = write.shutdown().await;
    });
    tokio::spawn(async move {
        let mut buffer = vec![0_u8; 16 * 1024];
        loop {
            let count = match read.read(&mut buffer).await {
                Ok(0) | Err(_) => {
                    let _ = send.send_data(Bytes::new(), true);
                    return;
                }
                Ok(count) => count,
            };
            let mut chunk = Bytes::copy_from_slice(&buffer[..count]);
            while !chunk.is_empty() {
                send.reserve_capacity(chunk.len());
                let capacity = match poll_fn(|context| send.poll_capacity(context)).await {
                    Some(Ok(capacity)) => capacity,
                    _ => return,
                };
                let part = chunk.split_to(capacity.min(chunk.len()));
                if send.send_data(part, false).is_err() {
                    return;
                }
            }
        }
    });
}

fn connect_error<'a>(error: &'a (dyn StdError + 'static)) -> Option<&'a HttpConnectError> {
    let mut current = Some(error);
    while let Some(error) = current {
        if let Some(found) = error.downcast_ref::<HttpConnectError>() {
            return Some(found);
        }
        current = error.source();
    }
    None
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "HTTP/2 proxy integration test exceeded its deadline")?
}
