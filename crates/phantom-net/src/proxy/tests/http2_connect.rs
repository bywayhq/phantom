use std::time::Duration;

use bytes::Bytes;
use http::{Method, Response};
use phantom_profile::chromium::v154_http2;
use phantom_testkit::http2::CLIENT_CONNECTION_PREFACE;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex},
    net::TcpListener,
    sync::oneshot,
    time::timeout,
};

use super::https_connect::tls_settings;
use crate::{
    http2::Http2Connection,
    proxy::{
        HttpBasicCredentials, HttpConnectError, HttpConnectErrorKind, HttpConnectHeader,
        HttpsProxyConnector, HttpsProxyProtocol,
        http2_connect::{self, PreparedHttp2Connect},
    },
    request::RequestHeader,
    tls::test_support::{
        TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity, TestResult, TestServerAlpn, accept_tls,
        loopback_listener,
    },
};

const ORIGIN: &str = "origin.example:443";

#[tokio::test]
async fn h2_proxy_transport_requires_h2_alpn_selection() -> TestResult<()> {
    bounded(async {
        for (alpn, expected_http1) in [(TestServerAlpn::Http1, true), (TestServerAlpn::None, false)]
        {
            let identity = TestIdentity::generate()?;
            let connector = http2_connector(&identity)?;
            let (address, listener) = loopback_listener().await?;
            let acceptor = identity.acceptor(alpn)?;
            let proxy_task = tokio::spawn(async move {
                let (mut stream, _) = accept_tls(listener, acceptor).await?;
                let mut byte = [0_u8; 1];
                let read = timeout(Duration::from_millis(250), stream.read(&mut byte)).await;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(matches!(read, Ok(Ok(0))))
            });

            let error = connector
                .connect_tunnel(
                    "127.0.0.1",
                    address.port(),
                    TEST_SERVER_NAME,
                    ORIGIN,
                    &[HttpConnectHeader::authority("Host")],
                )
                .await
                .err()
                .ok_or("HTTP/2 proxy transport accepted a non-h2 selection")?;
            if expected_http1 {
                assert!(matches!(
                    error,
                    HttpConnectError::UnsupportedAlpn { ref selected }
                        if selected.as_ref() == b"http/1.1"
                ));
            } else {
                assert!(matches!(error, HttpConnectError::MissingNegotiatedAlpn));
            }
            assert_eq!(error.kind(), HttpConnectErrorKind::UnsupportedProtocol);
            assert!(
                proxy_task.await??,
                "proxy received bytes after ALPN mismatch"
            );
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn h2_proxy_configuration_errors_precede_proxy_io() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (address, listener) = loopback_listener().await?;

    let mut http1_only = tls_settings();
    http1_only.alpn_protocols = vec![Box::from(&b"http/1.1"[..])];
    let missing_h2 =
        HttpsProxyConnector::new_with_additional_roots(&http1_only, [identity.root_der()])?
            .with_http2_settings(&v154_http2())
            .with_protocol(HttpsProxyProtocol::Http2);
    let missing_settings =
        HttpsProxyConnector::new_with_additional_roots(&tls_settings(), [identity.root_der()])?
            .with_protocol(HttpsProxyProtocol::Http2);
    let connector = http2_connector(&identity)?;

    for (connector, headers, expected) in [
        (
            &missing_h2,
            vec![HttpConnectHeader::authority("Host")],
            "missing_h2",
        ),
        (
            &missing_settings,
            vec![HttpConnectHeader::authority("Host")],
            "missing_settings",
        ),
        (
            &connector,
            vec![
                HttpConnectHeader::authority("Host"),
                HttpConnectHeader::field(RequestHeader::new("Proxy-Connection", "keep-alive")),
            ],
            "connection_header",
        ),
    ] {
        let error = connector
            .connect_tunnel(
                "127.0.0.1",
                address.port(),
                TEST_SERVER_NAME,
                ORIGIN,
                &headers,
            )
            .await
            .err()
            .ok_or("invalid HTTP/2 proxy configuration was accepted")?;
        match expected {
            "missing_h2" => assert!(matches!(error, HttpConnectError::MissingH2Alpn)),
            "missing_settings" => {
                assert!(matches!(error, HttpConnectError::MissingHttp2Settings));
            }
            _ => assert!(matches!(
                error,
                HttpConnectError::Http2ConnectionHeader { index: 1 }
            )),
        }
    }
    let error = connector
        .connect_forward("127.0.0.1", address.port(), TEST_SERVER_NAME)
        .await
        .err()
        .ok_or("HTTP/2 proxy transport accepted absolute-form forwarding")?;
    assert!(matches!(error, HttpConnectError::ForwardingRequiresHttp1));
    assert_eq!(error.kind(), HttpConnectErrorKind::InvalidConfiguration);
    assert!(
        timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err(),
        "invalid HTTP/2 proxy configuration opened a proxy connection"
    );
    Ok(())
}

#[tokio::test]
async fn h2_proxy_connect_emits_two_field_pseudo_order() -> TestResult<()> {
    bounded(async {
        let (client, mut server) = duplex(64 * 1024);
        let request = PreparedHttp2Connect::new(
            ORIGIN,
            &[
                HttpConnectHeader::field(RequestHeader::new("User-Agent", "fixture")),
                HttpConnectHeader::authority("host"),
                HttpConnectHeader::field(RequestHeader::new("X-Order", "last")),
            ],
        )?;
        let exchange = tokio::spawn(async move {
            let connection = Http2Connection::connect(client, &v154_http2()).await?;
            http2_connect::establish(&connection, &request)
                .await
                .map(drop)
                .map_err(Box::<dyn std::error::Error + Send + Sync>::from)
        });

        let mut preface = [0_u8; 24];
        server.read_exact(&mut preface).await?;
        assert_eq!(&preface, CLIENT_CONNECTION_PREFACE);
        let (flags, payload) = loop {
            let (frame_type, flags, payload) = read_raw_frame(&mut server).await?;
            if frame_type == 1 {
                break (flags, payload);
            }
        };
        assert_eq!(flags & 0x01, 0, "CONNECT must keep its stream open");
        // The Chromium profile's HEADERS priority fields precede the block.
        assert_ne!(flags & 0x20, 0);
        let names = static_name_indexes(&payload[5..])?;
        // HPACK static table: 1 `:authority`, 2 or 3 `:method`, 58
        // `user-agent`, and 0 for a literal name (`x-order`). `:path` (4, 5)
        // and `:scheme` (6, 7) are absent.
        assert!(matches!(names.as_slice(), [2 | 3, 1, 58, 0]), "{names:?}");

        drop(server);
        assert!(exchange.await?.is_err());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn h2_proxy_tunnel_backpressures_origin_tls() -> TestResult<()> {
    const WINDOW: u32 = 1024;
    const PAYLOAD: usize = 16 * 1024;
    bounded(async {
        let identity = TestIdentity::generate()?;
        let connector = http2_connector(&identity)?;
        let (address, listener) = loopback_listener().await?;
        let acceptor = identity.acceptor(TestServerAlpn::H2)?;
        let (release_tx, release_rx) = oneshot::channel::<()>();
        let proxy_task = tokio::spawn(async move {
            let (stream, _) = accept_tls(listener, acceptor).await?;
            let mut connection = ::http2::server::Builder::new()
                .initial_window_size(WINDOW)
                .handshake::<_, Bytes>(stream)
                .await?;
            let (request, mut respond) = connection
                .accept()
                .await
                .ok_or("proxy connection closed before CONNECT")??;
            assert_eq!(request.method(), Method::CONNECT);
            let driver = tokio::spawn(async move {
                while let Some(result) = connection.accept().await {
                    result?;
                }
                Ok::<_, ::http2::Error>(())
            });
            let _send = respond.send_response(Response::new(()), false)?;
            let mut body = request.into_body();
            let mut received = Vec::with_capacity(PAYLOAD);
            let mut release_rx = release_rx;
            // Read without returning capacity until the client has stalled.
            loop {
                tokio::select! {
                    _ = &mut release_rx => break,
                    chunk = body.data() => {
                        let chunk = chunk.ok_or("tunnel ended before release")??;
                        received.extend_from_slice(&chunk);
                    }
                }
            }
            let before_release = received.len();
            body.flow_control().release_capacity(before_release)?;
            while received.len() < PAYLOAD {
                let chunk = body.data().await.ok_or("tunnel ended early")??;
                body.flow_control().release_capacity(chunk.len())?;
                received.extend_from_slice(&chunk);
            }
            driver.abort();
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((before_release, received))
        });

        let mut tunnel = connector
            .connect_tunnel(
                "127.0.0.1",
                address.port(),
                TEST_SERVER_NAME,
                ORIGIN,
                &[HttpConnectHeader::authority("Host")],
            )
            .await?;
        let payload: Vec<u8> = (0..PAYLOAD).map(|index| (index % 251) as u8).collect();
        let mut written = 0;
        let stalled = timeout(Duration::from_millis(300), async {
            while written < PAYLOAD {
                written += tunnel.write(&payload[written..]).await?;
            }
            Ok::<_, std::io::Error>(())
        })
        .await;
        assert!(
            stalled.is_err(),
            "tunnel accepted bytes beyond the stream window"
        );
        assert!(written <= WINDOW as usize, "wrote {written} bytes");

        release_tx.send(()).map_err(|()| "proxy task ended early")?;
        tunnel.write_all(&payload[written..]).await?;
        let (before_release, received) = proxy_task.await??;
        assert!(before_release <= WINDOW as usize);
        assert_eq!(received, payload);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn h2_proxy_tunnel_drop_resets_only_its_stream() -> TestResult<()> {
    bounded(async {
        let (client, server) = duplex(64 * 1024);
        let proxy_task = tokio::spawn(async move {
            let mut connection = ::http2::server::handshake(server).await?;
            let mut accepted = Vec::new();
            for _ in 0..2 {
                let (request, mut respond) = connection
                    .accept()
                    .await
                    .ok_or("proxy connection closed before CONNECT")??;
                let authority = request.uri().authority().map(ToString::to_string);
                let send = respond.send_response(Response::new(()), false)?;
                accepted.push((authority, request.into_body(), send));
            }
            let driver = tokio::spawn(async move {
                while let Some(result) = connection.accept().await {
                    result?;
                }
                Ok::<_, ::http2::Error>(())
            });
            let (second_authority, mut second_body, mut second_send) =
                accepted.pop().ok_or("missing second tunnel")?;
            let (first_authority, mut first_body, _first_send) =
                accepted.pop().ok_or("missing first tunnel")?;
            let first_reset = match first_body.data().await {
                Some(Err(error)) => error.reason(),
                _ => None,
            };
            let echoed = second_body.data().await.ok_or("second tunnel ended")??;
            second_body.flow_control().release_capacity(echoed.len())?;
            second_send.send_data(echoed, false)?;
            let still_open = !driver.is_finished();
            let _ = timeout(TEST_TIMEOUT, driver).await;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((
                first_authority,
                second_authority,
                first_reset,
                still_open,
            ))
        });

        let connection = Http2Connection::connect(client, &v154_http2()).await?;
        let first = PreparedHttp2Connect::new(
            "first.example:443",
            &[HttpConnectHeader::authority("host")],
        )?;
        let second = PreparedHttp2Connect::new(
            "second.example:443",
            &[HttpConnectHeader::authority("host")],
        )?;
        let first = http2_connect::establish(&connection, &first).await?;
        let mut second = http2_connect::establish(&connection, &second).await?;
        drop(first);

        second.write_all(b"ping").await?;
        let mut echoed = [0_u8; 4];
        second.read_exact(&mut echoed).await?;
        assert_eq!(&echoed, b"ping");
        drop(second);
        drop(connection);

        let (first_authority, second_authority, first_reset, still_open) = proxy_task.await??;
        assert_eq!(first_authority.as_deref(), Some("first.example:443"));
        assert_eq!(second_authority.as_deref(), Some("second.example:443"));
        assert_eq!(first_reset, Some(::http2::Reason::CANCEL));
        assert!(
            still_open,
            "dropping one tunnel closed the proxy connection"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn h2_proxy_rejection_is_typed() -> TestResult<()> {
    bounded(async {
        for (status, challenge, credentials) in [
            (403, None, false),
            (407, Some("Basic realm=\"proxy\""), false),
            (407, Some("Basic realm=\"proxy\""), true),
        ] {
            let identity = TestIdentity::generate()?;
            let connector = http2_connector(&identity)?;
            let (address, listener) = loopback_listener().await?;
            let acceptor = identity.acceptor(TestServerAlpn::H2)?;
            let attempts = if credentials { 2 } else { 1 };
            let proxy_task = tokio::spawn(async move {
                let listener = listener;
                for _ in 0..attempts {
                    reject_one(&listener, &acceptor, status, challenge).await?;
                }
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            });

            let result = if credentials {
                connector
                    .connect_tunnel_with_basic_auth(
                        "127.0.0.1",
                        address.port(),
                        TEST_SERVER_NAME,
                        ORIGIN,
                        &[
                            HttpConnectHeader::authority("Host"),
                            HttpConnectHeader::proxy_authorization("Proxy-Authorization"),
                        ],
                        &HttpBasicCredentials::new("alice", "secret")?,
                    )
                    .await
            } else {
                connector
                    .connect_tunnel(
                        "127.0.0.1",
                        address.port(),
                        TEST_SERVER_NAME,
                        ORIGIN,
                        &[HttpConnectHeader::authority("Host")],
                    )
                    .await
            };
            let error = result.err().ok_or("rejected HTTP/2 CONNECT succeeded")?;
            if credentials {
                assert!(matches!(error, HttpConnectError::AuthenticationRejected));
                assert_eq!(error.kind(), HttpConnectErrorKind::Authentication);
            } else {
                assert!(
                    matches!(error, HttpConnectError::Rejected { status: rejected } if rejected == status)
                );
                assert_eq!(error.kind(), HttpConnectErrorKind::Rejected);
            }
            proxy_task.await??;
        }
        Ok(())
    })
    .await
}

async fn reject_one(
    listener: &TcpListener,
    acceptor: &btls::ssl::SslAcceptor,
    status: u16,
    challenge: Option<&'static str>,
) -> TestResult<()> {
    let (tcp, _) = listener.accept().await?;
    let ssl = btls::ssl::Ssl::new(acceptor.context())?;
    let mut stream = tokio_btls::SslStream::new(ssl, tcp)?;
    std::pin::Pin::new(&mut stream).accept().await?;
    let mut connection = ::http2::server::handshake(stream).await?;
    let (_request, mut respond) = connection
        .accept()
        .await
        .ok_or("proxy connection closed before CONNECT")??;
    let mut response = Response::builder().status(status);
    if let Some(challenge) = challenge {
        response = response.header("proxy-authenticate", challenge);
    }
    respond.send_response(response.body(())?, true)?;
    // The client abandons the connection after one final status.
    if let Some(Ok(_)) = connection.accept().await {
        return Err("client reused a rejected proxy connection".into());
    }
    Ok(())
}

fn http2_connector(identity: &TestIdentity) -> TestResult<HttpsProxyConnector> {
    Ok(
        HttpsProxyConnector::new_with_additional_roots(&tls_settings(), [identity.root_der()])?
            .with_http2_settings(&v154_http2())
            .with_protocol(HttpsProxyProtocol::Http2),
    )
}

async fn read_raw_frame(stream: &mut DuplexStream) -> std::io::Result<(u8, u8, Vec<u8>)> {
    let mut header = [0_u8; 9];
    stream.read_exact(&mut header).await?;
    let length =
        (usize::from(header[0]) << 16) | (usize::from(header[1]) << 8) | usize::from(header[2]);
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload).await?;
    Ok((header[3], header[4], payload))
}

/// Returns each field representation's HPACK static-table name index.
///
/// A literal field name is reported as 0. This decodes representation
/// framing only; values are skipped.
fn static_name_indexes(block: &[u8]) -> TestResult<Vec<usize>> {
    let mut names = Vec::new();
    let mut position = 0;
    while position < block.len() {
        let first = block[position];
        let index = if first & 0x80 != 0 {
            names.push(read_integer(block, &mut position, 7)?);
            continue;
        } else if first & 0xc0 == 0x40 {
            read_integer(block, &mut position, 6)?
        } else if first & 0xe0 == 0x20 {
            read_integer(block, &mut position, 5)?;
            continue;
        } else {
            read_integer(block, &mut position, 4)?
        };
        if index == 0 {
            skip_string(block, &mut position)?;
        }
        skip_string(block, &mut position)?;
        names.push(index);
    }
    Ok(names)
}

fn read_integer(block: &[u8], position: &mut usize, prefix_bits: u32) -> TestResult<usize> {
    let mask = (1_usize << prefix_bits) - 1;
    let mut value = usize::from(*block.get(*position).ok_or("truncated integer")?) & mask;
    *position += 1;
    if value < mask {
        return Ok(value);
    }
    let mut shift = 0;
    loop {
        let byte = *block.get(*position).ok_or("truncated integer")?;
        *position += 1;
        value += usize::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
}

fn skip_string(block: &[u8], position: &mut usize) -> TestResult<()> {
    let length = read_integer(block, position, 7)?;
    *position += length;
    if *position > block.len() {
        return Err("truncated string".into());
    }
    Ok(())
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: std::future::Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "HTTP/2 proxy test exceeded its deadline")?
}
