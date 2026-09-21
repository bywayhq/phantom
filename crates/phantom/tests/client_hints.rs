//! Public client-hint session integration tests.

#[allow(dead_code)]
#[path = "support/h2.rs"]
mod h2_support;
#[allow(dead_code)]
#[path = "support/h3.rs"]
mod h3_support;
#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;

use std::{future::poll_fn, net::Ipv4Addr, pin::Pin, time::Duration};

use btls::ssl::{Ssl, SslAcceptor, SslVersion};
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use phantom::{
    Client, HttpProtocol, RequestErrorKind, RequestHeader,
    profile::{
        AlpsSettings, CipherSuite, ClientHint, ClientHintDelivery, ClientHintSettings,
        ClientProfile, NamedGroup, TlsVersion, chromium,
    },
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};
use tokio_btls::SslStream;

use h2_support::{accept_client_preface, read_request_headers, write_frame};
use h3_support::{accept_request, client_settings, server_endpoint};
use tls_support::{H1_ALPN, H2_ALPN, TestIdentity, TestResult, read_head, tls_settings};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPT_CH_VALUE: &str = "Sec-CH-UA-Arch, Sec-CH-UA-Platform-Version";

#[tokio::test]
async fn http1_client_hints_share_the_canonical_origin_key() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            let mut stream = accept_tls(&listener, &acceptor).await?;
            let first = read_head(&mut stream).await?;
            write_http1_response(&mut stream, Some(ACCEPT_CH_VALUE)).await?;
            let second = read_head(&mut stream).await?;
            write_http1_response(&mut stream, Some("")).await?;
            let third = read_head(&mut stream).await?;
            write_http1_response(&mut stream, None).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>([first, second, third])
        });

        let client = client(&identity)?;
        let session = client.session();
        let url = format!("https://{address}/");
        let unicode_url = format!("https://１２７．０．０．１:{}/", address.port());
        send_and_drain(&session, HttpProtocol::Http1, &unicode_url).await?;
        send_and_drain(&session, HttpProtocol::Http1, &url).await?;
        send_and_drain(&session, HttpProtocol::Http1, &url).await?;

        let requests = server.await??;
        assert_http1_hints(&requests[0], false)?;
        assert_http1_hints(&requests[1], true)?;
        assert_http1_hints(&requests[2], false)?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn http2_client_hints_share_one_session_connection() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let (client_done, wait_for_client) = oneshot::channel();
        let server = tokio::spawn(async move {
            let stream = accept_tls(&listener, &acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;

            let (first, mut first_response) = accept_http2(&mut connection).await?;
            assert_hints(first.headers(), false)?;
            first_response.send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .header("accept-ch", ACCEPT_CH_VALUE)
                    .body(())?,
                true,
            )?;

            let (second, mut second_response) = accept_http2(&mut connection).await?;
            assert_hints(second.headers(), true)?;
            second_response.send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .header("accept-ch", "")
                    .body(())?,
                true,
            )?;

            let (third, mut third_response) = accept_http2(&mut connection).await?;
            assert_hints(third.headers(), false)?;
            third_response.send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(())?,
                true,
            )?;
            drop((
                first,
                first_response,
                second,
                second_response,
                third,
                third_response,
            ));
            drive_http2_until_client_done(&mut connection, wait_for_client).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        let client = client(&identity)?;
        let session = client.session();
        let url = format!("https://{address}/");
        send_and_drain(&session, HttpProtocol::Http2, &url).await?;
        send_and_drain(&session, HttpProtocol::Http2, &url).await?;
        send_and_drain(&session, HttpProtocol::Http2, &url).await?;
        client_done
            .send(())
            .map_err(|_| "HTTP/2 server stopped before client completion")?;
        drop(session);
        server.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn http2_alps_accept_ch_applies_to_the_first_request_without_a_probe() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let origin = format!("https://{address}");
        let application_settings = accept_ch_alps(&origin, ACCEPT_CH_VALUE);
        let mut acceptor = identity.acceptor_builder(H2_ALPN)?;
        acceptor.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        acceptor.set_max_proto_version(Some(SslVersion::TLS1_3))?;
        let acceptor = acceptor.build();
        let (client_done, wait_for_client) = oneshot::channel();
        let server = tokio::spawn(async move {
            let stream = accept_tls_with_alps(&listener, &acceptor, &application_settings).await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            let (request, mut response) = accept_http2(&mut connection).await?;
            assert_eq!(
                request.headers().get("sec-ch-ua"),
                Some(&"baseline".parse()?)
            );
            assert_eq!(
                request.headers().get("sec-ch-ua-arch"),
                Some(&"\"caller\"".parse()?)
            );
            assert_eq!(
                request.headers().get("sec-ch-ua-platform-version"),
                Some(&"\"15.5.0\"".parse()?)
            );
            response.send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(())?,
                true,
            )?;
            drop((request, response));

            let outcome: TestResult<()> = tokio::select! {
                request = connection.accept() => {
                    match request {
                        Some(Ok(_)) => Err("client sent an unexpected HTTP/2 probe request".into()),
                        Some(Err(error)) => Err(error.into()),
                        None => Err("HTTP/2 connection closed before client completion".into()),
                    }
                }
                result = wait_for_client => {
                    result.map_err(|_| "client stopped before HTTP/2 response completion".into())
                }
            };
            outcome
        });

        let response = alps_client(&identity)?
            .session()
            .get(HttpProtocol::Http2, &format!("{origin}/"))?
            .header(RequestHeader::new("sec-ch-ua-arch", "\"caller\""))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response.into_body().collect().await?;
        client_done
            .send(())
            .map_err(|_| "HTTP/2 server stopped before client completion")?;
        server.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn negotiated_http2_applies_alps_and_retains_response_accept_ch() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let origin = format!("https://{address}");
        let application_settings = accept_ch_alps(&origin, ACCEPT_CH_VALUE);
        let mut acceptor = identity.acceptor_builder(H2_ALPN)?;
        acceptor.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        acceptor.set_max_proto_version(Some(SslVersion::TLS1_3))?;
        let acceptor = acceptor.build();
        let server = tokio::spawn(async move {
            let stream = accept_tls_with_alps(&listener, &acceptor, &application_settings).await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            let (request, mut response) = accept_http2(&mut connection).await?;
            assert_eq!(
                request.headers().get("sec-ch-ua"),
                Some(&"baseline".parse()?)
            );
            assert_eq!(
                request.headers().get("sec-ch-ua-arch"),
                Some(&"\"caller\"".parse()?)
            );
            assert_eq!(
                request.headers().get("sec-ch-ua-platform-version"),
                Some(&"\"15.5.0\"".parse()?)
            );
            response.send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .header("accept-ch", "Sec-CH-UA-Arch")
                    .body(())?,
                true,
            )?;
            drop((request, response));
            let (request, mut response) = accept_http2(&mut connection).await?;
            assert_eq!(
                request.headers().get("sec-ch-ua"),
                Some(&"baseline".parse()?)
            );
            assert_eq!(
                request.headers().get("sec-ch-ua-arch"),
                Some(&"\"arm\"".parse()?)
            );
            assert_eq!(
                request.headers().get("sec-ch-ua-platform-version"),
                Some(&"\"15.5.0\"".parse()?)
            );
            response.send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(())?,
                true,
            )?;
            drop((request, response));
            poll_fn(|context| connection.poll_closed(context)).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        let client = alps_client(&identity)?;
        let response = client
            .get_negotiated(&format!("{origin}/"))?
            .header(RequestHeader::new("sec-ch-ua-arch", "\"caller\""))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response.into_body().collect().await?;
        let response = client
            .get_negotiated(&format!("{origin}/retained"))?
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response.into_body().collect().await?;
        drop(client);
        server.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn http2_replacement_uses_only_its_own_alps_accept_ch() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let origin = format!("https://{address}");
        let first_settings = accept_ch_alps(&origin, "Sec-CH-UA-Arch");
        let replacement_settings = accept_ch_alps(&origin, "Sec-CH-UA-Platform-Version");
        let mut acceptor = identity.acceptor_builder(H2_ALPN)?;
        acceptor.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        acceptor.set_max_proto_version(Some(SslVersion::TLS1_3))?;
        let acceptor = acceptor.build();
        let (client_done, wait_for_client) = oneshot::channel();
        let server = tokio::spawn(async move {
            let mut first = accept_tls_with_alps(&listener, &acceptor, &first_settings).await?;
            accept_client_preface(&mut first).await?;
            read_request_headers(&mut first, 1).await?;
            write_frame(&mut first, 0x7, 0, 0, &[0, 0, 0, 0, 0, 0, 0, 0]).await?;
            first.flush().await?;
            first.shutdown().await?;

            let replacement =
                accept_tls_with_alps(&listener, &acceptor, &replacement_settings).await?;
            let mut connection = ::http2::server::handshake(replacement).await?;
            let (request, mut response) = accept_http2(&mut connection).await?;
            assert_eq!(
                request.headers().get("sec-ch-ua"),
                Some(&"baseline".parse()?)
            );
            assert!(!request.headers().contains_key("sec-ch-ua-arch"));
            assert_eq!(
                request.headers().get("sec-ch-ua-platform-version"),
                Some(&"\"15.5.0\"".parse()?)
            );
            response.send_response(
                Response::builder()
                    .status(StatusCode::OK)
                    .header("accept-ch", ACCEPT_CH_VALUE)
                    .header("critical-ch", "Sec-CH-UA-Arch")
                    .body(())?,
                true,
            )?;

            let (retry, mut retry_response) = accept_http2(&mut connection).await?;
            assert_hints(retry.headers(), true)?;
            retry_response.send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(())?,
                true,
            )?;
            drop((request, response, retry, retry_response));
            drive_http2_until_client_done(&mut connection, wait_for_client).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        let response = alps_client(&identity)?
            .session()
            .get(HttpProtocol::Http2, &format!("{origin}/replacement"))?
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response.into_body().collect().await?;
        client_done
            .send(())
            .map_err(|_| "HTTP/2 server stopped before client completion")?;
        server.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn http3_client_hints_share_one_session_connection() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let (address, endpoint) = server_endpoint(&identity)?;
        let (client_done, wait_for_client) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (first, mut first_stream, mut connection) = accept_request(&endpoint).await?;
            assert_hints(first.headers(), false)?;
            first_stream
                .send_response(
                    Response::builder()
                        .status(StatusCode::NO_CONTENT)
                        .header("accept-ch", ACCEPT_CH_VALUE)
                        .body(())?,
                )
                .await?;
            first_stream.finish().await?;
            drop(first_stream);

            let resolver = connection
                .accept()
                .await?
                .ok_or("HTTP/3 connection closed before learned request")?;
            let (second, mut second_stream) = resolver.resolve_request().await?;
            assert_hints(second.headers(), true)?;
            second_stream
                .send_response(
                    Response::builder()
                        .status(StatusCode::NO_CONTENT)
                        .header("accept-ch", "")
                        .body(())?,
                )
                .await?;
            second_stream.finish().await?;
            drop(second_stream);

            let resolver = connection
                .accept()
                .await?
                .ok_or("HTTP/3 connection closed before cleared request")?;
            let (third, mut third_stream) = resolver.resolve_request().await?;
            assert_hints(third.headers(), false)?;
            third_stream
                .send_response(
                    Response::builder()
                        .status(StatusCode::NO_CONTENT)
                        .body(())?,
                )
                .await?;
            third_stream.finish().await?;
            wait_for_client
                .await
                .map_err(|_| "client stopped before HTTP/3 response completion")?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        let client = client(&identity)?;
        let session = client.session();
        let url = format!("https://{address}/");
        send_and_drain(&session, HttpProtocol::Http3, &url).await?;
        send_and_drain(&session, HttpProtocol::Http3, &url).await?;
        send_and_drain(&session, HttpProtocol::Http3, &url).await?;
        let _ = client_done.send(());
        drop(session);
        server.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn critical_ch_retries_once_with_only_supported_requested_hints() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let (client_done, wait_for_client) = oneshot::channel();
        let server = tokio::spawn(async move {
            let stream = accept_tls(&listener, &acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            let (first, mut first_response) = accept_http2(&mut connection).await?;
            assert_hints(first.headers(), false)?;
            first_response.send_response(
                Response::builder()
                    .status(StatusCode::OK)
                    .header("accept-ch", "Sec-CH-UA-Arch, Sec-CH-Unknown")
                    .header("critical-ch", "Sec-CH-UA-Arch, Sec-CH-Unknown")
                    .body(())?,
                true,
            )?;

            let (retry, mut retry_response) = accept_http2(&mut connection).await?;
            assert_eq!(
                retry.headers().get("sec-ch-ua-arch"),
                Some(&"\"arm\"".parse()?)
            );
            assert!(!retry.headers().contains_key("sec-ch-unknown"));
            retry_response.send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .header("accept-ch", "Sec-CH-UA-Arch, Sec-CH-Unknown")
                    .header("critical-ch", "Sec-CH-UA-Arch, Sec-CH-Unknown")
                    .body(())?,
                true,
            )?;
            drop((first, first_response, retry, retry_response));
            drive_http2_until_client_done(&mut connection, wait_for_client).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        let response = client(&identity)?
            .session()
            .get(HttpProtocol::Http2, &format!("https://{address}/"))?
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        response.into_body().collect().await?;
        client_done
            .send(())
            .map_err(|_| "HTTP/2 server stopped before client completion")?;
        server.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn critical_ch_retry_rejects_a_consumed_streaming_body() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let (client_done, wait_for_client) = oneshot::channel();
        let server = tokio::spawn(async move {
            let stream = accept_tls(&listener, &acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            let (first, mut first_response) = accept_http2(&mut connection).await?;
            first_response.send_response(
                Response::builder()
                    .status(StatusCode::OK)
                    .header("accept-ch", "Sec-CH-UA-Arch")
                    .header("critical-ch", "Sec-CH-UA-Arch")
                    .body(())?,
                true,
            )?;
            drop((first, first_response));
            drive_http2_until_client_done(&mut connection, wait_for_client).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        let result = client(&identity)?
            .session()
            .get(HttpProtocol::Http2, &format!("https://{address}/"))?
            .streaming_body(Full::new(Bytes::from_static(b"one-shot")))
            .send()
            .await;
        let error = match result {
            Ok(_) => return Err("Critical-CH retry replayed a one-shot streaming body".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), RequestErrorKind::RequestBody);
        client_done
            .send(())
            .map_err(|_| "HTTP/2 server stopped before client completion")?;
        server.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn client_retains_accept_ch_across_requests() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            let mut stream = accept_tls(&listener, &acceptor).await?;
            let first = read_head(&mut stream).await?;
            write_http1_response(&mut stream, Some(ACCEPT_CH_VALUE)).await?;
            let second = read_head(&mut stream).await?;
            write_http1_response(&mut stream, None).await?;
            let observed = vec![first, second];
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(observed)
        });

        let client = client(&identity)?;
        let url = format!("https://{address}/");
        send_client_and_drain(&client, HttpProtocol::Http1, &url).await?;
        send_client_and_drain(&client, HttpProtocol::Http1, &url).await?;
        let requests = server.await??;
        assert_http1_hints(&requests[0], false)?;
        assert_http1_hints(&requests[1], true)?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn cloned_clients_share_client_hints_while_new_clients_are_isolated() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            let mut shared = accept_tls(&listener, &acceptor).await?;
            let first = read_head(&mut shared).await?;
            write_http1_response(&mut shared, Some("Sec-CH-UA-Arch")).await?;
            let cloned = read_head(&mut shared).await?;
            write_http1_response(&mut shared, None).await?;
            let cleared = read_head(&mut shared).await?;
            write_http1_response(&mut shared, None).await?;

            let mut isolated = accept_tls(&listener, &acceptor).await?;
            let separate = read_head(&mut isolated).await?;
            write_http1_response(&mut isolated, None).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>([first, cloned, cleared, separate])
        });

        let shared = client(&identity)?;
        let clone = shared.clone();
        let url = format!("https://{address}/");
        send_and_drain(&shared, HttpProtocol::Http1, &url).await?;
        send_and_drain(&clone, HttpProtocol::Http1, &url).await?;
        shared.clear_client_hints();
        send_and_drain(&shared, HttpProtocol::Http1, &url).await?;
        send_and_drain(&client(&identity)?, HttpProtocol::Http1, &url).await?;

        let requests = server.await??;
        assert_http1_hints(&requests[0], false)?;
        assert!(std::str::from_utf8(&requests[1])?.contains("\r\nsec-ch-ua-arch: \"arm\"\r\n"));
        assert_http1_hints(&requests[2], false)?;
        assert_http1_hints(&requests[3], false)?;
        Ok(())
    })
    .await
}

fn client(identity: &TestIdentity) -> TestResult<Client> {
    let profile = ClientProfile::new(tls_settings())
        .with_http2(chromium::v152_macos_http2())
        .with_http3(client_settings())
        .with_client_hints(client_hint_settings());
    Ok(Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .build()?)
}

fn alps_client(identity: &TestIdentity) -> TestResult<Client> {
    let mut tls = tls_settings();
    tls.min_version = TlsVersion::Tls13;
    tls.max_version = TlsVersion::Tls13;
    tls.cipher_suites = vec![CipherSuite::Aes128GcmSha256];
    tls.key_shares = vec![NamedGroup::X25519];
    tls.alps = Some(AlpsSettings {
        protocol: Box::from(&b"h2"[..]),
        settings: Box::default(),
        use_new_codepoint: true,
    });
    let profile = ClientProfile::new(tls)
        .with_http2(chromium::v152_macos_http2())
        .with_client_hints(client_hint_settings());
    Ok(Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .build()?)
}

fn client_hint_settings() -> ClientHintSettings {
    ClientHintSettings::new(vec![
        ClientHint::new("sec-ch-ua", "baseline", ClientHintDelivery::Default),
        ClientHint::new("sec-ch-ua-arch", "\"arm\"", ClientHintDelivery::AcceptCh),
        ClientHint::new(
            "sec-ch-ua-platform-version",
            "\"15.5.0\"",
            ClientHintDelivery::AcceptCh,
        ),
    ])
}

async fn send_and_drain(client: &Client, protocol: HttpProtocol, url: &str) -> TestResult<()> {
    let response = client.get(protocol, url)?.send().await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    response.into_body().collect().await?;
    Ok(())
}

async fn send_client_and_drain(
    client: &Client,
    protocol: HttpProtocol,
    url: &str,
) -> TestResult<()> {
    let response = client.get(protocol, url)?.send().await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    response.into_body().collect().await?;
    Ok(())
}

async fn accept_tls(
    listener: &TcpListener,
    acceptor: &SslAcceptor,
) -> TestResult<SslStream<TcpStream>> {
    let (tcp, _) = listener.accept().await?;
    let ssl = Ssl::new(acceptor.context())?;
    let mut stream = SslStream::new(ssl, tcp)?;
    Pin::new(&mut stream).accept().await?;
    Ok(stream)
}

async fn accept_tls_with_alps(
    listener: &TcpListener,
    acceptor: &SslAcceptor,
    application_settings: &[u8],
) -> TestResult<SslStream<TcpStream>> {
    let (tcp, _) = listener.accept().await?;
    let mut ssl = Ssl::new(acceptor.context())?;
    ssl.add_application_settings_with_payload(b"h2", application_settings)?;
    ssl.set_alps_use_new_codepoint(true);
    let mut stream = SslStream::new(ssl, tcp)?;
    Pin::new(&mut stream).accept().await?;
    Ok(stream)
}

fn accept_ch_alps(origin: &str, value: &str) -> Vec<u8> {
    let Ok(origin_len) = u16::try_from(origin.len()) else {
        panic!("test origin exceeds the HTTP/2 ALPS field width");
    };
    let Ok(value_len) = u16::try_from(value.len()) else {
        panic!("test value exceeds the HTTP/2 ALPS field width");
    };
    let payload_len = 4 + origin.len() + value.len();
    let mut encoded = vec![0, 0, 0, 4, 0, 0, 0, 0, 0];
    encoded.extend([
        ((payload_len >> 16) & 0xff) as u8,
        ((payload_len >> 8) & 0xff) as u8,
        (payload_len & 0xff) as u8,
        0x89,
        0,
        0,
        0,
        0,
        0,
    ]);
    encoded.extend(origin_len.to_be_bytes());
    encoded.extend(origin.as_bytes());
    encoded.extend(value_len.to_be_bytes());
    encoded.extend(value.as_bytes());
    encoded
}

async fn write_http1_response(
    stream: &mut SslStream<TcpStream>,
    accept_ch: Option<&str>,
) -> TestResult<()> {
    stream
        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n")
        .await?;
    if let Some(value) = accept_ch {
        stream.write_all(b"Accept-CH: ").await?;
        stream.write_all(value.as_bytes()).await?;
        stream.write_all(b"\r\n").await?;
    }
    stream.write_all(b"\r\n").await?;
    Ok(())
}

async fn accept_http2(
    connection: &mut ::http2::server::Connection<SslStream<TcpStream>, bytes::Bytes>,
) -> TestResult<(
    Request<::http2::RecvStream>,
    ::http2::server::SendResponse<bytes::Bytes>,
)> {
    connection
        .accept()
        .await
        .ok_or_else(|| -> Box<dyn std::error::Error + Send + Sync> {
            "HTTP/2 connection closed before request".into()
        })?
        .map_err(Into::into)
}

async fn drive_http2_until_client_done(
    connection: &mut ::http2::server::Connection<SslStream<TcpStream>, bytes::Bytes>,
    wait_for_client: oneshot::Receiver<()>,
) -> TestResult<()> {
    tokio::select! {
        result = poll_fn(|context| connection.poll_closed(context)) => {
            result?;
            Err("HTTP/2 client closed before response completion".into())
        }
        result = wait_for_client => {
            result.map_err(|_| "client stopped before HTTP/2 response completion".into())
        }
    }
}

fn assert_hints(headers: &http::HeaderMap, high_entropy: bool) -> TestResult<()> {
    assert_eq!(headers.get("sec-ch-ua"), Some(&"baseline".parse()?));
    assert_eq!(headers.contains_key("sec-ch-ua-arch"), high_entropy);
    assert_eq!(
        headers.contains_key("sec-ch-ua-platform-version"),
        high_entropy
    );
    Ok(())
}

fn assert_http1_hints(head: &[u8], high_entropy: bool) -> TestResult<()> {
    let text = std::str::from_utf8(head)?;
    assert!(text.contains("\r\nsec-ch-ua: baseline\r\n"));
    assert_eq!(
        text.contains("\r\nsec-ch-ua-arch: \"arm\"\r\n"),
        high_entropy
    );
    assert_eq!(
        text.contains("\r\nsec-ch-ua-platform-version: \"15.5.0\"\r\n"),
        high_entropy
    );
    Ok(())
}

async fn bounded<F, T>(future: F) -> TestResult<T>
where
    F: std::future::Future<Output = TestResult<T>>,
{
    timeout(TEST_TIMEOUT, future).await.map_err(
        |_| -> Box<dyn std::error::Error + Send + Sync> { "client-hint test timed out".into() },
    )?
}

#[test]
fn caller_header_type_remains_public_for_overrides() {
    let header = RequestHeader::new("sec-ch-ua", "caller");
    assert_eq!(header.name(), "sec-ch-ua");
}
