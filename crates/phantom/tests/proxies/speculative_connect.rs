//! Public proxy setup must overlap TLS without bypassing acceptance or trust.

use std::{error::Error, net::Ipv4Addr, num::NonZeroUsize, pin::Pin, time::Duration};

use btls::ssl::{Ssl, SslAcceptor};
use bytes::Bytes;
use http_body_util::BodyExt;
use phantom::{
    Client, HttpProtocol, HttpProxy, RequestErrorKind, RetryPolicy, Route,
    profile::{
        ClientProfile,
        browser::{chrome, firefox},
    },
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpListener,
    time::timeout,
};
use tokio_btls::SslStream;

use crate::support::tls::{
    H1_ALPN, H2_ALPN, TestIdentity, TestResult, accept_tls_stream, read_head,
};

mod controls;

async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    acceptor: SslAcceptor,
    h2: bool,
    basic: bool,
    completed: tokio::sync::oneshot::Receiver<()>,
) -> TestResult<()> {
    let mut stream = BufReader::new(stream);
    let head = String::from_utf8(read_head(&mut stream).await?)?;
    assert!(head.starts_with("CONNECT 127.0.0.1:443 HTTP/1.1\r\n"));
    assert_eq!(
        head.matches("Basic dXNlcjpzZWNyZXQ=").count(),
        usize::from(basic)
    );
    // fill_buf leaves ClientHello available for the TLS acceptor. Acceptance
    // is withheld until it arrives, so a sequential CONNECT cannot pass.
    assert_eq!(stream.fill_buf().await?.first(), Some(&22));
    stream
        .write_all(b"HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    let ssl = Ssl::new(acceptor.context())?;
    let mut tls = SslStream::new(ssl, stream)?;
    Pin::new(&mut tls).accept().await?;
    if h2 {
        let mut connection = http2::server::handshake(tls).await?;
        let (request, mut response) = connection.accept().await.ok_or("missing H2 request")??;
        assert_eq!(request.uri().path(), "/speculative");
        response
            .send_response(
                http::Response::builder()
                    .status(200)
                    .header("content-length", "2")
                    .body(())?,
                false,
            )?
            .send_data(Bytes::from_static(b"ok"), true)?;
        // Drive response writes until the caller confirms payload delivery.
        // GOAWAY is a separate behavior and can retire this pooled connection.
        tokio::select! {
            received = completed => received?,
            next = connection.accept() => {
                if let Some(request) = next { request?; }
                return Err("H2 connection ended before payload acknowledgement".into());
            }
        }
    } else {
        assert!(
            read_head(&mut tls)
                .await?
                .starts_with(b"GET /speculative HTTP/1.1\r\n")
        );
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await?;
    }
    Ok(())
}

#[tokio::test]
async fn speculative_connect_carries_h1_h2_and_negotiated_tls_through_plain_and_tls_proxies()
-> TestResult<()> {
    timeout(Duration::from_secs(30), async {
        for secure in [false, true] {
            for mode in 0..3 {
                for basic in [false, true] {
                    eprintln!("speculative case secure={secure} mode={mode} basic={basic}");
                    let identity = TestIdentity::generate()?;
                    let outer = identity.acceptor(H1_ALPN)?;
                    let origin = identity.acceptor(if mode == 0 { H1_ALPN } else { H2_ALPN })?;
                    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
                    let scheme = if secure { "https" } else { "http" };
                    let proxy = HttpProxy::new(&format!("{scheme}://{}", listener.local_addr()?))?
                        .with_speculative_tls(true);
                    let proxy = if basic {
                        proxy.with_basic_auth("user", "secret")?
                    } else {
                        proxy
                    };
                    // Firefox exercises retained proxy openings; Chrome covers
                    // the ordinary connector path on exact H2 and negotiated.
                    let profile = if basic {
                        firefox::v157_windows()
                    } else {
                        chrome::v154_windows()
                    };
                    let client = Client::builder(profile)
                        .add_root_certificate_der(identity.root_der.clone())
                        .add_proxy_root_certificate_der(identity.root_der)
                        .route(Route::http_proxy(proxy))
                        .build()?;
                    let (complete, completed) = tokio::sync::oneshot::channel();
                    let request = async {
                        let request = match mode {
                            0 => client.get_with_protocol(
                                HttpProtocol::Http1,
                                "https://127.0.0.1/speculative",
                            )?,
                            1 => client.get_with_protocol(
                                HttpProtocol::Http2,
                                "https://127.0.0.1/speculative",
                            )?,
                            _ => client.get("https://127.0.0.1/speculative")?,
                        };
                        let response = request.send().await?;
                        assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
                        let _ = complete.send(());
                        TestResult::Ok(())
                    };
                    let peer = async move {
                        let (socket, _) = listener.accept().await?;
                        if secure {
                            serve(
                                accept_tls_stream(socket, outer).await?,
                                origin,
                                mode != 0,
                                basic,
                                completed,
                            )
                            .await
                        } else {
                            serve(socket, origin, mode != 0, basic, completed).await
                        }
                    };
                    tokio::try_join!(request, peer)?;
                }
            }
        }
        TestResult::Ok(())
    })
    .await?
}

#[tokio::test]
async fn speculative_rejection_keeps_the_proxy_error_and_does_not_redial() -> TestResult<()> {
    timeout(Duration::from_secs(10), async {
        for mode in 0..3 {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            let proxy = HttpProxy::new(&format!("http://{address}"))?.with_basic_auth("user", "secret")?.with_speculative_tls(true);
            let retry = RetryPolicy::connection_failures(NonZeroUsize::new(3).ok_or("zero attempts")?, Duration::ZERO).with_reused_connection_replay(true);
            let mut tls = chrome::v154_tcp_tls();
            tls.tcp_early_data = true;
            let profile = ClientProfile::new(tls).with_http2(chrome::v154_http2());
            let client = Client::builder(profile).retry_policy(retry).route(Route::http_proxy(proxy)).build()?;
            let request = async {
                let request = match mode {
                    0 => client.get_with_protocol(HttpProtocol::Http1, "https://127.0.0.1/speculative")?,
                    1 => client.get_with_protocol(HttpProtocol::Http2, "https://127.0.0.1/speculative")?,
                    _ => client.get("https://127.0.0.1/speculative")?,
                };
                let error = request.send().await.err().ok_or("rejected CONNECT succeeded")?;
                assert_eq!(error.kind(), RequestErrorKind::Proxy);
                let mut source = error.source();
                let mut status = None;
                while let Some(error) = source {
                    if let Some(phantom_net::proxy::HttpConnectError::Rejected { status: value }) = error.downcast_ref() { status = Some(*value); }
                    source = error.source();
                }
                assert_eq!(status, Some(407));
                TestResult::Ok(())
            };
            let peer = async {
                let (socket, _) = listener.accept().await?;
                let mut stream = BufReader::new(socket);
                read_head(&mut stream).await?;
                assert_eq!(stream.fill_buf().await?.first(), Some(&22));
                stream.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\n\r\n").await?;
                let mut sent = Vec::new();
                tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut sent).await?;
                assert!(!sent.windows(8).any(|bytes| bytes == b"CONNECT "));
                TestResult::Ok(())
            };
            tokio::try_join!(request, peer)?;
            assert!(timeout(Duration::from_millis(20), listener.accept()).await.is_err());
        }
        TestResult::Ok(())
    }).await?
}
