//! Public opt-in response content decoding behavior.

use crate::support::h3 as h3_support;
use crate::support::tls as tls_support;

use std::{
    error::Error, future::Future, io::Write, net::Ipv4Addr, num::NonZeroUsize, time::Duration,
};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Response, StatusCode, header};
use http_body_util::BodyExt;
use phantom::{
    Client, ContentCoding, ContentDecoding, HttpProtocol, RedirectPolicy, RequestErrorKind,
    RequestHeader, RequestTimeouts, ResponseBody, ResponseInfo, profile::ClientProfile,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::{sleep, timeout},
};

use tls_support::{
    H1_ALPN, H2_ALPN, TestIdentity, TestResult, accept_tls, accept_tls_stream, read_head,
    tls_settings,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const NO_CONNECTION_WINDOW: Duration = Duration::from_millis(100);
const DECODED_LIMIT: u64 = 1 << 20;
const PAYLOAD: &[u8] = b"decoded response payload, repeated to compress. ";

fn payload() -> Vec<u8> {
    PAYLOAD.repeat(64)
}

fn gzip(data: &[u8]) -> TestResult<Vec<u8>> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

fn brotli(data: &[u8]) -> TestResult<Vec<u8>> {
    let mut output = Vec::new();
    brotli::BrotliCompress(
        &mut std::io::Cursor::new(data),
        &mut output,
        &brotli::enc::BrotliEncoderParams::default(),
    )?;
    Ok(output)
}

fn zstd(data: &[u8]) -> TestResult<Vec<u8>> {
    Ok(zstd::encode_all(data, 3)?)
}

fn http1_response(content_encoding: &str, body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Encoding: {content_encoding}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

fn plaintext_client() -> TestResult<Client> {
    Ok(Client::builder(ClientProfile::new(tls_settings())).build()?)
}

/// Serves `responses` in order on one accepted connection and returns each request head.
async fn serve_http1<S>(mut stream: S, responses: Vec<Vec<u8>>) -> TestResult<Vec<Vec<u8>>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut heads = Vec::new();
    for response in responses {
        heads.push(read_head(&mut stream).await?);
        stream.write_all(&response).await?;
        stream.flush().await?;
    }
    Ok(heads)
}

async fn accept_plaintext(listener: &TcpListener) -> TestResult<TcpStream> {
    Ok(listener.accept().await?.0)
}

fn response_info(response: &Response<ResponseBody>) -> TestResult<&ResponseInfo> {
    response
        .extensions()
        .get::<ResponseInfo>()
        .ok_or_else(|| "response omitted facade metadata".into())
}

async fn body_error_kind(response: Response<ResponseBody>) -> TestResult<RequestErrorKind> {
    match response.into_body().collect_with_limit(usize::MAX).await {
        Ok(_) => Err("coded body unexpectedly decoded".into()),
        Err(error) => Ok(error.kind()),
    }
}

async fn plaintext_exchange(
    response: Vec<u8>,
    accept_encoding: &str,
    policy: ContentDecoding,
) -> TestResult<(Vec<u8>, Response<ResponseBody>)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let stream = accept_plaintext(&listener).await?;
        let mut heads = serve_http1(stream, vec![response]).await?;
        heads
            .pop()
            .ok_or_else(|| Box::<dyn Error + Send + Sync>::from("server observed no request"))
    });
    let response = plaintext_client()?
        .get(HttpProtocol::Http1, &format!("http://{address}/coded"))?
        .header(RequestHeader::new("Accept-Encoding", accept_encoding))
        .content_decoding(policy)
        .send()
        .await?;
    let head = server.await??;
    Ok((head, response))
}

#[tokio::test]
async fn decoding_is_disabled_by_default_and_returns_wire_bytes() -> TestResult<()> {
    bounded(async {
        let encoded = gzip(&payload())?;
        let (_, response) = plaintext_exchange(
            http1_response("gzip", &encoded),
            "gzip",
            ContentDecoding::none(),
        )
        .await?;
        assert!(
            response_info(&response)?
                .decoded_content_codings()
                .is_empty()
        );
        let body = response.into_body().collect_with_limit(usize::MAX).await?;
        assert_eq!(body, encoded);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn enabling_decoding_leaves_request_head_bytes_unchanged() -> TestResult<()> {
    bounded(async {
        let encoded = gzip(&payload())?;
        let (plain_head, _) = plaintext_exchange(
            http1_response("gzip", &encoded),
            "gzip, br",
            ContentDecoding::none(),
        )
        .await?;
        let (decoding_head, _) = plaintext_exchange(
            http1_response("gzip", &encoded),
            "gzip, br",
            ContentDecoding::advertised(DECODED_LIMIT),
        )
        .await?;
        let normalize = |head: Vec<u8>| -> TestResult<String> {
            let head = String::from_utf8(head)?;
            Ok(head
                .lines()
                .filter(|line| !line.to_ascii_lowercase().starts_with("host:"))
                .collect::<Vec<_>>()
                .join("\n"))
        };
        assert_eq!(normalize(plain_head)?, normalize(decoding_head)?);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn http1_gzip_response_is_decoded_when_advertised() -> TestResult<()> {
    bounded(async {
        let data = payload();
        let encoded = gzip(&data)?;
        let (head, response) = plaintext_exchange(
            http1_response("gzip", &encoded),
            "gzip",
            ContentDecoding::advertised(DECODED_LIMIT),
        )
        .await?;
        assert!(String::from_utf8(head)?.contains("Accept-Encoding: gzip\r\n"));
        assert_eq!(
            response_info(&response)?.decoded_content_codings(),
            [ContentCoding::Gzip]
        );
        assert_eq!(response.headers()[header::CONTENT_ENCODING], "gzip");
        assert_eq!(
            response.headers()[header::CONTENT_LENGTH],
            encoded.len().to_string().as_str()
        );
        let body = response.into_body().collect_with_limit(usize::MAX).await?;
        assert_eq!(body, data);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn http2_brotli_response_is_decoded_when_advertised() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let data = payload();
        let encoded = brotli(&data)?;
        let server = tokio::spawn(async move {
            let stream = accept_tls(listener, acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            let (_request, mut respond) = connection
                .accept()
                .await
                .ok_or("connection closed before request")??;
            let response = Response::builder()
                .status(StatusCode::OK)
                .header("content-encoding", "br")
                .body(())?;
            let mut send = respond.send_response(response, false)?;
            let (first, second) = encoded.split_at(encoded.len() / 2);
            send.send_data(Bytes::copy_from_slice(first), false)?;
            send.send_data(Bytes::copy_from_slice(second), true)?;
            std::future::poll_fn(|context| connection.poll_closed(context)).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });

        let client = tls_support::test_client(&identity, true)?;
        let response = client
            .get(HttpProtocol::Http2, &format!("https://{address}/coded"))?
            .header(RequestHeader::new("accept-encoding", "br"))
            .content_decoding(ContentDecoding::advertised(DECODED_LIMIT))
            .send()
            .await?;
        assert_eq!(
            response_info(&response)?.decoded_content_codings(),
            [ContentCoding::Brotli]
        );
        let body = response.into_body().collect_with_limit(usize::MAX).await?;
        assert_eq!(body, data);
        drop(client);
        server.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn http3_zstd_response_is_decoded_when_advertised() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let (address, endpoint) = h3_support::server_endpoint(&identity)?;
        let data = payload();
        let encoded = zstd(&data)?;
        let (done, done_received) = oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            let (_request, mut stream, _connection) = h3_support::accept_request(&endpoint).await?;
            stream
                .send_response(
                    Response::builder()
                        .status(StatusCode::OK)
                        .header("content-encoding", "zstd")
                        .body(())?,
                )
                .await?;
            stream.send_data(Bytes::from(encoded)).await?;
            stream.finish().await?;
            done_received.await.map_err(std::io::Error::other)?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });

        let mut tcp_tls = tls_settings();
        tcp_tls.alpn_protocols = vec![Box::from(&b"http/1.1"[..])];
        let profile = ClientProfile::new(tcp_tls).with_http3(h3_support::client_settings());
        let client = Client::builder(profile)
            .add_root_certificate_der(identity.root_der.clone())
            .build()?;
        let response = client
            .get(HttpProtocol::Http3, &format!("https://{address}/coded"))?
            .header(RequestHeader::new("accept-encoding", "zstd"))
            .content_decoding(ContentDecoding::advertised(DECODED_LIMIT))
            .send()
            .await?;
        assert_eq!(
            response_info(&response)?.decoded_content_codings(),
            [ContentCoding::Zstd]
        );
        let body = response.into_body().collect_with_limit(usize::MAX).await?;
        assert_eq!(body, data);
        let _ = done.send(());
        server.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn collect_with_limit_counts_decoded_bytes() -> TestResult<()> {
    bounded(async {
        let data = payload();
        let encoded = gzip(&data)?;
        assert!(encoded.len() < data.len());
        let (_, response) = plaintext_exchange(
            http1_response("gzip", &encoded),
            "gzip",
            ContentDecoding::advertised(DECODED_LIMIT),
        )
        .await?;
        let Err(error) = response
            .into_body()
            .collect_with_limit(data.len() - 1)
            .await
        else {
            return Err("decoded body beyond the collection limit was accepted".into());
        };
        assert_eq!(error.kind(), RequestErrorKind::ResponseBodyLimit);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn decoded_limit_reports_response_body_limit_kind() -> TestResult<()> {
    bounded(async {
        let data = payload();
        let (_, response) = plaintext_exchange(
            http1_response("gzip", &gzip(&data)?),
            "gzip",
            ContentDecoding::advertised(u64::try_from(data.len())? - 1),
        )
        .await?;
        assert_eq!(
            body_error_kind(response).await?,
            RequestErrorKind::ResponseBodyLimit
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn unadvertised_coding_fails_on_first_body_poll_with_head_visible() -> TestResult<()> {
    bounded(async {
        let (_, response) = plaintext_exchange(
            http1_response("br", &brotli(&payload())?),
            "gzip",
            ContentDecoding::advertised(DECODED_LIMIT),
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_ENCODING], "br");
        assert!(
            response_info(&response)?
                .decoded_content_codings()
                .is_empty()
        );
        assert_eq!(
            body_error_kind(response).await?,
            RequestErrorKind::ContentDecoding
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn unknown_coding_fails_closed() -> TestResult<()> {
    bounded(async {
        for coding in ["compress", "identity, gzip", "gzip, gzip, gzip, gzip"] {
            let (_, response) = plaintext_exchange(
                http1_response(coding, b"opaque"),
                "*",
                ContentDecoding::advertised(DECODED_LIMIT),
            )
            .await?;
            assert_eq!(
                body_error_kind(response).await?,
                RequestErrorKind::ContentDecoding,
                "{coding}"
            );
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn invalid_accept_encoding_fails_before_network_io_only_when_decoding_enabled()
-> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let client = plaintext_client()?;
        let Err(error) = client
            .get(HttpProtocol::Http1, &format!("http://{address}/coded"))?
            .header(RequestHeader::new("accept-encoding", "gzip;q=2"))
            .content_decoding(ContentDecoding::advertised(DECODED_LIMIT))
            .send()
            .await
        else {
            return Err("malformed Accept-Encoding was sent".into());
        };
        assert_eq!(error.kind(), RequestErrorKind::InvalidHeader);
        assert!(
            timeout(NO_CONNECTION_WINDOW, listener.accept())
                .await
                .is_err(),
            "invalid request opened a connection"
        );

        let server = tokio::spawn(async move {
            let stream = accept_plaintext(&listener).await?;
            serve_http1(stream, vec![http1_response("identity", b"plain")]).await
        });
        let response = client
            .get(HttpProtocol::Http1, &format!("http://{address}/coded"))?
            .header(RequestHeader::new("accept-encoding", "gzip;q=2"))
            .send()
            .await?;
        assert_eq!(
            response.into_body().collect_with_limit(usize::MAX).await?,
            &b"plain"[..]
        );
        server.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn head_204_and_304_with_content_encoding_complete_empty() -> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let stream = accept_plaintext(&listener).await?;
            serve_http1(
                stream,
                vec![
                    b"HTTP/1.1 200 OK\r\nContent-Encoding: compress\r\nContent-Length: 10\r\n\r\n"
                        .to_vec(),
                    b"HTTP/1.1 204 No Content\r\nContent-Encoding: compress\r\n\r\n".to_vec(),
                    b"HTTP/1.1 304 Not Modified\r\nContent-Encoding: compress\r\n\r\n".to_vec(),
                ],
            )
            .await
        });
        let client = plaintext_client()?;
        for method in [Method::HEAD, Method::GET, Method::GET] {
            let response = client
                .request(HttpProtocol::Http1, method, &format!("http://{address}/"))?
                .header(RequestHeader::new("accept-encoding", "gzip"))
                .content_decoding(ContentDecoding::advertised(DECODED_LIMIT))
                .send()
                .await?;
            assert!(
                response_info(&response)?
                    .decoded_content_codings()
                    .is_empty()
            );
            assert!(response.into_body().collect_with_limit(0).await?.is_empty());
        }
        server.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn malformed_gzip_body_fails_and_next_http1_request_uses_new_connection() -> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let mut malformed = gzip(&payload())?;
        malformed.extend_from_slice(b"garbage");
        let (release, released) = oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            let mut first = accept_plaintext(&listener).await?;
            read_head(&mut first).await?;
            // Bytes after the gzip member fail decoding while the declared
            // length keeps the wire body incomplete.
            first
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
                        malformed.len() + 1024
                    )
                    .as_bytes(),
                )
                .await?;
            first.write_all(&malformed).await?;
            first.flush().await?;
            released.await.map_err(std::io::Error::other)?;
            let second = accept_plaintext(&listener).await?;
            serve_http1(second, vec![http1_response("identity", b"fresh")]).await?;
            drop(first);
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });

        let client = plaintext_client()?;
        let response = client
            .get(HttpProtocol::Http1, &format!("http://{address}/first"))?
            .header(RequestHeader::new("accept-encoding", "gzip"))
            .content_decoding(ContentDecoding::advertised(DECODED_LIMIT))
            .send()
            .await?;
        assert_eq!(
            body_error_kind(response).await?,
            RequestErrorKind::ContentDecoding
        );
        let _ = release.send(());

        let response = client
            .get(HttpProtocol::Http1, &format!("http://{address}/second"))?
            .send()
            .await?;
        assert_eq!(
            response.into_body().collect_with_limit(usize::MAX).await?,
            &b"fresh"[..]
        );
        server.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn trailers_follow_all_decoded_data() -> TestResult<()> {
    bounded(async {
        let data = payload();
        let encoded = gzip(&data)?;
        let mut response = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\nTrailer: x-checksum\r\n\r\n".to_vec();
        for chunk in encoded.chunks(9) {
            response.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            response.extend_from_slice(chunk);
            response.extend_from_slice(b"\r\n");
        }
        response.extend_from_slice(b"0\r\nx-checksum: done\r\n\r\n");
        let (_, response) = plaintext_exchange(
            response,
            "gzip",
            ContentDecoding::advertised(DECODED_LIMIT),
        )
        .await?;

        let mut body = response.into_body();
        let mut decoded = Vec::new();
        let mut trailers = None::<HeaderMap>;
        while let Some(frame) = body.frame().await {
            let frame = frame?;
            if trailers.is_some() {
                return Err("frame followed the trailers".into());
            }
            match frame.into_data() {
                Ok(data) => decoded.extend_from_slice(&data),
                Err(frame) => trailers = frame.into_trailers().ok(),
            }
        }
        assert_eq!(decoded, data);
        let trailers = trailers.ok_or("decoded body dropped its trailers")?;
        assert_eq!(trailers.get("x-checksum"), Some(&HeaderValue::from_static("done")));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn redirect_hop_bodies_are_not_decoded_and_final_response_is() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let data = payload();
        let encoded = gzip(&data)?;
        let server = tokio::spawn(async move {
            let (first, _) = listener.accept().await?;
            let first = accept_tls_stream(first, acceptor.clone()).await?;
            let mut redirect = b"HTTP/1.1 302 Found\r\nLocation: /final\r\nConnection: close\r\nContent-Encoding: compress\r\nContent-Length: 6\r\n\r\n".to_vec();
            redirect.extend_from_slice(b"opaque");
            let mut heads = serve_http1(first, vec![redirect]).await?;
            let (second, _) = listener.accept().await?;
            let second = accept_tls_stream(second, acceptor).await?;
            heads.extend(serve_http1(second, vec![http1_response("gzip", &encoded)]).await?);
            Ok::<_, Box<dyn Error + Send + Sync>>(heads)
        });

        let client = tls_support::client_builder(&identity, false)
            .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
            .build()?;
        let response = client
            .get(HttpProtocol::Http1, &format!("https://{address}/start"))?
            .header(RequestHeader::new("accept-encoding", "gzip"))
            .content_decoding(ContentDecoding::advertised(DECODED_LIMIT))
            .send()
            .await?;
        let info = response_info(&response)?;
        assert_eq!(info.redirects_followed(), 1);
        assert_eq!(info.decoded_content_codings(), [ContentCoding::Gzip]);
        assert_eq!(
            response.into_body().collect_with_limit(usize::MAX).await?,
            data
        );
        let heads = server.await??;
        assert!(heads[1].starts_with(b"GET /final HTTP/1.1\r\n"));
        Ok(())
    })
    .await
}

#[tokio::test]
async fn total_timeout_interrupts_decoding_of_buffered_input() -> TestResult<()> {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let encoded = zstd(&vec![0_u8; 8 << 20])?;
        let server = tokio::spawn(async move {
            let stream = accept_plaintext(&listener).await?;
            serve_http1(stream, vec![http1_response("zstd", &encoded)]).await
        });
        let response = plaintext_client()?
            .get(HttpProtocol::Http1, &format!("http://{address}/coded"))?
            .header(RequestHeader::new("accept-encoding", "zstd"))
            .content_decoding(ContentDecoding::advertised(u64::MAX))
            .timeouts(RequestTimeouts::new().total(Duration::from_millis(500)))
            .send()
            .await?;
        let mut body = response.into_body();
        let first = body.frame().await.ok_or("coded body ended early")??;
        assert!(first.is_data());
        server.await??;
        sleep(Duration::from_millis(600)).await;
        let error = loop {
            match body.frame().await {
                Some(Ok(_)) => {}
                Some(Err(error)) => break error,
                None => return Err("decoding outran the total deadline".into()),
            }
        };
        assert_eq!(error.kind(), RequestErrorKind::Timeout);
        Ok(())
    })
    .await
}

#[cfg(feature = "sse")]
#[tokio::test]
async fn sse_stream_still_rejects_compressed_response_with_decoding_enabled() -> TestResult<()> {
    bounded(async {
        let encoded = gzip(b"data: event\n\n")?;
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
            encoded.len()
        )
        .into_bytes();
        response.extend_from_slice(&encoded);
        let (_, response) = plaintext_exchange(
            response,
            "gzip",
            ContentDecoding::advertised(DECODED_LIMIT),
        )
        .await?;
        let Err(error) = phantom::SseStream::from_response(response) else {
            return Err("SSE accepted a compressed response".into());
        };
        assert_eq!(error.kind(), phantom::SseErrorKind::UnsupportedContentEncoding);
        Ok(())
    })
    .await
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "content coding test exceeded its deadline")?
}
