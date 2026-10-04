//! The opt-in wait for `100 Continue` before a request body is sent.

use crate::support::h2 as h2_support;
use crate::support::tls as tls_support;

use std::{
    error::Error,
    future::Future,
    net::Ipv4Addr,
    num::NonZeroUsize,
    time::{Duration, Instant},
};

use btls::ssl::SslAcceptor;
use http::{Method, StatusCode};
use http_body_util::BodyExt;
use phantom::{Client, HttpProtocol, RedirectPolicy, RequestErrorKind, profile::ClientProfile};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

use h2_support::{accept_client_preface, read_frame, write_frame};
use tls_support::{
    H2_ALPN, TestIdentity, accept_tls_stream, client_builder, read_head, tls_settings,
};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Long enough that a body that did not wait would arrive within it.
const NO_BODY_WINDOW: Duration = Duration::from_millis(300);
const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

fn plain_client() -> TestResult<Client> {
    Ok(Client::builder(ClientProfile::new(tls_settings())).build()?)
}

async fn bounded<F>(future: F) -> TestResult
where
    F: Future<Output = TestResult>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "expect-continue test exceeded its deadline")?
}

fn lowercase(head: &[u8]) -> String {
    String::from_utf8_lossy(head).to_ascii_lowercase()
}

/// Requires that nothing arrives on `stream` for [`NO_BODY_WINDOW`].
async fn assert_nothing_arrives(stream: &mut (impl AsyncReadExt + Unpin)) -> TestResult {
    let mut byte = [0_u8; 1];
    match timeout(NO_BODY_WINDOW, stream.read(&mut byte)).await {
        Err(_) => Ok(()),
        Ok(read) => Err(format!("the body did not wait: read {read:?}").into()),
    }
}

/// Reads what arrives until the client closes the connection. A close can
/// surface as a reset or an abort as well as an end of stream.
async fn read_until_closed(stream: &mut TcpStream) -> TestResult<Vec<u8>> {
    let mut rest = Vec::new();
    match timeout(Duration::from_secs(5), stream.read_to_end(&mut rest)).await? {
        Ok(_) => Ok(rest),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
            ) =>
        {
            Ok(rest)
        }
        Err(error) => Err(error.into()),
    }
}

#[tokio::test]
async fn an_http1_body_waits_for_100_continue() -> TestResult {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let head = lowercase(&read_head(&mut stream).await?);
            assert_nothing_arrives(&mut stream).await?;
            stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
            let mut body = [0_u8; 7];
            stream.read_exact(&mut body).await?;
            stream.write_all(OK).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((head, body))
        });

        let response = plain_client()?
            .request(
                HttpProtocol::Http1,
                Method::PUT,
                &format!("http://{address}/upload"),
            )?
            .body("payload")
            .expect_continue(Duration::from_secs(10))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");

        let (head, body) = server.await??;
        // The generated field follows the generated framing.
        assert!(
            head.ends_with("\r\ncontent-length: 7\r\nexpect: 100-continue\r\n\r\n"),
            "{head}"
        );
        assert_eq!(&body, b"payload");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn an_http1_body_is_sent_when_the_wait_ends() -> TestResult {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            read_head(&mut stream).await?;
            let head_read = Instant::now();
            let mut body = [0_u8; 7];
            stream.read_exact(&mut body).await?;
            let waited = head_read.elapsed();
            stream.write_all(OK).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((body, waited))
        });

        let response = plain_client()?
            .request(
                HttpProtocol::Http1,
                Method::PUT,
                &format!("http://{address}/upload"),
            )?
            .body("payload")
            .expect_continue(Duration::from_millis(500))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        response.into_body().collect().await?;

        let (body, waited) = server.await??;
        assert_eq!(&body, b"payload");
        assert!(
            waited >= Duration::from_millis(400) && waited < Duration::from_secs(5),
            "body after {waited:?}"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn an_http1_final_response_first_withholds_the_body_and_closes_the_connection() -> TestResult
{
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await?;
            read_head(&mut first).await?;
            first
                .write_all(b"HTTP/1.1 417 Expectation Failed\r\nContent-Length: 0\r\n\r\n")
                .await?;
            let rest = read_until_closed(&mut first).await?;
            // The next request needs a new connection.
            let (mut second, _) = listener.accept().await?;
            let retry = lowercase(&read_head(&mut second).await?);
            let mut body = [0_u8; 7];
            second.read_exact(&mut body).await?;
            second.write_all(OK).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((rest, retry, body))
        });

        let client = plain_client()?;
        let url = format!("http://{address}/upload");
        let rejected = client
            .request(HttpProtocol::Http1, Method::PUT, &url)?
            .body("payload")
            .expect_continue(Duration::from_secs(10))
            .send()
            .await?;
        assert_eq!(rejected.status(), StatusCode::EXPECTATION_FAILED);
        rejected.into_body().collect().await?;
        let accepted = client
            .request(HttpProtocol::Http1, Method::PUT, &url)?
            .body("payload")
            .send()
            .await?;
        assert_eq!(accepted.status(), StatusCode::OK);
        accepted.into_body().collect().await?;

        let (rest, retry, body) = server.await??;
        assert!(rest.is_empty(), "the withheld body was sent: {rest:?}");
        assert!(!retry.contains("\r\nexpect:"), "{retry}");
        assert_eq!(&body, b"payload");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_redirect_that_keeps_the_body_waits_again() -> TestResult {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await?;
            let first_head = lowercase(&read_head(&mut first).await?);
            first
                .write_all(b"HTTP/1.1 307 Temporary Redirect\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n")
                .await?;
            let rest = read_until_closed(&mut first).await?;
            let (mut second, _) = listener.accept().await?;
            let second_head = lowercase(&read_head(&mut second).await?);
            assert_nothing_arrives(&mut second).await?;
            second.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
            let mut body = [0_u8; 7];
            second.read_exact(&mut body).await?;
            second.write_all(OK).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((first_head, rest, second_head, body))
        });

        let client = Client::builder(ClientProfile::new(tls_settings()))
            .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
            .build()?;
        let response = client
            .request(
                HttpProtocol::Http1,
                Method::PUT,
                &format!("http://{address}/upload"),
            )?
            .body("payload")
            .expect_continue(Duration::from_secs(10))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        response.into_body().collect().await?;

        let (first_head, rest, second_head, body) = server.await??;
        assert!(first_head.contains("\r\nexpect: 100-continue\r\n"), "{first_head}");
        assert!(rest.is_empty(), "the withheld body was sent: {rest:?}");
        assert!(second_head.starts_with("put /next "), "{second_head}");
        assert!(second_head.contains("\r\nexpect: 100-continue\r\n"), "{second_head}");
        assert_eq!(&body, b"payload");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_request_without_a_body_sends_no_expectation() -> TestResult {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let head = lowercase(&read_head(&mut stream).await?);
            stream.write_all(OK).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(head)
        });

        let response = plain_client()?
            .get(HttpProtocol::Http1, &format!("http://{address}/"))?
            .expect_continue(Duration::from_secs(10))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        response.into_body().collect().await?;
        let head = server.await??;
        assert!(!head.contains("\r\nexpect:"), "{head}");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_caller_expect_field_keeps_its_position_and_must_be_100_continue() -> TestResult {
    bounded(async {
        let client = plain_client()?;
        let error = client
            .request(
                HttpProtocol::Http1,
                Method::PUT,
                "http://127.0.0.1:9/upload",
            )?
            .header(phantom::RequestHeader::new("Expect", "something-else"))
            .body("payload")
            .expect_continue(Duration::from_secs(1))
            .send()
            .await
            .err()
            .ok_or("a request with a conflicting Expect field was sent")?;
        assert_eq!(error.kind(), RequestErrorKind::InvalidHeader);

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let head = String::from_utf8_lossy(&read_head(&mut stream).await?).into_owned();
            stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
            let mut body = [0_u8; 7];
            stream.read_exact(&mut body).await?;
            stream.write_all(OK).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(head)
        });
        let response = client
            .request(
                HttpProtocol::Http1,
                Method::PUT,
                &format!("http://{address}/upload"),
            )?
            .header(phantom::RequestHeader::new("EXPECT", "100-Continue"))
            .header(phantom::RequestHeader::new("X-After", "1"))
            .body("payload")
            .expect_continue(Duration::from_secs(10))
            .send()
            .await?;
        response.into_body().collect().await?;
        let head = server.await??;
        assert!(
            head.contains("\r\nEXPECT: 100-Continue\r\nX-After: 1\r\n"),
            "{head}"
        );
        assert_eq!(head.to_ascii_lowercase().matches("expect:").count(), 1);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn an_unrepresentable_wait_fails_before_any_connection() -> TestResult {
    let error = plain_client()?
        .request(
            HttpProtocol::Http1,
            Method::PUT,
            "http://127.0.0.1:9/upload",
        )?
        .body("payload")
        .expect_continue(Duration::MAX)
        .send()
        .await
        .err()
        .ok_or("a request with an unrepresentable wait was sent")?;
    assert_eq!(error.kind(), RequestErrorKind::InvalidTimeout);
    Ok(())
}

/// The literal HPACK encoding of `:status: 100`, static name index 8.
const STATUS_100: &[u8] = &[0x08, 0x03, b'1', b'0', b'0'];
/// The indexed HPACK encoding of `:status: 200`.
const STATUS_200: &[u8] = &[0x88];
const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const RST_STREAM: u8 = 0x3;
const END_STREAM: u8 = 0x1;
const END_HEADERS: u8 = 0x4;

/// Reads frames until one of `kind` on stream 1, failing on DATA when it is
/// not the kind sought.
async fn read_until(
    stream: &mut (impl AsyncReadExt + AsyncWriteExt + Unpin),
    kind: u8,
) -> TestResult<h2_support::Frame> {
    loop {
        let frame = read_frame(stream).await?;
        if frame.stream_id == 1 && frame.kind == kind {
            return Ok(frame);
        }
        if frame.stream_id == 1 && frame.kind == DATA {
            return Err("the client sent DATA before it should".into());
        }
    }
}

async fn http2_server(
    listener: TcpListener,
    acceptor: SslAcceptor,
) -> TestResult<tokio_btls::SslStream<TcpStream>> {
    let (tcp, _) = listener.accept().await?;
    let mut stream = accept_tls_stream(tcp, acceptor).await?;
    accept_client_preface(&mut stream).await?;
    Ok(stream)
}

/// Requires that the body waits for `100 Continue`, then answers `200`, and
/// returns the body.
async fn serve_100_then_ok(listener: TcpListener, acceptor: SslAcceptor) -> TestResult<Vec<u8>> {
    let mut stream = http2_server(listener, acceptor).await?;
    read_until(&mut stream, HEADERS).await?;
    match timeout(NO_BODY_WINDOW, read_until(&mut stream, DATA)).await {
        Err(_) => {}
        Ok(_) => return Err("the body did not wait".into()),
    }
    write_frame(&mut stream, HEADERS, END_HEADERS, 1, STATUS_100).await?;
    let mut body = Vec::new();
    loop {
        let frame = read_until(&mut stream, DATA).await?;
        body.extend_from_slice(&frame.payload);
        if frame.flags & END_STREAM != 0 {
            break;
        }
    }
    write_frame(
        &mut stream,
        HEADERS,
        END_STREAM | END_HEADERS,
        1,
        STATUS_200,
    )
    .await?;
    stream.flush().await?;
    Ok(body)
}

#[tokio::test]
async fn an_http2_body_waits_for_100_continue() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(serve_100_then_ok(listener, identity.acceptor(H2_ALPN)?));

        let response = client_builder(&identity, true)
            .build()?
            .request(
                HttpProtocol::Http2,
                Method::PUT,
                &format!("https://{address}/upload"),
            )?
            .body("payload")
            .expect_continue(Duration::from_secs(10))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        response.into_body().collect().await?;
        assert_eq!(server.await??, b"payload");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_negotiated_body_waits_for_100_continue() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(serve_100_then_ok(listener, identity.acceptor(H2_ALPN)?));

        let response = client_builder(&identity, true)
            .build()?
            .request_negotiated(Method::PUT, &format!("https://{address}/upload"))?
            .body("payload")
            .expect_continue(Duration::from_secs(10))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        response.into_body().collect().await?;
        assert_eq!(server.await??, b"payload");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn an_http2_final_response_first_cancels_the_stream_without_data() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let server = tokio::spawn(async move {
            let mut stream = http2_server(listener, acceptor).await?;
            read_until(&mut stream, HEADERS).await?;
            // `:status: 417`, a literal with static name index 8.
            write_frame(
                &mut stream,
                HEADERS,
                END_STREAM | END_HEADERS,
                1,
                &[0x08, 0x03, b'4', b'1', b'7'],
            )
            .await?;
            stream.flush().await?;
            let reset = read_until(&mut stream, RST_STREAM).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(reset.payload)
        });

        let response = client_builder(&identity, true)
            .build()?
            .request(
                HttpProtocol::Http2,
                Method::PUT,
                &format!("https://{address}/upload"),
            )?
            .body("payload")
            .expect_continue(Duration::from_secs(10))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::EXPECTATION_FAILED);
        response.into_body().collect().await?;
        // RST_STREAM(CANCEL), and no DATA before it.
        assert_eq!(server.await??, 0x8_u32.to_be_bytes());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn an_http2_final_response_with_a_body_cancels_the_upload_when_it_ends() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let server = tokio::spawn(async move {
            let mut stream = http2_server(listener, acceptor).await?;
            read_until(&mut stream, HEADERS).await?;
            // `:status: 417`, a literal with static name index 8.
            write_frame(
                &mut stream,
                HEADERS,
                END_HEADERS,
                1,
                &[0x08, 0x03, b'4', b'1', b'7'],
            )
            .await?;
            write_frame(&mut stream, DATA, END_STREAM, 1, b"no").await?;
            stream.flush().await?;
            let reset = read_until(&mut stream, RST_STREAM).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(reset.payload)
        });

        let response = client_builder(&identity, true)
            .build()?
            .request(
                HttpProtocol::Http2,
                Method::PUT,
                &format!("https://{address}/upload"),
            )?
            .body("payload")
            .expect_continue(Duration::from_secs(10))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::EXPECTATION_FAILED);
        assert_eq!(response.into_body().collect().await?.to_bytes(), "no");
        // RST_STREAM(CANCEL), and no DATA before it.
        assert_eq!(server.await??, 0x8_u32.to_be_bytes());
        Ok(())
    })
    .await
}
