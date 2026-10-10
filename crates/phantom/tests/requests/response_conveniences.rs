//! Bounded response reads and recoverable HTTP status errors.

use std::{
    error::Error,
    future::{Future, poll_fn},
    io::Write,
    net::Ipv4Addr,
    task::Poll,
    time::Duration,
};

use http::{HeaderMap, Response, StatusCode, Version};
use phantom::{
    Client, ContentDecoding, HttpProtocol, RequestError, RequestErrorKind, RequestHeader,
    ResponseBody, ResponseInfo, ResponseReadErrorKind, error_for_status, profile::ClientProfile,
    response_bytes, response_text,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};

use crate::support::tls::{TestResult, read_head, tls_settings};

mod peer_contract;

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const PRIVATE: &str = "https://example.test/private?token=sensitive";

#[derive(Clone, Debug, Eq, PartialEq)]
struct Marker(&'static str);

struct Metadata {
    status: StatusCode,
    version: Version,
    headers: HeaderMap,
    info: ResponseInfo,
}

impl Metadata {
    fn record(response: &mut Response<ResponseBody>) -> TestResult<Self> {
        response.extensions_mut().insert(Marker(PRIVATE));
        Ok(Self {
            status: response.status(),
            version: response.version(),
            headers: response.headers().clone(),
            info: response
                .extensions()
                .get::<ResponseInfo>()
                .ok_or("missing response info")?
                .clone(),
        })
    }

    fn check<B>(&self, response: &Response<B>) {
        assert_eq!(response.status(), self.status);
        assert_eq!(response.version(), self.version);
        assert_eq!(response.headers(), &self.headers);
        assert_eq!(
            response.extensions().get::<ResponseInfo>(),
            Some(&self.info)
        );
        assert_eq!(
            response.extensions().get::<Marker>(),
            Some(&Marker(PRIVATE))
        );
    }
}

fn wire(status: &str, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut wire =
        format!("HTTP/1.1 {status}\r\nX-Metadata: preserved\r\n{headers}\r\n").into_bytes();
    wire.extend_from_slice(body);
    wire
}

async fn exchange(wire: Vec<u8>, decoding: ContentDecoding) -> TestResult<Response<ResponseBody>> {
    timeout(TEST_TIMEOUT, async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let peer = async move {
            let (mut stream, _) = listener.accept().await?;
            let head = read_head(&mut stream).await?;
            stream.write_all(&wire).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(head)
        };

        let (head, response) = exchange_peer(peer, async {
            let client = Client::builder(ClientProfile::new(tls_settings())).build()?;
            let response = client
                .get(
                    HttpProtocol::Http1,
                    &format!("http://{address}/private?token=sensitive"),
                )?
                .header(RequestHeader::new("Accept-Encoding", "gzip"))
                .content_decoding(decoding)
                .send()
                .await?;
            Ok(response)
        })
        .await?;

        assert!(
            !head
                .windows(b"content-type:".len())
                .any(|part| part.eq_ignore_ascii_case(b"content-type:"))
        );
        Ok(response)
    })
    .await?
}

#[tokio::test]
async fn status_error_keeps_the_unread_body_and_all_metadata() -> TestResult<()> {
    let mut response = exchange(
        wire("503 Unavailable", "Content-Length: 6\r\n", b"denied"),
        ContentDecoding::none(),
    )
    .await?;
    let metadata = Metadata::record(&mut response)?;
    let mut error = error_for_status(response)
        .err()
        .ok_or("error status accepted")?;
    assert_eq!(error.status(), StatusCode::SERVICE_UNAVAILABLE);
    metadata.check(error.response());
    assert!(!format!("{error:?} {error}").contains("sensitive"));
    assert!(!format!("{error:?} {error}").contains("preserved"));
    error.response_mut().extensions_mut().insert(42_u32);
    let response = response_bytes(error.into_response(), 6).await?;
    metadata.check(&response);
    assert_eq!(response.extensions().get::<u32>(), Some(&42));
    assert_eq!(response.body(), b"denied".as_slice());

    let response = exchange(
        wire("404 Not Found", "Content-Length: 0\r\n", b""),
        ContentDecoding::none(),
    )
    .await?;
    let error = error_for_status(response)
        .err()
        .ok_or("4xx status accepted")?;
    assert_eq!(error.status(), StatusCode::NOT_FOUND);
    assert!(
        response_bytes(error.into_response(), 0)
            .await?
            .body()
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn non_error_status_and_chunked_reads_keep_headers_and_discard_trailers() -> TestResult<()> {
    let mut response = exchange(
        wire(
            "302 Found",
            "Transfer-Encoding: chunked\r\nTrailer: X-Trailer\r\n",
            b"2\r\nhe\r\n3\r\nllo\r\n0\r\nX-Trailer: discarded\r\n\r\n",
        ),
        ContentDecoding::none(),
    )
    .await?;
    let metadata = Metadata::record(&mut response)?;
    let response = response_text(error_for_status(response)?, 5).await?;
    metadata.check(&response);
    assert_eq!(response.body(), "hello");
    assert!(!response.headers().contains_key("x-trailer"));
    Ok(())
}

#[tokio::test]
async fn decoded_data_limit_returns_metadata_and_the_original_typed_body_error() -> TestResult<()> {
    let data = vec![b'x'; 1024];
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&data)?;
    let encoded = encoder.finish()?;
    assert!(encoded.len() < 100);
    let headers = format!(
        "Content-Encoding: gzip\r\nContent-Length: {}\r\n",
        encoded.len()
    );
    let mut response = exchange(
        wire("200 OK", &headers, &encoded),
        ContentDecoding::advertised(4096),
    )
    .await?;
    let metadata = Metadata::record(&mut response)?;
    let mut error = response_bytes(response, 100)
        .await
        .err()
        .ok_or("decoded limit ignored")?;
    assert_eq!(error.kind(), ResponseReadErrorKind::Body);
    let original = error.request_error().ok_or("body cause missing")?;
    assert_eq!(original.kind(), RequestErrorKind::ResponseBodyLimit);
    assert!(std::ptr::eq(
        error
            .source()
            .and_then(|cause| cause.downcast_ref::<RequestError>())
            .ok_or("direct body source missing")?,
        original
    ));
    metadata.check(error.response());
    assert!(!format!("{error:?} {error}").contains("sensitive"));
    error.response_mut().extensions_mut().insert(42_u32);
    let response = error.into_response();
    metadata.check(&response);
    assert_eq!(response.extensions().get::<u32>(), Some(&42));

    let mut response = exchange(
        wire("200 OK", &headers, &encoded),
        ContentDecoding::advertised(4096),
    )
    .await?;
    let metadata = Metadata::record(&mut response)?;
    let response = response_bytes(response, data.len()).await?;
    metadata.check(&response);
    assert_eq!(response.body(), &data);
    Ok(())
}

#[tokio::test]
async fn truncated_wire_body_keeps_metadata_and_transport_classification() -> TestResult<()> {
    let mut response = exchange(
        wire("200 OK", "Content-Length: 8\r\n", b"short"),
        ContentDecoding::none(),
    )
    .await?;
    let metadata = Metadata::record(&mut response)?;
    let error = response_text(response, 8)
        .await
        .err()
        .ok_or("truncated body accepted")?;
    assert_eq!(error.kind(), ResponseReadErrorKind::Body);
    assert_eq!(
        error.request_error().ok_or("body cause missing")?.kind(),
        RequestErrorKind::Http1
    );
    metadata.check(error.response());
    Ok(())
}

#[tokio::test]
async fn invalid_utf8_keeps_metadata_and_exposes_utf8_source() -> TestResult<()> {
    let mut response = exchange(
        wire("200 OK", "Content-Length: 1\r\n", &[0xff]),
        ContentDecoding::none(),
    )
    .await?;
    let metadata = Metadata::record(&mut response)?;
    let error = response_text(response, 1)
        .await
        .err()
        .ok_or("invalid UTF-8 accepted")?;
    assert_eq!(error.kind(), ResponseReadErrorKind::Utf8);
    assert!(error.request_error().is_none());
    assert!(
        error
            .source()
            .is_some_and(|cause| cause.is::<std::str::Utf8Error>())
    );
    metadata.check(error.response());
    assert!(!format!("{error:?} {error}").contains("sensitive"));
    metadata.check(&error.into_response());
    Ok(())
}

#[tokio::test]
async fn dropping_a_pending_read_closes_the_unfinished_body() -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let peer = async move {
            let (mut stream, _) = listener.accept().await?;
            read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nabc")
                .await?;
            let mut byte = [0];
            let closed = match stream.read(&mut byte).await {
                Ok(0) => true,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::BrokenPipe
                    ) =>
                {
                    true
                }
                _ => false,
            };
            Ok::<_, Box<dyn Error + Send + Sync>>(closed)
        };

        let client = Client::builder(ClientProfile::new(tls_settings())).build()?;
        let (closed, ()) = exchange_peer(peer, async {
            let response = client
                .get(HttpProtocol::Http1, &format!("http://{address}/"))?
                .send()
                .await?;
            let mut read = Box::pin(response_bytes(response, 100));
            poll_fn(|context| {
                assert!(read.as_mut().poll(context).is_pending());
                Poll::Ready(())
            })
            .await;
            drop(read);
            Ok(())
        })
        .await?;

        assert!(closed);
        Ok(())
    })
    .await?
}

#[cfg(feature = "json")]
#[tokio::test]
async fn typed_json_keeps_metadata_without_a_content_type_header() -> TestResult<()> {
    let mut response = exchange(
        wire("200 OK", "Content-Length: 5\r\n", b"[1,2]"),
        ContentDecoding::none(),
    )
    .await?;
    let metadata = Metadata::record(&mut response)?;
    let response = phantom::response_json::<Vec<u32>>(response, 5).await?;
    metadata.check(&response);
    assert_eq!(response.body(), &[1, 2]);
    assert!(!response.headers().contains_key("content-type"));
    Ok(())
}

#[cfg(feature = "json")]
#[tokio::test]
async fn invalid_json_keeps_metadata_and_its_typed_source() -> TestResult<()> {
    let mut response = exchange(
        wire("200 OK", "Content-Length: 5\r\n", b"[1,2,"),
        ContentDecoding::none(),
    )
    .await?;
    let metadata = Metadata::record(&mut response)?;
    let error = phantom::response_json::<Vec<u32>>(response, 5)
        .await
        .err()
        .ok_or("invalid JSON accepted")?;
    assert_eq!(error.kind(), ResponseReadErrorKind::Json);
    assert!(error.request_error().is_none());
    assert!(
        error
            .source()
            .is_some_and(|cause| cause.is::<serde_json::Error>())
    );
    metadata.check(error.response());
    assert!(!format!("{error:?} {error}").contains("sensitive"));
    let response = exchange(
        wire("200 OK", "Content-Length: 5\r\n", b"[1,2,"),
        ContentDecoding::none(),
    )
    .await?;
    let error = phantom::response_json::<Vec<u32>>(response, 4)
        .await
        .err()
        .ok_or("JSON input limit ignored")?;
    assert_eq!(error.kind(), ResponseReadErrorKind::Body);
    assert_eq!(
        error.request_error().ok_or("body cause missing")?.kind(),
        RequestErrorKind::ResponseBodyLimit
    );
    Ok(())
}

async fn exchange_peer<T: Send + 'static, R>(
    peer: impl Future<Output = TestResult<T>> + Send + 'static,
    request: impl Future<Output = TestResult<R>>,
) -> TestResult<(T, R)> {
    let peer = tokio::spawn(peer);
    let result = request.await?;
    Ok((peer.await??, result))
}
