//! Charset selection, strict conversion and metadata through the public helper.

use super::*;
use phantom::response_text_with_charset;

#[tokio::test]
async fn charset_conversion_keeps_received_headers_status_and_extensions() -> TestResult<()> {
    let mut response = exchange(
        wire(
            "418 I'm a teapot",
            "Content-Type: text/plain; note=\"a;b=c\"; charset=\"ISO-8859-1\"\r\nContent-Length: 5\r\n",
            b"caf\xe9\x80",
        ),
        ContentDecoding::none(),
    )
    .await?;
    let metadata = Metadata::record(&mut response)?;
    let response = response_text_with_charset(response, 5, 8).await?;
    metadata.check(&response);
    assert_eq!(response.body(), "caf\u{e9}\u{20ac}");
    Ok(())
}

#[tokio::test]
async fn charset_errors_retain_metadata_and_redact_supplied_fields_and_bytes() -> TestResult<()> {
    for (headers, body, input_limit, output_limit, expected) in [
        (
            "Content-Type: text/plain; charset=sensitive-secret\r\n",
            b"\xef\xbb\xbf".as_slice(),
            0,
            0,
            ResponseReadErrorKind::UnsupportedCharset,
        ),
        (
            "Content-Type: text/plain; charset=utf-8; charset=UTF-8\r\n",
            b"\xef\xbb\xbf",
            0,
            0,
            ResponseReadErrorKind::InvalidContentType,
        ),
        (
            "Content-Type: text/plain; charset=utf-8\r\n",
            b"\xc3",
            1,
            8,
            ResponseReadErrorKind::MalformedText,
        ),
        (
            "Content-Type: text/plain; charset=windows-1252\r\n",
            b"\x80",
            1,
            2,
            ResponseReadErrorKind::TextLimit,
        ),
    ] {
        let headers = format!("{headers}Content-Length: {}\r\n", body.len());
        let mut response =
            exchange(wire("200 OK", &headers, body), ContentDecoding::none()).await?;
        let metadata = Metadata::record(&mut response)?;
        let error = response_text_with_charset(response, input_limit, output_limit)
            .await
            .err()
            .ok_or("invalid text accepted")?;
        assert_eq!(error.kind(), expected);
        assert!(error.request_error().is_none());
        metadata.check(error.response());
        let formatted = format!("{error:?} {error}");
        assert!(!formatted.contains("sensitive"));
        assert!(!formatted.contains("preserved"));
        metadata.check(&error.into_response());
    }
    Ok(())
}

#[tokio::test]
async fn charset_input_limit_counts_content_decoded_bytes_and_keeps_body_cause() -> TestResult<()> {
    let data = [0x80; 128];
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&data)?;
    let encoded = encoder.finish()?;
    let headers = format!(
        "Content-Type: text/plain; charset=windows-1252\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n",
        encoded.len()
    );
    for limit in [127, 128] {
        let mut response = exchange(
            wire("200 OK", &headers, &encoded),
            ContentDecoding::advertised(1024),
        )
        .await?;
        let metadata = Metadata::record(&mut response)?;
        let result = response_text_with_charset(response, limit, 384).await;
        if limit < data.len() {
            let error = result.err().ok_or("input limit ignored")?;
            assert_eq!(error.kind(), ResponseReadErrorKind::Body);
            let original = error.request_error().ok_or("body cause missing")?;
            assert_eq!(original.kind(), RequestErrorKind::ResponseBodyLimit);
            assert!(std::ptr::eq(
                error
                    .source()
                    .and_then(|cause| cause.downcast_ref::<RequestError>())
                    .ok_or("body source missing")?,
                original
            ));
            metadata.check(error.response());
        } else {
            let response = result?;
            metadata.check(&response);
            assert_eq!(response.body(), &"\u{20ac}".repeat(128));
        }
    }
    Ok(())
}

#[tokio::test]
async fn unicode_bom_overrides_valid_charset_and_empty_text_accepts_zero_output_cap()
-> TestResult<()> {
    for (body, output_limit, expected) in [
        (b"\xff\xfeA\0".as_slice(), 1, "A"),
        (b"\xef\xbb\xbf", 0, ""),
        (b"", 0, ""),
    ] {
        let headers = format!(
            "Content-Type: text/plain; charset=windows-1252\r\nContent-Length: {}\r\n",
            body.len()
        );
        let response = exchange(wire("200 OK", &headers, body), ContentDecoding::none()).await?;
        assert_eq!(
            response_text_with_charset(response, body.len(), output_limit)
                .await?
                .body(),
            expected
        );
    }
    let response = exchange(
        wire(
            "200 OK",
            "Content-Type: text/plain; charset=windows-1252\r\nContent-Length: 1\r\n",
            b"\xe9",
        ),
        ContentDecoding::none(),
    )
    .await?;
    assert_eq!(
        response_text(response, 1)
            .await
            .err()
            .ok_or("strict UTF-8 changed")?
            .kind(),
        ResponseReadErrorKind::Utf8
    );
    Ok(())
}

#[derive(Clone, Copy)]
enum Stop {
    Cancellation,
    InputLimit,
    UnsupportedCharset,
}

#[tokio::test]
async fn stopping_charset_collection_preserves_other_http2_streams_and_connection() -> TestResult<()>
{
    for stop in [
        Stop::Cancellation,
        Stop::InputLimit,
        Stop::UnsupportedCharset,
    ] {
        timeout(TEST_TIMEOUT, isolated_h2_stream(stop)).await??;
    }
    Ok(())
}

async fn isolated_h2_stream(stop: Stop) -> TestResult<()> {
    use crate::support::h2;
    use phantom::profile::browser::chrome;
    use tokio::net::TcpStream;

    async fn request_headers(stream: &mut TcpStream) -> TestResult<u32> {
        loop {
            let frame = h2::read_frame(stream).await?;
            if frame.kind == 1 {
                assert_ne!(frame.flags & 4, 0, "test requests require no continuation");
                return Ok(frame.stream_id);
            }
        }
    }

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let mut peers = tokio::task::JoinSet::new();
    peers.spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        h2::accept_client_preface(&mut stream).await?;
        let first = request_headers(&mut stream).await?;
        // RFC7541 AppendixA: indexed :status=200; literal indexed-name31
        // is content-type. This independent peer sends no dynamic table entries.
        let mut head = vec![0x88];
        if matches!(stop, Stop::UnsupportedCharset) {
            let value = b"text/plain; charset=unknown-secret";
            head.extend_from_slice(&[0x0f, 0x10, u8::try_from(value.len())?]);
            head.extend_from_slice(value);
        }
        h2::write_frame(&mut stream, 1, 4, first, &head).await?;
        if matches!(stop, Stop::InputLimit) {
            h2::write_frame(&mut stream, 0, 0, first, b"abc").await?;
        }
        stream.flush().await?;
        let second = request_headers(&mut stream).await?;
        assert!(second > first);
        h2::write_frame(&mut stream, 1, 4, second, &[0x88]).await?;
        stream.flush().await?;
        loop {
            let frame = h2::read_frame(&mut stream).await?;
            if frame.kind == 3 {
                assert_eq!(frame.stream_id, first);
                assert_eq!(frame.payload, 8_u32.to_be_bytes());
                break;
            }
            assert_ne!(frame.kind, 7, "cancelling one body closed the connection");
        }
        h2::write_frame(&mut stream, 0, 1, second, b"ok").await?;
        stream.flush().await?;
        let third = request_headers(&mut stream).await?;
        assert!(third > second);
        h2::write_frame(&mut stream, 1, 5, third, &[0x88]).await?;
        stream.flush().await?;
        TestResult::Ok(())
    });
    let client = Client::builder(chrome::v154_windows()).build()?;
    let url = format!("http://{address}/charset");
    let first = client.get(HttpProtocol::Http2, &url)?.send().await?;
    let second = client.get(HttpProtocol::Http2, &url)?.send().await?;
    let mut read = Box::pin(response_text_with_charset(first, 2, 8));
    if matches!(stop, Stop::Cancellation) {
        poll_fn(|context| {
            assert!(read.as_mut().poll(context).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(read);
    } else {
        let error = read.await.err().ok_or("unfinished response accepted")?;
        if matches!(stop, Stop::InputLimit) {
            assert_eq!(error.kind(), ResponseReadErrorKind::Body);
            assert_eq!(
                error.request_error().ok_or("body cause missing")?.kind(),
                RequestErrorKind::ResponseBodyLimit
            );
        } else {
            assert_eq!(error.kind(), ResponseReadErrorKind::UnsupportedCharset);
        }
    }
    assert_eq!(response_text_with_charset(second, 2, 2).await?.body(), "ok");
    let third = client.get(HttpProtocol::Http2, &url)?.send().await?;
    assert_eq!(response_text_with_charset(third, 0, 0).await?.body(), "");
    peers.join_next().await.ok_or("missing HTTP/2 peer")???;
    Ok(())
}
