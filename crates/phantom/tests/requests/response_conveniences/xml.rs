//! Typed XML, metadata and body ownership through independent HTTP peers.

use super::*;
use phantom::response_xml;
use serde::Deserialize;

#[derive(Debug, Deserialize, Eq, PartialEq)]
struct Message {
    #[serde(rename = "@id")]
    id: u32,
    text: String,
}

#[tokio::test]
async fn typed_xml_keeps_error_status_headers_and_extensions_without_content_type() -> TestResult<()>
{
    let body = b"<message id='7'><text>hello &amp; goodbye</text></message>";
    let mut response = exchange(
        wire(
            "418 I'm a teapot",
            &format!("Content-Length: {}\r\n", body.len()),
            body,
        ),
        ContentDecoding::none(),
    )
    .await?;
    let metadata = Metadata::record(&mut response)?;
    let response = response_xml::<Message>(response, body.len()).await?;
    metadata.check(&response);
    assert_eq!(response.body().id, 7);
    assert_eq!(response.body().text, "hello & goodbye");
    assert!(!response.headers().contains_key("content-type"));
    Ok(())
}

#[tokio::test]
async fn xml_utf8_and_body_errors_keep_metadata_and_redact_supplied_content() -> TestResult<()> {
    for (body, declared_length, limit, expected) in [
        (
            b"<message id='sensitive'><text>preserved</text></message>".as_slice(),
            None,
            usize::MAX,
            ResponseReadErrorKind::Xml,
        ),
        (
            b"<a/>sensitive",
            None,
            usize::MAX,
            ResponseReadErrorKind::Xml,
        ),
        (
            b"<!DOCTYPE a SYSTEM 'file:///sensitive'><a/>",
            None,
            usize::MAX,
            ResponseReadErrorKind::Xml,
        ),
        (
            b"<?xml version='1.0' encoding='UTF-16'?><a/>",
            None,
            usize::MAX,
            ResponseReadErrorKind::Xml,
        ),
        (
            b"<a>\xff</a>",
            None,
            usize::MAX,
            ResponseReadErrorKind::Utf8,
        ),
        (b"", None, 0, ResponseReadErrorKind::Xml),
        (b"<a/>", None, 0, ResponseReadErrorKind::Body),
        (b"<a/>", Some(20), 20, ResponseReadErrorKind::Body),
    ] {
        let mut response = exchange(
            wire(
                "200 OK",
                &format!(
                    "Content-Length: {}\r\n",
                    declared_length.unwrap_or(body.len())
                ),
                body,
            ),
            ContentDecoding::none(),
        )
        .await?;
        let metadata = Metadata::record(&mut response)?;
        let error = response_xml::<Message>(response, limit)
            .await
            .err()
            .ok_or("invalid XML response accepted")?;
        assert_eq!(error.kind(), expected);
        metadata.check(error.response());
        assert_eq!(
            error.request_error().is_some(),
            expected == ResponseReadErrorKind::Body
        );
        assert!(error.source().is_some());
        let formatted = format!("{error:?} {error}");
        assert!(!formatted.contains("sensitive"));
        assert!(!formatted.contains("preserved"));
        metadata.check(&error.into_response());
    }
    Ok(())
}

#[tokio::test]
async fn xml_input_limit_counts_decoded_bytes_and_preserves_the_body_cause() -> TestResult<()> {
    let body = format!("<message id='1'><text>{}</text></message>", "x".repeat(256));
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(body.as_bytes())?;
    let encoded = encoder.finish()?;
    let headers = format!(
        "Content-Encoding: gzip\r\nContent-Length: {}\r\n",
        encoded.len()
    );
    assert!(encoded.len() < body.len());
    for limit in [body.len() - 1, body.len()] {
        let mut response = exchange(
            wire("200 OK", &headers, &encoded),
            ContentDecoding::advertised(1024),
        )
        .await?;
        let metadata = Metadata::record(&mut response)?;
        let result = response_xml::<Message>(response, limit).await;
        if limit < body.len() {
            let error = result.err().ok_or("XML input cap ignored")?;
            assert_eq!(error.kind(), ResponseReadErrorKind::Body);
            assert_eq!(
                error.request_error().ok_or("body cause missing")?.kind(),
                RequestErrorKind::ResponseBodyLimit
            );
            assert!(
                error
                    .source()
                    .is_some_and(|cause| cause.is::<RequestError>())
            );
            metadata.check(error.response());
        } else {
            let response = result?;
            assert_eq!(response.body().text, "x".repeat(256));
            metadata.check(&response);
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Stop {
    Cancellation,
    InputLimit,
}

#[tokio::test]
async fn stopping_xml_collection_resets_only_the_selected_http2_stream() -> TestResult<()> {
    for stop in [Stop::Cancellation, Stop::InputLimit] {
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
            assert_ne!(frame.kind, 7, "selected stream closed the connection");
        }
    }

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let mut peers = tokio::task::JoinSet::new();
    peers.spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        h2::accept_client_preface(&mut stream).await?;
        let first = request_headers(&mut stream).await?;
        h2::write_frame(&mut stream, 1, 4, first, &[0x88]).await?;
        if matches!(stop, Stop::InputLimit) {
            h2::write_frame(&mut stream, 0, 0, first, b"<m>").await?;
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
            assert_ne!(frame.kind, 7, "cancelling XML closed the connection");
        }
        h2::write_frame(&mut stream, 0, 1, second, b"<m>ok</m>").await?;
        stream.flush().await?;
        let third = request_headers(&mut stream).await?;
        assert!(third > second);
        h2::write_frame(&mut stream, 1, 4, third, &[0x88]).await?;
        h2::write_frame(&mut stream, 0, 1, third, b"<m/>").await?;
        stream.flush().await?;
        TestResult::Ok(())
    });
    let client = Client::builder(chrome::v154_windows()).build()?;
    let url = format!("http://{address}/xml");
    let first = client.get(HttpProtocol::Http2, &url)?.send().await?;
    let second = client.get(HttpProtocol::Http2, &url)?.send().await?;
    let mut read = Box::pin(response_xml::<String>(first, 2));
    match stop {
        Stop::Cancellation => {
            poll_fn(|context| {
                assert!(read.as_mut().poll(context).is_pending());
                Poll::Ready(())
            })
            .await;
            drop(read);
        }
        Stop::InputLimit => {
            let error = read.await.err().ok_or("unfinished XML accepted")?;
            assert_eq!(error.kind(), ResponseReadErrorKind::Body);
            assert_eq!(
                error.request_error().ok_or("body cause missing")?.kind(),
                RequestErrorKind::ResponseBodyLimit
            );
        }
    }
    assert_eq!(response_xml::<String>(second, 16).await?.body(), "ok");
    let third = client.get(HttpProtocol::Http2, &url)?.send().await?;
    assert_eq!(response_xml::<String>(third, 16).await?.body(), "");
    peers
        .join_next()
        .await
        .ok_or("missing XML HTTP/2 peer")???;
    Ok(())
}
