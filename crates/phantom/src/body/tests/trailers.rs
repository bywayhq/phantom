use super::*;
use http::Response;
use http_body_util::BodyExt;

use crate::{ResponseTrailers, response_bytes, response_text};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

async fn wire_response(wire: Vec<u8>) -> TestResult<Response<ResponseBody>> {
    assert!(wire.len() < 4096, "fixture must fit the duplex buffer");
    let (stream, mut peer) = tokio::io::duplex(4096);
    let server = async move {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            if head.len() >= 1024 {
                return Err("request head exceeds fixture bound".into());
            }
            head.push(peer.read_u8().await?);
        }
        peer.write_all(&wire).await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    };
    let caller = async {
        let connection = Http1Connection::connect(stream).await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
            connection
                .send_get(
                    OriginForm::parse("/")?,
                    vec![RequestHeader::new("Host", "example.test")],
                )
                .await?,
        )
    };
    let (response, ()) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::try_join!(caller, server)
    })
    .await
    .map_err(|_| "HTTP/1 trailer fixture timed out")??;
    Ok(response.map(ResponseBody::http1))
}

fn chunked(data: &[u8], trailers: &[u8], extra_head: &str) -> Vec<u8> {
    let mut wire =
        format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n{extra_head}\r\n").into_bytes();
    if !data.is_empty() {
        wire.extend_from_slice(format!("{:x}\r\n", data.len()).as_bytes());
        wire.extend_from_slice(data);
        wire.extend_from_slice(b"\r\n");
    }
    wire.extend_from_slice(b"0\r\n");
    wire.extend_from_slice(trailers);
    wire.extend_from_slice(b"\r\n");
    wire
}

fn fields(trailers: &ResponseTrailers) -> TestResult<Vec<(&str, &[u8])>> {
    let ResponseTrailers::Complete(headers) = trailers else {
        return Err("response trailers are not complete".into());
    };
    Ok(headers
        .iter()
        .map(|field| (field.name(), field.value()))
        .collect())
}

#[tokio::test]
async fn ordered_trailers_are_pending_until_actual_outer_eof() -> TestResult {
    let response = wire_response(chunked(
        b"ok",
        b"X-One: first\r\nX-Two: \xff\r\nx-one: last\r\n",
        "",
    ))
    .await?;
    let mut body = response.into_body();
    assert_eq!(body.trailers(), &ResponseTrailers::Pending);
    assert_eq!(
        body.frame().await.ok_or("missing data")??.data_ref(),
        Some(&Bytes::from_static(b"ok"))
    );
    assert_eq!(body.trailers(), &ResponseTrailers::Pending);
    assert!(
        body.frame()
            .await
            .ok_or("missing trailers")??
            .trailers_ref()
            .is_some()
    );
    assert!(body.is_end_stream());
    assert_eq!(body.trailers(), &ResponseTrailers::Pending);
    assert!(body.frame().await.is_none());
    assert_eq!(
        fields(body.trailers())?,
        vec![
            ("X-One", b"first".as_slice()),
            ("X-Two", b"\xff".as_slice()),
            ("x-one", b"last".as_slice()),
        ]
    );
    let retained = body.into_trailers();
    assert_eq!(fields(&retained)?.len(), 3);
    assert!(!format!("{retained:?}").contains("first"));
    Ok(())
}

#[tokio::test]
async fn empty_completion_and_abandonment_remain_distinct() -> TestResult {
    let mut body = wire_response(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec())
        .await?
        .into_body();
    assert_eq!(body.trailers(), &ResponseTrailers::Pending);
    assert!(body.frame().await.is_none());
    assert!(fields(&body.into_trailers())?.is_empty());
    let body = wire_response(chunked(b"ok", b"X-One: value\r\n", ""))
        .await?
        .into_body();
    assert_eq!(body.into_trailers(), ResponseTrailers::Unavailable);
    let mut body = wire_response(chunked(b"ok", b"X-One: value\r\n", ""))
        .await?
        .into_body();
    while let Some(frame) = body.frame().await {
        if frame?.trailers_ref().is_some() {
            break;
        }
    }
    assert_eq!(body.into_trailers(), ResponseTrailers::Unavailable);
    Ok(())
}

#[tokio::test]
async fn wire_failure_and_collection_limit_never_publish_trailers() -> TestResult {
    let mut body =
        wire_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\ninvalid\r\n".to_vec())
            .await?
            .into_body();
    assert!(body.frame().await.ok_or("missing wire failure")?.is_err());
    assert_eq!(body.trailers(), &ResponseTrailers::Unavailable);
    assert!(body.frame().await.is_none());
    assert_eq!(body.into_trailers(), ResponseTrailers::Unavailable);
    let response = wire_response(chunked(b"ok", b"X-One: value\r\n", "")).await?;
    let error = response_bytes(response, 1)
        .await
        .err()
        .ok_or("limit accepted")?;
    assert_eq!(
        error.request_error().ok_or("missing body error")?.kind(),
        RequestErrorKind::ResponseBodyLimit
    );
    assert_eq!(
        error.response().extensions().get::<ResponseTrailers>(),
        Some(&ResponseTrailers::Unavailable)
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn expired_total_clears_trailers_received_in_the_failing_poll() -> TestResult {
    let mut body = wire_response(chunked(b"ok", b"X-One: value\r\n", ""))
        .await?
        .into_body();
    body.apply_timeouts(
        TimeoutBudget::new(RequestTimeouts::new().total(Duration::from_secs(1)))?,
        HttpProtocol::Http1,
    )?;
    assert!(
        body.frame()
            .await
            .ok_or("missing DATA")??
            .data_ref()
            .is_some()
    );
    tokio::time::advance(Duration::from_secs(2)).await;
    let error = body
        .frame()
        .await
        .ok_or("missing timeout")?
        .err()
        .ok_or("expired trailer poll succeeded")?;
    assert_eq!(error.kind(), RequestErrorKind::Timeout);
    assert_eq!(error.timeout_phase(), Some(TimeoutPhase::Total));
    assert_eq!(body.trailers(), &ResponseTrailers::Unavailable);
    assert!(body.frame().await.is_none());
    assert_eq!(body.into_trailers(), ResponseTrailers::Unavailable);
    Ok(())
}

fn enable_gzip(response: &mut Response<ResponseBody>) -> TestResult {
    let advertised = AdvertisedContentCodings::from_request_headers(&[RequestHeader::new(
        "accept-encoding",
        "gzip",
    )])?;
    let decoder = match plan(
        ContentDecoding::advertised(10),
        advertised,
        &Method::GET,
        response.status(),
        response.headers(),
        false,
        HttpProtocol::Http1,
    ) {
        ContentDecodingPlan::Decode(decoder, _) => decoder,
        _ => return Err("fixture did not enable gzip".into()),
    };
    response.body_mut().decode_content(decoder);
    Ok(())
}

#[tokio::test]
async fn decoder_must_finish_before_staged_trailers_become_complete() -> TestResult {
    // An independently encoded empty gzip member, including CRC32 and ISIZE.
    let gzip = [
        31, 139, 8, 0, 0, 0, 0, 0, 0, 255, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    for valid in [false, true] {
        let data = if valid { gzip.as_slice() } else { &gzip[..17] };
        let mut response = wire_response(chunked(
            data,
            b"X-One: value\r\n",
            "Content-Encoding: gzip\r\n",
        ))
        .await?;
        enable_gzip(&mut response)?;
        let result = response_bytes(response, 0).await;
        if valid {
            let response = result?;
            assert!(response.body().is_empty());
            assert_eq!(
                fields(
                    response
                        .extensions()
                        .get::<ResponseTrailers>()
                        .ok_or("missing retained trailers")?
                )?,
                vec![("X-One", b"value".as_slice())]
            );
        } else {
            let error = result.err().ok_or("truncated gzip accepted")?;
            assert_eq!(
                error.request_error().ok_or("missing decoder error")?.kind(),
                RequestErrorKind::ContentDecoding
            );
            assert_eq!(
                error.response().extensions().get::<ResponseTrailers>(),
                Some(&ResponseTrailers::Unavailable)
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn parse_failure_after_validated_eof_keeps_complete_trailers() -> TestResult {
    let response = wire_response(chunked(b"\xff", b"X-One: value\r\n", "")).await?;
    let error = response_text(response, 1)
        .await
        .err()
        .ok_or("invalid UTF-8 accepted")?;
    assert_eq!(error.kind(), crate::ResponseReadErrorKind::Utf8);
    assert_eq!(
        fields(
            error
                .response()
                .extensions()
                .get::<ResponseTrailers>()
                .ok_or("missing retained trailers")?
        )?
        .len(),
        1
    );
    #[cfg(feature = "json")]
    {
        let response = wire_response(chunked(b"{", b"X-One: value\r\n", "")).await?;
        let error = crate::response_json::<serde_json::Value>(response, 1)
            .await
            .err()
            .ok_or("invalid JSON accepted")?;
        assert_eq!(error.kind(), crate::ResponseReadErrorKind::Json);
        assert_eq!(
            fields(
                error
                    .response()
                    .extensions()
                    .get::<ResponseTrailers>()
                    .ok_or("missing retained trailers")?
            )?
            .len(),
            1
        );
    }
    #[cfg(feature = "xml")]
    {
        let response = wire_response(chunked(b"<", b"X-One: value\r\n", "")).await?;
        let error = crate::response_xml::<String>(response, 1)
            .await
            .err()
            .ok_or("invalid XML accepted")?;
        assert_eq!(error.kind(), crate::ResponseReadErrorKind::Xml);
        assert_eq!(
            fields(
                error
                    .response()
                    .extensions()
                    .get::<ResponseTrailers>()
                    .ok_or("missing XML trailers")?
            )?
            .len(),
            1
        );
    }
    Ok(())
}

#[cfg(feature = "charset")]
#[tokio::test]
async fn charset_validation_distinguishes_unread_body_and_post_eof_failure() -> TestResult {
    for content_type in ["broken", "text/plain; charset=utf-8"] {
        let response = wire_response(chunked(
            b"\xff",
            b"X-One: value\r\n",
            &format!("Content-Type: {content_type}\r\n"),
        ))
        .await?;
        let error = crate::response_text_with_charset(response, 1, 1)
            .await
            .err()
            .ok_or("invalid text accepted")?;
        let retained = error
            .response()
            .extensions()
            .get::<ResponseTrailers>()
            .ok_or("missing charset trailers")?;
        if content_type == "broken" {
            assert_eq!(
                error.kind(),
                crate::ResponseReadErrorKind::InvalidContentType
            );
            assert_eq!(retained, &ResponseTrailers::Unavailable);
        } else {
            assert_eq!(error.kind(), crate::ResponseReadErrorKind::MalformedText);
            assert_eq!(fields(retained)?.len(), 1);
        }
    }
    Ok(())
}

#[tokio::test]
async fn digest_failure_invalidates_staged_and_missing_trailers() -> TestResult {
    use phantom_net::{
        proxy::{DigestForwardAuthentication, HttpDigestCredentials},
        route::{Endpoint, ProxyTransport},
    };
    for trailer in [b"X-One: value\r\n".as_slice(), b"".as_slice()] {
        let mut response = wire_response(chunked(
            b"ok",
            trailer,
            "Trailer: Proxy-Authentication-Info\r\n",
        ))
        .await?;
        let credentials = HttpDigestCredentials::new("user", "password")?;
        let mut authentication = DigestForwardAuthentication::new(
            &credentials,
            ProxyTransport::Tcp(Endpoint {
                host: "proxy.test",
                port: 8080,
            }),
            false,
        );
        let mut challenge = HeaderMap::new();
        challenge.insert(
            "proxy-authenticate",
            HeaderValue::from_static(
                "Digest realm=\"test\", nonce=\"nonce\", algorithm=SHA-256, qop=\"auth\"",
            ),
        );
        authentication.challenge(&challenge)?;
        let _authorization = authentication
            .authorization(&Method::GET, "http://example.test/")?
            .ok_or("missing Digest authorization")?;
        let proof = authentication
            .accept(response.headers())?
            .ok_or("missing Digest proof guard")?;
        response
            .body_mut()
            .authenticate_proxy(proof, HttpProtocol::Http1)?;
        let error = response_bytes(response, 2)
            .await
            .err()
            .ok_or("missing authentication trailer accepted")?;
        assert_eq!(
            error.request_error().ok_or("missing Digest error")?.kind(),
            RequestErrorKind::Proxy
        );
        assert_eq!(
            error.response().extensions().get::<ResponseTrailers>(),
            Some(&ResponseTrailers::Unavailable)
        );
    }
    Ok(())
}
