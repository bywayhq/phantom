use std::{error::Error, sync::Arc};

use bytes::BytesMut;
use h3::ext::{OrderedHeaders, RequestPseudoHeader, RequestPseudoHeaderOrder};
use http::{HeaderValue, Request, Response, StatusCode};
use phantom_profile::{
    Http3PseudoHeader, Http3QpackEncoding, Http3Setting, Http3SettingOrder, Http3Settings, chromium,
};
use tokio::{sync::oneshot, time::timeout};
use tracing::instrument::WithSubscriber;

use super::{
    TestResult, accept_request, client_config, join_server, send_test_request, server_endpoint,
};
use crate::{
    http3::{Http3ErrorKind, OriginForm, RequestHeader},
    tls::test_support::{TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity},
    tracing_test::OutcomeSubscriber,
};

const CHROME_FIXTURE: &str = include_str!(
    "../../../../../fixtures/http3/chrome/152.0.7977.83/macos-15.5/client-startup.txt"
);

#[test]
fn chrome_capture_matches_dynamic_qpack_bytes() -> TestResult<()> {
    let expected = fixture_request_headers()?;
    let (authority, target, headers) = fixture_request_input(&expected)?;
    let request = crate::http3::request::prepare_get(
        &chromium::v152_macos_http3_request(),
        &authority,
        target,
        headers,
    )?;
    let (parts, ()) = request.into_parts();
    let header = h3::proto::headers::Header::request(
        parts.method,
        parts.uri,
        parts.headers,
        parts.extensions,
    )?;
    let fields = header.into_iter().collect::<Vec<_>>();

    assert_eq!(fields.len(), expected.len());
    for (actual, (expected_name, expected_value)) in fields.iter().zip(&expected) {
        assert_eq!(actual.name.as_ref(), expected_name);
        assert_eq!(actual.value.as_ref(), expected_value);
    }

    let mut encoder = h3::qpack::Encoder::default();
    let mut encoder_instructions = BytesMut::new();
    encoder.set_max_table_capacity(
        fixture_value("server_qpack_max_table_capacity")?.parse()?,
        &mut encoder_instructions,
    )?;
    encoder.set_max_blocked_streams(fixture_value("server_qpack_blocked_streams")?.parse()?)?;
    let mut field_section = BytesMut::new();
    let required_insert_count = encoder.encode(
        fixture_value("request_stream_id")?.parse()?,
        &mut field_section,
        &mut encoder_instructions,
        fields,
    )?;

    assert_eq!(required_insert_count, 13);
    assert_eq!(
        encoder_instructions.as_ref(),
        &decode_hex(fixture_value("request_qpack_encoder_stream_prefix_hex")?)?[1..]
    );
    assert_eq!(
        field_section.as_ref(),
        decode_hex(fixture_value("request_headers_payload_hex")?)?
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn chrome_request_matches_captured_qpack_on_a_live_connection() -> TestResult<()> {
    let expected_headers = fixture_request_headers()?;
    let (authority, target, headers) = fixture_request_input(&expected_headers)?;
    let expected_encoder = decode_hex(fixture_value("request_qpack_encoder_stream_prefix_hex")?)?;
    let expected_encoder = expected_encoder
        .strip_prefix(&[0x02])
        .ok_or("fixture QPACK encoder prefix omitted its stream type")?
        .to_vec();
    let expected_frame = decode_hex(fixture_value("request_headers_frame_hex")?)?;

    let identity = TestIdentity::generate()?;
    let client = client_config(&identity)?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (client_done, done_received) = oneshot::channel();
    let server = tokio::spawn(async move {
        let incoming = endpoint.accept().await.ok_or("test endpoint closed")?;
        let connection = incoming.await?;
        let mut control = connection.open_uni().await?;
        control
            .write_all(&[0x00, 0x04, 0x05, 0x01, 0x50, 0x00, 0x07, 0x10])
            .await?;

        let mut streams = accept_chrome_client_streams(&connection).await?;
        let mut encoder = vec![0; expected_encoder.len()];
        streams.encoder.read_exact(&mut encoder).await?;
        assert_eq!(encoder, expected_encoder);

        let (mut response, mut request) = connection.accept_bi().await?;
        let mut frame = vec![0; expected_frame.len()];
        request.read_exact(&mut frame).await?;
        assert_eq!(frame, expected_frame);

        response.write_all(&[0x01, 0x03, 0x00, 0x00, 0xd9]).await?;
        response.finish()?;
        let _ = done_received.await;
        connection.close(quinn::VarInt::from_u32(0), b"");
        drop((control, streams));
        Ok::<(), Box<dyn Error + Send + Sync>>(())
    });

    let response = timeout(
        TEST_TIMEOUT,
        crate::http3::send_get(
            address,
            TEST_SERVER_NAME,
            client,
            &chromium::v152_macos_http3(),
            &chromium::v152_macos_http3_request(),
            &authority,
            target,
            headers,
        ),
    )
    .await
    .map_err(|_| "live Chrome QPACK request timed out")??;
    assert_eq!(response.status(), StatusCode::OK);
    drop(response);
    let _ = client_done.send(());
    join_server(server).await?;
    Ok(())
}

#[test]
fn prepared_get_retains_cross_name_order_and_duplicates() -> TestResult<()> {
    let request = crate::http3::request::prepare_get(
        &chromium::v152_macos_http3_request(),
        "server.phantom.test",
        OriginForm::parse("/ordered")?,
        vec![
            RequestHeader::new("x-repeat", "alpha"),
            RequestHeader::new("x-middle", "between"),
            RequestHeader::new("x-repeat", "beta"),
        ],
    )?;
    let ordered = request
        .extensions()
        .get::<OrderedHeaders>()
        .ok_or("prepared HTTP/3 GET omitted ordered headers")?;
    assert_eq!(
        ordered
            .as_slice()
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_bytes()))
            .collect::<Vec<_>>(),
        [
            ("x-repeat", b"alpha".as_slice()),
            ("x-middle", b"between".as_slice()),
            ("x-repeat", b"beta".as_slice()),
        ]
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn rejects_disagreeing_order_extensions_before_connecting() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let mut ordinary = Request::get("https://server.phantom.test/")
        .header("x-field", "semantic")
        .body(())?;
    ordinary.extensions_mut().insert(OrderedHeaders::new(vec![(
        "x-field".parse()?,
        HeaderValue::from_static("different"),
    )]));

    let mut pseudo = Request::get("https://server.phantom.test/").body(())?;
    pseudo
        .extensions_mut()
        .insert(RequestPseudoHeaderOrder::new(vec![
            RequestPseudoHeader::Method,
            RequestPseudoHeader::Method,
            RequestPseudoHeader::Scheme,
            RequestPseudoHeader::Path,
        ]));

    let mut sensitive = Request::get("https://server.phantom.test/").body(())?;
    let mut semantic_value = HeaderValue::from_static("same");
    semantic_value.set_sensitive(true);
    sensitive.headers_mut().insert("x-field", semantic_value);
    sensitive.extensions_mut().insert(OrderedHeaders::new(vec![(
        "x-field".parse()?,
        HeaderValue::from_static("same"),
    )]));

    let mut missing = Request::get("https://server.phantom.test/")
        .header("x-field", "semantic")
        .body(())?;
    missing
        .extensions_mut()
        .insert(OrderedHeaders::new(Vec::new()));

    let mut extra = Request::get("https://server.phantom.test/").body(())?;
    extra.extensions_mut().insert(OrderedHeaders::new(vec![(
        "x-field".parse()?,
        HeaderValue::from_static("extra"),
    )]));

    let mut reordered = Request::get("https://server.phantom.test/").body(())?;
    reordered
        .headers_mut()
        .append("x-field", HeaderValue::from_static("first"));
    reordered
        .headers_mut()
        .append("x-field", HeaderValue::from_static("second"));
    reordered.extensions_mut().insert(OrderedHeaders::new(vec![
        ("x-field".parse()?, HeaderValue::from_static("second")),
        ("x-field".parse()?, HeaderValue::from_static("first")),
    ]));

    for request in [ordinary, pseudo, sensitive, missing, extra, reordered] {
        let result = send_test_request(
            "127.0.0.1:9".parse()?,
            TEST_SERVER_NAME,
            client_config(&identity)?,
            request,
        )
        .await;
        let error = match result {
            Ok(_) => return Err("disagreeing order metadata reached the network".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), Http3ErrorKind::Request);
    }
    Ok(())
}

#[test]
fn ordered_get_rejects_invalid_input_before_network_setup() -> TestResult<()> {
    let settings = chromium::v152_macos_http3_request();
    let cases = [
        (
            "user@server.phantom.test",
            vec![],
            "authority containing userinfo",
        ),
        (
            TEST_SERVER_NAME,
            vec![RequestHeader::new("Uppercase", "value")],
            "uppercase field name",
        ),
        (
            TEST_SERVER_NAME,
            vec![RequestHeader::new("bad name", "value")],
            "invalid field name",
        ),
        (
            TEST_SERVER_NAME,
            vec![RequestHeader::new("x-field", b"value\r\ninjected")],
            "invalid field value",
        ),
        (
            TEST_SERVER_NAME,
            vec![RequestHeader::new("te", "Trailers")],
            "invalid TE value",
        ),
        (
            TEST_SERVER_NAME,
            vec![RequestHeader::new("content-length", "1")],
            "nonzero content length",
        ),
    ];
    for (authority, headers, description) in cases {
        let error = expected_http3_error(
            crate::http3::request::prepare_get(
                &settings,
                authority,
                OriginForm::parse("/")?,
                headers,
            ),
            description,
        )?;
        assert_eq!(error.kind(), Http3ErrorKind::Request, "{description}");
    }

    for forbidden in [
        "host",
        "connection",
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
        "upgrade",
        "trailer",
    ] {
        let error = expected_http3_error(
            crate::http3::request::prepare_get(
                &settings,
                TEST_SERVER_NAME,
                OriginForm::parse("/")?,
                vec![RequestHeader::new(forbidden, "value")],
            ),
            "forbidden HTTP/3 field was accepted",
        )?;
        assert_eq!(error.kind(), Http3ErrorKind::Request, "{forbidden}");
    }

    let too_many = (0..=crate::http3::request::MAX_REQUEST_HEADERS)
        .map(|index| RequestHeader::new(format!("x-{index}"), "v"))
        .collect();
    let error = expected_http3_error(
        crate::http3::request::prepare_get(
            &settings,
            TEST_SERVER_NAME,
            OriginForm::parse("/")?,
            too_many,
        ),
        "request header count limit was not enforced",
    )?;
    assert_eq!(error.kind(), Http3ErrorKind::Request);

    let error = expected_http3_error(
        crate::http3::request::prepare_get(
            &settings,
            TEST_SERVER_NAME,
            OriginForm::parse("/")?,
            vec![RequestHeader::new(
                "x-large",
                vec![b'a'; crate::http3::request::MAX_REQUEST_HEADER_BYTES],
            )],
        ),
        "request header byte limit was not enforced",
    )?;
    assert_eq!(error.kind(), Http3ErrorKind::Request);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn invalid_ordered_get_is_traced_before_connecting() -> TestResult<()> {
    OutcomeSubscriber::install_dynamic_callsite_fallback();
    let identity = TestIdentity::generate()?;
    let subscriber = OutcomeSubscriber::default();
    let result = crate::http3::send_get(
        "127.0.0.1:9".parse()?,
        TEST_SERVER_NAME,
        client_config(&identity)?,
        &chromium::v152_macos_http3(),
        &chromium::v152_macos_http3_request(),
        "user@server.phantom.test",
        OriginForm::parse("/")?,
        Vec::new(),
    )
    .with_subscriber(subscriber.dispatch())
    .await;

    let error = expected_http3_error(result, "invalid authority unexpectedly reached the network")?;
    assert_eq!(error.kind(), Http3ErrorKind::Request);
    assert_eq!(subscriber.outcomes_for("http3.request.prepare"), ["error"]);
    assert_eq!(
        subscriber.error_kinds_for("http3.request.prepare"),
        ["request"]
    );
    assert!(subscriber.outcomes_for("http3.response_head").is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn request_errors_precede_profile_errors() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = client_config(&identity)?;
    let invalid_settings = Http3Settings {
        initial_settings: vec![Http3Setting::QpackMaxTableCapacity(1 << 30)],
        setting_order: Http3SettingOrder::Fixed,
        qpack_encoding: Http3QpackEncoding::Stateless,
    };
    let mut invalid_request_settings = chromium::v152_macos_http3_request();
    invalid_request_settings.pseudo_header_order[3] = Http3PseudoHeader::Method;

    let error = expected_http3_error(
        crate::http3::send_get(
            "127.0.0.1:9".parse()?,
            TEST_SERVER_NAME,
            Arc::clone(&client),
            &invalid_settings,
            &invalid_request_settings,
            "user@server.phantom.test",
            OriginForm::parse("/")?,
            Vec::new(),
        )
        .await,
        "mixed-invalid ordered request unexpectedly reached the network",
    )?;
    assert_eq!(error.kind(), Http3ErrorKind::Request);

    let error = expected_http3_error(
        crate::http3::send_request(
            "127.0.0.1:9".parse()?,
            TEST_SERVER_NAME,
            client,
            &invalid_settings,
            Request::get("http://server.phantom.test/").body(())?,
        )
        .await,
        "mixed-invalid legacy request unexpectedly reached the network",
    )?;
    assert_eq!(error.kind(), Http3ErrorKind::Request);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn ordered_get_completes_with_duplicate_fields() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = client_config(&identity)?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (client_done, done_received) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (request, mut stream, _connection) = accept_request(&endpoint).await?;
        assert_eq!(request.uri().path(), "/ordered");
        assert_eq!(
            request
                .headers()
                .get_all("x-repeat")
                .iter()
                .map(HeaderValue::as_bytes)
                .collect::<Vec<_>>(),
            [b"alpha".as_slice(), b"beta".as_slice()]
        );
        stream
            .send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(())?,
            )
            .await?;
        stream.finish().await?;
        let _ = done_received.await;
        Ok::<(), Box<dyn Error + Send + Sync>>(())
    });

    let settings = chromium::v152_macos_http3();
    let request_settings = chromium::v152_macos_http3_request();
    let response = timeout(
        TEST_TIMEOUT,
        crate::http3::send_get(
            address,
            TEST_SERVER_NAME,
            client,
            &settings,
            &request_settings,
            &format!("{TEST_SERVER_NAME}:{}", address.port()),
            OriginForm::parse("/ordered")?,
            vec![
                RequestHeader::new("x-repeat", "alpha"),
                RequestHeader::new("x-middle", "between"),
                RequestHeader::new("x-repeat", "beta"),
            ],
        ),
    )
    .await
    .map_err(|_| "ordered HTTP/3 GET timed out")??;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    drop(response);
    let _ = client_done.send(());
    join_server(server).await?;
    Ok(())
}

fn fixture_request_headers() -> TestResult<Vec<(Vec<u8>, Vec<u8>)>> {
    let count = fixture_value("request_header_count")?.parse::<usize>()?;
    (0..count)
        .map(|index| {
            let line = fixture_value(&format!("request_header_{index}"))?;
            let (name, value) = line
                .split_once(':')
                .ok_or("fixture request header is missing its value")?;
            Ok((decode_hex(name)?, decode_hex(value)?))
        })
        .collect()
}

fn fixture_request_input(
    expected: &[(Vec<u8>, Vec<u8>)],
) -> TestResult<(String, OriginForm, Vec<RequestHeader>)> {
    let authority = std::str::from_utf8(&expected[1].1)?.to_owned();
    let target = OriginForm::parse(std::str::from_utf8(&expected[3].1)?)?;
    let headers = expected[4..]
        .iter()
        .map(|(name, value)| {
            Ok(RequestHeader::new(
                std::str::from_utf8(name)?.to_owned(),
                value,
            ))
        })
        .collect::<TestResult<Vec<_>>>()?;
    Ok((authority, target, headers))
}

struct ChromeClientStreams {
    _control: quinn::RecvStream,
    encoder: quinn::RecvStream,
    _decoder: quinn::RecvStream,
    _grease: Vec<quinn::RecvStream>,
}

async fn accept_chrome_client_streams(
    connection: &quinn::Connection,
) -> TestResult<ChromeClientStreams> {
    let mut control = None;
    let mut encoder = None;
    let mut decoder = None;
    let mut grease = Vec::new();
    while control.is_none() || encoder.is_none() || decoder.is_none() {
        let mut stream = connection.accept_uni().await?;
        match read_stream_varint(&mut stream).await? {
            0x00 => {
                if control.replace(stream).is_some() {
                    return Err("client opened a duplicate control stream".into());
                }
            }
            0x02 => {
                if encoder.replace(stream).is_some() {
                    return Err("client opened a duplicate QPACK encoder stream".into());
                }
            }
            0x03 => {
                if decoder.replace(stream).is_some() {
                    return Err("client opened a duplicate QPACK decoder stream".into());
                }
            }
            _ => grease.push(stream),
        }
    }
    Ok(ChromeClientStreams {
        _control: control.ok_or("client omitted its control stream")?,
        encoder: encoder.ok_or("client omitted its QPACK encoder stream")?,
        _decoder: decoder.ok_or("client omitted its QPACK decoder stream")?,
        _grease: grease,
    })
}

async fn read_stream_varint(stream: &mut quinn::RecvStream) -> TestResult<u64> {
    let mut first = [0];
    stream.read_exact(&mut first).await?;
    let width = 1_usize << (first[0] >> 6);
    let mut encoded = [0; 8];
    encoded[0] = first[0];
    stream.read_exact(&mut encoded[1..width]).await?;
    Ok(encoded[..width]
        .iter()
        .enumerate()
        .fold(0_u64, |value, (index, byte)| {
            let byte = if index == 0 { *byte & 0x3f } else { *byte };
            (value << 8) | u64::from(byte)
        }))
}

fn fixture_value(key: &str) -> TestResult<&'static str> {
    let prefix = format!("{key}=");
    CHROME_FIXTURE
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .ok_or_else(|| format!("fixture is missing {key}").into())
}

fn decode_hex(encoded: &str) -> TestResult<Vec<u8>> {
    if encoded.len() % 2 != 0 {
        return Err("fixture hex value has odd length".into());
    }
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digits = std::str::from_utf8(pair)?;
            u8::from_str_radix(digits, 16).map_err(Into::into)
        })
        .collect()
}

fn expected_http3_error<T>(
    result: Result<T, crate::http3::Http3Error>,
    message: &str,
) -> TestResult<crate::http3::Http3Error> {
    match result {
        Ok(_) => Err(message.to_owned().into()),
        Err(error) => Ok(error),
    }
}
