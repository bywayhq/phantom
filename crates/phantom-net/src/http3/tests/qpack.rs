use std::{error::Error, time::Duration};

use http::{HeaderMap, HeaderValue, Request, StatusCode};
use http_body_util::BodyExt;
use phantom_profile::{
    Http3QpackDecoderStream, Http3QpackEncoding, Http3Setting, Http3SettingOrder, Http3Settings,
};
use tokio::{sync::oneshot, time::timeout};

use super::{
    Http3ErrorKind, TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity, TestResult, client_config,
    join_server, server_endpoint, test_settings,
};

const CONTROL_STREAM: u8 = 0x00;
const QPACK_ENCODER_STREAM: u8 = 0x02;
const QPACK_DECODER_STREAM: u64 = 0x03;
const SETTINGS_FRAME: u8 = 0x04;
const HEADERS_FRAME: u8 = 0x01;
const PEER_SETTINGS: &[u8] = &[CONTROL_STREAM, SETTINGS_FRAME, 0x00];
const PENDING_WINDOW: Duration = Duration::from_millis(100);
const QPACK_CALLBACK: &str = "/.well-known/phantom/h3-qpack/0123456789abcdef0123456789abcdef";

#[tokio::test(flavor = "current_thread")]
async fn static_and_literal_status_encodings_decode_equivalently() -> TestResult<()> {
    for (initial_path, status_field) in [
        ("/.well-known/phantom/h3-qpack-static", &[0xff, 0x03][..]),
        (
            "/.well-known/phantom/h3-qpack-literal",
            &[0x5f, 0x33, 0x03, b'3', b'0', b'2'][..],
        ),
    ] {
        assert_qpack_layout(initial_path, status_field).await?;
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn blocked_response_waits_for_insertion_and_acknowledges_headers() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = client_config(&identity)?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (blocked_sent, blocked_received) = oneshot::channel();
    let (release_encoder, encoder_released) = oneshot::channel();
    let (client_done, done_received) = oneshot::channel();

    let server = tokio::spawn(async move {
        timeout(TEST_TIMEOUT, async move {
            let incoming = endpoint.accept().await.ok_or("test endpoint closed")?;
            let connection = incoming.await?;
            let mut control = connection.open_uni().await?;
            control.write_all(PEER_SETTINGS).await?;

            let mut critical = accept_client_critical_streams(&connection).await?;
            let (mut response, mut request) = connection.accept_bi().await?;
            let _ = request.read_to_end(64 * 1024).await?;
            let (instructions, field_section) = dynamic_response()?;

            write_headers(&mut response, &field_section).await?;
            let _ = blocked_sent.send(());
            encoder_released
                .await
                .map_err(|_| "test did not release the QPACK encoder")?;

            let mut encoder = connection.open_uni().await?;
            encoder.write_all(&[QPACK_ENCODER_STREAM]).await?;
            encoder.write_all(&instructions).await?;

            let mut feedback = [0; 2];
            critical.decoder.read_exact(&mut feedback).await?;
            assert_eq!(
                feedback,
                [0x01, 0x80],
                "expected insert-count increment and header acknowledgement for stream zero"
            );

            response.finish()?;
            done_received
                .await
                .map_err(|_| "client did not finish response validation")?;
            connection.close(quinn::VarInt::from_u32(0), b"");
            drop((control, encoder, critical));
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        })
        .await
        .map_err(|_| "dynamic QPACK server timed out")?
    });

    let request = request(address, "/blocked-response")?;
    let mut client = tokio::spawn(async move {
        super::send_request_head(
            address,
            TEST_SERVER_NAME,
            client,
            &dynamic_settings(),
            request,
        )
        .await
    });

    timeout(TEST_TIMEOUT, blocked_received)
        .await
        .map_err(|_| "server did not send the blocked field section")??;
    if timeout(PENDING_WINDOW, &mut client).await.is_ok() {
        return Err("response completed before its QPACK insertion arrived".into());
    }

    let _ = release_encoder.send(());
    let response = timeout(TEST_TIMEOUT, &mut client)
        .await
        .map_err(|_| "response remained blocked after its QPACK insertion")???;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("x-phantom-dynamic"),
        Some(&HeaderValue::from_static("released"))
    );
    drop(response);

    let _ = client_done.send(());
    join_server(server).await
}

#[tokio::test(flavor = "current_thread")]
async fn closing_peer_qpack_encoder_closes_connection_and_fails_request() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = client_config(&identity)?;
    let (address, endpoint) = server_endpoint(&identity)?;

    let server = tokio::spawn(async move {
        timeout(TEST_TIMEOUT, async move {
            let incoming = endpoint.accept().await.ok_or("test endpoint closed")?;
            let connection = incoming.await?;
            let mut control = connection.open_uni().await?;
            control.write_all(PEER_SETTINGS).await?;

            let mut encoder = connection.open_uni().await?;
            encoder.write_all(&[QPACK_ENCODER_STREAM]).await?;
            encoder.finish()?;

            match connection.closed().await {
                quinn::ConnectionError::ApplicationClosed(close)
                    if close.error_code.into_inner()
                        == h3::error::Code::H3_CLOSED_CRITICAL_STREAM.value() =>
                {
                    Ok::<(), Box<dyn Error + Send + Sync>>(())
                }
                error => Err(format!(
                    "client closed with {error:?}, expected H3_CLOSED_CRITICAL_STREAM"
                )
                .into()),
            }
        })
        .await
        .map_err(|_| "critical-stream server timed out")?
    });

    let result = timeout(
        TEST_TIMEOUT,
        super::send_request_head(
            address,
            TEST_SERVER_NAME,
            client,
            &dynamic_settings(),
            request(address, "/closed-qpack-encoder")?,
        ),
    )
    .await
    .map_err(|_| "client did not reject the closed QPACK encoder stream")?;
    let error = match result {
        Ok(_) => return Err("closed peer QPACK encoder unexpectedly produced a response".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), Http3ErrorKind::Protocol);

    join_server(server).await
}

async fn assert_qpack_layout(
    initial_path: &'static str,
    status_field: &'static [u8],
) -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = client_config(&identity)?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (client_done, done_received) = oneshot::channel();

    let server = tokio::spawn(async move {
        timeout(TEST_TIMEOUT, async move {
            let incoming = endpoint.accept().await.ok_or("test endpoint closed")?;
            let connection = incoming.await?;
            let mut control = connection.open_uni().await?;
            control.write_all(PEER_SETTINGS).await?;

            let (mut initial_response, mut initial_request) = connection.accept_bi().await?;
            let _ = initial_request.read_to_end(64 * 1024).await?;
            write_headers(&mut initial_response, &qpack_redirect(status_field)?).await?;
            initial_response.finish()?;

            let (mut callback_response, mut callback_request) = connection.accept_bi().await?;
            let _ = callback_request.read_to_end(64 * 1024).await?;
            write_headers(&mut callback_response, &[0x00, 0x00, 0xd9]).await?;
            callback_response.finish()?;

            done_received
                .await
                .map_err(|_| "client did not finish QPACK equivalence validation")?;
            connection.close(quinn::VarInt::from_u32(0), b"");
            drop(control);
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        })
        .await
        .map_err(|_| "QPACK equivalence server timed out")?
    });

    let connection = timeout(
        TEST_TIMEOUT,
        super::super::connect_direct(address, TEST_SERVER_NAME, client, &test_settings()),
    )
    .await
    .map_err(|_| "HTTP/3 connection timed out")??;
    let initial = timeout(
        TEST_TIMEOUT,
        connection.send_request(request(address, initial_path)?, None),
    )
    .await
    .map_err(|_| "QPACK response timed out")??;
    assert_eq!(initial.status(), StatusCode::FOUND);
    assert_eq!(
        initial.headers().get("location"),
        Some(&HeaderValue::from_static(QPACK_CALLBACK))
    );
    assert!(initial.into_body().collect().await?.to_bytes().is_empty());

    let callback = timeout(
        TEST_TIMEOUT,
        connection.send_request(request(address, QPACK_CALLBACK)?, None),
    )
    .await
    .map_err(|_| "request after QPACK response timed out")??;
    assert_eq!(callback.status(), StatusCode::OK);
    assert!(callback.into_body().collect().await?.to_bytes().is_empty());

    let _ = client_done.send(());
    join_server(server).await
}

fn dynamic_settings() -> Http3Settings {
    Http3Settings {
        initial_settings: vec![
            Http3Setting::QpackMaxTableCapacity(256),
            Http3Setting::MaxFieldSectionSize(65_536),
            Http3Setting::QpackBlockedStreams(1),
        ],
        setting_order: Http3SettingOrder::Fixed,
        qpack_encoding: Http3QpackEncoding::Stateless,
        qpack_decoder_stream: Http3QpackDecoderStream::Eager,
    }
}

fn dynamic_response() -> TestResult<(Vec<u8>, Vec<u8>)> {
    let mut fields = HeaderMap::new();
    fields.insert("x-phantom-dynamic", HeaderValue::from_static("released"));
    let header =
        h3::proto::headers::Header::response(StatusCode::OK, fields, http::Extensions::new())?;
    let mut encoder = h3::qpack::Encoder::default();
    let mut instructions = Vec::new();
    encoder.set_max_table_capacity(256, &mut instructions)?;
    encoder.set_max_blocked_streams(1)?;
    let mut field_section = Vec::new();
    let required_insert_count = encoder.encode(0, &mut field_section, &mut instructions, header)?;
    if required_insert_count == 0 {
        return Err("test response did not reference the dynamic table".into());
    }
    Ok((instructions, field_section))
}

fn qpack_redirect(status_field: &[u8]) -> TestResult<Vec<u8>> {
    let callback_len = u8::try_from(QPACK_CALLBACK.len())?;
    let mut field_section = Vec::with_capacity(5 + status_field.len() + callback_len as usize);
    field_section.extend_from_slice(&[0x00, 0x00]);
    field_section.extend_from_slice(status_field);
    field_section.extend_from_slice(&[0x5c, callback_len]);
    field_section.extend_from_slice(QPACK_CALLBACK.as_bytes());
    Ok(field_section)
}

async fn write_headers(stream: &mut quinn::SendStream, field_section: &[u8]) -> TestResult<()> {
    let length = u16::try_from(field_section.len())?;
    stream.write_all(&[HEADERS_FRAME]).await?;
    if length < 64 {
        stream.write_all(&[u8::try_from(length)?]).await?;
    } else if length < 16_384 {
        let [high, low] = length.to_be_bytes();
        stream.write_all(&[0x40 | high, low]).await?;
    } else {
        return Err("test field section exceeds the two-byte QUIC varint bound".into());
    }
    stream.write_all(field_section).await?;
    Ok(())
}

struct ClientCriticalStreams {
    decoder: quinn::RecvStream,
    _other: Vec<quinn::RecvStream>,
}

async fn accept_client_critical_streams(
    connection: &quinn::Connection,
) -> TestResult<ClientCriticalStreams> {
    let mut decoder = None;
    let mut other = Vec::with_capacity(2);
    for _ in 0..3 {
        let mut stream = connection.accept_uni().await?;
        let stream_type = read_varint(&mut stream).await?;
        if stream_type == QPACK_DECODER_STREAM {
            if decoder.replace(stream).is_some() {
                return Err("client opened duplicate QPACK decoder streams".into());
            }
        } else {
            other.push(stream);
        }
    }
    Ok(ClientCriticalStreams {
        decoder: decoder.ok_or("client omitted its QPACK decoder stream")?,
        _other: other,
    })
}

async fn read_varint(stream: &mut quinn::RecvStream) -> TestResult<u64> {
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

fn request(address: std::net::SocketAddr, path: &str) -> TestResult<Request<()>> {
    Ok(Request::get(format!(
        "https://{TEST_SERVER_NAME}:{}{path}",
        address.port()
    ))
    .body(())?)
}
