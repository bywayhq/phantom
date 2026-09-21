use bytes::Bytes;
use http::Request;
use phantom_profile::{
    Http3QpackDecoderStream, Http3QpackEncoding, Http3Setting, Http3SettingOrder, Http3Settings,
    chromium,
};
use tokio::time::timeout;

use super::{
    TestResult, client_config, client_config_with_profile, profiled_client_config, server_endpoint,
};
use crate::tls::test_support::{TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity};

const CHROME_H3_FIXTURE: &str = include_str!(
    "../../../../../fixtures/http3/chrome/152.0.7977.83/macos-15.5/client-startup.txt"
);
const STABLE_SETTINGS_COUNT: usize = 3;

#[tokio::test(flavor = "current_thread")]
async fn rejects_invalid_profile_before_connecting() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let request = Request::get("https://server.phantom.test/").body(())?;
    let settings = Http3Settings {
        initial_settings: vec![Http3Setting::QpackMaxTableCapacity(1 << 30)],
        setting_order: Http3SettingOrder::Fixed,
        qpack_encoding: Http3QpackEncoding::Stateless,
        qpack_decoder_stream: Http3QpackDecoderStream::Eager,
    };
    let result = super::send_request_head(
        "127.0.0.1:9".parse()?,
        TEST_SERVER_NAME,
        client_config(&identity)?,
        &settings,
        request,
    )
    .await;
    let error = match result {
        Ok(_) => return Err("invalid profile unexpectedly reached the network".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), super::super::Http3ErrorKind::Configuration);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn rejects_invalid_pseudo_layout_before_connecting() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let settings = chromium::v152_http3();
    let mut request_settings = chromium::v152_http3_request();
    request_settings.pseudo_header_order[3] = phantom_profile::Http3PseudoHeader::Method;
    let result = super::super::send_get(
        "127.0.0.1:9".parse()?,
        TEST_SERVER_NAME,
        client_config(&identity)?,
        &settings,
        &request_settings,
        TEST_SERVER_NAME,
        super::super::OriginForm::parse("/")?,
        Vec::new(),
    )
    .await;
    let error = match result {
        Ok(_) => return Err("invalid pseudo layout unexpectedly reached the network".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), super::super::Http3ErrorKind::Configuration);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn rejects_http_datagrams_when_quic_datagrams_are_disabled() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let mut quic = chromium::v152_quic();
    quic.max_datagram_frame_size = None;
    quic.wire_parameters.retain(|parameter| {
        !matches!(
            &parameter.kind,
            phantom_profile::quic::QuicTransportParameterKind::MaxDatagramFrameSize { .. }
        )
    });
    let request = Request::get("https://server.phantom.test/").body(())?;
    let settings = chromium::v152_http3();
    let result = super::send_request_head(
        "127.0.0.1:9".parse()?,
        TEST_SERVER_NAME,
        client_config_with_profile(&identity, quic)?,
        &settings,
        request,
    )
    .await;
    let error = match result {
        Ok(_) => {
            return Err("inconsistent datagram profiles unexpectedly reached the network".into());
        }
        Err(error) => error,
    };
    assert_eq!(error.kind(), super::super::Http3ErrorKind::Configuration);
    Ok(())
}

#[test]
fn chrome_profile_materializes_randomized_grease_from_entropy() -> TestResult<()> {
    let profile = chromium::v152_http3();
    for (identifier_seed, value) in [
        (0, 0),
        (1, 63),
        (0x1234_5678, 0x9abc_def0),
        (u32::MAX, u32::MAX),
    ] {
        let entries = super::super::settings::materialize_for_test(
            &profile,
            grease_entropy(identifier_seed, value),
        )?;
        let expected_grease = (31 * u64::from(identifier_seed) + 33, u64::from(value));

        assert_eq!(
            entries
                .iter()
                .filter(|(identifier, _)| !is_reserved_setting(*identifier))
                .copied()
                .collect::<Vec<_>>(),
            [(0x01, 65_536), (0x06, 262_144), (0x07, 100), (0x33, 1)]
        );
        assert_eq!(
            entries
                .iter()
                .filter(|(identifier, _)| is_reserved_setting(*identifier))
                .copied()
                .collect::<Vec<_>>(),
            [expected_grease]
        );
        assert!(entries.windows(2).all(|pair| pair[0].0 < pair[1].0));
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn chrome_profile_emits_capture_backed_control_stream_shape() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = profiled_client_config(&identity)?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let settings = chromium::v152_http3();
    let request = Request::get(format!(
        "https://{TEST_SERVER_NAME}:{}/control-stream",
        address.port()
    ))
    .body(())?;

    let client_task = tokio::spawn(async move {
        let result =
            super::send_request_head(address, TEST_SERVER_NAME, client, &settings, request).await;
        drop(result);
    });
    let incoming = timeout(TEST_TIMEOUT, endpoint.accept())
        .await
        .map_err(|_| "client did not connect")?
        .ok_or("test endpoint closed")?;
    let connection = timeout(TEST_TIMEOUT, incoming)
        .await
        .map_err(|_| "QUIC handshake timed out")??;
    let prefix = timeout(TEST_TIMEOUT, capture_control_stream(&connection))
        .await
        .map_err(|_| "control stream timed out")??;

    let fixture_prefix = fixture_hex("control_stream_prefix_hex")?;
    let (fixture_payload_offset, fixture_payload) = settings_payload(&fixture_prefix)?;
    let (observed_payload_offset, observed_payload) = settings_payload(&prefix)?;
    let fixture_stable_prefix = encoded_settings_prefix(fixture_payload, STABLE_SETTINGS_COUNT)?;
    let observed_stable_prefix = observed_payload
        .get(..fixture_stable_prefix.len())
        .ok_or("control stream omitted the stable SETTINGS prefix")?;

    assert_eq!(&prefix[..2], &fixture_prefix[..2]);
    assert_eq!(observed_payload_offset, fixture_payload_offset);
    assert_eq!(observed_stable_prefix, fixture_stable_prefix);

    let entries = parse_control_settings(&prefix)?;
    assert_eq!(
        entries
            .iter()
            .filter(|(identifier, _)| !is_reserved_setting(*identifier))
            .copied()
            .collect::<Vec<_>>(),
        [(0x01, 65_536), (0x06, 262_144), (0x07, 100), (0x33, 1)]
    );
    assert_eq!(
        entries
            .iter()
            .filter(|(identifier, _)| is_reserved_setting(*identifier))
            .count(),
        1
    );
    assert!(entries.windows(2).all(|pair| pair[0].0 < pair[1].0));
    let (_, grease_value) = entries
        .iter()
        .find(|(identifier, _)| is_reserved_setting(*identifier))
        .ok_or("control stream omitted GREASE")?;
    assert!(*grease_value <= u64::from(u32::MAX));

    connection.close(quinn::VarInt::from_u32(0), b"");
    timeout(TEST_TIMEOUT, client_task)
        .await
        .map_err(|_| "HTTP/3 client did not stop")??;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn chrome_profile_emits_seeded_grease_varint_widths() -> TestResult<()> {
    let eight_byte_seed = u32::try_from((1_u64 << 30).div_ceil(31))?;
    let cases = [
        (0, 0, 1, 1),
        (1, 64, 2, 2),
        (528, 16_384, 4, 4),
        (eight_byte_seed, 1 << 30, 8, 8),
    ];

    for (identifier_seed, value, expected_identifier_width, expected_value_width) in cases {
        let prefix = capture_seeded_control_stream(grease_entropy(identifier_seed, value)).await?;
        let entries = parse_encoded_settings(&prefix)?;
        let grease = entries
            .iter()
            .filter(|entry| is_reserved_setting(entry.0))
            .collect::<Vec<_>>();

        assert_eq!(grease.len(), 1);
        assert_eq!(grease[0].0, 31 * u64::from(identifier_seed) + 33);
        assert_eq!(grease[0].1, expected_identifier_width);
        assert_eq!(grease[0].2, u64::from(value));
        assert_eq!(grease[0].3, expected_value_width);
    }
    Ok(())
}

async fn capture_seeded_control_stream(entropy: [u8; 8]) -> TestResult<Vec<u8>> {
    let identity = TestIdentity::generate()?;
    let crypto = profiled_client_config(&identity)?;
    let (address, server_endpoint) = server_endpoint(&identity)?;
    let client_endpoint = super::super::endpoint(
        address,
        std::sync::Arc::clone(&crypto),
        super::super::ConnectionDiagnostics::default(),
    )?;
    let connecting = client_endpoint.connect(address, TEST_SERVER_NAME)?;
    let connecting = async {
        Ok::<quinn::Connection, Box<dyn std::error::Error + Send + Sync>>(connecting.await?)
    };
    let accepting = async {
        let connection = server_endpoint
            .accept()
            .await
            .ok_or("test endpoint closed")?
            .await?;
        Ok::<quinn::Connection, Box<dyn std::error::Error + Send + Sync>>(connection)
    };
    let (client_connection, server_connection) = timeout(TEST_TIMEOUT, async {
        tokio::try_join!(connecting, accepting)
    })
    .await
    .map_err(|_| "QUIC handshake timed out")??;
    super::super::require_h3(&client_connection)?;

    let settings = chromium::v152_http3();
    let mut builder = super::super::settings::builder_for_test(&settings, &crypto, entropy)?;
    let (mut driver, sender) = builder
        .build::<_, _, Bytes>(h3_quinn::Connection::new(client_connection.clone()))
        .await?;
    let driver_task =
        tokio::spawn(
            async move { std::future::poll_fn(|context| driver.poll_close(context)).await },
        );
    let prefix = timeout(TEST_TIMEOUT, capture_control_stream(&server_connection))
        .await
        .map_err(|_| "control stream timed out")??;

    client_connection.close(quinn::VarInt::from_u32(0), b"");
    server_connection.close(quinn::VarInt::from_u32(0), b"");
    drop(sender);
    drop(client_endpoint);
    let _ = timeout(TEST_TIMEOUT, driver_task)
        .await
        .map_err(|_| "HTTP/3 driver did not stop")??;
    Ok(prefix)
}

async fn capture_control_stream(connection: &quinn::Connection) -> TestResult<Vec<u8>> {
    loop {
        let mut stream = connection.accept_uni().await?;
        let mut bytes = Vec::new();
        loop {
            let chunk = stream
                .read_chunk(64, true)
                .await?
                .ok_or("unidirectional stream ended before SETTINGS")?;
            bytes.extend_from_slice(&chunk.bytes);
            let Some((stream_type, _)) = decode_varint(&bytes, 0) else {
                continue;
            };
            if stream_type != 0 {
                break;
            }
            if let Some(length) = control_prefix_length(&bytes)? {
                bytes.truncate(length);
                return Ok(bytes);
            }
        }
    }
}

fn control_prefix_length(bytes: &[u8]) -> TestResult<Option<usize>> {
    let Some((_, stream_type_len)) = decode_varint(bytes, 0) else {
        return Ok(None);
    };
    let Some((frame_type, frame_type_len)) = decode_varint(bytes, stream_type_len) else {
        return Ok(None);
    };
    if frame_type != 0x04 {
        return Err("control stream does not start with SETTINGS".into());
    }
    let length_offset = stream_type_len + frame_type_len;
    let Some((payload_len, payload_len_len)) = decode_varint(bytes, length_offset) else {
        return Ok(None);
    };
    let total = length_offset
        .checked_add(payload_len_len)
        .and_then(|value| value.checked_add(usize::try_from(payload_len).ok()?))
        .ok_or("SETTINGS frame length overflowed")?;
    Ok((bytes.len() >= total).then_some(total))
}

fn parse_control_settings(bytes: &[u8]) -> TestResult<Vec<(u64, u64)>> {
    Ok(parse_encoded_settings(bytes)?
        .into_iter()
        .map(|(identifier, _, value, _)| (identifier, value))
        .collect())
}

fn parse_encoded_settings(bytes: &[u8]) -> TestResult<Vec<(u64, usize, u64, usize)>> {
    let (_, payload) = settings_payload(bytes)?;
    let mut offset = 0;
    let mut entries = Vec::new();
    while offset < payload.len() {
        let (identifier, id_len) = decode_varint(payload, offset).ok_or("truncated setting ID")?;
        offset += id_len;
        let (value, value_len) = decode_varint(payload, offset).ok_or("truncated setting value")?;
        offset += value_len;
        entries.push((identifier, id_len, value, value_len));
    }
    if offset != payload.len() {
        return Err("SETTINGS payload length mismatch".into());
    }
    Ok(entries)
}

fn settings_payload(bytes: &[u8]) -> TestResult<(usize, &[u8])> {
    let (stream_type, stream_type_len) =
        decode_varint(bytes, 0).ok_or("missing control stream type")?;
    if stream_type != 0 {
        return Err("unidirectional stream is not a control stream".into());
    }
    let (frame_type, frame_type_len) =
        decode_varint(bytes, stream_type_len).ok_or("missing frame type")?;
    if frame_type != 0x04 {
        return Err("control stream does not start with SETTINGS".into());
    }
    let length_offset = stream_type_len + frame_type_len;
    let (payload_len, payload_len_len) =
        decode_varint(bytes, length_offset).ok_or("missing SETTINGS length")?;
    let payload_offset = length_offset + payload_len_len;
    let payload_len = usize::try_from(payload_len)?;
    let payload_end = payload_offset
        .checked_add(payload_len)
        .ok_or("SETTINGS frame length overflowed")?;
    let payload = bytes
        .get(payload_offset..payload_end)
        .ok_or("truncated SETTINGS payload")?;
    Ok((payload_offset, payload))
}

fn encoded_settings_prefix(payload: &[u8], count: usize) -> TestResult<&[u8]> {
    let mut offset = 0;
    for _ in 0..count {
        let (_, identifier_len) =
            decode_varint(payload, offset).ok_or("fixture contains a truncated setting ID")?;
        offset += identifier_len;
        let (_, value_len) =
            decode_varint(payload, offset).ok_or("fixture contains a truncated setting value")?;
        offset += value_len;
    }
    Ok(&payload[..offset])
}

fn decode_varint(bytes: &[u8], offset: usize) -> Option<(u64, usize)> {
    let first = *bytes.get(offset)?;
    let width = 1_usize << (first >> 6);
    let encoded = bytes.get(offset..offset.checked_add(width)?)?;
    let mut value = u64::from(first & 0x3f);
    for byte in &encoded[1..] {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, width))
}

fn is_reserved_setting(identifier: u64) -> bool {
    identifier >= 33 && (identifier - 33) % 31 == 0
}

fn grease_entropy(identifier_seed: u32, value: u32) -> [u8; 8] {
    let mut entropy = [0; 8];
    entropy[..4].copy_from_slice(&identifier_seed.to_ne_bytes());
    entropy[4..].copy_from_slice(&value.to_ne_bytes());
    entropy
}

fn fixture_hex(key: &str) -> TestResult<Vec<u8>> {
    let prefix = format!("{key}=");
    let encoded = CHROME_H3_FIXTURE
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .ok_or_else(|| format!("fixture is missing {key}"))?;
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
