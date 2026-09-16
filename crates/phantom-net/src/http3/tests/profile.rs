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
    let result = super::super::send_request(
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
    let settings = chromium::v152_macos_http3();
    let mut request_settings = chromium::v152_macos_http3_request();
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
    let mut quic = chromium::v152_macos_quic();
    quic.max_datagram_frame_size = None;
    quic.wire_parameters.retain(|parameter| {
        !matches!(
            &parameter.kind,
            phantom_profile::quic::QuicTransportParameterKind::MaxDatagramFrameSize { .. }
        )
    });
    let request = Request::get("https://server.phantom.test/").body(())?;
    let settings = chromium::v152_macos_http3();
    let result = super::super::send_request(
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
fn chrome_profile_materializes_retained_settings() -> TestResult<()> {
    let profile = chromium::v152_macos_http3();
    let captured_grease = (47_398_610_487, 289_824_385);

    assert_eq!(
        super::super::settings::materialize_for_test(&profile, captured_grease)?,
        [
            (0x01, 65_536),
            (0x06, 262_144),
            (0x07, 100),
            (0x33, 1),
            captured_grease,
        ]
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn chrome_profile_emits_capture_backed_control_stream_shape() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = profiled_client_config(&identity)?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let settings = chromium::v152_macos_http3();
    let request = Request::get(format!(
        "https://{TEST_SERVER_NAME}:{}/control-stream",
        address.port()
    ))
    .body(())?;

    let client_task = tokio::spawn(async move {
        let result =
            super::super::send_request(address, TEST_SERVER_NAME, client, &settings, request).await;
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
    let (_, stream_type_len) = decode_varint(bytes, 0).ok_or("missing control stream type")?;
    let (_, frame_type_len) = decode_varint(bytes, stream_type_len).ok_or("missing frame type")?;
    let length_offset = stream_type_len + frame_type_len;
    let (payload_len, payload_len_len) =
        decode_varint(bytes, length_offset).ok_or("missing SETTINGS length")?;
    let mut offset = length_offset + payload_len_len;
    let end = offset + usize::try_from(payload_len)?;
    let mut entries = Vec::new();
    while offset < end {
        let (identifier, id_len) = decode_varint(bytes, offset).ok_or("truncated setting ID")?;
        offset += id_len;
        let (value, value_len) = decode_varint(bytes, offset).ok_or("truncated setting value")?;
        offset += value_len;
        entries.push((identifier, value));
    }
    if offset != end {
        return Err("SETTINGS payload length mismatch".into());
    }
    Ok(entries)
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
