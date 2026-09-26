use std::future::poll_fn;

use http::Response;
use http_body_util::BodyExt;
use phantom_profile::{
    Http2HpackSettings, Http2Priority, Http2PseudoHeader, Http2Setting, Http2Settings,
    Http2StreamSettings, chromium::v154_http2,
};
use phantom_testkit::http2::{
    CLIENT_CONNECTION_PREFACE, CaptureCompletion, CaptureLimits, capture_client_frames,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex},
    time::Instant,
};
use tracing::instrument::WithSubscriber;

use super::{
    PEER_TEST_TIMEOUT, TestResult, bounded_peer_test, headers, prime_request_trace_callsites,
    target,
};
use crate::http2::{Http2Error, Http2ProtocolErrorKind, OriginForm, RequestHeader, send_get};
use crate::tracing_test::OutcomeSubscriber;

#[test]
fn protocol_errors_expose_stable_metadata_and_retain_backend_source() {
    let error = Http2Error::protocol(::http2::Error::from(::http2::Reason::PROTOCOL_ERROR));
    let Http2Error::Protocol(protocol) = &error else {
        panic!("backend protocol error used the wrong public variant");
    };
    assert_eq!(protocol.kind(), Http2ProtocolErrorKind::Protocol);
    assert_eq!(protocol.reason_code(), Some(1));
    assert!(std::error::Error::source(protocol).is_some());
    assert!(std::error::Error::source(&error).is_some());
}

#[tokio::test]
async fn protocol_failure_has_specific_response_head_outcome() -> TestResult<()> {
    bounded_peer_test(async {
        prime_request_trace_callsites().await?;
        let subscriber = OutcomeSubscriber::default();
        let (client, server) = duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            let mut connection = ::http2::server::handshake(server).await?;
            let (_request, _respond) = connection
                .accept()
                .await
                .ok_or("connection closed before request")??;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        let result = send_get(client, &v154_http2(), "example.test", target()?, Vec::new())
            .with_subscriber(subscriber.dispatch())
            .await;
        assert!(matches!(result, Err(Http2Error::Protocol(_))));
        assert_eq!(
            subscriber.outcomes_for("http2.response_head"),
            ["protocol_error"]
        );
        server_task.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn peer_reset_preserves_stream_error_classification() -> TestResult<()> {
    bounded_peer_test(async {
        let (client, server) = duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            let mut connection = ::http2::server::handshake(server).await?;
            let (request, mut respond) = connection
                .accept()
                .await
                .ok_or("connection closed before request")??;
            respond.send_reset(::http2::Reason::REFUSED_STREAM);
            drop(request);
            drop(respond);
            poll_fn(|context| connection.poll_closed(context)).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        let result = send_get(client, &v154_http2(), "example.test", target()?, Vec::new()).await;
        let error = match result {
            Ok(_) => return Err("peer RST_STREAM was accepted as a response".into()),
            Err(error) => error,
        };
        let Http2Error::Protocol(protocol) = error else {
            return Err("peer RST_STREAM used a non-protocol error variant".into());
        };
        assert_eq!(protocol.kind(), Http2ProtocolErrorKind::StreamReset);
        assert_eq!(
            protocol.reason_code(),
            Some(u32::from(::http2::Reason::REFUSED_STREAM))
        );
        server_task.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn peer_goaway_preserves_connection_error_classification() -> TestResult<()> {
    bounded_peer_test(async {
        let (client, mut server) = duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            let mut preface = [0_u8; CLIENT_CONNECTION_PREFACE.len()];
            server.read_exact(&mut preface).await?;
            if &preface != CLIENT_CONNECTION_PREFACE {
                return Err("client sent an invalid connection preface".into());
            }
            server.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await?;
            loop {
                let frame = read_raw_frame(&mut server).await?;
                if frame.frame_type == 1 && frame.stream_id == 1 {
                    break;
                }
            }
            server
                .write_all(&[
                    0, 0, 8, 7, 0, 0, 0, 0, 0, // GOAWAY frame header
                    0, 0, 0, 0, // last processed stream ID
                    0, 0, 0, 11, // ENHANCE_YOUR_CALM
                ])
                .await?;
            let mut remaining = Vec::new();
            server.read_to_end(&mut remaining).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        let result = send_get(client, &v154_http2(), "example.test", target()?, Vec::new()).await;
        let error = match result {
            Ok(_) => return Err("peer GOAWAY was accepted as a response".into()),
            Err(error) => error,
        };
        let Http2Error::Protocol(protocol) = error else {
            return Err("peer GOAWAY used a non-protocol error variant".into());
        };
        assert_eq!(
            protocol.kind(),
            Http2ProtocolErrorKind::ConnectionError,
            "{protocol:?}"
        );
        assert_eq!(
            protocol.reason_code(),
            Some(u32::from(::http2::Reason::ENHANCE_YOUR_CALM))
        );
        server_task.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn emits_every_supported_setting_in_declared_order() -> TestResult<()> {
    let settings = Http2Settings {
        initial_settings: vec![
            Http2Setting::MaxConcurrentStreams(17),
            Http2Setting::NoRfc7540Priorities(true),
            Http2Setting::MaxFrameSize(32_768),
            Http2Setting::EnableConnectProtocol(false),
            Http2Setting::InitialWindowSize(70_000),
            Http2Setting::HeaderTableSize(123),
            Http2Setting::MaxHeaderListSize(456),
            Http2Setting::EnablePush(true),
        ],
        initial_connection_window_size: 80_000,
        pseudo_header_order: vec![
            Http2PseudoHeader::Path,
            Http2PseudoHeader::Scheme,
            Http2PseudoHeader::Authority,
            Http2PseudoHeader::Method,
        ],
        extended_connect_pseudo_header_order: None,
        extended_connect_priority: None,
        headers_priority: Some(Http2Priority {
            dependency_stream_id: 31,
            weight: 1,
            exclusive: false,
        }),
        hpack: Http2HpackSettings::default(),
        streams: Http2StreamSettings::default(),
    };
    bounded_peer_test(async {
        let (client, mut server) = duplex(64 * 1024);
        let transaction = tokio::spawn(async move {
            send_get(
                client,
                &settings,
                "example.test",
                OriginForm::parse("/").map_err(|error| error.to_string())?,
                vec![],
            )
            .await
            .map_err(|error| error.to_string())
        });
        let capture = capture_client_frames(
            &mut server,
            Instant::now() + PEER_TEST_TIMEOUT,
            CaptureLimits::new(1024, 4096, 4),
            CaptureCompletion::InitialSettings,
        )
        .await?;
        let initial = capture
            .frames()
            .iter()
            .find_map(|frame| frame.settings().transpose())
            .transpose()?
            .ok_or("missing initial SETTINGS")?;
        assert_eq!(
            initial
                .entries()
                .iter()
                .map(|setting| (setting.identifier(), setting.value()))
                .collect::<Vec<_>>(),
            [
                (3, 17),
                (9, 1),
                (5, 32_768),
                (8, 0),
                (4, 70_000),
                (1, 123),
                (6, 456),
                (2, 1),
            ]
        );
        drop(server);
        assert!(transaction.await?.is_err());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn emits_chrome_preface_settings_and_connection_window() -> TestResult<()> {
    bounded_peer_test(async {
        let settings = v154_http2();
        let request_target = target()?;
        let (client, mut server) = duplex(64 * 1024);
        let transaction = tokio::spawn(async move {
            send_get(client, &settings, "example.test", request_target, vec![]).await
        });

        let capture = capture_client_frames(
            &mut server,
            Instant::now() + PEER_TEST_TIMEOUT,
            CaptureLimits::new(1024, 4096, 4),
            CaptureCompletion::InitialSettingsAndConnectionWindowUpdate,
        )
        .await?;
        assert_eq!(capture.preface_bytes(), CLIENT_CONNECTION_PREFACE);

        let mut observed_settings = None;
        let mut observed_increment = None;
        for frame in capture.frames() {
            if let Some(settings) = frame.settings()? {
                observed_settings = Some(settings.entries().to_vec());
            }
            if let Some(update) = frame.window_update()? {
                assert_eq!(frame.header().stream_id(), 0);
                observed_increment = Some(update.increment());
            }
        }
        let observed_settings = observed_settings.ok_or("missing initial SETTINGS")?;
        assert_eq!(
            observed_settings
                .iter()
                .map(|setting| (setting.identifier(), setting.value()))
                .collect::<Vec<_>>(),
            [(1, 65_536), (2, 0), (4, 6_291_456), (6, 262_144)]
        );
        assert_eq!(observed_increment, Some(15_663_105));

        drop(server);
        assert!(transaction.await?.is_err());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn headers_carry_chrome_priority_and_pseudo_order() -> TestResult<()> {
    bounded_peer_test(async {
        let settings = v154_http2();
        let request_target = OriginForm::parse("/")?;
        let (client, mut server) = duplex(64 * 1024);
        let transaction = tokio::spawn(async move {
            send_get(client, &settings, "example.test", request_target, headers()).await
        });

        let mut preface = [0_u8; 24];
        server.read_exact(&mut preface).await?;
        assert_eq!(&preface, CLIENT_CONNECTION_PREFACE);
        let headers = loop {
            let frame = read_raw_frame(&mut server).await?;
            if frame.frame_type == 1 {
                break frame;
            }
        };
        assert_eq!(headers.stream_id, 1);
        assert_eq!(headers.flags, 0x25);
        assert_eq!(&headers.payload[..4], &0x8000_0000_u32.to_be_bytes());
        assert_eq!(headers.payload[4], 255);
        assert_eq!(
            &headers.payload[5..],
            &[
                0x82, // :method GET
                0x41, 0x89, 0x2f, 0x91, 0xd3, 0x5d, 0x05, 0x5d, 0x25, 0x42,
                0x7f, // :authority
                0x87, // :scheme https
                0x84, // :path /
                // Chrome Huffman-codes a literal only when that shortens it, so
                // `*/*` and the name `te`, which both code to their own length,
                // are sent raw. The retained capture shows the same
                // representation for an ordinary GET:
                // fixtures/websocket/chrome/154.0.8037.58/windows-11-26200/
                // accept.txt:330 records `accept: */*` as
                // `repr:incremental,index:19,value_huffman:false`.
                0x53, 0x03, 0x2a, 0x2f, 0x2a, // accept: */*
                0x40, 0x86, 0xf2, 0xb5, 0x85, 0xac, 0xa3, 0x4f, 0x84, 0x1d, 0x15, 0xce,
                0x3f, // x-repeat: alpha
                0x40, 0x86, 0xf2, 0xb5, 0x26, 0x92, 0x4a, 0x0b, 0x85, 0x8c, 0xa9, 0xf0, 0x52,
                0xd5, // x-middle: between
                0x7f, 0x00, 0x83, 0x8c, 0xa9, 0x1f, // x-repeat: beta
                0x40, 0x02, 0x74, 0x65, 0x86, 0x4d, 0x83, 0x35, 0x05, 0xb1,
                0x1f, // te: trailers
            ]
        );

        drop(server);
        assert!(transaction.await?.is_err());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn content_length_zero_is_emitted_in_declared_wire_order() -> TestResult<()> {
    bounded_peer_test(async {
        let settings = v154_http2();
        let request_target = OriginForm::parse("/")?;
        let (client, mut server) = duplex(64 * 1024);
        let transaction = tokio::spawn(async move {
            send_get(
                client,
                &settings,
                "example.test",
                request_target,
                vec![
                    RequestHeader::new("x-before", "a"),
                    RequestHeader::new("content-length", "0"),
                    RequestHeader::new("x-after", "b"),
                ],
            )
            .await
        });

        let mut preface = [0_u8; 24];
        server.read_exact(&mut preface).await?;
        assert_eq!(&preface, CLIENT_CONNECTION_PREFACE);
        let headers = loop {
            let frame = read_raw_frame(&mut server).await?;
            if frame.frame_type == 1 {
                break frame;
            }
        };
        assert_eq!(headers.stream_id, 1);
        assert_eq!(headers.flags, 0x25);
        assert_eq!(&headers.payload[..4], &0x8000_0000_u32.to_be_bytes());
        assert_eq!(headers.payload[4], 255);
        assert_eq!(
            &headers.payload[5..],
            &[
                0x82, // :method GET
                0x41, 0x89, 0x2f, 0x91, 0xd3, 0x5d, 0x05, 0x5d, 0x25, 0x42,
                0x7f, // :authority
                0x87, // :scheme https
                0x84, // :path /
                // Every value here codes to one byte, its own length, so
                // Chrome's rule sends all three raw. The capture shows the
                // same for one-byte ordinary values:
                // fixtures/websocket/chrome/154.0.8037.58/windows-11-26200/
                // accept.txt:289 records `upgrade-insecure-requests: 1` as
                // `value_huffman:false`.
                0x40, 0x86, 0xf2, 0xb4, 0x65, 0x94, 0xf6, 0x17, 0x01, 0x61, // x-before: a
                // quiche's default policy indexes every ordinary field,
                // `content-length` included, naming static entry 28.
                0x5c, 0x01, 0x30, // content-length: 0
                0x40, 0x85, 0xf2, 0xb0, 0xe5, 0x49, 0x6c, 0x01, 0x62, // x-after: b
            ]
        );

        drop(server);
        assert!(transaction.await?.is_err());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn accepts_bracketed_ipv6_authority_with_port() -> TestResult<()> {
    bounded_peer_test(async {
        let (client, server) = duplex(64 * 1024);
        let server = tokio::spawn(uri_observing_server(server));
        let response = send_get(
            client,
            &v154_http2(),
            "[2001:db8::1]:8443",
            OriginForm::parse("/ipv6")?,
            vec![],
        )
        .await?;
        assert_eq!(response.status(), 204);
        assert!(response.into_body().collect().await?.to_bytes().is_empty());
        assert_eq!(server.await??, "https://[2001:db8::1]:8443/ipv6");
        Ok(())
    })
    .await
}

async fn uri_observing_server(stream: DuplexStream) -> TestResult<http::Uri> {
    let mut connection = ::http2::server::handshake(stream).await?;
    let (request, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before request")??;
    let uri = request.uri().clone();
    respond.send_response(Response::builder().status(204).body(())?, true)?;
    drop(request);
    drop(respond);
    poll_fn(|context| connection.poll_closed(context)).await?;
    Ok(uri)
}

struct RawFrame {
    frame_type: u8,
    flags: u8,
    stream_id: u32,
    payload: Vec<u8>,
}

async fn read_raw_frame(stream: &mut DuplexStream) -> Result<RawFrame, std::io::Error> {
    let mut header = [0_u8; 9];
    stream.read_exact(&mut header).await?;
    let length =
        (usize::from(header[0]) << 16) | (usize::from(header[1]) << 8) | usize::from(header[2]);
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload).await?;
    Ok(RawFrame {
        frame_type: header[3],
        flags: header[4],
        stream_id: u32::from_be_bytes([header[5], header[6], header[7], header[8]]) & 0x7fff_ffff,
        payload,
    })
}
