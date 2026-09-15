use std::{
    error::Error,
    future::{Future, poll_fn},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use http::{HeaderMap, Response};
use http_body_util::BodyExt;
use phantom_profile::{
    Http2Priority, Http2PseudoHeader, Http2Setting, Http2Settings, chromium::v152_macos_http2,
};
use phantom_testkit::http2::{
    CLIENT_CONNECTION_PREFACE, CaptureCompletion, CaptureLimits, capture_client_frames,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, DuplexStream, ReadBuf, duplex},
    sync::oneshot,
    time::{Instant, timeout},
};
use tracing::instrument::WithSubscriber;

use super::{MAX_REQUEST_HEADER_BYTES, MAX_REQUEST_HEADERS, OriginForm, RequestHeader, send_get};
use crate::tracing_test::{OutcomeSubscriber, poll_once_then_drop};

type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

const PEER_TEST_TIMEOUT: Duration = Duration::from_secs(3);

async fn bounded_peer_test<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    match timeout(PEER_TEST_TIMEOUT, future).await {
        Ok(result) => result,
        Err(_) => Err("HTTP/2 peer test exceeded its absolute deadline".into()),
    }
}

fn target() -> Result<OriginForm, crate::request::InvalidOriginForm> {
    OriginForm::parse("/resource?item=1")
}

fn headers() -> Vec<RequestHeader> {
    vec![
        RequestHeader::new("accept", "*/*"),
        RequestHeader::new("x-repeat", "alpha"),
        RequestHeader::new("x-middle", "between"),
        RequestHeader::new("x-repeat", "beta"),
        RequestHeader::new("te", "trailers"),
    ]
}

#[tokio::test]
async fn invalid_settings_and_request_never_touch_stream() -> TestResult<()> {
    let mut invalid_settings = v152_macos_http2();
    invalid_settings.initial_connection_window_size = 65_534;

    let mut cases = vec![
        (invalid_settings, "example.test", vec![]),
        (v152_macos_http2(), "bad authority/", vec![]),
        (
            v152_macos_http2(),
            "example.test",
            vec![RequestHeader::new("Uppercase", "value")],
        ),
        (
            v152_macos_http2(),
            "example.test",
            vec![RequestHeader::new("bad name", "value")],
        ),
        (
            v152_macos_http2(),
            "example.test",
            vec![RequestHeader::new("x-bad", b"ok\r\ninjected")],
        ),
    ];
    for name in [
        "host",
        "connection",
        "keep-alive",
        "proxy-connection",
        "upgrade",
        "content-length",
        "transfer-encoding",
        "trailer",
    ] {
        cases.push((
            v152_macos_http2(),
            "example.test",
            vec![RequestHeader::new(name, "value")],
        ));
    }
    cases.push((
        v152_macos_http2(),
        "example.test",
        vec![RequestHeader::new("te", "Trailers")],
    ));

    let too_many = (0..=MAX_REQUEST_HEADERS)
        .map(|index| RequestHeader::new(format!("x-{index}"), "v"))
        .collect();
    cases.push((v152_macos_http2(), "example.test", too_many));
    cases.push((
        v152_macos_http2(),
        "example.test",
        vec![RequestHeader::new(
            "x-large",
            vec![b'a'; MAX_REQUEST_HEADER_BYTES],
        )],
    ));

    for (settings, authority, headers) in cases {
        let touches = Arc::new(AtomicUsize::new(0));
        let (client, _server) = duplex(128);
        let result = send_get(
            TouchCountingStream {
                inner: client,
                touches: Arc::clone(&touches),
            },
            &settings,
            authority,
            target()?,
            headers,
        )
        .await;
        assert!(result.is_err());
        assert_eq!(touches.load(Ordering::SeqCst), 0);
    }
    Ok(())
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
        headers_priority: Some(Http2Priority {
            dependency_stream_id: 31,
            weight: 1,
            exclusive: false,
        }),
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
        let settings = v152_macos_http2();
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
        let settings = v152_macos_http2();
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
                0x53, 0x83, 0xf9, 0x63, 0xe7, // accept: */*
                0x40, 0x86, 0xf2, 0xb5, 0x85, 0xac, 0xa3, 0x4f, 0x84, 0x1d, 0x15, 0xce,
                0x3f, // x-repeat: alpha
                0x40, 0x86, 0xf2, 0xb5, 0x26, 0x92, 0x4a, 0x0b, 0x85, 0x8c, 0xa9, 0xf0, 0x52,
                0xd5, // x-middle: between
                0x7f, 0x00, 0x83, 0x8c, 0xa9, 0x1f, // x-repeat: beta
                0x40, 0x82, 0x49, 0x7f, 0x86, 0x4d, 0x83, 0x35, 0x05, 0xb1,
                0x1f,
                // te: trailers
            ]
        );

        drop(server);
        assert!(transaction.await?.is_err());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn streams_data_then_trailers_without_buffering_later_data() -> TestResult<()> {
    bounded_peer_test(async {
        let (client, server) = duplex(64 * 1024);
        let (release_tx, release_rx) = oneshot::channel();
        let server_task = tokio::spawn(streaming_server(server, release_rx));

        let response = send_get(
            client,
            &v152_macos_http2(),
            "example.test",
            target()?,
            headers(),
        )
        .await?;
        assert_eq!(response.status(), 206);
        let mut body = response.into_body();
        let first = next_nonempty_data(&mut body).await?;
        assert_eq!(first, "first");

        release_tx
            .send(())
            .map_err(|_| "server stopped before later data release")?;
        let mut later = None;
        let mut trailers = None;
        while let Some(frame) = body.frame().await {
            let frame = frame?;
            match frame.into_data() {
                Ok(data) if !data.is_empty() => later = Some(data),
                Ok(_) => {}
                Err(frame) => {
                    if let Ok(fields) = frame.into_trailers() {
                        trailers = Some(fields);
                    }
                }
            }
        }
        assert_eq!(later.as_deref(), Some(&b"later"[..]));
        assert_eq!(
            trailers
                .as_ref()
                .and_then(|fields| fields.get("x-finished"))
                .and_then(|value| value.to_str().ok()),
            Some("yes")
        );

        let request = server_task.await??;
        assert_eq!(request.method, http::Method::GET);
        assert_eq!(
            request.uri.authority().map(|value| value.as_str()),
            Some("example.test")
        );
        assert_eq!(
            request.uri.path_and_query().map(|value| value.as_str()),
            Some("/resource?item=1")
        );
        assert_eq!(request.repeat_count, 2);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn terminal_data_completes_without_an_extra_body_poll() -> TestResult<()> {
    bounded_peer_test(async {
        let subscriber = OutcomeSubscriber::default();
        let (client, server) = duplex(64 * 1024);
        let server_task = tokio::spawn(terminal_data_server(server));

        async {
            let response = send_get(
                client,
                &v152_macos_http2(),
                "example.test",
                target()?,
                vec![],
            )
            .await?;
            let mut body = response.into_body();
            let frame = body
                .frame()
                .await
                .ok_or("response ended before terminal DATA")??;
            assert_eq!(frame.into_data().map_err(|_| "expected DATA")?, "terminal");
            drop(body);
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        }
        .with_subscriber(subscriber.clone())
        .await?;

        assert!(!server_task.await??, "terminal DATA was followed by CANCEL");
        assert_eq!(
            subscriber.response_body_events(),
            [(8, "complete".to_owned())]
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn incomplete_body_drop_flushes_reset_and_driver_closes() -> TestResult<()> {
    bounded_peer_test(async {
        let subscriber = OutcomeSubscriber::default();
        let (client, server) = duplex(64 * 1024);
        let server_task = tokio::spawn(reset_observing_server(server));

        async {
            let response = send_get(
                client,
                &v152_macos_http2(),
                "example.test",
                target()?,
                vec![],
            )
            .await?;
            let mut body = response.into_body();
            assert_eq!(next_nonempty_data(&mut body).await?, "partial");
            drop(body);
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        }
        .with_subscriber(subscriber.clone())
        .await?;

        let (reason, connection_closed) = server_task.await??;
        assert_eq!(reason, ::http2::Reason::CANCEL);
        assert!(connection_closed);
        assert_eq!(
            subscriber.response_body_events(),
            [(7, "dropped".to_owned())]
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn cancelled_response_head_records_outcome_once() -> TestResult<()> {
    let subscriber = OutcomeSubscriber::default();
    let (client, _server) = duplex(4096);
    let settings = v152_macos_http2();
    let pending = poll_once_then_drop(
        send_get(client, &settings, "example.test", target()?, vec![]),
        subscriber.clone(),
    )
    .await;
    if !pending {
        return Err("HTTP/2 response-head future completed before cancellation".into());
    }
    assert_eq!(
        subscriber.outcomes_for("http2.response_head"),
        ["cancelled"]
    );
    Ok(())
}

async fn streaming_server(
    stream: DuplexStream,
    release_later: oneshot::Receiver<()>,
) -> TestResult<RequestObservation> {
    let mut connection = ::http2::server::handshake(stream).await?;
    let (request, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before request")??;
    let response = Response::builder().status(206).body(())?;
    let mut send = respond.send_response(response, false)?;
    send.send_data(Bytes::from_static(b"first"), false)?;

    tokio::pin!(release_later);
    tokio::select! {
        result = &mut release_later => {
            result.map_err(std::io::Error::other)?;
        }
        incoming = connection.accept() => {
            if incoming.is_none() {
                return Err("connection closed before later data release".into());
            }
            return Err("one-shot client sent an unexpected second request".into());
        }
    }

    send.send_data(Bytes::from_static(b"later"), false)?;
    let mut trailers = HeaderMap::new();
    trailers.insert("x-finished", http::HeaderValue::from_static("yes"));
    send.send_trailers(trailers)?;
    let observation = RequestObservation {
        method: request.method().clone(),
        uri: request.uri().clone(),
        repeat_count: request.headers().get_all("x-repeat").iter().count(),
    };
    drop(request);
    drop(send);
    drop(respond);
    poll_fn(|context| connection.poll_closed(context)).await?;
    Ok(observation)
}

struct RequestObservation {
    method: http::Method,
    uri: http::Uri,
    repeat_count: usize,
}

async fn reset_observing_server(stream: DuplexStream) -> TestResult<(::http2::Reason, bool)> {
    let mut connection = ::http2::server::handshake(stream).await?;
    let (_request, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before request")??;
    let response = Response::builder().status(200).body(())?;
    let mut send = respond.send_response(response, false)?;
    send.send_data(Bytes::from_static(b"partial"), false)?;

    let reason = tokio::select! {
        biased;
        result = poll_fn(|context| send.poll_reset(context)) => result?,
        incoming = connection.accept() => {
            if incoming.is_none() {
                return Err("connection closed without an observable stream reset".into());
            }
            return Err("one-shot client sent an unexpected second request".into());
        }
    };
    drop(send);
    poll_fn(|context| connection.poll_closed(context)).await?;
    Ok((reason, true))
}

async fn terminal_data_server(stream: DuplexStream) -> TestResult<bool> {
    let mut connection = ::http2::server::handshake(stream).await?;
    let (request, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before request")??;
    let response = Response::builder().status(200).body(())?;
    let mut send = respond.send_response(response, false)?;
    send.send_data(Bytes::from_static(b"terminal"), true)?;
    drop(request);
    drop(respond);

    let reset = tokio::select! {
        biased;
        result = poll_fn(|context| send.poll_reset(context)) => {
            result?;
            true
        }
        incoming = connection.accept() => {
            if incoming.is_some() {
                return Err("one-shot client sent an unexpected second request".into());
            }
            false
        }
    };
    drop(send);
    Ok(reset)
}

async fn next_nonempty_data(body: &mut super::Http2Body) -> TestResult<Bytes> {
    loop {
        let frame = body
            .frame()
            .await
            .ok_or("response ended before non-empty DATA")??;
        if let Ok(data) = frame.into_data() {
            if !data.is_empty() {
                return Ok(data);
            }
        }
    }
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

struct TouchCountingStream {
    inner: DuplexStream,
    touches: Arc<AtomicUsize>,
}

impl AsyncRead for TouchCountingStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.touches.fetch_add(1, Ordering::SeqCst);
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for TouchCountingStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        self.touches.fetch_add(1, Ordering::SeqCst);
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        self.touches.fetch_add(1, Ordering::SeqCst);
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        self.touches.fetch_add(1, Ordering::SeqCst);
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}
