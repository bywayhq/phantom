use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};

use http::Method;
use phantom_profile::chromium::v152_macos_http2;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf, duplex};
use tracing::instrument::WithSubscriber;

use super::{TestResult, prime_request_trace_callsites, target};
use crate::http2::{
    Http2Error, MAX_REQUEST_HEADER_BYTES, MAX_REQUEST_HEADERS, RequestHeader, send_get,
    send_request_body_with_trailers,
};
use crate::tracing_test::OutcomeSubscriber;

#[tokio::test]
async fn invalid_settings_and_request_never_touch_stream() -> TestResult<()> {
    let mut invalid_settings = v152_macos_http2();
    invalid_settings.initial_connection_window_size = 65_534;
    let mut self_dependent = v152_macos_http2();
    self_dependent
        .headers_priority
        .as_mut()
        .ok_or("Chrome profile unexpectedly lacks HEADERS priority")?
        .dependency_stream_id = 1;

    let mut cases = vec![
        (invalid_settings, "example.test", vec![]),
        (self_dependent, "example.test", vec![]),
        (v152_macos_http2(), "bad authority/", vec![]),
        (v152_macos_http2(), "user@example.test", vec![]),
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
async fn self_dependency_and_userinfo_report_specific_errors_before_io() -> TestResult<()> {
    let mut settings = v152_macos_http2();
    settings
        .headers_priority
        .as_mut()
        .ok_or("Chrome profile unexpectedly lacks HEADERS priority")?
        .dependency_stream_id = 1;
    let touches = Arc::new(AtomicUsize::new(0));
    let (client, _server) = duplex(128);
    let result = send_get(
        TouchCountingStream {
            inner: client,
            touches: Arc::clone(&touches),
        },
        &settings,
        "example.test",
        target()?,
        vec![],
    )
    .await;
    let error = match result {
        Ok(_) => return Err("self-dependent request priority was accepted".into()),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        Http2Error::InvalidPriorityDependency { stream_id: 1 }
    ));
    assert_eq!(touches.load(Ordering::SeqCst), 0);

    let touches = Arc::new(AtomicUsize::new(0));
    let (client, _server) = duplex(128);
    let result = send_get(
        TouchCountingStream {
            inner: client,
            touches: Arc::clone(&touches),
        },
        &v152_macos_http2(),
        "user@example.test",
        target()?,
        vec![],
    )
    .await;
    let error = match result {
        Ok(_) => return Err("authority user information was accepted".into()),
        Err(error) => error,
    };
    assert!(matches!(error, Http2Error::AuthorityContainsUserinfo));
    assert_eq!(touches.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn exact_zero_content_length_is_preserved_in_declared_order() -> TestResult<()> {
    let request = crate::http2::request::prepare_get(
        "example.test",
        target()?,
        vec![
            RequestHeader::new("x-before", "a"),
            RequestHeader::new("content-length", "0"),
            RequestHeader::new("x-after", "b"),
        ],
    )?;
    let ordered = request
        .extensions()
        .get::<::http2::ext::OrderedHeaders>()
        .ok_or("prepared request omitted ordered headers")?;
    assert_eq!(
        ordered
            .as_slice()
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_bytes()))
            .collect::<Vec<_>>(),
        [
            ("x-before", b"a".as_slice()),
            ("content-length", b"0".as_slice()),
            ("x-after", b"b".as_slice()),
        ]
    );
    Ok(())
}

#[test]
fn sensitive_fields_reach_semantic_and_ordered_hpack_inputs() -> TestResult<()> {
    let request = crate::http2::request::prepare_get(
        "example.test",
        target()?,
        vec![RequestHeader::new("cookie", "secret=value").sensitive()],
    )?;
    let semantic = request
        .headers()
        .get("cookie")
        .ok_or("prepared request omitted semantic cookie")?;
    let ordered = request
        .extensions()
        .get::<::http2::ext::OrderedHeaders>()
        .ok_or("prepared request omitted ordered headers")?;

    assert!(semantic.is_sensitive());
    assert!(ordered.as_slice()[0].1.is_sensitive());
    Ok(())
}

#[tokio::test]
async fn nonzero_or_malformed_content_length_is_rejected_before_io() -> TestResult<()> {
    for value in [b"1".as_slice(), b"00", b"", b"not-a-number"] {
        let touches = Arc::new(AtomicUsize::new(0));
        let (client, _server) = duplex(128);
        let result = send_get(
            TouchCountingStream {
                inner: client,
                touches: Arc::clone(&touches),
            },
            &v152_macos_http2(),
            "example.test",
            target()?,
            vec![RequestHeader::new("content-length", value)],
        )
        .await;
        assert!(matches!(
            result,
            Err(Http2Error::InvalidContentLength { index: 0 })
        ));
        assert_eq!(touches.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[tokio::test]
async fn invalid_request_is_traced_before_stream_io() -> TestResult<()> {
    prime_request_trace_callsites().await?;
    let subscriber = OutcomeSubscriber::default();
    let touches = Arc::new(AtomicUsize::new(0));
    let (client, _server) = duplex(128);
    let result = send_get(
        TouchCountingStream {
            inner: client,
            touches: Arc::clone(&touches),
        },
        &v152_macos_http2(),
        "user@example.test",
        target()?,
        Vec::new(),
    )
    .with_subscriber(subscriber.dispatch())
    .await;

    assert!(matches!(result, Err(Http2Error::AuthorityContainsUserinfo)));
    assert_eq!(touches.load(Ordering::SeqCst), 0);
    assert_eq!(subscriber.outcomes_for("http2.request.prepare"), ["error"]);
    assert_eq!(
        subscriber.error_kinds_for("http2.request.prepare"),
        ["authority_contains_userinfo"]
    );
    assert!(subscriber.outcomes_for("http2.response_head").is_empty());
    Ok(())
}

#[tokio::test]
async fn invalid_static_trailers_never_touch_stream() -> TestResult<()> {
    let mut cases = vec![
        vec![RequestHeader::new("Uppercase", "value")],
        vec![RequestHeader::new("x-bad", b"ok\r\ninjected")],
    ];
    for name in [
        "authorization",
        "cache-control",
        "connection",
        "content-encoding",
        "content-length",
        "content-range",
        "content-type",
        "host",
        "keep-alive",
        "max-forwards",
        "proxy-connection",
        "set-cookie",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        cases.push(vec![RequestHeader::new(name, "value")]);
    }
    for trailers in cases {
        let touches = Arc::new(AtomicUsize::new(0));
        let (client, _server) = duplex(128);
        let result = send_request_body_with_trailers(
            TouchCountingStream {
                inner: client,
                touches: Arc::clone(&touches),
            },
            &v152_macos_http2(),
            Method::POST,
            "example.test",
            target()?,
            Vec::new(),
            None,
            trailers,
        )
        .await;
        assert!(result.is_err());
        assert_eq!(touches.load(Ordering::SeqCst), 0);
    }
    Ok(())
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
