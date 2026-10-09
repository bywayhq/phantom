use std::{error::Error, time::Duration};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

type TestResult = Result<(), Box<dyn Error + Send + Sync>>;
const HEAD: &[u8] =
    b"GET /path?q=1 HTTP/1.1\r\nHost: example.test\r\nX-Probe:\t one \t\r\nx-probe: two\r\n\r\n";
const LIMITS: CaptureLimits = CaptureLimits::new(4096, 1024, 32);

#[test]
fn parsing_keeps_every_byte_and_duplicate_position() -> TestResult {
    let head = RequestHeadCapture::parse(HEAD, LIMITS)?;
    assert_eq!(head.bytes(), HEAD);
    assert_eq!(head.request_line(), b"GET /path?q=1 HTTP/1.1");
    assert_eq!(head.method(), b"GET");
    assert_eq!(head.target(), b"/path?q=1");
    assert_eq!(head.version(), b"HTTP/1.1");
    assert_eq!(head.headers().len(), 3);
    assert_eq!(head.headers()[1].name(), b"X-Probe");
    assert_eq!(head.headers()[1].bytes(), b"X-Probe:\t one \t");
    assert_eq!(head.headers()[1].value_bytes(), b"\t one \t");
    assert_eq!(head.headers()[2].name(), b"x-probe");
    Ok(())
}

#[test]
fn parsing_allows_opaque_header_values_and_http10() -> TestResult {
    let head = RequestHeadCapture::parse(b"OPTIONS * HTTP/1.0\r\nX: \xff\r\n\r\n", LIMITS)?;
    assert_eq!(head.headers()[0].value_bytes(), b" \xff");
    assert_eq!(head.version(), b"HTTP/1.0");
    Ok(())
}

#[test]
fn malformed_or_incomplete_heads_are_rejected() {
    assert!(matches!(
        RequestHeadCapture::parse(b"", LIMITS),
        Err(CaptureError::EmptyInput)
    ));
    for bytes in [
        b"GET / HTTP/1.1\r\nHost: x\r\n".as_slice(),
        b"GET / HTTP/1.1\nHost: x\n\n".as_slice(),
    ] {
        assert!(matches!(
            RequestHeadCapture::parse(bytes, LIMITS),
            Err(CaptureError::TruncatedHead)
        ));
    }
    for bytes in [
        b"GET  / HTTP/1.1\r\n\r\n".as_slice(),
        b"GET / HTTP/2\r\n\r\n".as_slice(),
        b"G\tET / HTTP/1.1\r\n\r\n".as_slice(),
    ] {
        assert!(matches!(
            RequestHeadCapture::parse(bytes, LIMITS),
            Err(CaptureError::InvalidRequestLine)
        ));
    }
    for bytes in [
        b"GET / HTTP/1.1\r\n Host: x\r\n\r\n".as_slice(),
        b"GET / HTTP/1.1\r\nHost : x\r\n\r\n".as_slice(),
        b"GET / HTTP/1.1\r\nHost: x\nX: y\r\n\r\n".as_slice(),
        b"GET / HTTP/1.1\r\nX: \x7f\r\n\r\n".as_slice(),
    ] {
        assert!(matches!(
            RequestHeadCapture::parse(bytes, LIMITS),
            Err(CaptureError::InvalidLine { .. })
        ));
    }
    assert!(matches!(
        RequestHeadCapture::parse(b"GET / HTTP/1.1\r\n\r\nextra\r\n\r\n", LIMITS),
        Err(CaptureError::TrailingBytes)
    ));
    assert!(matches!(
        RequestHeadCapture::parse(b"GET / HTTP/1.1\r\n\r\nbody", LIMITS),
        Err(CaptureError::TrailingBytes)
    ));
    assert!(matches!(
        RequestHeadCapture::parse(b"\r\n\r\n", LIMITS),
        Err(CaptureError::EmptyInput)
    ));
}

#[test]
fn each_limit_accepts_its_exact_boundary() -> TestResult {
    let longest = HEAD
        .split(|byte| *byte == b'\n')
        .map(|line| line.len() + 1)
        .max()
        .ok_or("no lines")?;
    RequestHeadCapture::parse(HEAD, CaptureLimits::new(HEAD.len(), longest, 3))?;
    assert!(matches!(
        RequestHeadCapture::parse(HEAD, CaptureLimits::new(HEAD.len() - 1, longest, 3)),
        Err(CaptureError::HeadLimitExceeded)
    ));
    assert!(matches!(
        RequestHeadCapture::parse(HEAD, CaptureLimits::new(HEAD.len(), longest - 1, 3)),
        Err(CaptureError::LineLimitExceeded { line: 0 })
    ));
    assert!(matches!(
        RequestHeadCapture::parse(HEAD, CaptureLimits::new(HEAD.len(), longest, 2)),
        Err(CaptureError::HeaderLimitExceeded)
    ));
    assert!(matches!(
        RequestHeadCapture::parse(HEAD, CaptureLimits::new(0, 0, 0)),
        Err(CaptureError::HeadLimitExceeded)
    ));
    Ok(())
}

#[tokio::test]
async fn fragmented_reads_leave_body_bytes_unread() -> TestResult {
    let (mut sender, mut reader) = tokio::io::duplex(8);
    let producer = tokio::spawn(async move {
        for byte in HEAD {
            sender.write_all(&[*byte]).await?;
        }
        sender.write_all(b"body").await
    });
    let capture =
        capture_request_head(&mut reader, Instant::now() + Duration::from_secs(2), LIMITS).await?;
    assert_eq!(capture.bytes(), HEAD);
    let mut body = [0; 4];
    reader.read_exact(&mut body).await?;
    assert_eq!(&body, b"body");
    producer.await??;
    Ok(())
}

#[tokio::test]
async fn every_truncated_prefix_fails_without_completing() {
    for length in 0..HEAD.len() {
        let mut reader = &HEAD[..length];
        let error =
            capture_request_head(&mut reader, Instant::now() + Duration::from_secs(1), LIMITS)
                .await;
        assert!(
            matches!(
                error,
                Err(CaptureError::EmptyInput | CaptureError::TruncatedHead)
            ),
            "prefix {length}"
        );
    }
}

#[tokio::test]
async fn capture_bounds_apply_before_reading_more_bytes() -> TestResult {
    let mut reader = HEAD;
    assert!(matches!(
        capture_request_head(
            &mut reader,
            Instant::now() + Duration::from_secs(1),
            CaptureLimits::new(4, 1024, 32)
        )
        .await,
        Err(CaptureError::HeadLimitExceeded)
    ));
    assert_eq!(reader, &HEAD[4..]);
    let mut reader = HEAD;
    assert!(matches!(
        capture_request_head(
            &mut reader,
            Instant::now() + Duration::from_secs(1),
            CaptureLimits::new(4096, 4, 32)
        )
        .await,
        Err(CaptureError::LineLimitExceeded { line: 0 })
    ));
    assert_eq!(reader, &HEAD[4..]);
    let mut reader = HEAD;
    assert!(matches!(
        capture_request_head(
            &mut reader,
            Instant::now() + Duration::from_secs(1),
            CaptureLimits::new(4096, 1024, 0)
        )
        .await,
        Err(CaptureError::HeaderLimitExceeded)
    ));
    Ok(())
}

#[tokio::test]
async fn deadline_covers_an_incomplete_head() -> TestResult {
    let (mut sender, mut reader) = tokio::io::duplex(64);
    sender.write_all(b"GET / HTTP/1.1\r\n").await?;
    assert!(matches!(
        capture_request_head(
            &mut reader,
            Instant::now() + Duration::from_millis(20),
            LIMITS
        )
        .await,
        Err(CaptureError::DeadlineExceeded)
    ));
    drop(sender);
    Ok(())
}

#[test]
fn debug_and_errors_do_not_print_request_or_io_payloads() -> TestResult {
    let head = RequestHeadCapture::parse(
        b"GET /private-token HTTP/1.1\r\nAuthorization: secret-token\r\n\r\n",
        LIMITS,
    )?;
    assert!(!format!("{head:?}").contains("token"));
    assert!(!format!("{:?}", head.headers()[0]).contains("token"));
    let error = CaptureError::Io(std::io::Error::other("secret-token"));
    assert!(!format!("{error:?} {error}").contains("token"));
    assert!(error.source().is_some());
    Ok(())
}

#[test]
fn capture_types_are_send_and_sync() {
    fn check<T: Send + Sync>() {}
    check::<CaptureLimits>();
    check::<CapturedHeader>();
    check::<RequestHeadCapture>();
    check::<CaptureError>();
}
