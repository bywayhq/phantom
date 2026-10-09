use std::{error::Error, time::Duration};

use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    time::{Instant, timeout_at},
};

use super::*;
use crate::http1::capture_request_head;

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;
const CHROME: &str = include_str!("../../../fixtures/http1/chrome-154-windows-h1-accept.txt");
const FIREFOX: &str = include_str!("../../../fixtures/http1/firefox-157-windows-h1-accept.txt");
const LIMITS: CaptureLimits = CaptureLimits::new(32 * 1024, 8 * 1024, 128);

fn chrome() -> Result<RequestExpectation, ExpectationError> {
    RequestExpectation::from_retained(CHROME, 0, 0, CHROME.len(), LIMITS)
}

fn replace_record(text: &str, key: &str, value: Option<&str>) -> String {
    let prefix = format!("{key}=");
    text.lines()
        .filter_map(|line| {
            if line.starts_with(&prefix) {
                value.map(|value| format!("{key}={value}"))
            } else {
                Some(line.to_owned())
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn retained_requests_keep_exact_identity_and_all_runs() -> TestResult {
    let expected = chrome()?;
    assert_eq!(expected.metadata().browser(), "Google Chrome");
    assert_eq!(expected.metadata().build(), "154.0.8037.58");
    assert_eq!(
        expected.metadata().platform(),
        "Windows 11 Home 10.0.26200 x64"
    );
    assert_eq!(expected.metadata().captured_at_unix(), 1790242984);
    assert_eq!(expected.metadata().launch_mode(), "headless");
    assert_eq!(expected.metadata().scenario(), "h1-accept");
    assert_eq!(expected.metadata().request_kind(), "page");
    assert_eq!(
        expected.head().request_line(),
        b"GET /ws.html?run=d51f48ce63705760 HTTP/1.1"
    );
    assert_eq!(expected.head().headers().len(), 14);
    assert_eq!(expected.head().headers()[0].name(), b"Host");
    assert_eq!(expected.head().headers()[6].name(), b"User-Agent");
    assert!(
        expected.head().headers()[6]
            .value_bytes()
            .windows(b"HeadlessChrome/".len())
            .any(|bytes| bytes == b"HeadlessChrome/")
    );
    for fixture in [CHROME, FIREFOX] {
        for run in 0..3 {
            for (request, kind) in ["page", "websocket", "done"].into_iter().enumerate() {
                let expected = RequestExpectation::from_retained(
                    fixture,
                    run,
                    request,
                    fixture.len(),
                    LIMITS,
                )?;
                assert_eq!(expected.metadata().run(), run);
                assert_eq!(expected.metadata().request(), request);
                assert_eq!(expected.metadata().request_kind(), kind);
                let actual = RequestHeadCapture::parse(expected.head().bytes(), LIMITS)?;
                expected.compare(&actual)?;
            }
        }
    }
    let firefox = RequestExpectation::from_retained(FIREFOX, 0, 0, FIREFOX.len(), LIMITS)?;
    assert_eq!(firefox.metadata().browser(), "Mozilla Firefox");
    assert_eq!(firefox.metadata().build(), "157.0");
    assert_eq!(firefox.head().headers().len(), 12);
    assert_eq!(firefox.head().headers()[1].name(), b"User-Agent");
    Ok(())
}

#[tokio::test]
async fn loopback_capture_matches_retained_bytes_with_bounded_join() -> TestResult {
    let expected = chrome()?;
    let bytes = expected.head().bytes().to_vec();
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut sender = tokio::spawn(async move {
        let mut stream = TcpStream::connect(address).await?;
        for fragment in bytes.chunks(7) {
            stream.write_all(fragment).await?;
        }
        Ok::<_, std::io::Error>(())
    });
    let result = timeout_at(deadline, async {
        let (mut stream, _) = listener.accept().await?;
        let actual = capture_request_head(&mut stream, deadline, LIMITS).await?;
        expected.compare(&actual)?;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    })
    .await;
    if result.is_err() || result.as_ref().is_ok_and(|inner| inner.is_err()) {
        sender.abort();
    }
    let joined = timeout_at(deadline, &mut sender).await;
    if joined.is_err() {
        sender.abort();
        let _ = sender.await;
    }
    result??;
    joined???;
    Ok(())
}

#[test]
fn retained_input_rejects_missing_empty_truncated_and_duplicate_records() {
    for text in [
        String::new(),
        replace_record(CHROME, "client", None),
        replace_record(CHROME, "client_version", Some("")),
        replace_record(CHROME, "run_0_request_0_header_13", None),
        replace_record(CHROME, "run_0_request_0_line_hex", Some("4")),
        replace_record(CHROME, "run_0_request_0_line_hex", Some("zz")),
        format!("{CHROME}client=other\n"),
        replace_record(CHROME, "run_0_request_0_header_count", Some("13")),
        replace_record(
            CHROME,
            "run_0_request_0_header_count",
            Some("184467440737095516160"),
        ),
        replace_record(CHROME, "run_0_timed_out", Some("true")),
        replace_record(CHROME, "run_0_request_0", Some("kind:page,kind:done")),
        replace_record(
            CHROME,
            "run_0_request_0_header_0",
            Some("486f73743a20780d0a583a2079"),
        ),
    ] {
        assert!(RequestExpectation::from_retained(&text, 0, 0, CHROME.len() * 2, LIMITS).is_err());
    }
    assert!(matches!(
        RequestExpectation::from_retained(CHROME, 3, 0, CHROME.len(), LIMITS),
        Err(ExpectationError::RunOutOfRange)
    ));
    assert!(matches!(
        RequestExpectation::from_retained(CHROME, 0, 3, CHROME.len(), LIMITS),
        Err(ExpectationError::RequestOutOfRange)
    ));
}

#[test]
fn retained_input_enforces_fixture_and_head_bounds() {
    assert!(matches!(
        RequestExpectation::from_retained(CHROME, 0, 0, CHROME.len() - 1, LIMITS),
        Err(ExpectationError::FixtureLimitExceeded)
    ));
    assert!(matches!(
        RequestExpectation::from_retained(
            CHROME,
            0,
            0,
            CHROME.len(),
            CaptureLimits::new(32, 8192, 128)
        ),
        Err(ExpectationError::Head(CaptureError::HeadLimitExceeded))
    ));
    assert!(matches!(
        RequestExpectation::from_retained(
            CHROME,
            0,
            0,
            CHROME.len(),
            CaptureLimits::new(32768, 8, 128)
        ),
        Err(ExpectationError::Head(
            CaptureError::LineLimitExceeded { .. }
        ))
    ));
    assert!(matches!(
        RequestExpectation::from_retained(
            CHROME,
            0,
            0,
            CHROME.len(),
            CaptureLimits::new(32768, 8192, 13)
        ),
        Err(ExpectationError::Head(CaptureError::HeaderLimitExceeded))
    ));
}

fn changed_head(
    expected: &RequestExpectation,
    lines: &[Vec<u8>],
) -> Result<RequestHeadCapture, CaptureError> {
    let mut bytes = expected.head().request_line().to_vec();
    bytes.extend_from_slice(b"\r\n");
    for line in lines {
        bytes.extend_from_slice(line);
        bytes.extend_from_slice(b"\r\n");
    }
    bytes.extend_from_slice(b"\r\n");
    RequestHeadCapture::parse(&bytes, LIMITS)
}

#[test]
fn changed_bytes_order_case_count_and_whitespace_fail_exact_comparison() -> TestResult {
    let expected = chrome()?;
    let lines = expected
        .head()
        .headers()
        .iter()
        .map(|header| header.bytes().to_vec())
        .collect::<Vec<_>>();
    let mut reordered = lines.clone();
    reordered.swap(2, 3);
    assert!(matches!(
        expected
            .compare(&changed_head(&expected, &reordered)?)
            .err()
            .ok_or("accepted order change")?
            .location(),
        MismatchLocation::HeaderName { index: 2, .. }
    ));
    let mut changed = lines.clone();
    changed[0][0] = b'h';
    assert_eq!(
        expected
            .compare(&changed_head(&expected, &changed)?)
            .err()
            .ok_or("accepted case change")?
            .location(),
        MismatchLocation::HeaderName { index: 0, byte: 0 }
    );
    let mut changed = lines.clone();
    changed[0].push(b' ');
    assert!(matches!(
        expected
            .compare(&changed_head(&expected, &changed)?)
            .err()
            .ok_or("accepted whitespace change")?
            .location(),
        MismatchLocation::HeaderValue { index: 0, .. }
    ));
    let mut changed = lines.clone();
    changed[6] = b"User-Agent: secret-marker".to_vec();
    let mismatch = expected
        .compare(&changed_head(&expected, &changed)?)
        .err()
        .ok_or("accepted value change")?;
    assert!(matches!(
        mismatch.location(),
        MismatchLocation::HeaderValue { index: 6, .. }
    ));
    assert!(!format!("{mismatch:?} {mismatch}").contains("secret-marker"));
    assert!(matches!(
        expected
            .compare(&changed_head(&expected, &lines[..13])?)
            .err()
            .ok_or("accepted missing header")?
            .location(),
        MismatchLocation::HeaderCount {
            expected: 14,
            actual: 13
        }
    ));
    let mut added = lines.clone();
    added.push(lines[0].clone());
    assert!(matches!(
        expected
            .compare(&changed_head(&expected, &added)?)
            .err()
            .ok_or("accepted extra duplicate")?
            .location(),
        MismatchLocation::HeaderCount {
            expected: 14,
            actual: 15
        }
    ));
    let mut changed = expected.clone();
    changed.replace_target(b"/changed")?;
    assert!(matches!(
        expected
            .compare(changed.head())
            .err()
            .ok_or("accepted target change")?
            .location(),
        MismatchLocation::RequestLine { .. }
    ));
    Ok(())
}

#[test]
fn explicit_adjustments_preserve_names_positions_and_metadata() -> TestResult {
    let original = chrome()?;
    let mut adjusted = original.clone();
    adjusted.replace_target(b"/ws.html?run=local-test")?;
    adjusted.replace_header_value(0, AdjustableHeader::Host, b" 127.0.0.1:12345")?;
    adjusted.replace_header_value(6, AdjustableHeader::UserAgent, b" chosen-agent")?;
    assert_eq!(adjusted.metadata(), original.metadata());
    assert_eq!(adjusted.head().method(), original.head().method());
    assert_eq!(adjusted.head().version(), original.head().version());
    for (index, (before, after)) in original
        .head()
        .headers()
        .iter()
        .zip(adjusted.head().headers())
        .enumerate()
    {
        assert_eq!(before.name(), after.name());
        if ![0, 6].contains(&index) {
            assert_eq!(before.bytes(), after.bytes());
        }
    }
    assert_eq!(
        adjusted.head().headers()[0].value_bytes(),
        b" 127.0.0.1:12345"
    );
    assert_eq!(adjusted.head().headers()[6].value_bytes(), b" chosen-agent");
    assert!(original.compare(adjusted.head()).is_err());
    adjusted.compare(adjusted.head())?;
    Ok(())
}

#[test]
fn invalid_adjustments_leave_expectation_unchanged() -> TestResult {
    let original = chrome()?;
    let mut adjusted = original.clone();
    for (index, header, value) in [
        (1, AdjustableHeader::Host, b" x".as_slice()),
        (999, AdjustableHeader::UserAgent, b" x".as_slice()),
        (0, AdjustableHeader::Host, b" x\r\nInjected: x".as_slice()),
        (6, AdjustableHeader::UserAgent, b" \x00".as_slice()),
    ] {
        assert!(adjusted.replace_header_value(index, header, value).is_err());
        assert_eq!(adjusted, original);
    }
    for target in [
        b"".as_slice(),
        b"/bad target".as_slice(),
        b"/x\r\nInjected: x".as_slice(),
    ] {
        assert!(adjusted.replace_target(target).is_err());
        assert_eq!(adjusted, original);
    }
    assert!(adjusted.replace_target(&vec![b'x'; 32769]).is_err());
    assert_eq!(adjusted, original);
    Ok(())
}

#[test]
fn expectation_types_are_send_and_sync() {
    fn check<T: Send + Sync>() {}
    check::<RequestExpectation>();
    check::<RequestMetadata>();
    check::<ExpectationError>();
    check::<RequestMismatch>();
    check::<MismatchLocation>();
    check::<AdjustableHeader>();
}
