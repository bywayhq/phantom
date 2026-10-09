//! Exercise the public harness against real plaintext HTTP/1 requests.

use std::{net::Ipv4Addr, time::Duration};

use phantom::{
    Client, HttpProtocol, StatusCode,
    profile::{
        ClientProfile,
        browser::{chrome, firefox},
    },
};
use phantom_testkit::http1::{
    CaptureError, CaptureLimits, RequestHeadCapture, capture_request_head,
    expectation::{AdjustableHeader, RequestExpectation},
};
use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::TcpListener,
    time::{Instant, timeout_at},
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

const CHROME: &str = include_str!("../fixtures/http1/chrome-154-windows-h1-accept.txt");
const FIREFOX: &str = include_str!("../fixtures/http1/firefox-157-windows-h1-accept.txt");
const TARGET: &str = "/ws.html?run=local-wire-check";
const CHROME_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36";

#[tokio::test]
async fn chrome_navigation_matches_retained_header_bytes() -> TestResult {
    let profile = ClientProfile::new(chrome::v154_tcp_tls())
        .with_tcp(chrome::v154_tcp())
        .with_http1(chrome::v154_http1())
        .with_client_hints(chrome::v154_windows_client_hints())
        .with_request_template(chrome::v154_windows_navigation_template());
    check_navigation(profile, CHROME, "Google Chrome", "154.0.8037.58", Some(6)).await
}

#[tokio::test]
async fn firefox_navigation_matches_retained_header_bytes() -> TestResult {
    let profile = ClientProfile::new(firefox::v157_tcp_tls())
        .with_tcp(firefox::v157_tcp())
        .with_http1(firefox::v157_http1())
        .with_request_template(firefox::v157_windows_navigation_template());
    check_navigation(profile, FIREFOX, "Mozilla Firefox", "157.0", None).await
}

async fn check_navigation(
    profile: ClientProfile,
    fixture: &str,
    browser: &str,
    build: &str,
    user_agent_index: Option<usize>,
) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(10);
    timeout_at(deadline, async {
        let limits = CaptureLimits::new(32_768, 8_192, 128);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let authority = listener.local_addr()?.to_string();
        let mut expected = RequestExpectation::from_retained(fixture, 0, 0, 65_536, limits)?;
        assert_eq!(expected.metadata().browser(), browser);
        assert_eq!(expected.metadata().build(), build);
        assert_eq!(
            expected.metadata().platform(),
            "Windows 11 Home 10.0.26200 x64"
        );
        assert_eq!(expected.metadata().launch_mode(), "headless");
        assert_eq!(expected.metadata().scenario(), "h1-accept");
        assert_eq!(expected.metadata().request_kind(), "page");
        expected.replace_target(TARGET.as_bytes())?;
        expected.replace_header_value(
            0,
            AdjustableHeader::Host,
            format!(" {authority}").as_bytes(),
        )?;
        // This capture used headless Chrome. The ordinary Windows recipe has
        // a different User-Agent; declare that one value change explicitly.
        if let Some(index) = user_agent_index {
            expected.replace_header_value(
                index,
                AdjustableHeader::UserAgent,
                format!(" {CHROME_USER_AGENT}").as_bytes(),
            )?;
        }
        let peer = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let mut stream = BufReader::new(stream);
            let head = capture_request_head(&mut stream, deadline, limits).await?;
            stream
                .get_mut()
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(head)
        });
        let client = Client::builder(profile).build()?;
        let response = client
            .get(HttpProtocol::Http1, &format!("http://{authority}{TARGET}"))?
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(
            response
                .into_body()
                .collect_with_limit(1_024)
                .await?
                .is_empty()
        );
        let actual = peer.await??;
        expected.compare(&actual)?;
        check_negative_controls(&expected, &actual, limits)?;
        Ok(())
    })
    .await?
}

fn check_negative_controls(
    expected: &RequestExpectation,
    actual: &RequestHeadCapture,
    limits: CaptureLimits,
) -> TestResult {
    let original: Vec<Vec<u8>> = actual
        .headers()
        .iter()
        .map(|field| field.bytes().to_vec())
        .collect();
    let mut reordered = original.clone();
    reordered.swap(1, 2);
    assert!(
        expected
            .compare(&mutant(actual, &reordered, limits)?)
            .is_err()
    );
    let mut changed_value = original.clone();
    changed_value[1].push(b'x');
    assert!(
        expected
            .compare(&mutant(actual, &changed_value, limits)?)
            .is_err()
    );
    let mut changed_case = original.clone();
    changed_case[0][0] = b'h';
    assert!(
        expected
            .compare(&mutant(actual, &changed_case, limits)?)
            .is_err()
    );
    assert!(
        expected
            .compare(&mutant(actual, &original[..original.len() - 1], limits)?)
            .is_err()
    );
    assert!(matches!(
        RequestHeadCapture::parse(&[], limits),
        Err(CaptureError::EmptyInput)
    ));
    assert!(matches!(
        RequestHeadCapture::parse(&actual.bytes()[..actual.bytes().len() - 1], limits),
        Err(CaptureError::TruncatedHead)
    ));
    Ok(())
}

fn mutant(
    actual: &RequestHeadCapture,
    headers: &[Vec<u8>],
    limits: CaptureLimits,
) -> TestResult<RequestHeadCapture> {
    let mut bytes = actual.request_line().to_vec();
    bytes.extend_from_slice(b"\r\n");
    for header in headers {
        bytes.extend_from_slice(header);
        bytes.extend_from_slice(b"\r\n");
    }
    bytes.extend_from_slice(b"\r\n");
    Ok(RequestHeadCapture::parse(&bytes, limits)?)
}
