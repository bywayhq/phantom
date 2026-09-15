use phantom_net::http2::{Http2Error, OriginForm, send_get};
use phantom_profile::chromium::v152_macos_http2;
use phantom_testkit::http2::{CaptureCompletion, capture_client_frames};
use tokio::{io::duplex, time::timeout};

use super::{TEST_TIMEOUT, TestResult, assert_raw_startup, fixture::Fixture};

pub(super) const FIXTURE_TEXT: &str = include_str!(concat!(
    "../../../../fixtures/http2/chrome/152.0.7977.83/",
    "macos-15.5/client-startup.txt"
));
const EXPECTED_LAUNCH_ARGUMENTS: &str = "--headless=new --user-data-dir=<temporary-profile> --no-first-run --no-default-browser-check --disable-background-networking --disable-component-update --disable-default-apps --disable-quic --no-proxy-server --host-resolver-rules=MAP server.phantom.test 127.0.0.1, EXCLUDE localhost --ignore-certificate-errors --dump-dom";

#[tokio::test]
async fn chrome_fixture_retains_exact_metadata_and_startup_bytes() -> TestResult<()> {
    let fixture = Fixture::parse(FIXTURE_TEXT)?;
    assert_eq!(fixture.captured_at_unix, 1_789_486_120);
    assert_eq!(fixture.browser, "Google Chrome");
    assert_eq!(fixture.browser_version, "152.0.7977.83");
    assert_eq!(fixture.operating_system, "macOS 15.5 (24F74)");
    assert_eq!(fixture.listen_address, "127.0.0.1:9444".parse()?);
    assert_eq!(fixture.launch_mode, "command-line");
    assert_eq!(fixture.launch_arguments, EXPECTED_LAUNCH_ARGUMENTS);
    assert_eq!(fixture.peer_alps_state, "empty");
    assert_eq!(fixture.preface.len(), 24);
    assert_eq!(
        fixture.frames.iter().map(Vec::len).collect::<Vec<_>>(),
        [33, 13]
    );
    assert_eq!(
        fixture.initial_settings,
        "0x0001:65536,0x0002:0,0x0004:6291456,0x0006:262144"
    );
    assert_eq!(fixture.connection_window_update, 15_663_105);
    assert_raw_startup(&fixture).await
}

#[tokio::test]
async fn phantom_chrome_startup_matches_retained_browser_frames_exactly() -> TestResult<()> {
    let fixture = Fixture::parse(FIXTURE_TEXT)?;
    let settings = v152_macos_http2();
    let target = OriginForm::parse("/")?;
    let (client, mut server) = duplex(64 * 1024);
    let transaction = tokio::spawn(async move {
        send_get(client, &settings, "server.phantom.test", target, vec![])
            .await
            .map(drop)
    });

    let capture = capture_client_frames(
        &mut server,
        tokio::time::Instant::now() + TEST_TIMEOUT,
        fixture.limits,
        CaptureCompletion::InitialSettingsAndConnectionWindowUpdate,
    )
    .await?;
    assert_eq!(capture.preface_bytes(), &fixture.preface);
    assert_eq!(capture.frames().len(), fixture.frames.len());
    for (actual, expected) in capture.frames().iter().zip(&fixture.frames) {
        assert_eq!(actual.wire_bytes(), expected);
    }

    assert!(
        !transaction.is_finished(),
        "client completed before the captured peer was closed"
    );
    drop(server);
    let client_result = timeout(TEST_TIMEOUT, transaction).await??;
    assert!(matches!(client_result, Err(Http2Error::Protocol(_))));
    Ok(())
}
