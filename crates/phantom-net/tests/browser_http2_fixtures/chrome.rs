use phantom_profile::chromium::v152_macos_http2;

use super::{
    TestResult, assert_public_startup_matches_fixture, assert_raw_startup, fixture::Fixture,
};

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
    assert_public_startup_matches_fixture(&fixture, v152_macos_http2()).await
}
