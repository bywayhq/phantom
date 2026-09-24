use phantom_profile::chromium::v154_http2;

use super::{
    TestResult, assert_public_startup_matches_fixture, assert_raw_startup, fixture::Fixture,
};

pub(super) const FIXTURE_TEXT: &str = include_str!(concat!(
    "../../../../fixtures/http2/chrome/154.0.8037.58/",
    "windows-11-26200/client-startup.txt"
));
const EDGE_153_FIXTURE_TEXT: &str = include_str!(concat!(
    "../../../../fixtures/http2/edge/153.0.4234.48/",
    "windows-11-26200/client-startup.txt"
));
const EXPECTED_LAUNCH_ARGUMENTS: &str = "--headless=new --user-data-dir=<temporary-profile> --no-first-run --no-default-browser-check --disable-background-networking --disable-component-update --disable-default-apps --disable-quic --no-proxy-server --host-resolver-rules=MAP server.phantom.test 127.0.0.1, EXCLUDE localhost --ignore-certificate-errors --dump-dom";

#[tokio::test]
async fn chrome_fixture_retains_exact_metadata_and_startup_bytes() -> TestResult<()> {
    let fixture = Fixture::parse(FIXTURE_TEXT)?;
    assert_eq!(fixture.captured_at_unix, 1_790_242_789);
    assert_eq!(fixture.browser, "Google Chrome");
    assert_eq!(fixture.browser_version, "154.0.8037.58");
    assert_eq!(fixture.operating_system, "Windows 11 Home 10.0.26200 x64");
    assert_eq!(fixture.listen_address, "127.0.0.1:55017".parse()?);
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
async fn chrome_154_http2_recipe_matches_windows_capture() -> TestResult<()> {
    let fixture = Fixture::parse(FIXTURE_TEXT)?;
    assert_public_startup_matches_fixture(&fixture, v154_http2()).await
}

/// Edge 153 has no separate HTTP/2 recipe: its startup equals the Chromium
/// recipe's, byte for byte.
#[tokio::test]
async fn chromium_http2_recipe_matches_windows_edge_capture() -> TestResult<()> {
    let fixture = Fixture::parse(EDGE_153_FIXTURE_TEXT)?;
    assert_eq!(fixture.browser, "Microsoft Edge");
    assert_eq!(fixture.browser_version, "153.0.4234.48");
    assert_eq!(fixture.launch_arguments, EXPECTED_LAUNCH_ARGUMENTS);
    assert_raw_startup(&fixture).await?;
    assert_public_startup_matches_fixture(&fixture, v154_http2()).await
}
