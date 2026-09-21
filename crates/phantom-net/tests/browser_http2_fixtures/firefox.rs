use phantom_profile::firefox::v154_macos_http2;

use super::{
    TestResult, assert_public_startup_matches_fixture, assert_raw_startup, fixture::Fixture,
};

const FIXTURE_TEXT: &str = include_str!(concat!(
    "../../../../fixtures/http2/firefox/154.0/",
    "macos-15.5/client-startup.txt"
));

#[tokio::test]
async fn firefox_154_fixture_retains_exact_metadata_and_startup_bytes() -> TestResult<()> {
    let fixture = Fixture::parse(FIXTURE_TEXT)?;
    assert_eq!(fixture.captured_at_unix, 1_789_498_021);
    assert_eq!(fixture.browser, "Mozilla Firefox");
    assert_eq!(fixture.browser_version, "154.0");
    assert_eq!(fixture.operating_system, "macOS 15.5 (24F74)");
    assert_eq!(fixture.listen_address, "127.0.0.1:9448".parse()?);
    assert_eq!(fixture.launch_mode, "WebDriver");
    assert_eq!(fixture.launch_arguments, "--headless");
    assert_eq!(fixture.peer_alps_state, "absent");
    assert_eq!(fixture.preface.len(), 24);
    assert_eq!(
        fixture.frames.iter().map(Vec::len).collect::<Vec<_>>(),
        [33, 13]
    );
    assert_eq!(
        fixture.initial_settings,
        "0x0001:65536,0x0002:0,0x0004:131072,0x0005:16384"
    );
    assert_eq!(fixture.connection_window_update, 12_517_377);
    assert_raw_startup(&fixture).await
}

#[tokio::test]
async fn phantom_firefox_startup_matches_retained_browser_frames_exactly() -> TestResult<()> {
    let fixture = Fixture::parse(FIXTURE_TEXT)?;

    // The local fixture ends before request HEADERS. Firefox pseudo-header
    // order and priority remain separate, supplemental profile evidence.
    assert_public_startup_matches_fixture(&fixture, v154_macos_http2()).await
}

const WINDOWS_FIXTURE_TEXT: &str = include_str!(concat!(
    "../../../../fixtures/http2/firefox/154.0/",
    "windows-11-26200/client-startup.txt"
));

#[tokio::test]
async fn firefox_154_http2_recipe_matches_windows_capture() -> TestResult<()> {
    let fixture = Fixture::parse(WINDOWS_FIXTURE_TEXT)?;
    assert_raw_startup(&fixture).await?;
    assert_public_startup_matches_fixture(&fixture, v154_macos_http2()).await
}
