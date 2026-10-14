use phantom_profile::browser::edge;

use super::{
    TestResult, assert_public_startup_matches_fixture, assert_raw_startup, fixture::Fixture,
};

#[tokio::test]
async fn historical_edge_153_http2_startup_matches_retained_capture() -> TestResult<()> {
    let fixture = Fixture::parse(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/http2/edge/153.0.4234.48/windows-11-26200/client-startup.txt"
    )))?;
    assert_eq!(fixture.browser, "Microsoft Edge");
    assert_eq!(fixture.browser_version, "153.0.4234.48");
    assert_raw_startup(&fixture).await?;
    assert_public_startup_matches_fixture(&fixture, edge::v153_http2()).await
}
