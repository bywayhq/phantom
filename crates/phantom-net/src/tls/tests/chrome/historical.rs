use super::{TestResult, assert_recipe_matches_fixture};
use phantom_profile::browser::edge;

#[tokio::test]
async fn historical_edge_153_tcp_client_hello_matches_retained_capture() -> TestResult<()> {
    assert_recipe_matches_fixture(
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/tls/edge/153.0.4234.48/windows-11-26200/client-hello.txt"
        )),
        &edge::v153_tcp_tls(),
        None,
    )
    .await
}
