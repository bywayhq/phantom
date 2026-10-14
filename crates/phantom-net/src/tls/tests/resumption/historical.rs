use phantom_profile::browser::edge;

use super::{
    EARLY_DATA, PRE_SHARED_KEY, TestResult, Tickets, assert_same_resumed_shape,
    fresh_and_resumed_client_hellos, resumed_client_hellos, without_grease,
};

#[tokio::test]
async fn historical_edge_153_resumed_tcp_offer_matches_retained_capture() -> TestResult<()> {
    let settings = edge::v153_tcp_tls();
    let (_, resumed) =
        fresh_and_resumed_client_hellos(&settings, Tickets::PermittingEarlyData).await?;
    let capture = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/tls/edge/153.0.4234.48/windows-11-26200/resumption-sequential.txt"
    ));
    let hellos = resumed_client_hellos(capture)?;
    assert!(!hellos.is_empty());
    for expected in hellos {
        assert_same_resumed_shape(resumed.handshake_bytes(), &expected, &settings)?;
    }
    let extensions = without_grease(resumed.summary()?.extension_types());
    assert_eq!(extensions.last(), Some(&PRE_SHARED_KEY));
    assert!(!extensions.contains(&EARLY_DATA));
    Ok(())
}
