use phantom_profile::browser::edge;

use super::{
    TestResult, capture_seeded_control_stream, encoded_settings_prefix, grease_entropy,
    is_reserved_setting, parse_encoded_settings, settings_payload,
};

#[tokio::test(flavor = "current_thread")]
async fn historical_edge_153_http3_control_stream_matches_retained_capture() -> TestResult<()> {
    let startup = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/http3/edge/153.0.4234.48/windows-11-26200/client-startup.txt"
    ));
    let expected = super::super::connector::fixture_hex(startup, "control_stream_prefix_hex")?;
    let prefix =
        capture_seeded_control_stream(&edge::v153_http3(), grease_entropy(u32::MAX, u32::MAX))
            .await?;
    let (expected_offset, expected_payload) = settings_payload(&expected)?;
    let (actual_offset, actual_payload) = settings_payload(&prefix)?;
    assert_eq!(&prefix[..2], &expected[..2]);
    assert_eq!(actual_offset, expected_offset);
    assert_eq!(
        encoded_settings_prefix(actual_payload, 4)?,
        encoded_settings_prefix(expected_payload, 4)?
    );

    let stable = |entries: Vec<(u64, usize, u64, usize)>| {
        entries
            .into_iter()
            .filter(|entry| !is_reserved_setting(entry.0))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        stable(parse_encoded_settings(&prefix)?),
        stable(parse_encoded_settings(&expected)?)
    );
    let entries = parse_encoded_settings(&prefix)?;
    let reserved = entries
        .into_iter()
        .filter(|entry| is_reserved_setting(entry.0))
        .collect::<Vec<_>>();
    assert_eq!(reserved.len(), 1);
    assert_eq!((reserved[0].1, reserved[0].3), (8, 8));
    Ok(())
}
