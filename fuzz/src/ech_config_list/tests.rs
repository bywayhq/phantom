//! Deterministic regressions for the `ECHConfigList` harness.

use phantom_net::dns::EchConfigListErrorKind;

use super::{LIST, drive, exercise};

/// The embedded list must keep parsing into its two configurations, or the
/// perturbed inputs would all fail at the length check.
#[test]
fn structural_seed_parses_into_both_configurations() {
    let configs = drive(LIST).expect("the structural seed must parse");
    assert_eq!(configs.len(), 2);
    assert!(configs[0].is_supported());
    assert_eq!(configs[0].config_id(), Some(7));
    assert_eq!(configs[0].public_name(), Some(&b"a.test"[..]));
    assert_eq!(configs[0].extensions().len(), 1);
    assert_eq!(configs[1].version(), 0xfe0a);
    assert!(!configs[1].is_supported());
}

#[test]
fn truncated_seed_is_rejected() {
    let error = drive(&LIST[..LIST.len() - 1]).expect_err("a truncated list must fail");
    assert_eq!(error.kind(), EchConfigListErrorKind::ListLength);
}

#[test]
fn harness_accepts_empty_and_arbitrary_inputs() {
    exercise(&[]);
    exercise(&[0xff; 7]);
    exercise(LIST);
}
