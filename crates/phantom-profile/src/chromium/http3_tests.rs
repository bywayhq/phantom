use crate::{Http3Setting, Http3SettingOrder};

use super::v152_macos_http3;

const FIXTURE: &str =
    include_str!("../../../../fixtures/http3/chrome/152.0.7977.83/macos-15.5/client-startup.txt");

#[test]
fn v152_http3_settings_match_retained_control_stream() {
    let profile = v152_macos_http3();
    assert_eq!(profile.setting_order, Http3SettingOrder::Ascending);
    assert_eq!(
        profile.initial_settings,
        [
            Http3Setting::QpackMaxTableCapacity(fixture_value(0)),
            Http3Setting::MaxFieldSectionSize(fixture_value(1)),
            Http3Setting::QpackBlockedStreams(fixture_value(2)),
            Http3Setting::H3Datagram(fixture_value(3) == 1),
            Http3Setting::RandomizedGrease,
        ]
    );
}

fn fixture_value(index: usize) -> u64 {
    let prefix = format!("setting_{index}=");
    let line = FIXTURE
        .lines()
        .find(|line| line.starts_with(&prefix))
        .unwrap_or_else(|| panic!("fixture must contain {prefix}"));
    line.split(',')
        .find_map(|field| field.strip_prefix("value:"))
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| panic!("fixture setting value must be an integer"))
}
