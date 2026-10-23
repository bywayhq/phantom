use phantom_profile::{
    browser,
    catalog::{ProfileLayer, profile},
};

use super::{TestResult, field};

const CAPTURES: [&str; 2] = [
    include_str!(
        "../../../../../fixtures/socket-hooks/chrome/156.0.8078.48/windows-11-26200/hooks-single.txt"
    ),
    include_str!(
        "../../../../../fixtures/socket-hooks/chrome/156.0.8078.48/windows-11-26200/hooks-parallel.txt"
    ),
];

#[test]
fn windows156_udp_randomization_matches_headed_and_headless_socket_calls() -> TestResult {
    let selected = profile("chrome-156-windows")?.instantiate(&[ProfileLayer::Udp])?;
    assert_eq!(selected, browser::chrome::v156_windows());
    let settings = selected.udp().ok_or("missing UDP settings")?;

    for capture in CAPTURES {
        assert_eq!(field(capture, "browser_version")?, "156.0.8078.48");
        assert_eq!(field(capture, "hook_intervention")?, "none");
        assert_eq!(field(capture, "run_0_hook_error_count")?, "0");
        assert_eq!(field(capture, "run_0_timed_out")?, "false");
        let mut observed_randomization = false;
        for (name, value) in capture.lines().filter_map(|line| line.split_once('=')) {
            if !name.starts_with("run_0_udp_option_set_") {
                continue;
            }
            let (_, options) = value.split_once("x ").ok_or("missing UDP option count")?;
            observed_randomization |= options
                .split(',')
                .any(|option| option == "SO_RANDOMIZE_PORT=1");
        }
        assert!(
            observed_randomization,
            "capture has no randomized UDP socket"
        );
        assert_eq!(settings.port_randomization, observed_randomization);
    }
    Ok(())
}
