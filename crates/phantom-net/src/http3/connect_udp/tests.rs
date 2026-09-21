use super::{
    ConnectUdpErrorKind, MIN_OUTER_DATAGRAM_FRAME_SIZE, OUTER_PATH_MTU, OuterProfile,
    validate_outer_profile,
};

fn chrome_like_outer() -> OuterProfile {
    OuterProfile {
        receives_http_datagrams: true,
        max_datagram_frame_size: Some(65_536),
        max_udp_payload_size: 1_472,
    }
}

#[test]
fn outer_mtu_fits_a_full_inner_initial_with_worst_case_packet_overhead() {
    // 1200-byte Initial + Quarter Stream ID 0 + Context ID 0, plus 1 flag byte,
    // a 20-byte DCID, a 4-byte packet number, a 16-byte tag, and Quinn's
    // 9-byte DATAGRAM frame bound.
    assert_eq!(OUTER_PATH_MTU, 1252);
    assert_eq!(MIN_OUTER_DATAGRAM_FRAME_SIZE, 1205);
    assert!(validate_outer_profile(&chrome_like_outer()).is_ok());
}

#[test]
fn outer_profiles_that_cannot_fit_an_initial_are_configuration_errors() {
    let mut without_setting = chrome_like_outer();
    without_setting.receives_http_datagrams = false;
    let mut without_frames = chrome_like_outer();
    without_frames.max_datagram_frame_size = None;
    let mut small_frames = chrome_like_outer();
    small_frames.max_datagram_frame_size = Some(MIN_OUTER_DATAGRAM_FRAME_SIZE - 1);
    let mut small_payloads = chrome_like_outer();
    small_payloads.max_udp_payload_size = u64::from(OUTER_PATH_MTU) - 1;

    for profile in [
        without_setting,
        without_frames,
        small_frames,
        small_payloads,
    ] {
        let error = validate_outer_profile(&profile)
            .err()
            .map(|error| error.kind());
        assert_eq!(error, Some(ConnectUdpErrorKind::Configuration));
    }

    let mut smallest = chrome_like_outer();
    smallest.max_datagram_frame_size = Some(MIN_OUTER_DATAGRAM_FRAME_SIZE);
    smallest.max_udp_payload_size = u64::from(OUTER_PATH_MTU);
    assert!(validate_outer_profile(&smallest).is_ok());
}
