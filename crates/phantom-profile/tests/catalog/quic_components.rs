//! QUIC factory values frozen before replacement at f2cbd3a8657d63df34d7b5f01b3025e94a2f7744.

use phantom_profile::{
    GoogleConnectionOption, QuicAckFrequencyDraft, QuicConnectionIdLength, QuicTransportGrease,
    QuicTransportParameter, QuicTransportParameterKind, QuicTransportParameterOrder,
    QuicTransportSettings, QuicVarIntWidth, QuicVersionGrease, QuicVersionInformation, browser,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
#[test]
fn browser_quic_factories_preserve_every_stored_field() -> TestResult {
    for (actual, expected) in [
        (browser::chrome::v154_quic(), chrome_original()),
        (browser::firefox::v157_quic(), firefox_original()),
    ] {
        actual.validate()?;
        expected.validate()?;
        assert_eq!(actual, expected);
    }
    Ok(())
}
#[test]
fn composed_recipes_preserve_quic_policies_and_fresh_ownership() -> TestResult {
    for profile in [
        browser::chrome::v154_windows(),
        browser::chrome::v154_android(),
        browser::edge::v154_windows(),
        browser::edge::v153_android(),
        browser::brave::v154_windows(),
        browser::brave::v153_android(),
        browser::opera::v136_windows(),
    ] {
        assert_eq!(
            *profile
                .http3()
                .ok_or("composed recipe lost HTTP/3")?
                .quic_transport(),
            chrome_original()
        );
    }
    let profile = browser::firefox::v157_windows();
    assert_eq!(
        *profile
            .http3()
            .ok_or("Firefox lost HTTP/3")?
            .quic_transport(),
        firefox_original()
    );
    for (mut changed, fresh, original) in [
        (
            browser::chrome::v154_quic(),
            browser::chrome::v154_quic(),
            chrome_original(),
        ),
        (
            browser::firefox::v157_quic(),
            browser::firefox::v157_quic(),
            firefox_original(),
        ),
    ] {
        changed.wire_parameters.reverse();
        changed.early_data = false;
        assert_eq!(fresh, original);
    }
    Ok(())
}
fn chrome_original() -> QuicTransportSettings {
    use QuicTransportParameterKind as Kind;
    use QuicVarIntWidth::{Eight, Four, One, Two};

    let parameter = |kind, id_width, length_width| QuicTransportParameter {
        kind,
        id_width,
        length_width,
    };

    QuicTransportSettings {
        max_idle_timeout_ms: 30_000,
        max_udp_payload_size: 1_472,
        initial_max_data: 15_728_640,
        initial_max_stream_data_bidi_local: 6_291_456,
        initial_max_stream_data_bidi_remote: 6_291_456,
        initial_max_stream_data_uni: 6_291_456,
        initial_max_streams_bidi: 100,
        initial_max_streams_uni: 103,
        max_datagram_frame_size: Some(65_536),
        max_ack_delay_ms: 25,
        active_connection_id_limit: 2,
        min_ack_delay_us: None,
        reset_stream_at: false,
        initial_path_mtu: None,
        initial_destination_connection_id: None,
        wire_parameters: vec![
            parameter(Kind::InitialMaxStreamsBidi { value_width: Two }, One, One),
            parameter(
                Kind::InitialMaxStreamDataUni { value_width: Four },
                One,
                One,
            ),
            parameter(
                Kind::VersionInformation(QuicVersionInformation {
                    available_version_count: 1,
                    grease: QuicVersionGrease::Permuted,
                }),
                One,
                One,
            ),
            parameter(Kind::InitialMaxData { value_width: Four }, One, One),
            parameter(Kind::InitialMaxStreamsUni { value_width: Two }, One, One),
            parameter(
                Kind::InitialMaxStreamDataBidiRemote { value_width: Four },
                One,
                One,
            ),
            parameter(Kind::MaxIdleTimeout { value_width: Four }, One, One),
            parameter(
                Kind::GoogleConnectionOptions(vec![GoogleConnectionOption::RequestOriginFrame]),
                Two,
                One,
            ),
            parameter(Kind::MaxDatagramFrameSize { value_width: Four }, One, One),
            parameter(
                Kind::Grease(QuicTransportGrease {
                    minimum_payload_length: 0,
                    maximum_payload_length: 15,
                }),
                Eight,
                One,
            ),
            parameter(Kind::MaxUdpPayloadSize { value_width: Two }, One, One),
            parameter(
                Kind::InitialMaxStreamDataBidiLocal { value_width: Four },
                One,
                One,
            ),
            parameter(Kind::InitialSourceConnectionId { length: 0 }, One, One),
            parameter(Kind::InitialRtt, Two, One),
        ],
        parameter_order: QuicTransportParameterOrder::Permuted,
        early_data: true,
    }
}

fn firefox_original() -> QuicTransportSettings {
    use QuicTransportParameterKind as Kind;
    use QuicVarIntWidth::{Eight, Four, One, Two};

    let parameter = |kind, id_width| QuicTransportParameter {
        kind,
        id_width,
        length_width: One,
    };

    QuicTransportSettings {
        max_idle_timeout_ms: 30_000,
        max_udp_payload_size: 65_527,
        initial_max_data: 25_165_824,
        initial_max_stream_data_bidi_local: 12_582_912,
        initial_max_stream_data_bidi_remote: 1_048_576,
        initial_max_stream_data_uni: 1_048_576,
        initial_max_streams_bidi: 100,
        initial_max_streams_uni: 100,
        max_datagram_frame_size: Some(65_535),
        max_ack_delay_ms: 20,
        active_connection_id_limit: 8,
        min_ack_delay_us: Some(1_000),
        reset_stream_at: true,
        initial_path_mtu: Some(1_280),
        initial_destination_connection_id: Some(QuicConnectionIdLength::MaskedRandom {
            minimum: 8,
            base: 5,
        }),
        wire_parameters: vec![
            parameter(Kind::MaxIdleTimeout { value_width: Four }, One),
            parameter(Kind::InitialMaxData { value_width: Four }, One),
            parameter(
                Kind::InitialMaxStreamDataBidiLocal { value_width: Four },
                One,
            ),
            parameter(
                Kind::InitialMaxStreamDataBidiRemote { value_width: Four },
                One,
            ),
            parameter(Kind::InitialMaxStreamDataUni { value_width: Four }, One),
            parameter(Kind::InitialMaxStreamsBidi { value_width: Two }, One),
            parameter(Kind::InitialMaxStreamsUni { value_width: Two }, One),
            parameter(Kind::MaxAckDelay { value_width: One }, One),
            parameter(Kind::ActiveConnectionIdLimit { value_width: One }, One),
            parameter(Kind::InitialSourceConnectionId { length: 3 }, One),
            parameter(
                Kind::VersionInformation(QuicVersionInformation {
                    available_version_count: 2,
                    grease: QuicVersionGrease::First,
                }),
                One,
            ),
            parameter(Kind::ResetStreamAt, One),
            parameter(
                Kind::MinAckDelay {
                    draft: QuicAckFrequencyDraft::Draft02,
                    value_width: Two,
                },
                Eight,
            ),
            parameter(Kind::MaxDatagramFrameSize { value_width: Four }, One),
        ],
        parameter_order: QuicTransportParameterOrder::Fixed,
        early_data: true,
    }
}
