use super::{
    GoogleConnectionOption, MAX_STREAM_COUNT, MAX_VARINT, QuicTransportGrease,
    QuicTransportParameter, QuicTransportParameterKind, QuicTransportParameterOrder,
    QuicTransportSettings, QuicVarIntWidth, QuicVersionGrease, QuicVersionInformation,
};

fn parameter(
    kind: QuicTransportParameterKind,
    id_width: QuicVarIntWidth,
    length_width: QuicVarIntWidth,
) -> QuicTransportParameter {
    QuicTransportParameter {
        kind,
        id_width,
        length_width,
    }
}

fn minimal_valid_settings() -> QuicTransportSettings {
    QuicTransportSettings {
        max_idle_timeout_ms: 0,
        max_udp_payload_size: 65_527,
        initial_max_data: 0,
        initial_max_stream_data_bidi_local: 0,
        initial_max_stream_data_bidi_remote: 0,
        initial_max_stream_data_uni: 0,
        initial_max_streams_bidi: 0,
        initial_max_streams_uni: 0,
        max_datagram_frame_size: None,
        wire_parameters: vec![parameter(
            QuicTransportParameterKind::InitialSourceConnectionId { length: 0 },
            QuicVarIntWidth::One,
            QuicVarIntWidth::One,
        )],
        parameter_order: QuicTransportParameterOrder::Fixed,
    }
}

fn validation_result(settings: &QuicTransportSettings) -> Result<(), &'static str> {
    settings.validate().map_err(|error| error.field())
}

#[test]
fn fixed_and_permuted_layouts_are_valid_profile_data() {
    let mut settings = minimal_valid_settings();
    assert_eq!(validation_result(&settings), Ok(()));

    settings.parameter_order = QuicTransportParameterOrder::Permuted;
    assert_eq!(validation_result(&settings), Ok(()));
}

#[test]
fn semantic_values_enforce_quic_limits() {
    let mut settings = minimal_valid_settings();
    settings.max_idle_timeout_ms = MAX_VARINT + 1;
    assert_eq!(validation_result(&settings), Err("max_idle_timeout_ms"));

    let mut settings = minimal_valid_settings();
    settings.initial_max_streams_uni = MAX_STREAM_COUNT + 1;
    assert_eq!(validation_result(&settings), Err("initial_max_streams_uni"));

    for invalid_size in [1_199, 65_528] {
        let mut settings = minimal_valid_settings();
        settings.max_udp_payload_size = invalid_size;
        assert_eq!(validation_result(&settings), Err("max_udp_payload_size"));
    }
}

#[test]
fn non_default_semantics_must_have_a_wire_entry() {
    let mut settings = minimal_valid_settings();
    settings.initial_max_data = 1;

    assert_eq!(validation_result(&settings), Err("wire_parameters"));
}

#[test]
fn parameter_kinds_must_not_repeat() {
    let mut settings = minimal_valid_settings();
    settings.wire_parameters.push(parameter(
        QuicTransportParameterKind::InitialSourceConnectionId { length: 0 },
        QuicVarIntWidth::One,
        QuicVarIntWidth::One,
    ));

    assert_eq!(validation_result(&settings), Err("wire_parameters"));
}

#[test]
fn runtime_owned_source_connection_id_marker_is_required() {
    let mut settings = minimal_valid_settings();
    settings.wire_parameters.remove(0);
    assert_eq!(validation_result(&settings), Err("wire_parameters"));
}

#[test]
fn explicit_varint_widths_must_fit_identifiers_and_values() {
    let mut settings = minimal_valid_settings();
    settings.wire_parameters.push(parameter(
        QuicTransportParameterKind::GoogleConnectionOptions(vec![
            GoogleConnectionOption::RequestOriginFrame,
        ]),
        QuicVarIntWidth::One,
        QuicVarIntWidth::One,
    ));
    assert_eq!(
        validation_result(&settings),
        Err("wire_parameters.id_width")
    );

    let mut settings = minimal_valid_settings();
    settings.initial_max_data = 64;
    settings.wire_parameters.push(parameter(
        QuicTransportParameterKind::InitialMaxData {
            value_width: QuicVarIntWidth::One,
        },
        QuicVarIntWidth::One,
        QuicVarIntWidth::One,
    ));
    assert_eq!(
        validation_result(&settings),
        Err("wire_parameters.value_width")
    );
}

#[test]
fn explicit_non_minimal_varint_widths_are_preserved() {
    let mut settings = minimal_valid_settings();
    settings.max_idle_timeout_ms = 42;
    settings.wire_parameters.push(parameter(
        QuicTransportParameterKind::MaxIdleTimeout {
            value_width: QuicVarIntWidth::Eight,
        },
        QuicVarIntWidth::Eight,
        QuicVarIntWidth::Eight,
    ));

    assert_eq!(validation_result(&settings), Ok(()));
    assert_eq!(QuicVarIntWidth::Eight.encoded_len(), 8);
    assert!(QuicVarIntWidth::Eight.can_encode(MAX_VARINT));
}

#[test]
fn datagram_semantics_and_wire_entry_are_consistent() {
    let mut settings = minimal_valid_settings();
    settings.max_datagram_frame_size = Some(65_536);
    assert_eq!(validation_result(&settings), Err("wire_parameters"));

    let mut settings = minimal_valid_settings();
    settings.wire_parameters.push(parameter(
        QuicTransportParameterKind::MaxDatagramFrameSize {
            value_width: QuicVarIntWidth::Four,
        },
        QuicVarIntWidth::One,
        QuicVarIntWidth::One,
    ));
    assert_eq!(validation_result(&settings), Err("wire_parameters"));
}

#[test]
fn google_connection_options_are_named_nonempty_and_unique() {
    for options in [
        Vec::new(),
        vec![
            GoogleConnectionOption::RequestOriginFrame,
            GoogleConnectionOption::RequestOriginFrame,
        ],
    ] {
        let mut settings = minimal_valid_settings();
        settings.wire_parameters.push(parameter(
            QuicTransportParameterKind::GoogleConnectionOptions(options),
            QuicVarIntWidth::Two,
            QuicVarIntWidth::One,
        ));
        assert_eq!(
            validation_result(&settings),
            Err("wire_parameters.google_connection_options")
        );
    }
}

#[test]
fn grease_payload_policy_is_bounded_to_captured_vocabulary() {
    for grease in [
        QuicTransportGrease {
            minimum_payload_length: 8,
            maximum_payload_length: 7,
        },
        QuicTransportGrease {
            minimum_payload_length: 0,
            maximum_payload_length: 16,
        },
    ] {
        let mut settings = minimal_valid_settings();
        settings.wire_parameters.push(parameter(
            QuicTransportParameterKind::Grease(grease),
            QuicVarIntWidth::Eight,
            QuicVarIntWidth::One,
        ));
        assert_eq!(validation_result(&settings), Err("wire_parameters.grease"));
    }
}

#[test]
fn version_information_keeps_versions_runtime_owned() {
    let mut settings = minimal_valid_settings();
    settings.wire_parameters.push(parameter(
        QuicTransportParameterKind::VersionInformation(QuicVersionInformation {
            available_version_count: 1,
            grease: QuicVersionGrease::Permuted,
        }),
        QuicVarIntWidth::One,
        QuicVarIntWidth::One,
    ));

    assert_eq!(validation_result(&settings), Ok(()));
}

#[test]
fn source_connection_id_length_is_explicit_and_bounded() {
    let mut settings = minimal_valid_settings();
    settings.wire_parameters[0].kind =
        QuicTransportParameterKind::InitialSourceConnectionId { length: 20 };
    assert_eq!(validation_result(&settings), Ok(()));

    settings.wire_parameters[0].kind =
        QuicTransportParameterKind::InitialSourceConnectionId { length: 21 };
    assert_eq!(
        validation_result(&settings),
        Err("wire_parameters.initial_source_connection_id")
    );
}

#[test]
fn version_information_requires_the_chosen_version_in_available_versions() {
    let mut settings = minimal_valid_settings();
    settings.wire_parameters.push(parameter(
        QuicTransportParameterKind::VersionInformation(QuicVersionInformation {
            available_version_count: 0,
            grease: QuicVersionGrease::Omit,
        }),
        QuicVarIntWidth::One,
        QuicVarIntWidth::One,
    ));

    assert_eq!(
        validation_result(&settings),
        Err("wire_parameters.version_information")
    );
}
