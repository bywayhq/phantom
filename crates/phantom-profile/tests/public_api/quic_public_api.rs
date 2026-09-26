//! Public QUIC profile construction checks.

use phantom_profile::quic::{
    QuicTransportParameter, QuicTransportParameterKind, QuicTransportParameterOrder,
    QuicTransportSettings, QuicVarIntWidth,
};

#[test]
fn downstream_code_can_build_a_custom_quic_profile() {
    let settings = QuicTransportSettings {
        max_idle_timeout_ms: 0,
        max_udp_payload_size: 65_527,
        initial_max_data: 0,
        initial_max_stream_data_bidi_local: 0,
        initial_max_stream_data_bidi_remote: 0,
        initial_max_stream_data_uni: 0,
        initial_max_streams_bidi: 0,
        initial_max_streams_uni: 0,
        max_datagram_frame_size: None,
        wire_parameters: vec![QuicTransportParameter {
            kind: QuicTransportParameterKind::InitialSourceConnectionId { length: 0 },
            id_width: QuicVarIntWidth::One,
            length_width: QuicVarIntWidth::One,
        }],
        parameter_order: QuicTransportParameterOrder::Fixed,
        early_data: false,
    };

    assert!(settings.validate().is_ok());
}
