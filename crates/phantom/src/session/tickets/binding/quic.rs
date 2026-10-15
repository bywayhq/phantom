use phantom_profile::{
    GoogleConnectionOption, QuicAckFrequencyDraft, QuicTransportParameterOrder, QuicVarIntWidth,
    QuicVersionGrease,
};

use super::{PreparationError, encoding::Encoder};

fn quic_var_int_width(e: &mut Encoder, value: &QuicVarIntWidth) -> Result<(), PreparationError> {
    e.u8(match value {
        QuicVarIntWidth::One => 0,
        QuicVarIntWidth::Two => 1,
        QuicVarIntWidth::Four => 2,
        QuicVarIntWidth::Eight => 3,
        _ => return Err(PreparationError::Unsupported("QuicVarIntWidth")),
    })
}

fn quic_transport_parameter_order(
    e: &mut Encoder,
    value: &QuicTransportParameterOrder,
) -> Result<(), PreparationError> {
    e.u8(match value {
        QuicTransportParameterOrder::Fixed => 0,
        QuicTransportParameterOrder::Permuted => 1,
        _ => return Err(PreparationError::Unsupported("QuicTransportParameterOrder")),
    })
}

fn quic_version_grease(e: &mut Encoder, value: &QuicVersionGrease) -> Result<(), PreparationError> {
    e.u8(match value {
        QuicVersionGrease::Omit => 0,
        QuicVersionGrease::Permuted => 1,
        QuicVersionGrease::First => 2,
        _ => return Err(PreparationError::Unsupported("QuicVersionGrease")),
    })
}

fn quic_ack_frequency_draft(
    e: &mut Encoder,
    value: &QuicAckFrequencyDraft,
) -> Result<(), PreparationError> {
    e.u8(match value {
        QuicAckFrequencyDraft::Draft02 => 0,
        QuicAckFrequencyDraft::Draft07 => 1,
        _ => return Err(PreparationError::Unsupported("QuicAckFrequencyDraft")),
    })
}

fn google_connection_option(
    e: &mut Encoder,
    value: &GoogleConnectionOption,
) -> Result<(), PreparationError> {
    e.u8(match value {
        GoogleConnectionOption::RequestOriginFrame => 0,
        _ => return Err(PreparationError::Unsupported("GoogleConnectionOption")),
    })
}
use phantom_profile::{
    QuicConnectionIdLength, QuicTransportGrease, QuicTransportParameter,
    QuicTransportParameterKind, QuicTransportSettings, QuicVersionInformation,
};

pub(super) fn encode(
    e: &mut Encoder,
    value: &QuicTransportSettings,
) -> Result<(), PreparationError> {
    let QuicTransportSettings {
        max_idle_timeout_ms,
        max_udp_payload_size,
        initial_max_data,
        initial_max_stream_data_bidi_local,
        initial_max_stream_data_bidi_remote,
        initial_max_stream_data_uni,
        initial_max_streams_bidi,
        initial_max_streams_uni,
        max_datagram_frame_size,
        max_ack_delay_ms,
        active_connection_id_limit,
        min_ack_delay_us,
        reset_stream_at,
        initial_path_mtu,
        initial_destination_connection_id,
        wire_parameters,
        parameter_order,
        early_data,
    } = value;
    e.u64(*max_idle_timeout_ms)?;
    e.u64(*max_udp_payload_size)?;
    e.u64(*initial_max_data)?;
    e.u64(*initial_max_stream_data_bidi_local)?;
    e.u64(*initial_max_stream_data_bidi_remote)?;
    e.u64(*initial_max_stream_data_uni)?;
    e.u64(*initial_max_streams_bidi)?;
    e.u64(*initial_max_streams_uni)?;
    e.option(max_datagram_frame_size.as_ref(), |e, value| e.u64(*value))?;
    e.u64(*max_ack_delay_ms)?;
    e.u64(*active_connection_id_limit)?;
    e.option(min_ack_delay_us.as_ref(), |e, value| e.u64(*value))?;
    e.bool(*reset_stream_at)?;
    e.option(initial_path_mtu.as_ref(), |e, value| e.u16(*value))?;
    e.option(initial_destination_connection_id.as_ref(), encode_cid)?;
    e.list(wire_parameters, |e, value| {
        let QuicTransportParameter {
            kind,
            id_width,
            length_width,
        } = value;
        encode_parameter(e, kind)?;
        quic_var_int_width(e, id_width)?;
        quic_var_int_width(e, length_width)
    })?;
    quic_transport_parameter_order(e, parameter_order)?;
    e.bool(*early_data)
}

fn encode_cid(e: &mut Encoder, value: &QuicConnectionIdLength) -> Result<(), PreparationError> {
    match value {
        QuicConnectionIdLength::Fixed(length) => {
            e.u8(0)?;
            e.u8(*length)
        }
        QuicConnectionIdLength::MaskedRandom { minimum, base } => {
            e.u8(1)?;
            e.u8(*minimum)?;
            e.u8(*base)
        }
        _ => Err(PreparationError::Unsupported("initial_cid")),
    }
}

fn encode_parameter(
    e: &mut Encoder,
    value: &QuicTransportParameterKind,
) -> Result<(), PreparationError> {
    match value {
        QuicTransportParameterKind::MaxIdleTimeout { value_width } => {
            e.u8(0)?;
            quic_var_int_width(e, value_width)
        }
        QuicTransportParameterKind::MaxUdpPayloadSize { value_width } => {
            e.u8(1)?;
            quic_var_int_width(e, value_width)
        }
        QuicTransportParameterKind::InitialMaxData { value_width } => {
            e.u8(2)?;
            quic_var_int_width(e, value_width)
        }
        QuicTransportParameterKind::InitialMaxStreamDataBidiLocal { value_width } => {
            e.u8(3)?;
            quic_var_int_width(e, value_width)
        }
        QuicTransportParameterKind::InitialMaxStreamDataBidiRemote { value_width } => {
            e.u8(4)?;
            quic_var_int_width(e, value_width)
        }
        QuicTransportParameterKind::InitialMaxStreamDataUni { value_width } => {
            e.u8(5)?;
            quic_var_int_width(e, value_width)
        }
        QuicTransportParameterKind::InitialMaxStreamsBidi { value_width } => {
            e.u8(6)?;
            quic_var_int_width(e, value_width)
        }
        QuicTransportParameterKind::InitialMaxStreamsUni { value_width } => {
            e.u8(7)?;
            quic_var_int_width(e, value_width)
        }
        QuicTransportParameterKind::MaxAckDelay { value_width } => {
            e.u8(8)?;
            quic_var_int_width(e, value_width)
        }
        QuicTransportParameterKind::ActiveConnectionIdLimit { value_width } => {
            e.u8(9)?;
            quic_var_int_width(e, value_width)
        }
        QuicTransportParameterKind::MaxDatagramFrameSize { value_width } => {
            e.u8(10)?;
            quic_var_int_width(e, value_width)
        }
        QuicTransportParameterKind::InitialSourceConnectionId { length } => {
            e.u8(11)?;
            e.u8(*length)
        }
        QuicTransportParameterKind::VersionInformation(value) => {
            let QuicVersionInformation {
                available_version_count,
                grease,
            } = value;
            e.u8(12)?;
            e.u8(*available_version_count)?;
            quic_version_grease(e, grease)
        }
        QuicTransportParameterKind::ResetStreamAt => e.u8(13),
        QuicTransportParameterKind::MinAckDelay { draft, value_width } => {
            e.u8(14)?;
            quic_ack_frequency_draft(e, draft)?;
            quic_var_int_width(e, value_width)
        }
        QuicTransportParameterKind::GoogleConnectionOptions(options) => {
            e.u8(15)?;
            e.list(options, google_connection_option)
        }
        QuicTransportParameterKind::InitialRtt => e.u8(16),
        QuicTransportParameterKind::Grease(value) => {
            let QuicTransportGrease {
                minimum_payload_length,
                maximum_payload_length,
            } = value;
            e.u8(17)?;
            e.u8(*minimum_payload_length)?;
            e.u8(*maximum_payload_length)
        }
        _ => Err(PreparationError::Unsupported("quic_parameter")),
    }
}
