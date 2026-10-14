//! Complete QUIC policies and ordered parameter parsing.

use super::{
    FingerprintImportError, Result,
    json::{self, Value},
};
use phantom_profile::{
    GoogleConnectionOption, QuicAckFrequencyDraft, QuicConnectionIdLength, QuicTransportGrease,
    QuicTransportParameter, QuicTransportParameterKind, QuicTransportParameterOrder,
    QuicTransportSettings, QuicVarIntWidth, QuicVersionGrease, QuicVersionInformation,
};

pub(super) fn parse(v: &Value) -> Result<QuicTransportSettings> {
    v.record(
        &[
            "max_idle_timeout_ms",
            "max_udp_payload_size",
            "initial_max_data",
            "initial_max_stream_data_bidi_local",
            "initial_max_stream_data_bidi_remote",
            "initial_max_stream_data_uni",
            "initial_max_streams_bidi",
            "initial_max_streams_uni",
            "max_datagram_frame_size",
            "max_ack_delay_ms",
            "active_connection_id_limit",
            "min_ack_delay_us",
            "reset_stream_at",
            "initial_path_mtu",
            "initial_destination_connection_id",
            "wire_parameters",
            "parameter_order",
            "early_data",
        ],
        "http3.quic_transport",
    )?;
    let settings = QuicTransportSettings {
        max_idle_timeout_ms: v
            .member(
                "max_idle_timeout_ms",
                "http3.quic_transport.max_idle_timeout_ms",
            )?
            .integer("http3.quic_transport.max_idle_timeout_ms")?,
        max_udp_payload_size: v
            .member(
                "max_udp_payload_size",
                "http3.quic_transport.max_udp_payload_size",
            )?
            .integer("http3.quic_transport.max_udp_payload_size")?,
        initial_max_data: v
            .member("initial_max_data", "http3.quic_transport.initial_max_data")?
            .integer("http3.quic_transport.initial_max_data")?,
        initial_max_stream_data_bidi_local: v
            .member(
                "initial_max_stream_data_bidi_local",
                "http3.quic_transport.initial_max_stream_data_bidi_local",
            )?
            .integer("http3.quic_transport.initial_max_stream_data_bidi_local")?,
        initial_max_stream_data_bidi_remote: v
            .member(
                "initial_max_stream_data_bidi_remote",
                "http3.quic_transport.initial_max_stream_data_bidi_remote",
            )?
            .integer("http3.quic_transport.initial_max_stream_data_bidi_remote")?,
        initial_max_stream_data_uni: v
            .member(
                "initial_max_stream_data_uni",
                "http3.quic_transport.initial_max_stream_data_uni",
            )?
            .integer("http3.quic_transport.initial_max_stream_data_uni")?,
        initial_max_streams_bidi: v
            .member(
                "initial_max_streams_bidi",
                "http3.quic_transport.initial_max_streams_bidi",
            )?
            .integer("http3.quic_transport.initial_max_streams_bidi")?,
        initial_max_streams_uni: v
            .member(
                "initial_max_streams_uni",
                "http3.quic_transport.initial_max_streams_uni",
            )?
            .integer("http3.quic_transport.initial_max_streams_uni")?,
        max_datagram_frame_size: v
            .member(
                "max_datagram_frame_size",
                "http3.quic_transport.max_datagram_frame_size",
            )?
            .optional(|v| v.integer("http3.quic_transport.max_datagram_frame_size"))?,
        max_ack_delay_ms: v
            .member("max_ack_delay_ms", "http3.quic_transport.max_ack_delay_ms")?
            .integer("http3.quic_transport.max_ack_delay_ms")?,
        active_connection_id_limit: v
            .member(
                "active_connection_id_limit",
                "http3.quic_transport.active_connection_id_limit",
            )?
            .integer("http3.quic_transport.active_connection_id_limit")?,
        min_ack_delay_us: v
            .member("min_ack_delay_us", "http3.quic_transport.min_ack_delay_us")?
            .optional(|v| v.integer("http3.quic_transport.min_ack_delay_us"))?,
        reset_stream_at: v
            .member("reset_stream_at", "http3.quic_transport.reset_stream_at")?
            .boolean("http3.quic_transport.reset_stream_at")?,
        initial_path_mtu: v
            .member("initial_path_mtu", "http3.quic_transport.initial_path_mtu")?
            .optional(|v| v.integer("http3.quic_transport.initial_path_mtu"))?,
        initial_destination_connection_id: v
            .member(
                "initial_destination_connection_id",
                "http3.quic_transport.initial_destination_connection_id",
            )?
            .optional(cid)?,
        wire_parameters: v
            .member("wire_parameters", "http3.quic_transport.wire_parameters")?
            .list("http3.quic_transport.wire_parameters", parameter)?,
        parameter_order: order(
            v.member("parameter_order", "http3.quic_transport.parameter_order")?,
        )?,
        early_data: v
            .member("early_data", "http3.quic_transport.early_data")?
            .boolean("http3.quic_transport.early_data")?,
    };
    settings
        .validate()
        .map_err(|error| FingerprintImportError::native("http3.quic_transport", error))?;
    Ok(settings)
}

fn width(v: &Value) -> Result<QuicVarIntWidth> {
    match v.text("http3.quic_transport.wire_parameters.width")? {
        "One" => Ok(QuicVarIntWidth::One),
        "Two" => Ok(QuicVarIntWidth::Two),
        "Four" => Ok(QuicVarIntWidth::Four),
        "Eight" => Ok(QuicVarIntWidth::Eight),
        _ => Err(json::unsupported(
            "http3.quic_transport.wire_parameters.width",
        )),
    }
}

fn order(v: &Value) -> Result<QuicTransportParameterOrder> {
    match v.text("http3.quic_transport.parameter_order")? {
        "Fixed" => Ok(QuicTransportParameterOrder::Fixed),
        "Permuted" => Ok(QuicTransportParameterOrder::Permuted),
        _ => Err(json::unsupported("http3.quic_transport.parameter_order")),
    }
}

fn draft(v: &Value) -> Result<QuicAckFrequencyDraft> {
    match v.text("http3.quic_transport.wire_parameters.draft")? {
        "Draft02" => Ok(QuicAckFrequencyDraft::Draft02),
        "Draft07" => Ok(QuicAckFrequencyDraft::Draft07),
        _ => Err(json::unsupported(
            "http3.quic_transport.wire_parameters.draft",
        )),
    }
}

fn grease(v: &Value) -> Result<QuicVersionGrease> {
    match v.text("http3.quic_transport.wire_parameters.grease")? {
        "Omit" => Ok(QuicVersionGrease::Omit),
        "Permuted" => Ok(QuicVersionGrease::Permuted),
        "First" => Ok(QuicVersionGrease::First),
        _ => Err(json::unsupported(
            "http3.quic_transport.wire_parameters.grease",
        )),
    }
}

fn google(v: &Value) -> Result<GoogleConnectionOption> {
    match v.text("http3.quic_transport.wire_parameters.options")? {
        "RequestOriginFrame" => Ok(GoogleConnectionOption::RequestOriginFrame),
        _ => Err(json::unsupported(
            "http3.quic_transport.wire_parameters.options",
        )),
    }
}

fn cid(v: &Value) -> Result<QuicConnectionIdLength> {
    match v
        .member(
            "kind",
            "http3.quic_transport.initial_destination_connection_id.kind",
        )?
        .text("http3.quic_transport.initial_destination_connection_id.kind")?
    {
        "Fixed" => {
            v.record(
                &["kind", "length"],
                "http3.quic_transport.initial_destination_connection_id",
            )?;
            Ok(QuicConnectionIdLength::Fixed(
                v.member(
                    "length",
                    "http3.quic_transport.initial_destination_connection_id.length",
                )?
                .integer("http3.quic_transport.initial_destination_connection_id.length")?,
            ))
        }
        "MaskedRandom" => {
            v.record(
                &["kind", "minimum", "base"],
                "http3.quic_transport.initial_destination_connection_id",
            )?;
            Ok(QuicConnectionIdLength::MaskedRandom {
                minimum: v
                    .member(
                        "minimum",
                        "http3.quic_transport.initial_destination_connection_id.minimum",
                    )?
                    .integer("http3.quic_transport.initial_destination_connection_id.minimum")?,
                base: v
                    .member(
                        "base",
                        "http3.quic_transport.initial_destination_connection_id.base",
                    )?
                    .integer("http3.quic_transport.initial_destination_connection_id.base")?,
            })
        }
        _ => Err(json::unsupported(
            "http3.quic_transport.initial_destination_connection_id.kind",
        )),
    }
}
fn parameter(v: &Value) -> Result<QuicTransportParameter> {
    v.record(
        &["kind", "id_width", "length_width"],
        "http3.quic_transport.wire_parameters",
    )?;
    Ok(QuicTransportParameter {
        kind: parameter_kind(v.member("kind", "http3.quic_transport.wire_parameters.kind")?)?,
        id_width: width(v.member("id_width", "http3.quic_transport.wire_parameters.id_width")?)?,
        length_width: width(v.member(
            "length_width",
            "http3.quic_transport.wire_parameters.length_width",
        )?)?,
    })
}
fn parameter_kind(v: &Value) -> Result<QuicTransportParameterKind> {
    match v
        .member("kind", "http3.quic_transport.wire_parameters.kind")?
        .text("http3.quic_transport.wire_parameters.kind")?
    {
        "MaxIdleTimeout" => {
            v.record(
                &["kind", "value_width"],
                "http3.quic_transport.wire_parameters.kind",
            )?;
            Ok(QuicTransportParameterKind::MaxIdleTimeout {
                value_width: width(v.member(
                    "value_width",
                    "http3.quic_transport.wire_parameters.value_width",
                )?)?,
            })
        }
        "MaxUdpPayloadSize" => {
            v.record(
                &["kind", "value_width"],
                "http3.quic_transport.wire_parameters.kind",
            )?;
            Ok(QuicTransportParameterKind::MaxUdpPayloadSize {
                value_width: width(v.member(
                    "value_width",
                    "http3.quic_transport.wire_parameters.value_width",
                )?)?,
            })
        }
        "InitialMaxData" => {
            v.record(
                &["kind", "value_width"],
                "http3.quic_transport.wire_parameters.kind",
            )?;
            Ok(QuicTransportParameterKind::InitialMaxData {
                value_width: width(v.member(
                    "value_width",
                    "http3.quic_transport.wire_parameters.value_width",
                )?)?,
            })
        }
        "InitialMaxStreamDataBidiLocal" => {
            v.record(
                &["kind", "value_width"],
                "http3.quic_transport.wire_parameters.kind",
            )?;
            Ok(QuicTransportParameterKind::InitialMaxStreamDataBidiLocal {
                value_width: width(v.member(
                    "value_width",
                    "http3.quic_transport.wire_parameters.value_width",
                )?)?,
            })
        }
        "InitialMaxStreamDataBidiRemote" => {
            v.record(
                &["kind", "value_width"],
                "http3.quic_transport.wire_parameters.kind",
            )?;
            Ok(QuicTransportParameterKind::InitialMaxStreamDataBidiRemote {
                value_width: width(v.member(
                    "value_width",
                    "http3.quic_transport.wire_parameters.value_width",
                )?)?,
            })
        }
        "InitialMaxStreamDataUni" => {
            v.record(
                &["kind", "value_width"],
                "http3.quic_transport.wire_parameters.kind",
            )?;
            Ok(QuicTransportParameterKind::InitialMaxStreamDataUni {
                value_width: width(v.member(
                    "value_width",
                    "http3.quic_transport.wire_parameters.value_width",
                )?)?,
            })
        }
        "InitialMaxStreamsBidi" => {
            v.record(
                &["kind", "value_width"],
                "http3.quic_transport.wire_parameters.kind",
            )?;
            Ok(QuicTransportParameterKind::InitialMaxStreamsBidi {
                value_width: width(v.member(
                    "value_width",
                    "http3.quic_transport.wire_parameters.value_width",
                )?)?,
            })
        }
        "InitialMaxStreamsUni" => {
            v.record(
                &["kind", "value_width"],
                "http3.quic_transport.wire_parameters.kind",
            )?;
            Ok(QuicTransportParameterKind::InitialMaxStreamsUni {
                value_width: width(v.member(
                    "value_width",
                    "http3.quic_transport.wire_parameters.value_width",
                )?)?,
            })
        }
        "MaxAckDelay" => {
            v.record(
                &["kind", "value_width"],
                "http3.quic_transport.wire_parameters.kind",
            )?;
            Ok(QuicTransportParameterKind::MaxAckDelay {
                value_width: width(v.member(
                    "value_width",
                    "http3.quic_transport.wire_parameters.value_width",
                )?)?,
            })
        }
        "ActiveConnectionIdLimit" => {
            v.record(
                &["kind", "value_width"],
                "http3.quic_transport.wire_parameters.kind",
            )?;
            Ok(QuicTransportParameterKind::ActiveConnectionIdLimit {
                value_width: width(v.member(
                    "value_width",
                    "http3.quic_transport.wire_parameters.value_width",
                )?)?,
            })
        }
        "MaxDatagramFrameSize" => {
            v.record(
                &["kind", "value_width"],
                "http3.quic_transport.wire_parameters.kind",
            )?;
            Ok(QuicTransportParameterKind::MaxDatagramFrameSize {
                value_width: width(v.member(
                    "value_width",
                    "http3.quic_transport.wire_parameters.value_width",
                )?)?,
            })
        }
        "ResetStreamAt" => {
            v.record(&["kind"], "http3.quic_transport.wire_parameters.kind")?;
            Ok(QuicTransportParameterKind::ResetStreamAt)
        }
        "MinAckDelay" => {
            v.record(
                &["kind", "draft", "value_width"],
                "http3.quic_transport.wire_parameters.kind",
            )?;
            Ok(QuicTransportParameterKind::MinAckDelay {
                draft: draft(v.member("draft", "http3.quic_transport.wire_parameters.draft")?)?,
                value_width: width(v.member(
                    "value_width",
                    "http3.quic_transport.wire_parameters.value_width",
                )?)?,
            })
        }
        "InitialSourceConnectionId" => {
            v.record(
                &["kind", "length"],
                "http3.quic_transport.wire_parameters.kind",
            )?;
            Ok(QuicTransportParameterKind::InitialSourceConnectionId {
                length: v
                    .member("length", "http3.quic_transport.wire_parameters.length")?
                    .integer("http3.quic_transport.wire_parameters.length")?,
            })
        }
        "VersionInformation" => {
            v.record(
                &["kind", "available_version_count", "grease"],
                "http3.quic_transport.wire_parameters.kind",
            )?;
            Ok(QuicTransportParameterKind::VersionInformation(
                QuicVersionInformation {
                    available_version_count: v
                        .member(
                            "available_version_count",
                            "http3.quic_transport.wire_parameters.available_version_count",
                        )?
                        .integer("http3.quic_transport.wire_parameters.available_version_count")?,
                    grease: grease(
                        v.member("grease", "http3.quic_transport.wire_parameters.grease")?,
                    )?,
                },
            ))
        }
        "GoogleConnectionOptions" => {
            v.record(
                &["kind", "options"],
                "http3.quic_transport.wire_parameters.kind",
            )?;
            Ok(QuicTransportParameterKind::GoogleConnectionOptions(
                v.member("options", "http3.quic_transport.wire_parameters.options")?
                    .list("http3.quic_transport.wire_parameters.options", google)?,
            ))
        }
        "InitialRtt" => {
            v.record(&["kind"], "http3.quic_transport.wire_parameters.kind")?;
            Ok(QuicTransportParameterKind::InitialRtt)
        }
        "Grease" => {
            v.record(
                &["kind", "minimum_payload_length", "maximum_payload_length"],
                "http3.quic_transport.wire_parameters.kind",
            )?;
            Ok(QuicTransportParameterKind::Grease(QuicTransportGrease {
                minimum_payload_length: v
                    .member(
                        "minimum_payload_length",
                        "http3.quic_transport.wire_parameters.minimum_payload_length",
                    )?
                    .integer("http3.quic_transport.wire_parameters.minimum_payload_length")?,
                maximum_payload_length: v
                    .member(
                        "maximum_payload_length",
                        "http3.quic_transport.wire_parameters.maximum_payload_length",
                    )?
                    .integer("http3.quic_transport.wire_parameters.maximum_payload_length")?,
            }))
        }
        _ => Err(json::unsupported(
            "http3.quic_transport.wire_parameters.kind",
        )),
    }
}
