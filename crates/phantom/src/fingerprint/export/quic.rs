//! quic settings in the custom-profile format.

use super::{Encode, Encoder, Result};
use phantom_profile::*;
use serde_json::Value;

record!(QuicTransportParameter, kind, id_width, length_width);

impl Encode for QuicConnectionIdLength {
    fn encode(&self, e: &mut Encoder, f: &str) -> Result<Value> {
        match self {
            Self::Fixed(length) => object!(e, f, "kind" => "Fixed", "length" => length),
            Self::MaskedRandom { minimum, base } => {
                object!(e, f, "kind" => "MaskedRandom", "minimum" => minimum, "base" => base)
            }
            _ => Err(super::super::json::unsupported(f)),
        }
    }
}
impl Encode for QuicTransportParameterKind {
    fn encode(&self, e: &mut Encoder, f: &str) -> Result<Value> {
        match self {
            Self::MaxIdleTimeout { value_width } => {
                object!(e, f, "kind" => "MaxIdleTimeout", "value_width" => value_width)
            }
            Self::MaxUdpPayloadSize { value_width } => {
                object!(e, f, "kind" => "MaxUdpPayloadSize", "value_width" => value_width)
            }
            Self::InitialMaxData { value_width } => {
                object!(e, f, "kind" => "InitialMaxData", "value_width" => value_width)
            }
            Self::InitialMaxStreamDataBidiLocal { value_width } => {
                object!(e, f, "kind" => "InitialMaxStreamDataBidiLocal", "value_width" => value_width)
            }
            Self::InitialMaxStreamDataBidiRemote { value_width } => {
                object!(e, f, "kind" => "InitialMaxStreamDataBidiRemote", "value_width" => value_width)
            }
            Self::InitialMaxStreamDataUni { value_width } => {
                object!(e, f, "kind" => "InitialMaxStreamDataUni", "value_width" => value_width)
            }
            Self::InitialMaxStreamsBidi { value_width } => {
                object!(e, f, "kind" => "InitialMaxStreamsBidi", "value_width" => value_width)
            }
            Self::InitialMaxStreamsUni { value_width } => {
                object!(e, f, "kind" => "InitialMaxStreamsUni", "value_width" => value_width)
            }
            Self::MaxAckDelay { value_width } => {
                object!(e, f, "kind" => "MaxAckDelay", "value_width" => value_width)
            }
            Self::ActiveConnectionIdLimit { value_width } => {
                object!(e, f, "kind" => "ActiveConnectionIdLimit", "value_width" => value_width)
            }
            Self::MaxDatagramFrameSize { value_width } => {
                object!(e, f, "kind" => "MaxDatagramFrameSize", "value_width" => value_width)
            }
            Self::InitialSourceConnectionId { length } => {
                object!(e, f, "kind" => "InitialSourceConnectionId", "length" => length)
            }
            Self::MinAckDelay { draft, value_width } => {
                object!(e, f, "kind" => "MinAckDelay", "draft" => draft, "value_width" => value_width)
            }
            Self::VersionInformation(v) => {
                object!(e, f, "kind" => "VersionInformation", "available_version_count" => &v.available_version_count, "grease" => &v.grease)
            }
            Self::GoogleConnectionOptions(options) => {
                object!(e, f, "kind" => "GoogleConnectionOptions", "options" => options)
            }
            Self::Grease(v) => {
                object!(e, f, "kind" => "Grease", "minimum_payload_length" => &v.minimum_payload_length, "maximum_payload_length" => &v.maximum_payload_length)
            }
            Self::ResetStreamAt => object!(e, f, "kind" => "ResetStreamAt"),
            Self::InitialRtt => object!(e, f, "kind" => "InitialRtt"),
            _ => Err(super::super::json::unsupported(f)),
        }
    }
}

tokens!(QuicVarIntWidth, One, Two, Four, Eight);
tokens!(QuicTransportParameterOrder, Fixed, Permuted);
tokens!(QuicVersionGrease, Omit, Permuted, First);
tokens!(QuicAckFrequencyDraft, Draft02, Draft07);
tokens!(GoogleConnectionOption, RequestOriginFrame);
record!(QuicVersionInformation, available_version_count, grease);
record!(
    QuicTransportGrease,
    minimum_payload_length,
    maximum_payload_length
);
record!(
    QuicTransportSettings,
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
    early_data
);
