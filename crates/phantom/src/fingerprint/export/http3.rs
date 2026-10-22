//! http3 settings in the custom-profile format.

use super::{Encode, Encoder, Result};
use phantom_profile::*;
use serde_json::Value;

tokens!(Http3SettingOrder, Fixed, Ascending);
tokens!(
    Http3QpackEncoding,
    Stateless,
    Dynamic,
    DynamicUnmatchedNames
);
tokens!(Http3QpackDecoderStream, Eager, OnFeedback);
tokens!(Http3QpackStreamOrder, EncoderFirst, DecoderFirst);
tokens!(Http3QpackEncoderStream, Eager, OnFirstInstruction);
tokens!(Http3PseudoHeader, Method, Authority, Scheme, Path, Protocol);
tokens!(Http3CookieCrumbs, Whole, Split);
tokens!(Http3AltUsed, Omit, Append, ValidatedMapping);
tokens!(Http3AltUsedPort, Explicit, OmitDefault);
record!(
    Http3Settings,
    initial_settings,
    setting_order,
    qpack_encoding,
    qpack_decoder_stream,
    qpack_encoder_stream,
    qpack_stream_order,
    reserved_frame_after_settings
);
record!(
    Http3RequestSettings,
    pseudo_header_order,
    extended_connect_pseudo_header_order,
    cookie_crumbs,
    alt_used,
    alt_used_port
);

impl Encode for Http3ClientSettings {
    fn encode(&self, e: &mut Encoder, f: &str) -> Result<Value> {
        object!(e, f, "tls" => self.tls(), "quic_transport" => self.quic_transport(),
            "http3" => self.http3(), "request" => self.request())
    }
}
impl Encode for Http3Setting {
    fn encode(&self, e: &mut Encoder, f: &str) -> Result<Value> {
        match self {
            Self::QpackMaxTableCapacity(value) => {
                object!(e, f, "kind" => "QpackMaxTableCapacity", "value" => value)
            }
            Self::MaxFieldSectionSize(value) => {
                object!(e, f, "kind" => "MaxFieldSectionSize", "value" => value)
            }
            Self::QpackBlockedStreams(value) => {
                object!(e, f, "kind" => "QpackBlockedStreams", "value" => value)
            }
            Self::H3Datagram(value) => object!(e, f, "kind" => "H3Datagram", "value" => value),
            Self::EnableConnectProtocol(value) => {
                object!(e, f, "kind" => "EnableConnectProtocol", "value" => value)
            }
            Self::EnableWebTransportDraft02(value) => {
                object!(e, f, "kind" => "EnableWebTransportDraft02", "value" => value)
            }
            Self::H3DatagramDraft04(value) => {
                object!(e, f, "kind" => "H3DatagramDraft04", "value" => value)
            }
            Self::RandomizedGrease => {
                object!(e, f, "kind" => "RandomizedGrease", "value" => &Option::<u8>::None)
            }
            _ => Err(super::super::json::unsupported(f)),
        }
    }
}
