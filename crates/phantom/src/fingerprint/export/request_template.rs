//! request template settings in the custom-profile format.

use super::{Encode, Encoder, Result};
use phantom_profile::*;
use serde_json::Value;

impl Encode for Http2RequestPriority {
    fn encode(&self, e: &mut Encoder, f: &str) -> Result<Value> {
        match self {
            Self::Fixed(priority) => object!(e, f,
                "variant" => "Fixed",
                "dependency_stream_id" => &priority.dependency_stream_id,
                "weight" => &priority.weight,
                "exclusive" => &priority.exclusive
            ),
            Self::WeightBand { weight, exclusive } => object!(e, f,
                "variant" => "WeightBand", "weight" => weight, "exclusive" => exclusive
            ),
        }
    }
}

impl Encode for RequestField {
    fn encode(&self, e: &mut Encoder, f: &str) -> Result<Value> {
        match self {
            Self::Literal { name, value } => {
                object!(e, f, "variant" => "Literal", "name" => name, "value" => value)
            }
            Self::Caller { name, required } => {
                object!(e, f, "variant" => "Caller", "name" => name, "required" => required)
            }
            Self::ClientHint { name } => object!(e, f, "variant" => "ClientHint", "name" => name),
            Self::ClientHints => object!(e, f, "variant" => "ClientHints"),
            Self::ByTrust {
                name,
                trustworthy,
                untrustworthy,
            } => {
                object!(e, f, "variant" => "ByTrust", "name" => name, "trustworthy" => trustworthy, "untrustworthy" => untrustworthy)
            }
            Self::ByForwarding {
                name,
                unforwarded,
                forwarded,
            } => {
                object!(e, f, "variant" => "ByForwarding", "name" => name, "unforwarded" => unforwarded, "forwarded" => forwarded)
            }
            Self::ProxyAuthorization { name, attempt } => {
                object!(e, f, "variant" => "ProxyAuthorization", "name" => name, "attempt" => attempt)
            }
            Self::RestartClientHints => object!(e, f, "variant" => "RestartClientHints"),
            Self::AltUsed => object!(e, f, "variant" => "AltUsed"),
            _ => Err(super::super::json::unsupported(f)),
        }
    }
}

tokens!(ProxyAuthorizationAttempt, Every, Preemptive, Replay);
record!(
    RequestTemplate,
    http1_fields,
    http2_fields,
    http3_fields,
    http2_priority,
    requested_client_hint_placement,
    restarts_for_connection_accept_ch
);
