//! proxy connect settings in the custom-profile format.

use super::{Encode, Encoder, Result};
use phantom_profile::*;
use serde_json::Value;

impl Encode for ProxyConnectField {
    fn encode(&self, e: &mut Encoder, f: &str) -> Result<Value> {
        match self {
            Self::Authority { name } => object!(e, f, "kind" => "Authority", "name" => name),
            Self::Literal { name, value } => {
                object!(e, f, "kind" => "Literal", "name" => name, "value" => value)
            }
            Self::FromRequest { name } => object!(e, f, "kind" => "FromRequest", "name" => name),
            Self::ProxyAuthorization { name } => {
                object!(e, f, "kind" => "ProxyAuthorization", "name" => name)
            }
            _ => Err(super::super::json::unsupported(f)),
        }
    }
}

tokens!(Http2RejectedConnect, EndStream, LeaveOpen);
tokens!(Http2ProxyConnections, Shared, ByPurpose);
record!(
    ProxyConnectTemplate,
    http1_fields,
    http2_fields,
    http2_rejected,
    http2_connections
);
