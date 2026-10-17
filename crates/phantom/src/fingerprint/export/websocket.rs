//! websocket settings in the custom-profile format.

use super::{Encode, Encoder, Result};
use phantom_profile::*;
use serde_json::Value;

impl Encode for WebSocketField {
    fn encode(&self, e: &mut Encoder, f: &str) -> Result<Value> {
        match self {
            Self::Literal { name, value } => {
                object!(e, f, "kind" => "Literal", "name" => name, "value" => value)
            }
            Self::Caller { name } => object!(e, f, "kind" => "Caller", "name" => name),
            Self::Authority { name } => object!(e, f, "kind" => "Authority", "name" => name),
            Self::Key { name } => object!(e, f, "kind" => "Key", "name" => name),
            Self::PerMessageDeflate { name } => {
                object!(e, f, "kind" => "PerMessageDeflate", "name" => name)
            }
            Self::ClientCookies { name } => {
                object!(e, f, "kind" => "ClientCookies", "name" => name)
            }
            Self::ByTrust {
                name,
                trustworthy,
                untrustworthy,
            } => {
                object!(e, f, "kind" => "ByTrust", "name" => name, "trustworthy" => trustworthy, "untrustworthy" => untrustworthy)
            }
            _ => Err(super::super::json::unsupported(f)),
        }
    }
}
impl Encode for WebSocketDeflateParameter {
    fn encode(&self, e: &mut Encoder, f: &str) -> Result<Value> {
        match self {
            Self::ServerNoContextTakeover => object!(e, f, "kind" => "ServerNoContextTakeover"),
            Self::ClientNoContextTakeover => object!(e, f, "kind" => "ClientNoContextTakeover"),
            Self::ServerMaxWindowBits(bits) => {
                object!(e, f, "kind" => "ServerMaxWindowBits", "bits" => bits)
            }
            Self::ClientMaxWindowBits(bits) => {
                object!(e, f, "kind" => "ClientMaxWindowBits", "bits" => bits)
            }
            _ => Err(super::super::json::unsupported(f)),
        }
    }
}

tokens!(WebSocketEmptyMessageCompression, Compressed, Uncompressed);
tokens!(WebSocketNewConnection, Http1Upgrade, Http2ExtendedConnect);
tokens!(
    WebSocketRefusedStreamRetry,
    None,
    SameSessionOnce,
    ReacquireTwice
);
tokens!(WebSocketProxiedSession, Reuse, Ignore);
record!(
    WebSocketConnectionPolicy,
    without_http2_session,
    with_incapable_http2_session,
    http1_alpn_protocols,
    refused_stream_retry,
    proxied_http2_session
);
record!(
    WebSocketSettings,
    connection,
    http1_fields,
    http2_fields,
    permessage_deflate_offer,
    empty_message_compression,
    handshake_timeout
);
