//! http2 settings in the custom-profile format.

use super::{Encode, Encoder, Result};
use phantom_profile::*;
use serde_json::Value;

tokens!(Http2PseudoHeader, Method, Authority, Scheme, Path, Protocol);
tokens!(Http2StaticNameIndex, Lowest, Highest);
tokens!(
    Http2HuffmanCoding,
    Always,
    WhenShorter,
    WhenNotLonger,
    AlwaysIncludingEmpty
);
tokens!(Http2CookieCrumbs, Whole, IndexAll, NeverIndexShort);
tokens!(Http2FieldIndexing, Nghttp2, All, NeverIndexAuthorization);
tokens!(
    Http2NameReference,
    StaticUnlessSensitive,
    StaticThenNewest,
    OldestDynamic
);
tokens!(Http2UnindexedMatch, Index, Literal);
tokens!(Http2IndexingLimit, ThreeQuarters, Half, Unlimited);
tokens!(Http2TableSizeUpdates, WhenChanged, EverySetting);
tokens!(
    Http2SensitiveProxyAuthorization,
    NeverIndexed,
    FieldIndexing
);
record!(
    Http2HpackSettings,
    literal_pseudo_headers,
    static_name_index,
    huffman_coding,
    cookie_crumbs,
    field_indexing,
    name_reference,
    unindexed_match,
    indexing_limit,
    table_size_updates,
    sensitive_proxy_authorization
);
record!(
    Http2StreamSettings,
    first_stream_id,
    assumed_max_concurrent_streams,
    max_concurrent_streams_cap
);
record!(Http2Priority, dependency_stream_id, weight, exclusive);
record!(
    Http2Settings,
    initial_settings,
    initial_connection_window_size,
    initial_stream_window_target,
    pseudo_header_order,
    extended_connect_pseudo_header_order,
    headers_priority,
    extended_connect_priority,
    hpack,
    streams,
    preface_ping_after,
    ping_timeout,
    ping_failure_retries,
    idle_ping_after,
    idle_ping_timeout,
    idle_timeout
);

impl Encode for Http2Setting {
    fn encode(&self, e: &mut Encoder, f: &str) -> Result<Value> {
        match self {
            Self::HeaderTableSize(value) => {
                object!(e, f, "kind" => "HeaderTableSize", "value" => value)
            }
            Self::EnablePush(value) => object!(e, f, "kind" => "EnablePush", "value" => value),
            Self::MaxConcurrentStreams(value) => {
                object!(e, f, "kind" => "MaxConcurrentStreams", "value" => value)
            }
            Self::InitialWindowSize(value) => {
                object!(e, f, "kind" => "InitialWindowSize", "value" => value)
            }
            Self::MaxFrameSize(value) => object!(e, f, "kind" => "MaxFrameSize", "value" => value),
            Self::MaxHeaderListSize(value) => {
                object!(e, f, "kind" => "MaxHeaderListSize", "value" => value)
            }
            Self::EnableConnectProtocol(value) => {
                object!(e, f, "kind" => "EnableConnectProtocol", "value" => value)
            }
            Self::NoRfc7540Priorities(value) => {
                object!(e, f, "kind" => "NoRfc7540Priorities", "value" => value)
            }
            _ => Err(super::super::json::unsupported(f)),
        }
    }
}
impl Encode for Http2IdleTimeout {
    fn encode(&self, e: &mut Encoder, f: &str) -> Result<Value> {
        let (kind, duration) = match self {
            Self::Unlimited => ("Unlimited", None),
            Self::ClosedOnTimer(duration) => ("ClosedOnTimer", Some(duration)),
            _ => return Err(super::super::json::unsupported(f)),
        };
        object!(e, f, "kind" => kind, "duration" => &duration)
    }
}
