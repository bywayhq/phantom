//! Complete HTTP/2 description parsing.

use super::{
    FingerprintImportError, Result,
    json::{self, Value},
};
use phantom_profile::{
    Http2CookieCrumbs, Http2FieldIndexing, Http2HpackSettings, Http2HuffmanCoding,
    Http2IdleTimeout, Http2IndexingLimit, Http2NameReference, Http2Priority, Http2PseudoHeader,
    Http2SensitiveProxyAuthorization, Http2Setting, Http2Settings, Http2StaticNameIndex,
    Http2StreamSettings, Http2TableSizeUpdates, Http2UnindexedMatch,
};

pub(super) fn parse(v: &Value) -> Result<Http2Settings> {
    v.record(
        &[
            "initial_settings",
            "initial_connection_window_size",
            "initial_stream_window_target",
            "pseudo_header_order",
            "extended_connect_pseudo_header_order",
            "headers_priority",
            "extended_connect_priority",
            "hpack",
            "streams",
            "preface_ping_after",
            "ping_timeout",
            "idle_ping_after",
            "idle_ping_timeout",
            "ping_failure_retries",
            "idle_timeout",
        ],
        "http2",
    )?;
    let settings = Http2Settings {
        initial_settings: v
            .member("initial_settings", "http2.initial_settings")?
            .list("http2.initial_settings", setting)?,
        initial_connection_window_size: v
            .member(
                "initial_connection_window_size",
                "http2.initial_connection_window_size",
            )?
            .integer("http2.initial_connection_window_size")?,
        initial_stream_window_target: v
            .member(
                "initial_stream_window_target",
                "http2.initial_stream_window_target",
            )?
            .optional(|v| v.integer("http2.initial_stream_window_target"))?,
        pseudo_header_order: v
            .member("pseudo_header_order", "http2.pseudo_header_order")?
            .list("http2.pseudo_header_order", pseudo)?,
        extended_connect_pseudo_header_order: v
            .member(
                "extended_connect_pseudo_header_order",
                "http2.extended_connect_pseudo_header_order",
            )?
            .optional(|v| v.list("http2.extended_connect_pseudo_header_order", pseudo))?,
        headers_priority: v
            .member("headers_priority", "http2.headers_priority")?
            .optional(priority)?,
        extended_connect_priority: v
            .member(
                "extended_connect_priority",
                "http2.extended_connect_priority",
            )?
            .optional(priority)?,
        hpack: hpack(v.member("hpack", "http2.hpack")?)?,
        streams: streams(v.member("streams", "http2.streams")?)?,
        preface_ping_after: v
            .member("preface_ping_after", "http2.preface_ping_after")?
            .optional(|v| v.duration("http2.preface_ping_after"))?,
        ping_timeout: v
            .member("ping_timeout", "http2.ping_timeout")?
            .optional(|v| v.duration("http2.ping_timeout"))?,
        idle_ping_after: v
            .member("idle_ping_after", "http2.idle_ping_after")?
            .optional(|v| v.duration("http2.idle_ping_after"))?,
        idle_ping_timeout: v
            .member("idle_ping_timeout", "http2.idle_ping_timeout")?
            .optional(|v| v.duration("http2.idle_ping_timeout"))?,
        ping_failure_retries: v
            .member("ping_failure_retries", "http2.ping_failure_retries")?
            .integer("http2.ping_failure_retries")?,
        idle_timeout: idle(v.member("idle_timeout", "http2.idle_timeout")?)?,
    };
    settings
        .validate()
        .map_err(|error| FingerprintImportError::native("http2", error))?;
    Ok(settings)
}

fn pseudo(v: &Value) -> Result<Http2PseudoHeader> {
    match v.text("http2.pseudo_header_order")? {
        "Method" => Ok(Http2PseudoHeader::Method),
        "Authority" => Ok(Http2PseudoHeader::Authority),
        "Scheme" => Ok(Http2PseudoHeader::Scheme),
        "Path" => Ok(Http2PseudoHeader::Path),
        "Protocol" => Ok(Http2PseudoHeader::Protocol),
        _ => Err(json::unsupported("http2.pseudo_header_order")),
    }
}

fn setting(v: &Value) -> Result<Http2Setting> {
    v.record(&["kind", "value"], "http2.initial_settings")?;
    let value = v.member("value", "http2.initial_settings.value")?;
    match v
        .member("kind", "http2.initial_settings.kind")?
        .text("http2.initial_settings.kind")?
    {
        "EnableConnectProtocol" => Ok(Http2Setting::EnableConnectProtocol(
            value.boolean("http2.initial_settings.value")?,
        )),
        "EnablePush" => Ok(Http2Setting::EnablePush(
            value.boolean("http2.initial_settings.value")?,
        )),
        "HeaderTableSize" => Ok(Http2Setting::HeaderTableSize(
            value.integer("http2.initial_settings.value")?,
        )),
        "InitialWindowSize" => Ok(Http2Setting::InitialWindowSize(
            value.integer("http2.initial_settings.value")?,
        )),
        "MaxConcurrentStreams" => Ok(Http2Setting::MaxConcurrentStreams(
            value.integer("http2.initial_settings.value")?,
        )),
        "MaxFrameSize" => Ok(Http2Setting::MaxFrameSize(
            value.integer("http2.initial_settings.value")?,
        )),
        "MaxHeaderListSize" => Ok(Http2Setting::MaxHeaderListSize(
            value.integer("http2.initial_settings.value")?,
        )),
        "NoRfc7540Priorities" => Ok(Http2Setting::NoRfc7540Priorities(
            value.boolean("http2.initial_settings.value")?,
        )),
        _ => Err(json::unsupported("http2.initial_settings.kind")),
    }
}
pub(super) fn priority(v: &Value) -> Result<Http2Priority> {
    v.record(
        &["dependency_stream_id", "weight", "exclusive"],
        "http2.priority",
    )?;
    let settings = Http2Priority {
        dependency_stream_id: v
            .member(
                "dependency_stream_id",
                "http2.priority.dependency_stream_id",
            )?
            .integer("http2.priority.dependency_stream_id")?,
        weight: v
            .member("weight", "http2.priority.weight")?
            .integer("http2.priority.weight")?,
        exclusive: v
            .member("exclusive", "http2.priority.exclusive")?
            .boolean("http2.priority.exclusive")?,
    };
    Ok(settings)
}

pub(super) fn streams(v: &Value) -> Result<Http2StreamSettings> {
    v.record(
        &[
            "first_stream_id",
            "assumed_max_concurrent_streams",
            "max_concurrent_streams_cap",
        ],
        "http2.streams",
    )?;
    let settings = Http2StreamSettings {
        first_stream_id: v
            .member("first_stream_id", "http2.streams.first_stream_id")?
            .integer("http2.streams.first_stream_id")?,
        assumed_max_concurrent_streams: v
            .member(
                "assumed_max_concurrent_streams",
                "http2.streams.assumed_max_concurrent_streams",
            )?
            .optional(|v| v.integer("http2.streams.assumed_max_concurrent_streams"))?,
        max_concurrent_streams_cap: v
            .member(
                "max_concurrent_streams_cap",
                "http2.streams.max_concurrent_streams_cap",
            )?
            .optional(|v| v.integer("http2.streams.max_concurrent_streams_cap"))?,
    };
    Ok(settings)
}

fn static_name_index(v: &Value) -> Result<Http2StaticNameIndex> {
    match v.text("http2.hpack.static_name_index")? {
        "Lowest" => Ok(Http2StaticNameIndex::Lowest),
        "Highest" => Ok(Http2StaticNameIndex::Highest),
        _ => Err(json::unsupported("http2.hpack.static_name_index")),
    }
}

fn huffman_coding(v: &Value) -> Result<Http2HuffmanCoding> {
    match v.text("http2.hpack.huffman_coding")? {
        "Always" => Ok(Http2HuffmanCoding::Always),
        "WhenShorter" => Ok(Http2HuffmanCoding::WhenShorter),
        "WhenNotLonger" => Ok(Http2HuffmanCoding::WhenNotLonger),
        "AlwaysIncludingEmpty" => Ok(Http2HuffmanCoding::AlwaysIncludingEmpty),
        _ => Err(json::unsupported("http2.hpack.huffman_coding")),
    }
}

fn cookie_crumbs(v: &Value) -> Result<Http2CookieCrumbs> {
    match v.text("http2.hpack.cookie_crumbs")? {
        "Whole" => Ok(Http2CookieCrumbs::Whole),
        "IndexAll" => Ok(Http2CookieCrumbs::IndexAll),
        "NeverIndexShort" => Ok(Http2CookieCrumbs::NeverIndexShort),
        _ => Err(json::unsupported("http2.hpack.cookie_crumbs")),
    }
}

fn field_indexing(v: &Value) -> Result<Http2FieldIndexing> {
    match v.text("http2.hpack.field_indexing")? {
        "Nghttp2" => Ok(Http2FieldIndexing::Nghttp2),
        "All" => Ok(Http2FieldIndexing::All),
        "NeverIndexAuthorization" => Ok(Http2FieldIndexing::NeverIndexAuthorization),
        _ => Err(json::unsupported("http2.hpack.field_indexing")),
    }
}

fn name_reference(v: &Value) -> Result<Http2NameReference> {
    match v.text("http2.hpack.name_reference")? {
        "StaticUnlessSensitive" => Ok(Http2NameReference::StaticUnlessSensitive),
        "StaticThenNewest" => Ok(Http2NameReference::StaticThenNewest),
        "OldestDynamic" => Ok(Http2NameReference::OldestDynamic),
        _ => Err(json::unsupported("http2.hpack.name_reference")),
    }
}

fn unindexed_match(v: &Value) -> Result<Http2UnindexedMatch> {
    match v.text("http2.hpack.unindexed_match")? {
        "Index" => Ok(Http2UnindexedMatch::Index),
        "Literal" => Ok(Http2UnindexedMatch::Literal),
        _ => Err(json::unsupported("http2.hpack.unindexed_match")),
    }
}

fn indexing_limit(v: &Value) -> Result<Http2IndexingLimit> {
    match v.text("http2.hpack.indexing_limit")? {
        "ThreeQuarters" => Ok(Http2IndexingLimit::ThreeQuarters),
        "Half" => Ok(Http2IndexingLimit::Half),
        "FullTable" => Ok(Http2IndexingLimit::FullTable),
        "Unlimited" => Ok(Http2IndexingLimit::Unlimited),
        _ => Err(json::unsupported("http2.hpack.indexing_limit")),
    }
}

fn table_size_updates(v: &Value) -> Result<Http2TableSizeUpdates> {
    match v.text("http2.hpack.table_size_updates")? {
        "WhenChanged" => Ok(Http2TableSizeUpdates::WhenChanged),
        "EverySetting" => Ok(Http2TableSizeUpdates::EverySetting),
        _ => Err(json::unsupported("http2.hpack.table_size_updates")),
    }
}

fn sensitive_proxy_authorization(v: &Value) -> Result<Http2SensitiveProxyAuthorization> {
    match v.text("http2.hpack.sensitive_proxy_authorization")? {
        "NeverIndexed" => Ok(Http2SensitiveProxyAuthorization::NeverIndexed),
        "FieldIndexing" => Ok(Http2SensitiveProxyAuthorization::FieldIndexing),
        _ => Err(json::unsupported(
            "http2.hpack.sensitive_proxy_authorization",
        )),
    }
}

pub(super) fn hpack(v: &Value) -> Result<Http2HpackSettings> {
    v.record(
        &[
            "literal_pseudo_headers",
            "static_name_index",
            "huffman_coding",
            "cookie_crumbs",
            "field_indexing",
            "name_reference",
            "unindexed_match",
            "indexing_limit",
            "table_size_updates",
            "sensitive_proxy_authorization",
        ],
        "http2.hpack",
    )?;
    let settings = Http2HpackSettings {
        literal_pseudo_headers: v
            .member(
                "literal_pseudo_headers",
                "http2.hpack.literal_pseudo_headers",
            )?
            .list("http2.hpack.literal_pseudo_headers", pseudo)?,
        static_name_index: static_name_index(
            v.member("static_name_index", "http2.hpack.static_name_index")?,
        )?,
        huffman_coding: huffman_coding(v.member("huffman_coding", "http2.hpack.huffman_coding")?)?,
        cookie_crumbs: cookie_crumbs(v.member("cookie_crumbs", "http2.hpack.cookie_crumbs")?)?,
        field_indexing: field_indexing(v.member("field_indexing", "http2.hpack.field_indexing")?)?,
        name_reference: name_reference(v.member("name_reference", "http2.hpack.name_reference")?)?,
        unindexed_match: unindexed_match(
            v.member("unindexed_match", "http2.hpack.unindexed_match")?,
        )?,
        indexing_limit: indexing_limit(v.member("indexing_limit", "http2.hpack.indexing_limit")?)?,
        table_size_updates: table_size_updates(
            v.member("table_size_updates", "http2.hpack.table_size_updates")?,
        )?,
        sensitive_proxy_authorization: sensitive_proxy_authorization(v.member(
            "sensitive_proxy_authorization",
            "http2.hpack.sensitive_proxy_authorization",
        )?)?,
    };
    Ok(settings)
}

fn idle(v: &Value) -> Result<Http2IdleTimeout> {
    v.record(&["kind", "duration"], "http2.idle_timeout")?;
    match v
        .member("kind", "http2.idle_timeout.kind")?
        .text("http2.idle_timeout.kind")?
    {
        "Unlimited" => {
            v.member("duration", "http2.idle_timeout.duration")?
                .null("http2.idle_timeout.duration")?;
            Ok(Http2IdleTimeout::Unlimited)
        }
        "ClosedOnTimer" => Ok(Http2IdleTimeout::ClosedOnTimer(
            v.member("duration", "http2.idle_timeout.duration")?
                .duration("http2.idle_timeout.duration")?,
        )),
        _ => Err(json::unsupported("http2.idle_timeout.kind")),
    }
}
