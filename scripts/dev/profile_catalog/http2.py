"""Closed HTTP/2 settings, compression, streams and timer policies."""

from .declarations import (
    MAX_U32,
    PSEUDO_HEADERS,
    DeclarationError,
    boolean,
    bounded_integer,
    choice,
    duration_is_zero,
    keys,
    validate_duration,
)
from .http3 import (
    validate_pseudo_headers,
)
from .rust_literals import (
    rust_duration,
    rust_header_order,
    rust_option,
)

HTTP2_HPACK_ENUMS = {
    "static_name_index": ("Http2StaticNameIndex", ("Lowest", "Highest")),
    "huffman_coding": (
        "Http2HuffmanCoding",
        ("Always", "WhenShorter", "WhenNotLonger", "AlwaysIncludingEmpty"),
    ),
    "cookie_crumbs": ("Http2CookieCrumbs", ("Whole", "IndexAll", "NeverIndexShort")),
    "field_indexing": (
        "Http2FieldIndexing",
        ("Nghttp2", "All", "NeverIndexAuthorization"),
    ),
    "name_reference": (
        "Http2NameReference",
        ("StaticUnlessSensitive", "StaticThenNewest", "OldestDynamic"),
    ),
    "unindexed_match": ("Http2UnindexedMatch", ("Index", "Literal")),
    "indexing_limit": ("Http2IndexingLimit", ("ThreeQuarters", "Half", "Unlimited")),
    "table_size_updates": ("Http2TableSizeUpdates", ("WhenChanged", "EverySetting")),
    "sensitive_proxy_authorization": (
        "Http2SensitiveProxyAuthorization",
        ("NeverIndexed", "FieldIndexing"),
    ),
}


HTTP2_HPACK_FIELDS = ("literal_pseudo_headers", *HTTP2_HPACK_ENUMS)


HTTP2_STREAM_FIELDS = (
    "first_stream_id",
    "assumed_max_concurrent_streams",
    "max_concurrent_streams_cap",
)


HTTP2_PRIORITY_FIELDS = ("dependency_stream_id", "weight", "exclusive")


HTTP2_BOOL_SETTINGS = {"EnablePush", "EnableConnectProtocol", "NoRfc7540Priorities"}


HTTP2_NUMERIC_SETTINGS = {
    "HeaderTableSize",
    "MaxConcurrentStreams",
    "InitialWindowSize",
    "MaxFrameSize",
    "MaxHeaderListSize",
}


MAX_HTTP2_WINDOW = (1 << 31) - 1


def validate_http2_initial_settings(settings):
    if not isinstance(settings, list) or len(settings) > 64:
        raise DeclarationError("HTTP/2 initial_settings: expected at most 64 settings")
    seen = set()
    for setting in settings:
        keys(setting, ("kind", "value"), "HTTP/2 setting")
        kind = choice(
            setting["kind"],
            (*HTTP2_NUMERIC_SETTINGS, *HTTP2_BOOL_SETTINGS),
            "HTTP/2 setting kind",
        )
        if kind in seen:
            raise DeclarationError(f"duplicate HTTP/2 setting: {kind}")
        seen.add(kind)
        value = setting["value"]
        if kind in HTTP2_BOOL_SETTINGS:
            boolean(value, kind)
        elif kind == "InitialWindowSize":
            bounded_integer(value, 0, MAX_HTTP2_WINDOW, kind)
        elif kind == "MaxFrameSize":
            bounded_integer(value, 1 << 14, (1 << 24) - 1, kind)
        else:
            bounded_integer(value, 0, MAX_U32, kind)
    if "InitialWindowSize" not in seen:
        raise DeclarationError("HTTP/2 requires exactly one InitialWindowSize setting")


def validate_http2_priority(value, context):
    keys(value, HTTP2_PRIORITY_FIELDS, context)
    bounded_integer(value["dependency_stream_id"], 0, MAX_HTTP2_WINDOW, context)
    bounded_integer(value["weight"], 1, 256, context)
    boolean(value["exclusive"], context)


def validate_http2_hpack(value):
    keys(value, HTTP2_HPACK_FIELDS, "HTTP/2 HPACK")
    headers = value["literal_pseudo_headers"]
    if not isinstance(headers, list) or len(headers) > len(PSEUDO_HEADERS):
        raise DeclarationError("HPACK literal headers must be a bounded list")
    for header in headers:
        choice(header, PSEUDO_HEADERS, "HPACK literal pseudo-header")
    if len(set(headers)) != len(headers):
        raise DeclarationError("duplicate HPACK literal pseudo-header")
    for field, (_, variants) in HTTP2_HPACK_ENUMS.items():
        choice(value[field], variants, field)


def validate_http2_streams(value):
    keys(value, HTTP2_STREAM_FIELDS, "HTTP/2 streams")
    first = value["first_stream_id"]
    bounded_integer(first, 1, MAX_HTTP2_WINDOW, "first_stream_id")
    if first % 2 == 0:
        raise DeclarationError("first_stream_id must be odd")
    for field in HTTP2_STREAM_FIELDS[1:]:
        if value[field] is not None:
            bounded_integer(value[field], 1, MAX_U32, field)


def validate_http2_values(values):
    validate_http2_initial_settings(values["initial_settings"])
    bounded_integer(
        values["initial_connection_window_size"],
        65_535,
        MAX_HTTP2_WINDOW,
        "initial_connection_window_size",
    )
    target = values["initial_stream_window_target"]
    if target is not None:
        advertised = next(
            item["value"]
            for item in values["initial_settings"]
            if item["kind"] == "InitialWindowSize"
        )
        bounded_integer(
            target, advertised, MAX_HTTP2_WINDOW, "initial_stream_window_target"
        )
    validate_pseudo_headers(values["pseudo_header_order"], False)
    if values["extended_connect_pseudo_header_order"] is not None:
        validate_pseudo_headers(values["extended_connect_pseudo_header_order"], True)
    for field in ("headers_priority", "extended_connect_priority"):
        if values[field] is not None:
            validate_http2_priority(values[field], field)
    validate_http2_hpack(values["hpack"])
    validate_http2_streams(values["streams"])
    for field in (
        "preface_ping_after",
        "ping_timeout",
        "idle_ping_after",
        "idle_ping_timeout",
    ):
        if values[field] is not None:
            validate_duration(values[field], field)
            if field != "preface_ping_after" and duration_is_zero(values[field]):
                raise DeclarationError(f"{field}: duration must be positive")
    for after, timeout in (
        ("preface_ping_after", "ping_timeout"),
        ("idle_ping_after", "idle_ping_timeout"),
    ):
        if values[timeout] is not None and values[after] is None:
            raise DeclarationError(f"{timeout} requires {after}")
    bounded_integer(values["ping_failure_retries"], 0, 255, "ping_failure_retries")
    if values["ping_failure_retries"] and (
        values["ping_timeout"] is None and values["idle_ping_timeout"] is None
    ):
        raise DeclarationError("PING retries require a PING timeout")
    idle = values["idle_timeout"]
    keys(idle, ("kind", "duration"), "HTTP/2 idle timeout")
    kind = choice(idle["kind"], ("Unlimited", "ClosedOnTimer"), "HTTP/2 idle timeout")
    if kind == "Unlimited":
        if idle["duration"] is not None:
            raise DeclarationError("Unlimited idle timeout has no duration")
    else:
        limit = idle["duration"]
        validate_duration(limit, "closed idle timeout")
        if not 1 <= limit["seconds"] <= 65_535 or (
            limit["seconds"] == 65_535 and limit["nanoseconds"] != 0
        ):
            raise DeclarationError("closed idle timeout must be in 1..=65535 seconds")


def rust_http2_priority(value):
    return (
        "crate::Http2Priority { "
        f"dependency_stream_id: {value['dependency_stream_id']}, "
        f"weight: {value['weight']}, exclusive: {str(value['exclusive']).lower()} "
        "}"
    )


def rust_http2_value(field, value):
    if field == "initial_settings":
        return (
            "vec!["
            + ", ".join(
                f"crate::Http2Setting::{item['kind']}({str(item['value']).lower()})"
                for item in value
            )
            + "]"
        )
    if field == "initial_stream_window_target":
        return rust_option(value, str)
    if field in ("initial_connection_window_size", "ping_failure_retries"):
        return str(value)
    if field == "pseudo_header_order":
        return rust_header_order(value, "Http2")
    if field == "extended_connect_pseudo_header_order":
        return rust_option(value, lambda headers: rust_header_order(headers, "Http2"))
    if field in ("headers_priority", "extended_connect_priority"):
        return rust_option(value, rust_http2_priority)
    if field == "hpack":
        fields = [
            "literal_pseudo_headers: "
            + rust_header_order(value["literal_pseudo_headers"], "Http2")
        ]
        fields.extend(
            f"{name}: crate::{enum}::{value[name]}"
            for name, (enum, _) in HTTP2_HPACK_ENUMS.items()
        )
        return "crate::Http2HpackSettings { " + ", ".join(fields) + " }"
    if field == "streams":
        fields = [f"first_stream_id: {value['first_stream_id']}"]
        fields.extend(
            f"{name}: {rust_option(value[name], str)}"
            for name in HTTP2_STREAM_FIELDS[1:]
        )
        return "crate::Http2StreamSettings { " + ", ".join(fields) + " }"
    if field == "idle_timeout":
        if value["kind"] == "Unlimited":
            return "crate::Http2IdleTimeout::Unlimited"
        return f"crate::Http2IdleTimeout::ClosedOnTimer({rust_duration(value['duration'])})"
    return rust_option(value, rust_duration)
