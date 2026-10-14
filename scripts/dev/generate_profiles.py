"""Validate catalog records and typed components, then generate Rust offline."""

import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

REPO = Path(__file__).resolve().parents[2]
RECORDS = REPO / "crates/phantom-profile/catalog/profiles.json"
OUTPUT = REPO / "crates/phantom-profile/src/catalog/generated.rs"
COMPONENT_RECORDS = REPO / "crates/phantom-profile/catalog/http3-components.json"
COMPONENT_OUTPUT = REPO / "crates/phantom-profile/src/catalog/http3_components.rs"
HTTP2_COMPONENT_RECORDS = REPO / "crates/phantom-profile/catalog/http2-components.json"
HTTP2_COMPONENT_OUTPUT = REPO / "crates/phantom-profile/src/catalog/http2_components.rs"

# Resource ceilings for local declarations, not corpus performance claims.
MAX_BYTES = 16 * 1024 * 1024
MAX_PROFILES = 4096
MAX_DEPTH = 16
MAX_STRING = 4096
MAX_REFERENCES = 16
MAX_COMPONENTS = 4096
MAX_COMPONENT_CHAIN = 32
MAX_VARINT = (1 << 62) - 1
MAX_QPACK_TABLE_CAPACITY = (1 << 30) - 1
COMPONENT_FIELDS = {
    "Http2Settings": (
        "initial_settings",
        "initial_connection_window_size",
        "pseudo_header_order",
        "extended_connect_pseudo_header_order",
        "headers_priority",
        "extended_connect_priority",
        "hpack",
        "streams",
        "preface_ping_after",
        "ping_timeout",
        "ping_failure_retries",
        "idle_ping_after",
        "idle_ping_timeout",
        "idle_timeout",
    ),
    "Http3Settings": (
        "initial_settings",
        "setting_order",
        "qpack_encoding",
        "qpack_decoder_stream",
        "qpack_encoder_stream",
        "qpack_stream_order",
        "reserved_frame_after_settings",
    ),
    "Http3RequestSettings": (
        "pseudo_header_order",
        "extended_connect_pseudo_header_order",
        "cookie_crumbs",
        "alt_used",
    ),
}
COMPONENT_ENUMS = {
    "setting_order": ("Http3SettingOrder", ("Fixed", "Ascending")),
    "qpack_encoding": (
        "Http3QpackEncoding",
        ("Stateless", "Dynamic", "DynamicUnmatchedNames"),
    ),
    "qpack_decoder_stream": ("Http3QpackDecoderStream", ("Eager", "OnFeedback")),
    "qpack_encoder_stream": (
        "Http3QpackEncoderStream",
        ("Eager", "OnFirstInstruction"),
    ),
    "qpack_stream_order": ("Http3QpackStreamOrder", ("EncoderFirst", "DecoderFirst")),
    "cookie_crumbs": ("Http3CookieCrumbs", ("Whole", "Split")),
    "alt_used": ("Http3AltUsed", ("Omit", "Append")),
}
SETTING_BOUNDS = {
    "QpackMaxTableCapacity": MAX_QPACK_TABLE_CAPACITY,
    "MaxFieldSectionSize": MAX_VARINT,
    "QpackBlockedStreams": MAX_VARINT,
}
BOOL_SETTINGS = {
    "H3Datagram",
    "EnableConnectProtocol",
    "EnableWebTransportDraft02",
    "H3DatagramDraft04",
}
PSEUDO_HEADERS = ("Method", "Authority", "Scheme", "Path", "Protocol")
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
MAX_U32 = (1 << 32) - 1
MAX_U64 = (1 << 64) - 1
MAX_HTTP2_WINDOW = (1 << 31) - 1
RUST_KEYWORDS = {
    "as",
    "async",
    "await",
    "break",
    "const",
    "continue",
    "crate",
    "dyn",
    "else",
    "enum",
    "extern",
    "false",
    "fn",
    "for",
    "if",
    "impl",
    "in",
    "let",
    "loop",
    "match",
    "mod",
    "move",
    "mut",
    "pub",
    "ref",
    "return",
    "self",
    "static",
    "struct",
    "super",
    "trait",
    "true",
    "type",
    "unsafe",
    "use",
    "where",
    "while",
    "abstract",
    "become",
    "box",
    "do",
    "final",
    "gen",
    "macro",
    "override",
    "priv",
    "try",
    "typeof",
    "unsized",
    "virtual",
    "yield",
    "union",
}
LAYERS = (
    "TcpTls",
    "Tcp",
    "Udp",
    "Dns",
    "Http1",
    "Http2",
    "QuicTls",
    "QuicTransport",
    "Http3",
    "Http3Request",
    "ClientHints",
    "WebSocket",
    "ProxyConnect",
    "CookiePlacement",
)
WINDOWS = set(LAYERS)
ANDROID = {
    "TcpTls",
    "Http2",
    "QuicTls",
    "QuicTransport",
    "Http3",
    "Http3Request",
    "ClientHints",
    "WebSocket",
}
BINDINGS = {
    "ChromeWindows154": ("Chrome", "Windows", WINDOWS),
    "ChromeAndroid154": ("Chrome", "Android", ANDROID),
    "EdgeWindows154": ("Edge", "Windows", WINDOWS),
    "EdgeAndroid153": ("Edge", "Android", ANDROID - {"WebSocket"}),
    "BraveWindows154": ("Brave", "Windows", WINDOWS),
    "BraveAndroid153": ("Brave", "Android", ANDROID),
    "FirefoxWindows157": ("Firefox", "Windows", WINDOWS - {"Udp", "ClientHints"}),
    "FirefoxAndroid156": ("Firefox", "Android", {"TcpTls"}),
    "OperaWindows136": ("Opera", "Windows", WINDOWS),
    "OperaAndroid102": ("Opera", "Android", {"TcpTls", "ClientHints"}),
}
TARGETS = {
    "ChromeWindows154": ("154.0.8037.97", "windows-11-26200", None, "Desktop", 1),
    "ChromeAndroid154": (
        "154.0.8037.57",
        "android-17-pixel7-emulator",
        "x86_64",
        "Emulator",
        1,
    ),
    "EdgeWindows154": ("154.0.4258.48", "windows-11-26200", None, "Desktop", 1),
    "EdgeAndroid153": (
        "153.0.4234.49",
        "android-17-pixel7-emulator",
        "arm64",
        "Emulator",
        1,
    ),
    "BraveWindows154": ("154.1.96.59", "windows-11-26200", None, "Desktop", 1),
    "BraveAndroid153": (
        "153.1.95.104",
        "android-17-pixel7-emulator",
        None,
        "Emulator",
        1,
    ),
    "FirefoxWindows157": ("157.0", "windows-11-26200", None, "Desktop", 1),
    "FirefoxAndroid156": ("156.0.1", "android-35-emulator", None, "Emulator", 1),
    "OperaWindows136": ("136.0.6008.52", "windows-11-26200", None, "Desktop", 1),
    "OperaAndroid102": (
        "102.1.5206.90382",
        "android-17-pixel7-emulator",
        None,
        "Emulator",
        1,
    ),
}


class DeclarationError(ValueError):
    """A declaration violates the closed schema or compiled recipe contract."""


def object_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DeclarationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def keys(value, expected, context):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise DeclarationError(f"{context}: expected keys {', '.join(expected)}")


def text(value, context):
    if not isinstance(value, str) or not value or len(value) > MAX_STRING:
        raise DeclarationError(f"{context}: expected bounded nonempty string")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise DeclarationError(f"{context}: control characters are forbidden")
    if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise DeclarationError(f"{context}: invalid Unicode scalar value")
    return value


def choice(value, allowed, context):
    text(value, context)
    if value not in allowed:
        raise DeclarationError(f"{context}: unknown value {value}")
    return value


def string_list(value, context):
    if not isinstance(value, list) or len(value) > 64:
        raise DeclarationError(f"{context}: expected at most 64 strings")
    for item in value:
        text(item, context)
    if len(set(value)) != len(value):
        raise DeclarationError(f"{context}: duplicate entry")


def check_depth(value, depth=0):
    if depth > MAX_DEPTH:
        raise DeclarationError("declaration nesting limit exceeded")
    if isinstance(value, dict):
        for item in value.values():
            check_depth(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            check_depth(item, depth + 1)


def validate(document, repo=REPO):
    check_depth(document)
    keys(document, ("schema", "profiles"), "catalog")
    if type(document["schema"]) is not int or document["schema"] != 1:
        raise DeclarationError("unsupported catalog schema")
    profiles = document["profiles"]
    if not isinstance(profiles, list) or not 0 < len(profiles) <= MAX_PROFILES:
        raise DeclarationError("profile count is outside declaration limits")

    ids = set()
    for entry in profiles:
        keys(entry, ("id", "binding", "metadata", "layers"), "profile")
        identifier = text(entry["id"], "profile id")
        if not re.fullmatch(r"[a-z0-9][a-z0-9./-]{0,191}", identifier):
            raise DeclarationError("invalid profile identifier")
        if identifier in ids:
            raise DeclarationError(f"duplicate profile identifier: {identifier}")
        ids.add(identifier)
        binding = choice(entry["binding"], BINDINGS, identifier)
        browser, platform, configured = BINDINGS[binding]

        metadata = entry["metadata"]
        keys(
            metadata,
            (
                "browser",
                "build",
                "platform",
                "platform_release",
                "architecture",
                "environment",
                "revision",
            ),
            identifier,
        )
        if metadata["browser"] != browser or metadata["platform"] != platform:
            raise DeclarationError(f"{identifier}: incompatible recipe binding")
        text(metadata["build"], "browser build")
        text(metadata["platform_release"], "platform release")
        if metadata["architecture"] is not None:
            choice(metadata["architecture"], ("x86_64", "arm64"), "architecture")
        environment = choice(
            metadata["environment"],
            ("Desktop", "Emulator", "PhysicalDevice"),
            "environment",
        )
        if (platform == "Windows") != (environment == "Desktop"):
            raise DeclarationError(f"{identifier}: incompatible capture environment")
        revision = metadata["revision"]
        if type(revision) is not int or not 1 <= revision <= 0xFFFFFFFF:
            raise DeclarationError(f"{identifier}: invalid recipe revision")
        target = tuple(
            metadata[key]
            for key in (
                "build",
                "platform_release",
                "architecture",
                "environment",
                "revision",
            )
        )
        if target != TARGETS[binding]:
            raise DeclarationError(
                f"{identifier}: unsupported recipe target or revision"
            )
        suffix = f"/{metadata['build']}/{metadata['platform_release']}/r{revision}"
        if identifier != browser.lower() + suffix:
            raise DeclarationError(f"{identifier}: identifier disagrees with metadata")

        layers = entry["layers"]
        if not isinstance(layers, list) or len(layers) != len(LAYERS):
            raise DeclarationError(f"{identifier}: every layer needs an explicit state")
        seen = set()
        for layer in layers:
            keys(
                layer,
                ("layer", "support", "references", "verified_fields", "limitations"),
                identifier,
            )
            name = choice(layer["layer"], LAYERS, "layer")
            if name in seen:
                raise DeclarationError(f"{identifier}: duplicate layer {name}")
            seen.add(name)
            support = choice(
                layer["support"],
                ("Configured", "IntentionallyAbsent", "Unavailable"),
                name,
            )
            if (support == "Configured") != (name in configured):
                raise DeclarationError(
                    f"{identifier}: support disagrees with {binding} for {name}"
                )
            if support == "IntentionallyAbsent" and not (
                browser == "Firefox" and name == "ClientHints"
            ):
                raise DeclarationError(f"{identifier}: unsupported absence claim")
            references = layer["references"]
            if not isinstance(references, list) or len(references) > MAX_REFERENCES:
                raise DeclarationError(f"{identifier}: too many evidence references")
            if support == "Configured" and not references:
                raise DeclarationError(
                    f"{identifier}: configured layer lacks provenance"
                )
            for reference in references:
                keys(reference, ("kind", "location", "build"), "evidence reference")
                kind = choice(
                    reference["kind"],
                    ("Capture", "Source", "Reused", "Recipe"),
                    "evidence kind",
                )
                location = text(reference["location"], "evidence location")
                text(reference["build"], "evidence build")
                if location.startswith("https://"):
                    if kind != "Source":
                        raise DeclarationError("only source references may use URLs")
                    try:
                        url = urlsplit(location)
                    except ValueError as error:
                        raise DeclarationError("invalid primary-source URL") from error
                    if not url.hostname or url.username or url.password:
                        raise DeclarationError("invalid primary-source URL")
                else:
                    if kind == "Source":
                        raise DeclarationError(
                            "browser source must use an upstream HTTPS URL"
                        )
                    path = Path(location.split("#", 1)[0])
                    if (
                        path.is_absolute()
                        or ".." in path.parts
                        or "\\" in location
                        or ":" in location
                    ):
                        raise DeclarationError(
                            "evidence path must stay within the repository"
                        )
                    if not (repo / path).is_file():
                        raise DeclarationError(f"missing evidence file: {location}")
                    if not (repo / path).resolve().is_relative_to(repo.resolve()):
                        raise DeclarationError(
                            "evidence symlink escapes the repository"
                        )
                    if kind == "Capture" and not location.startswith("fixtures/"):
                        raise DeclarationError(
                            "capture reference must name a retained fixture"
                        )
            string_list(layer["verified_fields"], "verified fields")
            string_list(layer["limitations"], "limitations")
            if layer["verified_fields"] and not any(
                item["kind"] == "Capture" for item in references
            ):
                raise DeclarationError("observed fields require capture evidence")
            if support != "Configured" and layer["verified_fields"]:
                raise DeclarationError(
                    "unconfigured layer cannot claim verified settings"
                )
    return sorted(profiles, key=lambda entry: entry["id"])


def read_document(path):
    with path.open("rb") as source:
        raw = source.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise DeclarationError("catalog input byte limit exceeded")
    try:
        return json.loads(raw, object_pairs_hook=object_pairs)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise DeclarationError(f"invalid catalog JSON: {error}") from error


def load(path=RECORDS, repo=REPO):
    return validate(read_document(path), repo)


def component_identifier(value):
    text(value, "component identifier")
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", value) or value in RUST_KEYWORDS:
        raise DeclarationError("component identifier must be a non-keyword Rust name")
    return value


def boolean(value, context):
    if type(value) is not bool:
        raise DeclarationError(f"{context}: expected boolean")


def validate_initial_settings(settings):
    if not isinstance(settings, list) or len(settings) > 64:
        raise DeclarationError("initial_settings: expected at most 64 settings")
    kinds = {}
    for setting in settings:
        keys(setting, ("kind", "value"), "HTTP/3 setting")
        kind = choice(
            setting["kind"],
            (*SETTING_BOUNDS, *BOOL_SETTINGS, "RandomizedGrease"),
            "HTTP/3 setting kind",
        )
        if kind in kinds:
            raise DeclarationError(f"duplicate HTTP/3 setting: {kind}")
        value = setting["value"]
        kinds[kind] = value
        if kind in SETTING_BOUNDS:
            if type(value) is not int or not 0 <= value <= SETTING_BOUNDS[kind]:
                raise DeclarationError(f"{kind}: HTTP/3 setting value out of range")
        elif kind in BOOL_SETTINGS:
            boolean(value, kind)
        elif value is not None:
            raise DeclarationError(
                "RandomizedGrease is a runtime policy without a value"
            )
    if kinds.get("EnableWebTransportDraft02"):
        raise DeclarationError("WebTransport is not implemented")
    if kinds.get("H3DatagramDraft04") and not kinds.get("H3Datagram"):
        raise DeclarationError("draft datagrams require final H3Datagram enabled")


def validate_pseudo_headers(order, extended):
    required = set(PSEUDO_HEADERS if extended else PSEUDO_HEADERS[:-1])
    if not isinstance(order, list) or len(order) != len(required):
        raise DeclarationError("pseudo-header order has an invalid length")
    for header in order:
        choice(header, required, "HTTP pseudo-header")
    if set(order) != required:
        raise DeclarationError("pseudo-header order must contain each header once")


def validate_component_values(kind, values):
    keys(values, COMPONENT_FIELDS[kind], kind)
    if kind == "Http2Settings":
        validate_http2_values(values)
        return
    for field, value in values.items():
        if field in COMPONENT_ENUMS:
            choice(value, COMPONENT_ENUMS[field][1], field)
        elif field == "initial_settings":
            validate_initial_settings(value)
        elif field == "reserved_frame_after_settings":
            boolean(value, field)
        elif field == "pseudo_header_order":
            validate_pseudo_headers(value, False)
        elif value is not None:
            validate_pseudo_headers(value, True)


def bounded_integer(value, minimum, maximum, context):
    if type(value) is not int or not minimum <= value <= maximum:
        raise DeclarationError(f"{context}: integer out of range")


def validate_duration(value, context):
    keys(value, ("seconds", "nanoseconds"), context)
    bounded_integer(value["seconds"], 0, MAX_U64, context)
    bounded_integer(value["nanoseconds"], 0, 999_999_999, context)


def duration_is_zero(value):
    return value["seconds"] == 0 and value["nanoseconds"] == 0


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
    # Instant::checked_add is host-specific. Native profile validation checks
    # clock representability; declarations bound Duration's stored fields only.


def validate_components(document, allowed_kinds=None):
    check_depth(document)
    keys(document, ("schema", "components"), "components")
    if type(document["schema"]) is not int or document["schema"] != 1:
        raise DeclarationError("unsupported component schema")
    components = document["components"]
    if not isinstance(components, list) or not 0 < len(components) <= MAX_COMPONENTS:
        raise DeclarationError("component count is outside declaration limits")
    by_id = {}
    for component in components:
        keys(component, ("id", "kind", "base", "values"), "component")
        identifier = component_identifier(component["id"])
        if identifier in by_id:
            raise DeclarationError(f"duplicate component identifier: {identifier}")
        kind = choice(component["kind"], COMPONENT_FIELDS, "component kind")
        if allowed_kinds is not None:
            choice(kind, allowed_kinds, "declaration layer kind")
        if component["base"] is not None:
            component_identifier(component["base"])
        values = component["values"]
        if not isinstance(values, dict) or not set(values) <= set(
            COMPONENT_FIELDS[kind]
        ):
            raise DeclarationError(f"{identifier}: unknown component override field")
        by_id[identifier] = component

    resolved = {}
    chain_lengths = {}

    def resolve(identifier, ancestors=()):
        if identifier in ancestors:
            raise DeclarationError("component reference cycle")
        if len(ancestors) >= MAX_COMPONENT_CHAIN:
            raise DeclarationError("component inheritance depth limit exceeded")
        if identifier not in by_id:
            raise DeclarationError(f"unknown component reference: {identifier}")
        if identifier in resolved:
            if len(ancestors) + chain_lengths[identifier] > MAX_COMPONENT_CHAIN:
                raise DeclarationError("component inheritance depth limit exceeded")
            return resolved[identifier]
        component = by_id[identifier]
        kind = component["kind"]
        values = {}
        chain_length = 1
        if component["base"] is not None:
            base = resolve(component["base"], (*ancestors, identifier))
            if base["kind"] != kind:
                raise DeclarationError(
                    f"{identifier}: incompatible base component kind"
                )
            values.update(base["values"])
            chain_length += chain_lengths[base["id"]]
        if chain_length > MAX_COMPONENT_CHAIN:
            raise DeclarationError("component inheritance depth limit exceeded")
        # An override replaces one complete typed field, including ordered lists.
        values.update(component["values"])
        validate_component_values(kind, values)
        resolved[identifier] = {"id": identifier, "kind": kind, "values": values}
        chain_lengths[identifier] = chain_length
        return resolved[identifier]

    return [resolve(identifier) for identifier in sorted(by_id)]


def load_components(path=COMPONENT_RECORDS):
    return validate_components(
        read_document(path), ("Http3Settings", "Http3RequestSettings")
    )


def load_http2_components(path=HTTP2_COMPONENT_RECORDS):
    return validate_components(read_document(path), ("Http2Settings",))


def rust_header_order(headers, protocol="Http3"):
    return (
        "vec!["
        + ", ".join(f"crate::{protocol}PseudoHeader::{item}" for item in headers)
        + "]"
    )


def rust_duration(value):
    return f"std::time::Duration::new({value['seconds']}, {value['nanoseconds']})"


def rust_option(value, expression):
    return "None" if value is None else f"Some({expression(value)})"


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


def rust_component_value(field, value, kind="Http3Settings"):
    if kind == "Http2Settings":
        return rust_http2_value(field, value)
    if field in COMPONENT_ENUMS:
        return f"crate::{COMPONENT_ENUMS[field][0]}::{value}"
    if field == "reserved_frame_after_settings":
        return str(value).lower()
    if field == "pseudo_header_order":
        return rust_header_order(value)
    if field == "extended_connect_pseudo_header_order":
        return "None" if value is None else f"Some({rust_header_order(value)})"
    settings = []
    for setting in value:
        kind, argument = setting["kind"], setting["value"]
        expression = f"crate::Http3Setting::{kind}"
        if kind != "RandomizedGrease":
            expression += f"({str(argument).lower()})"
        settings.append(expression)
    return "vec![" + ", ".join(settings) + "]"


def generate_components(components, declaration="http3-components.json"):
    lines = [
        f"// Generated by scripts/dev/generate_profiles.py; edit catalog/{declaration}.",
        "// Runtime draw policies remain enum variants; construction performs no draws.",
        "",
    ]
    for component in components:
        kind = component["kind"]
        lines.extend(
            [
                "#[rustfmt::skip]",
                f"pub(crate) fn {component['id']}() -> crate::{kind} {{",
                f"    crate::{kind} {{",
            ]
        )
        for field in COMPONENT_FIELDS[kind]:
            expression = rust_component_value(field, component["values"][field], kind)
            lines.append(f"        {field}: {expression},")
        lines.extend(["    }", "}", ""])
    return "\n".join(lines)


def rust_string(value):
    # JSON escaping of printable ASCII matches ordinary Rust string literals.
    # Keep non-ASCII literal so JSON's \uXXXX syntax never reaches Rust.
    return json.dumps(value, ensure_ascii=False)


def rust_strings(values):
    return "&[" + ", ".join(rust_string(value) for value in values) + "]"


def generate(profiles):
    lines = [
        "// Generated by scripts/dev/generate_profiles.py; edit catalog/profiles.json.",
        "use super::{",
        "    Browser, CaptureEnvironment, EvidenceKind, EvidenceReference, LayerEvidence, LayerSupport,",
        "    ProfileDefinition, ProfileId, ProfileLayer, ProfileMetadata, ProfilePlatform, RecipeBinding,",
        "};",
        "",
        "#[rustfmt::skip]",
        "pub(super) static PROFILES: &[ProfileDefinition] = &[",
    ]
    for entry in profiles:
        metadata = entry["metadata"]
        architecture = (
            "None"
            if metadata["architecture"] is None
            else f"Some({rust_string(metadata['architecture'])})"
        )
        lines.extend(
            [
                "    ProfileDefinition {",
                f"        id: ProfileId({rust_string(entry['id'])}),",
                "        metadata: ProfileMetadata {",
                f"            browser: Browser::{metadata['browser']},",
                f"            build: {rust_string(metadata['build'])},",
                f"            platform: ProfilePlatform::{metadata['platform']},",
                f"            platform_release: {rust_string(metadata['platform_release'])},",
                f"            architecture: {architecture},",
                f"            environment: CaptureEnvironment::{metadata['environment']},",
                f"            revision: {metadata['revision']},",
                "        },",
                "        layers: &[",
            ]
        )
        by_layer = {layer["layer"]: layer for layer in entry["layers"]}
        for name in LAYERS:
            layer = by_layer[name]
            lines.extend(
                [
                    "            LayerEvidence {",
                    f"                layer: ProfileLayer::{name},",
                    f"                support: LayerSupport::{layer['support']},",
                    "                references: &[",
                ]
            )
            for reference in layer["references"]:
                lines.extend(
                    [
                        "                    EvidenceReference {",
                        f"                        kind: EvidenceKind::{reference['kind']},",
                        f"                        location: {rust_string(reference['location'])},",
                        f"                        build: {rust_string(reference['build'])},",
                        "                    },",
                    ]
                )
            lines.extend(
                [
                    "                ],",
                    f"                verified_fields: {rust_strings(layer['verified_fields'])},",
                    f"                limitations: {rust_strings(layer['limitations'])},",
                    "            },",
                ]
            )
        lines.extend(
            [
                "        ],",
                f"        binding: RecipeBinding::{entry['binding']},",
                "    },",
            ]
        )
    lines.extend(["];"])
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true", help="reject stale committed generated files"
    )
    arguments = parser.parse_args()
    try:
        outputs = (
            (OUTPUT, generate(load())),
            (COMPONENT_OUTPUT, generate_components(load_components())),
            (
                HTTP2_COMPONENT_OUTPUT,
                generate_components(load_http2_components(), "http2-components.json"),
            ),
        )
        for output, generated in outputs:
            if arguments.check:
                if (
                    not output.is_file()
                    or output.read_text(encoding="utf-8") != generated
                ):
                    raise DeclarationError(
                        f"{output.name} is stale; run generate_profiles.py"
                    )
            else:
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(generated, encoding="utf-8", newline="\n")
    except (DeclarationError, OSError) as error:
        print(f"catalog generation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
