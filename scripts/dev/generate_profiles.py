"""Validate catalog records and typed components, then generate Rust offline."""

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

REPO = Path(__file__).resolve().parents[2]
RECORDS = REPO / "crates/phantom-profile/catalog/profiles.json"
OUTPUT = REPO / "crates/phantom-profile/src/catalog/generated.rs"
COMPONENT_RECORDS = REPO / "crates/phantom-profile/catalog/http3-components.json"
COMPONENT_OUTPUT = REPO / "crates/phantom-profile/src/catalog/http3_components.rs"
HTTP2_COMPONENT_RECORDS = REPO / "crates/phantom-profile/catalog/http2-components.json"
HTTP2_COMPONENT_OUTPUT = REPO / "crates/phantom-profile/src/catalog/http2_components.rs"
TLS_COMPONENT_RECORDS = REPO / "crates/phantom-profile/catalog/tls-components.json"
TLS_COMPONENT_OUTPUT = REPO / "crates/phantom-profile/src/tls/components.rs"
QUIC_COMPONENT_RECORDS = REPO / "crates/phantom-profile/catalog/quic-components.json"
QUIC_COMPONENT_OUTPUT = REPO / "crates/phantom-profile/src/catalog/quic_components.rs"
HTTP1_COMPONENT_RECORDS = REPO / "crates/phantom-profile/catalog/http1-components.json"
HTTP1_COMPONENT_OUTPUT = REPO / "crates/phantom-profile/src/catalog/http1_components.rs"
DNS_COMPONENT_RECORDS = REPO / "crates/phantom-profile/catalog/dns-components.json"
DNS_COMPONENT_OUTPUT = REPO / "crates/phantom-profile/src/catalog/dns_components.rs"
UDP_COMPONENT_RECORDS = REPO / "crates/phantom-profile/catalog/udp-components.json"
UDP_COMPONENT_OUTPUT = REPO / "crates/phantom-profile/src/catalog/udp_components.rs"

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
    "Http1Settings": ("max_connections_per_origin", "idle_timeout"),
    "DnsCacheSettings": ("max_entries", "ttl", "min_record_ttl", "negative_ttl"),
    "UdpSettings": ("port_randomization",),
    "QuicTransportSettings": (
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
    ),
    "TlsSettings": (
        "versions",
        "cipher_suites",
        "groups",
        "key_shares",
        "signature_schemes",
        "delegated_credential_schemes",
        "alpn_protocols",
        "alps",
        "certificate_compression",
        "session_tickets",
        "session_ticket_order",
        "session_ticket_extension_when_resuming",
        "tcp_early_data",
        "record_size_limit",
        "tls12_extensions_in_tls13_client_hello",
        "requested_trust_anchor_ids",
        "grease",
        "grease_signature_algorithms",
        "extension_order",
        "ech",
        "request_ocsp_staple",
        "request_signed_certificate_timestamps",
        "aes_hardware",
        "close_notify",
    ),
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
TLS_VERSIONS = ("Tls10", "Tls11", "Tls12", "Tls13")
TLS_ENUM_LISTS = {
    "cipher_suites": (
        "CipherSuite",
        (
            "Aes128GcmSha256",
            "Aes256GcmSha384",
            "Chacha20Poly1305Sha256",
            "EcdheEcdsaAes128GcmSha256",
            "EcdheRsaAes128GcmSha256",
            "EcdheEcdsaAes256GcmSha384",
            "EcdheRsaAes256GcmSha384",
            "EcdheEcdsaChacha20Poly1305Sha256",
            "EcdheRsaChacha20Poly1305Sha256",
            "EcdheRsaAes128CbcSha",
            "EcdheRsaAes256CbcSha",
            "EcdheEcdsaAes128CbcSha",
            "EcdheEcdsaAes256CbcSha",
            "EcdheEcdsa3DesEdeCbcSha",
            "EcdheRsa3DesEdeCbcSha",
            "RsaAes128GcmSha256",
            "RsaAes256GcmSha384",
            "RsaAes128CbcSha",
            "RsaAes256CbcSha",
            "Rsa3DesEdeCbcSha",
        ),
    ),
    "groups": (
        "NamedGroup",
        (
            "X25519MlKem768",
            "X25519",
            "Secp256r1",
            "Secp384r1",
            "Secp521r1",
            "Ffdhe2048",
            "Ffdhe3072",
        ),
    ),
    "signature_schemes": (
        "SignatureScheme",
        (
            "MlDsa44",
            "MlDsa65",
            "MlDsa87",
            "EcdsaSecp256r1Sha256",
            "RsaPssRsaeSha256",
            "RsaPkcs1Sha256",
            "EcdsaSecp384r1Sha384",
            "EcdsaSecp521r1Sha512",
            "RsaPssRsaeSha384",
            "RsaPkcs1Sha384",
            "RsaPssRsaeSha512",
            "RsaPkcs1Sha512",
            "EcdsaSha1",
            "RsaPkcs1Sha1",
        ),
    ),
    "certificate_compression": ("CertificateCompression", ("Zlib", "Brotli", "Zstd")),
}
TLS_ENUM_LISTS["key_shares"] = TLS_ENUM_LISTS["groups"]
TLS_ENUM_LISTS["delegated_credential_schemes"] = TLS_ENUM_LISTS["signature_schemes"]
TLS_DELEGATED_SCHEMES = (
    "EcdsaSecp256r1Sha256",
    "EcdsaSecp384r1Sha384",
    "EcdsaSecp521r1Sha512",
    "EcdsaSha1",
)
TLS_EXTENSIONS = (
    "ServerName",
    "ExtendedMasterSecret",
    "RenegotiationInfo",
    "SupportedGroups",
    "EcPointFormats",
    "SessionTicket",
    "RecordSizeLimit",
    "Alpn",
    "StatusRequest",
    "SignedCertificateTimestamp",
    "KeyShare",
    "EarlyData",
    "SupportedVersions",
    "SignatureAlgorithms",
    "DelegatedCredential",
    "PskKeyExchangeModes",
    "CertificateCompression",
    "TrustAnchors",
    "ApplicationSettings",
    "ApplicationSettingsLegacy",
    "EncryptedClientHello",
    "QuicTransportParameters",
)
TLS_AEADS = ("Aes128Gcm", "Aes256Gcm", "ChaCha20Poly1305")
TLS_BOOLEAN_FIELDS = (
    "session_ticket_extension_when_resuming",
    "tcp_early_data",
    "tls12_extensions_in_tls13_client_hello",
    "grease",
    "grease_signature_algorithms",
    "request_ocsp_staple",
    "request_signed_certificate_timestamps",
    "aes_hardware",
    "close_notify",
)
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
    if kind == "Http1Settings":
        validate_http1_values(values)
        return
    if kind == "DnsCacheSettings":
        validate_dns_values(values)
        return
    if kind == "UdpSettings":
        boolean(values["port_randomization"], "port_randomization")
        return
    if kind == "QuicTransportSettings":
        validate_quic_values(values)
        return
    if kind == "TlsSettings":
        validate_tls_values(values)
        return
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


def bounded_list(value, minimum, maximum, context):
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise DeclarationError(f"{context}: list length out of range")


def validate_bytes(value, minimum, maximum, context):
    bounded_list(value, minimum, maximum, context)
    for byte in value:
        bounded_integer(byte, 0, 255, context)


def validate_tls_trust_anchors(value):
    if value is None:
        return
    keys(value, ("kind", "orders"), "TLS trust anchors")
    kind = choice(
        value["kind"],
        ("Fixed", "PerClient", "PerConnection"),
        "TLS trust anchor policy",
    )
    orders = value["orders"]
    bounded_list(orders, 1, 1 if kind == "Fixed" else 64, "TLS trust anchor candidates")
    expected = None
    for order in orders:
        bounded_list(order, 0, 4096, "TLS trust anchor IDs")
        for identifier in order:
            validate_bytes(identifier, 1, 255, "TLS trust anchor ID")
        if sum(1 + len(identifier) for identifier in order) > 65_533:
            raise DeclarationError("TLS trust anchor encoded list exceeds 65533 bytes")
        multiset = sorted(tuple(identifier) for identifier in order)
        if expected is not None and multiset != expected:
            raise DeclarationError(
                "TLS trust anchor candidates must preserve the same ID multiset"
            )
        expected = multiset


def validate_tls_ech(value):
    keys(value, ("kind", "settings"), "TLS ECH")
    kind = choice(
        value["kind"], ("Disabled", "Grease", "HttpsRecords"), "TLS ECH policy"
    )
    settings = value["settings"]
    if kind == "Disabled":
        if settings is not None:
            raise DeclarationError("Disabled ECH has no GREASE settings")
        return
    keys(settings, ("payload_length", "aeads"), "TLS ECH GREASE settings")
    payload = settings["payload_length"]
    keys(payload, ("kind", "value"), "TLS ECH GREASE payload")
    policy = choice(
        payload["kind"],
        ("BackendDefault", "Exact", "FromClientHello"),
        "TLS ECH payload policy",
    )
    if policy == "BackendDefault":
        if payload["value"] is not None:
            raise DeclarationError("BackendDefault ECH payload has no value")
    else:
        minimum, maximum = (1, 65_493) if policy == "Exact" else (0, 255)
        bounded_integer(payload["value"], minimum, maximum, "TLS ECH payload")
    aeads = settings["aeads"]
    bounded_list(aeads, 0, len(TLS_AEADS), "TLS ECH AEADs")
    for aead in aeads:
        choice(aead, TLS_AEADS, "TLS ECH AEAD")
    if len(set(aeads)) != len(aeads):
        raise DeclarationError("duplicate TLS ECH AEAD")


def validate_tls_values(values):
    versions = values["versions"]
    keys(versions, ("min", "max"), "TLS versions")
    for endpoint in versions.values():
        choice(endpoint, TLS_VERSIONS, "TLS version")
    if TLS_VERSIONS.index(versions["min"]) > TLS_VERSIONS.index(versions["max"]):
        raise DeclarationError("TLS version range is reversed")
    tls13 = versions["max"] == "Tls13"
    for field, (_, variants) in TLS_ENUM_LISTS.items():
        items = values[field]
        bounded_list(
            items,
            1 if field in ("cipher_suites", "groups", "signature_schemes") else 0,
            64,
            field,
        )
        for item in items:
            choice(item, variants, field)
    for scheme in values["delegated_credential_schemes"]:
        choice(scheme, TLS_DELEGATED_SCHEMES, "TLS delegated credential scheme")
    compression = values["certificate_compression"]
    if len(set(compression)) != len(compression):
        raise DeclarationError("duplicate TLS certificate compression algorithm")
    for field in TLS_BOOLEAN_FIELDS:
        boolean(values[field], field)
    tickets = values["session_tickets"]
    keys(tickets, ("enabled", "tcp_per_origin"), "TLS session tickets")
    boolean(tickets["enabled"], "TLS session tickets enabled")
    if tickets["enabled"]:
        bounded_integer(tickets["tcp_per_origin"], 1, 10, "TLS ticket limit")
    elif tickets["tcp_per_origin"] is not None:
        raise DeclarationError("disabled TLS tickets have no limit")
    choice(
        values["session_ticket_order"],
        ("NewestFirst", "OldestConnectionFirst", "OldestFirst"),
        "TLS ticket order",
    )
    if values["tcp_early_data"] and not tickets["enabled"]:
        raise DeclarationError("TCP early data requires TLS session tickets")
    if values["record_size_limit"] is not None:
        bounded_integer(
            values["record_size_limit"], 64, 16_385, "TLS record size limit"
        )
    validate_tls_trust_anchors(values["requested_trust_anchor_ids"])
    validate_tls_ech(values["ech"])
    if not tls13:
        if (
            values["tcp_early_data"]
            or values["key_shares"]
            or values["ech"]["kind"] != "Disabled"
            or values["requested_trust_anchor_ids"] is not None
            or values["certificate_compression"]
            or values["delegated_credential_schemes"]
            or values["alps"] is not None
        ):
            raise DeclarationError("TLS 1.3-only settings require TLS 1.3")
    elif not values["key_shares"] or any(
        group not in values["groups"] for group in values["key_shares"]
    ):
        raise DeclarationError(
            "TLS 1.3 requires key shares present in supported groups"
        )
    protocols = values["alpn_protocols"]
    bounded_list(protocols, 1, 256, "TLS ALPN protocols")
    for protocol in protocols:
        validate_bytes(protocol, 1, 255, "TLS ALPN protocol")
    if sum(1 + len(protocol) for protocol in protocols) > 65_535:
        raise DeclarationError("TLS ALPN encoded list exceeds 65535 bytes")
    alps = values["alps"]
    if alps is not None:
        keys(alps, ("protocol", "settings", "use_new_codepoint"), "TLS ALPS")
        validate_bytes(alps["protocol"], 1, 255, "TLS ALPS protocol")
        validate_bytes(alps["settings"], 0, 65_535, "TLS ALPS settings")
        boolean(alps["use_new_codepoint"], "TLS ALPS codepoint")
        if alps["protocol"] not in protocols:
            raise DeclarationError("TLS ALPS protocol is absent from ALPN")
    extension = values["extension_order"]
    keys(extension, ("kind", "extensions"), "TLS extension order")
    kind = choice(
        extension["kind"],
        ("BackendDefault", "Permuted", "Fixed", "PermutedWithTail"),
        "TLS extension policy",
    )
    extensions = extension["extensions"]
    bounded_list(
        extensions,
        1 if kind in ("Fixed", "PermutedWithTail") else 0,
        64,
        "TLS extension list",
    )
    for name in extensions:
        choice(name, TLS_EXTENSIONS, "TLS extension")
    if len(set(extensions)) != len(extensions):
        raise DeclarationError("duplicate TLS extension")
    if kind in ("BackendDefault", "Permuted") and extensions:
        raise DeclarationError("TLS extension policy has no fixed list")


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


def validate_http1_values(values):
    # Compiled declarations fit both 32-bit and 64-bit usize. Custom typed
    # settings retain their native host-sized range.
    bounded_integer(
        values["max_connections_per_origin"], 1, MAX_U32, "connection limit"
    )
    timeout = values["idle_timeout"]
    if not isinstance(timeout, dict):
        raise DeclarationError("HTTP/1.1 idle timeout must be a typed record")
    kind = choice(
        timeout.get("kind"),
        ("Unlimited", "CheckedOnRequest", "ClosedOnTimer"),
        "HTTP/1.1 idle timeout",
    )
    if kind == "Unlimited":
        keys(timeout, ("kind",), "HTTP/1.1 idle timeout")
        return
    keys(timeout, ("kind", "duration"), "HTTP/1.1 idle timeout")
    validate_duration(timeout["duration"], "HTTP/1.1 idle timeout")
    duration = timeout["duration"]
    if kind == "ClosedOnTimer" and (
        duration["seconds"] > 65_535
        or (duration["seconds"] == 65_535 and duration["nanoseconds"] != 0)
    ):
        raise DeclarationError(
            "HTTP/1.1 timer idle limit must be at most 65535 seconds"
        )


def validate_dns_values(values):
    bounded_integer(values["max_entries"], 1, MAX_U32, "DNS cache entry limit")
    for field in ("ttl", "min_record_ttl"):
        validate_duration(values[field], field)
    if values["negative_ttl"] is not None:
        validate_duration(values["negative_ttl"], "negative_ttl")


QUIC_WIDTHS = {"One": 1, "Two": 2, "Four": 4, "Eight": 8}
QUIC_SCALARS = {
    "MaxIdleTimeout": ("max_idle_timeout_ms", 0x01, 0),
    "MaxUdpPayloadSize": ("max_udp_payload_size", 0x03, 65_527),
    "InitialMaxData": ("initial_max_data", 0x04, 0),
    "InitialMaxStreamDataBidiLocal": ("initial_max_stream_data_bidi_local", 0x05, 0),
    "InitialMaxStreamDataBidiRemote": ("initial_max_stream_data_bidi_remote", 0x06, 0),
    "InitialMaxStreamDataUni": ("initial_max_stream_data_uni", 0x07, 0),
    "InitialMaxStreamsBidi": ("initial_max_streams_bidi", 0x08, 0),
    "InitialMaxStreamsUni": ("initial_max_streams_uni", 0x09, 0),
    "MaxAckDelay": ("max_ack_delay_ms", 0x0B, 25),
    "ActiveConnectionIdLimit": ("active_connection_id_limit", 0x0E, 2),
    "MaxDatagramFrameSize": ("max_datagram_frame_size", 0x20, None),
}
QUIC_PARAMETER_FIELDS = {
    **dict.fromkeys(QUIC_SCALARS, ("value_width",)),
    "ResetStreamAt": (),
    "MinAckDelay": ("draft", "value_width"),
    "InitialSourceConnectionId": ("length",),
    "VersionInformation": ("available_version_count", "grease"),
    "GoogleConnectionOptions": ("options",),
    "InitialRtt": (),
    "Grease": ("minimum_payload_length", "maximum_payload_length"),
}


def quic_width(width, value):
    size = QUIC_WIDTHS[choice(width, QUIC_WIDTHS, "QUIC integer width")]
    bounded_integer(value, 0, (1 << (size * 8 - 2)) - 1, "QUIC encoded integer")
    return size


def validate_quic_parameter(parameter, values):
    keys(parameter, ("kind", "id_width", "length_width"), "QUIC parameter")
    record = parameter["kind"]
    if not isinstance(record, dict):
        raise DeclarationError("QUIC parameter kind must be a typed record")
    kind = choice(record.get("kind"), QUIC_PARAMETER_FIELDS, "QUIC parameter kind")
    keys(record, ("kind", *QUIC_PARAMETER_FIELDS[kind]), "QUIC parameter kind")
    if kind in QUIC_SCALARS:
        field, identifier, _ = QUIC_SCALARS[kind]
        if values[field] is None:
            raise DeclarationError(f"{kind} requires {field}")
        length = quic_width(record["value_width"], values[field])
    elif kind == "MinAckDelay":
        draft = choice(record["draft"], ("Draft02", "Draft07"), "ACK frequency draft")
        identifier = 0xFF02DE1A if draft == "Draft02" else 0xFF04DE1B
        if values["min_ack_delay_us"] is None:
            raise DeclarationError("MinAckDelay requires min_ack_delay_us")
        length = quic_width(record["value_width"], values["min_ack_delay_us"])
    elif kind == "ResetStreamAt":
        identifier, length = 0x1D, 0
    elif kind == "InitialSourceConnectionId":
        identifier = 0x0F
        bounded_integer(record["length"], 0, 20, "source connection ID length")
        length = record["length"]
    elif kind == "VersionInformation":
        identifier = 0x11
        # The current provider implements QUIC v1 and v2 only.
        count = record["available_version_count"]
        bounded_integer(count, 0, 2, "available version count")
        if count == 0:
            raise DeclarationError("available versions must include the chosen version")
        grease = choice(
            record["grease"], ("Omit", "Permuted", "First"), "version GREASE"
        )
        length = 4 + 4 * (count + (grease != "Omit"))
    elif kind == "GoogleConnectionOptions":
        identifier = 0x3128
        bounded_list(record["options"], 1, 1, "Google connection options")
        choice(
            record["options"][0], ("RequestOriginFrame",), "Google connection option"
        )
        length = 4 * len(record["options"])
    elif kind == "InitialRtt":
        identifier, length = 0x3127, 8
    else:
        # A reserved identifier is drawn and encoded by the runtime.
        identifier = None
        for field in ("minimum_payload_length", "maximum_payload_length"):
            bounded_integer(record[field], 0, 15, "GREASE payload length")
        if record["minimum_payload_length"] > record["maximum_payload_length"]:
            raise DeclarationError("GREASE payload length range must not be empty")
        length = record["maximum_payload_length"]
    if identifier is None:
        choice(parameter["id_width"], QUIC_WIDTHS, "QUIC integer width")
    else:
        quic_width(parameter["id_width"], identifier)
    quic_width(parameter["length_width"], length)
    return kind


def validate_quic_values(values):
    for kind, (field, _, _) in QUIC_SCALARS.items():
        value = values[field]
        if kind == "MaxDatagramFrameSize" and value is None:
            continue
        maximum = 1 << 60 if "Streams" in kind else MAX_VARINT
        bounded_integer(value, 0, maximum, field)
    if not 1_200 <= values["max_udp_payload_size"] <= 65_527:
        raise DeclarationError("max_udp_payload_size must be in 1200..=65527")
    if values["max_ack_delay_ms"] >= 16_384:
        raise DeclarationError("max_ack_delay_ms must be below 16384")
    if not 2 <= values["active_connection_id_limit"] <= 8:
        raise DeclarationError("active_connection_id_limit must be in 2..=8")
    delay = values["min_ack_delay_us"]
    if delay is not None:
        bounded_integer(delay, 0, MAX_VARINT, "min_ack_delay_us")
        if delay != 1_000 or delay > values["max_ack_delay_ms"] * 1_000:
            raise DeclarationError(
                "provider ACK delay must be 1000 us and within max ACK delay"
            )
    mtu = values["initial_path_mtu"]
    if mtu is not None:
        bounded_integer(mtu, 0, 65_535, "initial_path_mtu")
        if not 1_248 <= mtu <= values["max_udp_payload_size"] + 28:
            raise DeclarationError("path MTU exceeds the IPv4/IPv6 payload bounds")
    cid = values["initial_destination_connection_id"]
    if cid is not None:
        if not isinstance(cid, dict):
            raise DeclarationError("connection ID length must be a typed record")
        policy = choice(
            cid.get("kind"), ("Fixed", "MaskedRandom"), "connection ID policy"
        )
        if policy == "Fixed":
            keys(cid, ("kind", "length"), "connection ID policy")
            bounded_integer(cid["length"], 0, 20, "connection ID length")
            shortest = longest = cid["length"]
        else:
            keys(cid, ("kind", "minimum", "base"), "connection ID policy")
            bounded_integer(cid["minimum"], 0, 255, "minimum connection ID length")
            bounded_integer(cid["base"], 0, 255, "base connection ID length")
            shortest = cid["minimum"]
            longest = max(shortest, min(255, cid["base"] + 15))
        if shortest < 8 or longest > 20:
            raise DeclarationError("connection ID length policy must stay in 8..=20")
    boolean(values["reset_stream_at"], "reset_stream_at")
    boolean(values["early_data"], "early_data")
    choice(values["parameter_order"], ("Fixed", "Permuted"), "parameter order")
    parameters = values["wire_parameters"]
    if not isinstance(parameters, list) or not 1 <= len(parameters) <= len(
        QUIC_PARAMETER_FIELDS
    ):
        raise DeclarationError(
            "QUIC wire parameter count is outside declaration limits"
        )
    identities = [
        validate_quic_parameter(parameter, values) for parameter in parameters
    ]
    if len(set(identities)) != len(identities):
        raise DeclarationError("QUIC wire parameter kinds must not repeat")
    if "InitialSourceConnectionId" not in identities:
        raise DeclarationError("InitialSourceConnectionId is required")
    for kind, (field, _, default) in QUIC_SCALARS.items():
        if values[field] != default and kind not in identities:
            raise DeclarationError(f"nondefault {field} must be advertised")
    for enabled, kind in (
        (values["max_datagram_frame_size"] is not None, "MaxDatagramFrameSize"),
        (delay is not None, "MinAckDelay"),
        (values["reset_stream_at"], "ResetStreamAt"),
    ):
        if enabled != (kind in identities):
            raise DeclarationError(f"{kind} must match its configured value")


def rust_quic_parameter(parameter):
    record = parameter["kind"]
    kind = record["kind"]
    expression = f"crate::QuicTransportParameterKind::{kind}"
    if kind in QUIC_SCALARS:
        expression += (
            f" {{ value_width: crate::QuicVarIntWidth::{record['value_width']} }}"
        )
    elif kind == "MinAckDelay":
        expression += (
            f" {{ draft: crate::QuicAckFrequencyDraft::{record['draft']},"
            f" value_width: crate::QuicVarIntWidth::{record['value_width']} }}"
        )
    elif kind == "InitialSourceConnectionId":
        expression += f" {{ length: {record['length']} }}"
    elif kind == "VersionInformation":
        expression += (
            "(crate::QuicVersionInformation {"
            f" available_version_count: {record['available_version_count']},"
            f" grease: crate::QuicVersionGrease::{record['grease']} }})"
        )
    elif kind == "GoogleConnectionOptions":
        options = ", ".join(
            f"crate::GoogleConnectionOption::{item}" for item in record["options"]
        )
        expression += f"(vec![{options}])"
    elif kind == "Grease":
        expression += (
            "(crate::QuicTransportGrease {"
            f" minimum_payload_length: {record['minimum_payload_length']},"
            f" maximum_payload_length: {record['maximum_payload_length']} }})"
        )
    return (
        f"crate::QuicTransportParameter {{ kind: {expression},"
        f" id_width: crate::QuicVarIntWidth::{parameter['id_width']},"
        f" length_width: crate::QuicVarIntWidth::{parameter['length_width']} }}"
    )


def rust_quic_value(field, value):
    if field == "wire_parameters":
        return "vec![" + ", ".join(rust_quic_parameter(item) for item in value) + "]"
    if field == "parameter_order":
        return f"crate::QuicTransportParameterOrder::{value}"
    if field == "initial_destination_connection_id":
        if value is None:
            return "None"
        if value["kind"] == "Fixed":
            return f"Some(crate::QuicConnectionIdLength::Fixed({value['length']}))"
        return (
            "Some(crate::QuicConnectionIdLength::MaskedRandom {"
            f" minimum: {value['minimum']}, base: {value['base']} }})"
        )
    if field in ("max_datagram_frame_size", "min_ack_delay_us", "initial_path_mtu"):
        return rust_option(value, str)
    return str(value).lower()


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


def load_tls_components(path=TLS_COMPONENT_RECORDS):
    return validate_components(read_document(path), ("TlsSettings",))


def load_quic_components(path=QUIC_COMPONENT_RECORDS):
    return validate_components(read_document(path), ("QuicTransportSettings",))


def load_http1_components(path=HTTP1_COMPONENT_RECORDS):
    return validate_components(read_document(path), ("Http1Settings",))


def load_dns_components(path=DNS_COMPONENT_RECORDS):
    return validate_components(read_document(path), ("DnsCacheSettings",))


def load_udp_components(path=UDP_COMPONENT_RECORDS):
    return validate_components(read_document(path), ("UdpSettings",))


def rust_byte_slice(value):
    return "&[" + ", ".join(str(byte) for byte in value) + "]"


def rust_bytes(value):
    return f"Box::<[u8]>::from({rust_byte_slice(value)}[..])"


def rust_trust_order(order):
    return (
        "crate::TrustAnchorOrder::from_recipe(vec!["
        + ", ".join(rust_bytes(identifier) for identifier in order)
        + "])"
    )


def rust_tls_ech(value):
    if value["kind"] == "Disabled":
        return "crate::EchSettings::Disabled"
    settings = value["settings"]
    payload = settings["payload_length"]
    length = f"crate::EchGreasePayloadLength::{payload['kind']}"
    if payload["kind"] == "Exact":
        length += f"({payload['value']})"
    elif payload["kind"] == "FromClientHello":
        length += f" {{ maximum_name_length: {payload['value']} }}"
    aeads = (
        "vec!["
        + ", ".join(f"crate::EchGreaseAead::{name}" for name in settings["aeads"])
        + "]"
    )
    grease = f"crate::EchGreaseSettings {{ payload_length: {length}, aeads: {aeads} }}"
    return f"crate::EchSettings::{value['kind']}({grease})"


def rust_tls_value(field, value):
    if field in TLS_ENUM_LISTS:
        enum = TLS_ENUM_LISTS[field][0]
        return "vec![" + ", ".join(f"crate::{enum}::{item}" for item in value) + "]"
    if field in TLS_BOOLEAN_FIELDS:
        return str(value).lower()
    if field == "versions":
        return f"crate::TlsVersionRange {{ min: crate::TlsVersion::{value['min']}, max: crate::TlsVersion::{value['max']} }}"
    if field == "alpn_protocols":
        return "vec![" + ", ".join(rust_bytes(protocol) for protocol in value) + "]"
    if field == "alps":
        return rust_option(
            value,
            lambda alps: (
                "crate::AlpsSettings { "
                + f"protocol: {rust_bytes(alps['protocol'])}, settings: {rust_bytes(alps['settings'])}, use_new_codepoint: {str(alps['use_new_codepoint']).lower()} "
                + "}"
            ),
        )
    if field == "session_tickets":
        if not value["enabled"]:
            return "crate::SessionTickets::disabled()"
        if value["tcp_per_origin"] == 2:
            return "crate::tls::TWO_SESSION_TICKETS"
        if value["tcp_per_origin"] == 10:
            return "crate::tls::TEN_SESSION_TICKETS"
        return f"crate::SessionTickets {{ tcp_per_origin: std::num::NonZeroU8::new({value['tcp_per_origin']}) }}"
    if field == "session_ticket_order":
        return f"crate::SessionTicketOrder::{value}"
    if field == "record_size_limit":
        return rust_option(value, str)
    if field == "requested_trust_anchor_ids":
        if value is None:
            return "None"
        orders = value["orders"]
        if value["kind"] == "Fixed":
            inner = rust_trust_order(orders[0])
        else:
            inner = (
                "crate::TrustAnchorOrders::from_recipe(vec!["
                + ", ".join(rust_trust_order(order) for order in orders)
                + "])"
            )
        return f"Some(crate::TrustAnchorIds::{value['kind']}({inner}))"
    if field == "extension_order":
        expression = f"crate::ClientHelloExtensionOrder::{value['kind']}"
        if value["kind"] in ("Fixed", "PermutedWithTail"):
            expression += (
                "(vec!["
                + ", ".join(
                    f"crate::ClientHelloExtension::{name}"
                    for name in value["extensions"]
                )
                + "])"
            )
        return expression
    return rust_tls_ech(value)


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
    if kind == "Http1Settings":
        if field == "max_connections_per_origin":
            return rust_nonzero_usize(value)
        expression = f"crate::Http1IdleTimeout::{value['kind']}"
        if value["kind"] != "Unlimited":
            expression += f"({rust_duration(value['duration'])})"
        return expression
    if kind == "DnsCacheSettings":
        if field == "max_entries":
            return rust_nonzero_usize(value)
        return (
            rust_option(value, rust_duration)
            if field == "negative_ttl"
            else rust_duration(value)
        )
    if kind == "UdpSettings":
        return str(value).lower()
    if kind == "QuicTransportSettings":
        return rust_quic_value(field, value)
    if kind == "TlsSettings":
        return rust_tls_value(field, value)
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


def rust_nonzero_usize(value):
    # The const block rejects invalid emitted literals at compile time; no
    # runtime panic or substitution exists in a generated factory.
    return (
        f"const {{ match std::num::NonZeroUsize::new({value}) {{"
        ' Some(value) => value, None => panic!("invalid nonzero component literal") } }'
    )


TLS_TRUST_CANDIDATE_VALIDATOR = """#[allow(dead_code, reason = "Rust 1.88 does not count anonymous const assertions as uses")]
const fn _valid_recipe_trust_candidates<const N: usize>(orders: &[&[&[u8]]], expected: &[(&[u8], usize); N]) -> bool {
    const fn compare_ids(left: &[u8], right: &[u8]) -> i8 {
        let mut index = 0;
        while index < left.len() && index < right.len() {
            if left[index] < right[index] { return -1; }
            if left[index] > right[index] { return 1; }
            index += 1;
        }
        if left.len() < right.len() { return -1; }
        if left.len() > right.len() { return 1; }
        0
    }
    if orders.is_empty() { return false; }
    let mut total = 0usize;
    let mut encoded = 0usize;
    let mut index = 0;
    while index < N {
        let (id, count) = expected[index];
        if id.is_empty() || id.len() > 255 || count == 0 { return false; }
        if index > 0 && compare_ids(expected[index - 1].0, id) >= 0 { return false; }
        let Some(next_total) = total.checked_add(count) else { return false; };
        total = next_total;
        let Some(bytes) = (id.len() + 1).checked_mul(count) else { return false; };
        let Some(next_encoded) = encoded.checked_add(bytes) else { return false; };
        encoded = next_encoded;
        index += 1;
    }
    if encoded > 65533 { return false; }
    let mut candidate = 0;
    while candidate < orders.len() {
        let order = orders[candidate];
        if order.len() != total { return false; }
        let mut counts = [0usize; N];
        let mut position = 0;
        while position < order.len() {
            let id = order[position];
            let mut low = 0;
            let mut high = N;
            let mut found = false;
            while low < high {
                let middle = low + (high - low) / 2;
                let comparison = compare_ids(id, expected[middle].0);
                if comparison < 0 { high = middle; }
                else if comparison > 0 { low = middle + 1; }
                else {
                    counts[middle] += 1;
                    found = true;
                    break;
                }
            }
            if !found { return false; }
            position += 1;
        }
        index = 0;
        while index < N {
            if counts[index] != expected[index].1 { return false; }
            index += 1;
        }
        candidate += 1;
    }
    true
}

#[cfg(test)]
#[rustfmt::skip]
#[test]
fn _trust_candidate_assertion_preserves_multisets_and_duplicate_slots() {
    let expected: &[(&[u8], usize); 2] = &[(&[1], 2), (&[2], 1)];
    assert!(_valid_recipe_trust_candidates(&[&[], &[]], &[]));
    assert!(_valid_recipe_trust_candidates(&[&[&[1], &[2], &[1]], &[&[2], &[1], &[1]], &[&[1], &[2], &[1]]], expected));
    assert!(_valid_recipe_trust_candidates(&[&[&[1, 0], &[1]]], &[(&[1], 1), (&[1, 0], 1)]));
    assert!(!_valid_recipe_trust_candidates(&[], expected));
    assert!(!_valid_recipe_trust_candidates(&[&[&[1], &[2], &[2]]], expected));
    assert!(!_valid_recipe_trust_candidates(&[&[&[1], &[1]]], expected));
    assert!(!_valid_recipe_trust_candidates(&[&[&[1], &[2], &[3]]], expected));
    assert!(!_valid_recipe_trust_candidates(&[&[&[1, 2]]], &[(&[1, 3], 1)]));
    assert!(!_valid_recipe_trust_candidates(&[&[&[1]]], &[(&[1, 0], 1)]));
    assert!(!_valid_recipe_trust_candidates(&[&[&[1], &[2]]], &[(&[2], 1), (&[1], 1)]));
    assert!(!_valid_recipe_trust_candidates(&[&[&[1], &[1]]], &[(&[1], 1), (&[1], 1)]));
    assert!(!_valid_recipe_trust_candidates(&[&[]], &[(&[1], 0)]));
    assert!(!_valid_recipe_trust_candidates(&[&[&[]]], &[(&[], 1)]));
    assert!(!_valid_recipe_trust_candidates(&[&[]], &[(&[1; 256], 1)]));
    assert!(!_valid_recipe_trust_candidates(&[&[]], &[(&[1; 255], 256)]));
    assert!(!_valid_recipe_trust_candidates(&[&[]], &[(&[1], usize::MAX)]));
}

#[cfg(test)]
#[rustfmt::skip]
#[test]
fn _trust_candidate_assertion_accepts_declared_count_ceilings() {
    let ids = (0..4096_u16).map(u16::to_be_bytes).collect::<Vec<_>>();
    let reference: [(&[u8], usize); 4096] = std::array::from_fn(|index| (ids[index].as_slice(), 1));
    let reversed = ids.iter().rev().map(|id| id.as_slice()).collect::<Vec<_>>();
    assert!(_valid_recipe_trust_candidates(&[reversed.as_slice(); 64], &reference));
}
"""


def generate_components(components, declaration="http3-components.json"):
    lines = [
        f"// Generated by scripts/dev/generate_profiles.py; edit catalog/{declaration}.",
        "// Runtime draw policies remain enum variants; construction performs no draws.",
        "",
    ]
    if any(
        component["kind"] == "TlsSettings"
        and component["values"]["requested_trust_anchor_ids"] is not None
        and component["values"]["requested_trust_anchor_ids"]["kind"] != "Fixed"
        for component in components
    ):
        lines.extend(["#[rustfmt::skip]", TLS_TRUST_CANDIDATE_VALIDATOR.rstrip(), ""])
    for component in components:
        kind = component["kind"]
        if kind == "TlsSettings":
            tickets = component["values"]["session_tickets"]
            if tickets["enabled"]:
                lines.append("#[rustfmt::skip]")
                lines.append(
                    f"const _: () = assert!(matches!({tickets['tcp_per_origin']}, 1..=10));"
                )
            anchors = component["values"]["requested_trust_anchor_ids"]
            if anchors is not None:
                if anchors["kind"] != "Fixed":
                    candidates = (
                        "&["
                        + ", ".join(
                            "&["
                            + ", ".join(
                                rust_byte_slice(identifier) for identifier in order
                            )
                            + "]"
                            for order in anchors["orders"]
                        )
                        + "]"
                    )
                    counts = Counter(
                        tuple(identifier) for identifier in anchors["orders"][0]
                    )
                    reference = (
                        "&["
                        + ", ".join(
                            f"({rust_byte_slice(identifier)}, {count})"
                            for identifier, count in sorted(counts.items())
                        )
                        + "]"
                    )
                    lines.extend(
                        [
                            "#[rustfmt::skip]",
                            f"const _: () = assert!(_valid_recipe_trust_candidates({candidates}, {reference}));",
                        ]
                    )
                for order in anchors["orders"]:
                    static_ids = (
                        "&["
                        + ", ".join(rust_byte_slice(identifier) for identifier in order)
                        + "]"
                    )
                    lines.append("#[rustfmt::skip]")
                    lines.append(
                        f"const _: () = assert!(crate::TrustAnchorOrder::valid_recipe_ids({static_ids}));"
                    )
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
            (
                TLS_COMPONENT_OUTPUT,
                generate_components(load_tls_components(), "tls-components.json"),
            ),
            (
                QUIC_COMPONENT_OUTPUT,
                generate_components(load_quic_components(), "quic-components.json"),
            ),
            (
                HTTP1_COMPONENT_OUTPUT,
                generate_components(load_http1_components(), "http1-components.json"),
            ),
            (
                DNS_COMPONENT_OUTPUT,
                generate_components(load_dns_components(), "dns-components.json"),
            ),
            (
                UDP_COMPONENT_OUTPUT,
                generate_components(load_udp_components(), "udp-components.json"),
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
