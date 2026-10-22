"""Closed typed component dispatch, inheritance and Rust generation."""

from collections import Counter

from .client_hints import (
    generate_client_hints_component,
    validate_client_hints_values,
    validate_hint_function_names,
)
from .connection_policies import (
    validate_dns_values,
    validate_http1_values,
)
from .cookie import rust_cookie_values, validate_cookie_values
from .declarations import (
    MAX_COMPONENT_CHAIN,
    MAX_COMPONENTS,
    DeclarationError,
    boolean,
    check_depth,
    choice,
    component_identifier,
    keys,
)
from .http2 import (
    rust_http2_value,
    validate_http2_values,
)
from .http3 import (
    COMPONENT_ENUMS,
    validate_initial_settings,
    validate_pseudo_headers,
)
from .proxy_connect import rust_proxy_connect_value, validate_proxy_connect_values
from .quic import (
    rust_quic_value,
    validate_quic_values,
)
from .rust_literals import (
    rust_byte_slice,
    rust_duration,
    rust_header_order,
    rust_nonzero_usize,
    rust_option,
)
from .tcp import (
    rust_tcp_value,
    validate_tcp_values,
)
from .tls import (
    TLS_TRUST_CANDIDATE_VALIDATOR,
    rust_tls_value,
    validate_tls_values,
)
from .websocket import rust_websocket_value, validate_websocket_values

COMPONENT_FIELDS = {
    "WebSocketSettings": (
        "connection",
        "http1_fields",
        "http2_fields",
        "permessage_deflate_offer",
        "empty_message_compression",
        "handshake_timeout",
    ),
    "ClientHintSettings": ("hints",),
    "CookiePlacement": ("before",),
    "ProxyConnectTemplate": (
        "http1_fields",
        "http2_fields",
        "http2_rejected",
        "http2_connections",
    ),
    "TcpSettings": (
        "nodelay",
        "send_buffer_size",
        "keepalive",
        "address_selection",
        "port_randomization",
    ),
    "Http1Settings": ("max_connections_per_origin", "idle_timeout"),
    "DnsCacheSettings": (
        "address_failure_policy",
        "system_ttl",
        "max_entries",
        "ttl",
        "min_record_ttl",
        "negative_ttl",
    ),
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
        "initial_stream_window_target",
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
        "alt_used_port",
    ),
}


def validate_component_values(kind, values):
    keys(values, COMPONENT_FIELDS[kind], kind)
    if kind == "WebSocketSettings":
        validate_websocket_values(values)
        return
    if kind == "ClientHintSettings":
        validate_client_hints_values(values)
        return
    if kind == "CookiePlacement":
        validate_cookie_values(values)
        return
    if kind == "ProxyConnectTemplate":
        validate_proxy_connect_values(values)
        return
    if kind == "TcpSettings":
        validate_tcp_values(values)
        return
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

    components = [resolve(identifier) for identifier in sorted(by_id)]
    validate_hint_function_names(components)
    return components


def rust_component_value(field, value, kind="Http3Settings"):
    if kind == "WebSocketSettings":
        return rust_websocket_value(field, value)
    if kind == "ProxyConnectTemplate":
        return rust_proxy_connect_value(field, value)
    if kind == "TcpSettings":
        return rust_tcp_value(field, value)
    if kind == "Http1Settings":
        if field == "max_connections_per_origin":
            return rust_nonzero_usize(value)
        expression = f"crate::Http1IdleTimeout::{value['kind']}"
        if value["kind"] != "Unlimited":
            expression += f"({rust_duration(value['duration'])})"
        return expression
    if kind == "DnsCacheSettings":
        if field == "address_failure_policy":
            if value["kind"] == "Ignore":
                return "crate::DnsAddressFailurePolicy::Ignore"
            return (
                "crate::DnsAddressFailurePolicy::Record { max_unusable_addresses: "
                + rust_nonzero_usize(value["max_unusable_addresses"])
                + " }"
            )
        if field == "system_ttl":
            return f"crate::SystemDnsTtlPolicy::{value}"
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
        if kind == "ClientHintSettings":
            lines.extend(generate_client_hints_component(component))
            continue
        if kind == "CookiePlacement":
            lines.extend(
                [
                    "#[rustfmt::skip]",
                    f"pub(crate) fn {component['id']}() -> crate::{kind} {{",
                    f"    {rust_cookie_values(component['values'])}",
                    "}",
                    "",
                ]
            )
            continue
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
