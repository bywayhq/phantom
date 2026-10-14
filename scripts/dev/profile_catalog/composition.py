"""Closed component references and immutable connection-profile composition."""

from .declarations import RUST_KEYWORDS, DeclarationError, component_identifier, keys

LAYER_KINDS = {
    "TcpTls": "TlsSettings",
    "Tcp": "TcpSettings",
    "Udp": "UdpSettings",
    "Dns": "DnsCacheSettings",
    "Http1": "Http1Settings",
    "Http2": "Http2Settings",
    "QuicTls": "TlsSettings",
    "QuicTransport": "QuicTransportSettings",
    "Http3": "Http3Settings",
    "Http3Request": "Http3RequestSettings",
    "ClientHints": "ClientHintSettings",
    "WebSocket": "WebSocketSettings",
    "ProxyConnect": "ProxyConnectTemplate",
    "CookiePlacement": "CookiePlacement",
}
HTTP3_LAYERS = ("QuicTls", "QuicTransport", "Http3", "Http3Request")
DOMAINS = {
    "TlsSettings": ("TlsComponent", "crate::tls::components"),
    "TcpSettings": ("TcpComponent", "super::tcp_components"),
    "UdpSettings": ("UdpComponent", "super::udp_components"),
    "DnsCacheSettings": ("DnsComponent", "super::dns_components"),
    "Http1Settings": ("Http1Component", "super::http1_components"),
    "Http2Settings": ("Http2Component", "super::http2_components"),
    "QuicTransportSettings": ("QuicComponent", "super::quic_components"),
    "Http3Settings": ("Http3Component", "super::http3_components"),
    "Http3RequestSettings": ("Http3RequestComponent", "super::http3_components"),
    "ClientHintSettings": ("ClientHintsComponent", "super::client_hints_components"),
    "WebSocketSettings": ("WebSocketComponent", "super::websocket_components"),
    "ProxyConnectTemplate": (
        "ProxyConnectComponent",
        "super::proxy_connect_components",
    ),
    "CookiePlacement": ("CookieComponent", "super::cookie_components"),
}
FIELDS = {
    "TcpTls": "tls",
    "Tcp": "tcp",
    "Udp": "udp",
    "Dns": "dns_cache",
    "Http1": "http1",
    "Http2": "http2",
    "QuicTls": "tls",
    "QuicTransport": "quic_transport",
    "Http3": "http3",
    "Http3Request": "request",
    "ClientHints": "client_hints",
    "WebSocket": "websocket",
    "ProxyConnect": "proxy_connect",
    "CookiePlacement": "cookie_placement",
}
COMPONENT_SUFFIXES = {
    "TlsSettings": "_tls",
    "TcpSettings": "_tcp",
    "UdpSettings": "_udp",
    "DnsCacheSettings": "_dns_cache",
    "Http1Settings": "_http1",
    "Http2Settings": "_http2",
    "QuicTransportSettings": "_quic",
    "Http3Settings": "_http3",
    "Http3RequestSettings": "_http3_request",
    "ClientHintSettings": "_client_hints",
    "WebSocketSettings": "_websocket",
    "ProxyConnectTemplate": "_proxy_connect",
    "CookiePlacement": "_cookie",
}


def validate_composition(entry):
    """Check explicit absence and native grouping against the evidence states."""
    composition = entry["composition"]
    keys(composition, LAYER_KINDS, "profile composition")
    for identifier in composition.values():
        if identifier is not None:
            component_identifier(identifier)
    if composition["TcpTls"] is None:
        raise DeclarationError("profile composition requires TCP TLS")
    present = [composition[name] is not None for name in HTTP3_LAYERS]
    if any(present) and not all(present):
        raise DeclarationError("HTTP/3 composition requires all four layers")
    for layer in entry["layers"]:
        if (composition[layer["layer"]] is not None) != (
            layer["support"] == "Configured"
        ):
            raise DeclarationError("component presence disagrees with layer support")


def validate_composition_bindings(profiles, components):
    """Resolve references only to already validated typed component declarations."""
    kinds = {}
    for component in components:
        identifier = component["id"]
        if identifier in kinds:
            raise DeclarationError(f"ambiguous component identifier: {identifier}")
        kinds[identifier] = component["kind"]
    for entry in profiles:
        validate_composition(entry)
        for layer, identifier in entry["composition"].items():
            if identifier is None:
                continue
            if identifier not in kinds:
                raise DeclarationError(f"unknown composition component: {identifier}")
            if kinds[identifier] != LAYER_KINDS[layer]:
                raise DeclarationError(f"incompatible component kind for {layer}")
    component_variants(profiles)


def component_variants(profiles):
    """Give each selected component a stable private variant within its domain."""
    used = {kind: set() for kind in DOMAINS}
    for entry in profiles:
        for layer, identifier in entry["composition"].items():
            if identifier is not None:
                component_identifier(identifier)
                used[LAYER_KINDS[layer]].add(identifier)
    variants = {}
    for kind, identifiers in used.items():
        names = {}
        variants[kind] = {}
        for identifier in sorted(identifiers):
            stem = identifier.removesuffix(COMPONENT_SUFFIXES[kind])
            name = "".join(part[:1].upper() + part[1:] for part in stem.split("_"))
            if name == "Self" or name in RUST_KEYWORDS:
                raise DeclarationError(f"reserved component variant: {identifier}")
            if name in names:
                raise DeclarationError(
                    f"colliding component variants: {names[name]} and {identifier}"
                )
            names[name] = identifier
            variants[kind][identifier] = name
    return variants


def generate_compositions(profiles):
    """Emit typed references and owned component construction without draws."""
    variants = component_variants(profiles)
    lines = [
        "// Generated by scripts/dev/generate_profiles.py; edit catalog/profiles.json.",
        "use super::connection_profile_values::{ConnectionProfileDefinition, Http3Definition};",
        "",
    ]
    for kind, (name, module) in DOMAINS.items():
        lines.extend(
            [
                "#[derive(Clone, Copy, Debug)]",
                "#[rustfmt::skip]",
                f"pub(super) enum {name} {{",
            ]
        )
        lines.extend(f"    {variant}," for variant in variants[kind].values())
        lines.extend(
            [
                "}",
                "",
                "#[rustfmt::skip]",
                f"impl {name} {{",
                f"    pub(super) fn create(self) -> crate::{kind} {{",
                "        match self {",
            ]
        )
        lines.extend(
            f"            Self::{variant} => {module}::{identifier}(),"
            for identifier, variant in variants[kind].items()
        )
        lines.extend(["        }", "    }", "}", ""])

    def reference(entry, layer):
        identifier = entry["composition"][layer]
        if identifier is None:
            return "None"
        kind = LAYER_KINDS[layer]
        value = f"{DOMAINS[kind][0]}::{variants[kind][identifier]}"
        return value if layer == "TcpTls" else f"Some({value})"

    for entry in sorted(profiles, key=lambda item: item["id"]):
        lines.extend(
            [
                "#[rustfmt::skip]",
                f"pub(super) static {entry['target'].upper()}: ConnectionProfileDefinition = ConnectionProfileDefinition {{",
            ]
        )
        for layer in LAYER_KINDS:
            if layer in HTTP3_LAYERS:
                if layer == "QuicTls":
                    if entry["composition"][layer] is None:
                        lines.append("    http3: None,")
                    else:
                        lines.append("    http3: Some(Http3Definition {")
                        for h3layer in HTTP3_LAYERS:
                            kind = LAYER_KINDS[h3layer]
                            identifier = entry["composition"][h3layer]
                            value = f"{DOMAINS[kind][0]}::{variants[kind][identifier]}"
                            lines.append(f"        {FIELDS[h3layer]}: {value},")
                        lines.append("    }),")
                continue
            lines.append(f"    {FIELDS[layer]}: {reference(entry, layer)},")
        lines.extend(["};", ""])
    return "\n".join(lines)
