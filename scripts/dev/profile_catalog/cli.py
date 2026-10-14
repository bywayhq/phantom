"""Validate catalog records and typed components, then generate Rust offline."""

import argparse
import sys

from .components import generate_components, validate_components
from .declarations import REPO, DeclarationError, read_document
from .registry import generate, validate
from .request_template import (
    generate_templates,
    validate_template_bindings,
    validate_templates,
)

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


TCP_COMPONENT_RECORDS = REPO / "crates/phantom-profile/catalog/tcp-components.json"


TCP_COMPONENT_OUTPUT = REPO / "crates/phantom-profile/src/catalog/tcp_components.rs"


COOKIE_COMPONENT_RECORDS = (
    REPO / "crates/phantom-profile/catalog/cookie-components.json"
)
COOKIE_COMPONENT_OUTPUT = (
    REPO / "crates/phantom-profile/src/catalog/cookie_components.rs"
)
PROXY_CONNECT_COMPONENT_RECORDS = (
    REPO / "crates/phantom-profile/catalog/proxy-connect-components.json"
)
PROXY_CONNECT_COMPONENT_OUTPUT = (
    REPO / "crates/phantom-profile/src/catalog/proxy_connect_components.rs"
)


CLIENT_HINTS_COMPONENT_RECORDS = (
    REPO / "crates/phantom-profile/catalog/client-hints-components.json"
)
CLIENT_HINTS_COMPONENT_OUTPUT = (
    REPO / "crates/phantom-profile/src/catalog/client_hints_components.rs"
)


WEBSOCKET_COMPONENT_RECORDS = (
    REPO / "crates/phantom-profile/catalog/websocket-components.json"
)
WEBSOCKET_COMPONENT_OUTPUT = (
    REPO / "crates/phantom-profile/src/catalog/websocket_components.rs"
)

REQUEST_TEMPLATE_RECORDS = (
    REPO / "crates/phantom-profile/catalog/request-templates.json"
)
REQUEST_TEMPLATE_OUTPUT = (
    REPO / "crates/phantom-profile/src/catalog/request_template_definitions.rs"
)


def load(path=RECORDS, repo=REPO):
    return validate(read_document(path), repo)


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


def load_tcp_components(path=TCP_COMPONENT_RECORDS):
    return validate_components(read_document(path), ("TcpSettings",))


def load_cookie_components(path=COOKIE_COMPONENT_RECORDS):
    return validate_components(read_document(path), ("CookiePlacement",))


def load_proxy_connect_components(path=PROXY_CONNECT_COMPONENT_RECORDS):
    return validate_components(read_document(path), ("ProxyConnectTemplate",))


def load_client_hints_components(path=CLIENT_HINTS_COMPONENT_RECORDS):
    return validate_components(read_document(path), ("ClientHintSettings",))


def load_websocket_components(path=WEBSOCKET_COMPONENT_RECORDS):
    return validate_components(read_document(path), ("WebSocketSettings",))


def load_request_templates(path=REQUEST_TEMPLATE_RECORDS):
    return validate_templates(read_document(path))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true", help="reject stale committed generated files"
    )
    arguments = parser.parse_args()
    try:
        profiles = load()
        templates = load_request_templates()
        validate_template_bindings(profiles, templates)
        outputs = (
            (OUTPUT, generate(profiles)),
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
            (
                TCP_COMPONENT_OUTPUT,
                generate_components(load_tcp_components(), "tcp-components.json"),
            ),
            (
                COOKIE_COMPONENT_OUTPUT,
                generate_components(load_cookie_components(), "cookie-components.json"),
            ),
            (
                PROXY_CONNECT_COMPONENT_OUTPUT,
                generate_components(
                    load_proxy_connect_components(), "proxy-connect-components.json"
                ),
            ),
            (
                CLIENT_HINTS_COMPONENT_OUTPUT,
                generate_components(
                    load_client_hints_components(), "client-hints-components.json"
                ),
            ),
            (
                WEBSOCKET_COMPONENT_OUTPUT,
                generate_components(
                    load_websocket_components(), "websocket-components.json"
                ),
            ),
            (REQUEST_TEMPLATE_OUTPUT, generate_templates(templates)),
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
