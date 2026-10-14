"""Validate catalog records and typed components, then generate Rust offline."""

import argparse
import sys

from .components import generate_components, validate_components
from .declarations import REPO, DeclarationError, read_document
from .registry import generate, validate

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
            (
                TCP_COMPONENT_OUTPUT,
                generate_components(load_tcp_components(), "tcp-components.json"),
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
