"""Serve HTTP/3 from aioquic on loopback and report each connection's QUIC version.

aioquic 1.3.0 implements QUIC v1 and v2 and, as a server, moves a client to
the first compatible version the client lists as available (RFC 9368). The
server issues session tickets and accepts early data, so a client's later
connections can resume. For every connection it prints one line with the
version of the client's first packet, the negotiated version, the client's
Version Information, and whether the session resumed and early data was
accepted.

The server writes the DER root that signs its `localhost` certificate and its
port to the given paths, answers every request with `ok`, and exits after the
requested number of requests.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import tempfile
from pathlib import Path

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted, ProtocolNegotiated, QuicEvent

try:
    from .loopback_tls import generate_loopback_certificate
except ImportError:  # pragma: no cover - direct script execution
    from loopback_tls import generate_loopback_certificate

REQUEST_TIMEOUT_SECONDS = 60
# Windows hands out UDP ports for binds to port 0 from one counter for the
# whole host. When the counter reaches a reserved block (`netsh int ipv4 show
# excludedportrange protocol=udp`), the bind can fail with WSAENOBUFS (os error
# 10055) and the counter moves past the block, so the next bind gets a port.
# scripts/capture/reserved_ports.py has the same rule; this file runs as a
# script, outside the `scripts` package.
WSAENOBUFS = 10055
RESERVED_PORT_RETRIES = 3


async def serve_past_reserved_ports(serve_at):
    """Return `await serve_at()`, retrying a bind to port 0 that Windows refused."""
    retries = 0
    while True:
        try:
            return await serve_at()
        except OSError as error:
            refused = getattr(error, "winerror", None) == WSAENOBUFS
            if not refused or retries == RESERVED_PORT_RETRIES:
                raise
            retries += 1


def version_report(
    first_packet_version: int | None,
    negotiated_version: int,
    chosen_version: int | None,
    available_versions: list[int],
    resumed: bool,
    early_data_accepted: bool,
) -> str:
    """Formats one connection's line of the report."""

    def hexadecimal(version: int | None) -> str:
        return "none" if version is None else f"0x{version:08x}"

    available = ",".join(hexadecimal(version) for version in available_versions)
    return (
        f"first_packet_version={hexadecimal(first_packet_version)} "
        f"negotiated_version={hexadecimal(negotiated_version)} "
        f"chosen_version={hexadecimal(chosen_version)} "
        f"available_versions={available or 'none'} "
        f"resumed={str(resumed).lower()} "
        f"early_data_accepted={str(early_data_accepted).lower()}"
    )


class ReportingProtocol(QuicConnectionProtocol):
    """Answers HTTP/3 requests and reports the connection's versions."""

    requests: list[int]
    done: asyncio.Event
    expected: int

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._http: H3Connection | None = None
        self._first_packet_version: int | None = None

    def datagram_received(self, data: bytes, addr) -> None:
        if self._first_packet_version is None and data and data[0] & 0x80:
            self._first_packet_version = int.from_bytes(data[1:5], "big")
        super().datagram_received(data, addr)

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, ProtocolNegotiated):
            self._http = H3Connection(self._quic)
        if isinstance(event, HandshakeCompleted):
            # aioquic keeps the peer's Version Information only privately.
            information = self._quic._remote_version_information
            print(
                version_report(
                    self._first_packet_version,
                    self._quic._version,
                    None if information is None else information.chosen_version,
                    [] if information is None else information.available_versions,
                    event.session_resumed,
                    event.early_data_accepted,
                ),
                flush=True,
            )
        if self._http is None:
            return
        for http_event in self._http.handle_event(event):
            if isinstance(http_event, HeadersReceived):
                self._http.send_headers(
                    http_event.stream_id, [(b":status", b"200")], end_stream=False
                )
                self._http.send_data(http_event.stream_id, b"ok", end_stream=True)
                self.transmit()
                self.requests.append(http_event.stream_id)
                if len(self.requests) >= self.expected:
                    self.done.set()


async def run(args: argparse.Namespace) -> None:
    directory = Path(tempfile.mkdtemp(prefix="phantom-aioquic-versions-"))
    certificate = generate_loopback_certificate(directory)
    args.root.write_bytes(certificate.root_der.read_bytes())
    configuration = QuicConfiguration(
        is_client=False,
        alpn_protocols=H3_ALPN,
        max_datagram_frame_size=65_536,
    )
    configuration.load_cert_chain(
        certificate.certificate_pem, certificate.private_key_pem
    )
    tickets: dict[bytes, object] = {}
    ReportingProtocol.requests = []
    ReportingProtocol.done = asyncio.Event()
    ReportingProtocol.expected = args.requests
    server = await serve_past_reserved_ports(
        lambda: serve(
            args.listen,
            0,
            configuration=configuration,
            create_protocol=ReportingProtocol,
            session_ticket_fetcher=tickets.pop,
            session_ticket_handler=lambda ticket: tickets.__setitem__(
                ticket.ticket, ticket
            ),
        )
    )
    port = server._transport.get_extra_info("sockname")[1]
    args.port_file.write_text(str(port), encoding="utf-8")
    try:
        await asyncio.wait_for(ReportingProtocol.done.wait(), REQUEST_TIMEOUT_SECONDS)
        # Let the last response reach the client before closing.
        await asyncio.sleep(0.5)
    finally:
        server.close()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--port-file", type=Path, required=True)
    parser.add_argument("--requests", type=int, default=3)
    parser.add_argument("--listen", default="127.0.0.1")
    args = parser.parse_args(argv)
    if args.requests <= 0:
        parser.error("requests must be positive")
    if not ipaddress.ip_address(args.listen).is_loopback:
        parser.error("the server must listen on a loopback address")
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
