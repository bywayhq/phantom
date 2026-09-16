"""Capture one browser HTTP/3 startup against a loopback aioquic server."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import platform
import time
from dataclasses import dataclass, field
from pathlib import Path

import aioquic
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3_ALPN, H3Connection, Setting
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ProtocolNegotiated, QuicEvent, StreamDataReceived

from .http3_wire import (
    CONTROL_STREAM,
    SENSITIVE_REQUEST_HEADERS,
    SETTINGS_FRAME,
    capture_request_snapshot,
    first_frame,
    normalize_settings,
    normalize_transport_parameters,
    parse_parameters,
    parse_settings,
    pull_varint,
    unidirectional_stream,
)

SUPPORTED_AIOQUIC = "1.3.0"
MAX_STREAM_CAPTURE = 256 * 1024


@dataclass
class Capture:
    complete: asyncio.Event
    metadata: argparse.Namespace
    streams: dict[int, bytearray] = field(default_factory=dict)
    transport_parameters: bytes | None = None
    settings_frame: bytes | None = None
    settings_payload: bytes | None = None
    request_stream_id: int | None = None
    request_headers_frame: bytes | None = None
    request_headers_payload: bytes | None = None
    request_qpack_encoder_stream_prefix: bytes | None = None
    request_qpack_decoder_stream_prefix: bytes | None = None
    headers: list[tuple[bytes, bytes]] | None = None
    server_qpack_max_table_capacity: int | None = None
    server_qpack_blocked_streams: int | None = None
    alpn: str | None = None
    quic_version: int | None = None
    connection_claimed: bool = False

    def stream_data(self, event: StreamDataReceived) -> None:
        data = self.streams.setdefault(event.stream_id, bytearray())
        if len(data) + len(event.data) > MAX_STREAM_CAPTURE:
            raise ValueError(f"stream {event.stream_id} exceeds the capture limit")
        data.extend(event.data)
        raw = bytes(data)
        if event.stream_id % 4 == 2 and self.settings_frame is None:
            frame = first_frame(raw, has_stream_type=True)
            if frame is not None:
                frame_type, frame_bytes, payload = frame
                if frame_type == SETTINGS_FRAME:
                    self.settings_frame = frame_bytes
                    self.settings_payload = payload
        self.maybe_complete()

    def snapshot_request(
        self, stream_id: int, headers: list[tuple[bytes, bytes]]
    ) -> None:
        snapshot = capture_request_snapshot(self.streams, stream_id)
        self.request_stream_id = snapshot.stream_id
        self.request_headers_frame = snapshot.headers_frame
        self.request_headers_payload = snapshot.headers_payload
        self.request_qpack_encoder_stream_prefix = snapshot.qpack_encoder_stream_prefix
        self.request_qpack_decoder_stream_prefix = snapshot.qpack_decoder_stream_prefix
        self.headers = list(headers)
        self.maybe_complete()

    def maybe_complete(self) -> None:
        if (
            self.transport_parameters is not None
            and self.settings_frame is not None
            and self.request_stream_id is not None
            and self.request_headers_frame is not None
            and self.request_qpack_encoder_stream_prefix is not None
            and self.request_qpack_decoder_stream_prefix is not None
            and self.headers is not None
            and self.server_qpack_max_table_capacity is not None
            and self.server_qpack_blocked_streams is not None
        ):
            self.complete.set()

    def fixture(self) -> str:
        if (
            self.transport_parameters is None
            or self.settings_payload is None
            or self.settings_frame is None
            or self.request_stream_id is None
            or self.request_headers_frame is None
            or self.request_headers_payload is None
            or self.request_qpack_encoder_stream_prefix is None
            or self.request_qpack_decoder_stream_prefix is None
            or self.headers is None
            or self.server_qpack_max_table_capacity is None
            or self.server_qpack_blocked_streams is None
            or self.alpn is None
            or self.quic_version is None
        ):
            raise RuntimeError("capture completed without all required evidence")
        if any(name.lower() in SENSITIVE_REQUEST_HEADERS for name, _ in self.headers):
            raise ValueError(
                "refusing to retain a fixture with credential-bearing headers"
            )
        parameters = parse_parameters(self.transport_parameters)
        settings = parse_settings(self.settings_payload)
        settings_prefix_length = len(self.settings_frame) - len(self.settings_payload)
        control_stream = unidirectional_stream(self.streams, CONTROL_STREAM)
        control_stream_type = pull_varint(control_stream, 0)
        if control_stream_type is None:
            raise RuntimeError("captured control stream has no stream type")
        control_prefix_length = control_stream_type[1] + len(self.settings_frame)
        lines = [
            "format=phantom-http3-client-startup-v2",
            f"captured_at_unix={int(time.time())}",
            f"client={self.metadata.client}",
            f"client_version={self.metadata.client_version}",
            f"operating_system={self.metadata.operating_system}",
            f"hostname={self.metadata.hostname}",
            f"listen_address={self.metadata.listen}",
            f"launch_mode={self.metadata.launch_mode}",
            f"launch_arguments={self.metadata.launch_arguments}",
            f"capture_tool=aioquic {aioquic.__version__}",
            f"quic_version=0x{self.quic_version:08x}",
            f"alpn={self.alpn}",
            f"transport_parameters_hex={self.transport_parameters.hex()}",
            "transport_parameters_normalized_hex="
            + normalize_transport_parameters(
                self.transport_parameters, parameters
            ).hex(),
            f"transport_parameter_count={len(parameters)}",
        ]
        lines.extend(
            f"transport_parameter_{index}=id:{parameter.identifier},id_width:{parameter.identifier_width},length_width:{parameter.length_width},value_hex:{parameter.value.hex()}"
            for index, parameter in enumerate(parameters)
        )
        lines.extend(
            [
                f"settings_frame_hex={self.settings_frame.hex()}",
                "control_stream_prefix_hex="
                + control_stream[:control_prefix_length].hex(),
                "settings_frame_normalized_hex="
                + self.settings_frame[:settings_prefix_length].hex()
                + normalize_settings(self.settings_payload).hex(),
                f"settings_payload_normalized_hex={normalize_settings(self.settings_payload).hex()}",
                f"setting_count={len(settings)}",
            ]
        )
        lines.extend(
            f"setting_{index}=id:{identifier},id_width:{identifier_width},value:{value},value_width:{value_width}"
            for index, (identifier, identifier_width, value, value_width) in enumerate(
                settings
            )
        )
        lines.extend(
            [
                f"server_qpack_max_table_capacity={self.server_qpack_max_table_capacity}",
                f"server_qpack_blocked_streams={self.server_qpack_blocked_streams}",
                f"request_stream_id={self.request_stream_id}",
                f"request_headers_frame_hex={self.request_headers_frame.hex()}",
                f"request_headers_payload_hex={self.request_headers_payload.hex()}",
                "request_qpack_encoder_stream_prefix_hex="
                + self.request_qpack_encoder_stream_prefix.hex(),
                "request_qpack_decoder_stream_prefix_hex="
                + self.request_qpack_decoder_stream_prefix.hex(),
                f"request_header_count={len(self.headers)}",
            ]
        )
        lines.extend(
            f"request_header_{index}={name.hex()}:{value.hex()}"
            for index, (name, value) in enumerate(self.headers)
        )
        return "\n".join(lines) + "\n"


class CaptureProtocol(QuicConnectionProtocol):
    capture: Capture

    def __init__(self, *args, capture: Capture, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.capture = capture
        self.active = not capture.connection_claimed
        capture.connection_claimed = True
        self.http: H3Connection | None = None

    def quic_event_received(self, event: QuicEvent) -> None:
        if not self.active:
            return
        if isinstance(event, ProtocolNegotiated):
            self.capture.alpn = event.alpn_protocol
            self.capture.quic_version = self._quic._version
            self.capture.transport_parameters = getattr(
                self._quic, "_phantom_transport_parameters", None
            )
            self.http = H3Connection(self._quic)
            sent_settings = self.http.sent_settings
            if sent_settings is None:
                raise RuntimeError("HTTP/3 server did not materialize local settings")
            self.capture.server_qpack_max_table_capacity = sent_settings.get(
                Setting.QPACK_MAX_TABLE_CAPACITY, 0
            )
            self.capture.server_qpack_blocked_streams = sent_settings.get(
                Setting.QPACK_BLOCKED_STREAMS, 0
            )
        if isinstance(event, StreamDataReceived):
            self.capture.stream_data(event)
        if self.http is None:
            return
        for http_event in self.http.handle_event(event):
            if isinstance(http_event, HeadersReceived) and self.capture.headers is None:
                self.capture.snapshot_request(http_event.stream_id, http_event.headers)
                self.http.send_headers(
                    http_event.stream_id,
                    [(b":status", b"200"), (b"content-length", b"2")],
                )
                self.http.send_data(http_event.stream_id, b"ok", end_stream=True)
                self.transmit()


def patch_transport_parameter_capture() -> None:
    original = QuicConnection._parse_transport_parameters

    def capture(
        self: QuicConnection, data: bytes, from_session_ticket: bool = False
    ) -> None:
        if not self._is_client and not from_session_ticket:
            self._phantom_transport_parameters = bytes(data)
        original(self, data, from_session_ticket)

    QuicConnection._parse_transport_parameters = capture


async def run(args: argparse.Namespace) -> str:
    complete = asyncio.Event()
    capture = Capture(complete=complete, metadata=args)
    configuration = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
    configuration.load_cert_chain(args.certificate, args.private_key)
    server = await serve(
        str(ipaddress.ip_address(args.listen.rsplit(":", 1)[0])),
        int(args.listen.rsplit(":", 1)[1]),
        configuration=configuration,
        create_protocol=lambda *values, **kwargs: CaptureProtocol(
            *values, capture=capture, **kwargs
        ),
    )
    try:
        await asyncio.wait_for(complete.wait(), timeout=args.timeout)
        await asyncio.sleep(0.2)
        return capture.fixture()
    finally:
        server.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--listen", default="127.0.0.1:9447")
    parser.add_argument("--hostname", default="server.phantom.test")
    parser.add_argument("--client", default="Google Chrome")
    parser.add_argument("--client-version", required=True)
    parser.add_argument("--operating-system", default=platform.platform())
    parser.add_argument("--launch-mode", default="command-line")
    parser.add_argument("--launch-arguments", required=True)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()
    if aioquic.__version__ != SUPPORTED_AIOQUIC:
        parser.error(
            f"aioquic {SUPPORTED_AIOQUIC} is required, found {aioquic.__version__}"
        )
    if not ipaddress.ip_address(args.listen.rsplit(":", 1)[0]).is_loopback:
        parser.error("the capture listener must be a loopback address")
    patch_transport_parameter_capture()
    print(asyncio.run(run(args)), end="")


if __name__ == "__main__":
    main()
