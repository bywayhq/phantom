"""Capture one browser HTTP/3 startup against a loopback aioquic server."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
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
from aioquic.quic.events import (
    HandshakeCompleted,
    ProtocolNegotiated,
    QuicEvent,
    StreamDataReceived,
)
from aioquic.tls import CipherSuite

from .fixture_file import write_atomically, write_text_fixture
from .http3_wire import (
    CONTROL_STREAM,
    QPACK_DECODER_STREAM,
    QPACK_ENCODER_STREAM,
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
    unidirectional_stream_id,
)
from .quic_flight import PacketSummary
from .quic_packet_diff import QuicPacketAnalysis, QuicPacketCapture
from .quic_summary import SymbolicSpan

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
    cipher_suite: CipherSuite | None = None
    short_header_cid_length: int | None = None
    packet_capture: QuicPacketCapture | None = None
    client_hello: bytes | None = None
    failure: Exception | None = None
    connection_claimed: bool = False

    def fail(self, error: Exception) -> None:
        if self.failure is None:
            self.failure = error
        self.complete.set()

    def raise_if_failed(self) -> None:
        if self.failure is not None:
            raise RuntimeError("HTTP/3 capture failed") from self.failure

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
        if self.packet_capture is not None:
            self.packet_capture.finish_datagrams()
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

    def client_hello_fixture(self) -> str:
        if self.client_hello is None or self.alpn is None or self.quic_version is None:
            raise RuntimeError("capture completed without a QUIC ClientHello")
        lines = [
            "format=phantom-quic-client-hello-v1",
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
            f"handshake_hex={self.client_hello.hex()}",
        ]
        return "\n".join(lines) + "\n"

    def packet_spans(self) -> tuple[SymbolicSpan, ...]:
        if (
            self.settings_frame is None
            or self.request_stream_id is None
            or self.request_headers_frame is None
            or self.request_qpack_encoder_stream_prefix is None
            or self.request_qpack_decoder_stream_prefix is None
        ):
            raise RuntimeError("capture has no complete request boundary")

        control_stream_id = unidirectional_stream_id(self.streams, CONTROL_STREAM)
        control_stream = bytes(self.streams[control_stream_id])
        control_type = pull_varint(control_stream, 0)
        if control_type is None:
            raise RuntimeError("captured control stream has no stream type")
        control_start = control_type[1]
        settings_frame = first_frame(self.settings_frame, has_stream_type=False)
        if settings_frame is None or settings_frame[0] != SETTINGS_FRAME:
            raise RuntimeError("captured SETTINGS frame is malformed")
        _, frame_bytes, settings_payload = settings_frame
        settings = parse_settings(settings_payload)
        if [setting[0] for setting in settings[:3]] != [1, 6, 7]:
            raise RuntimeError("captured SETTINGS omit the stable required prefix")
        frame_header_length = len(frame_bytes) - len(settings_payload)
        stable_settings_length = sum(
            identifier_width + value_width
            for _, identifier_width, _, value_width in settings[:3]
        )
        stable_settings_start = control_start + frame_header_length
        spans = [
            SymbolicSpan(
                "control_settings_prefix",
                control_stream_id,
                stable_settings_start,
                stable_settings_start + stable_settings_length,
            ),
            SymbolicSpan(
                "request_headers",
                self.request_stream_id,
                0,
                len(self.request_headers_frame),
            ),
        ]
        for label, stream_type, prefix in (
            (
                "qpack_encoder_prefix",
                QPACK_ENCODER_STREAM,
                self.request_qpack_encoder_stream_prefix,
            ),
            (
                "qpack_decoder_prefix",
                QPACK_DECODER_STREAM,
                self.request_qpack_decoder_stream_prefix,
            ),
        ):
            if prefix:
                spans.append(
                    SymbolicSpan(
                        label,
                        unidirectional_stream_id(self.streams, stream_type),
                        0,
                        len(prefix),
                    )
                )
        return tuple(spans)

    def packet_analysis(self) -> QuicPacketAnalysis:
        if self.packet_capture is None:
            raise RuntimeError("capture has no packet analyzer")
        if self.cipher_suite is None or self.short_header_cid_length is None:
            raise RuntimeError("capture completed without negotiated QUIC metadata")
        return self.packet_capture.summarize_with_client_hello(
            cipher_suite=self.cipher_suite,
            short_header_cid_length=self.short_header_cid_length,
            spans=self.packet_spans(),
        )


@dataclass(frozen=True)
class CaptureResult:
    fixture: str
    packet_summary: PacketSummary | None
    client_hello_fixture: str | None


class CaptureProtocol(QuicConnectionProtocol):
    capture: Capture

    def __init__(self, *args, capture: Capture, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.capture = capture
        self.active = not capture.connection_claimed
        capture.connection_claimed = True
        self.http: H3Connection | None = None

    def close(self, error_code: int = 0, reason_phrase: str = "") -> None:
        if not self.active:
            return
        super().close(error_code=error_code, reason_phrase=reason_phrase)

    def datagram_received(self, data: bytes, addr) -> None:
        if not self.active:
            return
        try:
            if self.capture.packet_capture is not None:
                self.capture.packet_capture.add_datagram(data)
            super().datagram_received(data, addr)
        except Exception as error:
            self.capture.fail(error)

    def quic_event_received(self, event: QuicEvent) -> None:
        if not self.active:
            return
        try:
            self._handle_quic_event(event)
        except Exception as error:
            self.capture.fail(error)

    def _handle_quic_event(self, event: QuicEvent) -> None:
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
        if isinstance(event, HandshakeCompleted):
            key_schedule = self._quic.tls.key_schedule
            if key_schedule is None:
                raise RuntimeError("QUIC handshake completed without a key schedule")
            self.capture.cipher_suite = key_schedule.cipher_suite
            self.capture.short_header_cid_length = (
                self._quic.configuration.connection_id_length
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


async def run(args: argparse.Namespace) -> CaptureResult:
    complete = asyncio.Event()
    packet_capture = (
        QuicPacketCapture()
        if args.packet_summary is not None or args.client_hello is not None
        else None
    )
    capture = Capture(
        complete=complete,
        metadata=args,
        packet_capture=packet_capture,
    )
    configuration = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
    configuration.load_cert_chain(args.certificate, args.private_key)
    if packet_capture is not None:
        configuration.secrets_log_file = packet_capture
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
        capture.raise_if_failed()
        await asyncio.sleep(0.2)
        capture.raise_if_failed()
        server.close()
        fixture = capture.fixture()
        if packet_capture is None:
            return CaptureResult(fixture, None, None)
        analysis = capture.packet_analysis()
        capture.client_hello = analysis.client_hello
        packet_summary = analysis.summary if args.packet_summary is not None else None
        return CaptureResult(fixture, packet_summary, capture.client_hello_fixture())
    finally:
        server.close()
        if packet_capture is not None:
            packet_capture.clear()


def write_packet_summary(path: Path, summary: PacketSummary) -> None:
    write_atomically(
        path,
        json.dumps(summary.as_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


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
    parser.add_argument("--packet-summary", type=Path)
    parser.add_argument("--client-hello", type=Path)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()
    if aioquic.__version__ != SUPPORTED_AIOQUIC:
        parser.error(
            f"aioquic {SUPPORTED_AIOQUIC} is required, found {aioquic.__version__}"
        )
    if not ipaddress.ip_address(args.listen.rsplit(":", 1)[0]).is_loopback:
        parser.error("the capture listener must be a loopback address")
    patch_transport_parameter_capture()
    result = asyncio.run(run(args))
    if args.packet_summary is not None:
        if result.packet_summary is None:
            raise RuntimeError("packet summary was requested but not produced")
        write_packet_summary(args.packet_summary, result.packet_summary)
    if args.client_hello is not None:
        if result.client_hello_fixture is None:
            raise RuntimeError("ClientHello fixture was requested but not produced")
        write_text_fixture(args.client_hello, result.client_hello_fixture)
    print(result.fixture, end="")


if __name__ == "__main__":
    main()
