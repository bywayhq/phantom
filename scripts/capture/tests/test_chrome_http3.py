import argparse
import asyncio
import hashlib
import re
import unittest
from pathlib import Path

import pylsqpack
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import StreamDataReceived

from scripts.capture.chrome_http3 import Capture, CaptureProtocol
from scripts.capture.http3_wire import (
    CONTROL_STREAM,
    HEADERS_FRAME,
    QPACK_ENCODER_STREAM,
    SENSITIVE_REQUEST_HEADERS,
    first_frame,
    is_h3_grease,
    is_quic_grease,
    normalize_settings,
    normalize_transport_parameters,
    parse_parameters,
    parse_settings,
    pull_varint,
    push_varint,
)
from scripts.capture.quic_packet_diff import SymbolicSpan

FIXTURE_PATH = Path("fixtures/http3/chrome/152.0.7977.83/macos-15.5/client-startup.txt")
FIXTURE_SHA256 = "c52cd57896f824fdefdcfdda77d40fe3bd928f2a97ef5093ebd888aa8fb18aaf"
PARAMETER_PATTERN = re.compile(
    r"id:(\d+),id_width:(\d+),length_width:(\d+),value_hex:([0-9a-f]*)"
)
SETTING_PATTERN = re.compile(r"id:(\d+),id_width:(\d+),value:(\d+),value_width:(\d+)")


def load_fixture() -> tuple[bytes, list[tuple[str, str]], dict[str, str]]:
    source = FIXTURE_PATH.read_bytes()
    fields = []
    for line in source.decode("ascii").splitlines():
        key, separator, value = line.partition("=")
        if not separator or not key:
            raise ValueError(f"invalid fixture line: {line!r}")
        fields.append((key, value))
    mapping = dict(fields)
    if len(mapping) != len(fields):
        raise ValueError("duplicate fixture key")
    return source, fields, mapping


def fixture_hex(mapping: dict[str, str], key: str) -> bytes:
    value = mapping[key]
    if value != value.lower() or len(value) % 2:
        raise ValueError(f"{key} is not lowercase even-length hex")
    return bytes.fromhex(value)


class VarintTests(unittest.TestCase):
    def test_round_trips_each_width(self) -> None:
        samples = {
            1: (0, 27, 63),
            2: (64, 89, 16383),
            4: (16384, 16400, (1 << 30) - 1),
            8: (1 << 30, (1 << 62) - 1),
        }
        for width, values in samples.items():
            for value in values:
                with self.subTest(width=width, value=value):
                    encoded = push_varint(value, width)
                    self.assertEqual(pull_varint(encoded, 0), (value, width))

    def test_rejects_value_that_does_not_fit_requested_width(self) -> None:
        with self.assertRaises(ValueError):
            push_varint(64, 1)


class CaptureBoundaryTests(unittest.TestCase):
    def test_unclaimed_protocol_can_be_closed_without_a_network_path(self) -> None:
        async def exercise() -> None:
            capture = Capture(complete=asyncio.Event(), metadata=argparse.Namespace())
            capture.connection_claimed = True
            connection = QuicConnection(configuration=QuicConfiguration(is_client=True))
            protocol = CaptureProtocol(connection, capture=capture)

            self.assertFalse(protocol.active)
            protocol.close()

        asyncio.run(exercise())

    def test_first_request_snapshots_do_not_include_later_stream_bytes(self) -> None:
        capture = Capture(complete=asyncio.Event(), metadata=argparse.Namespace())
        capture.streams = {
            0: bytearray(b"\x01\x00"),
            2: bytearray(b"\x02encoder-at-request"),
            6: bytearray(b"\x03decoder-at-request"),
        }

        capture.snapshot_request(0, [(b":method", b"GET")])
        capture.stream_data(
            StreamDataReceived(
                data=b"later-encoder-bytes", end_stream=False, stream_id=2
            )
        )
        capture.stream_data(
            StreamDataReceived(
                data=b"later-decoder-bytes", end_stream=False, stream_id=6
            )
        )

        self.assertEqual(capture.request_headers_frame, b"\x01\x00")
        self.assertEqual(capture.request_stream_id, 0)
        self.assertEqual(
            capture.request_qpack_encoder_stream_prefix,
            b"\x02encoder-at-request",
        )
        self.assertEqual(
            capture.request_qpack_decoder_stream_prefix,
            b"\x03decoder-at-request",
        )

    def test_request_snapshot_preserves_not_yet_observed_critical_stream(self) -> None:
        capture = Capture(complete=asyncio.Event(), metadata=argparse.Namespace())
        capture.streams = {
            0: bytearray(b"\x01\x00"),
            2: bytearray(b"\x02encoder-at-request"),
        }

        capture.snapshot_request(0, [(b":method", b"GET")])

        self.assertEqual(
            capture.request_qpack_encoder_stream_prefix,
            b"\x02encoder-at-request",
        )
        self.assertEqual(capture.request_qpack_decoder_stream_prefix, b"")

    def test_packet_spans_use_frozen_request_boundary(self) -> None:
        capture = Capture(complete=asyncio.Event(), metadata=argparse.Namespace())
        capture.streams = {
            0: bytearray(b"\x01\x02hh"),
            2: bytearray(bytes([QPACK_ENCODER_STREAM]) + b"encoder-at-request"),
            6: bytearray(bytes([CONTROL_STREAM]) + b"\x04\x02ss"),
        }
        capture.settings_frame = b"\x04\x02ss"
        capture.request_stream_id = 0
        capture.request_headers_frame = b"\x01\x02hh"
        capture.request_qpack_encoder_stream_prefix = b"\x02encoder-at-request"
        capture.request_qpack_decoder_stream_prefix = b""

        capture.streams[2].extend(b"later-encoder-bytes")

        self.assertEqual(
            capture.packet_spans(),
            (
                SymbolicSpan("control_settings", 6, 1, 5),
                SymbolicSpan("request_headers", 0, 0, 4),
                SymbolicSpan("qpack_encoder_prefix", 2, 0, 19),
            ),
        )

    def test_packet_spans_reject_duplicate_critical_streams(self) -> None:
        capture = Capture(complete=asyncio.Event(), metadata=argparse.Namespace())
        capture.streams = {
            0: bytearray(b"\x01\x00"),
            2: bytearray(bytes([CONTROL_STREAM]) + b"\x04\x00"),
            6: bytearray(bytes([CONTROL_STREAM]) + b"\x04\x00"),
        }
        capture.settings_frame = b"\x04\x00"
        capture.request_stream_id = 0
        capture.request_headers_frame = b"\x01\x00"
        capture.request_qpack_encoder_stream_prefix = b""
        capture.request_qpack_decoder_stream_prefix = b""

        with self.assertRaisesRegex(ValueError, "expected one client stream"):
            capture.packet_spans()


class ChromeFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source, cls.fields, cls.fixture = load_fixture()

    def test_fixture_integrity_and_ordered_schema(self) -> None:
        self.assertEqual(hashlib.sha256(self.source).hexdigest(), FIXTURE_SHA256)
        self.assertEqual(self.fixture["format"], "phantom-http3-client-startup-v2")
        self.assertEqual(self.fixture["client_version"], "152.0.7977.83")
        self.assertEqual(self.fixture["operating_system"], "macOS 15.5 (24F74)")
        self.assertEqual(self.fixture["listen_address"], "127.0.0.1:9447")
        self.assertEqual(self.fixture["quic_version"], "0x00000001")
        self.assertEqual(self.fixture["alpn"], "h3")

        parameter_count = int(self.fixture["transport_parameter_count"])
        setting_count = int(self.fixture["setting_count"])
        header_count = int(self.fixture["request_header_count"])
        expected_keys = [
            "format",
            "captured_at_unix",
            "client",
            "client_version",
            "operating_system",
            "hostname",
            "listen_address",
            "launch_mode",
            "launch_arguments",
            "capture_tool",
            "quic_version",
            "alpn",
            "transport_parameters_hex",
            "transport_parameters_normalized_hex",
            "transport_parameter_count",
            *(f"transport_parameter_{index}" for index in range(parameter_count)),
            "settings_frame_hex",
            "control_stream_prefix_hex",
            "settings_frame_normalized_hex",
            "settings_payload_normalized_hex",
            "setting_count",
            *(f"setting_{index}" for index in range(setting_count)),
            "server_qpack_max_table_capacity",
            "server_qpack_blocked_streams",
            "request_stream_id",
            "request_headers_frame_hex",
            "request_headers_payload_hex",
            "request_qpack_encoder_stream_prefix_hex",
            "request_qpack_decoder_stream_prefix_hex",
            "request_header_count",
            *(f"request_header_{index}" for index in range(header_count)),
        ]
        self.assertEqual([key for key, _ in self.fields], expected_keys)

    def test_transport_parameters_redecode_and_normalize(self) -> None:
        raw = fixture_hex(self.fixture, "transport_parameters_hex")
        parameters = parse_parameters(raw)
        self.assertEqual(len(parameters), 13)
        self.assertEqual(
            normalize_transport_parameters(raw, parameters),
            fixture_hex(self.fixture, "transport_parameters_normalized_hex"),
        )

        for index, parameter in enumerate(parameters):
            match = PARAMETER_PATTERN.fullmatch(
                self.fixture[f"transport_parameter_{index}"]
            )
            self.assertIsNotNone(match)
            assert match is not None
            self.assertEqual(
                (
                    parameter.identifier,
                    parameter.identifier_width,
                    parameter.length_width,
                    parameter.value.hex(),
                ),
                (int(match[1]), int(match[2]), int(match[3]), match[4]),
            )

        stable_ids = {
            parameter.identifier
            for parameter in parameters
            if not is_quic_grease(parameter.identifier)
        }
        self.assertEqual(stable_ids, {1, 3, 4, 5, 6, 7, 8, 9, 15, 17, 32, 12584})
        self.assertEqual(
            sum(is_quic_grease(parameter.identifier) for parameter in parameters), 1
        )

    def test_settings_redecode_and_normalize(self) -> None:
        raw_frame = fixture_hex(self.fixture, "settings_frame_hex")
        frame = first_frame(b"\x00" + raw_frame, has_stream_type=True)
        self.assertIsNotNone(frame)
        assert frame is not None
        frame_type, frame_bytes, payload = frame
        self.assertEqual(frame_type, 4)
        self.assertEqual(frame_bytes, raw_frame)
        self.assertEqual(
            fixture_hex(self.fixture, "control_stream_prefix_hex"), b"\x00" + raw_frame
        )
        self.assertEqual(
            normalize_settings(payload),
            fixture_hex(self.fixture, "settings_payload_normalized_hex"),
        )
        prefix_length = len(raw_frame) - len(payload)
        self.assertEqual(
            raw_frame[:prefix_length] + normalize_settings(payload),
            fixture_hex(self.fixture, "settings_frame_normalized_hex"),
        )

        settings = parse_settings(payload)
        self.assertEqual(
            [(identifier, value) for identifier, _, value, _ in settings[:4]],
            [(1, 65536), (6, 262144), (7, 100), (51, 1)],
        )
        self.assertEqual(len(settings), 5)
        self.assertTrue(is_h3_grease(settings[-1][0]))
        for index, setting in enumerate(settings):
            match = SETTING_PATTERN.fullmatch(self.fixture[f"setting_{index}"])
            self.assertIsNotNone(match)
            assert match is not None
            self.assertEqual(
                setting,
                (int(match[1]), int(match[2]), int(match[3]), int(match[4])),
            )

    def test_request_header_order_and_qpack_evidence(self) -> None:
        table_capacity = int(self.fixture["server_qpack_max_table_capacity"])
        blocked_streams = int(self.fixture["server_qpack_blocked_streams"])
        stream_id = int(self.fixture["request_stream_id"])
        self.assertEqual(table_capacity, 4096)
        self.assertEqual(blocked_streams, 16)
        self.assertEqual(stream_id, 0)

        raw_frame = fixture_hex(self.fixture, "request_headers_frame_hex")
        frame = first_frame(raw_frame, has_stream_type=False)
        self.assertIsNotNone(frame)
        assert frame is not None
        frame_type, frame_bytes, payload = frame
        self.assertEqual(frame_type, HEADERS_FRAME)
        self.assertEqual(frame_bytes, raw_frame)
        self.assertEqual(
            payload, fixture_hex(self.fixture, "request_headers_payload_hex")
        )
        encoder_prefix = fixture_hex(
            self.fixture, "request_qpack_encoder_stream_prefix_hex"
        )
        encoder_type = pull_varint(encoder_prefix, 0)
        self.assertIsNotNone(encoder_type)
        assert encoder_type is not None
        self.assertEqual(encoder_type[0], 2)
        self.assertEqual(len(encoder_prefix), 437)
        self.assertEqual(
            fixture_hex(self.fixture, "request_qpack_decoder_stream_prefix_hex"),
            b"",
        )

        headers = []
        for index in range(int(self.fixture["request_header_count"])):
            name_hex, separator, value_hex = self.fixture[
                f"request_header_{index}"
            ].partition(":")
            self.assertEqual(separator, ":")
            headers.append((bytes.fromhex(name_hex), bytes.fromhex(value_hex)))
        self.assertEqual(
            [name for name, _ in headers],
            [
                b":method",
                b":authority",
                b":scheme",
                b":path",
                b"sec-ch-ua",
                b"sec-ch-ua-mobile",
                b"sec-ch-ua-platform",
                b"upgrade-insecure-requests",
                b"user-agent",
                b"accept",
                b"sec-fetch-site",
                b"sec-fetch-mode",
                b"sec-fetch-user",
                b"sec-fetch-dest",
                b"accept-encoding",
                b"accept-language",
                b"priority",
            ],
        )
        self.assertFalse(
            any(name.lower() in SENSITIVE_REQUEST_HEADERS for name, _ in headers)
        )

        decoder = pylsqpack.Decoder(table_capacity, blocked_streams)
        decoder.feed_encoder(encoder_prefix[encoder_type[1] :])
        _, decoded_headers = decoder.feed_header(stream_id, payload)
        self.assertEqual(decoded_headers, headers)


if __name__ == "__main__":
    unittest.main()
