import hashlib
import re
import unittest
from pathlib import Path

from scripts.capture.http3_wire import (
    HEADERS_FRAME,
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

FIXTURE_PATH = Path("fixtures/http3/chrome/152.0.7977.83/macos-15.5/client-startup.txt")
FIXTURE_SHA256 = "0199af21d3c623600fb4bdc86c2fd3d019820baaa3fe9b38860adf9b020167de"
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


class ChromeFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source, cls.fields, cls.fixture = load_fixture()

    def test_fixture_integrity_and_ordered_schema(self) -> None:
        self.assertEqual(hashlib.sha256(self.source).hexdigest(), FIXTURE_SHA256)
        self.assertEqual(self.fixture["format"], "phantom-http3-client-startup-v1")
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
            "request_headers_frame_hex",
            "request_headers_payload_hex",
            "qpack_encoder_stream_hex",
            "qpack_decoder_stream_hex",
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
        self.assertEqual(
            pull_varint(fixture_hex(self.fixture, "qpack_encoder_stream_hex"), 0)[0], 2
        )
        self.assertEqual(
            pull_varint(fixture_hex(self.fixture, "qpack_decoder_stream_hex"), 0)[0], 3
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


if __name__ == "__main__":
    unittest.main()
