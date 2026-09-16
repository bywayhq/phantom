import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from scripts.capture.compare_quic_flights import load_logical_flight, main
from scripts.capture.quic_flight import (
    PacketSummary,
    compare_logical_flights,
    parse_logical_flight_summary,
)
from scripts.capture.quic_summary import (
    FrameKind,
    NormalizedPacket,
    StreamFrame,
    SymbolicSpan,
)

SPANS = (
    SymbolicSpan("control_settings_prefix", 2, 0, 4),
    SymbolicSpan("request_headers", 0, 0, 6),
)


def stream(
    stream_id: int,
    offset: int,
    length: int,
    *overlaps: str,
    fin: bool = False,
) -> StreamFrame:
    return StreamFrame("stream", stream_id, offset, length, fin, overlaps)


def reference_summary() -> PacketSummary:
    return PacketSummary.build(
        (
            NormalizedPacket("initial", (FrameKind("crypto"), FrameKind("padding"))),
            NormalizedPacket("handshake", (FrameKind("crypto"), FrameKind("ack"))),
            NormalizedPacket(
                "1rtt",
                (
                    stream(2, 0, 4, "control_settings_prefix"),
                    stream(0, 0, 6, "request_headers", fin=True),
                    FrameKind("padding"),
                ),
            ),
        ),
        SPANS,
    )


class LogicalFlightTests(unittest.TestCase):
    def test_comparison_ignores_packetization_ack_padding_and_retransmission(
        self,
    ) -> None:
        reference = reference_summary()
        fragmented = PacketSummary.build(
            (
                NormalizedPacket("initial", (FrameKind("ack"), FrameKind("crypto"))),
                NormalizedPacket("handshake", (FrameKind("crypto"),)),
                NormalizedPacket(
                    "1rtt",
                    (
                        stream(0, 0, 2, "request_headers"),
                        stream(2, 0, 2, "control_settings_prefix"),
                        FrameKind("ack"),
                    ),
                ),
                NormalizedPacket(
                    "1rtt",
                    (
                        stream(2, 2, 2, "control_settings_prefix"),
                        stream(0, 2, 4, "request_headers", fin=True),
                        stream(0, 0, 2, "request_headers"),
                    ),
                ),
            ),
            SPANS,
        )

        self.assertFalse(reference.logical_flight.stream_retransmission_observed)
        self.assertTrue(fragmented.logical_flight.stream_retransmission_observed)
        self.assertEqual(
            compare_logical_flights(
                reference.logical_flight, fragmented.logical_flight
            ),
            (),
        )

    def test_comparison_rejects_incomplete_markers_and_terminal_frames(self) -> None:
        reference = reference_summary()
        incomplete = PacketSummary.build(
            (
                NormalizedPacket("initial", (FrameKind("crypto"),)),
                NormalizedPacket("handshake", (FrameKind("crypto"),)),
                NormalizedPacket(
                    "1rtt",
                    (
                        stream(2, 0, 4, "control_settings_prefix"),
                        stream(0, 0, 5, "request_headers", fin=True),
                        FrameKind("application_close"),
                    ),
                ),
            ),
            SPANS,
        )

        differences = compare_logical_flights(
            reference.logical_flight, incomplete.logical_flight
        )
        self.assertTrue(any("terminal frames" in item for item in differences))
        self.assertTrue(any("incomplete markers" in item for item in differences))
        self.assertTrue(any("request_headers" in item for item in differences))

    def test_comparison_rejects_flights_without_symbolic_markers(self) -> None:
        empty = PacketSummary.build(
            (
                NormalizedPacket("initial", (FrameKind("crypto"),)),
                NormalizedPacket("handshake", (FrameKind("crypto"),)),
                NormalizedPacket("1rtt", (FrameKind("ping"),)),
            ),
            (),
        )

        differences = compare_logical_flights(
            empty.logical_flight, empty.logical_flight
        )
        self.assertEqual(
            differences,
            ("left contains no symbolic markers", "right contains no symbolic markers"),
        )

    def test_comparison_rejects_fin_and_packet_space_differences(self) -> None:
        reference = reference_summary()
        no_fin_or_handshake = PacketSummary.build(
            (
                NormalizedPacket("initial", (FrameKind("crypto"),)),
                NormalizedPacket(
                    "1rtt",
                    (
                        stream(2, 0, 4, "control_settings_prefix"),
                        stream(0, 0, 6, "request_headers"),
                    ),
                ),
            ),
            SPANS,
        )

        differences = compare_logical_flights(
            reference.logical_flight, no_fin_or_handshake.logical_flight
        )
        self.assertTrue(any("packet spaces" in item for item in differences))
        self.assertTrue(any("request_headers" in item for item in differences))

    def test_fin_must_land_exactly_at_the_marker_end(self) -> None:
        reference = reference_summary()
        fin_at_end = PacketSummary.build(
            (
                NormalizedPacket("initial", (FrameKind("crypto"),)),
                NormalizedPacket("handshake", (FrameKind("crypto"),)),
                NormalizedPacket(
                    "1rtt",
                    (
                        stream(2, 0, 4, "control_settings_prefix"),
                        stream(0, 0, 6, "request_headers"),
                        stream(0, 6, 0, fin=True),
                    ),
                ),
            ),
            SPANS,
        )
        fin_after_end = PacketSummary.build(
            (
                NormalizedPacket("initial", (FrameKind("crypto"),)),
                NormalizedPacket("handshake", (FrameKind("crypto"),)),
                NormalizedPacket(
                    "1rtt",
                    (
                        stream(2, 0, 4, "control_settings_prefix"),
                        stream(0, 0, 6, "request_headers"),
                        stream(0, 7, 0, fin=True),
                    ),
                ),
            ),
            SPANS,
        )

        self.assertEqual(
            compare_logical_flights(
                reference.logical_flight, fin_at_end.logical_flight
            ),
            (),
        )
        self.assertTrue(
            any(
                "request_headers" in difference
                for difference in compare_logical_flights(
                    reference.logical_flight, fin_after_end.logical_flight
                )
            )
        )

    def test_repeated_fin_only_frame_is_stream_retransmission(self) -> None:
        repeated_fin = PacketSummary.build(
            (
                NormalizedPacket("initial", (FrameKind("crypto"),)),
                NormalizedPacket("handshake", (FrameKind("crypto"),)),
                NormalizedPacket(
                    "1rtt",
                    (
                        stream(2, 0, 4, "control_settings_prefix"),
                        stream(0, 0, 6, "request_headers", fin=True),
                    ),
                ),
                NormalizedPacket("1rtt", (stream(0, 6, 0, fin=True),)),
            ),
            SPANS,
        )

        self.assertTrue(repeated_fin.logical_flight.stream_retransmission_observed)

    def test_terminal_frame_space_is_preserved(self) -> None:
        reference = reference_summary()
        initial_close = PacketSummary.build(
            (
                NormalizedPacket(
                    "initial", (FrameKind("crypto"), FrameKind("transport_close"))
                ),
                *reference.packets[1:],
            ),
            SPANS,
        )
        application_close = PacketSummary.build(
            (
                *reference.packets[:2],
                NormalizedPacket(
                    "1rtt",
                    (*reference.packets[2].frames, FrameKind("transport_close")),
                ),
            ),
            SPANS,
        )

        differences = compare_logical_flights(
            initial_close.logical_flight, application_close.logical_flight
        )
        self.assertTrue(any("terminal frames differ" in item for item in differences))

    def test_summary_round_trips_through_strict_logical_schema(self) -> None:
        summary = reference_summary()
        serialized = summary.as_dict()
        parsed = parse_logical_flight_summary(serialized)

        self.assertEqual(parsed, summary.logical_flight)
        self.assertEqual(serialized["format"], "phantom-quic-packet-summary-v2")

        unknown = copy.deepcopy(serialized)
        unknown["logical_flight"]["extra"] = True
        with self.assertRaisesRegex(ValueError, "invalid schema"):
            parse_logical_flight_summary(unknown)

        inconsistent = copy.deepcopy(serialized)
        inconsistent["logical_flight"]["markers"][0]["complete"] = False
        with self.assertRaisesRegex(ValueError, "completeness"):
            parse_logical_flight_summary(inconsistent)

        forged = copy.deepcopy(serialized)
        forged["packets"][2]["frames"][1]["length"] = 5
        with self.assertRaisesRegex(ValueError, "disagrees"):
            parse_logical_flight_summary(forged)

        unknown_frame = copy.deepcopy(serialized)
        unknown_frame["packets"][0]["frames"][0]["kind"] = "made_up"
        with self.assertRaisesRegex(ValueError, "frame kind"):
            parse_logical_flight_summary(unknown_frame)

        malformed_frame = copy.deepcopy(serialized)
        malformed_frame["packets"][0]["frames"][0]["kind"] = []
        with self.assertRaisesRegex(ValueError, "frame kind"):
            parse_logical_flight_summary(malformed_frame)

    def test_projection_rejects_unknown_or_cross_stream_span_labels(self) -> None:
        unknown = NormalizedPacket("1rtt", (stream(2, 0, 1, "missing_marker"),))
        with self.assertRaisesRegex(ValueError, "unknown symbolic span"):
            PacketSummary.build((unknown,), SPANS)

        cross_stream = NormalizedPacket(
            "1rtt", (stream(6, 0, 4, "control_settings_prefix"),)
        )
        with self.assertRaisesRegex(ValueError, "another stream"):
            PacketSummary.build((cross_stream,), SPANS)

    def test_command_compares_separate_summary_files(self) -> None:
        document = reference_summary().as_dict()
        with tempfile.TemporaryDirectory() as directory:
            left = Path(directory, "left.json")
            right = Path(directory, "right.json")
            left.write_text(json.dumps(document), encoding="utf-8")
            right.write_text(json.dumps(document), encoding="utf-8")

            output = io.StringIO()
            with (
                patch("sys.argv", ["compare", str(left), str(right)]),
                redirect_stdout(output),
            ):
                main()
            self.assertEqual(output.getvalue(), "logical QUIC flights match\n")

            changed = copy.deepcopy(document)
            changed["logical_flight"]["markers"][1]["fin_at_end"] = False
            changed["packets"][2]["frames"][1]["fin"] = False
            right.write_text(json.dumps(changed), encoding="utf-8")
            output = io.StringIO()
            with (
                patch("sys.argv", ["compare", str(left), str(right)]),
                redirect_stdout(output),
                self.assertRaises(SystemExit) as exit_status,
            ):
                main()
            self.assertEqual(exit_status.exception.code, 1)
            self.assertIn("request_headers", output.getvalue())

    def test_command_loader_rejects_duplicate_json_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "duplicate.json")
            path.write_text('{"format":"one","format":"two"}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                load_logical_flight(path)


if __name__ == "__main__":
    unittest.main()
