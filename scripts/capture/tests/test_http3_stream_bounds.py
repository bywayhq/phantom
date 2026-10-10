import argparse
import asyncio
import unittest

from aioquic.quic.events import StreamDataReceived

from scripts.capture.chrome_http3 import MAX_STREAM_CAPTURE, Capture
from scripts.capture.quic_packet_diff import QuicPacketCapture


def event(stream_id, data=b"", *, end_stream=False):
    return StreamDataReceived(stream_id=stream_id, data=data, end_stream=end_stream)


def capture(packet_capture=None):
    return Capture(
        complete=asyncio.Event(),
        metadata=argparse.Namespace(),
        packet_capture=packet_capture,
    )


class Http3StreamBoundsTests(unittest.TestCase):
    def test_distinct_empty_streams_cannot_exceed_the_capture_count_budget(self):
        recorded = capture()
        for index in range(128):
            recorded.stream_data(event(index * 4, end_stream=True))
        self.assertEqual(len(recorded.streams), 128)

        with self.assertRaisesRegex(ValueError, "stream count exceeds"):
            recorded.stream_data(event(128 * 4, end_stream=True))

        self.assertEqual(len(recorded.streams), 128)
        self.assertNotIn(128 * 4, recorded.streams)

    def test_combined_bytes_are_bounded_without_a_packet_collector(self):
        recorded = capture()
        for stream_id in (0, 4, 8, 12):
            recorded.stream_data(event(stream_id, b"x" * (256 * 1024)))
        self.assertEqual(sum(map(len, recorded.streams.values())), 1024 * 1024)
        self.assertIsNone(recorded.packet_capture)

        with self.assertRaisesRegex(ValueError, "stream bytes exceed"):
            recorded.stream_data(event(16, b"y"))

        self.assertEqual(sum(map(len, recorded.streams.values())), 1024 * 1024)
        self.assertNotIn(16, recorded.streams)

    def test_packet_freeze_does_not_remove_the_combined_stream_budget(self):
        packets = QuicPacketCapture()
        packets.add_datagram(b"one initial datagram")
        recorded = capture(packets)
        recorded.stream_data(event(0, b"\x01\x00"))
        recorded.snapshot_request(0, [(b":method", b"GET")])
        packets.add_datagram(b"after the first request")
        self.assertEqual(packets.buffered_datagram_count, 1)

        for stream_id in (4, 8, 12):
            recorded.stream_data(event(stream_id, b"x" * (256 * 1024)))
        recorded.stream_data(event(16, b"x" * (256 * 1024 - 2)))
        self.assertEqual(sum(map(len, recorded.streams.values())), 1024 * 1024)
        snapshot = recorded.request_headers_frame

        with self.assertRaisesRegex(ValueError, "stream bytes exceed"):
            recorded.stream_data(event(16, b"y"))

        self.assertEqual(recorded.request_headers_frame, b"\x01\x00")
        self.assertEqual(recorded.request_headers_frame, snapshot)
        self.assertEqual(sum(map(len, recorded.streams.values())), 1024 * 1024)
        packets.clear()

    def test_a_reported_failure_prevents_further_stream_retention(self):
        recorded = capture()
        recorded.stream_data(event(0, b"retained"))
        failure = ValueError("capture already failed")
        recorded.fail(failure)
        before = {stream: bytes(data) for stream, data in recorded.streams.items()}

        recorded.stream_data(event(0, b"later"))
        recorded.stream_data(event(4, b"new stream"))

        self.assertEqual(recorded.streams, before)
        self.assertIs(recorded.failure, failure)
        self.assertTrue(recorded.complete.is_set())

    def test_existing_streams_can_extend_at_the_count_boundary(self):
        recorded = capture()
        for index in range(128):
            recorded.stream_data(event(index * 4))

        recorded.stream_data(event(0, b"later bytes"))

        self.assertEqual(recorded.streams[0], b"later bytes")
        self.assertEqual(len(recorded.streams), 128)

    def test_one_stream_still_obeys_its_existing_byte_limit(self):
        recorded = capture()
        recorded.stream_data(event(0, b"x" * MAX_STREAM_CAPTURE))

        with self.assertRaisesRegex(ValueError, "stream 0 exceeds"):
            recorded.stream_data(event(0, b"y"))

        self.assertEqual(len(recorded.streams[0]), MAX_STREAM_CAPTURE)

    def test_first_request_snapshots_remain_exact_after_later_stream_data(self):
        recorded = capture()
        recorded.stream_data(event(0, b"\x01\x00"))
        recorded.stream_data(event(2, b"\x02encoder"))
        recorded.stream_data(event(6, b"\x03decoder"))
        recorded.snapshot_request(0, [(b":method", b"GET")])

        recorded.stream_data(event(2, b"later encoder bytes"))
        recorded.stream_data(event(6, b"later decoder bytes"))

        self.assertEqual(recorded.request_headers_frame, b"\x01\x00")
        self.assertEqual(recorded.request_qpack_encoder_stream_prefix, b"\x02encoder")
        self.assertEqual(recorded.request_qpack_decoder_stream_prefix, b"\x03decoder")


if __name__ == "__main__":
    unittest.main()
