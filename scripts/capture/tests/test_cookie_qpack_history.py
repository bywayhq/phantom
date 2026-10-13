import asyncio
import ssl
import unittest
from unittest import mock

import pylsqpack
from aioquic.asyncio import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.quic.configuration import QuicConfiguration

from scripts.capture import cookie_crumbs
from scripts.capture.http2_session import generate_certificate
from scripts.capture.tests.loopback_quic import connect_loopback


class QpackHistoryTests(unittest.TestCase):
    def test_wrapped_counts_keep_the_decoded_entry_identity(self):
        insertion = bytes.fromhex("47782d70726f62650178")  # x-probe: x
        for count, block_hex in (
            (255, "ff010080"),
            (256, "010080"),
            (257, "020080"),
        ):
            with self.subTest(count=count):
                decoder = pylsqpack.Decoder(4096, 16)
                decoder.feed_encoder(bytes.fromhex("3fe11f") + insertion * count)
                block = bytes.fromhex(block_hex)
                _feedback, decoded = decoder.feed_header(0, block)
                self.assertEqual(decoded, [(b"x-probe", b"x")])

                section = cookie_crumbs.field_section(block, 4096, count)
                self.assertEqual(section.required_insert_count, count)
                self.assertEqual(section.base, count)
                self.assertEqual(section.lines[0].absolute, count - 1)

    def test_partial_instruction_does_not_increment_the_decoder_history(self):
        insertion = bytes.fromhex("47782d70726f62650178")
        prefix = bytes.fromhex("023fe11f") + insertion * 257
        decoder = pylsqpack.Decoder(4096, 16)
        decoder.feed_encoder(prefix[1:])
        for length in range(1, len(insertion)):
            with self.subTest(length=length):
                self.assertEqual(
                    cookie_crumbs.encoder_insert_count(prefix + insertion[:length]), 257
                )
        decoder.feed_encoder(insertion[:5])
        _feedback, decoded = decoder.feed_header(0, bytes.fromhex("020080"))
        self.assertEqual(decoded, [(b"x-probe", b"x")])
        self.assertEqual(cookie_crumbs.encoder_insert_count(prefix + insertion), 258)
        with self.assertRaises(cookie_crumbs.IncompleteQpack):
            cookie_crumbs.encoder_instructions(prefix + insertion[:5])

    def test_stream_type_width_does_not_change_insertions(self):
        for stream_type in ("02", "4002", "80000002", "c000000000000002"):
            with self.subTest(stream_type=stream_type):
                stream = bytes.fromhex(stream_type + "3fe11f47782d70726f62650178")
                record = cookie_crumbs.QuicRecord(0, streams={2: bytearray(stream)})
                self.assertEqual(cookie_crumbs.encoder_stream(record.streams), stream)
                self.assertEqual(cookie_crumbs.encoder_insert_count(stream), 1)
                self.assertEqual(len(cookie_crumbs.encoder_instructions(stream)), 2)

    def test_request_keeps_its_history_after_later_table_wraps(self):
        insertion = bytes.fromhex("47782d70726f62650178")
        run = cookie_crumbs.CookieRun("history", 0)
        block = bytes.fromhex("020080")
        run.quic_connections.append(
            cookie_crumbs.QuicRecord(
                0,
                streams={
                    0: bytearray(b"\x01\x03" + block),
                    2: bytearray(bytes.fromhex("023fe11f") + insertion * 513),
                },
            )
        )
        request = cookie_crumbs.RequestRecord(
            0, 0, "other", 0, decoded=[(b"x-probe", b"x")], qpack_inserts=257
        )
        lines = cookie_crumbs.h3_request_lines(
            "request", run, request, request.decoded, 4096
        )
        self.assertIn("request_required_insert_count=257", lines)
        self.assertIn("absolute:256", lines[-1])

    def test_invalid_counts_bases_and_references_are_refused(self):
        for block, capacity, inserts in (
            ("020080", 0, 257),
            ("ff020080", 4096, 257),
            ("0100", 4096, 0),
            ("0281", 4096, 1),
            ("020081", 4096, 1),
            ("020010", 4096, 1),
            ("0200", -1, 1),
            ("0200", 4096, -1),
        ):
            with (
                self.subTest(block=block, capacity=capacity, inserts=inserts),
                self.assertRaises(ValueError),
            ):
                cookie_crumbs.field_section(bytes.fromhex(block), capacity, inserts)

    def test_prefixed_integers_accept_62_bits_and_refuse_overflow(self):
        literal = bytes.fromhex("ff80feffffffffffff3f")
        self.assertEqual(
            cookie_crumbs.qpack_integer(literal, 0, 8), ((1 << 62) - 1, 10)
        )
        with self.assertRaises(ValueError):
            cookie_crumbs.qpack_integer(bytes.fromhex("ff81feffffffffffff3f"), 0, 8)
        with self.assertRaises(ValueError):
            cookie_crumbs.encoder_insert_count(bytes.fromhex("023f") + b"\xff" * 10)


class QpackCaptureHistoryTests(unittest.IsolatedAsyncioTestCase):
    async def test_actual_decoded_requests_keep_separate_table_histories(self):
        class Client(QuicConnectionProtocol):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.http = H3Connection(self._quic)

            def quic_event_received(self, event):
                # Literal encoder bytes below have their own insertion history.
                # Feeding acknowledgments to the unused client encoder is invalid.
                pass

        run = cookie_crumbs.CookieRun("qpack", 0)
        recorded = asyncio.Event()
        original_record = run.record

        def observe(request):
            original_record(request)
            recorded.set()

        configuration = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
        configuration.verify_mode = ssl.CERT_NONE
        insertion = bytes.fromhex("47782d70726f62650178")
        # GET https://localhost/ with a dynamic x-probe: x field.
        block = bytes.fromhex("0200d1d750096c6f63616c686f7374c180")
        certificate = generate_certificate()
        with mock.patch.object(run, "record", side_effect=observe):
            async with (
                cookie_crumbs.serving_http3(run, "127.0.0.1", certificate) as port,
                connect_loopback(port, configuration, Client) as client,
            ):
                encoder_stream = client.http._local_encoder_stream_id
                for stream_id, additions in ((0, 257), (4, 256)):
                    recorded.clear()
                    prefix = bytes.fromhex("3fe11f") if stream_id == 0 else b""
                    client._quic.send_stream_data(
                        encoder_stream, prefix + insertion * additions
                    )
                    client.transmit()

                    async def received_insertions(expected):
                        while True:
                            if run.quic_connections:
                                received = cookie_crumbs.encoder_stream(
                                    run.quic_connections[0].streams
                                )
                                if (
                                    cookie_crumbs.encoder_insert_count(received)
                                    == expected
                                ):
                                    return
                            await asyncio.sleep(0.001)

                    # A literal encoder cannot send more than a table window
                    # ahead of the decoder. Drain inserts before sending HEADERS.
                    await asyncio.wait_for(
                        received_insertions(257 if stream_id == 0 else 513), 20.0
                    )
                    client._quic.send_stream_data(
                        stream_id,
                        b"\x01" + bytes([len(block)]) + block,
                        end_stream=True,
                    )
                    client.transmit()
                    try:
                        await asyncio.wait_for(recorded.wait(), 20.0)
                    except asyncio.TimeoutError as error:
                        protocols = run.quic_owners[0].protocols
                        outcomes = [
                            protocol._quic._close_event for protocol in protocols
                        ]
                        raise AssertionError((stream_id, outcomes)) from error

        self.assertEqual(
            [request.qpack_inserts for request in run.requests], [257, 513]
        )
        self.assertEqual(run.requests[0].decoded[-1], (b"x-probe", b"x"))
        for request, required, absolute in zip(
            run.requests, (257, 513), (256, 512), strict=True
        ):
            lines = cookie_crumbs.h3_request_lines(
                "request", run, request, request.decoded, 4096
            )
            self.assertIn(f"request_required_insert_count={required}", lines)
            self.assertIn(f"absolute:{absolute}", lines[-1])
        self.assertTrue(run.quic_owners[0].finished)


if __name__ == "__main__":
    unittest.main()
