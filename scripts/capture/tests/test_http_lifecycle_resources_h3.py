import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pylsqpack
from aioquic.asyncio import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection, Setting, encode_frame, encode_settings
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import (
    ConnectionTerminated,
    ProtocolNegotiated,
    StreamDataReceived,
)

from scripts.capture import http_lifecycle as lifecycle
from scripts.capture import http_lifecycle_resources_h3 as h3
from scripts.capture.http2_session import HOSTNAME, generate_certificate
from scripts.capture.http3_wire import pull_varint
from scripts.capture.http_lifecycle_resources import MAX_PEER_BYTES, ResourceCapture
from scripts.capture.quic_resumption import load_certificate
from scripts.capture.tests.loopback_quic import connect_loopback
from scripts.capture.tests.test_http_lifecycle import options
from scripts.capture.tests.test_http_lifecycle_resources import fields


def event(stream: int, data: bytes, ended: bool = False) -> StreamDataReceived:
    return StreamDataReceived(data=data, end_stream=ended, stream_id=stream)


def retained(
    parts: list[StreamDataReceived],
) -> tuple[h3.StreamCapture, ResourceCapture]:
    resources = ResourceCapture("token", 12345, "h3")
    capture = h3.StreamCapture(
        settings={
            Setting.QPACK_MAX_TABLE_CAPACITY: 4096,
            Setting.QPACK_BLOCKED_STREAMS: 16,
        }
    )
    for item in parts:
        capture.retain(item, resources)
    return capture, resources


CONTROL = b"\x00" + encode_frame(4, encode_settings({}))


class StreamReplayTests(unittest.TestCase):
    def test_fragmented_headers_preserve_order_and_duplicates(self) -> None:
        expected = tuple(fields(12345, "/start?run=token"))
        _, payload = pylsqpack.Encoder().encode(0, list(expected))
        parts = [event(2, CONTROL), event(6, b"\x02"), event(10, b"\x03")]
        head = encode_frame(1, payload)
        parts.extend(event(0, bytes([byte])) for byte in head)
        parts.append(event(0, b"", True))
        capture, _ = retained(parts)
        capture.replay({0: expected})
        self.assertEqual(
            b"".join(e.data for e in capture.events if e.stream == 0), head
        )
        self.assertEqual(capture.events[-1].offset, len(head))
        self.assertEqual(capture.events[-1].data, b"")
        self.assertTrue(capture.events[-1].ended)
        changed = expected[:-1] + ((b"accept", b"changed"),)
        with self.assertRaisesRegex(ValueError, "disagree"):
            capture.replay({0: changed})

    def test_encoder_arrives_after_blocked_request_and_reuses_dynamic_entry(
        self,
    ) -> None:
        encoder = pylsqpack.Encoder()
        settings = encoder.apply_settings(4096, 16)
        expected = fields(12345, "/start?run=token")
        first_inserts, first = encoder.encode(0, expected)
        second_inserts, second = encoder.encode(4, expected)
        self.assertTrue(
            second_inserts, "repeated fields must exercise the dynamic table"
        )
        parts = [
            event(2, CONTROL),
            event(6, b"\x02" + settings + first_inserts),
            event(0, encode_frame(1, first), True),
            event(4, encode_frame(1, second), True),
            *(event(6, bytes([byte])) for byte in second_inserts),
        ]
        capture, _ = retained(parts)
        capture.replay({0: tuple(expected), 4: tuple(expected)})
        parts.pop()
        broken, _ = retained(parts)
        with self.assertRaises((ValueError, pylsqpack.EncoderStreamError)):
            broken.replay({0: tuple(expected), 4: tuple(expected)})

    def test_missing_fin_truncated_frame_trailers_and_request_body_fail(self) -> None:
        expected = tuple(fields(12345, "/start?run=token"))
        _, payload = pylsqpack.Encoder().encode(0, list(expected))
        head = encode_frame(1, payload)
        for data, ended in (
            (head, False),
            (head[:-1], True),
            (head + head, True),
            (head + encode_frame(0, b"x"), True),
        ):
            with self.subTest(data=data, ended=ended):
                capture, _ = retained([event(2, CONTROL), event(0, data, ended)])
                with self.assertRaises(ValueError):
                    capture.replay({0: expected})

    def test_critical_stream_duplicates_fin_and_partial_instructions_fail(self) -> None:
        for parts in (
            [event(2, CONTROL), event(6, CONTROL)],
            [event(2, CONTROL, True)],
            [event(2, CONTROL), event(6, b"\x02", True)],
            [event(2, CONTROL), event(6, b"\x02\x3f")],
            [event(2, CONTROL), event(10, b"\x03\xff")],
            [event(2, CONTROL[:-1])],
            [event(2, b"\x00" + encode_frame(7, b"\x00"))],
        ):
            with self.subTest(parts=parts):
                capture, _ = retained(parts)
                with self.assertRaises((ValueError, pylsqpack.EncoderStreamError)):
                    capture.replay({})

    def test_unused_encoder_credentials_and_values_are_rejected(self) -> None:
        for name, value in (
            (b"authorization", b"private"),
            (b"user-agent", b"unowned-value"),
        ):
            encoder = pylsqpack.Encoder()
            settings = encoder.apply_settings(4096, 16)
            encoder.encode(0, [(name, value)])
            insert, _ = encoder.encode(4, [(name, value)])
            self.assertTrue(insert)
            capture, _ = retained(
                [event(2, CONTROL), event(6, b"\x02" + settings + insert)]
            )
            with self.assertRaises(ValueError):
                capture.replay({})

    def test_unused_static_name_references_require_an_approved_name(self) -> None:
        expected = tuple(fields(12345, "/start?run=token"))
        _, payload = pylsqpack.Encoder().encode(0, list(expected))
        capacity = pylsqpack.Encoder().apply_settings(4096, 16)
        value = b"/start?run=token"
        # RFC 9204 static entries: location, content-type and server.
        for index in (12, 44, 92):
            name = bytes([0xC0 | index]) if index < 63 else bytes([0xFF, index - 63])
            with self.subTest(index=index):
                capture, _ = retained(
                    [
                        event(2, CONTROL),
                        event(
                            6, b"\x02" + capacity + name + bytes([len(value)]) + value
                        ),
                        event(0, encode_frame(1, payload), True),
                    ]
                )
                with self.assertRaisesRegex(ValueError, "unapproved field name"):
                    capture.replay({0: expected})

    def test_static_dynamic_and_duplicate_approved_names_replay(self) -> None:
        expected = tuple(fields(12345, "/start?run=token"))
        _, payload = pylsqpack.Encoder().encode(0, list(expected))
        capacity = pylsqpack.Encoder().apply_settings(4096, 16)
        value = b"/start?run=token"
        # Static user-agent (95), dynamic name reference (0), then duplicate (0).
        inserts = b"\xff\x20" + bytes([len(value)]) + value
        inserts += b"\x80" + bytes([len(value)]) + value + b"\x00"
        capture, _ = retained(
            [
                event(2, CONTROL),
                event(6, b"\x02" + capacity + inserts),
                event(0, encode_frame(1, payload), True),
            ]
        )
        capture.replay({0: expected})

    def test_bounds_apply_before_retaining_and_zero_byte_events_are_bounded(
        self,
    ) -> None:
        capture, resources = retained([])
        with patch.object(h3, "MAX_EVENTS", 1):
            capture.retain(event(2, b""), resources)
            with self.assertRaisesRegex(ValueError, "event limit"):
                capture.retain(event(2, b""), resources)
        self.assertEqual(len(capture.events), 1)
        with (
            patch.object(h3, "MAX_STREAMS", 1),
            self.assertRaisesRegex(ValueError, "stream limit"),
        ):
            capture.retain(event(6, b"x"), resources)
        resources.retained = MAX_PEER_BYTES
        with self.assertRaisesRegex(ValueError, "peer bytes"):
            capture.retain(event(2, b"x"), resources)
        self.assertEqual(capture.streams[2], b"")

    def test_fin_cannot_be_followed_by_data(self) -> None:
        capture, resources = retained([event(0, b"", True)])
        with self.assertRaisesRegex(ValueError, "after stream FIN"):
            capture.retain(event(0, b"x"), resources)

    def test_nonempty_reserved_control_frames_preserve_captured_bytes(self) -> None:
        # Chrome 156.0.8078.47 Linux control frames, including their varint widths.
        for frame in (
            bytes.fromhex("c0000003a68e75af021b6e"),
            bytes.fromhex("c00000005d899fdf0272e2"),
        ):
            for chunks in ([frame], [bytes([byte]) for byte in frame]):
                with self.subTest(frame=frame.hex(), chunks=len(chunks)):
                    capture, _ = retained(
                        [event(2, CONTROL), *(event(2, chunk) for chunk in chunks)]
                    )
                    before = tuple(capture.events)
                    capture.replay({})
                    self.assertEqual(tuple(capture.events), before)
                    self.assertEqual(bytes(capture.streams[2]), CONTROL + frame)
                    self.assertEqual(
                        b"".join(item.data for item in capture.events), CONTROL + frame
                    )

    def test_reserved_control_frame_rejects_every_truncated_boundary(self) -> None:
        for frame in (
            bytes.fromhex("c0000003a68e75af021b6e"),
            bytes.fromhex("c00000005d899fdf0272e2"),
        ):
            for length in range(1, len(frame)):
                with self.subTest(frame=frame.hex(), length=length):
                    capture, _ = retained([event(2, CONTROL + frame[:length])])
                    with self.assertRaisesRegex(ValueError, "incomplete frame"):
                        capture.replay({})

    def test_control_stream_retains_valid_priorities_and_rejects_opaque_payloads(
        self,
    ) -> None:
        from aioquic.buffer import encode_uint_var

        for kind, payload in (
            (7, b"\x00"),
            (13, b"\x00"),
            (0xF0700, b"\x00u=1, i"),
            (0x21, b""),
        ):
            capture, _ = retained([event(2, CONTROL + encode_frame(kind, payload))])
            capture.replay({})
        for kind, payload in (
            (7, b"\x00opaque"),
            (0x22, b"private"),
            (0xF0700, encode_uint_var(0) + b"authorization=private"),
        ):
            capture, _ = retained([event(2, CONTROL + encode_frame(kind, payload))])
            with self.assertRaises(ValueError):
                capture.replay({})


class SelectionTests(unittest.TestCase):
    def test_explicit_h3_launch_keeps_traffic_on_owned_origin(self) -> None:
        args = options(scenario="resources", resource_protocol="h3")
        lifecycle.validate_options(args)
        plan = lifecycle.launch_plan(args, generate_certificate(), (12345,))
        self.assertIn("--enable-quic", plan.extra_arguments)
        self.assertNotIn("--disable-quic", plan.extra_arguments)
        self.assertIn(
            f"--origin-to-force-quic-on={HOSTNAME}:12345", plan.extra_arguments
        )
        self.assertTrue(
            any("MAP * ~NOTFOUND" in value for value in plan.extra_arguments)
        )
        for changes in ({"scenario": "close"}, {"browser": "firefox"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                lifecycle.validate_options(
                    options(
                        **{
                            "scenario": "resources",
                            "resource_protocol": "h3",
                            **changes,
                        }
                    )
                )


class WireQuic:
    def __init__(self) -> None:
        self.configuration = SimpleNamespace(is_client=False)
        self._quic_logger = None
        self._remote_max_datagram_frame_size = None
        self.next_uni = 3
        self.output: dict[int, bytearray] = {}
        self.ended: set[int] = set()
        self.closes = []

    def get_next_available_stream_id(self, is_unidirectional=False) -> int:
        value = self.next_uni
        self.next_uni += 4
        return value

    def send_stream_data(self, stream: int, data: bytes, end_stream=False) -> None:
        self.output.setdefault(stream, bytearray()).extend(data)
        if end_stream:
            self.ended.add(stream)

    def close(self, **kwargs) -> None:
        self.closes.append(kwargs)


class ProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.run = lifecycle.Run("resources", "token", 100)
        self.run.resources = ResourceCapture("token", 12345, "h3")
        self.owner = h3.ResourceServer(self.run, QuicConfiguration(is_client=False))
        self.quic = WireQuic()
        self.protocol = h3.ResourceProtocol(self.quic, owner=self.owner)
        self.protocol.transmit = Mock()
        self.protocol.handle(ProtocolNegotiated(alpn_protocol="h3"))

    async def asyncTearDown(self) -> None:
        if self.run.completion is not None:
            self.run.completion.cancel()

    def send(self, stream: int, target: str, extra=(), ended=True) -> None:
        _, payload = pylsqpack.Encoder().encode(
            stream, [*fields(12345, target), *extra]
        )
        self.protocol.quic_event_received(
            event(stream, encode_frame(1, payload), ended)
        )

    async def test_six_owned_requests_queue_complete_exact_asset_bodies(self) -> None:
        self.protocol.handle(event(2, CONTROL))
        paths = (
            "/start",
            "/resource.js",
            "/resource.css",
            "/resource.gif",
            "/resource.ttf",
            "/done",
        )
        for stream, path in zip(range(0, 24, 4), paths, strict=True):
            target = (
                self.run.resources.done_target("resources:ok")
                if path == "/done"
                else self.run.resources.target(path)
            )
            self.send(stream, target)
            raw = bytes(self.quic.output[stream])
            _, width = pull_varint(raw, 0)
            length, length_width = pull_varint(raw, width)
            offset = width + length_width + length
            kind, width = pull_varint(raw, offset)
            self.assertEqual(kind, 0)
            length, length_width = pull_varint(raw, offset + width)
            body = raw[offset + width + length_width :]
            expected = lifecycle.reply_for("resources", "GET", path, {}, self.run).body
            self.assertEqual(length, len(expected))
            self.assertEqual(body, expected)
            self.assertIn(stream, self.quic.ended)
        self.assertEqual(self.owner.errors, [])
        self.assertEqual(len(self.run.requests), 6)
        self.assertEqual(self.run.page_result, "resources:ok")
        self.assertIn("resource_protocol=h3", self.owner.evidence())
        self.run.page_result = "resources:error"
        with self.assertRaisesRegex(ValueError, "did not complete"):
            self.owner.evidence()

    async def test_delayed_fin_waits_and_body_or_credentials_prevent_response(
        self,
    ) -> None:
        self.send(0, "/start?run=token", ended=False)
        self.assertNotIn(0, self.quic.output)
        self.protocol.quic_event_received(event(0, b"", True))
        self.assertIn(0, self.quic.ended)
        self.send(4, "/resource.js?run=token", extra=[(b"authorization", b"private")])
        self.assertNotIn(4, self.quic.output)
        self.assertTrue(self.owner.errors)

    async def test_completion_on_another_h3_connection_replays_both_peers(
        self,
    ) -> None:
        self.protocol.handle(event(2, CONTROL))
        for stream, path in zip(
            range(0, 20, 4),
            (
                "/start",
                "/resource.js",
                "/resource.css",
                "/resource.gif",
                "/resource.ttf",
            ),
            strict=True,
        ):
            self.send(stream, self.run.resources.target(path))
        self.assertEqual(self.run.page_connection, 0)

        self.quic = WireQuic()
        self.protocol = h3.ResourceProtocol(self.quic, owner=self.owner)
        self.protocol.transmit = Mock()
        self.protocol.handle(ProtocolNegotiated(alpn_protocol="h3"))
        self.protocol.handle(event(2, CONTROL))
        self.send(0, self.run.resources.done_target("resources:ok"))

        self.assertEqual(self.owner.errors, [])
        self.assertEqual(self.run.page_result, "resources:ok")
        self.assertEqual(self.run.page_connection, 0)
        self.assertEqual(self.run.resources.requests[-1].connection, 1)
        self.assertIn(0, self.quic.ended)
        lines = self.owner.evidence()
        for connection in (0, 1):
            self.assertTrue(
                any(
                    line.startswith(f"resource_connection_{connection}_h3_")
                    for line in lines
                )
            )

    async def test_wrong_authority_and_token_fail(self) -> None:
        for extra in (
            [(b":authority", b"other.test:12345")],
            [(b":path", b"/start?run=other")],
        ):
            with self.subTest(extra=extra):
                self.send(0, "/start?run=token", extra=extra)
                self.assertTrue(self.owner.errors)
                self.assertNotIn(0, self.quic.output)

    async def test_request_body_is_rejected_without_a_response(self) -> None:
        self.send(0, "/start?run=token", ended=False)
        self.protocol.quic_event_received(event(0, encode_frame(0, b"body"), True))
        self.assertNotIn(0, self.quic.output)
        self.assertTrue(self.owner.errors)
        self.assertFalse(self.run.resources.responded)

    async def test_h3_protocol_error_and_early_termination_are_observed(self) -> None:
        self.protocol.quic_event_received(event(2, b"\x00" + encode_frame(0, b"")))
        self.assertTrue(self.quic.closes)
        self.assertTrue(self.owner.errors)
        self.protocol.quic_event_received(
            ConnectionTerminated(
                error_code=0x102, frame_type=None, reason_phrase="invalid"
            )
        )
        self.assertIsNotNone(self.protocol.record.eof)
        self.assertTrue(self.run.failure_ready.is_set())

    async def test_graceful_premature_disconnect_is_not_success(self) -> None:
        self.protocol.quic_event_received(
            ConnectionTerminated(error_code=0, frame_type=None, reason_phrase="")
        )
        self.assertRegex(str(self.owner.errors[0]), "before page completion")
        self.assertTrue(self.run.failure_ready.is_set())


class OwnershipTests(unittest.IsolatedAsyncioTestCase):
    async def test_loopback_h3_peer_reads_six_bodies_and_replays_retired_capture(
        self,
    ) -> None:
        certificate = generate_certificate()
        run = lifecycle.Run("resources", "token", 100)
        configuration = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
        load_certificate(configuration, certificate)
        owner = h3.ResourceServer(run, configuration)
        primary = None

        class Peer(QuicConnectionProtocol):
            def __init__(self, *args, **kwargs) -> None:
                super().__init__(*args, **kwargs)
                self.http = H3Connection(self._quic)
                self.responses = {}
                self.bodies = {}
                self.statuses = {}

            def quic_event_received(self, event) -> None:
                for item in self.http.handle_event(event):
                    if isinstance(item, HeadersReceived):
                        self.statuses[item.stream_id] = dict(item.headers)[b":status"]
                    elif isinstance(item, DataReceived):
                        self.bodies[item.stream_id].extend(item.data)
                        if item.stream_ended:
                            self.responses[item.stream_id].set_result(
                                bytes(self.bodies[item.stream_id])
                            )

            async def get(self, target: str) -> bytes:
                stream = self._quic.get_next_available_stream_id()
                self.responses[stream] = asyncio.get_running_loop().create_future()
                self.bodies[stream] = bytearray()
                self.http.send_headers(stream, fields(port, target), end_stream=True)
                self.transmit()
                body = await asyncio.wait_for(self.responses[stream], 5)
                self_status = self.statuses[stream]
                if self_status != b"200":
                    raise ValueError("controlled peer did not receive status 200")
                return body

        try:
            port = await owner.start("127.0.0.1")
            run.resources = ResourceCapture("token", port, "h3")
            owner.resources = run.resources
            client = QuicConfiguration(
                is_client=True, alpn_protocols=["h3"], server_name=HOSTNAME
            )
            client.load_verify_locations(cadata=certificate.certificate_pem)
            async with connect_loopback(port, client, Peer) as peer:
                for path in (
                    "/start",
                    "/resource.js",
                    "/resource.css",
                    "/resource.gif",
                    "/resource.ttf",
                    "/done",
                ):
                    target = (
                        run.resources.done_target("resources:ok")
                        if path == "/done"
                        else run.resources.target(path)
                    )
                    body = await peer.get(target)
                    expected = lifecycle.reply_for(
                        "resources", "GET", path, {}, run
                    ).body
                    self.assertEqual(body, expected)
                await owner.wait_done(2)
            await asyncio.wait_for(lifecycle.all_ended(run), 5)
        except BaseException as error:
            primary = error
        await owner.close(primary)
        self.assertTrue(owner.retired.done())
        self.assertTrue(owner.cleanup.done())
        self.assertTrue(all(protocol._closed.is_set() for protocol in owner.protocols))
        self.assertIn("resource_protocol=h3", owner.evidence())
        self.assertEqual(len(run.resources.requests), 6)

    async def test_timeout_and_callback_error_wake_the_owner(self) -> None:
        run = lifecycle.Run("resources", "token", 100)
        owner = h3.ResourceServer(run, QuicConfiguration(is_client=False))
        with self.assertRaises(TimeoutError):
            await owner.wait_done(0)
        failure = OSError("controlled callback failure")
        owner.error_received(failure)
        with self.assertRaises(OSError) as raised:
            await owner.wait_done(1)
        self.assertIs(raised.exception, failure)

    async def test_cancellation_keeps_udp_cleanup_owned(self) -> None:
        run = lifecycle.Run("resources", "token", 100)
        owner = h3.ResourceServer(run, QuicConfiguration(is_client=False))
        stopped = asyncio.Event()

        class Transport:
            def abort(self) -> None:
                stopped.set()
                owner.connection_lost(None)

        owner._transport = Transport()
        cancelled = asyncio.CancelledError()
        with self.assertRaises(asyncio.CancelledError) as raised:
            await owner.close(cancelled)
        self.assertIs(raised.exception, cancelled)
        self.assertTrue(stopped.is_set())
        self.assertTrue(owner.cleanup.done())
        self.assertTrue(owner.retired.done())

    async def test_cancel_during_close_joins_retirement_and_keeps_later_errors(
        self,
    ) -> None:
        run = lifecycle.Run("resources", "token", 100)
        owner = h3.ResourceServer(run, QuicConfiguration(is_client=False))
        waiting = asyncio.Event()
        release = asyncio.Event()
        aborted = asyncio.Event()
        cleanup_error = OSError("controlled UDP retirement failure")

        async def wait_closed() -> None:
            waiting.set()
            await release.wait()

        owner.protocols.append(
            SimpleNamespace(
                close=lambda: None,
                wait_closed=wait_closed,
                _timer=None,
                _transmit_task=None,
            )
        )

        class Transport:
            def abort(self) -> None:
                aborted.set()
                owner.connection_lost(cleanup_error)

        owner._transport = Transport()
        interrupted = []

        async def close() -> None:
            try:
                await owner.close()
            except asyncio.CancelledError as error:
                interrupted.append(error)
                raise

        closing = asyncio.create_task(close())
        try:
            await waiting.wait()
            closing.cancel("controlled interruption")
            await asyncio.sleep(0)
            still_joining = not closing.done()
            closing.cancel("second interruption")
            release.set()
            with self.assertRaises(asyncio.CancelledError):
                await closing
            self.assertTrue(still_joining)
            self.assertIs(interrupted[0], owner.errors[0])
            self.assertIsInstance(owner.errors[1], asyncio.CancelledError)
            self.assertTrue(aborted.is_set())
            self.assertTrue(owner.retired.done())
            self.assertTrue(owner.cleanup.done())
            self.assertIsInstance(interrupted[0].__cause__, lifecycle.LifecycleFailures)
            self.assertIn(cleanup_error, interrupted[0].__cause__.cleanup)
        finally:
            release.set()
            await asyncio.gather(closing, return_exceptions=True)
            if owner.cleanup is not None:
                await owner.cleanup

    async def test_missing_udp_retirement_is_a_cleanup_failure(self) -> None:
        run = lifecycle.Run("resources", "token", 100)
        owner = h3.ResourceServer(run, QuicConfiguration(is_client=False))
        owner._transport = SimpleNamespace(abort=lambda: None)
        with (
            patch.object(lifecycle, "CLEANUP_SECONDS", 0.01),
            self.assertRaises(lifecycle.LifecycleFailures) as raised,
        ):
            await owner.close()
        self.assertTrue(
            any(
                isinstance(error, asyncio.TimeoutError)
                for error in raised.exception.cleanup
            ),
            raised.exception.cleanup,
        )
        self.assertIs(raised.exception.owner, owner)
        self.assertFalse(owner.retired.done())

    async def test_failed_acquisition_preserves_error_and_never_publishes(self) -> None:
        primary = OSError("controlled UDP acquisition failure")
        with tempfile.TemporaryDirectory() as directory:
            args = options(
                scenario="resources", resource_protocol="h3", output_dir=Path(directory)
            )
            with (
                patch.object(
                    h3.ResourceServer, "start", AsyncMock(side_effect=primary)
                ),
                patch.object(h3, "write_text_fixture") as publish,
                self.assertRaises(OSError) as raised,
            ):
                await lifecycle.capture(args)
            self.assertIs(raised.exception, primary)
            publish.assert_not_called()
            self.assertEqual(
                await asyncio.to_thread(lambda: list(Path(directory).iterdir())), []
            )

    async def test_cleanup_preserves_primary_and_observes_transport_retirement(
        self,
    ) -> None:
        run = lifecycle.Run("resources", "token", 100)
        owner = h3.ResourceServer(run, QuicConfiguration(is_client=False))
        primary = ValueError("controlled page failure")
        cleanup = OSError("controlled UDP close failure")

        class Transport:
            def abort(self) -> None:
                owner.connection_lost(cleanup)

        owner._transport = Transport()
        with self.assertRaises(ValueError) as raised:
            await owner.close(primary)
        self.assertIs(raised.exception, primary)
        self.assertIsInstance(primary.__cause__, lifecycle.LifecycleFailures)
        self.assertEqual(primary.__cause__.cleanup, (cleanup,))
        self.assertTrue(owner.retired.done())
        self.assertTrue(owner.cleanup.done())


if __name__ == "__main__":
    unittest.main()
