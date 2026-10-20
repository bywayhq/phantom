"""The independent upload oracle requires both live directions and exact codes."""

import asyncio
import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from aioquic.quic.events import ConnectionTerminated, StopSendingReceived, StreamReset

from scripts.conformance.binding_upload_h3 import Peer, UploadProtocol


class HTTP:
    def __init__(self):
        self.sent = []

    def send_data(self, stream, data, *, end_stream):
        self.sent.append((stream, data, end_stream))

    def handle_event(self, _event):
        return []


class UploadOracleTests(unittest.TestCase):
    def protocol(self, directory):
        protocol = object.__new__(UploadProtocol)
        protocol.owner = SimpleNamespace(
            protocols=[protocol], stopping=False, directory=Path(directory)
        )
        protocol.http = HTTP()
        protocol.requests = {"/warm": 0, "/upload": 4, "/healthy": 8}
        protocol.upload_bytes = 1024
        protocol.selected, protocol.healthy = 4, 8
        protocol.live, protocol.released = True, False
        protocol.resets = {}
        protocol.transmit = lambda: None
        return protocol

    def test_both_remote_cancellation_directions_release_only_the_healthy_stream(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            protocol = self.protocol(directory)
            protocol.receive(StreamReset(error_code=0x10C, stream_id=4))
            self.assertEqual(protocol.http.sent, [])
            protocol.receive(StopSendingReceived(error_code=0x10C, stream_id=4))
            self.assertEqual(protocol.http.sent, [(8, b"healthy", True)])
            self.assertEqual(output.getvalue().strip(), '{"event": "cancelled"}')
            self.assertTrue(protocol.receipt()["healthy_released"])

    def test_wrong_code_unrelated_stream_early_reset_and_connection_close_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            for value in (
                StreamReset(error_code=0x102, stream_id=4),
                StopSendingReceived(error_code=0x10C, stream_id=8),
                ConnectionTerminated(error_code=0, frame_type=None, reason_phrase=""),
            ):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    self.protocol(directory).receive(value)
            protocol = self.protocol(directory)
            protocol.live = False
            with self.assertRaises(ValueError):
                protocol.receive(StreamReset(error_code=0x10C, stream_id=4))

    def test_live_event_requires_uploaded_prefix_and_an_unfinished_sibling(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            protocol = self.protocol(directory)
            protocol.live = False
            protocol.upload_bytes = 0
            protocol.publish_live()
            protocol.upload_bytes = 1024
            protocol.healthy = None
            protocol.publish_live()
            self.assertEqual(output.getvalue(), "")
            protocol.healthy = 8
            protocol.publish_live()
            protocol.publish_live()
            self.assertEqual(output.getvalue().strip(), '{"event": "live"}')

    def test_only_clean_codes_are_allowed_after_controlled_shutdown(self):
        with tempfile.TemporaryDirectory() as directory:
            protocol = self.protocol(directory)
            protocol.owner.stopping = True
            for code in (0, 0x100):
                protocol.receive(
                    ConnectionTerminated(
                        error_code=code, frame_type=None, reason_phrase=""
                    )
                )
            with self.assertRaises(ValueError):
                protocol.receive(
                    ConnectionTerminated(
                        error_code=0x102, frame_type=None, reason_phrase=""
                    )
                )


class CallbackFailureTests(unittest.IsolatedAsyncioTestCase):
    async def test_loop_callback_error_becomes_the_owned_peer_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            owner = Peer(Path(directory))
            error = RuntimeError("independent callback failed")
            loop = asyncio.get_running_loop()
            previous_handler = loop.get_exception_handler()
            try:
                loop.set_exception_handler(owner.callback_failed)
                loop.call_exception_handler({"exception": error})
                self.assertIs(await owner.failure, error)
            finally:
                loop.set_exception_handler(previous_handler)
