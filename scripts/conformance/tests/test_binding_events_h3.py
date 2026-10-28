"""The EventSource peer checks reconnect IDs and a genuinely live sibling."""

import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from aioquic.h3.events import HeadersReceived
from aioquic.quic.events import ConnectionTerminated, StopSendingReceived

from scripts.conformance.binding_events_h3 import EventsProtocol


class HTTP:
    def __init__(self) -> None:
        self.headers = []
        self.data = []

    def send_headers(
        self, stream: int, fields: list, *, end_stream: bool = False
    ) -> None:
        self.headers.append((stream, fields, end_stream))

    def send_data(self, stream: int, data: bytes, *, end_stream: bool) -> None:
        self.data.append((stream, data, end_stream))

    def handle_event(self, value: object) -> list:
        return []


class EventsOracleTests(unittest.TestCase):
    def protocol(self, directory: str, reject: str | None = None) -> EventsProtocol:
        protocol = object.__new__(EventsProtocol)
        protocol.owner = SimpleNamespace(
            protocols=[protocol],
            complete=False,
            directory=Path(directory),
            reject=reject,
        )
        protocol.http = HTTP()
        protocol.requests = []
        protocol.event_requests = 0
        protocol.healthy = None
        protocol.released = False
        protocol.rejected = None
        protocol.cancellations = []
        protocol.transmit = lambda: None
        return protocol

    def request(
        self,
        protocol: EventsProtocol,
        stream: int,
        path: bytes,
        event_id: bytes | None = None,
    ) -> None:
        fields = [
            (b":method", b"GET"),
            (b":path", path),
            (b"accept", b"text/event-stream"),
        ]
        if event_id is not None:
            fields.append((b"last-event-id", event_id))
        protocol.headers(
            HeadersReceived(headers=fields, stream_id=stream, stream_ended=True)
        )

    def test_reconnects_require_committed_ids_and_release_only_live_sibling(
        self,
    ) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            protocol = self.protocol(directory)
            self.request(protocol, 0, b"/events")
            self.assertEqual(
                protocol.http.data, [(0, b"id: 7\nretry: 0\ndata: first\n\n", True)]
            )
            self.request(protocol, 4, b"/healthy")
            self.assertFalse(protocol.released)
            self.assertFalse(any(stream == 4 for stream, _, _ in protocol.http.data))
            self.request(protocol, 8, b"/events", b"7")
            self.assertFalse(protocol.released)
            self.request(protocol, 12, b"/events", b"9")
            self.assertEqual(
                protocol.http.headers[-1],
                (
                    12,
                    [(b":status", b"204"), (b"content-type", b"text/event-stream")],
                    True,
                ),
            )
            self.assertEqual(protocol.http.data[-1], (4, b"healthy", True))
            self.request(protocol, 16, b"/reuse")
            receipt = json.loads((Path(directory) / "result.json").read_text())
            self.assertEqual(receipt["connections"], 1)
            self.assertEqual(
                [item["stream"] for item in receipt["requests"]], [0, 4, 8, 12, 16]
            )
            self.assertTrue(receipt["healthy_released"])

    def test_initial_and_reconnect_rejections_do_not_require_cancelling_a_sibling(
        self,
    ) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            for reject in ("initial", "reconnect"):
                protocol = self.protocol(directory, reject)
                self.request(protocol, 0, b"/events")
                if reject == "reconnect":
                    self.request(protocol, 4, b"/events", b"7")
                self.assertEqual(protocol.http.headers[-1][1][0], (b":status", b"403"))
                self.assertEqual(protocol.http.data[-1][1], b"private")
                self.request(protocol, 8, b"/reuse")
                self.assertTrue(protocol.owner.complete)
                self.assertFalse(protocol.released)

    def test_wrong_id_duplicate_stream_and_out_of_order_request_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            for stream, path, event_id in ((0, b"/reuse", None), (0, b"/events", b"7")):
                with (
                    self.subTest(path=path, event_id=event_id),
                    self.assertRaises(ValueError),
                ):
                    self.request(self.protocol(directory), stream, path, event_id)
            protocol = self.protocol(directory)
            self.request(protocol, 0, b"/events")
            with self.assertRaises(ValueError):
                self.request(protocol, 0, b"/healthy")

    def test_sibling_cancellation_and_early_connection_close_are_not_success(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            for value in (
                StopSendingReceived(error_code=0x10C, stream_id=4),
                ConnectionTerminated(error_code=0, frame_type=None, reason_phrase=""),
            ):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    self.protocol(directory).receive(value)


class StopCommandProcessTests(unittest.TestCase):
    def test_deadline_and_failure_exit_with_stdin_still_open(self) -> None:
        for fail in (False, True):
            program = f"""import asyncio
from scripts.conformance.binding_events_h3 import stop_command
async def run():
    command = stop_command()
    if {fail!r}:
        await asyncio.sleep(0.05)
        raise RuntimeError("controlled peer failure")
    try:
        await asyncio.wait_for(command, 0.05)
    except asyncio.TimeoutError:
        print("expired", flush=True)
asyncio.run(run())
"""
            with self.subTest(fail=fail):
                output, error, code = self.child(program)
                self.assertEqual(code, 1 if fail else 0, error.decode())
                if fail:
                    self.assertIn(b"controlled peer failure", error)
                else:
                    self.assertEqual(output, b"expired\n")
                    self.assertEqual(error, b"")

    def test_stop_command_is_accepted_without_waiting_for_stdin_eof(self) -> None:
        program = """import asyncio
from scripts.conformance.binding_events_h3 import stop_command
async def run():
    print(repr(await stop_command()), flush=True)
asyncio.run(run())
"""
        output, error, code = self.child(program, b"stop\n")
        self.assertEqual(code, 0, error.decode())
        self.assertEqual(output, b"'stop\\n'\n")
        self.assertEqual(error, b"")

    def child(
        self, program: str, command: bytes | None = None
    ) -> tuple[bytes, bytes, int]:
        process = subprocess.Popen(
            [sys.executable, "-c", program],
            cwd=Path(__file__).resolve().parents[3],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            if command is not None:
                process.stdin.write(command)
                process.stdin.flush()
            # Keep stdin open until the child exits: closing it would hide the bug.
            process.wait(timeout=5)
        finally:
            if process.poll() is None:
                process.kill()
            process.stdin.close()
            process.stdin = None
            output, error = process.communicate(timeout=5)
        return output.replace(b"\r\n", b"\n"), error, process.returncode
