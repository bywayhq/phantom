import argparse
import asyncio
import contextlib
import io
import ssl
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, StreamEnded

from scripts.capture import http2_preface_ping as preface
from scripts.capture.http2_preface_ping import (
    FORMAT,
    FrameLog,
    PrefaceServer,
    page,
    request_path,
)
from scripts.capture.http2_session import CONNECTION_PREFACE

FIXTURE = (
    Path(__file__).resolve().parents[3]
    / "fixtures/http2/chrome/154.0.8037.58/windows-11-26200/preface-ping.txt"
)


def frame(kind: int, flags: int, stream: int, payload: bytes) -> bytes:
    return (
        len(payload).to_bytes(3, "big")
        + bytes([kind, flags])
        + stream.to_bytes(4, "big")
        + payload
    )


class FrameLogTests(unittest.TestCase):
    def test_splits_frames_across_reads_and_keeps_only_ping_payloads(self) -> None:
        data = (
            CONNECTION_PREFACE
            + frame(0x1, 0x25, 5, b"\x82\x84")
            + frame(0x6, 0x0, 0, (1).to_bytes(8, "big"))
            + frame(0x0, 0x1, 5, b"x" * 100)
        )
        log = FrameLog()
        log.feed(data[:30], 1.0)
        log.feed(data[30:], 2.5)
        log.name_request(5, "/b")
        self.assertEqual(
            [item.line() for item in log.frames],
            [
                "ms:2.500,type:HEADERS,flags:0x25,stream:5,length:2,path:/b",
                "ms:2.500,type:PING,flags:0x00,stream:0,length:8,"
                "payload:0000000000000001",
                "ms:2.500,type:DATA,flags:0x01,stream:5,length:100",
            ],
        )

    def test_rejects_an_invalid_preface(self) -> None:
        with self.assertRaises(ValueError):
            FrameLog().feed(b"GET / HTTP/1.1\r\n\r\n" + b"x" * 16, 0.0)

    def test_request_path_drops_the_run_token(self) -> None:
        self.assertEqual(request_path(b"/b?run=0123"), "/b")

    def test_page_waits_the_configured_times(self) -> None:
        body = page("token", 11.5, 9.0).decode()
        self.assertIn("await wait(11500);", body)
        self.assertIn("await wait(9000);", body)
        self.assertIn("method: 'POST'", body)

    def test_frame_extent_is_rejected_before_waiting_for_payload(self) -> None:
        log = FrameLog()
        with self.assertRaisesRegex(ValueError, "frame exceeds"):
            log.feed(CONNECTION_PREFACE + b"\x00\x40\x01\x00\x00\x00\x00\x00\x01", 0)
        self.assertFalse(log.frames)

    def test_frame_count_is_bounded(self) -> None:
        log = FrameLog()
        log.feed(CONNECTION_PREFACE + frame(6, 0, 0, b"12345678") * 200, 0)
        self.assertEqual(len(log.frames), 200)
        with self.assertRaisesRegex(ValueError, "frame limit"):
            log.feed(frame(6, 0, 0, b"12345678"), 0)

    def test_invalid_durations_fail_before_certificate_or_browser_acquisition(self):
        for idle, short in (
            (float("nan"), 1),
            (1, float("inf")),
            (-1, 1),
            (1, 0),
            (1e300, 1),
        ):
            args = argparse.Namespace(listen="127.0.0.1", idle=idle, short=short)
            with (
                self.subTest(idle=idle, short=short),
                mock.patch.object(preface, "generate_certificate") as certificate,
                mock.patch.object(preface, "BrowserDriver") as browser,
            ):
                with self.assertRaises(ValueError):
                    asyncio.run(preface.capture(args))
                certificate.assert_not_called()
                browser.assert_not_called()

    def test_cli_rejects_nonfinite_waits_and_ipv6_mapping_uses_brackets(self):
        arguments = [
            "--browser",
            "chrome",
            "--browser-path",
            "chrome.exe",
            "--client-version",
            "0",
            "--output-dir",
            "unused",
        ]
        with (
            mock.patch.object(preface, "capture") as capture,
            contextlib.redirect_stderr(io.StringIO()),
        ):
            with self.assertRaises(SystemExit) as raised:
                preface.main([*arguments, "--idle", "nan"])
            self.assertEqual(raised.exception.code, 2)
            capture.assert_not_called()
        self.assertEqual(preface.resolver_address("::1"), "[::1]")
        self.assertEqual(preface.resolver_address("127.0.0.1"), "127.0.0.1")


class RetainedFixtureTests(unittest.TestCase):
    def test_fixture_holds_no_request_token_or_certificate(self) -> None:
        text = FIXTURE.read_text(encoding="ascii")
        values = dict(line.split("=", 1) for line in text.splitlines())
        self.assertEqual(values["format"], FORMAT)
        self.assertIn("<token>", values["launch_arguments"])
        self.assertIn("<certificate-spki>", values["launch_arguments"])
        frames = [value for key, value in values.items() if key.startswith("frame_")]
        self.assertEqual(len(frames) - 1, int(values["frame_count"]))


class PrefaceOwnershipTests(unittest.IsolatedAsyncioTestCase):
    def owner(self, run=None, context=None):
        if run is None:
            run = preface.Run("token", 11.5, 9.0)
        if context is None:
            context = preface.server_context(preface.generate_certificate())
        owner = PrefaceServer(run, context)
        protocols = []
        original = owner.new_protocol

        def created():
            protocol = original()
            protocols.append(protocol)
            return protocol

        owner.new_protocol = created
        self.addAsyncCleanup(owner.close)
        return owner, protocols

    async def peer(self, owner, *, tls=True):
        context = None
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.set_alpn_protocols(["h2"])
        reader, writer = await asyncio.open_connection(
            "127.0.0.1",
            owner.port,
            ssl=context,
            server_hostname=preface.HOSTNAME if tls else None,
        )

        async def close():
            writer.close()
            with contextlib.suppress(*preface.PEER_DISCONNECT):
                await asyncio.wait_for(writer.wait_closed(), 2)

        self.addAsyncCleanup(close)
        return reader, writer

    async def eof(self, reader):
        try:
            data = await asyncio.wait_for(reader.read(), 2)
        except preface.PEER_DISCONNECT:
            return
        self.assertTrue(reader.at_eof(), "native peer did not reach EOF")
        return data

    def retired(self, owner, protocols):
        self.assertTrue(protocols)
        for protocol in protocols:
            self.assertTrue(protocol.retired)
            self.assertTrue(protocol.waiter.done())
            if protocol.handler is not None:
                self.assertTrue(protocol.handler.done())
        self.assertFalse(owner.protocols)
        self.assertTrue(owner.listener_wait.done())

    async def stop_operation(self, operation):
        if operation.done():
            return
        operation.cancel("test backup")
        with contextlib.suppress(asyncio.CancelledError):
            await asyncio.wait_for(operation, 2)

    async def test_original_tls_callback_error_prevents_fixture_publication(self):
        owners = []
        failures = []
        feed = FrameLog.feed

        def observed(log, data, milliseconds):
            try:
                return feed(log, data, milliseconds)
            except ValueError as error:
                failures.append(error)
                raise

        def created(run, context):
            owner, protocols = self.owner(run, context)
            owners.append((owner, protocols))
            return owner

        @contextlib.asynccontextmanager
        async def drive(_plan, _url):
            owner, protocols = owners[0]
            reader, writer = await self.peer(owner)
            writer.write(b"GET / HTTP/1.1\r\n\r\n" + b"x" * 16)
            await writer.drain()
            try:
                yield
            finally:
                await self.eof(reader)
                self.assertIs(owner.run.failure, failures[0])
                self.assertTrue(protocols[0].handler.done())

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "preface-ping.txt"
            output.write_bytes(b"previous fixture\n")
            args = argparse.Namespace(
                listen="127.0.0.1",
                idle=11.5,
                short=9.0,
                browser="chrome",
                browser_path=Path("unused"),
                headful=False,
                client=None,
                client_version="0",
                operating_system="test",
                output_dir=Path(directory),
            )
            with (
                mock.patch.object(preface, "PrefaceServer", side_effect=created),
                mock.patch.object(preface, "BrowserDriver", side_effect=drive),
                mock.patch.object(FrameLog, "feed", observed),
                mock.patch.object(preface, "write_text_fixture") as publish,
            ):
                operation = asyncio.create_task(preface.capture(args))
                self.addAsyncCleanup(self.stop_operation, operation)
                done, _ = await asyncio.wait({operation}, timeout=2)
                self.assertIn(operation, done, "callback did not wake capture")
                with self.assertRaises(ValueError) as raised:
                    operation.result()
                self.assertIs(raised.exception, failures[0])
                publish.assert_not_called()
                self.assertEqual(output.read_bytes(), b"previous fixture\n")
            self.retired(*owners[0])

    async def test_failed_worker_submission_retires_accepted_plain_socket(self):
        owner, protocols = self.owner()
        await owner.start("127.0.0.1")
        failure = RuntimeError("worker submission failed")
        original = asyncio.create_task

        def submitted(operation, *args, **kwargs):
            if operation.cr_code.co_name == "handle":
                raise failure
            return original(operation, *args, **kwargs)

        with mock.patch.object(preface.asyncio, "create_task", submitted):
            reader, _writer = await self.peer(owner, tls=False)
            await asyncio.wait_for(owner.run.done.wait(), 2)
            self.assertIs(owner.run.failure, failure)
            self.assertIsNone(protocols[0].handler)
            with self.assertRaises(RuntimeError) as raised:
                await owner.close(failure)
            self.assertIs(raised.exception, failure)
            await self.eof(reader)
        self.retired(owner, protocols)

    async def test_pending_external_worker_cancellation_keeps_original_payload(self):
        owner, protocols = self.owner()
        await owner.start("127.0.0.1")
        original = preface.serve
        reading = asyncio.Event()
        cancellations = []

        async def observed(*args):
            reading.set()
            try:
                return await original(*args)
            except asyncio.CancelledError as error:
                cancellations.append(error)
                raise

        with mock.patch.object(preface, "serve", observed):
            reader, _writer = await self.peer(owner)
            await asyncio.wait_for(reading.wait(), 2)
            close_failure = RuntimeError("writer closure failed before retirement")
            with mock.patch.object(
                protocols[0].writer, "close", side_effect=close_failure
            ):
                protocols[0].handler.cancel("external pending worker")
                await asyncio.wait_for(owner.run.done.wait(), 2)
                self.assertIs(owner.run.failure, cancellations[0])
                self.assertEqual(owner.run.failure.args, ("external pending worker",))
                self.assertTrue(protocols[0].handler.done())
                self.assertFalse(protocols[0].transport.is_closing())
                with self.assertRaises(asyncio.CancelledError) as raised:
                    await owner.close(owner.run.failure)
                self.assertIs(raised.exception, cancellations[0])
                self.assertIsInstance(
                    raised.exception.__cause__, preface.PrefaceFailures
                )
                self.assertIn(close_failure, raised.exception.__cause__.cleanup)
                self.assertIs(raised.exception.__cause__.owner, owner)
            await self.eof(reader)
        self.retired(owner, protocols)

    async def request(self, connection, reader, writer, target):
        stream = connection.get_next_available_stream_id()
        connection.send_headers(
            stream,
            [
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", preface.HOSTNAME.encode()),
                (b":path", target),
            ],
            end_stream=True,
        )
        writer.write(connection.data_to_send())
        await writer.drain()
        body = bytearray()
        while True:
            data = await asyncio.wait_for(reader.read(65536), 2)
            self.assertTrue(data, "peer closed before the response completed")
            events = connection.receive_data(data)
            for event in events:
                if isinstance(event, DataReceived) and event.stream_id == stream:
                    body.extend(event.data)
            writer.write(connection.data_to_send())
            await writer.drain()
            if any(
                isinstance(event, StreamEnded) and event.stream_id == stream
                for event in events
            ):
                return bytes(body)

    async def test_completion_requires_selected_connection_and_exact_run_token(self):
        owner, protocols = self.owner()
        await owner.start("127.0.0.1")
        reader, writer = await self.peer(owner)
        connection = H2Connection(H2Configuration(client_side=True))
        connection.initiate_connection()
        self.assertEqual(
            await self.request(connection, reader, writer, b"/start?run=wrong"), b"ok"
        )
        self.assertIsNone(owner.run.page_connection)
        body = await self.request(connection, reader, writer, b"/start?run=token")
        self.assertIn(b"await wait(11500);", body)
        for target in (
            b"/done",
            b"/done?run=wrong",
            b"/done?run=token&run=token",
            b"/done?run=token&run=",
            b"/done?run=token#",
        ):
            await self.request(connection, reader, writer, target)
            self.assertIsNone(owner.run.completion)
            self.assertFalse(owner.run.done.is_set())
        other_reader, other_writer = await self.peer(owner)
        other = H2Connection(H2Configuration(client_side=True))
        other.initiate_connection()
        await self.request(other, other_reader, other_writer, b"/done?run=token")
        self.assertIsNone(owner.run.completion)
        await self.request(connection, reader, writer, b"/done?run=token")
        self.assertIsNotNone(owner.run.completion)
        await asyncio.wait_for(owner.run.done.wait(), 2)
        self.assertIsNone(owner.run.failure)
        await owner.close()
        self.assertTrue(owner.run.completion.cancelled())
        await self.eof(reader)
        await self.eof(other_reader)
        self.retired(owner, protocols)

    async def test_aggregate_byte_limit_reaches_actual_tls_capture(self):
        owner, protocols = self.owner()
        await owner.start("127.0.0.1")
        failures = []
        original = owner.run.retain

        def retained(size):
            try:
                original(size)
            except ValueError as error:
                failures.append(error)
                raise

        with (
            mock.patch.object(preface, "MAX_CAPTURE_BYTES", 1024),
            mock.patch.object(owner.run, "retain", side_effect=retained),
        ):
            reader, writer = await self.peer(owner)
            connection = H2Connection(H2Configuration(client_side=True))
            connection.initiate_connection()
            connection.send_headers(
                1,
                [
                    (b":method", b"POST"),
                    (b":scheme", b"https"),
                    (b":authority", preface.HOSTNAME.encode()),
                    (b":path", b"/p?run=token"),
                ],
            )
            connection.send_data(1, b"x" * 2048, end_stream=True)
            writer.write(connection.data_to_send())
            await writer.drain()
            await asyncio.wait_for(owner.run.done.wait(), 2)
            self.assertEqual(len(failures), 1)
            self.assertIs(owner.run.failure, failures[0])
            self.assertTrue(protocols[0].handler.done())
            self.assertLessEqual(owner.run.retained, 1024)
            with self.assertRaises(ValueError) as raised:
                await owner.close(owner.run.failure)
            self.assertIs(raised.exception, failures[0])
            await self.eof(reader)
        self.retired(owner, protocols)

    async def test_cleanup_cancellation_preserves_original_parser_failure(self):
        owner, protocols = self.owner()
        await owner.start("127.0.0.1")
        lost = asyncio.Event()
        callbacks = []
        connection_lost = preface.PrefaceProtocol.connection_lost

        def held(protocol, error):
            callbacks.append((protocol, error))
            lost.set()

        with mock.patch.object(preface.PrefaceProtocol, "connection_lost", held):
            reader, writer = await self.peer(owner)
            writer.write(b"GET / HTTP/1.1\r\n\r\n" + b"x" * 16)
            await writer.drain()
            await asyncio.wait_for(owner.run.done.wait(), 2)
            primary = owner.run.failure
            self.assertIsInstance(primary, ValueError)
            await asyncio.wait_for(lost.wait(), 2)
            entered = asyncio.Event()
            interruptions = []
            outcomes = []
            wait = asyncio.wait

            async def finish():
                try:
                    await owner.close(primary)
                except BaseException as error:
                    outcomes.append(error)
                    raise

            async def observed(*args, **kwargs):
                entered.set()
                try:
                    return await wait(*args, **kwargs)
                except asyncio.CancelledError as error:
                    interruptions.append(error)
                    raise

            with mock.patch.object(preface.asyncio, "wait", side_effect=observed):
                cleanup = asyncio.create_task(finish())
                self.addAsyncCleanup(self.stop_operation, cleanup)
                await asyncio.wait_for(entered.wait(), 2)
                cleanup.cancel("cancel during native retirement")
                await asyncio.sleep(0)
                for protocol, error in callbacks:
                    connection_lost(protocol, error)
                with self.assertRaises(asyncio.CancelledError):
                    await cleanup
            self.assertTrue(cleanup.cancelled())
            self.assertEqual(len(interruptions), 1)
            self.assertEqual(len(outcomes), 1)
            self.assertIs(outcomes[0], interruptions[0])
            self.assertEqual(outcomes[0].args, ("cancel during native retirement",))
            group = outcomes[0].__cause__
            self.assertIsInstance(group, preface.PrefaceFailures)
            self.assertIs(group.primary, primary)
            self.assertIs(group.owner, owner)
            self.assertIn(outcomes[0], group.cleanup)
            await self.eof(reader)
        self.retired(owner, protocols)


if __name__ == "__main__":
    unittest.main()
