import argparse
import asyncio
import contextlib
import dataclasses
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.capture import client_hints
from scripts.capture.tests.test_client_hints import (
    METADATA,
    ScriptedBrowser,
    ScriptedFailures,
    scripted,
)


def complete_run():
    run = client_hints.HintRun("literal-token", ())
    run.first = client_hints.Navigation((b"Host",), ())
    run.second = run.first
    return run


class ClientHintInputControlTest(unittest.IsolatedAsyncioTestCase):
    def test_invalid_non_hint_names_cannot_change_fixture_field_count(self):
        for name in (b"X,Bad", b"", b"Host ", b"X\tBad", b"X\xff"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                client_hints.parse_navigation(
                    b"GET / HTTP/1.1\r\n" + name + b": value\r\n\r\n", ()
                )

        navigation = client_hints.parse_navigation(
            b"GET / HTTP/1.1\r\nHost: x\r\nX-Good: value\r\n\r\n", ()
        )
        self.assertEqual(navigation.field_names, (b"Host", b"X-Good"))

        navigation = client_hints.parse_navigation(
            b"GET / HTTP/1.1\r\nX|Good: ignored\r\nSec-CH-Test: a|b\r\n\r\n", ()
        )
        self.assertEqual(navigation.field_names, (b"X|Good", b"Sec-CH-Test"))
        self.assertEqual(navigation.hints, (("sec-ch-test", b"a|b"),))

        run = complete_run()
        run.first = client_hints.Navigation((b"Host", b"X,Bad"), ())
        with self.assertRaises(ValueError):
            client_hints.fixture([run], METADATA, ())

    def test_metadata_cannot_publish_an_injected_record(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "hints.txt"
            output.write_bytes(b"previous fixture\n")
            for field in dataclasses.fields(METADATA):
                for value in ("Windows\nhint_0=forged", "tab\t", "\x7f", "é"):
                    output.write_bytes(b"previous fixture\n")
                    metadata = dataclasses.replace(METADATA, **{field.name: value})
                    with self.subTest(field=field.name, value=value):
                        with self.assertRaises(ValueError):
                            client_hints.write_text_fixture(
                                output,
                                client_hints.fixture([complete_run()], metadata, ()),
                            )
                        self.assertEqual(output.read_bytes(), b"previous fixture\n")

        metadata = client_hints.CaptureMetadata("", "", "", "", "", "")
        rendered = client_hints.fixture([complete_run()], metadata, ())
        self.assertIn("client=\n", rendered)
        self.assertIn("launch_arguments=\n", rendered)

    async def test_invalid_metadata_is_rejected_before_listener_acquisition(self):
        args = argparse.Namespace(
            repeat=1,
            accept_ch=(),
            run_timeout=5.0,
            listen="127.0.0.1:0",
            browser="manual",
            browser_path=None,
            headful=False,
            browser_switch=[],
            client=None,
            client_version="0",
            operating_system="Windows\nhint_0=forged",
            output=Path("unused.txt"),
        )
        with mock.patch.object(client_hints.HintServer, "start") as start:
            with self.assertRaises(ValueError):
                await client_hints.run(args)
            start.assert_not_called()


class ClientHintPeerControlTest(unittest.IsolatedAsyncioTestCase):
    async def test_failed_protocol_construction_retires_the_actual_accepted_peer(self):
        server = client_hints.HintServer()
        run = client_hints.HintRun("literal-token", ())
        server.run = run
        cause = ValueError("original protocol construction failure")
        protocols = []
        original = server.new_protocol

        def recorded():
            protocol = original()
            protocols.append(protocol)
            return protocol

        server.new_protocol = recorded
        await server.start("127.0.0.1", 0)
        loop = asyncio.get_running_loop()
        prior = loop.get_exception_handler()
        raw_sockets = []

        def failed(_loop, context):
            error = context.get("exception")
            if error is cause:
                trace = error.__traceback__
                while trace is not None:
                    raw = trace.tb_frame.f_locals.get("conn")
                    if raw is not None:
                        raw_sockets.append(raw)
                    trace = trace.tb_next
            else:
                loop.default_exception_handler(context)

        loop.set_exception_handler(failed)
        writer = None
        try:
            with mock.patch.object(client_hints, "_HintProtocol", side_effect=cause):
                reader, writer = await asyncio.open_connection(*server.address)
                await asyncio.wait_for(run.done.wait(), 2.0)
            with self.assertRaises(ValueError) as caught:
                await server.close(cause)
            self.assertIs(caught.exception, cause)
            self.assertIs(run.failure, cause)
            self.assertEqual(await asyncio.wait_for(reader.read(1), 0.2), b"")
            self.assertTrue(protocols)
            self.assertTrue(all(protocol.retired for protocol in protocols))
            self.assertFalse(server.connections)
            self.assertFalse(raw_sockets)
        finally:
            # These backups run only after the independent peer-retirement check.
            for raw in raw_sockets:
                raw.close()
            if writer is not None:
                writer.close()
                with contextlib.suppress(*client_hints.PEER_DISCONNECT):
                    await writer.wait_closed()
            with contextlib.suppress(BaseException):
                await server.close()
            loop.set_exception_handler(prior)

    async def test_scripted_parse_failure_closes_the_actual_client_before_backup(self):
        accepted = asyncio.Event()
        tasks = []
        writers = []
        eof = asyncio.Event()

        async def peer(reader, writer):
            tasks.append(asyncio.current_task())
            writers.append(writer)
            accepted.set()
            await reader.readuntil(b"\r\n\r\n")
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: invalid\r\n\r\n")
            await writer.drain()
            if await reader.read(1) == b"":
                eof.set()
            writer.close()
            await writer.wait_closed()

        listener = await asyncio.start_server(peer, "127.0.0.1", 0)
        host, port = listener.sockets[0].getsockname()[:2]
        browser = ScriptedBrowser(f"http://{host}:{port}/")
        try:
            with self.assertRaises(ValueError):
                await browser.fetch(browser.url, ())
            await asyncio.wait_for(accepted.wait(), 2.0)
            await asyncio.wait_for(eof.wait(), 0.2)
            await asyncio.wait_for(asyncio.gather(*tasks), 2.0)
            self.assertTrue(all(task.done() for task in tasks))
        finally:
            listener.close()
            await listener.wait_closed()
            for writer in writers:
                writer.close()
                with contextlib.suppress(*client_hints.PEER_DISCONNECT):
                    await writer.wait_closed()
            for task in tasks:
                if not task.done():
                    task.cancel("test backup")
            await asyncio.gather(*tasks, return_exceptions=True)

    async def test_scripted_caller_failure_collects_actual_task_and_connection(self):
        for cause in (
            OSError("original caller failure"),
            asyncio.CancelledError("caller"),
        ):
            with self.subTest(cause=type(cause).__name__):
                ready = asyncio.Event()
                eof = asyncio.Event()
                tasks = []
                writers = []

                async def peer(
                    reader,
                    writer,
                    *,
                    tasks=tasks,
                    writers=writers,
                    ready=ready,
                    eof=eof,
                ):
                    tasks.append(asyncio.current_task())
                    writers.append(writer)
                    await reader.readuntil(b"\r\n\r\n")
                    ready.set()
                    if await reader.read(1) == b"":
                        eof.set()
                    writer.close()
                    await writer.wait_closed()

                listener = await asyncio.start_server(peer, "127.0.0.1", 0)
                host, port = listener.sockets[0].getsockname()[:2]
                browser = None
                try:
                    with self.assertRaises(type(cause)) as caught:
                        async with scripted(f"http://{host}:{port}/") as browser:
                            await asyncio.wait_for(ready.wait(), 2.0)
                            raise cause
                    self.assertIs(caught.exception, cause)
                    await asyncio.wait_for(eof.wait(), 0.2)
                    await asyncio.wait_for(asyncio.gather(*tasks), 2.0)
                    self.assertTrue(browser.task.done())
                    self.assertTrue(
                        all(writer.is_closing() for writer in browser.writers)
                    )
                    self.assertTrue(
                        all(waiter.done() for waiter in browser.waiters.values())
                    )
                finally:
                    listener.close()
                    await listener.wait_closed()
                    if browser is not None:
                        for writer in browser.writers:
                            writer.close()
                    for writer in writers:
                        writer.close()
                    for task in tasks:
                        if not task.done():
                            task.cancel("test backup")
                    await asyncio.gather(*tasks, return_exceptions=True)

    async def test_scripted_read_and_close_failures_keep_both_original_causes(self):
        ready = asyncio.Event()
        eof = asyncio.Event()
        tasks = []
        writers = []
        primary = ValueError("original response parse failure")
        prior = OSError("original parse cause")
        primary.__cause__ = prior
        cleanup = OSError("original close failure")

        async def peer(reader, writer):
            tasks.append(asyncio.current_task())
            writers.append(writer)
            await reader.readuntil(b"\r\n\r\n")
            ready.set()
            if await reader.read(1) == b"":
                eof.set()
            writer.close()
            await writer.wait_closed()

        listener = await asyncio.start_server(peer, "127.0.0.1", 0)
        host, port = listener.sockets[0].getsockname()[:2]
        browser = ScriptedBrowser(f"http://{host}:{port}/")
        original = asyncio.open_connection

        async def opened(*args):
            reader, writer = await original(*args)
            close = writer.close

            async def readuntil(_separator):
                await ready.wait()
                raise primary

            def closed():
                close()
                raise cleanup

            reader.readuntil = readuntil
            writer.close = closed
            return reader, writer

        try:
            with (
                mock.patch.object(asyncio, "open_connection", side_effect=opened),
                self.assertRaises(ValueError) as caught,
            ):
                await browser.fetch(browser.url, ())
            self.assertIs(caught.exception, primary)
            self.assertIsInstance(primary.__cause__, ScriptedFailures)
            self.assertIs(primary.__cause__.primary, primary)
            self.assertIs(primary.__cause__.previous_cause, prior)
            self.assertEqual(primary.__cause__.cleanup, (cleanup,))
            self.assertIs(primary.__cause__.browser, browser)
            await asyncio.wait_for(eof.wait(), 0.2)
            await asyncio.wait_for(asyncio.gather(*tasks), 2.0)
            self.assertTrue(all(waiter.done() for waiter in browser.waiters.values()))
        finally:
            listener.close()
            await listener.wait_closed()
            for writer in writers:
                writer.close()
            for task in tasks:
                if not task.done():
                    task.cancel("test backup")
            await asyncio.gather(*tasks, return_exceptions=True)
