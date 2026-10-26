import argparse
import asyncio
import dataclasses
import io
import math
import tempfile
import unittest
from contextlib import asynccontextmanager, redirect_stderr
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

from scripts.capture import sse_reconnect as capture
from scripts.capture.tests.test_sse_reconnect import METADATA, driver, quick


def arguments(output: Path, **overrides) -> argparse.Namespace:
    values = {
        "browser": "manual",
        "browser_path": None,
        "headful": False,
        "client": "scripted client",
        "client_version": "0",
        "operating_system": "test",
        "listen": "127.0.0.1:0",
        "scenario": ["reconnect-204"],
        "repeat": 1,
        "run_timeout": 2.0,
        "output_dir": output,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


class CompletionTests(unittest.IsolatedAsyncioTestCase):
    async def test_completed_response_failure_refuses_publication(self) -> None:
        primary = ValueError("terminal response failed after its bytes were sent")
        original = capture.ReconnectServer.respond

        async def respond(server, run, request, reader, writer):
            result = await original(server, run, request, reader, writer)
            if request.attempt == 1:
                raise primary
            return result

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "fixtures"
            scenario = quick(capture.SCENARIOS["reconnect-204"])
            with (
                patch.object(capture.ReconnectServer, "respond", respond),
                patch.object(capture, "SCENARIOS", {scenario.name: scenario}),
                patch.object(
                    capture, "BrowserDriver", lambda _plan, url: driver()(url)
                ),
                self.assertRaises(ValueError) as raised,
            ):
                await capture.run(arguments(output))

            self.assertIs(raised.exception, primary)
            self.assertFalse((output / "reconnect-204.txt").exists())

    async def test_ipv6_url_has_a_bracketed_authority(self) -> None:
        server = capture.ReconnectServer()
        server.address = ("::1", 43210)
        run = capture.ScenarioRun(capture.SCENARIOS["reconnect-204"], "literal")

        url = server.url(run)

        self.assertEqual(url, "http://[::1]:43210/run/literal")
        self.assertEqual(urlsplit(url).hostname, "::1")
        self.assertEqual(urlsplit(url).port, 43210)

    async def test_invalid_timeout_and_metadata_fail_before_listener_acquisition(self):
        cases = [{"run_timeout": value} for value in (0.0, -1.0, math.nan, math.inf)]
        cases.extend(
            {field: value}
            for field in ("client", "client_version", "operating_system")
            for value in ("line\nformat=other", "line\rnext", "nonascii-é", "nul\0")
        )
        cases.append({"repeat": 0})
        cases.extend(
            {"listen": value}
            for value in ("192.0.2.1:0", "[::1]:65536", "127.0.0.1:-1", "bad:0")
        )
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                with (
                    patch.object(
                        capture.ReconnectServer,
                        "start",
                        side_effect=AssertionError("listener was acquired"),
                    ) as start,
                    self.assertRaises(ValueError),
                ):
                    await capture.run(arguments(Path(directory), **case))
                start.assert_not_called()

    def test_fixture_rejects_literal_schema_metadata_injection(self) -> None:
        scenario = capture.SCENARIOS["reconnect-204"]
        for value in ("x\nformat=other", "x\rnext", "nonascii-é", "x\0"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                metadata = dataclasses.replace(METADATA, client_version=value)
                capture.fixture(scenario, [], metadata)

    def test_cli_rejects_literal_invalid_limits_and_schema_fields_before_run(self):
        cases = (
            ("--run-timeout", "nan"),
            ("--run-timeout", "inf"),
            ("--run-timeout", "0"),
            ("--repeat", "0"),
            ("--client", "name\nformat=other"),
            ("--client-version", "é"),
            ("--operating-system", "test\0"),
            ("--listen", "[::1]:65536"),
        )
        for option, value in cases:
            with (
                self.subTest(option=option, value=value),
                patch.object(capture.asyncio, "run") as run,
                redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as raised,
            ):
                capture.main(
                    [
                        "--browser",
                        "manual",
                        "--client-version",
                        "0",
                        "--output-dir",
                        "unused",
                        option,
                        value,
                    ]
                )
            self.assertEqual(raised.exception.code, 2)
            run.assert_not_called()

    async def test_ipv6_run_passes_a_bracketed_url_and_retains_the_authority(self):
        urls = []
        scenario = quick(capture.SCENARIOS["reconnect-204"])

        def drive(_plan, url):
            urls.append(url)
            return driver()(url)

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            with (
                patch.object(capture, "SCENARIOS", {scenario.name: scenario}),
                patch.object(capture, "BrowserDriver", drive),
            ):
                await capture.run(arguments(output, listen="::1:0"))

            [url] = urls
            self.assertTrue(url.startswith("http://[::1]:"))
            self.assertEqual(urlsplit(url).hostname, "::1")
            fields = dict(
                line.split("=", 1)
                for line in (output / "reconnect-204.txt").read_text().splitlines()
            )
            self.assertEqual(fields["listen_address"], urlsplit(url).netloc)
            self.assertEqual(fields["client_version"], "0")
            self.assertEqual(fields["repeat_count"], "1")

    async def test_malformed_request_failure_is_collected_from_the_actual_server(self):
        server = capture.ReconnectServer()
        await server.start("127.0.0.1", 0)
        clients = []

        @asynccontextmanager
        async def drive(url):
            address = urlsplit(url)
            reader, writer = await asyncio.open_connection(
                address.hostname, address.port
            )
            clients.append(writer)
            writer.write(b"GET http://[ HTTP/1.1\r\nHost: literal\r\n\r\n")
            await writer.drain()
            yield
            self.assertEqual(await reader.read(), b"")

        try:
            with self.assertRaisesRegex(ValueError, "Invalid IPv6 URL"):
                await capture.capture_scenario(
                    server,
                    quick(capture.SCENARIOS["reconnect-204"]),
                    repeat=1,
                    run_timeout=2.0,
                    drive=drive,
                )
            self.assertFalse(server.tasks)
            self.assertFalse(server.writers)
        finally:
            for writer in clients:
                writer.close()
                await writer.wait_closed()
            await server.close()

    async def test_body_and_writer_cleanup_errors_survive_sibling_completion(self):
        server = capture.ReconnectServer()
        await server.start("127.0.0.1", 0)
        primary = LookupError("scripted driver body failed")
        previous = OSError("earlier driver cause")
        context = RuntimeError("earlier driver context")
        primary.__cause__, primary.__context__ = previous, context
        cleanup = PermissionError("accepted writer closure failed once")
        accepted = asyncio.Event()
        sibling_accepted = asyncio.Event()
        original_respond = server.respond
        original_wait = asyncio.StreamWriter.wait_closed
        failing_writer = None
        sibling_writer = None
        failed_once = False
        clients = []

        async def respond(run, request, reader, writer):
            nonlocal failing_writer, sibling_writer
            if failing_writer is None:
                failing_writer = writer
            else:
                sibling_writer = writer
                sibling_accepted.set()
            result = await original_respond(run, request, reader, writer)
            accepted.set()
            return result

        async def wait_closed(writer):
            nonlocal failed_once
            if writer is failing_writer and not failed_once:
                failed_once = True
                raise cleanup
            await original_wait(writer)

        @asynccontextmanager
        async def drive(url):
            nonlocal sibling_writer
            address = urlsplit(url)
            reader, writer = await asyncio.open_connection(
                address.hostname, address.port
            )
            clients.append(writer)
            writer.write(
                f"GET {address.path} HTTP/1.1\r\nHost: literal\r\n\r\n".encode()
            )
            await writer.drain()
            await asyncio.wait_for(accepted.wait(), timeout=5.0)

            other_reader, other_writer = await asyncio.open_connection(
                address.hostname, address.port
            )
            clients.append(other_writer)
            other_writer.write(
                f"GET {address.path} HTTP/1.1\r\nHost: sibling\r\n\r\n".encode()
            )
            await other_writer.drain()
            await asyncio.wait_for(sibling_accepted.wait(), timeout=5.0)
            server.run.done.set()
            yield
            raise primary

        try:
            with (
                patch.object(server, "respond", respond),
                patch.object(asyncio.StreamWriter, "wait_closed", wait_closed),
                self.assertRaises(LookupError) as raised,
            ):
                await capture.capture_scenario(
                    server,
                    quick(capture.SCENARIOS["reconnect-204"]),
                    repeat=1,
                    run_timeout=2.0,
                    drive=drive,
                )

            self.assertIs(raised.exception, primary)
            self.assertIs(primary.__cause__.owner, server)
            self.assertIs(primary.__cause__.failures[0], cleanup)
            self.assertIsInstance(primary.__cause__, RuntimeError)
            self.assertIs(primary.__cause__.previous_cause, previous)
            self.assertIs(primary.__cause__.previous_context, context)
            self.assertFalse(server.tasks)
            self.assertNotIn(sibling_writer, server.writers)
            self.assertIn(failing_writer, server.writers)
            self.assertTrue(sibling_writer.is_closing())

            with self.assertRaises(PermissionError) as retried:
                await server.finish_run()
            self.assertIs(retried.exception, cleanup)
            self.assertFalse(server.writers)
            self.assertFalse(server.writer_tasks)
        finally:
            for writer in clients:
                writer.close()
                await writer.wait_closed()
            await server.close()

    async def test_interrupted_cleanup_keeps_the_actual_worker_for_retry(self):
        server = capture.ReconnectServer()
        await server.start("127.0.0.1", 0)
        server.run = capture.ScenarioRun(capture.SCENARIOS["reconnect-204"], "literal")
        entered = asyncio.Event()
        cancelling = asyncio.Event()
        release = asyncio.Event()
        interruptions = []
        original = server.respond

        async def close_run():
            try:
                await server.finish_run()
            except asyncio.CancelledError as error:
                interruptions.append(error)
                raise

        async def respond(run, request, reader, writer):
            await original(run, request, reader, writer)
            entered.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                cancelling.set()
                await release.wait()
            return False

        reader, writer = await asyncio.open_connection(*server.address)
        try:
            with patch.object(server, "respond", respond):
                writer.write(b"GET /run/literal HTTP/1.1\r\nHost: literal\r\n\r\n")
                await writer.drain()
                await asyncio.wait_for(entered.wait(), timeout=5.0)
                worker = next(iter(server.tasks))
                closing = asyncio.create_task(close_run())
                await asyncio.wait_for(cancelling.wait(), timeout=5.0)
                closing.cancel("caller interrupted cleanup")
                with self.assertRaises(asyncio.CancelledError) as raised:
                    await closing

                [interruption] = interruptions
                self.assertTrue(
                    raised.exception is interruption
                    or raised.exception.__context__ is interruption
                )
                self.assertIs(interruption.__cause__.owner, server)
                self.assertIn(worker, server.tasks)
                self.assertFalse(worker.done())
                self.assertIsNotNone(server.cleanup)
                self.assertFalse(server.cleanup.done())

                release.set()
                await server.finish_run()
                self.assertTrue(worker.done())
                self.assertFalse(server.tasks)
                self.assertFalse(server.writers)
                self.assertIsNone(server.cleanup)
                self.assertIn(b"HTTP/1.1 200 OK", await reader.read())
        finally:
            release.set()
            writer.close()
            await writer.wait_closed()
            await server.close()

    async def test_owned_worker_cancellation_does_not_hide_its_close_failure(self):
        server = capture.ReconnectServer()
        await server.start("127.0.0.1", 0)
        server.run = capture.ScenarioRun(capture.SCENARIOS["reconnect-204"], "literal")
        entered = asyncio.Event()
        original_respond = server.respond
        original_close = asyncio.StreamWriter.close
        cleanup = PermissionError("worker final writer close failed")
        accepted_writer = None
        close_count = 0

        async def respond(run, request, reader, writer):
            nonlocal accepted_writer
            accepted_writer = writer
            await original_respond(run, request, reader, writer)
            entered.set()
            await asyncio.Future()

        def close(writer):
            nonlocal close_count
            original_close(writer)
            if writer is accepted_writer:
                close_count += 1
                if close_count == 2:
                    raise cleanup

        reader, writer = await asyncio.open_connection(*server.address)
        try:
            with (
                patch.object(server, "respond", respond),
                patch.object(asyncio.StreamWriter, "close", close),
            ):
                writer.write(b"GET /run/literal HTTP/1.1\r\nHost: literal\r\n\r\n")
                await writer.drain()
                await asyncio.wait_for(entered.wait(), timeout=5.0)
                with self.assertRaises(PermissionError) as raised:
                    await server.finish_run()

            self.assertIs(raised.exception, cleanup)
            self.assertFalse(server.tasks)
            self.assertFalse(server.writers)
            self.assertIn(b"HTTP/1.1 200 OK", await reader.read())
        finally:
            writer.close()
            await writer.wait_closed()
            await server.close()


if __name__ == "__main__":
    unittest.main()
