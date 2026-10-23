import asyncio
import json
import ssl
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.capture import firefox_socket_hooks as hooks
from scripts.capture.browser_failures import BrowserLaunchFailures


class DropFailureTests(unittest.IsolatedAsyncioTestCase):
    async def test_target_close_failure_prevents_drop_acknowledgement(self) -> None:
        origin = hooks.Origins(hooks.SCENARIOS["h2-backup"])
        listener = await asyncio.start_server(origin.accept_page, "127.0.0.1", 0)
        origin.listeners.append(listener)
        self.addAsyncCleanup(origin.shutdown)
        close_started = asyncio.Event()
        release = asyncio.Event()
        cause = ssl.SSLError("independent target shutdown failure")

        class Target:
            def close(self) -> None:
                close_started.set()

        target = Target()
        connection = hooks.ServerConnection("127.0.0.1:1", hooks.now_ms())
        origin.open.append((connection, target))

        async def peer() -> None:
            await close_started.wait()
            await release.wait()
            origin.open.remove((connection, target))
            raise cause

        task = asyncio.create_task(peer())
        origin.peers[task] = (target, False)
        task.add_done_callback(origin.completed)
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", listener.sockets[0].getsockname()[1]
        )
        try:
            writer.write(b"GET /drop HTTP/1.1\r\nHost: localhost\r\n\r\n")
            await writer.drain()
            await asyncio.wait_for(close_started.wait(), 2)
            release.set()
            self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"")
            self.assertIn(cause, origin.failures)
            self.assertEqual(connection.close_kind, "server")
        finally:
            release.set()
            writer.close()
            await writer.wait_closed()
            await asyncio.gather(task, return_exceptions=True)


class FailureReportTests(unittest.IsolatedAsyncioTestCase):
    async def test_raw_report_keeps_partial_hooks_peers_and_both_error_causes(
        self,
    ) -> None:
        owner = hooks._FirefoxRun(hooks.SCENARIOS["h2-backup"])
        read_error = ssl.SSLError("independent TLS read failure")
        close_error = ssl.SSLError("independent TLS close failure")
        primary = BrowserLaunchFailures(read_error, (close_error,))
        agent = hooks.Hooks(123, {})
        report = {"kind": "connect", "time_ms": 100, "socket": "0x123"}
        agent.reports.append(report)
        agent.failure = primary
        owner.native = SimpleNamespace(hooks=agent, failures=[primary])
        owner.origins.failures.append(primary)
        connection = hooks.ServerConnection("127.0.0.1:42", 100)
        connection.requests.append((101, "/fast?i=0"))
        owner.origins.connections.append(connection)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "raw" / "failed.json"
            hooks.write_failure_report(path, owner, primary, (close_error,))
            result = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(result["reports"], [report])
        self.assertEqual(result["connections"][0]["requests"], [[101, "/fast?i=0"]])
        self.assertEqual(result["primary"]["id"], id(primary))
        self.assertEqual(result["primary"]["primary"], repr(read_error))
        self.assertEqual(result["primary"]["primary_id"], id(read_error))
        self.assertEqual(result["primary"]["cleanup"], [repr(close_error)])
        self.assertEqual(result["primary"]["cleanup_ids"], [id(close_error)])
        self.assertEqual(result["cleanup"][0]["id"], id(close_error))
        self.assertEqual(result["origin_failures"][0]["id"], id(primary))
        self.assertFalse(result["done"])

    async def test_run_failure_writes_raw_diagnostics_and_preserves_the_original(
        self,
    ) -> None:
        cause = OSError("independent launch failure")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "failed.json"
            with (
                patch.object(hooks, "_FirefoxNative", side_effect=cause),
                self.assertRaises(OSError) as observed,
            ):
                await hooks.run_once(
                    hooks.SCENARIOS["http1-idle"], Path("unused"), failure_path=path
                )
            result = json.loads(path.read_text(encoding="utf-8"))

        self.assertIs(observed.exception, cause)
        self.assertEqual(result["primary"]["id"], id(cause))
        self.assertEqual(result["cleanup"], [])
        self.assertEqual(result["reports"], [])

    async def test_report_limit_failure_is_chained_after_owned_cleanup(self) -> None:
        cause = OSError("independent launch failure")
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(hooks, "_FirefoxNative", side_effect=cause),
            patch.object(hooks, "MAX_FAILURE_REPORT_BYTES", 1),
            self.assertRaises(BrowserLaunchFailures) as observed,
        ):
            await hooks.run_once(
                hooks.SCENARIOS["http1-idle"],
                Path("unused"),
                failure_path=Path(directory) / "failed.json",
            )

        self.assertIs(observed.exception.primary, cause)
        self.assertEqual(len(observed.exception.cleanup), 1)
        self.assertIsInstance(observed.exception.cleanup[0], ValueError)
