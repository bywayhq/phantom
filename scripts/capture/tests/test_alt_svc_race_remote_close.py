"""Headful shutdown keeps actual remote peers and initiating errors owned."""

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.capture import alt_svc_race as race
from scripts.capture import browser_remote
from scripts.capture.tests.test_browser_remote_lifecycle import (
    CommandPeer,
    command_seen,
)

DEADLINE = 3.0


class RemoteCloseTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.profile = Path(self.directory.name)
        self.peer = CommandPeer({"Browser.close": {}}, {})
        self.addAsyncCleanup(self.peer.finish)
        port = await self.peer.listen()
        (self.profile / browser_remote.CHROMIUM_PORT_FILE).write_text(
            f"{port}\n/devtools/browser/owned\n"
        )
        self.connections = []
        self.run = race.new_run()
        self.connection_type = race.RemoteConnection

    def connection(self, socket):
        connection = self.connection_type(socket)
        self.connections.append(connection)
        self.peer.connection = connection
        return connection

    def assert_retired(self, connection):
        self.assertTrue(connection.reader.done())
        self.assertTrue(connection.socket.writer.is_closing())
        if connection.reader.cancelled():
            self.assertTrue(connection._reader_cancel_requested)
            self.peer.observed_cancellations.add(connection.reader)

    async def test_graceful_close_retires_the_remote_reader_and_socket(self):
        with patch.object(race, "RemoteConnection", self.connection):
            await race.close_headful_browser(self.profile, "chrome", self.run)

        self.assertEqual(
            [command["method"] for command in self.peer.remote.commands],
            ["Browser.close"],
        )
        self.assertIsNone(self.run.remote_disconnect)
        self.assert_retired(self.connections[0])

    async def test_operation_and_cleanup_failures_keep_the_prior_cause_and_owner(self):
        original = OSError("controlled close operation failure")
        prior = ValueError("prior operation cause")
        original.__cause__ = prior
        cleanup = OSError("controlled remote retirement failure")
        actual_close = self.connection_type.close

        async def close(connection):
            await actual_close(connection)
            raise cleanup

        with (
            patch.object(race, "RemoteConnection", self.connection),
            patch.object(race, "request_browser_close", side_effect=original),
            patch.object(self.connection_type, "close", close),
            self.assertRaises(OSError) as raised,
        ):
            await race.close_headful_browser(self.profile, "chrome", self.run)

        self.assertIs(raised.exception, original)
        self.assertIs(original.__cause__, prior)
        retained = original.capture_cleanup_failure
        self.assertIsInstance(retained, race.RemoteCloseCleanupError)
        self.assertIs(retained.owner, self.connections[0])
        self.assertIs(retained.primary, original)
        self.assertEqual(retained.cleanup, (cleanup,))
        self.assertIs(prior.__cause__, retained)
        self.assert_retired(retained.owner)

    async def test_cancelled_command_keeps_cancellation_and_failed_remote_owner(self):
        self.peer.remote.replies.clear()
        cleanup = OSError("controlled cancellation retirement failure")
        actual_close = self.connection_type.close
        cancellations = []

        async def close(connection):
            await actual_close(connection)
            raise cleanup

        async def close_browser():
            try:
                await race.close_headful_browser(self.profile, "chrome", self.run)
            except asyncio.CancelledError as error:
                # Python 3.10 may replace the exception at the Task boundary.
                cancellations.append(error)
                raise

        with (
            patch.object(race, "RemoteConnection", self.connection),
            patch.object(self.connection_type, "close", close),
        ):
            task = asyncio.create_task(close_browser())
            self.peer.calls.append(task)
            await command_seen(self.peer.remote, "Browser.close")
            task.cancel("controlled headful-close cancellation")
            try:
                with self.assertRaises(asyncio.CancelledError):
                    await asyncio.wait_for(task, DEADLINE)
            finally:
                self.peer.observed_cancellations.add(task)
                self.assert_retired(self.connections[0])

        self.assertTrue(task.cancelled())
        self.assertEqual(len(cancellations), 1)
        cancellation = cancellations[0]
        retained = cancellation.__cause__
        self.assertEqual(cancellation.args, ("controlled headful-close cancellation",))
        self.assertIsInstance(retained, race.RemoteCloseCleanupError)
        self.assertIs(retained.primary, cancellation)
        self.assertIs(retained.owner, self.connections[0])
        self.assertEqual(retained.cleanup, (cleanup,))

    async def test_constructor_failure_still_retires_and_retains_the_socket(self):
        original = RuntimeError("controlled remote constructor failure")
        cleanup = OSError("controlled socket close failure")
        actual_close = race.RemoteSocket.close
        sockets = []

        def close(socket):
            sockets.append(socket)
            actual_close(socket)
            raise cleanup

        with (
            patch.object(race, "RemoteConnection", side_effect=original),
            patch.object(race.RemoteSocket, "close", close),
            self.assertRaises(RuntimeError) as raised,
        ):
            await race.close_headful_browser(self.profile, "chrome", self.run)

        self.assertIs(raised.exception, original)
        retained = original.capture_cleanup_failure
        self.assertIs(retained.owner, sockets[0])
        self.assertEqual(retained.cleanup, (cleanup,))
        self.assertTrue(sockets[0].writer.is_closing())

    async def test_unfinished_remote_owner_remains_reachable_until_backup(self):
        original = OSError("controlled close command failure")
        cleanup = OSError("controlled retirement interruption")
        with (
            patch.object(race, "RemoteConnection", self.connection),
            patch.object(race, "request_browser_close", side_effect=original),
            patch.object(self.connection_type, "close", side_effect=cleanup),
            self.assertRaises(OSError) as raised,
        ):
            await race.close_headful_browser(self.profile, "chrome", self.run)

        self.assertIs(raised.exception, original)
        retained = original.capture_cleanup_failure
        self.assertIs(retained.owner, self.connections[0])
        self.assertFalse(retained.owner.reader.done())
        self.assertFalse(retained.owner.socket.writer.is_closing())
        await retained.owner.close()
        self.assert_retired(retained.owner)

    async def test_missing_endpoint_fails_before_opening_a_remote_socket(self):
        (self.profile / browser_remote.CHROMIUM_PORT_FILE).unlink()
        actual_wait = race.wait_for_endpoint

        async def bounded_wait(find, profile):
            return await actual_wait(find, profile, timeout=0.01)

        with (
            patch.object(race, "wait_for_endpoint", bounded_wait),
            patch.object(race.RemoteSocket, "connect") as connect,
            self.assertRaisesRegex(TimeoutError, "did not publish"),
        ):
            await race.close_headful_browser(self.profile, "chrome", self.run)

        connect.assert_not_called()

    async def test_nonloopback_endpoint_is_rejected_before_io(self):
        with (
            patch.object(
                race, "wait_for_endpoint", return_value="ws://192.0.2.1:9222/session"
            ),
            patch.object(browser_remote.asyncio, "open_connection") as connect,
            self.assertRaisesRegex(ValueError, "must be loopback"),
        ):
            await race.close_headful_browser(self.profile, "chrome", self.run)

        connect.assert_not_called()
