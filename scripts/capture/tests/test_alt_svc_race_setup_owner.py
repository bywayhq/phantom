import asyncio
import errno
import unittest
from contextlib import ExitStack
from unittest.mock import patch

from hyperframe.frame import Frame, SettingsFrame

from scripts.capture.tests import test_alt_svc_race as original


class OriginalFailures(unittest.TestResult):
    def __init__(self):
        super().__init__()
        self.causes = []

    def addError(self, test, error):
        self.causes.append(error[1])
        super().addError(test, error)


class SetupPeers:
    def __init__(self, stage, cleanup_failure=False):
        self.stage = stage
        self.caller = (
            asyncio.CancelledError("controlled setup cancellation")
            if stage == "cancel"
            else OSError(errno.EIO, "controlled setup failure")
        )
        self.cause = LookupError("original setup cause")
        self.caller.__cause__ = self.cause
        self.cleanup = ValueError("controlled client close failure")
        self.cleanup_failure = cleanup_failure
        self.sockets = None
        self.server = None
        self.reader = None
        self.writer = None
        self.tasks = []
        self.observed = None
        self.backup_errors = []

    def install(self, stack):
        reserve = original.reserve_ports
        start = original.Http2Origin.start
        open_connection = original.asyncio.open_connection
        initiate = original.h2.connection.H2Connection.initiate_connection

        def reserve_owned(host):
            self.sockets = reserve(host)
            return self.sockets

        async def start_owned(server, sock):
            self.server = server
            await start(server, sock)
            if self.stage == "start":
                raise self.caller

        async def open_owned(*args, **kwargs):
            if self.stage == "open":
                raise self.caller

            self.reader, self.writer = await open_connection(*args, **kwargs)
            self.tasks = list(self.server.handlers)
            if not self.tasks:
                raise AssertionError("real TLS client has no accepted handler")

            # Receive the real server preface before deliberately closing TLS.
            # Otherwise its queued SETTINGS can arrive after our close_notify.
            async def receive_settings():
                header = await self.reader.readexactly(9)
                frame, size = Frame.parse_frame_header(memoryview(header), strict=True)
                if not isinstance(frame, SettingsFrame) or frame.flags:
                    raise AssertionError("expected the server's initial SETTINGS")
                if size > 65536:
                    raise AssertionError("initial SETTINGS exceeds the read bound")
                frame.parse_body(memoryview(await self.reader.readexactly(size)))

            await asyncio.wait_for(receive_settings(), 5)

            if self.stage == "write":

                def fail_write(data):
                    raise self.caller

                self.writer.write = fail_write

            if self.cleanup_failure:
                close = self.writer.close

                def fail_close_once():
                    close()
                    self.writer.close = close
                    raise self.cleanup

                self.writer.close = fail_close_once

            return self.reader, self.writer

        def initiate_owned(client):
            initiate(client)
            if self.stage == "cancel" and client.config.client_side:
                raise self.caller

        stack.enter_context(patch.object(original, "reserve_ports", reserve_owned))
        stack.enter_context(patch.object(original.Http2Origin, "start", start_owned))
        stack.enter_context(
            patch.object(original.asyncio, "open_connection", open_owned)
        )
        stack.enter_context(
            patch.object(
                original.h2.connection.H2Connection,
                "initiate_connection",
                initiate_owned,
            )
        )

    async def observe_before_backup(self):
        server = self.server
        writer = self.writer
        self.observed = {
            "sockets_closed": all(sock.fileno() == -1 for sock in self.sockets),
            "listener_closed": not server.server.is_serving(),
            "handler_collected": not server.handlers,
            "accepted_tasks_done": all(task.done() for task in self.tasks),
            "client_closed": writer is None or writer.is_closing(),
            "client_eof": writer is None,
        }
        if writer is not None and writer.is_closing() and server.closing:
            try:
                # Initial SETTINGS may already be buffered before peer shutdown.
                async def read_eof():
                    await self.reader.read()
                    return (await self.reader.read(1)) == b""

                self.observed["client_eof"] = await asyncio.wait_for(read_eof(), 5)
            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
                self.observed["client_eof"] = True

    async def backup(self):
        # The earlier observation is the oracle. Backups cannot make it pass.
        server = self.server
        writer = self.writer
        if writer is not None:
            try:
                writer.close()
            except ValueError as error:
                if error is not self.cleanup:
                    raise
                self.backup_errors.append(error)

        await original.Http2Origin.close(server)
        for sock in self.sockets:
            sock.close()


class SetupOwnershipTests(unittest.TestCase):
    def run_original(self, stage, cleanup_failure=False):
        peers = SetupPeers(stage, cleanup_failure)
        case = original.OriginServerTests(
            "test_learn_retire_advertises_h3_then_goaway_keeps_held_stream"
        )
        case.addAsyncCleanup(peers.backup)
        case.addAsyncCleanup(peers.observe_before_backup)
        result = OriginalFailures()
        with ExitStack() as stack:
            peers.install(stack)
            case.run(result)

        self.assertEqual(result.failures, [])
        expected = [peers.caller, peers.cleanup] if cleanup_failure else [peers.caller]
        self.assertEqual(len(result.causes), len(expected), result.causes)
        for actual, cause in zip(result.causes, expected, strict=True):
            self.assertIs(actual, cause)
        self.assertIs(peers.caller.__cause__, peers.cause)
        self.assertTrue(all(peers.observed.values()), peers.observed)
        return peers, result

    def test_failed_start_releases_reserved_socket_and_listener(self):
        peers, result = self.run_original("start")
        self.assertEqual(result.causes, [peers.caller])

    def test_failed_connection_open_releases_started_listener(self):
        peers, result = self.run_original("open")
        self.assertEqual(result.causes, [peers.caller])

    def test_setup_cancellation_collects_the_actual_accepted_peer(self):
        peers, result = self.run_original("cancel")
        self.assertTrue(peers.tasks)
        self.assertEqual(result.causes, [peers.caller])

    def test_write_and_close_failures_keep_both_causes_and_collect_peers(self):
        peers, result = self.run_original("write", cleanup_failure=True)
        self.assertTrue(peers.tasks)
        self.assertEqual(len(result.causes), 2)
        self.assertIs(result.causes[1], peers.cleanup)
        self.assertEqual(peers.backup_errors, [])


if __name__ == "__main__":
    unittest.main()
