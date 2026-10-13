import asyncio
import errno
import unittest
from unittest.mock import patch

from h2.exceptions import ProtocolError

from scripts.capture.http2_session import server_context
from scripts.capture.tests import test_http2_websocket as peers


class TlsPeer:
    def __init__(self):
        self.server = None
        self.tasks = []
        self.writers = []
        self.accepted = asyncio.Event()
        self.eof = asyncio.Event()
        self.input = asyncio.Event()
        self.data = b""

    async def start(self):
        context = server_context(peers.CERTIFICATE)
        context.set_alpn_protocols(["h2"])
        self.server = await asyncio.start_server(
            self.accept, "127.0.0.1", 0, ssl=context
        )
        return self.server.sockets[0].getsockname()[1]

    def accept(self, reader, writer):
        self.writers.append(writer)
        self.tasks.append(asyncio.create_task(self.read(reader)))
        self.accepted.set()

    async def read(self, reader):
        try:
            while data := await reader.read(65536):
                self.data += data
                self.input.set()
        finally:
            self.eof.set()

    async def backup(self):
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
        for writer in self.writers:
            writer.close()
        cancelled = []
        for task in self.tasks:
            if not task.done():
                cancelled.append(task)
                task.cancel()
        failures = []
        for task, result in zip(
            self.tasks,
            await asyncio.gather(*self.tasks, return_exceptions=True),
            strict=True,
        ):
            if isinstance(result, asyncio.CancelledError) and task in cancelled:
                continue
            if isinstance(result, BaseException) and not peers.peer_disconnected(
                result
            ):
                failures.append(result)

        for result in await asyncio.gather(
            *(writer.wait_closed() for writer in self.writers),
            return_exceptions=True,
        ):
            if isinstance(result, BaseException) and not peers.peer_disconnected(
                result
            ):
                failures.append(result)
        if failures:
            peers.raise_scripted_failures(failures[0], failures, self)


class PeerCompletionTests(unittest.IsolatedAsyncioTestCase):
    async def connect(self, peer):
        port = await peer.start()
        return await asyncio.open_connection(
            "127.0.0.1",
            port,
            ssl=peers.client_context(("h2",)),
            server_hostname=peers.HOSTNAME,
        )

    async def test_failed_settings_acquisition_closes_actual_writer_before_backup(self):
        peer = TlsPeer()
        self.addAsyncCleanup(peer.backup)
        reader, writer = await self.connect(peer)
        self.addAsyncCleanup(self.retire, writer)
        marker = OSError(errno.EIO, "settings input failed")

        async def settings(client, predicate):
            await peer.input.wait()
            raise marker

        with (
            patch.object(
                peers.asyncio, "open_connection", return_value=(reader, writer)
            ),
            patch.object(peers.ScriptedH2, "wait", settings),
            self.assertRaises(OSError) as observed,
        ):
            await peers.ScriptedH2.open(0)

        self.assertIs(observed.exception, marker)
        self.assertTrue(peer.data.startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
        self.assertTrue(writer.is_closing())
        await asyncio.wait_for(peer.eof.wait(), 1)

    async def retire(self, writer):
        writer.close()
        try:
            await writer.wait_closed()
        except OSError as error:
            if not peers.peer_disconnected(error):
                raise

    async def test_original_completed_connection_error_is_observed_and_writer_retired(
        self,
    ):
        peer = TlsPeer()
        self.addAsyncCleanup(peer.backup)
        reader, writer = await self.connect(peer)
        self.addAsyncCleanup(self.retire, writer)
        marker = ConnectionResetError(errno.EIO, "unrelated local input failure")
        client = peers.ScriptedH2(reader, writer)

        async def failed_read(size):
            await peer.accepted.wait()
            raise marker

        with patch.object(reader, "read", failed_read):
            client.task = asyncio.create_task(client.pump())
            await asyncio.wait((client.task,))
            with self.assertRaises(ConnectionResetError) as observed:
                await client.close()

        self.assertIs(observed.exception, marker)
        self.assertTrue(writer.is_closing())
        await asyncio.wait_for(peer.eof.wait(), 1)

    async def test_original_parse_failure_and_close_failure_are_both_retained(self):
        peer = TlsPeer()
        self.addAsyncCleanup(peer.backup)
        reader, writer = await self.connect(peer)
        self.addAsyncCleanup(self.retire, writer)
        client = peers.ScriptedH2(reader, writer)
        parser = []
        close_failure = ValueError("actual writer close failed")
        original_receive = client.connection.receive_data

        def receive(data):
            try:
                return original_receive(data)
            except ProtocolError as error:
                parser.append(error)
                raise

        def close():
            raise close_failure

        await peer.accepted.wait()
        peer.writers[0].write(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00")
        await peer.writers[0].drain()
        with patch.object(client.connection, "receive_data", receive):
            client.task = asyncio.create_task(client.pump())
            await asyncio.wait_for(asyncio.wait((client.task,)), 1)
            with self.assertRaises(ProtocolError) as waiting:
                await client.wait(lambda: False)
            with (
                patch.object(writer, "close", close),
                self.assertRaises(BaseException) as observed,
            ):
                await client.close()

        self.assertEqual(len(parser), 1)
        self.assertIs(waiting.exception, parser[0])
        self.assertIs(observed.exception, parser[0])
        self.assertTrue(writer.is_closing())
        self.assertIsInstance(observed.exception.__cause__, peers.ScriptedPeerFailures)
        self.assertIn(close_failure, observed.exception.__cause__.cleanup)
        await asyncio.wait_for(peer.eof.wait(), 1)

    async def test_driver_cancellation_collects_blocked_pump_and_keeps_caller_identity(
        self,
    ):
        peer = TlsPeer()
        self.addAsyncCleanup(peer.backup)
        reader, writer = await self.connect(peer)
        self.addAsyncCleanup(self.retire, writer)
        client = peers.ScriptedH2(reader, writer)
        pump_ready = asyncio.Event()
        pump_retired = asyncio.Event()
        browser_ready = asyncio.Event()
        marker = PermissionError("scripted caller failed")

        async def read(size):
            pump_ready.set()
            try:
                return await asyncio.StreamReader.read(reader, size)
            finally:
                pump_retired.set()

        async def run(browser):
            browser.page_client = client
            browser_ready.set()
            await asyncio.Future()

        with patch.object(reader, "read", read):
            client.task = asyncio.create_task(client.pump())
            await pump_ready.wait()
            with (
                patch.object(peers.ScriptedBrowser, "run", run),
                self.assertRaises(PermissionError) as observed,
            ):
                async with peers.driver()("https://fixture.test/"):
                    await browser_ready.wait()
                    raise marker

        self.assertIs(observed.exception, marker)
        self.assertTrue(client.task.done())
        self.assertTrue(pump_retired.is_set())
        self.assertTrue(writer.is_closing())
        await asyncio.wait_for(peer.eof.wait(), 1)

    async def test_driver_first_peer_error_does_not_skip_second_actual_writer(self):
        peers_and_clients = []
        for _ in range(2):
            peer = TlsPeer()
            self.addAsyncCleanup(peer.backup)
            reader, writer = await self.connect(peer)
            self.addAsyncCleanup(self.retire, writer)
            peers_and_clients.append((peer, peers.ScriptedH2(reader, writer)))
        first, second = [client for _, client in peers_and_clients]
        marker = ConnectionResetError(errno.EIO, "first real peer input failed")
        caller = PermissionError("driver caller failed")
        ready = asyncio.Event()

        async def failed_read(size):
            raise marker

        async def run(browser):
            browser.page_client = first
            browser.socket_client = second
            ready.set()
            await asyncio.Future()

        with patch.object(first.reader, "read", failed_read):
            first.task = asyncio.create_task(first.pump())
            await asyncio.wait((first.task,))
            second.task = asyncio.create_task(second.pump())
            with (
                patch.object(peers.ScriptedBrowser, "run", run),
                self.assertRaises(PermissionError) as observed,
            ):
                async with peers.driver()("https://fixture.test/"):
                    await ready.wait()
                    raise caller

        self.assertIs(observed.exception, caller)
        self.assertIsInstance(caller.__cause__, peers.ScriptedPeerFailures)
        self.assertIn(marker, caller.__cause__.cleanup)
        for peer, client in peers_and_clients:
            self.assertTrue(client.writer.is_closing())
            self.assertTrue(client.task.done())
            await asyncio.wait_for(peer.eof.wait(), 1)

    async def test_close_interruption_retains_original_pump_until_actual_release(self):
        peer = TlsPeer()
        self.addAsyncCleanup(peer.backup)
        reader, writer = await self.connect(peer)
        self.addAsyncCleanup(self.retire, writer)
        client = peers.ScriptedH2(reader, writer)
        ready = asyncio.Event()
        cancelled = asyncio.Event()
        release = asyncio.Event()
        marker = OSError(errno.EIO, "late real peer input failed")
        cancellation = []

        async def read(size):
            ready.set()
            try:
                return await asyncio.StreamReader.read(reader, size)
            except asyncio.CancelledError as error:
                cancelled.set()
                await release.wait()
                raise marker from error

        async def close():
            try:
                await client.close()
            except asyncio.CancelledError as error:
                cancellation.append(error)
                raise

        with patch.object(reader, "read", read):
            client.task = asyncio.create_task(client.pump())
            await ready.wait()
            closing = asyncio.create_task(close())
            self.addAsyncCleanup(self.release_pump, release, client, closing, marker)
            await cancelled.wait()
            closing.cancel("caller interrupted peer collection")
            await asyncio.wait_for(peer.eof.wait(), 1)

            self.assertFalse(client.task.done())
            self.assertFalse(client.close_task.done())
            self.assertTrue(writer.is_closing())
            release.set()
            await asyncio.wait((closing,), timeout=1)

        self.assertTrue(closing.done())
        self.assertEqual(len(cancellation), 1)
        self.assertIs(cancellation[0], client.failures[0])
        self.assertIsInstance(cancellation[0].__cause__, peers.ScriptedPeerFailures)
        self.assertIn(marker, cancellation[0].__cause__.cleanup)
        self.assertTrue(client.task.done())

    async def release_pump(self, release, client, closing, marker):
        release.set()
        tasks = [client.task, closing]
        if client.close_task is not None:
            tasks.append(client.close_task)
        for result in await asyncio.gather(*tasks, return_exceptions=True):
            if result is marker or isinstance(result, asyncio.CancelledError):
                continue
            if isinstance(result, BaseException):
                raise result

    async def test_first_flush_failure_retires_writer_before_pump_exists(self):
        peer = TlsPeer()
        self.addAsyncCleanup(peer.backup)
        reader, writer = await self.connect(peer)
        self.addAsyncCleanup(self.retire, writer)
        marker = OSError(errno.EIO, "first preface drain failed")

        async def drain():
            await peer.input.wait()
            raise marker

        with (
            patch.object(
                peers.asyncio, "open_connection", return_value=(reader, writer)
            ),
            patch.object(writer, "drain", drain),
            self.assertRaises(OSError) as observed,
        ):
            await peers.ScriptedH2.open(0)

        self.assertIs(observed.exception, marker)
        self.assertTrue(peer.data.startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
        self.assertTrue(writer.is_closing())
        await asyncio.wait_for(peer.eof.wait(), 1)


if __name__ == "__main__":
    unittest.main()
