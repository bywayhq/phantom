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
        for task in self.tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        await asyncio.gather(
            *(writer.wait_closed() for writer in self.writers),
            return_exceptions=True,
        )


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

        with patch.object(peers.asyncio, "open_connection", return_value=(reader, writer)):
            with patch.object(peers.ScriptedH2, "wait", settings):
                with self.assertRaises(OSError) as observed:
                    await peers.ScriptedH2.open(0)

        self.assertIs(observed.exception, marker)
        self.assertTrue(peer.data.startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
        self.assertTrue(writer.is_closing())
        await asyncio.wait_for(peer.eof.wait(), 1)

    async def retire(self, writer):
        writer.close()
        await asyncio.gather(writer.wait_closed(), return_exceptions=True)

    async def test_original_completed_connection_error_is_observed_and_writer_retired(self):
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
        original_close = writer.close

        def receive(data):
            try:
                return original_receive(data)
            except ProtocolError as error:
                parser.append(error)
                raise

        def close():
            original_close()
            raise close_failure

        await peer.accepted.wait()
        peer.writers[0].write(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00")
        await peer.writers[0].drain()
        with patch.object(client.connection, "receive_data", receive):
            client.task = asyncio.create_task(client.pump())
            await asyncio.wait_for(asyncio.wait((client.task,)), 1)
            with patch.object(writer, "close", close):
                with self.assertRaises(BaseException) as observed:
                    await client.close()

        self.assertEqual(len(parser), 1)
        self.assertIs(observed.exception, parser[0])
        self.assertTrue(writer.is_closing())
        self.assertIsInstance(observed.exception.__cause__, peers.ScriptedPeerFailures)
        self.assertIn(close_failure, observed.exception.__cause__.cleanup)
        await asyncio.wait_for(peer.eof.wait(), 1)

    async def test_driver_cancellation_collects_blocked_pump_and_keeps_caller_identity(self):
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
            with patch.object(peers.ScriptedBrowser, "run", run):
                with self.assertRaises(PermissionError) as observed:
                    async with peers.driver()("https://fixture.test/"):
                        await browser_ready.wait()
                        raise marker

        self.assertIs(observed.exception, marker)
        self.assertTrue(client.task.done())
        self.assertTrue(pump_retired.is_set())
        self.assertTrue(writer.is_closing())
        await asyncio.wait_for(peer.eof.wait(), 1)


if __name__ == "__main__":
    unittest.main()
