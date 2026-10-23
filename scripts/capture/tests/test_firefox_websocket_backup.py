import asyncio
import unittest

from scripts.capture import firefox_socket_hooks as hooks


class WebSocketBackupTests(unittest.IsolatedAsyncioTestCase):
    async def test_two_upgrades_close_before_readable_http_requests(self) -> None:
        origins = hooks.Origins(hooks.SCENARIOS["websocket-backup"])
        self.addAsyncCleanup(origins.shutdown)
        listener = await asyncio.start_server(origins.accept_target, "127.0.0.1", 0)
        origins.listeners.append(listener)
        origins.port = listener.sockets[0].getsockname()[1]

        async def connect() -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
            reader, writer = await asyncio.open_connection("127.0.0.1", origins.port)
            self.addAsyncCleanup(hooks.close_writer, writer, None)
            return reader, writer

        async def upgrade(
            index: int,
        ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
            reader, writer = await connect()
            writer.write(
                f"GET /ws?i={index} HTTP/1.1\r\nHost: {hooks.TARGET_HOST}\r\n".encode()
                + b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
                + b"Sec-WebSocket-Version: 13\r\n"
                + b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
            )
            await writer.drain()
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
            self.assertTrue(head.startswith(b"HTTP/1.1 101 Switching Protocols\r\n"))
            self.assertIn(b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", head)
            return reader, writer

        first, second = await upgrade(0), await upgrade(1)
        self.assertEqual(len(origins.open), 2)
        self.assertEqual(
            [connection.requests[0][1] for connection in origins.connections],
            ["/ws?i=0", "/ws?i=1"],
        )
        for reader, writer in (first, second):
            # A masked RFC 6455 close carrying status 1000.
            writer.write(b"\x88\x82\x01\x02\x03\x04\x02\xea")
            await writer.drain()
            self.assertEqual(
                await asyncio.wait_for(reader.readexactly(4), 2), b"\x88\x02\x03\xe8"
            )
            self.assertEqual(await asyncio.wait_for(reader.read(1), 2), b"")

        reader, writer = await connect()
        for index in (2, 3):
            writer.write(
                f"GET /fast?i={index} HTTP/1.1\r\nHost: {hooks.TARGET_HOST}\r\n\r\n".encode()
            )
            await writer.drain()
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
            self.assertTrue(head.startswith(b"HTTP/1.1 200 OK\r\n"))
            self.assertIn(b"Access-Control-Allow-Origin: *\r\n", head)
            self.assertEqual(await asyncio.wait_for(reader.readexactly(3), 2), b"ok\n")
        await hooks.close_writer(writer, None)
        if origins.peers:
            _, pending = await asyncio.wait(tuple(origins.peers), timeout=2)
            self.assertFalse(pending)
        self.assertFalse(origins.failures)
        self.assertEqual(len(origins.connections), 3)
        self.assertEqual(
            [connection.close_kind for connection in origins.connections],
            ["websocket", "websocket", "fin"],
        )
        self.assertEqual(
            [path for _, path in origins.connections[2].requests],
            ["/fast?i=2", "/fast?i=3"],
        )


if __name__ == "__main__":
    unittest.main()
