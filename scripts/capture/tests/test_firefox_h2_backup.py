import asyncio
import ssl
import unittest

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, ResponseReceived, StreamEnded

from scripts.capture.firefox_socket_hooks import SCENARIOS, TARGET_HOST, Origins
from scripts.capture.http2_session import generate_certificate, server_context


class H2BackupTests(unittest.IsolatedAsyncioTestCase):
    async def test_h2_origin_reuses_the_connection_and_redials_after_explicit_drop(
        self,
    ) -> None:
        scenario = SCENARIOS["h2-backup"]
        self.assertTrue(scenario.rewrite_lookup)
        origins = Origins(scenario)
        self.addAsyncCleanup(origins.shutdown)
        certificate = generate_certificate(TARGET_HOST)
        context = server_context(certificate)
        context.set_alpn_protocols(["h2"])
        listener = await asyncio.start_server(
            origins.accept_target, "127.0.0.1", 0, ssl=context
        )
        origins.listeners.append(listener)
        origins.port = listener.sockets[0].getsockname()[1]
        page = await asyncio.start_server(origins.accept_page, "127.0.0.1", 0)
        origins.listeners.append(page)
        page_port = page.sockets[0].getsockname()[1]
        client = ssl.create_default_context(cadata=certificate.certificate_pem.decode())
        client.set_alpn_protocols(["h2"])

        async def connect() -> tuple[
            asyncio.StreamReader, asyncio.StreamWriter, H2Connection
        ]:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", origins.port, ssl=client, server_hostname=TARGET_HOST
            )
            self.addAsyncCleanup(writer.wait_closed)
            self.addCleanup(writer.close)
            self.assertEqual(
                writer.get_extra_info("ssl_object").selected_alpn_protocol(), "h2"
            )
            session = H2Connection(H2Configuration(client_side=True))
            session.initiate_connection()
            return reader, writer, session

        async def request(
            peer: tuple[asyncio.StreamReader, asyncio.StreamWriter, H2Connection],
            path: str,
        ) -> None:
            reader, writer, session = peer
            stream = session.get_next_available_stream_id()
            session.send_headers(
                stream,
                [
                    (":method", "GET"),
                    (":scheme", "https"),
                    (":authority", TARGET_HOST),
                    (":path", path),
                ],
                end_stream=True,
            )
            writer.write(session.data_to_send())
            await writer.drain()
            body = b""
            while True:
                data = await asyncio.wait_for(reader.read(65536), 2)
                self.assertTrue(data, "origin closed before finishing the response")
                for event in session.receive_data(data):
                    if isinstance(event, ResponseReceived):
                        self.assertIn((b":status", b"200"), event.headers)
                    elif isinstance(event, DataReceived):
                        body += event.data
                    elif isinstance(event, StreamEnded) and event.stream_id == stream:
                        self.assertEqual(body, b"ok\n")
                        return

        first = await connect()
        await request(first, "/fast?i=0")
        await request(first, "/fast?i=1")
        self.assertEqual(len(origins.connections), 1)
        reader, writer = await asyncio.open_connection("127.0.0.1", page_port)
        try:
            writer.write(b"GET /drop HTTP/1.1\r\nHost: localhost\r\n\r\n")
            await writer.drain()
            await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
        finally:
            writer.close()
            await writer.wait_closed()
        self.assertEqual(await asyncio.wait_for(first[0].read(), 2), b"")
        first[1].close()
        await first[1].wait_closed()

        second = await connect()
        await request(second, "/fast?i=2")
        self.assertEqual(len(origins.connections), 2)
        self.assertEqual(origins.connections[0].close_kind, "server")
        self.assertEqual(
            [
                [path for _, path in connection.requests]
                for connection in origins.connections
            ],
            [["/fast?i=0", "/fast?i=1"], ["/fast?i=2"]],
        )
        second[1].close()
        await second[1].wait_closed()
        await origins.shutdown()
        self.assertFalse(origins.peers)
        self.assertFalse(origins.writers)
        self.assertFalse(origins.failures)
