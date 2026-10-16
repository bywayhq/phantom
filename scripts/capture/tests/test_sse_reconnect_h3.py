"""Run the same bounded SSE scenarios over real loopback QUIC H3 streams."""

import asyncio
import ssl
import unittest
from urllib.parse import urlsplit

from aioquic.asyncio import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, ProtocolNegotiated, StreamReset

from scripts.capture.sse_multiplexed import H3ReconnectServer
from scripts.capture.sse_reconnect import CATALOG, ScenarioRun
from scripts.capture.tests import test_sse_reconnect_h2 as h2_tests
from scripts.capture.tests.loopback_quic import connect_loopback


class ClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.pending = {}
        self.headers = {}
        self.bodies = {}
        self.alpn = None

    def quic_event_received(self, event):
        if isinstance(event, ProtocolNegotiated):
            self.alpn = event.alpn_protocol
        if isinstance(event, (StreamReset, ConnectionTerminated)):
            for stream, future in self.pending.items():
                if (
                    isinstance(event, ConnectionTerminated) or stream == event.stream_id
                ) and not future.done():
                    future.set_exception(ConnectionResetError("SSE QUIC stream ended"))
        for response in self.http.handle_event(event):
            if isinstance(response, HeadersReceived):
                self.headers[response.stream_id] = dict(response.headers)
            elif isinstance(response, DataReceived):
                self.bodies.setdefault(response.stream_id, bytearray()).extend(
                    response.data
                )
            if (
                isinstance(response, (HeadersReceived, DataReceived))
                and response.stream_ended
            ):
                future = self.pending.get(response.stream_id)
                if future is not None and not future.done():
                    future.set_result(
                        (
                            self.headers.pop(response.stream_id),
                            bytes(self.bodies.pop(response.stream_id, b"")),
                        )
                    )

    async def fetch(self, headers):
        stream = self._quic.get_next_available_stream_id()
        future = asyncio.get_running_loop().create_future()
        self.pending[stream] = future
        try:
            self.http.send_headers(stream, headers, end_stream=True)
            self.transmit()
            return await asyncio.wait_for(future, 2)
        finally:
            self.pending.pop(stream, None)
            self.headers.pop(stream, None)
            self.bodies.pop(stream, None)


class H3EventSource(h2_tests.H2EventSource):
    async def start(self, server):
        configuration = QuicConfiguration(
            is_client=True,
            alpn_protocols=["h3"],
            server_name="server.phantom.test",
        )
        configuration.load_verify_locations(cadata=server.certificate.certificate_pem)
        configuration.verify_mode = ssl.CERT_REQUIRED
        self.connection = connect_loopback(
            server.address[1], configuration, ClientProtocol
        )
        self.client = await self.connection.__aenter__()
        if self.client.alpn != "h3":
            raise AssertionError("client did not negotiate h3")

    async def close(self):
        await asyncio.wait_for(self.connection.__aexit__(None, None, None), 2)

    async def abort_response(self, stream):
        self.client._quic.stop_stream(stream, 0x10C)
        self.client.transmit()

    async def fetch(self, url, fields):
        parts = urlsplit(url)
        target = parts.path + (f"?{parts.query}" if parts.query else "")
        headers = [
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", parts.netloc.encode()),
            (b":path", target.encode()),
        ]
        headers.extend(
            (name.lower(), value.strip())
            for name, _, value in (field.partition(b":") for field in fields)
        )
        response, body = await self.client.fetch(headers)
        return self.response(response, body)


class H3CaptureTests(h2_tests.H2CaptureTests):
    server_type = H3ReconnectServer
    client_type = H3EventSource
    protocol = "h3"


class H3CleanupTests(unittest.IsolatedAsyncioTestCase):
    async def test_failed_close_keeps_owner_until_udp_and_callbacks_retire(self):
        server = H3ReconnectServer()
        await server.start("127.0.0.1", 0)
        server.run = ScenarioRun(CATALOG[0], "close-fault")
        client = H3EventSource(server.url(server.run))
        started = False
        try:
            await client.start(server)
            started = True
            protocol = server.protocols[0]

            async def failed_wait():
                raise RuntimeError("injected close wait failure")

            protocol.wait_closed = failed_wait
            with self.assertRaisesRegex(RuntimeError, "injected close wait failure"):
                await server.close()
            self.assertTrue(server.retired.done())
            self.assertTrue(server.transport.is_closing())
            self.assertIsNone(protocol._timer)
            self.assertIsNone(protocol._transmit_task)
            self.assertFalse(server.protocols)
        finally:
            if started:
                await client.close()
            if not server.transport.is_closing():
                await server.close()
