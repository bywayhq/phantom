"""Real loopback proxy and decrypted TLS H1/H2 WebSocket openings."""

import asyncio
import unittest

from h2.events import DataReceived, ResponseReceived, StreamEnded

from scripts.capture.http2_analysis import analyze_http2
from scripts.capture.http2_websocket import CaptureMetadata, validate_retained_fields
from scripts.capture.tests.tunnelled_websocket_peer import (
    TIMEOUT,
    open_h2,
    open_tunnel,
    servers,
)
from scripts.capture.tunnelled_websocket import (
    SCENARIOS,
    fixture,
)
from scripts.capture.websocket_frames import (
    BINARY,
    CLOSE,
    TEXT,
    FrameReader,
    client_frame,
)
from scripts.capture.websocket_tunnel import (
    MODES,
    PROXY_HOST,
    correlate,
)


class TunnelWireTests(unittest.IsolatedAsyncioTestCase):
    async def test_all_three_proxy_handshakes_reach_real_tls_h1_and_h2_websockets(self):
        for mode in MODES:
            for protocol in ("h2", "http/1.1"):
                with self.subTest(mode=mode, protocol=protocol):
                    async with servers(mode) as (
                        origin,
                        proxy,
                        run,
                        tunnels,
                        certificate,
                        proxy_certificate,
                    ):
                        tls = await open_tunnel(
                            proxy,
                            certificate,
                            proxy_certificate,
                            alpn=(protocol,),
                            fields=(b"X-Before: a", b"X-After: z"),
                        )
                        self.assertEqual(tls.tls.selected_alpn_protocol(), protocol)
                        if protocol == "h2":
                            await self.h2_exchange(tls)
                        else:
                            await self.h1_exchange(tls)
                        await proxy.stop_connections()
                        await origin.stop_connections()
                        correlate(tunnels, origin)
                        self.assertEqual(len(run.websockets), 1)
                        self.assertEqual(run.websockets[0].protocol, protocol)
                        self.assertEqual(run.connections[0].alpn, protocol)
                        opening = tunnels.openings[0]
                        self.assertEqual(opening.origin_connection, 0)
                        self.assertEqual(
                            opening.upstream, origin.endpoints[id(run.connections[0])]
                        )
                        self.assertIsNotNone(opening.finished)
                        if mode == "socks5":
                            self.assertEqual(opening.connection.protocol, "socks5")
                            self.assertEqual(
                                opening.reply[:6], b"\x05\x00\x05\x00\x00\x01"
                            )
                            self.assertEqual(
                                int.from_bytes(opening.reply[-2:], "big"),
                                opening.upstream[1],
                            )
                        else:
                            self.assertEqual(opening.connection.protocol, "http/1.1")
                            self.assertTrue(
                                opening.head.endswith(
                                    b"X-Before: a\r\nX-After: z\r\n\r\n"
                                )
                            )
                        if mode == "https":
                            self.assertEqual(opening.connection.alpn, "http/1.1")
                            self.assertEqual(
                                opening.connection.client_hello.alpn_offer,
                                ("http/1.1",),
                            )
                            self.assertEqual(
                                opening.connection.client_hello.server_name, PROXY_HOST
                            )
                            self.assertTrue(opening.tls_version.startswith("TLS"))
                        else:
                            self.assertIsNone(opening.connection.client_hello)
                            self.assertIsNone(opening.tls_version)
                        if protocol == "h2":
                            block = analyze_http2(run.connections[0]).client_headers[1]
                            self.assertEqual(
                                [field.name for field in block.fields][-3:],
                                [b"x-before", b"sec-websocket-version", b"x-after"],
                            )
                        else:
                            self.assertEqual(
                                run.requests[1].header_lines[-4:],
                                [
                                    b"X-Before: a",
                                    b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
                                    b"Sec-WebSocket-Version: 13",
                                    b"X-After: z",
                                ],
                            )
                        validate_retained_fields(run)
                        text = fixture(
                            SCENARIOS["accept"],
                            [tunnels],
                            CaptureMetadata(
                                "scripted",
                                "0",
                                "test",
                                "owned",
                                "owned",
                                "scripted",
                                "none",
                            ),
                            mode=mode,
                            origin_alpn="negotiate",
                            proxy_address="owned",
                        )
                        self.assertIn("_origin_connection=0", text)
                        self.assertIn(f"alpn:{protocol},protocol:{protocol}", text)
                        self.assertIn(opening.head.hex(), text)
                        if mode == "https":
                            self.assertIn("_client_hello_handshake_hex=01", text)
                        self.assertFalse(proxy.writers)
                        self.assertFalse(proxy.handlers)
                        self.assertFalse(proxy.protocols)

    async def h2_exchange(self, tls):
        peer = await open_h2(tls)
        try:
            self.assertEqual(await peer.get("/ws.html?run=scripted"), b"owned page")
            fields = [
                (b":method", b"CONNECT"),
                (b":protocol", b"websocket"),
                (b":scheme", b"https"),
                (b":path", b"/echo?run=scripted"),
                (b":authority", b"server.phantom.test"),
                (b"x-before", b"a"),
                (b"sec-websocket-version", b"13"),
                (b"x-after", b"z"),
            ]
            peer.connection.send_headers(3, fields)
            await peer.flush()
            await peer.wait(lambda: peer.stream_events(3, ResponseReceived))
            self.assertEqual(
                dict(peer.stream_events(3, ResponseReceived)[0].headers)[b":status"],
                b"200",
            )
            payloads = [b"ordered through tunnel", bytes(range(256)) * 512]
            for opcode, payload in zip((TEXT, BINARY), payloads, strict=True):
                await peer.send_all(3, client_frame(opcode, payload))
            await peer.send_all(3, client_frame(CLOSE, b"\x03\xe8"))
            await peer.wait(lambda: peer.stream_events(3, StreamEnded))
            frames = FrameReader().feed(
                b"".join(event.data for event in peer.stream_events(3, DataReceived))
            )
            self.assertEqual(
                [frame.payload for frame in frames], [*payloads, b"\x03\xe8"]
            )
        finally:
            await peer.close()

    async def h1_exchange(self, tls):
        try:
            tls.write(
                b"GET /ws.html?run=scripted HTTP/1.1\r\nHost: server.phantom.test\r\n\r\n"
            )
            await tls.drain()
            self.assertTrue(
                (await tls.readuntil(b"\r\n\r\n")).startswith(b"HTTP/1.1 200")
            )
            self.assertEqual(await tls.readexactly(10), b"owned page")
            tls.write(
                b"GET /echo?run=scripted HTTP/1.1\r\nHost: server.phantom.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nX-Before: a\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nX-After: z\r\n\r\n"
            )
            await tls.drain()
            self.assertTrue(
                (await tls.readuntil(b"\r\n\r\n")).startswith(b"HTTP/1.1 101")
            )
            payloads = [b"ordered through tunnel", bytes(range(256)) * 512]
            tls.write(
                client_frame(TEXT, payloads[0])
                + client_frame(BINARY, payloads[1])
                + client_frame(CLOSE, b"\x03\xe8")
            )
            await tls.drain()
            parser, frames = FrameReader(), []
            while not any(frame.opcode == CLOSE for frame in frames):
                data = await asyncio.wait_for(tls.read(65536), TIMEOUT)
                self.assertTrue(data)
                frames.extend(parser.feed(data))
            self.assertEqual(
                [frame.payload for frame in frames], [*payloads, b"\x03\xe8"]
            )
        finally:
            tls.close()
            await asyncio.wait_for(tls.wait_closed(), TIMEOUT)

    async def test_endpoint_correlation_distinguishes_repeated_tunnels(self):
        async with servers("http") as (
            origin,
            proxy,
            run,
            tunnels,
            certificate,
            proxy_certificate,
        ):
            for _ in range(2):
                tls = await open_tunnel(
                    proxy, certificate, proxy_certificate, alpn=("http/1.1",)
                )
                await self.h1_exchange(tls)
            await proxy.stop_connections()
            await origin.stop_connections()
            correlate(tunnels, origin)
            self.assertEqual(
                [opening.origin_connection for opening in tunnels.openings], [0, 1]
            )
            self.assertNotEqual(
                tunnels.openings[0].upstream, tunnels.openings[1].upstream
            )
            self.assertEqual(
                tunnels.openings[0].upstream[0], tunnels.openings[1].upstream[0]
            )
            tunnels.openings[1].upstream = tunnels.openings[0].upstream
            with self.assertRaisesRegex(ValueError, "exactly one"):
                correlate(tunnels, origin)
