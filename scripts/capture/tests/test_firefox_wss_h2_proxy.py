"""Fresh WSS family observations through the existing HTTPS/H2 proxy owner."""

import asyncio
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.capture import firefox_socket_hooks as hooks
from scripts.capture.http2_session import HOSTNAME, generate_certificate, server_context
from scripts.capture.tests import test_firefox_connect_backup as connect
from scripts.capture.tests.tunnelled_websocket_peer import ProxyH2, TunnelTls
from scripts.capture.websocket_tunnel import PROXY_HOST

SCENE = "wss-https-h2-proxy-backup"


class FreshWssProxyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.origins = hooks.Origins(hooks.SCENARIOS[SCENE])
        self.addAsyncCleanup(self.origins.shutdown)
        self.certificate = generate_certificate(HOSTNAME)
        self.proxy_certificate = generate_certificate(PROXY_HOST)
        context = server_context(self.certificate)
        context.set_alpn_protocols(["http/1.1"])
        listener = await asyncio.start_server(
            self.origins.accept_target, "127.0.0.1", 0, ssl=context
        )
        self.origins.listeners.append(listener)
        self.origins.port = listener.sockets[0].getsockname()[1]
        await hooks.start_connect_proxy(self.origins, self.proxy_certificate)
        self.peer = await ProxyH2.open(self.origins.proxy, self.proxy_certificate)
        self.addAsyncCleanup(self.peer.close)

    async def tunnel(self) -> TunnelTls:
        stream = await self.peer.connect(self.origins.proxy)
        tls = TunnelTls(stream, stream, self.certificate, ("h2", "http/1.1"))
        await asyncio.wait_for(tls.handshake(), 3)
        self.assertEqual(tls.tls.selected_alpn_protocol(), "http/1.1")
        return tls

    async def upgrade(self, index: int) -> TunnelTls:
        tls = await self.tunnel()
        tls.write(
            f"GET /ws?i={index} HTTP/1.1\r\nHost: {HOSTNAME}\r\n".encode()
            + b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
            + b"Sec-WebSocket-Version: 13\r\n"
            + b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
        )
        await tls.drain()
        head = await asyncio.wait_for(tls.readuntil(b"\r\n\r\n"), 3)
        self.assertTrue(head.startswith(b"HTTP/1.1 101 Switching Protocols\r\n"))
        self.assertIn(b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", head)
        return tls

    async def close_websocket(self, tls: TunnelTls) -> None:
        tls.write(b"\x88\x82\x01\x02\x03\x04\x02\xea")
        await tls.drain()
        self.assertEqual(
            await asyncio.wait_for(tls.readexactly(4), 3), b"\x88\x02\x03\xe8"
        )
        self.assertEqual(await asyncio.wait_for(tls.read(1), 3), b"")
        tls.close()
        await tls.wait_closed()

    async def https_requests(self) -> None:
        tls = await self.tunnel()
        try:
            for index in (2, 3):
                await connect.ConnectBackupTests.request(
                    self, (tls, tls), f"/fast?i={index}"
                )
        finally:
            tls.close()
            await tls.wait_closed()

    async def finish_page(self) -> None:
        listener = await asyncio.start_server(self.origins.accept_page, "127.0.0.1", 0)
        self.origins.listeners.append(listener)
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", listener.sockets[0].getsockname()[1]
        )
        try:
            writer.write(b"GET /done HTTP/1.1\r\nHost: localhost\r\n\r\n")
            await writer.drain()
            self.assertTrue(
                (await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 3)).startswith(
                    b"HTTP/1.1 200 OK\r\n"
                )
            )
            self.assertEqual(await asyncio.wait_for(reader.readexactly(3), 3), b"ok\n")
        finally:
            await hooks.close_writer(writer, None)
        self.assertTrue(self.origins.done.is_set())

    async def test_first_secure_request_is_wss_and_completion_requires_real_closes(
        self,
    ):
        first = await self.upgrade(0)
        self.assertEqual(
            await asyncio.wait_for(first.readexactly(6), 7), b"\x81\x04tick"
        )
        second = await self.upgrade(1)
        self.assertEqual(len(self.origins.open), 2)
        await self.close_websocket(first)
        await self.close_websocket(second)
        await self.https_requests()
        with self.assertRaisesRegex(ValueError, "page did not complete"):
            hooks.validate_connect_run(self.origins)
        await self.finish_page()
        hooks.validate_connect_run(self.origins)
        self.assertEqual(
            [[path for _, path in row.requests] for row in self.origins.connections],
            [["/ws?i=0"], ["/ws?i=1"], ["/fast?i=2", "/fast?i=3"]],
        )
        self.assertEqual(
            [row.websocket.close_code for row in self.origins.connections[:2]],
            [1000, 1000],
        )
        records = hooks.connect_observations(self.origins, 0)
        self.assertEqual([row["proxy_connection"] for row in records], [0, 0, 0])
        self.assertEqual([row["stream_id"] for row in records], [1, 3, 5])
        self.assertEqual([row["origin_connection"] for row in records], [0, 1, 2])
        self.assertTrue(all(row["status"] == 200 for row in records))

        result = SimpleNamespace(
            origins=self.origins,
            reports=[],
            errors=[],
            start_ms=0,
            timed_out=False,
            launcher_process=False,
            moz_log=[],
        )
        rendered = "\n".join(hooks.render_run(0, result))
        self.assertIn("run_0_server_connection_0_websocket_close_code=1000", rendered)
        self.assertIn("run_0_server_connection_1_websocket_close_code=1000", rendered)
        for row in self.origins.connections:
            row.requests = [(0, path) for _, path in row.requests]
        self.origins.connections.reverse()
        hooks.validate_connect_run(self.origins)
        self.origins.connections.reverse()
        self.origins.request_order[0:2] = ["/ws?i=1", "/ws?i=0"]
        with self.assertRaisesRegex(ValueError, "labeled requests"):
            hooks.validate_connect_run(self.origins)
        self.origins.request_order[0:2] = ["/ws?i=0", "/ws?i=1"]
        first_connection = self.origins.connections[0]
        closed_ms = first_connection.closed_ms
        first_connection.closed_ms = None
        with self.assertRaisesRegex(ValueError, "cleanly close"):
            hooks.validate_connect_run(self.origins)
        first_connection.closed_ms = closed_ms
        for code in (None, 1001):
            with self.subTest(code=code):
                self.origins.connections[0].websocket.close_code = code
                with self.assertRaisesRegex(ValueError, "cleanly close"):
                    hooks.validate_connect_run(self.origins)
        self.origins.connections[0].websocket.close_code = 1000
        self.origins.connections[0].websocket.ticks_sent = 0
        with self.assertRaisesRegex(ValueError, "tick"):
            hooks.validate_connect_run(self.origins)
        self.origins.connections[0].websocket.ticks_sent = 1
        self.origins.connections[0].requests[0] = (0, "/fast?i=0")
        with self.assertRaisesRegex(ValueError, "labeled requests"):
            hooks.validate_connect_run(self.origins)
        await self.peer.close()
        await self.origins.shutdown()
        self.assertFalse(self.origins.cleanup_pending())
        self.assertFalse(self.origins.failures)

    async def test_https_before_websocket_closes_is_an_observed_peer_failure(self):
        await self.upgrade(0)
        await self.upgrade(1)
        with self.assertRaises(EOFError):
            await self.https_requests()
        await asyncio.wait_for(self.origins.failed.wait(), 3)
        self.assertTrue(
            any(
                "HTTPS before its WebSockets closed" in str(error)
                for error in self.origins.failures
            )
        )
        self.assertFalse(self.origins.done.is_set())

    async def test_reset_is_not_a_completed_websocket_close(self):
        tls = await self.upgrade(0)
        tls.close()
        await tls.wait_closed()
        await self.peer.close()
        await self.origins.shutdown()
        row = self.origins.connections[0]
        self.assertIsNone(row.websocket.close_code)
        self.assertIsNotNone(row.closed_ms)
        self.assertFalse(self.origins.cleanup_pending())

    async def test_eof_and_partial_close_have_no_successful_close_code(self):
        class Writer:
            def __init__(self):
                self.output = bytearray()

            def write(self, data):
                self.output.extend(data)

            async def drain(self):
                return

        for partial in (b"", b"\x88\x82\x01\x02\x03\x04\x02"):
            with self.subTest(partial=partial):
                reader = asyncio.StreamReader()
                reader.feed_data(partial)
                reader.feed_eof()
                writer = Writer()
                result = await hooks.serve_websocket(
                    reader,
                    writer,
                    b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
                )
                self.assertIsNone(result.close_code)
                self.assertEqual(result.ticks_sent, 0)
                self.assertNotIn(b"\x88\x02\x03\xe8", writer.output)


class FreshWssLaunchTests(unittest.IsolatedAsyncioTestCase):
    async def test_launch_gates_exact_wss_and_https_pac_without_browser_preferences(
        self,
    ):
        cause = OSError("stop before native launch")
        owners = []

        def native(owner, plan, url, config):
            owners.append(owner)
            origins = owner.origins
            self.assertEqual(origins.proxy.alpn, "h2")
            self.assertEqual(origins.target_url, f"wss://{HOSTNAME}:{origins.port}")
            self.assertTrue(url.startswith("http://127.0.0.1:"))
            pac = hooks.connect_pac(origins).decode()
            self.assertIn(f'host === "{HOSTNAME}"', pac)
            self.assertIn(f'url.indexOf("wss://{HOSTNAME}:{origins.port}/") === 0', pac)
            self.assertIn(
                f'url.indexOf("https://{HOSTNAME}:{origins.port}/") === 0', pac
            )
            self.assertIn('return "DIRECT";', pac)
            preferences = dict(plan.firefox_preferences)
            self.assertFalse(preferences["network.proxy.failover_direct"])
            self.assertNotIn("network.dns.disableIPv6", preferences)
            self.assertNotIn("network.http.http2.websockets", preferences)
            self.assertEqual(
                config, {"rewrite_host": hooks.TARGET_HOST, "rewrite_to": "localhost"}
            )
            self.assertIn("fetch('/go'", origins.page().decode())
            self.assertLess(
                origins.page().index(b"fetch('/go'"),
                origins.page().index(b"new WebSocket"),
            )
            rows = [
                row
                for row in plan.profile_files[0][1].splitlines()
                if row and not row.startswith("#")
            ]
            self.assertEqual(len(rows), 2)
            self.assertTrue(rows[0].startswith(f"{HOSTNAME}:{origins.port}:\t"))
            self.assertTrue(
                rows[1].startswith(f"{hooks.TARGET_HOST}:{origins.proxy.address[1]}:\t")
            )
            raise cause

        with (
            patch.object(hooks, "_FirefoxNative", side_effect=native),
            patch.object(hooks, "localhost_ipv6_free", return_value=True),
            self.assertRaises(OSError) as observed,
        ):
            await hooks.run_once(hooks.SCENARIOS[SCENE], Path("unused"), headful=True)
        self.assertIs(observed.exception, cause)
        self.assertFalse(owners[0].origins.cleanup_pending())

    def test_scene_reuses_the_existing_script_and_labels_inner_h1(self):
        scenario = hooks.SCENARIOS[SCENE]
        self.assertEqual(scenario.script, hooks.SCENARIOS["wss-backup"].script)
        fixture = hooks.render_fixture(
            client_version="157.0",
            build_id="20260924084938",
            operating_system="Windows test",
            frida_version="17.24.3",
            launch_arguments="--profile <temporary-profile>",
            scenario=scenario,
            runs=[],
            headful=True,
        )
        self.assertIn("\nproxy_alpn_offer=h2\n", fixture)
        self.assertIn("\norigin_alpn_offer=http/1.1\n", fixture)
        self.assertIn("\nscenario=wss-https-h2-proxy-backup\n", fixture)
