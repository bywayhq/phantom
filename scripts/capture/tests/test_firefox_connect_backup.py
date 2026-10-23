import asyncio
import contextlib
import socket
import ssl
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.capture import firefox_socket_hooks as hooks
from scripts.capture.http2_session import HOSTNAME, generate_certificate, server_context


class ConnectBackupTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.origins = hooks.Origins(hooks.SCENARIOS["http-connect-backup"])
        self.addAsyncCleanup(self.origins.shutdown)
        self.certificate = generate_certificate(HOSTNAME)
        context = server_context(self.certificate)
        context.set_alpn_protocols(["http/1.1"])
        target = await asyncio.start_server(
            self.origins.accept_target, "127.0.0.1", 0, ssl=context
        )
        self.origins.listeners.append(target)
        self.origins.port = target.sockets[0].getsockname()[1]
        await hooks.start_connect_proxy(self.origins, self.certificate)
        self.proxy = self.origins.proxy
        self.client = ssl.create_default_context(
            cadata=self.certificate.certificate_pem.decode()
        )
        self.client.set_alpn_protocols(["h2", "http/1.1"])

    async def proxy_socket(self) -> socket.socket:
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(connection.close)
        connection.setblocking(False)
        await asyncio.wait_for(
            asyncio.get_running_loop().sock_connect(connection, self.proxy.address), 3
        )
        return connection

    async def tunnel(
        self, alpn: str | None = "http/1.1"
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        connection = await self.proxy_socket()
        loop = asyncio.get_running_loop()
        authority = f"{HOSTNAME}:{self.origins.port}"
        await loop.sock_sendall(
            connection,
            f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode(),
        )
        reply = bytearray()
        while not reply.endswith(b"\r\n\r\n"):
            data = await asyncio.wait_for(loop.sock_recv(connection, 1), 3)
            self.assertTrue(data, "proxy closed before its CONNECT reply")
            reply.extend(data)
            self.assertLess(len(reply), 1024)
        self.assertEqual(reply, b"HTTP/1.1 200 Connection Established\r\n\r\n")
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                sock=connection, ssl=self.client, server_hostname=HOSTNAME
            ),
            3,
        )
        self.addAsyncCleanup(hooks.close_writer, writer, None)
        self.assertEqual(
            writer.get_extra_info("ssl_object").selected_alpn_protocol(), alpn
        )
        return reader, writer

    async def request(
        self, stream: tuple[asyncio.StreamReader, asyncio.StreamWriter], path: str
    ) -> None:
        reader, writer = stream
        writer.write(f"GET {path} HTTP/1.1\r\nHost: {HOSTNAME}\r\n\r\n".encode())
        await writer.drain()
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
        self.assertTrue(head.startswith(b"HTTP/1.1 200 OK\r\n"))
        self.assertIn(b"Access-Control-Allow-Origin: *\r\n", head)
        self.assertEqual(await asyncio.wait_for(reader.readexactly(3), 3), b"ok\n")

    async def test_real_connect_tls_requests_correlate_and_reuse(self) -> None:
        first = await self.tunnel()
        await self.request(first, "/fast?i=0")
        with patch.object(hooks, "SLOW_RESPONSE_SECONDS", 0):
            await self.request(first, "/slow?i=1")
            await self.request(first, "/slow?i=2")
            await self.request(first, "/slow?i=3")
        page = await asyncio.start_server(self.origins.accept_page, "127.0.0.1", 0)
        self.origins.listeners.append(page)
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", page.sockets[0].getsockname()[1]
        )
        self.addAsyncCleanup(hooks.close_writer, writer, None)
        writer.write(b"GET /drop HTTP/1.1\r\nHost: localhost\r\n\r\n")
        await writer.drain()
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 3)
        self.assertTrue(head.startswith(b"HTTP/1.1 200 OK\r\n"))
        self.assertEqual(await asyncio.wait_for(reader.readexactly(3), 3), b"ok\n")
        self.assertEqual(await asyncio.wait_for(first[0].read(1), 3), b"")
        self.assertEqual(self.origins.connections[0].close_kind, "server")
        second = await self.tunnel()
        await self.request(second, "/fast?i=4")
        await hooks.close_writer(second[1], None)
        await self.origins.shutdown()
        self.assertFalse(self.origins.cleanup_pending())
        self.assertFalse(self.origins.failures)
        self.assertEqual(len(self.origins.connections), 2)
        hooks.validate_connect_run(self.origins)
        records = hooks.connect_observations(self.origins, 0)
        self.assertEqual([record["origin_connection"] for record in records], [0, 1])
        for record in records:
            self.assertTrue(
                bytes.fromhex(record["opening_hex"]).startswith(b"CONNECT ")
            )
            self.assertIsNotNone(record["finished_ms"])
        rendered = hooks.render_run(
            0,
            SimpleNamespace(
                origins=self.origins,
                reports=[],
                errors=[],
                start_ms=0,
                timed_out=False,
                launcher_process=False,
                moz_log=[],
            ),
        )
        self.assertIn("run_0_proxy_connection_count=2", rendered)
        self.assertTrue(any(",alpn:http/1.1" in row for row in rendered))
        self.origins.connections[0].peer = "127.0.0.1:1"
        with self.assertRaisesRegex(ValueError, "bypassed its CONNECT relay"):
            hooks.validate_connect_run(self.origins)

    async def test_quiet_unused_proxy_socket_fin_sends_no_connect_reply(self) -> None:
        connection = await self.proxy_socket()
        connection.shutdown(socket.SHUT_WR)
        self.assertEqual(
            await asyncio.wait_for(
                asyncio.get_running_loop().sock_recv(connection, 1024), 3
            ),
            b"",
        )
        await self.origins.shutdown()
        records = hooks.connect_observations(self.origins, 0)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["outcome"], "peer-disconnected")
        self.assertEqual(records[0]["opening_hex"], "")
        self.assertEqual(records[0]["reply_hex"], "")
        self.assertIsNone(records[0]["upstream"])
        self.assertFalse(self.origins.connections)
        self.assertFalse(self.origins.failures)

    async def test_unowned_connect_target_is_rejected_without_origin_io(self) -> None:
        connection = await self.proxy_socket()
        loop = asyncio.get_running_loop()
        await loop.sock_sendall(
            connection,
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
        )
        reply = await asyncio.wait_for(loop.sock_recv(connection, 1024), 3)
        self.assertTrue(reply.startswith(b"HTTP/1.1 403 Forbidden\r\n"))
        await self.origins.shutdown()
        self.assertFalse(self.origins.connections)
        self.assertIsNone(self.proxy.tunnel_run.openings[0].upstream)
        self.assertEqual(self.proxy.tunnel_run.openings[0].head, b"")

    async def test_cleanup_joins_partial_connect_and_active_tls_peers(self) -> None:
        stream = await self.tunnel()
        await self.request(stream, "/fast?i=0")
        partial = await self.proxy_socket()
        await asyncio.get_running_loop().sock_sendall(partial, b"CON")
        await asyncio.wait_for(self.origins.shutdown(), 5)
        self.assertFalse(self.origins.cleanup_pending())
        self.assertFalse(self.origins.failures)
        self.assertEqual(await asyncio.wait_for(stream[0].read(1), 3), b"")

    async def test_proxy_failure_wakes_owner_and_preserves_primary(self) -> None:
        cause = ValueError("proxy input bound exceeded")
        self.proxy.failed(cause, self.proxy.run)
        self.assertTrue(self.origins.failed.is_set())
        self.assertIn(cause, self.origins.failures)
        await self.origins.shutdown()
        self.assertFalse(self.origins.cleanup_pending())
        self.assertIn(cause, self.origins.failures)

    async def test_cancelled_run_joins_the_relay_and_origin_owners(self) -> None:
        stream = await self.tunnel()
        await self.request(stream, "/fast?i=0")
        partial = await self.proxy_socket()
        await asyncio.get_running_loop().sock_sendall(partial, b"CON")
        owner = hooks._FirefoxRun(self.origins.scenario)
        owner.origins = self.origins
        self.origins.changed = owner.changed
        entered = asyncio.Event()

        async def running() -> None:
            primary = None
            try:
                entered.set()
                await owner.wait(asyncio.Event(), 30)
            except BaseException as error:
                primary = error
            cleanup = await owner.finish(primary)
            hooks.raise_browser_failures(primary, cleanup)

        task = asyncio.create_task(running())
        try:
            await asyncio.wait_for(entered.wait(), 3)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(task, 5)
        finally:
            if not task.done():
                task.cancel()
            # This test owns and requested cancellation of the run.
            with contextlib.suppress(asyncio.CancelledError):
                await task
        self.assertFalse(self.origins.cleanup_pending())
        self.assertFalse(self.origins.failures)

    async def test_connect_origin_rejects_missing_h1_alpn(self) -> None:
        self.client.set_alpn_protocols(["h2"])
        reader, _ = await self.tunnel(alpn=None)
        self.assertEqual(await asyncio.wait_for(reader.read(1), 3), b"")
        await asyncio.wait_for(self.origins.failed.wait(), 3)
        self.assertFalse(self.origins.connections[0].requests)
        self.assertEqual(
            str(self.origins.failures[0]),
            "Firefox CONNECT origin requires HTTP/1.1 ALPN",
        )


class ConnectLaunchTests(unittest.IsolatedAsyncioTestCase):
    async def test_only_https_uses_named_proxy_and_profile_trust(self) -> None:
        cause = OSError("stop before native launch")
        owners = []

        def native(
            owner: hooks._FirefoxRun, plan: hooks.LaunchPlan, url: str, config: dict
        ) -> None:
            owners.append(owner)
            origins = owner.origins
            self.assertEqual(url, f"http://127.0.0.1:{origins.page_port}/")
            self.assertEqual(origins.target_url, f"https://{HOSTNAME}:{origins.port}")
            self.assertEqual(
                dict(plan.firefox_preferences),
                {
                    "network.proxy.type": 1,
                    "network.proxy.ssl": hooks.TARGET_HOST,
                    "network.proxy.ssl_port": origins.proxy.address[1],
                    "network.proxy.allow_hijacking_localhost": True,
                    "network.proxy.no_proxies_on": "",
                },
            )
            self.assertEqual(
                config, {"rewrite_host": hooks.TARGET_HOST, "rewrite_to": "localhost"}
            )
            self.assertEqual(plan.profile_files[0][0], "cert_override.txt")
            self.assertIn(f"{HOSTNAME}:{origins.port}", plan.profile_files[0][1])
            raise cause

        for headful in (False, True):
            with (
                self.subTest(headful=headful),
                patch.object(hooks, "_FirefoxNative", side_effect=native) as launch,
                patch.object(hooks, "localhost_ipv6_free", return_value=True) as ipv6,
                self.assertRaises(OSError) as observed,
            ):
                await hooks.run_once(
                    hooks.SCENARIOS["http-connect-backup"],
                    Path("unused"),
                    headful=headful,
                )
            self.assertIs(observed.exception, cause)
            owner = owners[-1]
            self.assertFalse(owner.origins.cleanup_pending())
            self.assertEqual(launch.call_args.args[1].headless, not headful)
            ipv6.assert_called_once_with(owner.origins.proxy.address[1])

    async def test_moz_filter_keeps_proxy_and_origin_owners(self) -> None:
        stamp = "2026-10-23 16:32:22.000000 UTC"
        lines = [
            f"{stamp} - [Parent 1: Socket Thread]: V/nsHttp "
            "ConnectionEntry::ConnectionEntry [this=0x100000000 " + HOSTNAME + ":123]",
            f"{stamp} - [Parent 1: Socket Thread]: V/nsSocketTransport "
            f"nsSocketTransport::ResolveHost [this=0x200000000 {hooks.TARGET_HOST}:456]",
            f"{stamp} - [Parent 1: Socket Thread]: V/nsHttp "
            "ConnectionEntry::RecordIPFamilyPreference 0x100000000 af=2",
            f"{stamp} - [Parent 1: Socket Thread]: V/nsHttp "
            "SetupBackupTimer [this=0x200000000]",
            f"{stamp} - [Parent 1: Socket Thread]: V/nsHttp "
            "SetupBackupTimer [this=0x300000000]",
        ]
        retained = hooks.moz_log_lines(
            "\n".join(lines),
            123,
            0,
            endpoints=((HOSTNAME, 123), (hooks.TARGET_HOST, 456)),
        )
        self.assertEqual(len(retained), 4)
        self.assertIn(f"{HOSTNAME}:123", retained[0])
        self.assertIn(f"{hooks.TARGET_HOST}:456", retained[1])
        self.assertIn("RecordIPFamilyPreference p0 af=2", retained[2])
        self.assertIn("SetupBackupTimer [this=p1]", retained[3])


if __name__ == "__main__":
    unittest.main()
