import asyncio
import contextlib
import socket
import ssl
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.capture import firefox_socket_hooks as hooks
from scripts.capture.http2_session import HOSTNAME, generate_certificate, server_context


class Socks5BackupTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.origins = hooks.Origins(hooks.SCENARIOS["socks5-backup"])
        self.addAsyncCleanup(self.origins.shutdown)
        certificate = generate_certificate(HOSTNAME)
        context = server_context(certificate)
        context.set_alpn_protocols(["http/1.1"])
        target = await asyncio.start_server(
            self.origins.accept_target, "127.0.0.1", 0, ssl=context
        )
        self.origins.listeners.append(target)
        self.origins.port = target.sockets[0].getsockname()[1]
        await hooks.start_connect_proxy(self.origins, certificate)
        self.proxy = self.origins.proxy
        self.client = ssl.create_default_context(
            cadata=certificate.certificate_pem.decode()
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

    async def socks_opening(self, connection: socket.socket, host: bytes) -> bytes:
        loop = asyncio.get_running_loop()
        await loop.sock_sendall(connection, b"\x05\x01\x00")
        self.assertEqual(await self.receive(connection, 2), b"\x05\x00")
        await loop.sock_sendall(
            connection,
            b"\x05\x01\x00\x03"
            + bytes((len(host),))
            + host
            + self.origins.port.to_bytes(2, "big"),
        )
        return await self.receive(connection, 10)

    async def receive(self, connection: socket.socket, size: int) -> bytes:
        reply = bytearray()
        while len(reply) < size:
            data = await asyncio.wait_for(
                asyncio.get_running_loop().sock_recv(connection, size - len(reply)), 3
            )
            self.assertTrue(data, "SOCKS5 peer closed before its reply")
            reply.extend(data)
        return bytes(reply)

    async def tunnel(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        connection = await self.proxy_socket()
        reply = await self.socks_opening(connection, b"server.phantom.test")
        self.assertEqual(reply[:8], b"\x05\x00\x00\x01\x7f\x00\x00\x01")
        self.assertNotEqual(reply[8:], b"\x00\x00")
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                sock=connection, ssl=self.client, server_hostname=HOSTNAME
            ),
            3,
        )
        self.addAsyncCleanup(hooks.close_writer, writer, None)
        self.assertEqual(
            writer.get_extra_info("ssl_object").selected_alpn_protocol(), "http/1.1"
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
        self.assertEqual(await asyncio.wait_for(reader.readexactly(3), 3), b"ok\n")

    async def test_domain_socks5_tls_requests_reuse_drop_and_correlate(self) -> None:
        first = await self.tunnel()
        await self.request(first, "/fast?i=0")
        with patch.object(hooks, "SLOW_RESPONSE_SECONDS", 0):
            for index in (1, 2, 3):
                await self.request(first, f"/slow?i={index}")
        page = await asyncio.start_server(self.origins.accept_page, "127.0.0.1", 0)
        self.origins.listeners.append(page)
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", page.sockets[0].getsockname()[1]
        )
        self.addAsyncCleanup(hooks.close_writer, writer, None)
        writer.write(b"GET /drop HTTP/1.1\r\nHost: localhost\r\n\r\n")
        await writer.drain()
        await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 3)
        self.assertEqual(await asyncio.wait_for(reader.readexactly(3), 3), b"ok\n")
        self.assertEqual(await asyncio.wait_for(first[0].read(1), 3), b"")
        self.assertEqual(self.origins.connections[0].close_kind, "server")
        second = await self.tunnel()
        await self.request(second, "/fast?i=4")
        await hooks.close_writer(second[1], None)
        await self.origins.shutdown()
        self.assertFalse(self.origins.cleanup_pending())
        self.assertFalse(self.origins.failures)
        hooks.validate_connect_run(self.origins)
        records = hooks.connect_observations(self.origins, 0)
        self.assertEqual([record["origin_connection"] for record in records], [0, 1])
        expected = (
            b"\x05\x01\x00\x05\x01\x00\x03\x13server.phantom.test"
            + self.origins.port.to_bytes(2, "big")
        )
        for record in records:
            self.assertEqual(bytes.fromhex(record["opening_hex"]), expected)
            self.assertTrue(
                bytes.fromhex(record["reply_hex"]).startswith(b"\x05\x00\x05\x00")
            )
            self.assertIsNotNone(record["finished_ms"])
        self.proxy.tunnel_run.openings[
            0
        ].head = b"\x05\x01\x00\x05\x01\x00\x01\x7f\0\0\x01"
        with self.assertRaisesRegex(ValueError, "remote hostname"):
            hooks.validate_connect_run(self.origins)

    async def test_quiet_unused_proxy_socket_fin_has_no_socks_reply(self) -> None:
        connection = await self.proxy_socket()
        connection.shutdown(socket.SHUT_WR)
        self.assertEqual(
            await asyncio.wait_for(
                asyncio.get_running_loop().sock_recv(connection, 32), 3
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
        self.assertFalse(self.origins.cleanup_pending())
        self.assertFalse(self.origins.failures)

    async def test_unowned_socks_target_is_refused_before_origin_io(self) -> None:
        connection = await self.proxy_socket()
        reply = await self.socks_opening(connection, b"unowned.invalid")
        self.assertEqual(reply, b"\x05\x02\x00\x01\0\0\0\0\0\0")
        await self.origins.shutdown()
        self.assertFalse(self.origins.connections)
        self.assertIsNone(self.proxy.tunnel_run.openings[0].upstream)
        self.assertFalse(self.origins.cleanup_pending())

    async def test_unsupported_socks_method_is_refused_without_origin_io(self) -> None:
        connection = await self.proxy_socket()
        await asyncio.get_running_loop().sock_sendall(connection, b"\x05\x01\x02")
        self.assertEqual(await self.receive(connection, 2), b"\x05\xff")
        await self.origins.shutdown()
        self.assertFalse(self.origins.connections)
        self.assertIsNone(self.proxy.tunnel_run.openings[0].upstream)
        self.assertFalse(self.origins.cleanup_pending())

    async def test_cancelled_owner_joins_active_tls_and_partial_socks(self) -> None:
        stream = await self.tunnel()
        await self.request(stream, "/fast?i=0")
        partial = await self.proxy_socket()
        await asyncio.get_running_loop().sock_sendall(partial, b"\x05\x01")
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
            with contextlib.suppress(asyncio.CancelledError):
                await task
        self.assertFalse(self.origins.cleanup_pending())
        self.assertFalse(self.origins.failures)
        self.assertEqual(await asyncio.wait_for(stream[0].read(1), 3), b"")


class Socks5LaunchTests(unittest.IsolatedAsyncioTestCase):
    def test_fixture_separates_proxy_endpoint_from_remote_origin(self) -> None:
        fixture = hooks.render_fixture(
            client_version="157.0",
            build_id="20260924084938",
            operating_system="Windows test",
            frida_version="17.24.3",
            launch_arguments="--profile <temporary-profile>",
            scenario=hooks.SCENARIOS["socks5-backup"],
            runs=[],
            headful=True,
        )
        self.assertIn("\ntarget=server.phantom.test\n", fixture)
        self.assertIn("\nproxy_hostname=127.0.0.1.nip.io\n", fixture)
        self.assertIn("\nproxy_mode=socks5\n", fixture)
        self.assertIn("\nproxy_dns=remote\n", fixture)
        self.assertIn("\norigin_alpn_offer=http/1.1\n", fixture)

    async def test_pac_keeps_bootstrap_direct_and_rewrites_only_physical_proxy(
        self,
    ) -> None:
        cause = OSError("stop before native launch")
        owners = []

        def native(
            owner: hooks._FirefoxRun, plan: hooks.LaunchPlan, url: str, config: dict
        ) -> None:
            owners.append(owner)
            origins = owner.origins
            self.assertEqual(url, f"http://127.0.0.1:{origins.page_port}/")
            self.assertEqual(
                origins.target_url, f"https://server.phantom.test:{origins.port}"
            )
            self.assertEqual(
                hooks.connect_pac(origins),
                (
                    "function FindProxyForURL(url, host) {\n"
                    '  if (host === "server.phantom.test" && '
                    f'url.indexOf("https://server.phantom.test:{origins.port}/") === 0) return '
                    f'"SOCKS5 127.0.0.1.nip.io:{origins.proxy.address[1]}";\n'
                    '  return "DIRECT";\n}\n'
                ).encode(),
            )
            self.assertEqual(
                config, {"rewrite_host": hooks.TARGET_HOST, "rewrite_to": "localhost"}
            )
            preferences = dict(plan.firefox_preferences)
            self.assertEqual(preferences["network.proxy.type"], 2)
            self.assertFalse(preferences["network.proxy.failover_direct"])
            self.assertEqual(preferences["network.proxy.no_proxies_on"], "")
            self.assertNotIn("network.dns.disableIPv6", preferences)
            self.assertNotIn("network.proxy.socks5_remote_dns", preferences)
            self.assertEqual(plan.profile_files[0][0], "cert_override.txt")
            self.assertIn(f"{HOSTNAME}:{origins.port}", plan.profile_files[0][1])
            raise cause

        with (
            patch.object(hooks, "_FirefoxNative", side_effect=native),
            patch.object(hooks, "localhost_ipv6_free", return_value=True) as ipv6,
            self.assertRaises(OSError) as observed,
        ):
            await hooks.run_once(
                hooks.SCENARIOS["socks5-backup"], Path("unused"), headful=True
            )
        self.assertIs(observed.exception, cause)
        self.assertFalse(owners[0].origins.cleanup_pending())
        ipv6.assert_called_once_with(owners[0].origins.proxy.address[1])


if __name__ == "__main__":
    unittest.main()
