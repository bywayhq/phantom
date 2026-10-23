"""HTTPS CONNECT family scene with independently authenticated nested TLS."""

import asyncio
import contextlib
import ssl
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.capture import firefox_socket_hooks as hooks
from scripts.capture.http2_session import HOSTNAME, generate_certificate, server_context
from scripts.capture.tests import test_firefox_connect_backup as connect
from scripts.capture.tests.tunnelled_websocket_peer import TunnelTls


class HttpsConnectBackupTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.origins = hooks.Origins(hooks.SCENARIOS["https-connect-backup"])
        self.addAsyncCleanup(self.origins.shutdown)
        self.certificate = generate_certificate(HOSTNAME)
        self.proxy_certificate = generate_certificate(hooks.TARGET_HOST)
        context = server_context(self.certificate)
        context.set_alpn_protocols(["http/1.1"])
        target = await asyncio.start_server(
            self.origins.accept_target, "127.0.0.1", 0, ssl=context
        )
        self.origins.listeners.append(target)
        self.origins.port = target.sockets[0].getsockname()[1]
        await hooks.start_connect_proxy(self.origins, self.proxy_certificate)
        self.proxy = self.origins.proxy

    async def proxy_stream(
        self, alpn: str = "http/1.1"
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        context = ssl.create_default_context(
            cadata=self.proxy_certificate.certificate_pem.decode()
        )
        context.set_alpn_protocols([alpn])
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                *self.proxy.address, ssl=context, server_hostname=hooks.TARGET_HOST
            ),
            3,
        )
        self.addAsyncCleanup(hooks.close_writer, writer, None)
        self.assertEqual(
            writer.get_extra_info("ssl_object").selected_alpn_protocol(),
            "http/1.1" if alpn == "http/1.1" else None,
        )
        return reader, writer

    async def tunnel(self) -> tuple[TunnelTls, TunnelTls]:
        reader, writer = await self.proxy_stream()
        authority = f"{HOSTNAME}:{self.origins.port}"
        writer.write(
            f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode()
        )
        await writer.drain()
        self.assertEqual(
            await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 3),
            b"HTTP/1.1 200 Connection Established\r\n\r\n",
        )
        inner = TunnelTls(reader, writer, self.certificate, ("h2", "http/1.1"))
        await asyncio.wait_for(inner.handshake(), 3)
        self.assertEqual(inner.tls.selected_alpn_protocol(), "http/1.1")
        return inner, inner

    async def request(self, stream: tuple[TunnelTls, TunnelTls], path: str) -> None:
        await connect.ConnectBackupTests.request(self, stream, path)

    async def test_nested_tls_completes_five_bodies_and_owned_origin_drop(self) -> None:
        await connect.ConnectBackupTests.test_real_connect_tls_requests_correlate_and_reuse(
            self
        )
        records = hooks.connect_observations(self.origins, 0)
        self.assertEqual([record["alpn"] for record in records], ["http/1.1"] * 2)
        self.assertNotEqual(
            self.certificate.sha256_fingerprint,
            self.proxy_certificate.sha256_fingerprint,
        )

    async def test_quiet_unused_outer_tls_closes_without_connect_or_origin(
        self,
    ) -> None:
        _, writer = await self.proxy_stream()
        await hooks.close_writer(writer, None)
        await self.origins.shutdown()
        records = hooks.connect_observations(self.origins, 0)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["alpn"], "http/1.1")
        self.assertEqual(records[0]["outcome"], "peer-disconnected")
        self.assertEqual(records[0]["opening_hex"], "")
        self.assertEqual(records[0]["reply_hex"], "")
        self.assertIsNone(records[0]["upstream"])
        self.assertFalse(self.origins.connections)
        self.assertFalse(self.origins.failures)
        self.assertFalse(self.origins.cleanup_pending())

    async def test_unowned_target_is_refused_inside_authenticated_proxy_tls(
        self,
    ) -> None:
        reader, writer = await self.proxy_stream()
        writer.write(b"CONNECT other.test:443 HTTP/1.1\r\nHost: other.test:443\r\n\r\n")
        await writer.drain()
        reply = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 3)
        self.assertTrue(reply.startswith(b"HTTP/1.1 403 Forbidden\r\n"))
        await self.origins.shutdown()
        self.assertFalse(self.origins.connections)
        self.assertIsNone(self.proxy.tunnel_run.openings[0].upstream)
        self.assertEqual(self.proxy.tunnel_run.openings[0].head, b"")
        self.assertFalse(self.origins.cleanup_pending())

    async def test_missing_outer_h1_alpn_fails_before_connect_or_origin(self) -> None:
        reader, _ = await self.proxy_stream(alpn="h2")
        self.assertEqual(await asyncio.wait_for(reader.read(1), 3), b"")
        await asyncio.wait_for(self.origins.failed.wait(), 3)
        self.assertEqual(
            str(self.origins.failures[0]), "Firefox HTTPS proxy requires HTTP/1.1 ALPN"
        )
        self.assertFalse(self.origins.connections)
        self.assertEqual(self.proxy.tunnel_run.openings[0].head, b"")

    async def test_cancelled_run_joins_nested_tls_and_partial_connect(self) -> None:
        stream = await self.tunnel()
        await self.request(stream, "/fast?i=0")
        _, partial = await self.proxy_stream()
        partial.write(b"CON")
        await partial.drain()
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
        try:
            remaining = await asyncio.wait_for(stream[0].read(1), 3)
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            # Closing both owned TLS transports can surface as a reset on Windows.
            pass
        else:
            self.assertEqual(remaining, b"")

    async def test_proxy_failure_remains_owned_and_visible(self) -> None:
        await connect.ConnectBackupTests.test_proxy_failure_wakes_owner_and_preserves_primary(
            self
        )


class HttpsConnectLaunchTests(unittest.IsolatedAsyncioTestCase):
    def test_fixture_distinguishes_outer_proxy_tls_from_origin_tls(self) -> None:
        fixture = hooks.render_fixture(
            client_version="157.0",
            build_id="20260924084938",
            operating_system="Windows test",
            frida_version="17.24.3",
            launch_arguments="--profile <temporary-profile>",
            scenario=hooks.SCENARIOS["https-connect-backup"],
            runs=[],
            headful=True,
        )
        self.assertIn("\ntarget=server.phantom.test\n", fixture)
        self.assertIn("\nproxy_hostname=127.0.0.1.nip.io\n", fixture)
        self.assertIn("\nproxy_mode=https-connect\n", fixture)
        self.assertIn("\nproxy_transport=tls\n", fixture)
        self.assertIn("\nproxy_alpn_offer=http/1.1\n", fixture)
        self.assertIn("\norigin_alpn_offer=http/1.1\n", fixture)
        self.assertIn("\nproxy_trust=separate disposable-profile", fixture)

    async def test_exact_origin_https_pac_and_two_profile_local_leaf_exceptions(
        self,
    ) -> None:
        cause = OSError("stop before native launch")
        owners = []

        def native(
            owner: hooks._FirefoxRun, plan: hooks.LaunchPlan, url: str, config: dict
        ) -> None:
            owners.append(owner)
            origins = owner.origins
            proxy_port = origins.proxy.address[1]
            self.assertEqual(url, f"http://127.0.0.1:{origins.page_port}/")
            self.assertEqual(origins.target_url, f"https://{HOSTNAME}:{origins.port}")
            self.assertEqual(
                hooks.connect_pac(origins).decode(),
                "function FindProxyForURL(url, host) {\n"
                f'  if (host === "{HOSTNAME}" && '
                f'url.indexOf("https://{HOSTNAME}:{origins.port}/") === 0) return '
                f'"HTTPS {hooks.TARGET_HOST}:{proxy_port}";\n'
                '  return "DIRECT";\n'
                "}\n",
            )
            self.assertFalse(
                dict(plan.firefox_preferences)["network.proxy.failover_direct"]
            )
            self.assertEqual(
                config, {"rewrite_host": hooks.TARGET_HOST, "rewrite_to": "localhost"}
            )
            self.assertEqual(len(plan.profile_files), 1)
            name, overrides = plan.profile_files[0]
            self.assertEqual(name, "cert_override.txt")
            rows = [
                row for row in overrides.splitlines() if row and not row.startswith("#")
            ]
            self.assertEqual(len(rows), 2)
            self.assertTrue(rows[0].startswith(f"{HOSTNAME}:{origins.port}:\t"))
            self.assertTrue(rows[1].startswith(f"{hooks.TARGET_HOST}:{proxy_port}:\t"))
            self.assertNotEqual(rows[0].split("\t")[2], rows[1].split("\t")[2])
            self.assertEqual(origins.proxy.mode, "https")
            self.assertEqual(origins.proxy.alpn, "h1")
            raise cause

        with (
            patch.object(hooks, "_FirefoxNative", side_effect=native) as launch,
            patch.object(hooks, "localhost_ipv6_free", return_value=True) as ipv6,
            self.assertRaises(OSError) as observed,
        ):
            await hooks.run_once(
                hooks.SCENARIOS["https-connect-backup"], Path("unused"), headful=True
            )
        self.assertIs(observed.exception, cause)
        owner = owners[0]
        self.assertFalse(owner.origins.cleanup_pending())
        self.assertFalse(launch.call_args.args[1].headless)
        ipv6.assert_called_once_with(owner.origins.proxy.address[1])


if __name__ == "__main__":
    unittest.main()
