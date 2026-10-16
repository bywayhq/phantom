"""Tunnel parser refusal, budget and error ownership boundaries."""

import asyncio
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from scripts.capture.http2_session import (
    MAX_REQUEST_HEAD,
    CaptureFailures,
    generate_certificate,
)
from scripts.capture.tests.tunnelled_websocket_peer import TIMEOUT, open_proxy, servers
from scripts.capture.tunnelled_websocket import launch_plan
from scripts.capture.websocket_tunnel import (
    MODES,
    PROXY_HOST,
    OpeningReader,
    RejectedOpening,
    connect_head,
    correlate,
)


def failures(error):
    result, pending, seen = [], [error], set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        result.append(current)
        if isinstance(current, CaptureFailures):
            pending.extend(current.cleanup)
            if current.primary is not None:
                pending.append(current.primary)
        if current.__cause__ is not None:
            pending.append(current.__cause__)
    return result


class TunnelRefusalTests(unittest.IsolatedAsyncioTestCase):
    async def test_connect_rejects_foreign_targets_credentials_and_malformed_fields(
        self,
    ):
        for mode in ("http", "https"):
            async with servers(mode) as (
                origin,
                proxy,
                run,
                tunnels,
                _,
                proxy_certificate,
            ):
                target = f"server.phantom.test:{proxy.origin[1]}".encode()
                good = b"CONNECT " + target + b" HTTP/1.1\r\nHost: " + target
                heads = [
                    b"CONNECT other.test:443 HTTP/1.1\r\nHost: other.test:443",
                    b"CONNECT " + target + b"9 HTTP/1.1\r\nHost: " + target + b"9",
                    b"GET / HTTP/1.1\r\nHost: " + target,
                    good + b"\r\nHost: " + target,
                    b"CONNECT " + target + b" HTTP/1.1\r\nHost: other.test",
                    good + b"\r\nAuthorization: private-value",
                    good + b"\r\nProxy-Authorization: private-value",
                    good + b"\r\nCookie: private-value",
                    good + b"\r\nContent-Length: 0",
                    good + b"\r\nTransfer-Encoding: chunked",
                    good + b"\r\n invalid: field",
                    good + b"\r\nX-Control: \x00",
                ]
                for head in heads:
                    with self.subTest(mode=mode, head=head.partition(b"\r\n")[0]):
                        reader, writer = await open_proxy(proxy, proxy_certificate)
                        try:
                            writer.write(head + b"\r\n\r\n")
                            await writer.drain()
                            reply = await asyncio.wait_for(reader.read(), TIMEOUT)
                            self.assertTrue(reply.startswith(b"HTTP/1.1 403"))
                        finally:
                            writer.close()
                            await asyncio.wait_for(writer.wait_closed(), TIMEOUT)
                await proxy.stop_connections()
                await origin.stop_connections()
                self.assertFalse(run.connections)
                self.assertEqual(len(tunnels.openings), len(heads))
                for opening in tunnels.openings:
                    self.assertEqual(opening.outcome, "rejected")
                    self.assertEqual(opening.head, b"")
                    self.assertFalse(opening.connection.client_chunks)
                    self.assertIsNone(opening.upstream)

    async def test_socks_rejects_auth_foreign_ports_and_malformed_commands(self):
        async with servers("socks5") as (
            origin,
            proxy,
            run,
            tunnels,
            _,
            proxy_certificate,
        ):
            name = b"server.phantom.test"
            valid = b"\x05\x01\x00\x03" + bytes((len(name),)) + name
            commands = [
                valid + (1).to_bytes(2, "big"),
                b"\x05\x01\x00\x03\x0aother.test" + proxy.origin[1].to_bytes(2, "big"),
                b"\x05\x02\x00\x03"
                + bytes((len(name),))
                + name
                + proxy.origin[1].to_bytes(2, "big"),
                b"\x05\x01\x00\x03\x01\xff" + proxy.origin[1].to_bytes(2, "big"),
                b"\x05\x01\x00\x09",
            ]
            for command in commands:
                reader, writer = await open_proxy(proxy, proxy_certificate)
                try:
                    writer.write(b"\x05\x01\x00")
                    await writer.drain()
                    self.assertEqual(await reader.readexactly(2), b"\x05\x00")
                    writer.write(command)
                    await writer.drain()
                    self.assertEqual(
                        (await asyncio.wait_for(reader.readexactly(10), TIMEOUT))[:2],
                        b"\x05\x02",
                    )
                finally:
                    writer.close()
                    await asyncio.wait_for(writer.wait_closed(), TIMEOUT)
            reader, writer = await open_proxy(proxy, proxy_certificate)
            try:
                writer.write(b"\x05\x01\x02")
                await writer.drain()
                self.assertEqual(
                    await asyncio.wait_for(reader.read(), TIMEOUT), b"\x05\xff"
                )
            finally:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), TIMEOUT)
            await proxy.stop_connections()
            self.assertFalse(run.connections)
            self.assertTrue(
                all(opening.outcome == "rejected" for opening in tunnels.openings)
            )
            self.assertTrue(all(not opening.head for opening in tunnels.openings))

    async def test_oversized_and_truncated_heads_have_bounded_parser_results(self):
        target = b"server.phantom.test:12345"
        prefix = b"CONNECT " + target + b" HTTP/1.1\r\nHost: " + target + b"\r\nX-Pad: "
        exact = prefix + b"a" * (MAX_REQUEST_HEAD - len(prefix) - 4) + b"\r\n\r\n"
        for data, accepted in (
            (exact, True),
            (exact[:-4] + b"a\r\n\r\n", False),
            (prefix, False),
        ):
            read = AsyncMock(side_effect=[data, b""])
            opening = OpeningReader(SimpleNamespace(read=read))
            if accepted:
                head = await opening.head()
                self.assertEqual(len(head), MAX_REQUEST_HEAD)
                connect_head(head, "127.0.0.1", 12345)
            else:
                with self.assertRaises(RejectedOpening):
                    await opening.head()
            self.assertLessEqual(read.await_count, 2)

    async def test_unknown_serving_failure_is_retained_and_all_owners_are_collected(
        self,
    ):
        error = OSError("deliberate non-peer I/O failure")
        proxy = None
        with self.assertRaises(BaseException) as raised:
            async with servers("http") as (_, proxy, _, _, _, proxy_certificate):
                with patch.object(proxy, "_opening", new=AsyncMock(side_effect=error)):
                    reader, writer = await open_proxy(proxy, proxy_certificate)
                    try:
                        self.assertEqual(
                            await asyncio.wait_for(reader.read(), TIMEOUT), b""
                        )
                    finally:
                        writer.close()
                        await asyncio.wait_for(writer.wait_closed(), TIMEOUT)
                    await proxy.stop_connections()
        self.assertIn(error, failures(raised.exception))
        self.assertFalse(proxy.handlers)
        self.assertFalse(proxy.writers)
        self.assertFalse(proxy.protocols)

    async def test_origin_refusal_is_an_explicit_proxy_response_without_forwarding(
        self,
    ):
        for mode in ("http", "socks5"):
            async with servers(mode) as (
                origin,
                proxy,
                _,
                tunnels,
                _,
                proxy_certificate,
            ):
                # Keep the actual assigned port, but close only its origin listener.
                origin.servers[0].close()
                await origin.servers[0].wait_closed()
                reader, writer = await open_proxy(proxy, proxy_certificate)
                try:
                    target = f"server.phantom.test:{proxy.origin[1]}".encode()
                    if mode == "http":
                        writer.write(
                            b"CONNECT "
                            + target
                            + b" HTTP/1.1\r\nHost: "
                            + target
                            + b"\r\n\r\n"
                        )
                    else:
                        name = b"server.phantom.test"
                        writer.write(
                            b"\x05\x01\x00\x05\x01\x00\x03"
                            + bytes((len(name),))
                            + name
                            + proxy.origin[1].to_bytes(2, "big")
                        )
                    await writer.drain()
                    reply = await asyncio.wait_for(reader.read(), TIMEOUT)
                    self.assertTrue(
                        reply.startswith(b"HTTP/1.1 502")
                        if mode == "http"
                        else reply.startswith(b"\x05\x00\x05\x05")
                    )
                finally:
                    writer.close()
                    await asyncio.wait_for(writer.wait_closed(), TIMEOUT)
                await proxy.stop_connections()
                self.assertEqual(tunnels.openings[0].outcome, "origin-refused")
                self.assertIsNone(tunnels.openings[0].upstream)

    async def test_correlation_rejects_origin_connections_that_bypass_the_tunnel(self):
        run = SimpleNamespace(
            origin=SimpleNamespace(connections=[object()]), openings=[]
        )
        with self.assertRaisesRegex(ValueError, "bypassed"):
            correlate(run, SimpleNamespace(endpoints={}))


class TunnelLaunchTests(unittest.TestCase):
    def test_fresh_profile_routes_and_scoped_trust_name_actual_ports(self):
        certificate, proxy_certificate = (
            generate_certificate(),
            generate_certificate(PROXY_HOST),
        )
        origin = SimpleNamespace(tls_address=("127.0.0.1", 31991))
        proxy = SimpleNamespace(address=("127.0.0.1", 31992))
        for browser in ("chrome", "firefox"):
            for mode in MODES:
                with self.subTest(browser=browser, mode=mode):
                    args = SimpleNamespace(
                        browser=browser,
                        browser_path=Path("browser.exe"),
                        headful=False,
                        proxy=mode,
                    )
                    plan = launch_plan(
                        args, origin, proxy, certificate, proxy_certificate
                    )
                    if browser == "chrome":
                        arguments = " ".join(plan.extra_arguments)
                        self.assertIn(f"--proxy-server={mode}://", arguments)
                        self.assertIn("31992", arguments)
                        self.assertIn(certificate.spki_sha256_base64, arguments)
                        self.assertIn(proxy_certificate.spki_sha256_base64, arguments)
                    else:
                        preferences = dict(plan.firefox_preferences)
                        self.assertEqual(preferences["network.proxy.no_proxies_on"], "")
                        self.assertTrue(plan.profile_files)
                        overrides = plan.profile_files[0][1]
                        self.assertIn("server.phantom.test:31991", overrides)
                        if mode == "https":
                            self.assertIn("proxy.phantom.test:31992", overrides)
                            self.assertIn(
                                "HTTPS proxy.phantom.test:31992",
                                preferences["network.proxy.autoconfig_url"],
                            )
                        if mode == "socks5":
                            self.assertTrue(
                                preferences["network.proxy.socks_remote_dns"]
                            )
