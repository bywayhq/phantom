"""Firefox family-scene ownership over real H2 CONNECT and nested TLS."""

import asyncio
import json
import re
import ssl
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.capture import firefox_socket_hooks as hooks
from scripts.capture.http2_session import (
    HOSTNAME,
    CaptureRun,
    ServerPolicy,
    TlsChannel,
    generate_certificate,
    server_context,
)
from scripts.capture.tests import test_firefox_connect_backup as connect
from scripts.capture.tests.tunnelled_websocket_peer import ProxyH2, TunnelTls
from scripts.capture.websocket_tunnel import PROXY_HOST, TunnelOrigin


class H2ConnectFixtureTests(unittest.TestCase):
    def test_retained_streams_link_to_physical_proxy_connections(self) -> None:
        fixture = (
            Path(__file__).resolve().parents[3]
            / "fixtures/socket-hooks/firefox/157.0/windows-11-26200"
            / "hooks-https-h2-connect-backup.txt"
        )
        fields = dict(row.split("=", 1) for row in fixture.read_text().splitlines())
        self.assertEqual(fields["run_0_timed_out"], "false")
        self.assertEqual(fields["run_0_hook_error_count"], "0")
        self.assertEqual(fields["proxy_alpn_offer"], "h2")
        connections = [
            json.loads(fields[f"run_0_proxy_connection_{i}"])
            for i in range(int(fields["run_0_proxy_connection_count"]))
        ]
        tunnels = [
            json.loads(fields[f"run_0_proxy_tunnel_{i}"])
            for i in range(int(fields["run_0_proxy_tunnel_count"]))
        ]
        self.assertEqual(len(connections), 2)
        self.assertEqual(len(tunnels), 4)
        self.assertEqual(
            [tunnel["origin_connection"] for tunnel in tunnels], [0, 1, 2, 3]
        )
        seen = set()
        for tunnel in tunnels:
            connection = connections[tunnel["proxy_connection"]]
            self.assertEqual(connection["alpn"], "h2")
            self.assertEqual(tunnel["peer"], connection["peer"])
            self.assertEqual(tunnel["status"], 200)
            self.assertEqual(tunnel["stream_id"] % 2, 1)
            identity = (tunnel["proxy_connection"], tunnel["stream_id"])
            self.assertNotIn(identity, seen)
            seen.add(identity)
            headers = [
                (bytes.fromhex(name), bytes.fromhex(value))
                for name, value in tunnel["headers"]
            ]
            self.assertEqual(headers[0], (b":method", b"CONNECT"))
            self.assertEqual(
                headers[1],
                (b":authority", f"{HOSTNAME}:{fields['run_0_origin_port']}".encode()),
            )

        paths = []
        for index in range(int(fields["run_0_server_connection_count"])):
            origin = fields[f"run_0_server_connection_{index}"]
            self.assertIn(",alpn:http/1.1", origin)
            paths.extend(re.findall(r"/(?:fast|slow)\?i=\d+", origin))
        self.assertEqual(
            sorted(paths),
            ["/fast?i=0", "/fast?i=4", "/slow?i=1", "/slow?i=2", "/slow?i=3"],
        )


class H2ConnectBackupTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.origins = hooks.Origins(hooks.SCENARIOS["https-h2-connect-backup"])
        self.addAsyncCleanup(self.origins.shutdown)
        self.certificate = generate_certificate(HOSTNAME)
        self.proxy_certificate = generate_certificate(PROXY_HOST)
        context = server_context(self.certificate)
        context.set_alpn_protocols(["http/1.1"])
        target = await asyncio.start_server(
            self.origins.accept_target, "127.0.0.1", 0, ssl=context
        )
        self.origins.listeners.append(target)
        self.origins.port = target.sockets[0].getsockname()[1]
        await hooks.start_connect_proxy(self.origins, self.proxy_certificate)
        self.proxy = self.origins.proxy

    async def peer(self) -> ProxyH2:
        peer = await ProxyH2.open(self.proxy, self.proxy_certificate)
        self.addAsyncCleanup(peer.close)
        return peer

    async def tunnel(self, peer: ProxyH2) -> TunnelTls:
        stream = await peer.connect(self.proxy)
        tls = TunnelTls(stream, stream, self.certificate, ("h2", "http/1.1"))
        await asyncio.wait_for(tls.handshake(), 3)
        self.assertEqual(tls.tls.selected_alpn_protocol(), "http/1.1")
        return tls

    async def request(self, tls: TunnelTls, path: str) -> None:
        await connect.ConnectBackupTests.request(self, (tls, tls), path)

    async def test_five_bodies_and_origin_drop_keep_one_outer_connection(self) -> None:
        peer = await self.peer()
        first = await self.tunnel(peer)
        await self.request(first, "/fast?i=0")
        second = await self.tunnel(peer)
        third = await self.tunnel(peer)
        with patch.object(hooks, "SLOW_RESPONSE_SECONDS", 0):
            await asyncio.gather(
                self.request(first, "/slow?i=1"),
                self.request(second, "/slow?i=2"),
                self.request(third, "/slow?i=3"),
            )

        page = await asyncio.start_server(self.origins.accept_page, "127.0.0.1", 0)
        self.origins.listeners.append(page)
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", page.sockets[0].getsockname()[1]
        )
        self.addAsyncCleanup(hooks.close_writer, writer, None)
        writer.write(b"GET /drop HTTP/1.1\r\nHost: localhost\r\n\r\n")
        await writer.drain()
        self.assertTrue(
            (await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 3)).startswith(
                b"HTTP/1.1 200 OK\r\n"
            )
        )
        self.assertEqual(await asyncio.wait_for(reader.readexactly(3), 3), b"ok\n")
        self.assertEqual(await asyncio.wait_for(first.read(1), 3), b"")
        self.assertEqual(self.origins.connections[0].close_kind, "server")
        await peer.ping()

        fourth = await self.tunnel(peer)
        await self.request(fourth, "/fast?i=4")
        await peer.close()
        await self.origins.shutdown()
        hooks.validate_connect_run(self.origins)
        self.assertFalse(self.origins.cleanup_pending())
        self.assertFalse(self.origins.failures)
        records = hooks.connect_observations(self.origins, 0)
        self.assertEqual([row["origin_connection"] for row in records], [0, 1, 2, 3])
        self.assertEqual([row["proxy_connection"] for row in records], [0, 0, 0, 0])
        self.assertEqual([row["stream_id"] for row in records], [1, 3, 5, 7])
        self.assertEqual([row["alpn"] for row in records], ["h2"] * 4)
        self.assertEqual([row["status"] for row in records], [200] * 4)
        self.assertTrue(all(row["finished_ms"] is not None for row in records))
        for row in records:
            self.assertEqual(
                row["headers"],
                [
                    [b":method".hex(), b"CONNECT".hex()],
                    [
                        b":authority".hex(),
                        f"{HOSTNAME}:{self.origins.port}".encode().hex(),
                    ],
                ],
            )

        rendered = self.rendered()
        self.assertEqual(rendered["run_0_proxy_connection_count"], "1")
        self.assertEqual(rendered["run_0_proxy_tunnel_count"], "4")
        self.assertEqual(
            json.loads(rendered["run_0_proxy_tunnel_3"])["origin_connection"], 3
        )
        self.assertEqual(json.loads(rendered["run_0_proxy_connection_0"])["alpn"], "h2")

        opening = self.proxy.tunnel_run.openings[-1]
        for index, stream in ((99, 7), (0, 1), (0, 2)):
            with self.subTest(connection=index, stream=stream):
                opening.proxy_connection, opening.stream_id = index, stream
                with self.assertRaisesRegex(ValueError, "lost its proxy connection"):
                    hooks.validate_connect_run(self.origins)
        opening.proxy_connection, opening.stream_id = 0, 7
        self.origins.connections[-1].peer = "127.0.0.1:1"
        with self.assertRaisesRegex(ValueError, "bypassed its CONNECT relay"):
            hooks.validate_connect_run(self.origins)

    def rendered(self) -> dict[str, str]:
        return dict(
            row.split("=", 1)
            for row in hooks.render_run(
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
        )

    async def test_same_stream_id_on_two_physical_connections_is_distinct(self) -> None:
        first_peer, second_peer = await self.peer(), await self.peer()
        first, second = await self.tunnel(first_peer), await self.tunnel(second_peer)
        await self.request(first, "/fast?i=0")
        with patch.object(hooks, "SLOW_RESPONSE_SECONDS", 0):
            for index in (1, 2, 3):
                await self.request(first, f"/slow?i={index}")
        await self.request(second, "/fast?i=4")
        await first_peer.close()
        await second_peer.close()
        await self.origins.shutdown()
        hooks.validate_connect_run(self.origins)
        records = hooks.connect_observations(self.origins, 0)
        self.assertEqual([row["stream_id"] for row in records], [1, 1])
        self.assertEqual([row["proxy_connection"] for row in records], [0, 1])
        self.assertEqual([row["origin_connection"] for row in records], [0, 1])
        self.assertEqual(self.rendered()["run_0_proxy_connection_count"], "2")

    async def test_rejected_target_does_not_open_an_origin_or_poison_proxy(
        self,
    ) -> None:
        peer = await self.peer()
        await peer.connect(self.proxy, target=b"other.test:443", status=b"403")
        await peer.ping()
        self.assertFalse(self.origins.connections)
        record = hooks.connect_observations(self.origins, 0)[0]
        self.assertEqual(record["status"], 403)
        self.assertEqual(record["outcome"], "rejected")
        self.assertIsNone(record["upstream"])
        tls = await self.tunnel(peer)
        await self.request(tls, "/fast?i=0")

    async def test_reset_one_tunnel_preserves_its_sibling(self) -> None:
        peer = await self.peer()
        first, second = await self.tunnel(peer), await self.tunnel(peer)
        first.close()
        await first.wait_closed()
        await self.request(second, "/fast?i=0")
        await peer.ping()
        await peer.close()
        await self.origins.shutdown()
        self.assertFalse(self.origins.cleanup_pending())
        self.assertFalse(self.origins.failures)
        self.assertEqual(self.proxy.tunnel_run.openings[0].outcome, "client-reset")

    async def test_shutdown_joins_partial_inner_tls_and_outer_connection(self) -> None:
        origin = TunnelOrigin(self.certificate)
        self.addAsyncCleanup(origin.close)
        origin.begin_run(CaptureRun("partial-tls", ServerPolicy(), {}))
        await origin.start("127.0.0.1")
        self.proxy.origin = origin.tls_address
        received = asyncio.Event()
        partial = bytearray()
        read_raw = TlsChannel.read_raw

        async def read(channel: TlsChannel) -> bytes:
            data = await read_raw(channel)
            if channel.run is origin.run:
                partial.extend(data)
                if len(partial) >= 2:
                    received.set()
            return data

        peer = await self.peer()
        with patch.object(TlsChannel, "read_raw", read):
            stream = await peer.connect(self.proxy)
            stream.write(b"\x16\x03")
            await stream.drain()
            await asyncio.wait_for(received.wait(), 3)
            self.assertEqual(partial, b"\x16\x03")
            # Drain preceding H2 frames before the server closes its connection.
            await peer.ping()
            await self.origins.shutdown()
            await origin.close()

        self.assertFalse(self.origins.cleanup_pending())
        self.assertFalse(self.origins.failures)
        self.assertEqual(len(self.proxy.tunnel_run.proxy_connections), 1)
        self.assertFalse(origin.handlers or origin.writers or origin.protocols)
        self.assertEqual(len(origin.run.connections), 1)
        self.assertIsNone(origin.run.connections[0].alpn)

    async def test_missing_h2_alpn_fails_before_connect_or_origin(self) -> None:
        context = ssl.create_default_context(
            cadata=self.proxy_certificate.certificate_pem.decode()
        )
        context.set_alpn_protocols(["http/1.1"])
        reader, writer = await asyncio.open_connection(
            *self.proxy.address, ssl=context, server_hostname=PROXY_HOST
        )
        self.addAsyncCleanup(hooks.close_writer, writer, None)
        self.assertEqual(await asyncio.wait_for(reader.read(1), 3), b"")
        await asyncio.wait_for(self.origins.failed.wait(), 3)
        self.assertEqual(
            str(self.origins.failures[0]), "the HTTPS proxy did not negotiate HTTP/2"
        )
        self.assertFalse(self.origins.connections)
        self.assertFalse(self.proxy.tunnel_run.openings)


class H2ConnectLaunchTests(unittest.IsolatedAsyncioTestCase):
    def test_fixture_names_outer_h2_and_inner_h1(self) -> None:
        fixture = hooks.render_fixture(
            client_version="157.0",
            build_id="20260924084938",
            operating_system="Windows test",
            frida_version="17.24.3",
            launch_arguments="--profile <temporary-profile>",
            scenario=hooks.SCENARIOS["https-h2-connect-backup"],
            runs=[],
            headful=True,
        )
        self.assertIn("\nproxy_mode=https-connect\n", fixture)
        self.assertIn("\nproxy_alpn_offer=h2\n", fixture)
        self.assertIn("\norigin_alpn_offer=http/1.1\n", fixture)
        self.assertIn("\nhook_intervention=getaddrinfo(", fixture)

    async def test_launch_keeps_exact_pac_scoped_trust_and_lookup(self) -> None:
        cause = OSError("stop before native launch")
        owners = []

        def native(owner, plan, url, config):
            owners.append(owner)
            origins = owner.origins
            self.assertEqual(origins.proxy.alpn, "h2")
            self.assertEqual(origins.target_url, f"https://{HOSTNAME}:{origins.port}")
            self.assertIn(
                f'"HTTPS {hooks.TARGET_HOST}:{origins.proxy.address[1]}"',
                hooks.connect_pac(origins).decode(),
            )
            self.assertFalse(
                dict(plan.firefox_preferences)["network.proxy.failover_direct"]
            )
            self.assertEqual(
                config, {"rewrite_host": hooks.TARGET_HOST, "rewrite_to": "localhost"}
            )
            rows = [
                row
                for row in plan.profile_files[0][1].splitlines()
                if row and not row.startswith("#")
            ]
            self.assertTrue(rows[0].startswith(f"{HOSTNAME}:{origins.port}:\t"))
            self.assertTrue(
                rows[1].startswith(f"{hooks.TARGET_HOST}:{origins.proxy.address[1]}:\t")
            )
            self.assertEqual(len(rows), 2)
            self.assertNotEqual(rows[0].split("\t")[2], rows[1].split("\t")[2])
            raise cause

        with (
            patch.object(hooks, "_FirefoxNative", side_effect=native),
            patch.object(hooks, "localhost_ipv6_free", return_value=True),
            self.assertRaises(OSError) as observed,
        ):
            await hooks.run_once(
                hooks.SCENARIOS["https-h2-connect-backup"], Path("unused"), headful=True
            )
        self.assertIs(observed.exception, cause)
        self.assertFalse(owners[0].origins.cleanup_pending())
