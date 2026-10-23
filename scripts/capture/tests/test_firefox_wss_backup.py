import asyncio
import ssl
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.capture import firefox_socket_hooks as hooks
from scripts.capture.http2_session import generate_certificate, server_context


class WssBackupTests(unittest.IsolatedAsyncioTestCase):
    async def test_tls_upgrades_close_before_readable_https_reuse(self) -> None:
        for offered in (["h2", "http/1.1"], []):
            with self.subTest(offered=offered):
                await self.exchange(offered)

    async def exchange(self, offered: list[str]) -> None:
        origins = hooks.Origins(hooks.SCENARIOS["wss-backup"])
        self.addAsyncCleanup(origins.shutdown)
        certificate = generate_certificate(hooks.TARGET_HOST)
        context = server_context(certificate)
        context.set_alpn_protocols(["http/1.1"])
        listener = await asyncio.start_server(
            origins.accept_target, "127.0.0.1", 0, ssl=context
        )
        origins.listeners.append(listener)
        origins.port = listener.sockets[0].getsockname()[1]
        client = ssl.create_default_context(cadata=certificate.certificate_pem.decode())
        client.set_alpn_protocols(offered)

        async def connect() -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    "127.0.0.1",
                    origins.port,
                    ssl=client,
                    server_hostname=hooks.TARGET_HOST,
                ),
                2,
            )
            self.addAsyncCleanup(hooks.close_writer, writer, None)
            self.assertEqual(
                writer.get_extra_info("ssl_object").selected_alpn_protocol(),
                "http/1.1" if offered else None,
            )
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
        for reader, writer in (first, second):
            # A masked RFC 6455 close carrying status 1000.
            writer.write(b"\x88\x82\x01\x02\x03\x04\x02\xea")
            await writer.drain()
            self.assertEqual(
                await asyncio.wait_for(reader.readexactly(4), 2), b"\x88\x02\x03\xe8"
            )
            self.assertEqual(await asyncio.wait_for(reader.read(1), 2), b"")
            await hooks.close_writer(writer, None)

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
        self.assertEqual(
            [connection.alpn for connection in origins.connections],
            ["http/1.1" if offered else None] * 3,
        )
        self.assertEqual(
            [connection.close_kind for connection in origins.connections],
            ["websocket", "websocket", "fin"],
        )
        self.assertEqual(
            [
                [path for _, path in connection.requests]
                for connection in origins.connections
            ],
            [["/ws?i=0"], ["/ws?i=1"], ["/fast?i=2", "/fast?i=3"]],
        )
        rendered = hooks.render_run(
            0,
            SimpleNamespace(
                origins=origins,
                reports=[],
                errors=[],
                start_ms=0,
                timed_out=False,
                launcher_process=False,
                moz_log=[],
            ),
        )
        for index in range(3):
            line = next(
                row
                for row in rendered
                if row.startswith(f"run_0_server_connection_{index}=")
            )
            self.assertTrue(line.endswith(",alpn:http/1.1" if offered else ",alpn:-"))
        await origins.shutdown()
        self.assertFalse(origins.peers)
        self.assertFalse(origins.writers)

    async def test_an_explicitly_different_alpn_cannot_reach_http1(self) -> None:
        origins = hooks.Origins(hooks.SCENARIOS["wss-backup"])
        self.addAsyncCleanup(origins.shutdown)
        certificate = generate_certificate(hooks.TARGET_HOST)
        context = server_context(certificate)
        context.set_alpn_protocols(["h2"])
        listener = await asyncio.start_server(
            origins.accept_target, "127.0.0.1", 0, ssl=context
        )
        origins.listeners.append(listener)
        client = ssl.create_default_context(cadata=certificate.certificate_pem.decode())
        client.set_alpn_protocols(["h2"])
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                "127.0.0.1",
                listener.sockets[0].getsockname()[1],
                ssl=client,
                server_hostname=hooks.TARGET_HOST,
            ),
            2,
        )
        self.addAsyncCleanup(hooks.close_writer, writer, None)
        self.assertEqual(await asyncio.wait_for(reader.read(1), 2), b"")
        await asyncio.wait_for(origins.failed.wait(), 2)
        self.assertEqual(origins.connections[0].alpn, "h2")
        self.assertFalse(origins.connections[0].requests)
        self.assertEqual(
            str(origins.failures[0]), "Firefox WSS origin requires HTTP/1.1"
        )

    async def test_launch_keeps_trust_in_the_owned_profile(self) -> None:
        certificate = generate_certificate(hooks.TARGET_HOST)
        context = server_context(certificate)
        cause = OSError("stop before starting the native worker")

        def native(
            owner: hooks._FirefoxRun, plan: hooks.LaunchPlan, url: str, config: dict
        ) -> None:
            self.assertEqual(
                owner.origins.target_url,
                f"wss://{hooks.TARGET_HOST}:{owner.origins.port}",
            )
            self.assertEqual(
                plan.profile_files,
                (
                    (
                        "cert_override.txt",
                        hooks.firefox_cert_override(
                            hooks.TARGET_HOST,
                            owner.origins.port,
                            certificate.sha256_fingerprint,
                        ),
                    ),
                ),
            )
            self.assertEqual(
                config, {"rewrite_host": hooks.TARGET_HOST, "rewrite_to": "localhost"}
            )
            raise cause

        for headful in (False, True):
            with (
                self.subTest(headful=headful),
                patch(
                    "scripts.capture.http2_session.generate_certificate",
                    return_value=certificate,
                ),
                patch(
                    "scripts.capture.http2_session.server_context", return_value=context
                ),
                patch.object(
                    context, "set_alpn_protocols", wraps=context.set_alpn_protocols
                ) as alpn,
                patch.object(hooks, "_FirefoxNative", side_effect=native) as launch,
                self.assertRaises(OSError) as observed,
            ):
                await hooks.run_once(
                    hooks.SCENARIOS["wss-backup"], Path("unused"), headful=headful
                )
            self.assertIs(observed.exception, cause)
            self.assertEqual(launch.call_args.args[1].headless, not headful)
            alpn.assert_called_once_with(["http/1.1"])


if __name__ == "__main__":
    unittest.main()
