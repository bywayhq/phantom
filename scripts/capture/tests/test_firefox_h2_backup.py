import asyncio
import ssl
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, PingAckReceived, ResponseReceived, StreamEnded

from scripts.capture import firefox_socket_hooks as hooks
from scripts.capture.firefox_socket_hooks import SCENARIOS, TARGET_HOST, Origins
from scripts.capture.http2_session import generate_certificate, server_context


class H2BackupTests(unittest.IsolatedAsyncioTestCase):
    async def test_drop_with_pending_h2_control_allows_a_fresh_connection(self) -> None:
        origins = Origins(SCENARIOS["h2-backup"])
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
        client = ssl.create_default_context(cadata=certificate.certificate_pem.decode())
        client.minimum_version = ssl.TLSVersion.TLSv1_3
        client.set_alpn_protocols(["h2"])

        async def connect() -> tuple[
            asyncio.StreamReader,
            asyncio.StreamWriter,
            ssl.SSLObject,
            ssl.MemoryBIO,
            ssl.MemoryBIO,
        ]:
            incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
            tls = client.wrap_bio(
                incoming, outgoing, server_side=False, server_hostname=TARGET_HOST
            )
            reader, writer = await asyncio.open_connection("127.0.0.1", origins.port)
            self.addAsyncCleanup(hooks.close_writer, writer, None)
            while True:
                try:
                    tls.do_handshake()
                    await flush(writer, outgoing)
                    break
                except ssl.SSLWantReadError:
                    await flush(writer, outgoing)
                    incoming.write(await ciphertext(reader))

            self.assertEqual(tls.selected_alpn_protocol(), "h2")
            return reader, writer, tls, incoming, outgoing

        async def flush(writer: asyncio.StreamWriter, outgoing: ssl.MemoryBIO) -> None:
            if outgoing.pending:
                writer.write(outgoing.read())
                await writer.drain()

        async def ciphertext(reader: asyncio.StreamReader) -> bytes:
            data = await asyncio.wait_for(reader.read(65536), 2)
            self.assertTrue(data, "origin closed before completing the H2 exchange")
            return data

        async def request(peer: tuple, path: str) -> H2Connection:
            reader, writer, tls, incoming, outgoing = peer
            session = H2Connection(H2Configuration(client_side=True))
            session.initiate_connection()
            session.send_headers(
                1,
                [
                    (":method", "GET"),
                    (":scheme", "https"),
                    (":authority", TARGET_HOST),
                    (":path", path),
                ],
                end_stream=True,
            )
            tls.write(session.data_to_send())
            await flush(writer, outgoing)
            ended = acknowledged = ping_sent = False
            body = bytearray()
            while not (ended and acknowledged):
                try:
                    data = tls.read(65536)
                except ssl.SSLWantReadError:
                    incoming.write(await ciphertext(reader))
                    continue
                for event in session.receive_data(data):
                    if isinstance(event, ResponseReceived):
                        self.assertIn((b":status", b"200"), event.headers)
                    elif isinstance(event, DataReceived):
                        body.extend(event.data)
                    elif isinstance(event, StreamEnded):
                        ended = True
                    elif isinstance(event, PingAckReceived):
                        self.assertEqual(event.ping_data, b"before12")
                        acknowledged = True
                if ended and not ping_sent:
                    # This ACK fences the SETTINGS ACK queued before this PING.
                    session.ping(b"before12")
                    ping_sent = True
                queued = session.data_to_send()
                if queued:
                    tls.write(queued)
                    await flush(writer, outgoing)

            self.assertEqual(body, b"ok\n")
            return session

        first = await connect()
        session = await request(first, "/fast?i=0")
        target = origins.open[0][1]
        closing = asyncio.Event()
        original_close = target.close
        original_abort = target.transport.abort

        def close() -> None:
            original_close()
            closing.set()

        def abort() -> None:
            original_abort()
            closing.set()

        page_reader, page_writer = await asyncio.open_connection(
            "127.0.0.1", page.sockets[0].getsockname()[1]
        )
        self.addAsyncCleanup(hooks.close_writer, page_writer, None)
        with (
            patch.object(target, "close", close),
            patch.object(target.transport, "abort", abort),
        ):
            page_writer.write(b"GET /drop HTTP/1.1\r\nHost: localhost\r\n\r\n")
            await page_writer.drain()
            await asyncio.wait_for(closing.wait(), 2)
            # Queue a valid control before this client processes close_notify.
            session.ping(b"during12")
            first[2].write(session.data_to_send())
            await flush(first[1], first[4])
            try:
                response = await asyncio.wait_for(page_reader.readuntil(b"\r\n\r\n"), 2)
            except asyncio.IncompleteReadError as error:
                causes = [
                    (
                        getattr(failure, "primary", failure),
                        getattr(failure, "cleanup", ()),
                    )
                    for failure in origins.failures
                ]
                raise AssertionError(
                    f"/drop closed without a response: {causes!r}"
                ) from error

        self.assertTrue(response.startswith(b"HTTP/1.1 200 "))
        self.assertEqual(origins.connections[0].close_kind, "server")
        self.assertFalse(origins.open)
        self.assertFalse(origins.failures)
        await hooks.close_writer(first[1], None)

        second = await connect()
        await request(second, "/fast?i=1")
        self.assertEqual(len(origins.connections), 2)
        self.assertEqual(
            [[path for _, path in peer.requests] for peer in origins.connections],
            [["/fast?i=0"], ["/fast?i=1"]],
        )
        await hooks.close_writer(second[1], None)
        await origins.shutdown()
        self.assertFalse(origins.peers)
        self.assertFalse(origins.writers)
        self.assertFalse(origins.failures)

    async def test_launch_mode_reaches_the_native_plan(self) -> None:
        cause = OSError("stop before starting the native worker")
        plans: list[hooks.LaunchPlan] = []

        def native(
            owner: hooks._FirefoxRun,
            plan: hooks.LaunchPlan,
            url: str,
            config: dict[str, str],
        ) -> None:
            plans.append(plan)
            raise cause

        for headful in (False, True):
            with self.subTest(headful=headful):
                plans.clear()
                with (
                    patch.object(hooks, "_FirefoxNative", side_effect=native),
                    self.assertRaises(OSError) as observed,
                ):
                    if headful:
                        await hooks.run_once(
                            SCENARIOS["h2-backup"], Path("unused"), headful=True
                        )
                    else:
                        await hooks.run_once(SCENARIOS["h2-backup"], Path("unused"))

                self.assertIs(observed.exception, cause)
                self.assertEqual(len(plans), 1)
                self.assertEqual(plans[0].headless, not headful)

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
                        self.assertIn(
                            (b"access-control-allow-origin", b"*"), event.headers
                        )
                    elif isinstance(event, DataReceived):
                        body += event.data
                    elif isinstance(event, StreamEnded) and event.stream_id == stream:
                        self.assertEqual(body, b"ok\n")
                        return

        first = await connect()
        await request(first, "/fast?i=0")
        await request(first, "/fast?i=1")
        self.assertEqual(len(origins.connections), 1)
        closing = asyncio.Event()
        release_close = asyncio.Event()
        response_started = asyncio.Event()
        target = origins.open[0][1]
        original_wait_closed = target.wait_closed
        original_write_response = hooks.write_response

        async def delayed_close() -> None:
            closing.set()
            await release_close.wait()
            await original_wait_closed()

        async def observed_response(*args, **kwargs) -> None:
            response_started.set()
            await original_write_response(*args, **kwargs)

        target.wait_closed = delayed_close
        reader, writer = await asyncio.open_connection("127.0.0.1", page_port)
        try:
            with patch.object(hooks, "write_response", observed_response):
                writer.write(b"GET /drop HTTP/1.1\r\nHost: localhost\r\n\r\n")
                await writer.drain()
                await asyncio.wait_for(closing.wait(), 2)
                self.assertFalse(
                    response_started.is_set(),
                    "/drop acknowledged before the target handler finished closing",
                )
                release_close.set()
                await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
                self.assertTrue(response_started.is_set())
        finally:
            release_close.set()
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


class H2LaunchTests(unittest.TestCase):
    def test_cli_mode_reaches_capture_and_the_fixture(self) -> None:
        result = SimpleNamespace(
            reports=[{}], errors=[], frida_version="0", timed_out=False
        )

        for headful in (False, True):
            with (
                self.subTest(headful=headful),
                tempfile.TemporaryDirectory() as directory,
            ):
                argv = [
                    "--browser-path",
                    "unused",
                    "--client-version",
                    "157.0",
                    "--output-dir",
                    directory,
                    "--scenario",
                    "h2-backup",
                ]
                if headful:
                    argv.append("--headful")

                with (
                    patch.object(hooks.sys, "platform", "win32"),
                    patch.object(hooks, "installed_build", return_value=("157.0", "1")),
                    patch.object(
                        hooks, "run_once", return_value=(result, "--test")
                    ) as run,
                    patch.object(
                        hooks, "render_run", return_value=["run_0_event_count=1"]
                    ),
                ):
                    hooks.main(argv)

                run.assert_awaited_once_with(
                    SCENARIOS["h2-backup"],
                    Path("unused"),
                    headful=headful,
                    failure_path=None,
                )
                text = (Path(directory) / "hooks-h2-backup.txt").read_text()
                fields = dict(line.split("=", 1) for line in text.splitlines())
                self.assertEqual(
                    fields["launch_mode"], "headful" if headful else "headless"
                )
