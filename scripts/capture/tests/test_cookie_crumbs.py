import argparse
import asyncio
import contextlib
import errno
import socket
import ssl
import traceback
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock
from urllib.parse import urlsplit

import pylsqpack
from aioquic.asyncio import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.quic.configuration import QuicConfiguration
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import StreamEnded

from scripts.capture import cookie_crumbs
from scripts.capture.cookie_crumbs import (
    FORMAT,
    PROBE_COOKIES,
    SCENARIOS,
    CaptureMetadata,
    CookieFailures,
    CookieRun,
    QuicRecord,
    RequestRecord,
    TcpServer,
    capture,
    check_field,
    check_inserted_fields,
    encoder_instructions,
    field_section,
    fixture,
    is_probe_cookie,
    serving_http3,
)
from scripts.capture.fixture_file import write_text_fixture
from scripts.capture.http2_session import (
    HOSTNAME,
    ConnectionRecord,
    generate_certificate,
)
from scripts.capture.tests.loopback_quic import connect_loopback

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "cookies"
CERTIFICATE = generate_certificate()
METADATA = CaptureMetadata(
    client="scripted",
    client_version="0",
    operating_system="test",
    listen_address="127.0.0.1:0",
    launch_mode="scripted",
    launch_arguments="none",
)
JOINED = "; ".join(PROBE_COOKIES).encode()
TIMEOUT = 20.0


def fixture_values(path: Path) -> dict[str, str]:
    lines = path.read_text(encoding="ascii").splitlines()
    return dict(line.split("=", 1) for line in lines)


def record(text: str) -> dict[str, str]:
    return dict(item.split(":", 1) for item in text.split(","))


async def h2_requests(port: int, token: str, cookie: bytes) -> None:
    """Send `/start`, then `/page` and `/done` with `cookie`, over one session."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["h2"])
    reader, writer = await asyncio.open_connection(
        "127.0.0.1", port, ssl=context, server_hostname=HOSTNAME
    )
    connection = H2Connection(H2Configuration(client_side=True, header_encoding=None))
    connection.initiate_connection()
    for path, carries_cookie in (("/start", False), ("/page", True), ("/done", True)):
        stream_id = connection.get_next_available_stream_id()
        headers = [
            (b":method", b"GET"),
            (b":authority", HOSTNAME.encode()),
            (b":scheme", b"https"),
            (b":path", f"{path}?run={token}".encode()),
            (b"accept", b"*/*"),
        ]
        if carries_cookie:
            headers.append((b"cookie", cookie))
        connection.send_headers(stream_id, headers, end_stream=True)
        writer.write(connection.data_to_send())
        await writer.drain()
        ended = False
        while not ended:
            data = await reader.read(65536)
            if not data:
                raise ConnectionError("server closed the session")
            for event in connection.receive_data(data):
                ended |= isinstance(event, StreamEnded) and event.stream_id == stream_id
            writer.write(connection.data_to_send())
    writer.close()


async def scripted_h2_run(cookie: bytes) -> CookieRun:
    server = TcpServer(CERTIFICATE)
    run = CookieRun("feedc0de", observation_seconds=0.05)
    server.run = run
    primary = None
    try:
        await server.start("127.0.0.1")
        await asyncio.wait_for(
            h2_requests(server.tls_address[1], run.token, cookie), TIMEOUT
        )
        await asyncio.wait_for(run.done.wait(), TIMEOUT)
        return run
    except BaseException as error:
        primary = error
        raise
    finally:
        await server.close(primary)


class CookieLaunchTests(unittest.TestCase):
    def test_tcp_launch_maps_canonical_addresses_without_enabling_quic(self):
        args = argparse.Namespace(browser="chrome", browser_path=None, headful=False)
        for host, mapped in (
            ("127.0.0.1", "127.0.0.1"),
            ("::1", "[::1]"),
            ("0:0:0:0:0:0:0:1", "[::1]"),
        ):
            with self.subTest(host=host):
                plan = cookie_crumbs.tcp_launch_plan(args, CERTIFICATE, host, 4433)
                self.assertIn(
                    f"--host-resolver-rules=MAP {HOSTNAME} {mapped}, EXCLUDE localhost",
                    plan.extra_arguments,
                )
                self.assertIn("--disable-quic", plan.extra_arguments)

        args.browser = "firefox"
        for host, ipv6 in (("127.0.0.1", False), ("::1", True)):
            with self.subTest(host=host):
                plan = cookie_crumbs.tcp_launch_plan(args, CERTIFICATE, host, 4433)
                preferences = dict(plan.firefox_preferences)
                self.assertEqual(preferences["network.dns.localDomains"], HOSTNAME)
                self.assertIs(preferences["network.dns.disableIPv6"], not ipv6)
                self.assertIs(preferences["network.dns.preferIPv6"], ipv6)
                self.assertIs(preferences["network.http.http3.enable"], False)
                self.assertEqual(
                    [name for name, _ in plan.profile_files], ["cert_override.txt"]
                )


class CookieOwnershipTests(unittest.IsolatedAsyncioTestCase):
    async def test_completion_requires_one_original_origin_form_run_token(self):
        invalid = (
            b"/done?run=wrong",
            b"/done?run=token&run=other",
            b"/done?run=token&run=",
            b"/done?run=&run=token",
            b"/done?run=token#fragment",
            b"/done?run=token#",
            b"https://localhost/done?run=token",
            b"//localhost/done?run=token",
            b"///done?run=token",
            b"done?run=token",
            b"/do\nne?run=token",
            b"/done?run=to\tken",
            b"\x00/done?run=token",
            b" /done?run=token",
            b"/done?run=to\rken",
            b"/done?run=token\x7f",
        )
        run = CookieRun("token", 0)
        run.connections.append(ConnectionRecord("plain", 0, protocol="http/1.1"))
        for target in invalid:
            with self.subTest(target=target):
                kind = run.classify(target)
                line = b"GET " + target + b" HTTP/1.1"
                run.record(RequestRecord(0, 0, kind, request_line=line))
                self.assertEqual(kind, "other")
                self.assertIsNone(run.finished)
                self.assertIsNone(run.observation_timer)
                self.assertFalse(run.done.is_set())

        with TemporaryDirectory() as directory:
            output = Path(directory) / "capture.txt"
            write_text_fixture(output, fixture(SCENARIOS["h1"], [run], METADATA, 4096))
            values = fixture_values(output)
            self.assertEqual(values["run_0_finished_ms"], "none")
            self.assertEqual(values["run_0_request_count"], str(len(invalid)))
            for index, target in enumerate(invalid):
                self.assertIn("kind:other", values[f"run_0_request_{index}"])
                self.assertEqual(
                    bytes.fromhex(values[f"run_0_request_{index}_line_hex"]),
                    b"GET " + target + b" HTTP/1.1",
                )

            kind = run.classify(b"/done?run=token")
            run.record(
                RequestRecord(0, 0, kind, request_line=b"GET /done?run=token HTTP/1.1")
            )
            try:
                await asyncio.wait_for(run.done.wait(), TIMEOUT)
                self.assertEqual(kind, "done")
                self.assertIsNotNone(run.finished)
                write_text_fixture(
                    output, fixture(SCENARIOS["h1"], [run], METADATA, 4096)
                )
                values = fixture_values(output)
                self.assertNotEqual(values["run_0_finished_ms"], "none")
                self.assertIn("kind:done", values[f"run_0_request_{len(invalid)}"])
            finally:
                if run.observation_timer is not None:
                    run.observation_timer.cancel()

    async def test_completed_http1_head_and_aggregate_boundaries(self):
        prefix = b"GET /done?run=head HTTP/1.1\r\nHost: localhost\r\nX-Pad: "
        for size, aggregate in (
            (65536, 8 * 1024 * 1024),
            (65537, 8 * 1024 * 1024),
            (65536, 65535),
        ):
            server = TcpServer(CERTIFICATE)
            run = CookieRun("head", 0)
            server.run = run
            client = None
            observed = None
            healthy = size == 65536 and aggregate > size
            try:
                with (
                    self.subTest(size=size, aggregate=aggregate),
                    mock.patch.object(cookie_crumbs, "MAX_RUN_CAPTURE", aggregate),
                ):
                    await server.start("127.0.0.1")
                    client = await asyncio.open_connection(*server.plain_address)
                    head = prefix + b"x" * (size - len(prefix) - 4) + b"\r\n\r\n"
                    client[1].write(head)
                    await asyncio.wait_for(run.done.wait(), TIMEOUT)
                    if healthy:
                        response = await asyncio.wait_for(
                            client[0].readuntil(b"\r\n\r\n"), TIMEOUT
                        )
                        self.assertTrue(response.startswith(b"HTTP/1.1 200 "))
                        self.assertEqual(
                            await asyncio.wait_for(client[0].readexactly(2), TIMEOUT),
                            b"ok",
                        )
                        await server.close()
                        self.assertEqual(len(run.requests), 1)
                        self.assertEqual(run.requests[0].kind, "done")
                        self.assertEqual(run.connections[0].client_stream(), head)
                    else:
                        self.assertEqual(run.requests, [])
                        observed = run.failures[0]
                        self.assertIsInstance(observed, ValueError)
                        self.assertIn(
                            "header limit" if size == 65537 else "aggregate",
                            str(observed),
                        )
                        with self.assertRaises(ValueError) as raised:
                            await server.close()
                        self.assertIs(raised.exception, observed)
                        if size == 65537:
                            self.assertEqual(run.connections[0].client_stream(), head)
                        else:
                            self.assertLess(run.connections[0].received, size)
                            self.assertLessEqual(run.retained, 65535)

                    self.assertTrue(server.finished)
                    self.assertEqual(len(server.protocols), 1)
                    protocol = server.protocols[0]
                    self.assertTrue(protocol.task.done())
                    self.assertTrue(protocol.close_task.done())
                    self.assertTrue(protocol.retired.done())
                    self.assertIsNone(protocol.transport._sock)
                    self.assertTrue(
                        all(not listener.sockets for listener in server.servers)
                    )
                    self.assertEqual(
                        await asyncio.wait_for(client[0].read(), TIMEOUT), b""
                    )

                    with TemporaryDirectory() as directory:
                        output = Path(directory) / "capture.txt"
                        output.write_bytes(b"previous fixture\n")
                        if healthy:
                            write_text_fixture(
                                output, fixture(SCENARIOS["h1"], [run], METADATA, 4096)
                            )
                            values = fixture_values(output)
                            self.assertEqual(values["run_0_request_count"], "1")
                            self.assertEqual(
                                bytes.fromhex(values["run_0_request_0_header_1"]),
                                b"X-Pad: " + b"x" * (size - len(prefix) - 4),
                            )
                        else:
                            with self.assertRaises(ValueError) as unpublished:
                                write_text_fixture(
                                    output,
                                    fixture(SCENARIOS["h1"], [run], METADATA, 4096),
                                )
                            self.assertIs(unpublished.exception, observed)
                            self.assertEqual(output.read_bytes(), b"previous fixture\n")
            finally:
                # Native assertions and publication precede backup cleanup.
                if client is not None:
                    client[1].close()
                    await client[1].wait_closed()
                if observed is None:
                    await server.close()
                else:
                    with self.assertRaises(ValueError) as final:
                        await server.close()
                    self.assertIs(final.exception, observed)

    async def test_failed_stream_setup_retains_native_transport_and_lost_error(self):
        server = TcpServer(CERTIFICATE)
        run = CookieRun("stream-setup", 0)
        server.run = run
        primary = RuntimeError("original stream setup failure")
        secondary = OSError(errno.EIO, "original connection retirement failure")
        acquired = []
        connected = asyncio.StreamReaderProtocol.connection_made
        lost = cookie_crumbs.CookieProtocol.connection_lost
        client = None

        def reject(protocol, transport):
            if isinstance(protocol, cookie_crumbs.CookieProtocol):
                acquired.append((protocol, transport))
                raise primary
            connected(protocol, transport)

        def fail_retirement(protocol, error):
            self.assertIsNone(error)
            lost(protocol, secondary)

        try:
            await server.start("127.0.0.1")
            with (
                mock.patch.object(
                    asyncio.StreamReaderProtocol, "connection_made", reject
                ),
                mock.patch.object(
                    cookie_crumbs.CookieProtocol, "connection_lost", fail_retirement
                ),
            ):
                client = await asyncio.open_connection(*server.plain_address)
                await asyncio.wait_for(run.done.wait(), TIMEOUT)
                with self.assertRaises(CookieFailures) as raised:
                    await server.close()

            self.assertEqual(len(acquired), 1)
            protocol, transport = acquired[0]
            self.assertIs(protocol.transport, transport)
            self.assertIsNone(protocol.writer)
            self.assertTrue(transport.is_closing())
            self.assertTrue(protocol.retired.done())
            self.assertTrue(protocol.close_task.done())
            self.assertTrue(server.finished)
            self.assertTrue(any(error is primary for error in raised.exception.cleanup))
            self.assertTrue(
                any(error is secondary for error in raised.exception.cleanup)
            )
            self.assertEqual(await asyncio.wait_for(client[0].read(), TIMEOUT), b"")
            with self.assertRaises(CookieFailures):
                fixture(SCENARIOS["h1"], [run], METADATA, 4096)
        finally:
            if client is not None:
                client[1].close()
                await client[1].wait_closed()
            with contextlib.suppress(CookieFailures, RuntimeError):
                await server.close()

    async def test_http1_ipv6_url_names_the_actual_loopback_listener(self):
        observed = []

        async def visit(run, plan, url, timeout):
            parsed = urlsplit(url)
            self.assertEqual(parsed.hostname, "::1")
            self.assertIsNotNone(parsed.port)
            observed.append(url)
            reader, writer = await asyncio.open_connection(parsed.hostname, parsed.port)
            try:
                writer.write(
                    f"GET /done?run={run.token} HTTP/1.1\r\nHost: [::1]\r\n\r\n".encode()
                )
                await writer.drain()
                response = await asyncio.wait_for(
                    reader.readuntil(b"\r\n\r\n"), TIMEOUT
                )
                self.assertTrue(response.startswith(b"HTTP/1.1 200 "))
                await asyncio.wait_for(run.done.wait(), TIMEOUT)
            finally:
                writer.close()
                await writer.wait_closed()

        with TemporaryDirectory() as directory:
            args = argparse.Namespace(
                run_timeout=1,
                observation=0,
                repeat=1,
                scenario=["h1"],
                output_dir=Path(directory),
                listen="::1",
                browser="manual",
                browser_path=None,
                headful=False,
                client="scripted",
                client_version="0",
                operating_system="test",
            )
            with mock.patch.object(cookie_crumbs, "wait_for_run", side_effect=visit):
                try:
                    await asyncio.wait_for(capture(args), TIMEOUT)
                except OSError as error:
                    if error.errno not in {errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL}:
                        raise
                    self.skipTest("IPv6 loopback is unavailable")
            self.assertEqual(len(observed), 1)
            self.assertEqual(
                fixture_values(Path(directory) / "crumbs-h1.txt")[
                    "run_0_request_count"
                ],
                "1",
            )

    async def test_invalid_run_bounds_fail_before_certificate_or_listener_acquisition(
        self,
    ):
        for timeout, observation, repeat, host in (
            (float("nan"), 0, 1, "127.0.0.1"),
            (1, float("inf"), 1, "127.0.0.1"),
            (1e308, 1e308, 1, "127.0.0.1"),
            (1, 0, 129, "127.0.0.1"),
            (1, 0, 1, "127.0.0.2"),
            (1, 0, 1, "0:0:0:0:0:0:0:1"),
        ):
            args = argparse.Namespace(
                run_timeout=timeout,
                observation=observation,
                repeat=repeat,
                scenario=["h1"],
                browser="firefox",
                browser_path=None,
                headful=False,
                listen=host,
            )
            if host != "127.0.0.1":
                with self.assertRaisesRegex(ValueError, "hostname mapping"):
                    cookie_crumbs.tcp_launch_plan(args, CERTIFICATE, host, 4433)
                with self.assertRaisesRegex(ValueError, "hostname mapping"):
                    cookie_crumbs.h3_launch_plan(args, CERTIFICATE, 4433)

            with (
                self.subTest(
                    timeout=timeout, observation=observation, repeat=repeat, host=host
                ),
                mock.patch.object(cookie_crumbs, "generate_certificate") as acquire,
                mock.patch.object(cookie_crumbs, "TcpServer") as tcp,
                mock.patch.object(cookie_crumbs, "serving_http3") as quic,
                self.assertRaises(ValueError),
            ):
                await capture(args)
            acquire.assert_not_called()
            tcp.assert_not_called()
            quic.assert_not_called()

    async def test_second_listener_failure_collects_first_accepted_socket(self):
        server = TcpServer(CERTIFICATE)
        run = CookieRun("partial", 0)
        server.run = run
        primary = OSError(errno.EIO, "original second listener failure")
        loop = asyncio.get_running_loop()
        create_server = loop.create_server
        acquired = []
        client = None
        admitted = asyncio.Event()
        connected = cookie_crumbs.CookieProtocol.connected

        def observe(protocol, reader, writer):
            connected(protocol, reader, writer)
            if protocol.owner is server:
                admitted.set()

        async def acquire(*args, **kwargs):
            nonlocal client
            if acquired:
                client = await asyncio.open_connection(*server.tls_address)
                await asyncio.wait_for(admitted.wait(), TIMEOUT)
                raise primary
            listener = await create_server(*args, **kwargs)
            acquired.append(listener)
            return listener

        try:
            with (
                mock.patch.object(loop, "create_server", side_effect=acquire),
                mock.patch.object(cookie_crumbs.CookieProtocol, "connected", observe),
                self.assertRaises(OSError) as raised,
            ):
                await asyncio.wait_for(server.start("127.0.0.1"), TIMEOUT)

            self.assertIs(raised.exception, primary)
            self.assertTrue(server.finished)
            self.assertTrue(server.protocols[0].retired.done())
            self.assertTrue(server.protocols[0].task.done())
            self.assertEqual(acquired[0].sockets, ())
            self.assertEqual(await asyncio.wait_for(client[0].read(), TIMEOUT), b"")
            with self.assertRaises(OSError) as unpublished:
                fixture(SCENARIOS["h2"], [run], METADATA, 4096)
            self.assertIs(unpublished.exception, primary)

            rebound = await asyncio.start_server(
                lambda reader, writer: writer.close(), *server.tls_address
            )
            rebound.close()
            await rebound.wait_closed()
        finally:
            if client is not None:
                client[1].close()
                await client[1].wait_closed()
            with self.assertRaises(OSError) as cleanup:
                await server.close()
            self.assertIs(cleanup.exception, primary)

    async def test_accepted_protocol_factory_failure_prevents_publication(self):
        for primary in (
            ValueError("original accepted protocol construction failure"),
            OSError(errno.EIO, "original accepted protocol I/O failure"),
            MemoryError("original accepted protocol allocation failure"),
        ):
            with self.subTest(error=type(primary)):
                await self.accepted_factory_failure(primary)

    async def accepted_factory_failure(self, primary):
        server = TcpServer(CERTIFICATE)
        run = CookieRun("factory", 0)
        server.run = run
        loop = asyncio.get_running_loop()
        previous_handler = loop.get_exception_handler()
        unexpected = []
        accepted_sockets = []
        client = None

        def observe_backend_failure(loop, context):
            if context.get("exception") is primary:
                # This fault precedes the backend's transport acquisition.
                # Retain its original accepted socket for test-only cleanup.
                for frame, _line in traceback.walk_tb(primary.__traceback__):
                    if frame.f_code.co_name in {"_accept_connection2", "loop"}:
                        accepted = frame.f_locals.get("conn")
                        if isinstance(accepted, socket.socket):
                            accepted_sockets.append(accepted)
                return
            unexpected.append(context)
            if previous_handler is None:
                loop.default_exception_handler(context)
            else:
                previous_handler(loop, context)

        try:
            await server.start("127.0.0.1")
            loop.set_exception_handler(observe_backend_failure)
            with mock.patch.object(
                cookie_crumbs, "CookieProtocol", side_effect=primary
            ):
                client = await asyncio.open_connection(*server.plain_address)
                await asyncio.wait_for(run.done.wait(), TIMEOUT)
                with self.assertRaises(type(primary)) as raised:
                    await server.close()

            self.assertIs(raised.exception, primary)
            self.assertIs(run.failures[0], primary)
            self.assertEqual(await asyncio.wait_for(client[0].read(1), 2.0), b"")
            self.assertEqual(len(server.protocols), 1)
            self.assertTrue(server.protocols[0].retired.done())
            self.assertTrue(server.finished)
            self.assertTrue(all(not listener.sockets for listener in server.servers))
            self.assertEqual(unexpected, [])
            self.assertEqual(accepted_sockets, [])
            with self.assertRaises(type(primary)) as unpublished:
                fixture(SCENARIOS["h1"], [run], METADATA, 4096)
            self.assertIs(unpublished.exception, primary)
            rebound = await asyncio.start_server(
                lambda reader, writer: writer.close(), *server.plain_address
            )
            rebound.close()
            await rebound.wait_closed()
        finally:
            loop.set_exception_handler(previous_handler)
            for accepted in accepted_sockets:
                accepted.close()
            if client is not None:
                client[1].close()
                await client[1].wait_closed()
            if run.failures:
                with self.assertRaises(type(primary)) as final:
                    await server.close()
                self.assertIs(final.exception, primary)
            else:
                await server.close()

    async def test_connection_limit_retires_every_accepted_peer(self):
        server = TcpServer(CERTIFICATE)
        run = CookieRun("connection-limit", 0)
        server.run = run
        clients = []
        loop = asyncio.get_running_loop()
        previous_handler = loop.get_exception_handler()
        unexpected = []
        try:
            await server.start("127.0.0.1")
            loop.set_exception_handler(
                lambda _loop, context: unexpected.append(context)
            )
            with mock.patch.object(cookie_crumbs, "MAX_CONNECTIONS", 1):
                for _ in range(2):
                    clients.append(await asyncio.open_connection(*server.plain_address))
                await asyncio.wait_for(run.done.wait(), TIMEOUT)
                with self.assertRaisesRegex(ValueError, "connection limit"):
                    await server.close()

            self.assertEqual(len(server.protocols), 2)
            self.assertTrue(
                all(protocol.retired.done() for protocol in server.protocols)
            )
            for reader, _writer in clients:
                self.assertEqual(await asyncio.wait_for(reader.read(1), 2.0), b"")
            self.assertTrue(server.finished)
            self.assertTrue(all(not listener.sockets for listener in server.servers))
            self.assertEqual(unexpected, [])
        finally:
            loop.set_exception_handler(previous_handler)
            for _reader, writer in clients:
                writer.close()
                await writer.wait_closed()
            if run.failures:
                with self.assertRaises(ValueError):
                    await server.close()
            else:
                await server.close()

    async def test_serving_cleanup_and_caller_cancellation_prevent_publication(self):
        primary = ValueError("original accepted serving failure")
        cleanup = OSError(errno.EIO, "original accepted writer cleanup failure")
        arrived = asyncio.Event()
        release = asyncio.Event()
        observing_writer = asyncio.Event()
        finish_writer = asyncio.Event()
        cancellation_cause = LookupError("original cancellation cause")
        original_wait = asyncio.wait

        async def observe(*args, **kwargs):
            try:
                return await original_wait(*args, **kwargs)
            except asyncio.CancelledError as error:
                error.__cause__ = cancellation_cause
                raise

        async def fail(channel, run, index):
            await channel.read()
            arrived.set()
            await release.wait()
            raise primary

        async def failed_close():
            observing_writer.set()
            await finish_writer.wait()
            raise cleanup

        server = TcpServer(CERTIFICATE)
        run = CookieRun("failure", 0)
        server.run = run
        client = None
        cancellation = None

        async def collect():
            nonlocal cancellation
            try:
                await server.close(primary)
            except asyncio.CancelledError as error:
                cancellation = error
                raise

        try:
            await server.start("127.0.0.1")
            with mock.patch.object(cookie_crumbs, "serve_http1", side_effect=fail):
                client = await asyncio.open_connection(*server.plain_address)
                client[1].write(
                    b"GET /page?run=failure HTTP/1.1\r\nHost: localhost\r\n\r\n"
                )
                await client[1].drain()
                await asyncio.wait_for(arrived.wait(), TIMEOUT)
                protocol = server.protocols[0]
                with (
                    mock.patch.object(
                        protocol.writer, "wait_closed", side_effect=failed_close
                    ),
                    mock.patch.object(
                        cookie_crumbs.asyncio, "wait", side_effect=observe
                    ),
                ):
                    release.set()
                    await asyncio.wait_for(run.done.wait(), TIMEOUT)
                    closing = asyncio.create_task(collect())
                    await asyncio.wait_for(observing_writer.wait(), TIMEOUT)
                    closing.cancel("original caller cleanup cancellation")
                    finish_writer.set()
                    with self.assertRaises(asyncio.CancelledError):
                        await closing

            self.assertTrue(closing.cancelled())
            self.assertIsInstance(cancellation, asyncio.CancelledError)
            failure = cancellation.__cause__
            self.assertIsInstance(failure, CookieFailures)
            self.assertIs(failure.primary, primary)
            self.assertIs(failure.interruption_cause, cancellation_cause)
            self.assertTrue(any(error is cleanup for error in failure.cleanup))
            self.assertTrue(any(error is cancellation for error in failure.cleanup))
            self.assertEqual(
                cancellation.args, ("original caller cleanup cancellation",)
            )
            self.assertIs(run.failures[0], primary)
            self.assertTrue(any(error is cleanup for error in run.failures))
            self.assertTrue(any(error is cancellation for error in run.failures))
            self.assertTrue(protocol.task.done())
            self.assertTrue(protocol.retired.done())
            self.assertEqual(await asyncio.wait_for(client[0].read(), TIMEOUT), b"")
            with TemporaryDirectory() as directory:
                output = Path(directory) / "capture.txt"
                output.write_bytes(b"previous fixture\n")
                with self.assertRaises(asyncio.CancelledError) as unpublished:
                    write_text_fixture(
                        output, fixture(SCENARIOS["h1"], [run], METADATA, 4096)
                    )
                self.assertIs(unpublished.exception, cancellation)
                self.assertEqual(output.read_bytes(), b"previous fixture\n")
        finally:
            release.set()
            finish_writer.set()
            if client is not None:
                client[1].close()
                await client[1].wait_closed()
            if cancellation is None:
                await server.close()
            else:
                with self.assertRaises(asyncio.CancelledError) as final:
                    await server.close()
                self.assertIs(final.exception, cancellation)

    async def test_external_handler_cancellation_retains_original_outcome(self):
        entered = asyncio.Event()

        async def read(channel, run, index):
            entered.set()
            await channel.read()

        server = TcpServer(CERTIFICATE)
        run = CookieRun("cancel", 0)
        server.run = run
        client = None
        original = None
        try:
            await server.start("127.0.0.1")
            with mock.patch.object(cookie_crumbs, "serve_http1", side_effect=read):
                client = await asyncio.open_connection(*server.plain_address)
                await asyncio.wait_for(entered.wait(), TIMEOUT)
                original_task = server.protocols[0].task
                original_task.cancel("external cookie cancellation")
                await asyncio.wait_for(run.done.wait(), TIMEOUT)
                original = run.failures[0]
                with self.assertRaises(asyncio.CancelledError) as raised:
                    await server.close()

            self.assertIs(raised.exception, original)
            self.assertEqual(original.args, ("external cookie cancellation",))
            self.assertIsNone(original_task.result())
            self.assertTrue(server.protocols[0].retired.done())
            self.assertEqual(await asyncio.wait_for(client[0].read(), TIMEOUT), b"")
        finally:
            if client is not None:
                client[1].close()
                await client[1].wait_closed()
            if original is None:
                await server.close()
            else:
                with self.assertRaises(asyncio.CancelledError) as final:
                    await server.close()
                self.assertIs(final.exception, original)

    async def test_original_http3_callback_failure_is_observed_before_return(self):
        class Client(QuicConnectionProtocol):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.http = H3Connection(self._quic)

            def quic_event_received(self, event):
                self.http.handle_event(event)

        run = CookieRun("quic", 0)
        primary = OSError(errno.EIO, "original HTTP/3 request callback failure")
        configuration = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
        configuration.verify_mode = ssl.CERT_NONE
        with (
            mock.patch.object(run, "record", side_effect=primary),
            self.assertRaises(OSError) as raised,
        ):
            async with (
                serving_http3(run, "127.0.0.1", CERTIFICATE) as port,
                connect_loopback(port, configuration, Client) as client,
            ):
                stream = client._quic.get_next_available_stream_id()
                client.http.send_headers(
                    stream,
                    [
                        (b":method", b"GET"),
                        (b":scheme", b"https"),
                        (b":authority", HOSTNAME.encode()),
                        (b":path", b"/done?run=quic"),
                    ],
                    end_stream=True,
                )
                client.transmit()
                await asyncio.wait_for(run.done.wait(), TIMEOUT)

        self.assertIs(raised.exception, primary)
        self.assertIs(run.failures[0], primary)
        owner = run.quic_owners[0]
        self.assertTrue(owner.retired.done())
        self.assertTrue(owner.finished)
        self.assertTrue(all(protocol.observed_closed for protocol in owner.protocols))


class ScriptedCaptureTests(unittest.TestCase):
    def test_h2_fixture_keeps_each_cookie_representation_in_order(self) -> None:
        run = asyncio.run(scripted_h2_run(JOINED))
        text = fixture(SCENARIOS["h2"], [run], METADATA, 4096)
        values = dict(line.split("=", 1) for line in text.splitlines())

        self.assertEqual(values["format"], FORMAT)
        self.assertEqual(values["run_0_request_count"], "3")
        self.assertIn("kind:page", values["run_0_request_1"])
        self.assertEqual(
            values["run_0_request_1_field_order"],
            ":method,:authority,:scheme,:path,accept,cookie",
        )
        field = record(values["run_0_request_1_field_5"])
        self.assertEqual(bytes.fromhex(field["value_hex"]), JOINED)

    def test_fixture_refuses_a_cookie_that_is_not_a_probe(self) -> None:
        run = asyncio.run(scripted_h2_run(b"session=secret"))
        with self.assertRaisesRegex(ValueError, "not a probe"):
            fixture(SCENARIOS["h2"], [run], METADATA, 4096)


class RetainedFieldTests(unittest.TestCase):
    def test_probe_cookies_pass_in_any_split(self) -> None:
        self.assertTrue(is_probe_cookie(JOINED))
        self.assertTrue(is_probe_cookie(PROBE_COOKIES[1].encode()))
        self.assertFalse(is_probe_cookie(JOINED + b"; other=1"))

    def test_credentials_are_refused(self) -> None:
        with self.assertRaisesRegex(ValueError, "credential"):
            check_field(b"Authorization", b"Basic eA==")

    def test_inserted_cookies_that_are_not_probes_are_refused(self) -> None:
        # Insert with static name reference 5 (`cookie`), a raw 14-byte value.
        stream = b"\x02\xc5\x0esession=secret"
        with self.assertRaisesRegex(ValueError, "not a probe"):
            check_inserted_fields(encoder_instructions(stream))
        check_inserted_fields(encoder_instructions(b"\x02\xc5\x04pa=1"))

    def test_unused_credential_inserts_refuse_fixture_publication(self) -> None:
        # Literal names and RFC 9204's static authorization name, index 84.
        inserts = (
            b"\x4dauthorization\x05probe",
            b"\x53proxy-authorization\x05probe",
            b"\xff\x15\x05probe",
        )
        with TemporaryDirectory() as directory:
            output = Path(directory) / "capture.txt"
            output.write_bytes(b"previous fixture\n")
            for insert in inserts:
                stream = b"\x02\x3f\xe1\x1f" + insert
                with self.subTest(insert=insert):
                    decoder = pylsqpack.Decoder(4096, 16)
                    self.assertEqual(decoder.feed_encoder(stream[1:]), [])
                    run = CookieRun("probe", 0.0)
                    run.quic_connections.append(QuicRecord(0.0, {2: bytearray(stream)}))

                    with self.assertRaisesRegex(ValueError, "credential"):
                        text = fixture(SCENARIOS["h3"], [run], METADATA, 4096)
                        write_text_fixture(output, text)

                    self.assertEqual(output.read_bytes(), b"previous fixture\n")

    def test_safe_insert_references_and_duplicates_keep_their_names(self) -> None:
        # Static cookie, duplicate, then dynamic name with a non-probe value.
        with self.assertRaisesRegex(ValueError, "not a probe"):
            check_inserted_fields(
                encoder_instructions(b"\x02\xc5\x04pa=1\x00\x80\x0esession=secret")
            )

        # Static user-agent, a duplicate and a dynamic reference remain safe.
        stream = b"\x02\x3f\xe1\x1f\xff\x20\x05probe\x00\x80\x04next"
        decoder = pylsqpack.Decoder(4096, 16)
        self.assertEqual(decoder.feed_encoder(stream[1:]), [])
        check_inserted_fields(encoder_instructions(stream))

    def test_unresolved_encoder_names_are_refused(self) -> None:
        for stream in (b"\x02\x80\x01x", b"\x02\x00", b"\x02\xff\x24\x01x"):
            with (
                self.subTest(stream=stream),
                self.assertRaisesRegex(ValueError, "reference"),
            ):
                check_inserted_fields(encoder_instructions(stream))


class QpackParserTests(unittest.TestCase):
    def test_field_lines_reference_the_entries_the_encoder_inserted(self) -> None:
        encoder = pylsqpack.Encoder()
        stream = b"\x02" + encoder.apply_settings(4096, 16)
        fields = [(b":method", b"GET"), (b"x-probe", b"1")]
        fields += [(b"cookie", cookie.encode()) for cookie in PROBE_COOKIES]
        # lsqpack inserts a field only once it has seen it before.
        for stream_id in (0, 4, 8):
            instructions, block = encoder.encode(stream_id, fields)
            stream += instructions
        parsed = encoder_instructions(stream)
        inserted = {item.inserted: item for item in parsed if item.inserted is not None}

        section = field_section(block, 4096, len(inserted))
        self.assertEqual(len(section.lines), len(fields))
        referenced = [line for line in section.lines if line.absolute is not None]
        self.assertTrue(referenced, "the last block used no dynamic entry")
        for line, (name, value) in zip(section.lines, fields, strict=True):
            if line.absolute is not None:
                entry = inserted[line.absolute]
                self.assertEqual(entry.value.decoded(), value, name)

    def test_retained_http3_fixtures_parse_to_their_recorded_field_lines(self) -> None:
        paths = sorted(FIXTURES.glob("*/*/*/crumbs-h3.txt"))
        self.assertEqual(len(paths), 5)
        for path in paths:
            values = fixture_values(path)
            capacity = int(values["server_qpack_max_table_capacity"])
            requests = [key for key in values if key.endswith("_block_hex")]
            self.assertTrue(requests, path)
            for key in requests:
                prefix = key.removesuffix("_block_hex")
                connection = int(record(values[prefix])["connection"])
                run = prefix.rsplit("_request_", 1)[0]
                encoder_key = f"{run}_connection_{connection}_encoder_stream_hex"
                encoder_bytes = values[encoder_key]
                instructions = encoder_instructions(
                    b"" if encoder_bytes == "none" else bytes.fromhex(encoder_bytes)
                )
                inserted = sum(item.inserted is not None for item in instructions)
                self.assertLess(inserted, capacity // 32)
                section = field_section(
                    bytes.fromhex(values[key]),
                    capacity,
                    inserted,
                )
                self.assertEqual(
                    section.required_insert_count,
                    int(values[f"{prefix}_required_insert_count"]),
                )
                self.assertEqual(section.base, int(values[f"{prefix}_base"]))
                count = int(values[f"{prefix}_field_count"])
                self.assertEqual(len(section.lines), count, key)
                for index, line in enumerate(section.lines):
                    recorded = record(values[f"{prefix}_field_{index}"])
                    self.assertEqual(recorded["repr"], line.representation)
                    self.assertEqual(recorded["table"], line.table)
                    self.assertEqual(
                        recorded["absolute"],
                        "none" if line.absolute is None else str(line.absolute),
                    )


if __name__ == "__main__":
    unittest.main()
