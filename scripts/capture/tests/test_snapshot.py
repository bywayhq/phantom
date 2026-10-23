import argparse
import asyncio
import contextlib
import errno
import io
import socket
import ssl
import struct
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import ConnectionTerminated, ResponseReceived, StreamEnded

from scripts.capture import snapshot
from scripts.capture.browser_launch import LaunchedBrowser
from scripts.capture.cookie_crumbs import CaptureMetadata
from scripts.capture.http2_session import (
    HOSTNAME,
    ConnectionRecord,
    generate_certificate,
)
from scripts.capture.quic_resumption import parse_client_hello
from scripts.capture.snapshot import (
    FORMAT,
    InitialDatagram,
    SnapshotFailures,
    SnapshotRun,
    client_hello_records,
    hello_message,
    initial_datagram,
    launch_plan,
    page_url,
    problems,
    render_snapshot,
    reserve_shared_port,
    serving,
    split_snapshot,
    summary_lines,
)
from scripts.capture.snapshot_compare import (
    CHROMIUM_VARIATION,
    FIREFOX_QUIC_VARIATION,
    FIREFOX_TCP_VARIATION,
    Variation,
    compare,
    compare_hello,
    fields,
    tls_message,
)
from scripts.capture.tests.loopback_quic import connect_loopback

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures"
CHROME = "154.0.8037.58/windows-11-26200"
FIREFOX = "157.0/windows-11-26200"
CERTIFICATE = generate_certificate()
TIMEOUT = 20.0
METADATA = CaptureMetadata(
    client="scripted",
    client_version="1.0",
    operating_system="test",
    listen_address="127.0.0.1:0",
    launch_mode="scripted",
    launch_arguments="none",
)


def retained(path: str) -> dict[str, str]:
    return fields((FIXTURES / path).read_text(encoding="utf-8"))


def vector(width: int, body: bytes) -> bytes:
    return len(body).to_bytes(width, "big") + body


def client_hello(extensions: list[tuple[int, bytes]]) -> bytes:
    """A TLS 1.3 ClientHello handshake message with extensions in order."""
    body = (
        b"\x03\x03"
        + bytes(32)
        + vector(1, bytes(32))
        + vector(2, struct.pack(">HH", 0x1A1A, 0x1301))
        + b"\x01\x00"
        + vector(
            2, b"".join(struct.pack(">H", k) + vector(2, v) for k, v in extensions)
        )
    )
    return b"\x01" + vector(3, body)


class CaptureHandlerTests(unittest.IsolatedAsyncioTestCase):
    async def dispatch(self, error: BaseException) -> None:
        fired = asyncio.Event()

        def fail() -> None:
            try:
                raise error
            finally:
                fired.set()

        handle = asyncio.get_running_loop().call_soon(fail)
        try:
            await asyncio.wait_for(fired.wait(), 5)
        finally:
            handle.cancel()

    async def test_capture_restores_and_forwards_the_callers_handler(self) -> None:
        loop = asyncio.get_running_loop()
        original = loop.get_exception_handler()
        reports = []
        failure = RuntimeError("unrelated snapshot callback")

        def caller(active_loop, context):
            reports.append((active_loop, context))

        async def recorded_run(_args, _certificate):
            self.assertIsNot(loop.get_exception_handler(), caller)
            await self.dispatch(ConnectionResetError("closed capture peer"))
            self.assertEqual(reports, [])
            await self.dispatch(failure)
            return "snapshot payload\n"

        loop.set_exception_handler(caller)
        try:
            with TemporaryDirectory() as directory:
                args = argparse.Namespace(
                    output_dir=Path(directory),
                    repeat=1,
                    allow_partial=False,
                    run_timeout=1.0,
                    observation=0.0,
                    client_version="1.0",
                    operating_system="test",
                )
                with (
                    mock.patch.object(snapshot, "capture_run", recorded_run),
                    mock.patch.object(
                        snapshot, "generate_certificate", return_value=None
                    ),
                    mock.patch.object(snapshot, "problems", return_value=[]),
                ):
                    self.assertEqual(await snapshot.capture(args), 0)

                self.assertIs(loop.get_exception_handler(), caller)
                self.assertEqual(
                    (Path(directory) / "snapshot-1.txt").read_text(),
                    "snapshot payload\n",
                )

            self.assertEqual(len(reports), 1)
            self.assertIs(reports[0][0], loop)
            self.assertIs(reports[0][1]["exception"], failure)
            reset = ConnectionResetError("after snapshot completion")
            await self.dispatch(reset)
            self.assertIs(reports[-1][1]["exception"], reset)
        finally:
            loop.set_exception_handler(original)

    async def test_failed_or_cancelled_capture_restores_handler_before_return(self):
        loop = asyncio.get_running_loop()
        original = loop.get_exception_handler()
        caller = mock.Mock()
        loop.set_exception_handler(caller)
        try:
            for failure in (
                RuntimeError("snapshot run failed"),
                asyncio.CancelledError("snapshot interrupted"),
            ):
                with (
                    self.subTest(failure=type(failure).__name__),
                    TemporaryDirectory() as directory,
                ):
                    output = Path(directory) / "snapshot-1.txt"
                    output.write_bytes(b"previous snapshot\n")
                    args = argparse.Namespace(
                        output_dir=Path(directory),
                        repeat=1,
                        allow_partial=False,
                        run_timeout=1.0,
                        observation=0.0,
                        client_version="1.0",
                        operating_system="test",
                    )
                    with (
                        mock.patch.object(snapshot, "capture_run", side_effect=failure),
                        mock.patch.object(
                            snapshot, "generate_certificate", return_value=None
                        ),
                    ):
                        try:
                            await snapshot.capture(args)
                        except BaseException as observed:
                            self.assertIs(observed, failure)
                        else:
                            self.fail("capture discarded the initiating failure")

                    self.assertIs(loop.get_exception_handler(), caller)
                    self.assertEqual(output.read_bytes(), b"previous snapshot\n")
        finally:
            loop.set_exception_handler(original)

    async def test_capture_keeps_a_handler_installed_by_its_caller(self):
        loop = asyncio.get_running_loop()
        original = loop.get_exception_handler()
        replacement = mock.Mock()
        failure = RuntimeError("caller changed handler during capture")

        async def interrupted_run(_args, _certificate):
            loop.set_exception_handler(replacement)
            raise failure

        try:
            with TemporaryDirectory() as directory:
                args = argparse.Namespace(
                    output_dir=Path(directory),
                    repeat=1,
                    allow_partial=False,
                    run_timeout=1.0,
                    observation=0.0,
                    client_version="1.0",
                    operating_system="test",
                )
                with (
                    mock.patch.object(snapshot, "capture_run", interrupted_run),
                    mock.patch.object(
                        snapshot, "generate_certificate", return_value=None
                    ),
                    self.assertRaises(RuntimeError) as raised,
                ):
                    await snapshot.capture(args)

                self.assertIs(raised.exception, failure)
                self.assertIs(loop.get_exception_handler(), replacement)
                self.assertFalse((Path(directory) / "snapshot-1.txt").exists())
        finally:
            loop.set_exception_handler(original)


class CaptureInputTests(unittest.IsolatedAsyncioTestCase):
    def test_invalid_cli_waits_fail_before_capture_and_package_probes(self):
        base = [
            "--browser",
            "chrome",
            "--browser-path",
            "unused-browser",
            "--client-version",
            "0",
            "--operating-system",
            "test",
            "--output-dir",
            "unused-output",
        ]
        invalid = [
            ["--run-timeout", value] for value in ("nan", "inf", "-inf", "0", "-1")
        ]
        invalid.extend(
            ["--observation", value] for value in ("nan", "inf", "-inf", "-1")
        )
        invalid.append(["--repeat", "0"])
        invalid.append(["--repeat", "129"])
        invalid.extend(
            ["--secure-port", value] for value in ("0", "-1", "65536", "1.5", "bad")
        )
        invalid.append(["--run-timeout", "1e308", "--observation", "1e308"])
        with (
            mock.patch.object(snapshot, "capture") as capture,
            mock.patch.object(snapshot.metadata, "version") as version,
        ):
            for options in invalid:
                with (
                    self.subTest(options=options),
                    contextlib.redirect_stderr(io.StringIO()),
                ):
                    with self.assertRaises(SystemExit) as raised:
                        snapshot.main([*base, *options])
                    self.assertEqual(raised.exception.code, 2)

            capture.assert_not_called()
            version.assert_not_called()

    def test_cli_preserves_the_optional_explicit_secure_port(self):
        base = [
            "--browser",
            "firefox",
            "--browser-path",
            "unused-browser",
            "--client-version",
            "157.0",
            "--operating-system",
            "test",
            "--output-dir",
            "unused-output",
        ]
        for port in (None, 1, 443, 65535):
            options = [] if port is None else ["--secure-port", str(port)]
            with (
                self.subTest(port=port),
                mock.patch.object(
                    snapshot, "capture", new_callable=mock.AsyncMock, return_value=0
                ) as capture,
                mock.patch.object(
                    snapshot.metadata,
                    "version",
                    side_effect=snapshot.SUPPORTED.__getitem__,
                ),
            ):
                self.assertEqual(snapshot.main([*base, *options]), 0)
                self.assertEqual(capture.call_args.args[0].secure_port, port)

    async def test_invalid_secure_port_fails_before_certificate_or_listeners(self):
        with (
            mock.patch.object(snapshot, "generate_certificate") as certificate,
            mock.patch.object(snapshot.socket, "socket") as acquire,
            mock.patch.object(snapshot, "BrowserDriver") as browser,
        ):
            for port in (0, -1, 65536, True, 443.0, "443"):
                args = argparse.Namespace(
                    repeat=1,
                    run_timeout=1.0,
                    observation=0.0,
                    client_version="157.0",
                    operating_system="test",
                    secure_port=port,
                )
                with self.subTest(port=port):
                    with self.assertRaisesRegex(ValueError, "secure.port"):
                        await snapshot.capture(args)
                    with self.assertRaisesRegex(ValueError, "secure.port"):
                        await snapshot.capture_run(args, CERTIFICATE)
                    with self.assertRaisesRegex(ValueError, "secure.port"):
                        async with serving(
                            CERTIFICATE, "invalid-port", 0, secure_port=port
                        ):
                            self.fail("invalid port acquired capture listeners")
                    with self.assertRaisesRegex(ValueError, "secure.port"):
                        reserve_shared_port(port)

            certificate.assert_not_called()
            acquire.assert_not_called()
            browser.assert_not_called()

    async def test_capture_passes_the_explicit_port_to_shared_socket_acquisition(self):
        primary = OSError(errno.EADDRINUSE, "requested secure port is occupied")
        args = argparse.Namespace(
            repeat=1,
            run_timeout=1.0,
            observation=0.0,
            client_version="157.0",
            operating_system="test",
            secure_port=443,
        )
        with (
            mock.patch.object(
                snapshot, "reserve_shared_port", side_effect=primary
            ) as reserve,
            mock.patch.object(snapshot, "BrowserDriver") as browser,
            self.assertRaises(OSError) as raised,
        ):
            await snapshot.capture_run(args, CERTIFICATE)

        self.assertIs(raised.exception, primary)
        reserve.assert_called_once_with(443)
        browser.assert_not_called()

    async def test_direct_capture_rejects_invalid_waits_before_acquisition(self):
        loop = asyncio.get_running_loop()
        handler = loop.get_exception_handler()
        invalid = (
            (0, 1.0, 0.0),
            (129, 1.0, 0.0),
            (1, float("nan"), 0.0),
            (1, float("inf"), 0.0),
            (1, 0.0, 0.0),
            (1, 1.0, float("nan")),
            (1, 1.0, float("inf")),
            (1, 1.0, -1.0),
            (1, 1e308, 1e308),
        )
        with (
            mock.patch.object(snapshot, "generate_certificate") as certificate,
            mock.patch.object(snapshot, "serving") as serving,
        ):
            for repeat, timeout, observation in invalid:
                args = argparse.Namespace(
                    repeat=repeat, run_timeout=timeout, observation=observation
                )
                with self.subTest(
                    repeat=repeat, timeout=timeout, observation=observation
                ):
                    with self.assertRaises(ValueError):
                        await snapshot.capture(args)
                    with self.assertRaises(ValueError):
                        await snapshot.capture_run(args, CERTIFICATE)
                    self.assertIs(loop.get_exception_handler(), handler)

            certificate.assert_not_called()
            serving.assert_not_called()

    async def test_invalid_observation_never_binds_or_starts_the_run_clock(self):
        with mock.patch.object(snapshot, "reserve_shared_port") as reserve:
            for observation in (float("nan"), float("inf"), -1.0):
                clock = mock.Mock()
                with self.subTest(observation=observation):
                    with self.assertRaises(ValueError):
                        SnapshotRun("input", 1, 2, observation, clock=clock)
                    clock.assert_not_called()
                    with self.assertRaises(ValueError):
                        async with serving(CERTIFICATE, "input", observation):
                            self.fail("invalid observation acquired capture listeners")

            reserve.assert_not_called()

        clock = mock.Mock(return_value=42.0)
        run = SnapshotRun("valid", 1, 2, 0.0, clock=clock)
        self.assertEqual(run.started, 42.0)
        clock.assert_called_once_with()


class SnapshotOwnershipTests(unittest.IsolatedAsyncioTestCase):
    async def test_incomplete_or_alerted_tls_openings_still_fail_capture(self):
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        tls = client_tls_context().wrap_bio(
            incoming, outgoing, server_side=False, server_hostname=HOSTNAME
        )
        with self.assertRaises(ssl.SSLWantReadError):
            tls.do_handshake()
        hello = outgoing.read()

        for payload, followup, error_type in (
            (b"", b"", ConnectionError),
            (hello[:-1], b"", ConnectionError),
            (hello + b"\x16", b"", ConnectionError),
            (bytes.fromhex("15030300020228"), b"", ssl.SSLError),
            (hello, b"\x16", ConnectionError),
            (hello, bytes.fromhex("15030300020228"), ssl.SSLError),
        ):
            client = None
            run = None
            try:
                with self.subTest(payload_bytes=len(payload), followup=followup):
                    with self.assertRaises(error_type) as raised:
                        async with serving(CERTIFICATE, "invalid-opening", 0) as run:
                            client = await asyncio.open_connection(
                                "127.0.0.1", run.port
                            )
                            client[1].write(payload)
                            await client[1].drain()
                            if followup:
                                self.assertTrue(
                                    await asyncio.wait_for(client[0].read(1), TIMEOUT)
                                )
                                client[1].write(followup)
                                await client[1].drain()
                            client[1].write_eof()
                            await asyncio.wait_for(
                                run.owners[0].protocols[0].task, TIMEOUT
                            )
                            self.assertTrue(run.done.is_set())

                    self.assertIs(run.failures[0], raised.exception)
                    self.assertIsNone(run.finished)
                    self.assertTrue(all(owner.finished for owner in run.owners))
                    with self.assertRaises(error_type) as unpublished:
                        render_snapshot(run, METADATA)
                    self.assertIs(unpublished.exception, raised.exception)
            finally:
                if client is not None:
                    client[1].close()
                    await client[1].wait_closed()
                if run is not None:
                    for owner in run.owners:
                        await owner.close(asyncio.get_running_loop().time() + 10)

    async def test_clean_complete_handshake_eof_keeps_other_requests_running(self):
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        tls = client_tls_context().wrap_bio(
            incoming, outgoing, server_side=False, server_hostname=HOSTNAME
        )
        with self.assertRaises(ssl.SSLWantReadError):
            tls.do_handshake()

        client = None
        run = None
        try:
            async with serving(CERTIFICATE, "peer-close", 0.05) as run:
                client = await asyncio.open_connection("127.0.0.1", run.port)
                client[1].write(outgoing.read())
                await client[1].drain()
                self.assertTrue(await asyncio.wait_for(client[0].read(1), TIMEOUT))
                client[1].write_eof()
                await asyncio.wait_for(run.owners[0].protocols[0].task, TIMEOUT)

                self.assertEqual(run.connections[0].failure, "ConnectionError")
                self.assertTrue(run.connections[0].client_hello.complete)
                self.assertEqual(run.failures, [])
                self.assertFalse(run.done.is_set())
                self.assertIsNone(run.finished)
                self.assertFalse(run.owners[0].stopping)

                await asyncio.wait_for(h2_session(run.port, run.token), TIMEOUT)
                await asyncio.wait_for(h3_session(run.port, run.token), TIMEOUT)
                await asyncio.wait_for(
                    http1_requests(run.plain_port, run.token), TIMEOUT
                )
                await asyncio.wait_for(run.done.wait(), TIMEOUT)

            self.assertIsNotNone(run.finished)
            self.assertTrue(all(owner.finished for owner in run.owners))
            text = render_snapshot(run, METADATA)
            self.assertIn("failure:ConnectionError", text)
            self.assertEqual(problems(text), [])
        finally:
            if client is not None:
                client[1].close()
                await client[1].wait_closed()
            if run is not None:
                for owner in run.owners:
                    await owner.close(asyncio.get_running_loop().time() + 10)

    async def test_completion_requires_one_origin_form_run_token(self):
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
        run = SnapshotRun("token", 1, 2, 0)
        for target in invalid:
            with self.subTest(target=target):
                kind = run.classify(target)
                run.record("http/1.1", snapshot.RequestRecord(0, 0, kind, None))
                self.assertEqual(kind, "other")
                self.assertIsNone(run.finished)
                self.assertIsNone(run.observation_timer)
                self.assertFalse(run.done.is_set())

        kind = run.classify(b"/done?run=token")
        run.record("http/1.1", snapshot.RequestRecord(0, 0, kind, None))
        try:
            self.assertEqual(kind, "done")
            self.assertIsNotNone(run.finished)
            await asyncio.wait_for(run.done.wait(), TIMEOUT)
        finally:
            if run.observation_timer is not None:
                run.observation_timer.cancel()

    async def test_failed_stream_setup_collects_original_transport_and_native_loss(
        self,
    ):
        primary = ValueError("original snapshot stream setup failure")
        abort_failure = OSError(errno.EIO, "original accepted transport abort failure")
        close_failure = OSError(errno.EIO, "original accepted transport close failure")
        native_loss = OSError(errno.EIO, "original accepted native loss")
        connected = asyncio.Event()
        original_made = snapshot.SnapshotTcpProtocol.connection_made
        loop = asyncio.get_running_loop()
        transports = []
        run = None
        client = None

        try:
            with contextlib.ExitStack() as faults:

                def made(protocol, transport):
                    transports.append(transport)
                    attempts = 0

                    def abort():
                        nonlocal attempts
                        attempts += 1
                        if attempts == 1:
                            raise abort_failure
                        # Both resolved native TCP backends deliver this
                        # original error through their real retirement path.
                        transport._force_close(native_loss)

                    faults.enter_context(
                        mock.patch.object(transport, "abort", side_effect=abort)
                    )
                    faults.enter_context(
                        mock.patch.object(transport, "close", side_effect=close_failure)
                    )
                    with mock.patch.object(
                        protocol._stream_reader, "set_transport", side_effect=primary
                    ):
                        original_made(protocol, transport)
                    connected.set()

                faults.enter_context(
                    mock.patch.object(
                        snapshot.SnapshotTcpProtocol, "connection_made", new=made
                    )
                )
                with self.assertRaises(SnapshotFailures) as raised:
                    async with serving(CERTIFICATE, "setup-fault", 0) as run:
                        client = await asyncio.open_connection(
                            "127.0.0.1", run.plain_port
                        )
                        await asyncio.wait_for(connected.wait(), TIMEOUT)
                        protocol = run.owners[0].protocols[0]
                        self.assertIs(protocol.transport, transports[0])
                        self.assertIsNone(protocol.writer)
                        self.assertFalse(protocol.retired.done())

                self.assertEqual(len(transports), 1)
                self.assertEqual(len(raised.exception.cleanup), 4)
                for error in (primary, abort_failure, close_failure, native_loss):
                    self.assertTrue(
                        any(retained is error for retained in raised.exception.cleanup)
                    )
                owner = run.owners[0]
                self.assertTrue(owner.finished)
                self.assertTrue(protocol.retired.done())
                self.assertTrue(protocol.close_task.done())
                self.assertTrue(protocol.closed_observed)
                self.assertIs(protocol.stream_closed.exception(), native_loss)
                self.assertIsNone(transports[0]._sock)
                self.assertEqual(await asyncio.wait_for(client[0].read(), TIMEOUT), b"")
                with self.assertRaises(SnapshotFailures) as unpublished:
                    render_snapshot(run, METADATA)
                for error in (primary, abort_failure, close_failure, native_loss):
                    self.assertTrue(
                        any(
                            retained is error
                            for retained in unpublished.exception.cleanup
                        )
                    )
        finally:
            # Retire only original native test backups after all assertions.
            for transport in transports:
                transport.abort()
            if client is not None:
                client[1].close()
                await client[1].wait_closed()
            if run is not None:
                for owner in run.owners:
                    await owner.close(loop.time() + 10)

    def test_shared_port_reservation_escapes_a_wide_ephemeral_exclusion(self):
        sockets = []
        candidates = []

        def acquire(*args):
            sock = mock.Mock()
            sockets.append(sock)
            ephemeral = 56_000 + len(sockets)

            def bind(address):
                host, port = address
                self.assertEqual(host, snapshot.HOST)
                candidates.append(port)
                if 55_961 <= port <= 56_860:
                    failure = PermissionError(errno.EACCES, "reserved test port")
                    failure.winerror = 10013
                    raise failure

            sock.bind.side_effect = bind
            sock.getsockname.return_value = (snapshot.HOST, ephemeral)
            return sock

        with (
            mock.patch.object(snapshot.socket, "socket", side_effect=acquire),
            mock.patch.object(snapshot.secrets, "randbelow", return_value=0),
        ):
            tcp, udp = reserve_shared_port()

        self.assertEqual(len(sockets), 2)
        self.assertIs(tcp, sockets[0])
        self.assertIs(udp, sockets[1])
        self.assertEqual(candidates, [20_000, 20_000])
        tcp.listen.assert_called_once_with(64)
        for sock in sockets:
            sock.setblocking.assert_called_once_with(False)
            sock.close.assert_not_called()

    def test_shared_port_reservation_exhaustion_preserves_last_bind_error(self):
        sockets = []
        candidates = []
        failures = []

        def acquire(*args):
            sock = mock.Mock()
            sockets.append(sock)

            def bind(address):
                candidates.append(address[1])
                failure = PermissionError(errno.EACCES, "reserved test port")
                failure.winerror = 10013
                failures.append(failure)
                raise failure

            sock.bind.side_effect = bind
            return sock

        with (
            mock.patch.object(snapshot.socket, "socket", side_effect=acquire),
            mock.patch.object(snapshot.secrets, "randbelow", return_value=12_767),
            self.assertRaises(PermissionError) as raised,
        ):
            reserve_shared_port()

        self.assertIs(raised.exception, failures[-1])
        self.assertEqual(len(failures), snapshot.MAX_PORT_ATTEMPTS)
        self.assertEqual(len(set(candidates)), snapshot.MAX_PORT_ATTEMPTS)
        self.assertTrue(all(20_000 <= port < 32_768 for port in candidates))
        for sock in sockets:
            sock.close.assert_called_once_with()
            sock.listen.assert_not_called()

    async def test_raw_socket_acquisition_preserves_creation_bind_and_listen_failures(
        self,
    ):
        create = socket.socket
        for scope, operation in (
            ("reserve", "create"),
            ("reserve", "bind"),
            ("reserve", "listen"),
            ("serving", "create"),
            ("serving", "bind"),
            ("serving", "listen"),
        ):
            primary = OSError(errno.EIO, f"original reservation {operation} failure")
            sockets = []
            index = 3 if scope == "serving" else 1 if operation == "listen" else 2

            def acquire(
                *args,
                operation=operation,
                index=index,
                primary=primary,
                sockets=sockets,
                **kwargs,
            ):
                if operation == "create" and len(sockets) + 1 == index:
                    raise primary
                sock = create(*args, **kwargs)
                sockets.append(sock)
                proxy = mock.Mock(wraps=sock)
                # These failures precede listener publication. Keep real socket
                # ownership without unrelated port collisions bypassing the fault.
                proxy.bind.return_value = None
                proxy.listen.return_value = None
                if operation == "bind" and len(sockets) == index:
                    proxy.bind.side_effect = primary
                if operation == "listen" and len(sockets) == index:
                    proxy.listen.side_effect = primary
                return proxy

            with (
                self.subTest(scope=scope, operation=operation),
                mock.patch.object(snapshot.socket, "socket", side_effect=acquire),
                self.assertRaises(OSError) as raised,
            ):
                if scope == "reserve":
                    reserve_shared_port()
                else:
                    async with serving(CERTIFICATE, "raw-fault", 0):
                        self.fail("raw acquisition failure entered serving scope")

            self.assertIs(raised.exception, primary)
            self.assertEqual(
                len(sockets),
                index - 1 if operation == "create" else 3 if scope == "serving" else 2,
            )
            self.assertTrue(all(sock.fileno() == -1 for sock in sockets))
            for sock in sockets:
                sock.close()

    def test_reserved_bind_retry_preserves_later_listen_failure(self):
        create = socket.socket
        primary = OSError(errno.EIO, "original listen failure after bind retry")
        reserved = PermissionError(errno.EACCES, "reserved test port")
        reserved.winerror = 10013
        sockets = []

        def acquire(*args, **kwargs):
            sock = create(*args, **kwargs)
            sockets.append(sock)
            proxy = mock.Mock(wraps=sock)
            proxy.bind.return_value = None
            proxy.listen.return_value = None
            if len(sockets) == 1:
                proxy.bind.side_effect = reserved
            if len(sockets) == 3:
                proxy.listen.side_effect = primary
            return proxy

        try:
            with (
                mock.patch.object(snapshot.socket, "socket", side_effect=acquire),
                self.assertRaises(OSError) as raised,
            ):
                reserve_shared_port()

            self.assertIs(raised.exception, primary)
            self.assertEqual(len(sockets), 4)
            self.assertTrue(all(sock.fileno() == -1 for sock in sockets))
        finally:
            for sock in sockets:
                sock.close()

    async def test_second_listener_failure_collects_first_accepted_stream(self):
        primary = OSError(errno.EIO, "original second snapshot listener failure")
        loop = asyncio.get_running_loop()
        original_create = loop.create_server
        connected = asyncio.Event()
        original_connected = snapshot.SnapshotTcpProtocol.connected
        acquired = []
        client = None
        run = None
        reservation = []
        original_reserve = reserve_shared_port

        def reserve(secure_port=None):
            sockets = original_reserve(secure_port)
            reservation.extend(sockets)
            return sockets

        def accepted(protocol, reader, writer):
            original_connected(protocol, reader, writer)
            connected.set()

        async def create(*args, **kwargs):
            nonlocal client, run
            if acquired:
                port = acquired[0].sockets[0].getsockname()[1]
                client = await asyncio.open_connection("127.0.0.1", port)
                await asyncio.wait_for(connected.wait(), TIMEOUT)
                raise primary
            listener = await original_create(*args, **kwargs)
            acquired.append(listener)
            return listener

        original_listeners = snapshot.TcpListeners

        def listeners(active_run, certificate):
            nonlocal run
            run = active_run
            return original_listeners(active_run, certificate)

        try:
            with (
                mock.patch.object(snapshot, "reserve_shared_port", side_effect=reserve),
                mock.patch.object(snapshot, "TcpListeners", side_effect=listeners),
                mock.patch.object(
                    snapshot.SnapshotTcpProtocol, "connected", new=accepted
                ),
                mock.patch.object(loop, "create_server", side_effect=create),
                self.assertRaises(OSError) as raised,
            ):
                async with serving(CERTIFICATE, "partial", 0):
                    self.fail("second listener failure entered serving scope")

            self.assertIs(raised.exception, primary)
            self.assertTrue(all(sock.fileno() == -1 for sock in reservation))
            owner = run.owners[0]
            self.assertTrue(owner.finished)
            protocol = owner.protocols[0]
            self.assertTrue(protocol.task.done())
            self.assertTrue(protocol.retired.done())
            self.assertTrue(protocol.close_task.done())
            self.assertTrue(protocol.closed_observed)
            self.assertIsNone(protocol.transport._sock)
            self.assertTrue(all(not server.is_serving() for server in acquired))
            self.assertTrue(all(not server.sockets for server in acquired))
            self.assertTrue(all(task.done() for task in owner.waiters.values()))
            self.assertTrue(
                all(
                    server in owner.closed and server in owner.observed
                    for server in acquired
                )
            )
            self.assertEqual(await asyncio.wait_for(client[0].read(), TIMEOUT), b"")
            with self.assertRaises(OSError) as unpublished:
                render_snapshot(run, METADATA)
            self.assertIs(unpublished.exception, primary)
        finally:
            if client is not None:
                client[1].close()
                await client[1].wait_closed()
            for sock in reservation:
                sock.close()
            if run is not None:
                for owner in run.owners:
                    await owner.close(loop.time() + 10)

    async def test_original_accepted_factory_fault_refuses_publication(self):
        primary = ValueError("original snapshot accepted factory failure")
        loop = asyncio.get_running_loop()
        previous_handler = loop.get_exception_handler()
        unexpected = []
        client = None
        run = None
        accepted = []
        listener_sockets = []

        def report(active_loop, context):
            if context.get("exception") is primary:
                retain_native_accept()
                return
            unexpected.append(context)
            if previous_handler is None:
                active_loop.default_exception_handler(context)
            else:
                previous_handler(active_loop, context)

        def retain_native_accept():
            traceback = primary.__traceback__
            while traceback is not None:
                conn = traceback.tb_frame.f_locals.get("conn")
                if isinstance(conn, socket.socket) and all(
                    sock is not conn for sock in accepted
                ):
                    accepted.append(conn)
                traceback = traceback.tb_next

        try:
            loop.set_exception_handler(report)
            with self.assertRaises(ValueError) as raised:
                async with serving(CERTIFICATE, "factory", 0) as run:
                    listener_sockets.extend(
                        sock
                        for server in run.owners[0].servers
                        for sock in server.sockets
                    )
                    with mock.patch.object(
                        snapshot, "SnapshotTcpProtocol", side_effect=primary
                    ):
                        client = await asyncio.open_connection(
                            "127.0.0.1", run.plain_port
                        )
                        await asyncio.wait_for(run.done.wait(), TIMEOUT)

            self.assertIs(raised.exception, primary)
            self.assertIs(run.failures[0], primary)
            self.assertEqual(run.owners[0].protocols, [])
            self.assertTrue(all(owner.finished for owner in run.owners))
            self.assertEqual(unexpected, [])
            with self.assertRaises(ValueError) as unpublished:
                render_snapshot(run, METADATA)
            self.assertIs(unpublished.exception, primary)
            owner = run.owners[0]
            self.assertTrue(all(sock.fileno() == -1 for sock in listener_sockets))
            self.assertTrue(all(not server.is_serving() for server in owner.servers))
            self.assertTrue(all(not server.sockets for server in owner.servers))
            self.assertTrue(all(task.done() for task in owner.waiters.values()))
            self.assertTrue(
                all(
                    server in owner.closed and server in owner.observed
                    for server in owner.servers
                )
            )
            self.assertEqual(len(accepted), 1)
        finally:
            # This socket never reached protocol attachment. Retire only this
            # original native test backup after the ownership assertions.
            try:
                retain_native_accept()
                for sock in accepted:
                    sock.close()
                if client is not None:
                    client[1].close()
                    await client[1].wait_closed()
                if run is not None:
                    for owner in run.owners:
                        await owner.close(loop.time() + 10)
            finally:
                loop.set_exception_handler(previous_handler)

    async def test_serving_and_cleanup_interruption_keep_original_causes(self):
        primary = TimeoutError(
            errno.ETIMEDOUT, "original snapshot retirement read failure"
        )
        cleanup = OSError(errno.EIO, "original snapshot writer cleanup failure")
        cancellation_cause = LookupError("original snapshot interruption cause")
        entered = asyncio.Event()
        release = asyncio.Event()
        observing = asyncio.Event()
        complete = asyncio.Event()
        original_wait = asyncio.wait
        client = None
        direct = None
        run = None

        async def observe(*args, **kwargs):
            try:
                return await original_wait(*args, **kwargs)
            except asyncio.CancelledError as error:
                error.__cause__ = cancellation_cause
                raise

        async def fail(channel, active_run, index, listener):
            await channel.read()
            entered.set()
            await release.wait()
            with mock.patch.object(channel, "read_raw", side_effect=primary):
                await snapshot.retire(channel)

        async def failed_close():
            observing.set()
            await complete.wait()
            raise cleanup

        scope = serving(CERTIFICATE, "causes", 0)
        try:
            run = await scope.__aenter__()
            with mock.patch.object(snapshot, "serve_http1", side_effect=fail):
                client = await asyncio.open_connection("127.0.0.1", run.plain_port)
                client[1].write(
                    b"GET /plain?run=causes HTTP/1.1\r\nHost: localhost\r\n\r\n"
                )
                await client[1].drain()
                await asyncio.wait_for(entered.wait(), TIMEOUT)
                protocol = run.owners[0].protocols[0]

                async def collect():
                    nonlocal direct
                    try:
                        await scope.__aexit__(None, None, None)
                    except asyncio.CancelledError as error:
                        direct = error
                        raise

                with (
                    mock.patch.object(
                        protocol.writer, "wait_closed", side_effect=failed_close
                    ),
                    mock.patch.object(snapshot.asyncio, "wait", side_effect=observe),
                ):
                    release.set()
                    await asyncio.wait_for(run.done.wait(), TIMEOUT)
                    closing = asyncio.create_task(collect())
                    await asyncio.wait_for(observing.wait(), TIMEOUT)
                    closing.cancel("original snapshot cleanup interruption")
                    complete.set()
                    with self.assertRaises(asyncio.CancelledError):
                        await closing

            self.assertTrue(closing.cancelled())
            self.assertIsInstance(direct, asyncio.CancelledError)
            self.assertEqual(direct.args, ("original snapshot cleanup interruption",))
            failure = direct.__cause__
            self.assertIsInstance(failure, SnapshotFailures)
            self.assertIs(failure.interruption_cause, cancellation_cause)
            self.assertTrue(any(error is primary for error in failure.cleanup))
            self.assertTrue(any(error is cleanup for error in failure.cleanup))
            self.assertTrue(any(error is direct for error in failure.cleanup))
            self.assertTrue(all(owner.finished for owner in run.owners))
            self.assertTrue(protocol.task.done())
            self.assertTrue(protocol.retired.done())
            self.assertEqual(await asyncio.wait_for(client[0].read(), TIMEOUT), b"")
            with TemporaryDirectory() as directory:
                output = Path(directory) / "snapshot.txt"
                output.write_bytes(b"previous snapshot\n")
                with self.assertRaises(asyncio.CancelledError) as unpublished:
                    snapshot.write_text_fixture(output, render_snapshot(run, METADATA))
                self.assertIs(unpublished.exception, direct)
                self.assertEqual(output.read_bytes(), b"previous snapshot\n")
        finally:
            release.set()
            complete.set()
            if client is not None:
                client[1].close()
                await client[1].wait_closed()
            await scope.__aexit__(None, None, None)
            if run is not None:
                for owner in run.owners:
                    await owner.close(asyncio.get_running_loop().time() + 10)

    async def test_completed_http1_header_limit_keeps_the_exact_boundary(self):
        prefix = b"GET /done?run=head HTTP/1.1\r\nHost: localhost\r\nX-Pad: "
        for size, aggregate in (
            (65536, 8 * 1024 * 1024),
            (65537, 8 * 1024 * 1024),
            (65536, 65535),
        ):
            run = None
            client = None
            observed = None
            try:
                with (
                    self.subTest(size=size, aggregate=aggregate),
                    mock.patch.object(snapshot, "MAX_RUN_CAPTURE", aggregate),
                ):
                    try:
                        async with serving(CERTIFICATE, "head", 0) as run:
                            client = await asyncio.open_connection(
                                "127.0.0.1", run.plain_port
                            )
                            head = (
                                prefix + b"x" * (size - len(prefix) - 4) + b"\r\n\r\n"
                            )
                            client[1].write(head)
                            await asyncio.wait_for(run.done.wait(), TIMEOUT)
                            if size == 65536 and aggregate > size:
                                response = await asyncio.wait_for(
                                    client[0].readuntil(b"\r\n\r\n"), TIMEOUT
                                )
                                self.assertTrue(response.startswith(b"HTTP/1.1 200 "))
                            else:
                                self.assertEqual(run.requests, [])
                    except ValueError as error:
                        observed = error
                    if size == 65536 and aggregate > size:
                        self.assertIsNone(observed)
                        self.assertEqual(len(run.requests), 1)
                        self.assertIn(
                            "http3=not-used", problems(render_snapshot(run, METADATA))
                        )
                    else:
                        self.assertIs(observed, run.failures[0])
                        self.assertIn(
                            "header limit" if size == 65537 else "aggregate",
                            str(observed),
                        )
                        with self.assertRaises(ValueError) as unpublished:
                            render_snapshot(run, METADATA)
                        self.assertIs(unpublished.exception, observed)
                    self.assertTrue(all(owner.finished for owner in run.owners))
            finally:
                if client is not None:
                    client[1].close()
                    await client[1].wait_closed()
                if run is not None:
                    for owner in run.owners:
                        await owner.close(asyncio.get_running_loop().time() + 10)

    async def test_original_http3_callback_failure_prevents_partial_publication(self):
        primary = OSError(errno.EIO, "original snapshot HTTP/3 callback failure")
        configuration = QuicConfiguration(
            is_client=True,
            alpn_protocols=H3_ALPN,
            server_name=HOSTNAME,
            verify_mode=ssl.CERT_NONE,
        )
        run = None
        try:
            with self.assertRaises(OSError) as raised:
                async with serving(CERTIFICATE, "quic-fault", 0) as run:
                    with mock.patch.object(run, "record", side_effect=primary):
                        async with connect_loopback(
                            run.port, configuration, H3Client
                        ) as client:
                            stream = client._quic.get_next_available_stream_id()
                            client.http.send_headers(
                                stream,
                                [
                                    (b":method", b"GET"),
                                    (b":scheme", b"https"),
                                    (b":authority", HOSTNAME.encode()),
                                    (b":path", b"/next?run=quic-fault"),
                                ],
                                end_stream=True,
                            )
                            client.transmit()
                            await asyncio.wait_for(run.done.wait(), TIMEOUT)

            self.assertIs(raised.exception, primary)
            self.assertIs(run.failures[0], primary)
            owner = run.owners[1]
            self.assertTrue(owner.retired.done())
            self.assertTrue(owner.finished)
            self.assertTrue(
                all(protocol.observed_closed for protocol in owner.protocols)
            )
            with self.assertRaises(OSError) as unpublished:
                render_snapshot(run, METADATA)
            self.assertIs(unpublished.exception, primary)
        finally:
            if run is not None:
                for owner in run.owners:
                    await owner.close(asyncio.get_running_loop().time() + 10)


class ClientHelloTests(unittest.TestCase):
    def test_summary_reproduces_the_retained_chrome_summary(self) -> None:
        values = retained(f"tls/chrome/{CHROME}/client-hello.txt")
        records = [bytes.fromhex(values[f"record_{i}_hex"]) for i in range(1)]
        expected = [
            f"{key}={values[key]}"
            for key in (
                "legacy_version",
                "cipher_suites",
                "extension_types",
                "supported_groups",
                "ec_point_formats",
                "signature_algorithms",
                "alpn_protocols_hex",
                "supported_versions",
                "key_share_groups",
                "server_name_hex",
            )
        ]
        self.assertEqual(summary_lines(hello_message(records)), expected)
        self.assertEqual(client_hello_records(b"".join(records)), records)

    def test_summary_reads_the_retained_quic_client_hello(self) -> None:
        values = retained(f"http3/chrome/{CHROME}/quic-client-hello-1.txt")
        summary = fields(
            "\n".join(summary_lines(bytes.fromhex(values["handshake_hex"])))
        )
        self.assertEqual(summary["cipher_suites"], "0x1301,0x1302,0x1303")
        self.assertEqual(summary["alpn_protocols_hex"], b"h3".hex())
        self.assertEqual(summary["server_name_hex"], HOSTNAME.encode().hex())

    def test_records_stop_at_the_end_of_the_client_hello(self) -> None:
        message = client_hello([(0x0000, b"")])
        record = b"\x16\x03\x01" + vector(2, message)
        self.assertEqual(
            client_hello_records(record + b"\x14\x03\x03\x00\x01\x01"), [record]
        )
        with self.assertRaisesRegex(ValueError, "no complete ClientHello"):
            client_hello_records(record[:-1])


class ComparisonTests(unittest.TestCase):
    ALPS = (0x44CD, bytes.fromhex("0003026832"))

    # quic_transport_parameters, encrypted_client_hello, pre_shared_key.
    TAIL = (
        (0x0039, b""),
        (0xFE0D, bytes.fromhex("0000010001070002000000020000")),
        (0x0029, b""),
    )

    def test_chromium_permutation_is_not_a_difference(self) -> None:
        old = client_hello([(0x0A0A, b""), (0x0017, b""), self.ALPS])
        new = client_hello([(0x3A3A, b""), self.ALPS, (0x0017, b"")])
        self.assertEqual(compare_hello("tls", new, old, CHROMIUM_VARIATION), [])

    def test_firefox_tcp_permutation_is_a_difference(self) -> None:
        old = client_hello([(0x0017, b""), self.ALPS])
        new = client_hello([self.ALPS, (0x0017, b"")])
        report = compare_hello("tls", new, old, FIREFOX_TCP_VARIATION)
        self.assertEqual(len(report), 1)
        self.assertIn("extension_types", report[0])

    def test_firefox_quic_shuffle_before_the_fixed_tail_is_not_a_difference(
        self,
    ) -> None:
        old = client_hello([(0x0017, b""), self.ALPS, *self.TAIL])
        new = client_hello([self.ALPS, (0x0017, b""), *self.TAIL])
        self.assertEqual(
            compare_hello("quic_tls", new, old, FIREFOX_QUIC_VARIATION), []
        )

    def test_firefox_quic_extension_moved_out_of_the_tail_is_a_difference(
        self,
    ) -> None:
        transport_parameters, ech, _ = self.TAIL
        old = client_hello([(0x0017, b""), self.ALPS, transport_parameters, ech])
        for new in (
            client_hello([transport_parameters, (0x0017, b""), self.ALPS, ech]),
            client_hello([(0x0017, b""), self.ALPS, ech, transport_parameters]),
            client_hello([(0x0017, b""), transport_parameters, ech]),
        ):
            report = compare_hello("quic_tls", new, old, FIREFOX_QUIC_VARIATION)
            self.assertEqual(len(report), 1, report)
            self.assertIn("quic_tls.extension_types", report[0])

    def test_retained_firefox_quic_client_hellos_match_one_another(self) -> None:
        directory = FIXTURES / "http3" / "firefox" / FIREFOX
        hellos = [
            bytes.fromhex(retained(path.relative_to(FIXTURES))["handshake_hex"])
            for path in sorted(directory.glob("quic-client-hello-*.txt"))
        ]
        self.assertEqual(len(hellos), 3)
        orders = {tuple(parse_client_hello(h).extension_types) for h in hellos}
        self.assertEqual(len(orders), 3, "the retained orders should all differ")
        for hello in hellos[1:]:
            self.assertEqual(
                compare_hello("quic_tls", hello, hellos[0], FIREFOX_QUIC_VARIATION),
                [],
            )
            self.assertNotEqual(
                compare_hello("quic_tls", hello, hellos[0], Variation()), []
            )

    def test_retained_firefox_snapshots_have_no_client_hello_difference(
        self,
    ) -> None:
        directory = FIXTURES / "http3" / "firefox" / FIREFOX
        snapshots = sorted(directory.glob("snapshot-*.txt"))
        self.assertEqual(
            {path.name for path in snapshots},
            {
                "snapshot-1.txt",
                "snapshot-2.txt",
                "snapshot-3.txt",
                "snapshot-4.txt",
                "snapshot-5.txt",
                "snapshot-port-443-diagnostic.txt",
            },
        )
        tcp = retained(f"tls/firefox/{FIREFOX}/client-hello.txt")
        quic = retained(f"http3/firefox/{FIREFOX}/quic-client-hello-1.txt")
        for path in snapshots:
            text = path.read_text(encoding="utf-8")
            with self.subTest(snapshot=path.name, protocol="tcp"):
                self.assertEqual(
                    compare_hello(
                        "tls",
                        tls_message(fields(text, "tls.")),
                        tls_message(tcp),
                        FIREFOX_TCP_VARIATION,
                    ),
                    [],
                )
            with self.subTest(snapshot=path.name, protocol="quic"):
                self.assertEqual(
                    compare_hello(
                        "quic_tls",
                        bytes.fromhex(
                            fields(text, "quic_client_hello.")["handshake_hex"]
                        ),
                        bytes.fromhex(quic["handshake_hex"]),
                        FIREFOX_QUIC_VARIATION,
                    ),
                    [],
                )

    def test_firefox_ech_grease_aead_is_not_a_difference(self) -> None:
        def hello(aead: int) -> bytes:
            # Outer ECH: HKDF-SHA256, the AEAD, config ID, and a 32-byte enc.
            body = b"\x00" + struct.pack(">HHB", 0x0001, aead, 7) + vector(2, bytes(32))
            return client_hello([(0xFE0D, body + vector(2, bytes(240)))])

        aes, chacha, aes_256 = hello(0x0001), hello(0x0003), hello(0x0002)
        self.assertEqual(compare_hello("tls", chacha, aes, FIREFOX_TCP_VARIATION), [])
        self.assertEqual(
            len(compare_hello("tls", aes_256, aes, FIREFOX_TCP_VARIATION)), 1
        )
        self.assertEqual(len(compare_hello("tls", chacha, aes, CHROMIUM_VARIATION)), 1)

    def test_a_changed_extension_body_is_a_difference(self) -> None:
        old = client_hello([self.ALPS])
        new = client_hello([(0x44CD, bytes.fromhex("0003026833"))])
        self.assertEqual(
            compare_hello("tls", new, old, CHROMIUM_VARIATION),
            ["tls.extension 0x44cd: retained 0003026832, snapshot 0003026833"],
        )

    def test_key_share_and_grease_values_are_normalized(self) -> None:
        def hello(grease: int, key: bytes) -> bytes:
            groups = vector(2, struct.pack(">HH", grease, 0x001D))
            share = vector(2, struct.pack(">H", 0x001D) + vector(2, key))
            return client_hello([(0x000A, groups), (0x0033, share)])

        new, old = hello(0x2A2A, bytes(32)), hello(0x8A8A, bytes(range(32)))
        self.assertEqual(compare_hello("tls", new, old, Variation()), [])

    def test_malformed_extension_extents_cannot_match_a_valid_hello(self) -> None:
        groups = bytes.fromhex("0002001d")
        shares = bytes.fromhex("0008001d000461626364")
        ech = self.TAIL[1][1]
        anchors = bytes.fromhex("0003026162")
        cases = (
            (0x000A, groups, bytes.fromhex("0003001d00")),
            (0x000D, groups, bytes.fromhex("0004001d")),
            (0x002B, bytes.fromhex("020304"), bytes.fromhex("03030400")),
            (0x000A, groups, bytes.fromhex("0000")),
            (0x0033, shares, bytes.fromhex("0008001d00046162")),
            (0x0033, shares, bytes.fromhex("0006001d00046162")),
            (0x0033, shares, bytes.fromhex("000100")),
            (0x0033, shares, bytes.fromhex("0004001d0000")),
            (0xFE0D, ech, ech[:8]),
            (0xFE0D, ech, ech[:9]),
            (0xFE0D, ech, ech[:10]),
            (0xFE0D, ech, ech[:-1]),
            (0xFE0D, ech, ech + b"\x00"),
            (0xCA34, anchors, bytes.fromhex("0004026162")),
            (0xCA34, anchors, bytes.fromhex("00030261")),
            (0xCA34, anchors, bytes.fromhex("000101")),
            (0xCA34, anchors, bytes.fromhex("000100")),
            (0x0039, bytes.fromhex("110400000001"), bytes.fromhex("1103000001")),
        )
        for kind, valid, malformed in cases:
            with (
                self.subTest(kind=kind, body=malformed.hex()),
                self.assertRaises(ValueError),
            ):
                compare_hello(
                    "tls",
                    client_hello([(kind, malformed)]),
                    client_hello([(kind, valid)]),
                    CHROMIUM_VARIATION,
                )

    def test_duplicate_extensions_cannot_hide_a_changed_body(self) -> None:
        old = client_hello([self.ALPS, (0x44CD, bytes.fromhex("0003026833"))])
        new = client_hello([(0x44CD, bytes.fromhex("0003026833"))] * 2)
        with self.assertRaisesRegex(ValueError, "duplicate ClientHello extension"):
            compare_hello("tls", new, old, CHROMIUM_VARIATION)

    def test_trust_anchor_permutation_keeps_the_browser_order_policy(self) -> None:
        old = client_hello([(0xCA34, vector(2, b"\x01a\x01b"))])
        new = client_hello([(0xCA34, vector(2, b"\x01b\x01a"))])
        self.assertEqual(compare_hello("tls", new, old, CHROMIUM_VARIATION), [])
        self.assertEqual(len(compare_hello("tls", new, old, FIREFOX_TCP_VARIATION)), 1)

    def test_snapshot_reports_malformed_hello_instead_of_a_false_match(self) -> None:
        values = retained(f"tls/chrome/{CHROME}/client-hello.txt")
        message = client_hello([(0x000A, bytes.fromhex("0003001d00"))])
        record = b"\x16\x03\x01" + vector(2, message)
        text = (
            f"format={FORMAT}\noperating_system={values['operating_system']}\n"
            "tls.format=phantom-client-hello-v2\ntls.record_count=1\n"
            f"tls.record_0_hex={record.hex()}\n"
        )
        report = compare(text, FIXTURES, "chrome")
        self.assertEqual(len(report), 1)
        self.assertTrue(report[0].startswith("differs input: ValueError:"), report)
        self.assertIn("extension 0x000a", report[0])

    def test_snapshot_rejects_invalid_counts_and_missing_declared_entries(self) -> None:
        values = retained(f"tls/chrome/{CHROME}/client-hello.txt")
        prefix = f"format={FORMAT}\noperating_system={values['operating_system']}\n"
        sections = (
            (
                "tls.format=phantom-client-hello-v2\n",
                "tls.record_count",
                "record_count",
            ),
            ("", "h2.frame_count", "frame_count"),
            ("", "hint_count", "hint_count"),
        )
        for section, key, diagnostic in sections:
            for count in ("-1", "1.5", "100000000", "16385"):
                with self.subTest(key=key, count=count):
                    report = compare(
                        prefix + section + f"{key}={count}\n", FIXTURES, "chrome"
                    )
                    self.assertEqual(len(report), 1)
                    self.assertTrue(
                        report[0].startswith("differs input: ValueError:"), report
                    )
                    self.assertIn(diagnostic, report[0])
        for section, key, missing in (
            (sections[0][0], "tls.record_count", "record_0_hex"),
            ("", "h2.frame_count", "frame_0_hex"),
            ("", "hint_count", "hint_0"),
        ):
            with self.subTest(missing=missing):
                report = compare(prefix + section + f"{key}=1\n", FIXTURES, "chrome")
                self.assertEqual(len(report), 1)
                self.assertTrue(
                    report[0].startswith("differs input: KeyError:"), report
                )
                self.assertIn(missing, report[0])

    def test_zero_counts_are_valid_but_negative_counts_cannot_match_no_hints(
        self,
    ) -> None:
        macos = retained("client-hints/firefox/157.0/macos-15.5-arm64/navigation.txt")
        prefix = f"format={FORMAT}\noperating_system={macos['operating_system']}\n"
        report = compare(prefix + "hint_count=0\n", FIXTURES, "firefox")
        self.assertFalse(
            any(line.startswith("differs client_hints") for line in report)
        )
        self.assertFalse(any(line.startswith("differs input:") for line in report))
        report = compare(prefix + "hint_count=-1\n", FIXTURES, "firefox")
        self.assertTrue(report[0].startswith("differs input: ValueError:"), report)
        chrome = retained(f"tls/chrome/{CHROME}/client-hello.txt")
        report = compare(
            f"operating_system={chrome['operating_system']}\nh2.frame_count=0\n",
            FIXTURES,
            "chrome",
        )
        self.assertFalse(any(line.startswith("differs input:") for line in report))
        self.assertTrue(
            any(line.startswith("differs h2.frame_count:") for line in report)
        )

    def test_a_layer_missing_from_the_snapshot_is_a_difference(self) -> None:
        values = retained(f"tls/chrome/{CHROME}/client-hello.txt")
        text = f"format={FORMAT}\noperating_system={values['operating_system']}\n"
        report = compare(text, FIXTURES, "chrome")
        for layer in ("tls", "h2", "h2_navigation", "quic_client_hello", "h3", "hints"):
            self.assertTrue(
                any(line.startswith(f"differs {layer}: missing") for line in report),
                layer,
            )

    def test_unparseable_evidence_is_noted_and_makes_the_run_partial(self) -> None:
        run = SnapshotRun("feedc0de", 1, 2, 0.1)
        record = ConnectionRecord("tls", 0.0, protocol="h2")
        record.client_chunks.append((0.0, b"GET / HTTP/1.1\r\n\r\n"))
        run.connections.append(record)
        text = render_snapshot(run, METADATA)
        self.assertIn("preface", fields(text)["h2_error"])
        self.assertIn("http3=not-used", problems(text))


# -- Scripted run over loopback, with Python clients -----------------------


def client_tls_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["h2"])
    return context


async def h2_session(port: int, token: str) -> dict[str, dict[bytes, bytes]]:
    """Load `/` and `/fetch` on one HTTP/2 session and read its GOAWAY."""
    reader, writer = await asyncio.open_connection(
        "127.0.0.1", port, ssl=client_tls_context(), server_hostname=HOSTNAME
    )
    connection = H2Connection(H2Configuration(client_side=True, header_encoding=None))
    connection.initiate_connection()
    responses: dict[str, dict[bytes, bytes]] = {}
    for path in ("/", "/fetch"):
        stream_id = connection.get_next_available_stream_id()
        connection.send_headers(
            stream_id,
            [
                (b":method", b"GET"),
                (b":authority", f"{HOSTNAME}:{port}".encode()),
                (b":scheme", b"https"),
                (b":path", f"{path}?run={token}".encode()),
                (b"sec-ch-ua", b'"Scripted";v="1"'),
            ],
            end_stream=True,
        )
        writer.write(connection.data_to_send())
        ended = False
        while not ended or "goaway" not in responses and path == "/fetch":
            data = await reader.read(65536)
            if not data:
                break
            for event in connection.receive_data(data):
                if isinstance(event, ResponseReceived):
                    responses[path] = dict(event.headers)
                ended |= isinstance(event, StreamEnded) and event.stream_id == stream_id
                if isinstance(event, ConnectionTerminated):
                    responses["goaway"] = {}
            writer.write(connection.data_to_send())
    writer.close()
    return responses


class H3Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.waiters: dict[int, asyncio.Future] = {}

    def quic_event_received(self, event) -> None:
        for http_event in self.http.handle_event(event):
            if isinstance(http_event, (HeadersReceived, DataReceived)):
                waiter = self.waiters.get(http_event.stream_id)
                if http_event.stream_ended and waiter and not waiter.done():
                    waiter.set_result(None)

    async def get(self, port: int, path: str) -> None:
        stream_id = self._quic.get_next_available_stream_id()
        self.http.send_headers(
            stream_id,
            [
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", f"{HOSTNAME}:{port}".encode()),
                (b":path", path.encode()),
                (b"sec-ch-ua", b'"Scripted";v="1"'),
            ],
            end_stream=True,
        )
        self.waiters[stream_id] = asyncio.get_running_loop().create_future()
        self.transmit()
        await self.waiters[stream_id]


async def h3_session(port: int, token: str) -> None:
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=H3_ALPN,
        server_name=HOSTNAME,
        verify_mode=ssl.CERT_NONE,
    )
    async with connect_loopback(port, configuration, H3Client) as client:
        await client.get(port, f"/next?run={token}")
        await client.get(port, f"/fetch?run={token}")


async def http1_requests(port: int, token: str) -> None:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    for path in ("/plain", "/done"):
        writer.write(
            f"GET {path}?run={token} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
            "User-Agent: scripted\r\n\r\n".encode()
        )
        head = await reader.readuntil(b"\r\n\r\n")
        length = next(
            int(line.split(b":")[1])
            for line in head.split(b"\r\n")
            if line.lower().startswith(b"content-length")
        )
        await reader.readexactly(length)
    writer.close()


async def scripted_run():
    async with serving(CERTIFICATE, "feedc0de", 0.05) as run:
        responses = await asyncio.wait_for(h2_session(run.port, run.token), TIMEOUT)
        await asyncio.wait_for(h3_session(run.port, run.token), TIMEOUT)
        await asyncio.wait_for(http1_requests(run.plain_port, run.token), TIMEOUT)
        await asyncio.wait_for(run.done.wait(), TIMEOUT)
    return run, responses


class ScriptedRunTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.scripted, cls.responses = asyncio.run(scripted_run())
        cls.text = render_snapshot(cls.scripted, METADATA)
        cls.values = fields(cls.text)

    def test_first_response_requests_hints_and_fetch_advertises_h3(self) -> None:
        start, fetch = self.responses["/"], self.responses["/fetch"]
        self.assertIn(b"sec-ch-ua-full-version-list", start[b"accept-ch"])
        self.assertEqual(start[b"critical-ch"], start[b"accept-ch"])
        self.assertNotIn(b"alt-svc", start)
        self.assertEqual(
            fetch[b"alt-svc"], f'h3=":{self.scripted.port}"; ma=86400'.encode()
        )
        self.assertIn("goaway", self.responses)

    def test_requests_are_recorded_per_protocol_in_order(self) -> None:
        self.assertEqual(
            [(r.protocol, r.record.kind) for r in self.scripted.requests],
            [
                ("h2", "start"),
                ("h2", "fetch"),
                ("h3", "next"),
                ("h3", "fetch"),
                ("http/1.1", "plain"),
                ("http/1.1", "done"),
            ],
        )

    def test_snapshot_holds_every_layer_without_problems(self) -> None:
        values = self.values
        self.assertEqual(problems(self.text), [])
        self.assertEqual(values["tls.format"], "phantom-client-hello-v2")
        self.assertEqual(values["tls.server_name_hex"], HOSTNAME.encode().hex())
        self.assertEqual(values["h2.frame_count"], "1")
        self.assertIn("priority:none", values["request_0_headers"])
        self.assertEqual(
            values["quic_client_hello.format"], "phantom-quic-client-hello-v1"
        )
        self.assertEqual(values["h3.alpn"], "h3")
        self.assertNotIn("h3.format", values)
        self.assertEqual(values["request_4_field_order"], "Host,User-Agent")
        self.assertEqual(values["hints_second_navigation"], "next")
        self.assertEqual(values["hint_0"], 'default|sec-ch-ua|"Scripted";v="1"')

    def test_initial_datagrams_record_their_size_and_connection_ids(self) -> None:
        count = int(self.values["quic_connection_0_initial_datagram_count"])
        self.assertGreaterEqual(count, 1)
        self.assertRegex(
            self.values["quic_connection_0_initial_datagram_0"],
            r"^size:1[0-9]{3},version:0x00000001,"
            r"destination_cid_length:[0-9]+,source_cid_length:[0-9]+$",
        )

    def test_split_writes_only_the_drop_in_fixtures(self) -> None:
        sections = split_snapshot(self.text)
        self.assertEqual(
            sorted(sections), ["client-hello.txt", "quic-client-hello.txt"]
        )
        hello = sections["client-hello.txt"].splitlines()
        self.assertEqual(hello[0], "format=phantom-client-hello-v2")
        self.assertTrue(hello[-1].startswith("server_name_hex="))
        quic = fields(sections["quic-client-hello.txt"])
        self.assertEqual(
            quic["handshake_hex"], self.values["quic_client_hello.handshake_hex"]
        )


class AndroidLaunchTests(unittest.TestCase):
    ADB = Path("adb")

    def android_launch(self, browser: str):
        plan = launch_plan(browser, self.ADB, True, 9450, 9451, CERTIFICATE)
        return plan, LaunchedBrowser(
            plan, page_url(browser, 9450, "t")
        ).android_launch()

    def test_chromium_opens_the_page_by_intent_over_the_emulator_route(self) -> None:
        plan, launch = self.android_launch("chrome-android")
        self.assertEqual(plan.launch_mode, "android-intent")
        self.assertEqual(launch.url, f"https://{HOSTNAME}:9450/?run=t")
        self.assertIn(
            f"--host-resolver-rules=MAP {HOSTNAME} 10.0.2.2, MAP * ~NOTFOUND, "
            "EXCLUDE 127.0.0.1",
            launch.arguments,
        )
        self.assertIn(
            f"--ignore-certificate-errors-spki-list={CERTIFICATE.spki_sha256_base64}",
            launch.arguments,
        )
        # `/plain` names the device's own 127.0.0.1.
        self.assertEqual(launch.reverse, (9450, 9451))

    def test_opera_opens_localhost_without_switches(self) -> None:
        _, launch = self.android_launch("opera-android")
        self.assertEqual(launch.url, "https://localhost:9450/?run=t")
        self.assertEqual(launch.arguments, ())
        self.assertIsNone(launch.configuration())

    def test_firefox_gets_preferences_but_no_certificate_override(self) -> None:
        plan, launch = self.android_launch("firefox-android")
        self.assertEqual(plan.profile_files, ())
        self.assertIn(("network.dns.localDomains", HOSTNAME), launch.preferences)
        self.assertEqual(launch.reverse, (9450, 9451))
        desktop = launch_plan("firefox", self.ADB, True, 9450, 9451, CERTIFICATE)
        self.assertEqual(
            [name for name, _ in desktop.profile_files], ["cert_override.txt"]
        )


class PortTests(unittest.TestCase):
    def test_explicit_secure_port_binds_both_protocols_without_random_selection(self):
        for port in (1, 443, 65535):
            tcp, udp = mock.Mock(), mock.Mock()
            with (
                self.subTest(port=port),
                mock.patch.object(
                    snapshot.socket, "socket", side_effect=(tcp, udp)
                ) as acquire,
                mock.patch.object(snapshot.secrets, "randbelow") as random,
            ):
                self.assertEqual(reserve_shared_port(port), (tcp, udp))

            self.assertEqual(
                acquire.call_args_list,
                [
                    mock.call(socket.AF_INET, socket.SOCK_STREAM),
                    mock.call(socket.AF_INET, socket.SOCK_DGRAM),
                ],
            )
            random.assert_not_called()
            tcp.listen.assert_called_once_with(64)
            for sock in (tcp, udp):
                sock.bind.assert_called_once_with(("127.0.0.1", port))
                sock.setblocking.assert_called_once_with(False)
                sock.close.assert_not_called()

    def test_explicit_available_port_returns_real_shared_loopback_sockets(self):
        reserved_tcp, reserved_udp = reserve_shared_port()
        port = reserved_tcp.getsockname()[1]
        reserved_tcp.close()
        reserved_udp.close()

        tcp, udp = reserve_shared_port(port)
        try:
            self.assertEqual(tcp.getsockname(), ("127.0.0.1", port))
            self.assertEqual(udp.getsockname(), ("127.0.0.1", port))
            self.assertFalse(tcp.getblocking())
            self.assertFalse(udp.getblocking())
            self.assertEqual(tcp.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN), 1)
        finally:
            tcp.close()
            udp.close()

    def test_occupied_explicit_port_fails_without_trying_another_port(self):
        create = socket.socket
        tcp, udp = reserve_shared_port()
        port = tcp.getsockname()[1]
        attempted = []
        try:

            def acquire(*args, **kwargs):
                sock = create(*args, **kwargs)
                attempted.append(sock)
                return sock

            with (
                mock.patch.object(
                    snapshot.socket, "socket", side_effect=acquire
                ) as factory,
                self.assertRaises(OSError) as raised,
            ):
                reserve_shared_port(port)

            self.assertIn(raised.exception.errno, (errno.EADDRINUSE, errno.EACCES))
            self.assertEqual(factory.call_count, 2)
            self.assertTrue(all(sock.fileno() == -1 for sock in attempted))
        finally:
            for sock in (*attempted, tcp, udp):
                sock.close()

    def test_explicit_port_partial_acquisition_preserves_errors_and_closes_sockets(
        self,
    ):
        create = socket.socket
        for operation in ("create", "bind", "listen"):
            for cleanup_fails in (False, True):
                primary = OSError(errno.EADDRINUSE, "original explicit port failure")
                cleanup = OSError(errno.EIO, "original socket close failure")
                sockets = []
                proxies = []

                def acquire(
                    *args,
                    operation=operation,
                    cleanup_fails=cleanup_fails,
                    primary=primary,
                    cleanup=cleanup,
                    sockets=sockets,
                    proxies=proxies,
                    **kwargs,
                ):
                    if operation == "create" and sockets:
                        raise primary
                    sock = create(*args, **kwargs)
                    sockets.append(sock)
                    proxy = mock.Mock(wraps=sock)
                    proxies.append(proxy)
                    # Isolate acquisition faults from host reservations; these
                    # remain real owned sockets with their original close.
                    proxy.bind.return_value = None
                    proxy.listen.return_value = None
                    if operation == "bind" and len(sockets) == 2:
                        proxy.bind.side_effect = primary
                    if operation == "listen" and len(sockets) == 1:
                        proxy.listen.side_effect = primary
                    if cleanup_fails and len(sockets) == 1:

                        def close():
                            sock.close()
                            raise cleanup

                        proxy.close.side_effect = close
                    return proxy

                try:
                    with (
                        self.subTest(operation=operation, cleanup_fails=cleanup_fails),
                        mock.patch.object(
                            snapshot.socket, "socket", side_effect=acquire
                        ) as factory,
                        self.assertRaises(
                            SnapshotFailures if cleanup_fails else OSError
                        ) as raised,
                    ):
                        reserve_shared_port(443)

                    if cleanup_fails:
                        self.assertIs(raised.exception.primary, primary)
                        self.assertEqual(raised.exception.cleanup, (cleanup,))
                    else:
                        self.assertIs(raised.exception, primary)
                    self.assertEqual(factory.call_count, 2)
                    self.assertEqual(len(sockets), 1 if operation == "create" else 2)
                    self.assertTrue(all(sock.fileno() == -1 for sock in sockets))
                    for proxy in proxies:
                        proxy.close.assert_called_once_with()
                finally:
                    for sock in sockets:
                        sock.close()

    def test_tcp_and_udp_share_one_loopback_port(self) -> None:
        tcp, udp = reserve_shared_port()
        try:
            self.assertEqual(tcp.getsockname(), udp.getsockname())
            self.assertEqual(tcp.getsockname()[0], "127.0.0.1")
        finally:
            tcp.close()
            udp.close()


class InitialDatagramTests(unittest.TestCase):
    def test_reads_version_1_and_version_2_initials(self) -> None:
        v1 = bytes([0xC3]) + (1).to_bytes(4, "big") + bytes([11]) + bytes(11)
        v1 += bytes([3]) + bytes(3)
        self.assertEqual(
            initial_datagram(v1 + bytes(1200 - len(v1))),
            InitialDatagram(1200, 1, 11, 3),
        )
        v2 = bytes([0xD3]) + (0x6B3343CF).to_bytes(4, "big") + bytes([8]) + bytes(9)
        datagram = initial_datagram(v2)
        self.assertIsNotNone(datagram)
        self.assertEqual(datagram.version, 0x6B3343CF)

    def test_other_packets_are_not_initials(self) -> None:
        handshake = bytes([0xE3]) + (1).to_bytes(4, "big") + bytes([8]) + bytes(9)
        self.assertIsNone(initial_datagram(handshake))
        self.assertIsNone(initial_datagram(bytes([0x43]) + bytes(40)))


if __name__ == "__main__":
    unittest.main()
