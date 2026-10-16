"""Owned SSE teardown classifies only known, terminal peer disconnects."""

import asyncio
import dataclasses
import errno
import socket
import ssl
import struct
import sys
import threading
import unittest
from types import SimpleNamespace

from scripts.capture.sse_multiplexed import (
    MAX_CONNECTIONS,
    H2ReconnectServer,
    H3ReconnectServer,
)
from scripts.capture.sse_reconnect import (
    CATALOG,
    NO_CONTENT,
    ReconnectServer,
    ScenarioRun,
)
from scripts.capture.tests.test_sse_reconnect_h2 import H2EventSource
from scripts.capture.tests.test_sse_reconnect_h3 import H3EventSource


def windows_error(kind, code):
    error = kind("injected Windows peer error")
    error.winerror = code
    return error


class ClosedWriter:
    def __init__(self, error, *, closing=True):
        self.error = error
        self.transport = SimpleNamespace(is_closing=lambda: closing)

    def close(self):
        pass

    async def wait_closed(self):
        raise self.error


class H2CleanupTests(unittest.IsolatedAsyncioTestCase):
    async def test_known_terminal_resets_retire_owned_h2_writers(self):
        errors = (
            ConnectionResetError(errno.ECONNRESET, "reset"),
            ConnectionAbortedError(errno.ECONNABORTED, "aborted"),
            BrokenPipeError(errno.EPIPE, "pipe"),
            windows_error(ConnectionResetError, 64),
            windows_error(OSError, 10054),
        )
        for error in errors:
            with self.subTest(
                error=repr(error), winerror=getattr(error, "winerror", None)
            ):
                server = H2ReconnectServer()
                server.writers.add(ClosedWriter(error))
                await server.finish_run()
                self.assertFalse(server.tasks)
                self.assertFalse(server.writers)
                self.assertFalse(server.writer_tasks)
                self.assertFalse(server.failures)

    async def test_other_errors_and_nonclosing_resets_remain_failures(self):
        cases = (
            (windows_error(OSError, 64), True),
            (PermissionError(errno.EACCES, "denied"), True),
            (OSError(errno.EIO, "I/O fault"), True),
            (windows_error(ConnectionResetError, 64), False),
            (asyncio.CancelledError(), True),
        )
        for error, closing in cases:
            with self.subTest(error=repr(error), closing=closing):
                server = H2ReconnectServer()
                writer = ClosedWriter(error, closing=closing)
                server.writers.add(writer)
                with self.assertRaises(type(error)) as raised:
                    await server.finish_run()
                if isinstance(error, asyncio.CancelledError):
                    # Task.result() may reconstruct cancellation on Python 3.10.
                    self.assertTrue(
                        any(
                            isinstance(item, asyncio.CancelledError)
                            for item in server.failures
                        )
                    )
                else:
                    self.assertIs(raised.exception, error)
                    self.assertIn(error, server.failures)
                self.assertIn(writer, server.writers)
                # The rejected owner is a scripted object, with no transport.
                server.writers.clear()

    async def test_h1_waiter_still_propagates_the_original_reset(self):
        error = windows_error(ConnectionResetError, 64)
        with self.assertRaises(ConnectionResetError) as raised:
            await ReconnectServer().wait_writer_closed(ClosedWriter(error))
        self.assertIs(raised.exception, error)

    async def test_actual_tls_h2_abrupt_peer_close_is_collected(self):
        server = H2ReconnectServer()
        await server.start("127.0.0.1", 0)
        run = ScenarioRun(CATALOG[0], "tls-reset")
        server.run = run
        client = H2EventSource(server.url(run))
        started = False
        collected = []
        original = server.wait_writer_closed

        async def observe(writer):
            collected.append(writer)
            await original(writer)

        server.wait_writer_closed = observe
        try:
            await client.start(server)
            started = True
            status, _, _ = await asyncio.wait_for(client.fetch(server.url(run), ()), 2)
            self.assertEqual(status, 200)
            self.assertEqual(run.connections[0].protocol, "h2")
            self.assertEqual(run.requests[0].kind, "page")
            peer = client.writer.get_extra_info("socket")
            peer.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_LINGER,
                struct.pack("hh" if sys.platform == "win32" else "ii", 1, 0),
            )
            client.writer.transport.abort()
            await asyncio.wait_for(asyncio.gather(*server.tasks), 2)
            await server.finish_run()
            # An actual abort need not surface as a reset on every host.
            # Exact close-wait errors are exercised by the injected controls.
            self.assertTrue(client.writer.transport.is_closing())
            self.assertEqual(len(collected), 1)
            self.assertFalse(server.writers)
            self.assertFalse(server.tasks)
        finally:
            try:
                if started:
                    client.writer.transport.abort()
            finally:
                await server.close()

    async def test_terminal_read_reset_requires_complete_observation_and_owned_close(
        self,
    ):
        cases = (
            "terminal",
            "active",
            "observing",
            "late-terminal",
            "nonclosing",
            "missing-record",
            "wrong-class",
            "wrong-code",
            "close-failure",
        )
        for case in cases:
            with self.subTest(case=case):
                await self.read_reset_case(case)

    async def read_reset_case(self, case):
        server = H2ReconnectServer()
        run = ScenarioRun(CATALOG[0], "read-boundary")
        if case not in {"active", "late-terminal"}:
            run.terminated = run.now()
        if case not in {"active", "observing", "late-terminal"}:
            run.done.set()
        error = windows_error(
            OSError if case == "wrong-class" else ConnectionResetError,
            5 if case == "wrong-code" else 64,
        )
        close_error = OSError(errno.EIO, "close failed")
        closing = False

        async def read(_):
            raise error

        async def drain():
            pass

        def ssl_object(_):
            if case == "missing-record":
                raise error
            return SimpleNamespace(selected_alpn_protocol=lambda: "h2")

        def close():
            nonlocal closing
            if case == "late-terminal":
                run.terminated = run.now()
                run.done.set()
            closing = case != "nonclosing"
            if case == "close-failure":
                raise close_error

        writer = SimpleNamespace(
            get_extra_info=ssl_object,
            write=lambda _: None,
            drain=drain,
            close=close,
            transport=SimpleNamespace(is_closing=lambda: closing),
        )
        result = await server.handle(SimpleNamespace(read=read), writer, run)
        if case == "terminal":
            self.assertIsNone(result)
            self.assertEqual(run.connections[0].peer_reset_winerror, 64)
            self.assertGreaterEqual(run.connections[0].peer_reset, run.terminated)
        else:
            self.assertIs(result, error)
            if run.connections:
                self.assertIsNone(run.connections[0].peer_reset)
                self.assertIsNone(run.connections[0].peer_reset_winerror)
        self.assertEqual(
            server.failures, [close_error] if case == "close-failure" else []
        )

    @unittest.skipUnless(sys.platform == "win32", "Windows Proactor native TLS reset")
    async def test_terminal_native_tls_read_reset_is_retained_as_an_observation(self):
        await self.native_tls_read_reset(terminal=True)

    @unittest.skipUnless(sys.platform == "win32", "Windows Proactor native TLS reset")
    async def test_active_native_tls_read_reset_remains_a_failure(self):
        await self.native_tls_read_reset(terminal=False)

    async def native_tls_read_reset(self, *, terminal):
        from h2.config import H2Configuration
        from h2.connection import H2Connection
        from h2.events import ResponseReceived, StreamEnded

        server = H2ReconnectServer()
        await server.start("127.0.0.1", 0)
        scenario = dataclasses.replace(
            CATALOG[0], attempts=(NO_CONTENT,), observation_seconds=0
        )
        run = ScenarioRun(scenario, "native-read-reset")
        server.run = run
        loop = asyncio.get_running_loop()
        received, release = asyncio.Event(), threading.Event()
        context = ssl.create_default_context(
            cadata=server.certificate.certificate_pem.decode()
        )
        context.set_alpn_protocols(["h2"])

        def peer():
            with (
                socket.create_connection(
                    ("127.0.0.1", server.address[1]), timeout=2
                ) as raw,
                context.wrap_socket(raw, server_hostname="server.phantom.test") as sock,
            ):
                self.assertEqual(sock.selected_alpn_protocol(), "h2")
                engine = H2Connection(H2Configuration(header_encoding=None))
                engine.initiate_connection()
                target = run.stream_path() if terminal else run.page_path()
                engine.send_headers(
                    1,
                    [
                        (b":method", b"GET"),
                        (b":scheme", b"https"),
                        (
                            b":authority",
                            f"server.phantom.test:{server.address[1]}".encode(),
                        ),
                        (b":path", target.encode()),
                    ],
                    end_stream=True,
                )
                sock.sendall(engine.data_to_send())
                status = None
                while True:
                    data = sock.recv(65536)
                    if not data:
                        raise AssertionError("TLS peer ended before H2 response")
                    events = engine.receive_data(data)
                    for event in events:
                        if isinstance(event, ResponseReceived):
                            status = dict(event.headers)[b":status"]
                    if any(
                        isinstance(event, StreamEnded) and event.stream_id == 1
                        for event in events
                    ):
                        break
                loop.call_soon_threadsafe(received.set)
                if not release.wait(2):
                    raise TimeoutError("owned TLS peer release timed out")
                # SSLSocket.close closes this owned socket without Proactor's
                # shutdown-before-close, retaining the actual native reset.
                sock.setsockopt(
                    socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("hh", 1, 0)
                )
                return status

        task = asyncio.create_task(asyncio.to_thread(peer))
        observed = []
        original = server.wait_writer_closed

        async def observe(writer):
            try:
                await writer.wait_closed()
            except ConnectionResetError as error:
                observed.append(error)
                self.assertTrue(writer.transport.is_closing())
            await original(writer)

        server.wait_writer_closed = observe
        try:
            await asyncio.wait_for(received.wait(), 2)
            if terminal:
                await asyncio.wait_for(run.done.wait(), 2)
            else:
                self.assertIsNone(run.terminated)
                self.assertFalse(run.done.is_set())
            release.set()
            self.assertEqual(
                await asyncio.wait_for(task, 2), b"204" if terminal else b"200"
            )
            results = await asyncio.wait_for(asyncio.gather(*server.tasks), 2)
            if terminal:
                await server.finish_run()
                self.assertTrue(all(result is None for result in results))
            else:
                with self.assertRaises(ConnectionResetError) as raised:
                    await server.finish_run()
                self.assertTrue(any(result is raised.exception for result in results))
                self.assertIs(raised.exception, observed[0])
            self.assertEqual(len(observed), 1)
            error = observed[0]
            self.assertEqual(error.winerror, 64)
            self.assertEqual(error.errno, errno.EINVAL)
            rebuilt = ConnectionResetError(*error.args)
            self.assertEqual(rebuilt.winerror, 64)
            self.assertEqual(rebuilt.args, error.args)
            connection = run.connections[0]
            self.assertEqual(connection.protocol, "h2")
            self.assertIsNone(connection.client_eof)
            if terminal:
                self.assertEqual(connection.peer_reset_winerror, 64)
                self.assertGreaterEqual(connection.peer_reset, run.terminated)
                from scripts.capture.sse_reconnect import fixture
                from scripts.capture.tests.test_sse_reconnect import METADATA

                text = fixture(
                    scenario, [run], dataclasses.replace(METADATA, protocol="h2")
                )
                self.assertIn("_connection_0_peer_reset=received_ms:", text)
                self.assertIn(",winerror:64", text)
                self.assertIn("client_eof_ms:none", text)
                self.assertNotIn("_close_code=64", text)
            else:
                self.assertIsNone(getattr(connection, "peer_reset_winerror", None))
                self.assertIsNone(getattr(connection, "peer_reset", None))
            self.assertFalse(server.tasks)
            self.assertFalse(server.writers)
            self.assertFalse(server.writer_tasks)
        finally:
            release.set()
            try:
                await asyncio.wait_for(asyncio.shield(task), 2)
            finally:
                await server.close()


class H3CleanupBoundaryTests(unittest.IsolatedAsyncioTestCase):
    def state(self):
        server = H3ReconnectServer()
        run = ScenarioRun(CATALOG[0], "udp-cleanup")
        run.terminated = run.now()
        run.done.set()
        server.protocols = [SimpleNamespace(run=run, record=object())]
        server.cleanup = asyncio.get_running_loop().create_future()
        return server, run

    async def test_known_udp_error_is_a_run_observation_only_during_cleanup(self):
        server, run = self.state()
        error = windows_error(OSError, 1234)
        server.udp_error(error)
        self.assertFalse(server.failures)
        self.assertEqual(len(run.udp_cleanup_disconnects), 1)
        received, code = run.udp_cleanup_disconnects[0]
        self.assertGreaterEqual(received, run.terminated)
        self.assertEqual(code, 1234)
        self.assertFalse(hasattr(server.protocols[0], "close_code"))
        server.cleanup.cancel()

    async def test_active_preterminal_mixed_missing_and_unknown_errors_fail(self):
        def active(server, run):
            server.run = run

        def preterminal(server, run):
            run.terminated = None

        def observing(server, run):
            run.done.clear()

        def mixed(server, run):
            server.protocols.append(
                SimpleNamespace(run=ScenarioRun(CATALOG[0], "other"), record=object())
            )

        def missing(server, run):
            server.protocols.clear()

        def unverified(server, run):
            server.protocols[0].record = None

        def finished(server, run):
            server.cleanup.set_result(None)

        def no_cleanup(server, run):
            server.cleanup.cancel()
            server.cleanup = None

        def serving_failure(server, run):
            server.failures.append(RuntimeError("serving failure"))

        for change in (
            active,
            preterminal,
            observing,
            mixed,
            missing,
            unverified,
            finished,
            no_cleanup,
            serving_failure,
            lambda *_: None,
        ):
            with self.subTest(change=change.__name__):
                server, run = self.state()
                change(server, run)
                error = windows_error(
                    OSError, 1234 if change.__name__ != "<lambda>" else 5
                )
                server.udp_error(error)
                self.assertIs(server.failures[-1], error)
                self.assertFalse(run.udp_cleanup_disconnects)
                if server.cleanup is not None:
                    server.cleanup.cancel()

    async def test_udp_observations_remain_bounded(self):
        server, run = self.state()
        for _ in range(MAX_CONNECTIONS):
            server.udp_error(windows_error(OSError, 1234))
        error = windows_error(OSError, 1234)
        server.udp_error(error)
        self.assertEqual(len(run.udp_cleanup_disconnects), MAX_CONNECTIONS)
        self.assertIs(server.failures[-1], error)
        server.cleanup.cancel()

    @unittest.skipUnless(sys.platform == "win32", "Windows Proactor UDP ICMP delivery")
    async def test_actual_closed_udp_peer_is_observed_during_owned_h3_cleanup(self):
        server = H3ReconnectServer()
        await server.start("127.0.0.1", 0)
        scenario = dataclasses.replace(
            CATALOG[0], attempts=(NO_CONTENT,), observation_seconds=0
        )
        run = ScenarioRun(scenario, "actual-udp-close")
        server.run = run
        client = H3EventSource(server.url(run))
        started = False
        cleanup = None
        entered, release, disconnected = (
            asyncio.Event(),
            asyncio.Event(),
            asyncio.Event(),
        )
        original_udp_error = server.udp_error

        def observe(error):
            original_udp_error(error)
            disconnected.set()

        server.udp_error = observe
        try:
            await client.start(server)
            started = True
            status, _, _ = await client.fetch(
                server.url(run).replace(run.page_path(), run.stream_path()), ()
            )
            self.assertEqual(status, 204)
            await asyncio.wait_for(run.done.wait(), 2)
            self.assertIsNotNone(run.terminated)
            self.assertEqual(run.connections[0].protocol, "h3")
            peer_transport = client.client._transport
            peer_socket = peer_transport.get_extra_info("socket")
            peer_address = peer_transport.get_extra_info("sockname")
            peer_retired = asyncio.Event()
            peer_protocol = peer_transport.get_protocol()
            original_lost = peer_protocol.connection_lost

            def peer_lost(error):
                try:
                    original_lost(error)
                finally:
                    peer_retired.set()

            peer_protocol.connection_lost = peer_lost
            await client.close()
            started = False
            await asyncio.wait_for(peer_retired.wait(), 2)
            self.assertEqual(peer_socket.fileno(), -1)
            protocol = server.protocols[0]
            original_wait = protocol.wait_closed

            async def held_wait():
                entered.set()
                await release.wait()
                await original_wait()

            protocol.wait_closed = held_wait
            cleanup = asyncio.create_task(server.finish_run())
            await asyncio.wait_for(entered.wait(), 2)
            self.assertIsNone(server.run)
            self.assertIsNotNone(server.cleanup)
            self.assertFalse(server.cleanup.done())
            # One actual datagram to the now-closed owned client endpoint asks
            # Windows to deliver ICMP through the server's real UDP transport.
            # error_received does not identify that endpoint in its observation.
            server.transport.sendto(b"closed-peer-probe", peer_address)
            await asyncio.wait_for(disconnected.wait(), 2)
            self.assertFalse(server.failures)
            self.assertEqual([code for _, code in run.udp_cleanup_disconnects], [1234])
            release.set()
            await asyncio.wait_for(cleanup, 2)
            self.assertFalse(server.protocols)
            self.assertFalse(server.tasks)
            from scripts.capture.sse_reconnect import fixture
            from scripts.capture.tests.test_sse_reconnect import METADATA

            text = fixture(
                scenario, [run], dataclasses.replace(METADATA, protocol="h3")
            )
            self.assertIn("_udp_cleanup_disconnect_count=1", text)
            self.assertIn("winerror:1234", text)
            self.assertNotIn("_close_code=1234", text)
        finally:
            release.set()
            try:
                if cleanup is not None:
                    await asyncio.wait_for(cleanup, 2)
            finally:
                try:
                    if started:
                        await client.close()
                finally:
                    await server.close()
