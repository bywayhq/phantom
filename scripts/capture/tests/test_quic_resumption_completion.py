import asyncio
import contextlib
import io
import socket
import ssl
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import mock

from aioquic import tls
from aioquic.buffer import Buffer
from aioquic.h3.connection import H3_ALPN
from aioquic.quic.configuration import QuicConfiguration

from scripts.capture import quic_resumption
from scripts.capture.fixture_file import write_text_fixture
from scripts.capture.http2_session import generate_certificate
from scripts.capture.quic_resumption import (
    SCENARIOS,
    RunRecord,
    RunResult,
    capture_run,
    parse_client_hello,
    render_fixture,
)
from scripts.capture.tests.loopback_quic import connect_loopback
from scripts.capture.tests.test_quic_resumption import Client

ODD_SUITES = bytes.fromhex("0100002b0303" + "00" * 32 + "000001130101000000")
EVEN_SUITES = bytes.fromhex("0100002b0303" + "00" * 32 + "000002130101000000")


class StreamObservationTests(unittest.TestCase):
    def test_fragmented_type_never_consumes_the_next_packet_frame(self):
        connection = SimpleNamespace(_phantom_clock=lambda: 12.5)
        streams = {}
        context = SimpleNamespace(epoch=tls.Epoch.ONE_RTT)
        # STREAM ID2, length1, first byte of two-byte type64, then PING.
        first = Buffer(data=bytes.fromhex("02014001"))
        quic_resumption.record_stream_start(connection, streams, context, 0x0A, first)
        self.assertEqual(streams, {})

        # Same stream, offset1, length1, final type byte. PING is not stream data.
        continuation = Buffer(data=bytes.fromhex("02010140"))
        connection._phantom_clock = lambda: 99.0
        quic_resumption.record_stream_start(
            connection, streams, context, 0x0E, continuation
        )
        self.assertEqual(streams[2].stream_type, 64)
        self.assertEqual(streams[2].first_frame_bytes, 1)
        self.assertEqual(streams[2].first_ms, 12.5)
        self.assertEqual(streams[2].space, "1rtt")


class CaptureOwnershipTests(unittest.IsolatedAsyncioTestCase):
    async def test_internal_wait_failure_retires_udp_without_faking_protocol_completion(
        self,
    ):
        await self.check_internal_wait_failure(
            RuntimeError("original internal collector wait failure")
        )

    async def test_internal_wait_cancellation_retires_udp_and_retains_original_cause(
        self,
    ):
        await self.check_internal_wait_failure(
            asyncio.CancelledError("original internal collector wait interruption")
        )

    async def check_internal_wait_failure(self, failure):
        configuration = QuicConfiguration(
            is_client=True, alpn_protocols=H3_ALPN, verify_mode=ssl.CERT_NONE
        )
        manager = quic_resumption.serving(
            SCENARIOS["accept"], "127.0.0.1", generate_certificate()
        )
        run, port = await manager.__aenter__()
        peer = connect_loopback(port, configuration, Client)
        client = await peer.__aenter__()
        protocol = run.owner.protocols[0]
        release = asyncio.Event()
        original_wait_closed = protocol.wait_closed
        original_wait = asyncio.wait
        injected = False
        waiter = None
        handles = ()

        async def held_wait_closed():
            await release.wait()
            await original_wait_closed()

        async def fail_once(tasks, **kwargs):
            nonlocal injected, waiter, handles
            if not injected and run.owner.waits:
                injected = True
                waiter = run.owner.waits[protocol]
                handles = tuple(
                    handle
                    for handle in (protocol._timer, protocol._transmit_task)
                    if handle is not None
                )
                raise failure
            return await original_wait(tasks, **kwargs)

        try:
            await asyncio.wait_for(client.request("GET", "/"), 5)
            with (
                mock.patch.object(protocol, "wait_closed", held_wait_closed),
                mock.patch.object(quic_resumption.asyncio, "wait", fail_once),
                self.assertRaises(
                    quic_resumption.ResumptionFailures
                    if isinstance(failure, Exception)
                    else type(failure)
                ) as raised,
            ):
                await manager.__aexit__(None, None, None)

            self.assertTrue(injected)
            retained = raised.exception
            if not isinstance(failure, Exception):
                self.assertIs(retained, failure)
                retained = retained.__cause__
            self.assertTrue(any(error is failure for error in retained.cleanup))
            self.assertIs(retained.owner, run.owner)
            self.assertFalse(run.owner.finished)
            self.assertFalse(protocol.observed_closed)
            self.assertFalse(waiter.done())
            self.assertIs(run.owner.waits[protocol], waiter)
            self.assertTrue(handles)
            self.assertTrue(all(handle.cancelled() for handle in handles))
            self.assertTrue(run.owner.retired.done())
            self.assertIsNone(run.owner._transport._sock)
            self.assertIsNone(protocol._timer)
            self.assertIsNone(protocol._transmit_task)
            self.assertIsNone(protocol.release_timer)
            self.assertEqual(protocol.retire_timers, [])
            self.assertTrue(run.owner.hooks_restored)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as rebound:
                rebound.bind(("127.0.0.1", port))
            with self.assertRaises(type(raised.exception)):
                render_fixture(
                    SCENARIOS["accept"],
                    [RunResult(run, port, "scripted", False)],
                    client="scripted",
                    client_version="0",
                    operating_system="test",
                    launch_mode="manual",
                    listen_host="127.0.0.1",
                )

            release.set()
            with self.assertRaises(type(failure)) as retried:
                await run.owner.shutdown()
            self.assertIs(retried.exception, failure)
            self.assertIs(run.owner.waits[protocol], waiter)
            self.assertTrue(waiter.done())
            self.assertTrue(protocol.observed_closed)
            self.assertTrue(run.owner.finished)
        finally:
            release.set()
            await peer.__aexit__(None, None, None)
            if not run.owner.finished:
                with contextlib.suppress(
                    quic_resumption.ResumptionFailures, type(failure)
                ):
                    await run.owner.shutdown()

    async def test_delayed_initial_is_retired_without_starting_after_context_exit(self):
        configuration = QuicConfiguration(
            is_client=True, alpn_protocols=H3_ALPN, verify_mode=ssl.CERT_NONE
        )
        manager = quic_resumption.serving(
            SCENARIOS["accept-delayed"], "127.0.0.1", generate_certificate()
        )
        run, port = await manager.__aenter__()
        arrived = asyncio.Event()
        receive = quic_resumption.ResumptionProtocol.receive

        def held(protocol, data, addr):
            receive(protocol, data, addr)
            if protocol.held:
                arrived.set()

        async with connect_loopback(
            port, configuration, Client, wait_connected=False
        ) as client:
            with mock.patch.object(quic_resumption.ResumptionProtocol, "receive", held):
                client.transmit()
                await asyncio.wait_for(arrived.wait(), 5)
                protocol = run.owner.protocols[0]
                timer = protocol.release_timer
                self.assertFalse(protocol.started)
                await manager.__aexit__(None, None, None)

            self.assertTrue(timer.cancelled())
            self.assertFalse(protocol.started)
            self.assertEqual(protocol.held, [])
            self.assertTrue(run.owner.finished)
            self.assertTrue(run.owner.retired.done())
            self.assertIsNone(run.owner._transport._sock)
            self.assertEqual(run.failures, [])

    async def test_actual_protected_header_and_body_limit_failures_prevent_publication(
        self,
    ):
        for protected in (True, False):
            configuration = QuicConfiguration(
                is_client=True, alpn_protocols=H3_ALPN, verify_mode=ssl.CERT_NONE
            )
            original = None
            with (
                self.subTest(protected=protected),
                self.assertRaises(ValueError) as raised,
            ):
                async with (
                    quic_resumption.serving(
                        SCENARIOS["accept"], "127.0.0.1", generate_certificate()
                    ) as (run, port),
                    connect_loopback(port, configuration, Client) as client,
                ):
                    if protected:
                        stream = client._quic.get_next_available_stream_id()
                        client.http.send_headers(
                            stream,
                            [
                                (b":method", b"GET"),
                                (b":scheme", b"https"),
                                (b":authority", b"server.phantom.test"),
                                (b":path", b"/done"),
                                (b"authorization", b"probe"),
                            ],
                            end_stream=True,
                        )
                        client.transmit()
                    else:
                        client.request("POST", "/done", b"x" * 65537)
                    await asyncio.wait_for(run.done.wait(), 5)
                    original = run.failures[0]

            self.assertIs(raised.exception, original)
            self.assertIn("credential" if protected else "body", str(original))
            self.assertTrue(run.owner.finished)
            with self.assertRaises(ValueError) as unpublished:
                render_fixture(
                    SCENARIOS["accept"],
                    [RunResult(run, port, "scripted", False)],
                    client="scripted",
                    client_version="0",
                    operating_system="test",
                    launch_mode="manual",
                    listen_host="127.0.0.1",
                )
            self.assertIs(unpublished.exception, original)

    async def test_actual_fragmented_unidirectional_type_keeps_connection_usable(self):
        configuration = QuicConfiguration(
            is_client=True, alpn_protocols=H3_ALPN, verify_mode=ssl.CERT_NONE
        )
        arrived = asyncio.Event()
        observe = quic_resumption.record_stream_start
        async with (
            quic_resumption.serving(
                SCENARIOS["accept"], "127.0.0.1", generate_certificate()
            ) as (run, port),
            connect_loopback(port, configuration, Client) as client,
        ):
            stream_id = client._quic.get_next_available_stream_id(
                is_unidirectional=True
            )

            def observed(connection, streams, context, frame_type, buf):
                observe(connection, streams, context, frame_type, buf)
                if stream_id in getattr(connection, "_phantom_stream_prefixes", {}):
                    arrived.set()

            with mock.patch.object(quic_resumption, "record_stream_start", observed):
                client._quic.send_stream_data(stream_id, b"\x40")
                client.transmit()
                await asyncio.wait_for(arrived.wait(), 5)
                first = (
                    run.owner.protocols[0]
                    ._quic._phantom_stream_prefixes[stream_id]
                    .first
                )

                client._quic.send_stream_data(stream_id, b"\x40", end_stream=True)
                await asyncio.wait_for(client.request("GET", "/done"), 5)

            record = run.connections[0].unidirectional_streams[stream_id]
            self.assertEqual(record.stream_type, 64)
            self.assertEqual(
                (record.space, record.first_frame_bytes, record.first_ms), first
            )
            self.assertEqual(run.failures, [])
        self.assertTrue(run.owner.finished)

    async def test_interrupted_cleanup_retains_owner_and_completes_on_retry(self):
        configuration = QuicConfiguration(
            is_client=True, alpn_protocols=H3_ALPN, verify_mode=ssl.CERT_NONE
        )
        manager = quic_resumption.serving(
            SCENARIOS["accept"], "127.0.0.1", generate_certificate()
        )
        run, port = await manager.__aenter__()
        peer = connect_loopback(port, configuration, Client)
        client = await peer.__aenter__()
        entered = asyncio.Event()
        release = asyncio.Event()
        original_wait = run.owner.protocols[0].wait_closed

        async def held_wait():
            entered.set()
            await release.wait()
            await original_wait()

        interruption = None

        async def close():
            nonlocal interruption
            try:
                await manager.__aexit__(None, None, None)
            except asyncio.CancelledError as error:
                interruption = error
                raise

        try:
            await asyncio.wait_for(client.request("GET", "/"), 5)
            with mock.patch.object(run.owner.protocols[0], "wait_closed", held_wait):
                closing = asyncio.create_task(close())
                await asyncio.wait_for(entered.wait(), 5)
                closing.cancel("original caller cleanup interruption")
                with self.assertRaises(asyncio.CancelledError) as interrupted:
                    await closing

                original = interruption
                self.assertIsInstance(interrupted.exception, asyncio.CancelledError)
                self.assertEqual(
                    original.args, ("original caller cleanup interruption",)
                )
                self.assertIs(original.__cause__.owner, run.owner)
                self.assertFalse(run.owner.cleanup_task.done())
                self.assertFalse(run.owner.hooks_restored)
                release.set()
                with self.assertRaises(asyncio.CancelledError) as retried:
                    await run.owner.shutdown()
                self.assertIs(retried.exception, original)

            self.assertTrue(run.owner.finished)
            self.assertTrue(run.owner.hooks_restored)
            self.assertTrue(run.owner.retired.done())
            self.assertIsNone(run.owner._transport._sock)
            self.assertTrue(all(task.done() for task in run.owner.waits.values()))
            self.assertTrue(run.owner.protocols[0].observed_closed)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as rebound:
                rebound.bind(("127.0.0.1", port))
        finally:
            release.set()
            await peer.__aexit__(None, None, None)
            if not run.owner.cleanup_task.done():
                with contextlib.suppress(asyncio.CancelledError):
                    await run.owner.shutdown()

    async def test_primary_and_failed_close_preserve_sibling_retirement(self):
        configuration = QuicConfiguration(
            is_client=True, alpn_protocols=H3_ALPN, verify_mode=ssl.CERT_NONE
        )
        manager = quic_resumption.serving(
            SCENARIOS["accept"], "127.0.0.1", generate_certificate()
        )
        run, port = await manager.__aenter__()
        peers = [connect_loopback(port, configuration, Client) for _ in range(2)]
        clients = [await peer.__aenter__() for peer in peers]
        primary = LookupError("original capture caller failure")
        cleanup = OSError("original close before work failure")
        attempted = asyncio.Event()
        first = run.owner.protocols[0]

        def fail_close(*args, **kwargs):
            attempted.set()
            raise cleanup

        try:
            for client in clients:
                await asyncio.wait_for(client.request("GET", "/"), 5)
            with mock.patch.object(first, "close", fail_close):
                closing = asyncio.create_task(
                    manager.__aexit__(LookupError, primary, None)
                )
                await asyncio.wait_for(attempted.wait(), 5)
                clients[0].close()
                with self.assertRaises(quic_resumption.ResumptionFailures) as raised:
                    await asyncio.wait_for(closing, 5)

            self.assertIs(raised.exception.primary, primary)
            self.assertTrue(any(error is cleanup for error in raised.exception.cleanup))
            self.assertIs(raised.exception.owner, run.owner)
            self.assertTrue(
                all(protocol.observed_closed for protocol in run.owner.protocols)
            )
            self.assertTrue(run.owner.finished)
            self.assertIsNone(run.owner._transport._sock)
            with self.assertRaises(quic_resumption.ResumptionFailures):
                render_fixture(
                    SCENARIOS["accept"],
                    [RunResult(run, port, "scripted", False)],
                    client="scripted",
                    client_version="0",
                    operating_system="test",
                    launch_mode="manual",
                    listen_host="127.0.0.1",
                )
        finally:
            for peer in peers:
                await peer.__aexit__(None, None, None)

    async def test_actual_callback_failure_refuses_canonical_capture_publication(self):
        original = OSError("original request callback failure")
        unexpected = []
        loop = asyncio.get_running_loop()
        previous = loop.get_exception_handler()
        loop.set_exception_handler(lambda _loop, context: unexpected.append(context))

        class ScriptedDriver:
            def __init__(self, _plan, url):
                self.port = int(url.split(":")[-1].split("/")[0])

            async def __aenter__(self):
                configuration = QuicConfiguration(
                    is_client=True, alpn_protocols=H3_ALPN, verify_mode=ssl.CERT_NONE
                )
                self.context = connect_loopback(self.port, configuration, Client)
                self.client = await self.context.__aenter__()
                self.client.request("GET", "/done")
                return self

            async def __aexit__(self, *details):
                await self.context.__aexit__(*details)

        try:
            with TemporaryDirectory() as directory:
                output = Path(directory) / "capture.txt"
                output.write_bytes(b"previous fixture\n")
                with (
                    mock.patch.object(quic_resumption, "BrowserDriver", ScriptedDriver),
                    mock.patch.object(
                        quic_resumption.ResumptionProtocol,
                        "headers",
                        side_effect=original,
                    ),
                    self.assertRaises(OSError) as raised,
                ):
                    result = await asyncio.wait_for(
                        capture_run(
                            SCENARIOS["accept"],
                            browser="manual",
                            executable=None,
                            headless=True,
                            listen_host="127.0.0.1",
                            timeout=0.4,
                            field_trial_config=False,
                        ),
                        5,
                    )
                    text = render_fixture(
                        SCENARIOS["accept"],
                        [result],
                        client="scripted",
                        client_version="0",
                        operating_system="test",
                        launch_mode="manual",
                        listen_host="127.0.0.1",
                    )
                    write_text_fixture(output, text)
                self.assertIs(raised.exception, original)
                self.assertEqual(output.read_bytes(), b"previous fixture\n")
                self.assertEqual(unexpected, [])
        finally:
            loop.set_exception_handler(previous)


class CaptureInputTests(unittest.IsolatedAsyncioTestCase):
    def test_odd_cipher_vector_is_refused_by_shared_parser_and_compare(self):
        from scripts.capture.snapshot_compare import Variation, compare_hello

        self.assertEqual(parse_client_hello(EVEN_SUITES).cipher_suites, (0x1301,))
        with self.assertRaises(ValueError):
            parse_client_hello(ODD_SUITES)
        with self.assertRaises(ValueError):
            compare_hello("hello", ODD_SUITES, EVEN_SUITES, Variation())

    def test_malformed_derived_vectors_raise_input_errors(self):
        from scripts.capture.quic_resumption import (
            KEY_SHARE,
            PRE_SHARED_KEY,
            PSK_KEY_EXCHANGE_MODES,
            ClientHelloShape,
        )

        for kind, body, method in (
            (KEY_SHARE, b"\x00\x01\x00", "key_share_groups"),
            (KEY_SHARE, b"\x00\x00\x00", "key_share_groups"),
            (PRE_SHARED_KEY, b"\x00\x01\x00\x00\x00\x00\x00\x00\x00", "pre_shared_key"),
            (PRE_SHARED_KEY, b"\x00\x00\x00\x01\x02", "pre_shared_key"),
            (PSK_KEY_EXCHANGE_MODES, b"", "psk_key_exchange_modes"),
            (PSK_KEY_EXCHANGE_MODES, b"\x02\x01", "psk_key_exchange_modes"),
        ):
            shape = ClientHelloShape((), ((kind, body),))
            with self.subTest(kind=kind, body=body), self.assertRaises(ValueError):
                getattr(shape, method)()

    def test_cli_input_failures_precede_all_run_acquisition(self):
        for option, value in (
            ("--timeout", "nan"),
            ("--timeout", "inf"),
            ("--timeout", "0"),
            ("--repeat", "129"),
            ("--client-version", "154\nformat=injected"),
            ("--operating-system", "test\x7f"),
        ):
            arguments = [
                "--browser",
                "manual",
                "--client-version",
                "0",
                "--scenario",
                "accept",
            ]
            arguments += [option, value]
            with (
                self.subTest(option=option, value=value),
                mock.patch.object(quic_resumption, "capture_run") as capture,
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as raised,
            ):
                quic_resumption.main(arguments)
            self.assertEqual(raised.exception.code, 2)
            capture.assert_not_called()

    async def test_invalid_deadlines_fail_before_capture_acquisition(self):
        for timeout in (0, -1, float("nan"), float("inf")):
            with (
                self.subTest(timeout=timeout),
                mock.patch.object(
                    quic_resumption, "generate_certificate"
                ) as certificate,
                mock.patch.object(quic_resumption, "serving") as listener,
                mock.patch.object(quic_resumption, "BrowserDriver") as browser,
                self.assertRaises(ValueError),
            ):
                await capture_run(
                    SCENARIOS["accept"],
                    browser="manual",
                    executable=None,
                    headless=True,
                    listen_host="127.0.0.1",
                    timeout=timeout,
                    field_trial_config=False,
                )
            certificate.assert_not_called()
            listener.assert_not_called()
            browser.assert_not_called()

    def test_literal_metadata_is_refused_before_fixture_serialization(self):
        result = RunResult(RunRecord(), 1, "manual", timed_out=True)
        for field in ("client", "client_version", "operating_system", "launch_mode"):
            for value in (
                "test\nformat=injected",
                "test\rnext=x",
                "test\0",
                "test\x7f",
                "tést",
            ):
                values = {
                    "client": "scripted",
                    "client_version": "0",
                    "operating_system": "test",
                    "launch_mode": "manual",
                    "listen_host": "127.0.0.1",
                }
                values[field] = value
                with (
                    self.subTest(field=field, value=value),
                    self.assertRaises(ValueError),
                ):
                    render_fixture(SCENARIOS["accept"], [result], **values)


if __name__ == "__main__":
    unittest.main()
