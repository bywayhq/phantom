"""Real H2 proxy streams, nested origin TLS and bounded relay ownership."""

import asyncio
import contextlib
import hashlib
import io
import unittest
from pathlib import Path
from unittest.mock import patch

from h2.events import DataReceived, StreamEnded
from h2.settings import SettingCodes

from scripts.capture.http2_session import (
    CaptureRun,
    ServerPolicy,
    generate_certificate,
    peer_disconnected,
    raise_capture_failures,
)
from scripts.capture.http2_websocket import CaptureMetadata
from scripts.capture.tests import test_tunnelled_websocket as wire
from scripts.capture.tests.test_tunnelled_websocket_limits import failures
from scripts.capture.tests.tunnelled_websocket_flow_peer import (
    NativeDrainWriter,
    RawOrigin,
)
from scripts.capture.tests.tunnelled_websocket_peer import (
    ProxyH2,
    TunnelTls,
    open_proxy,
    servers,
)
from scripts.capture.tunnelled_websocket import SCENARIOS, fixture, main
from scripts.capture.websocket_tunnel import PROXY_HOST, TunnelServer, correlate

TIMEOUT = 20.0


@contextlib.asynccontextmanager
async def raw_servers(origin):
    proxy, primary = None, None
    certificate = generate_certificate(PROXY_HOST)
    try:
        await origin.start()
        proxy = TunnelServer("https", certificate, origin.address, alpn="h2")
        await proxy.start()
        proxy.begin_run(CaptureRun("raw", ServerPolicy(), {}))
        yield origin, proxy, certificate
    except BaseException as error:
        primary = error
    cleanup = []
    origin.release.set()
    for owner in (proxy, origin):
        if owner is not None:
            try:
                await owner.close()
            except BaseException as error:
                cleanup.append(error)
    raise_capture_failures(primary, tuple(cleanup))


class ReplyOrigin(RawOrigin):
    async def exchange(self, reader, writer):
        try:
            choice = await reader.read(1)
            if not choice:
                return
            self.received += choice
            self.accepted.set()
            writer.write(b"x" * 131072 if choice == b"L" else b"okay")
            await writer.drain()
        except OSError as error:
            if not peer_disconnected(error):
                raise
        finally:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), TIMEOUT)
            except OSError as error:
                # A deliberate stream reset retires this exact owned socket.
                if not peer_disconnected(error):
                    raise
            self.writers.discard(writer)


class HalfClosedOrigin(RawOrigin):
    async def exchange(self, reader, writer):
        try:
            writer.write_eof()
            self.accepted.set()
            self.received = await reader.readexactly(4)
            if await reader.read(1):
                raise AssertionError("unexpected bytes after the scripted payload")
        finally:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), TIMEOUT)
            self.writers.discard(writer)


class Http2ProxyWireTests(unittest.IsolatedAsyncioTestCase):
    async def check_origin_half_close(self, window):
        async with raw_servers(HalfClosedOrigin()) as (origin, proxy, certificate):
            peer = await ProxyH2.open(proxy, certificate, window=window)
            try:
                stream = await peer.connect(proxy)
                self.assertEqual(await asyncio.wait_for(stream.read(), 2), b"")
                stream.write(b"late")
                await stream.drain()
                stream.write_eof()
                await peer.flush()
                await asyncio.wait_for(asyncio.gather(*origin.tasks), TIMEOUT)
                self.assertEqual(origin.received, b"late")
                await peer.ping()
            finally:
                await peer.close()

    async def test_origin_eof_needs_no_data_window(self):
        await self.check_origin_half_close(0)

    async def test_origin_half_close_keeps_upload_direction_open(self):
        await self.check_origin_half_close(65535)

    async def test_two_connect_streams_reach_independent_h1_and_h2_tls_websockets(self):
        async with servers("https", proxy_alpn="h2") as (
            origin,
            proxy,
            run,
            tunnels,
            certificate,
            proxy_certificate,
        ):
            peer = await ProxyH2.open(proxy, proxy_certificate)
            try:
                first = await peer.connect(proxy)
                first_tls = TunnelTls(first, first, certificate, ("http/1.1",))
                await asyncio.wait_for(first_tls.handshake(), TIMEOUT)
                second = await peer.connect(proxy)
                second_tls = TunnelTls(second, second, certificate, ("h2",))
                await asyncio.wait_for(second_tls.handshake(), TIMEOUT)
                self.assertEqual(first_tls.tls.selected_alpn_protocol(), "http/1.1")
                self.assertEqual(second_tls.tls.selected_alpn_protocol(), "h2")
                await wire.TunnelWireTests.h1_exchange(self, first_tls)
                await wire.TunnelWireTests.h2_exchange(self, second_tls)
                await peer.ping()
            finally:
                await peer.close()
            await proxy.stop_connections()
            await origin.stop_connections()
            correlate(tunnels, origin)
            self.assertEqual(len(tunnels.proxy_connections), 1)
            self.assertEqual([item.stream_id for item in tunnels.openings], [1, 3])
            self.assertEqual([item.status for item in tunnels.openings], [200, 200])
            self.assertEqual(
                [item.origin_connection for item in tunnels.openings], [0, 1]
            )
            self.assertEqual(
                [item.protocol for item in run.websockets], ["http/1.1", "h2"]
            )
            metadata = CaptureMetadata(
                "scripted", "0", "test", "owned", "owned", "scripted", "none"
            )
            text = fixture(
                SCENARIOS["accept"],
                [tunnels],
                metadata,
                mode="https",
                proxy_alpn="h2",
                origin_alpn="negotiate",
                proxy_address="127.0.0.1:0",
            )
            self.assertIn("proxy_alpn_offer=h2\n", text)
            self.assertIn("run_0_proxy_connection_count=1\n", text)
            self.assertIn("run_0_proxy_stream_count=2\n", text)
            self.assertIn("_client_stream_hex=505249202a20485454502f322e30", text)
            self.assertIn("connection:0,stream:3,status:200", text)
            self.assert_clean(proxy)

    def assert_clean(self, proxy):
        self.assertFalse(proxy.writers)
        self.assertFalse(proxy.handlers)
        self.assertFalse(proxy.protocols)

    async def test_padding_credit_and_native_backpressure_resume_before_half_close(
        self,
    ):
        async with raw_servers(RawOrigin(held=True)) as (origin, proxy, certificate):
            original, wrapped, paused = asyncio.open_connection, [], asyncio.Event()

            async def tracked(*args, **kwargs):
                reader, writer = await original(*args, **kwargs)
                if args == proxy.origin:
                    writer = NativeDrainWriter(writer, paused)
                    wrapped.append(writer)
                return reader, writer

            peer = await ProxyH2.open(proxy, certificate)
            sending = None
            try:
                with patch(
                    "scripts.capture.websocket_tunnel_h2.asyncio.open_connection",
                    new=tracked,
                ):
                    stream = await peer.connect(proxy)
                    payload = bytes(range(256)) * 4096

                    async def send_padded():
                        position = 0
                        while position < len(payload):
                            window = peer.connection.local_flow_control_window(
                                stream.stream_id
                            )
                            size = min(window - 256, 8192, len(payload) - position)
                            if size <= 0:
                                await peer.wait_for_window(len(peer.events))
                                continue
                            peer.connection.send_data(
                                stream.stream_id,
                                payload[position : position + size],
                                pad_length=255,
                            )
                            position += size
                            await peer.flush()
                        stream.write_eof()
                        await peer.flush()

                    sending = asyncio.create_task(send_padded())
                    await asyncio.wait_for(paused.wait(), TIMEOUT)
                    self.assertTrue(wrapped[0].undrained_write)
                    self.assertFalse(sending.done())
                    await peer.ping()
                    origin.release.set()
                    await asyncio.wait_for(sending, TIMEOUT)
                    await peer.wait(
                        lambda: peer.stream_events(stream.stream_id, StreamEnded)
                    )
                    self.assertEqual(
                        await stream.read(), hashlib.sha256(payload).digest()
                    )
                    self.assertEqual(origin.received, payload)
                    self.assertGreater(wrapped[0].pending_drains, 0)
            finally:
                origin.release.set()
                if sending is not None and not sending.done():
                    sending.cancel()
                    await asyncio.gather(sending, return_exceptions=True)
                await peer.close()
            await proxy.stop_connections()
            self.assert_clean(proxy)

    async def test_zero_window_reset_leaves_another_tunnel_usable(self):
        async with raw_servers(ReplyOrigin()) as (_, proxy, certificate):
            peer = await ProxyH2.open(
                proxy, certificate, auto_credit=False, window=1024
            )
            try:
                blocked = await peer.connect(proxy)
                blocked.write(b"L")
                await blocked.drain()
                await peer.wait(
                    lambda: (
                        sum(
                            len(event.data)
                            for event in peer.stream_events(1, DataReceived)
                        )
                        == 1024
                    )
                )
                await peer.ping()
                self.assertFalse(peer.stream_events(1, StreamEnded))
                blocked.close()
                await blocked.wait_closed()
                other = await peer.connect(proxy)
                other.write(b"K")
                await other.drain()
                await peer.wait(lambda: peer.stream_events(3, StreamEnded))
                self.assertEqual(await other.read(), b"okay")
                await peer.ping()
            finally:
                await peer.close()
            await proxy.stop_connections()
            self.assertEqual(proxy.tunnel_run.openings[0].outcome, "client-reset")
            self.assert_clean(proxy)

    async def test_window_and_settings_updates_resume_all_ordered_origin_bytes(self):
        async with raw_servers(ReplyOrigin()) as (_, proxy, certificate):
            peer = await ProxyH2.open(
                proxy, certificate, auto_credit=False, window=1024
            )
            try:
                stream = await peer.connect(proxy)
                peer.connection.update_settings({SettingCodes.INITIAL_WINDOW_SIZE: 0})
                await peer.flush()
                await peer.ping()
                stream.write(b"L")
                await stream.drain()
                await peer.ping()
                self.assertFalse(peer.stream_events(1, DataReceived))
                peer.connection.update_settings(
                    {SettingCodes.INITIAL_WINDOW_SIZE: 32768}
                )
                await peer.flush()
                credited = 0
                while not peer.stream_events(1, StreamEnded):
                    await peer.wait(
                        lambda credited=credited: (
                            len(peer.stream_events(1, DataReceived)) > credited
                            or peer.stream_events(1, StreamEnded)
                        )
                    )
                    events = peer.stream_events(1, DataReceived)
                    for event in events[credited:]:
                        peer.connection.acknowledge_received_data(
                            event.flow_controlled_length, 1
                        )
                    credited = len(events)
                    await peer.flush()
                payload = b"".join(
                    event.data for event in peer.stream_events(1, DataReceived)
                )
                self.assertEqual(payload, b"x" * 131072)
            finally:
                await peer.close()
            await proxy.stop_connections()
            self.assert_clean(proxy)

    async def test_stop_retires_a_stream_stalled_on_client_window_credit(self):
        async with raw_servers(ReplyOrigin()) as (_, proxy, certificate):
            peer = await ProxyH2.open(
                proxy, certificate, auto_credit=False, window=1024
            )
            try:
                stream = await peer.connect(proxy)
                stream.write(b"L")
                await stream.drain()
                await peer.wait(lambda: peer.stream_events(1, DataReceived))
                await peer.ping()
                await proxy.stop_connections()
                self.assert_clean(proxy)
            finally:
                await peer.close()

    async def test_target_and_origin_refusals_do_not_end_the_proxy_session(self):
        async with servers("https", proxy_alpn="h2") as (
            origin,
            proxy,
            run,
            tunnels,
            _,
            certificate,
        ):
            peer = await ProxyH2.open(proxy, certificate)
            try:
                await peer.connect(
                    proxy, target=b"elsewhere.invalid:443", status=b"403"
                )
                await peer.ping()
                self.assertFalse(run.connections)
                origin.servers[0].close()
                await origin.servers[0].wait_closed()
                await peer.connect(proxy, status=b"502")
                await peer.ping()
                self.assertEqual(
                    [item.outcome for item in tunnels.openings],
                    ["rejected", "origin-refused"],
                )
                self.assertTrue(all(item.upstream is None for item in tunnels.openings))
            finally:
                await peer.close()
            await proxy.stop_connections()
            self.assert_clean(proxy)

    async def test_reset_in_the_opening_batch_does_not_break_another_stream(self):
        async with servers("https", proxy_alpn="h2") as (
            _,
            proxy,
            run,
            _,
            _,
            certificate,
        ):
            peer = await ProxyH2.open(proxy, certificate)
            try:
                peer.connection.send_headers(
                    1,
                    [
                        (b":method", b"CONNECT"),
                        (b":authority", b"elsewhere.invalid:443"),
                    ],
                )
                peer.connection.reset_stream(1)
                await peer.flush()
                await peer.ping()
                self.assertFalse(run.connections)
            finally:
                await peer.close()
            await proxy.stop_connections()
            self.assert_clean(proxy)

    async def test_unknown_close_wait_failure_remains_owned_and_observable(self):
        async with raw_servers(RawOrigin()) as (_, proxy, certificate):
            original, wrapped = asyncio.open_connection, []
            failure = OSError("deliberate H2 relay close-wait failure")

            async def tracked(*args, **kwargs):
                reader, writer = await original(*args, **kwargs)
                if args == proxy.origin:
                    writer = NativeDrainWriter(writer, asyncio.Event())
                    wrapped.append(writer)
                return reader, writer

            peer = await ProxyH2.open(proxy, certificate)
            try:
                with patch(
                    "scripts.capture.websocket_tunnel_h2.asyncio.open_connection",
                    new=tracked,
                ):
                    stream = await peer.connect(proxy)
                    stream.write(b"owned")
                    await stream.drain()
                    stream.write_eof()
                    await peer.flush()
                    await peer.wait(lambda: peer.stream_events(1, StreamEnded))
                    wrapped[0].closed_error = failure
                await peer.close()
                with self.assertRaises(BaseException) as raised:
                    await proxy.stop_connections()
                self.assertIn(failure, failures(raised.exception))
                self.assertIn(wrapped[0], proxy.writers)
                await proxy.close()
                self.assert_clean(proxy)
            finally:
                await peer.close()

    async def test_missing_proxy_alpn_is_a_capture_failure_before_origin_io(self):
        async with servers("https", proxy_alpn="h2") as (
            _,
            proxy,
            run,
            _,
            _,
            certificate,
        ):
            reader, writer = await open_proxy(proxy, certificate)
            try:
                self.assertIsNone(
                    writer.get_extra_info("ssl_object").selected_alpn_protocol()
                )
                self.assertEqual(await asyncio.wait_for(reader.read(), TIMEOUT), b"")
            finally:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), TIMEOUT)
            with self.assertRaisesRegex(ValueError, "did not negotiate HTTP/2"):
                await proxy.stop_connections()
            self.assertFalse(run.connections)
            self.assert_clean(proxy)


class Http2ProxyArgumentTests(unittest.TestCase):
    def test_plaintext_and_socks_h2_selections_fail_before_starting_a_capture(self):
        for mode in ("http", "socks5"):
            with (
                self.subTest(mode=mode),
                contextlib.redirect_stderr(io.StringIO()),
                patch(
                    "scripts.capture.tunnelled_websocket.generate_certificate"
                ) as generate,
            ):
                with self.assertRaises(SystemExit) as raised:
                    main(
                        [
                            "--browser",
                            "firefox",
                            "--browser-path",
                            str(Path("owned.exe")),
                            "--client-version",
                            "157.0",
                            "--proxy",
                            mode,
                            "--proxy-alpn",
                            "h2",
                            "--output-dir",
                            "owned",
                        ]
                    )
                self.assertEqual(raised.exception.code, 2)
                generate.assert_not_called()
