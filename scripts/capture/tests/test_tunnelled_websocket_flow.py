"""Actual relay half-close, native backpressure and cleanup ownership controls."""

import asyncio
import contextlib
import hashlib
import re
import unittest
from unittest.mock import patch
from urllib.parse import urlencode, urlsplit

from scripts.capture.http2_session import raise_capture_failures
from scripts.capture.tests.test_http2_websocket import ScriptedBrowser
from scripts.capture.tests.test_tunnelled_websocket_limits import failures
from scripts.capture.tests.tunnelled_websocket_flow_peer import (
    NativeDrainWriter,
    connect,
    raw_tunnel,
)
from scripts.capture.tests.tunnelled_websocket_peer import (
    TIMEOUT,
    open_h2,
    open_proxy,
    open_tunnel,
    servers,
)
from scripts.capture.tunnelled_websocket import SCENARIOS, capture_through_proxy


class TunnelFlowTests(unittest.IsolatedAsyncioTestCase):
    async def test_half_close_preserves_every_delayed_origin_byte(self):
        async with raw_tunnel() as (origin, proxy):
            reader, writer = await connect(proxy)
            payload = b"ordered-after-half-close" * 4096
            try:
                writer.write(payload)
                await writer.drain()
                writer.write_eof()
                self.assertEqual(
                    await asyncio.wait_for(reader.readexactly(32), TIMEOUT),
                    hashlib.sha256(payload).digest(),
                )
                self.assertEqual(await asyncio.wait_for(reader.read(), TIMEOUT), b"")
            finally:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), TIMEOUT)
            await proxy.stop_connections()
            self.assertEqual(origin.received, payload)
            self.assertFalse(proxy.handlers)
            self.assertFalse(proxy.writers)

    async def test_actual_native_backpressure_stops_relay_reads_and_resumes_in_order(
        self,
    ):
        async with raw_tunnel(held=True) as (origin, proxy):
            original = asyncio.open_connection
            paused, wrapped = asyncio.Event(), []

            async def tracked(*args, **kwargs):
                reader, writer = await original(*args, **kwargs)
                if args == proxy.origin:
                    writer = NativeDrainWriter(writer, paused)
                    wrapped.append(writer)
                return reader, writer

            with patch(
                "scripts.capture.websocket_tunnel.asyncio.open_connection", new=tracked
            ):
                reader, writer = await connect(proxy)
                sending = None
                try:
                    await asyncio.wait_for(origin.accepted.wait(), TIMEOUT)
                    payload = bytes(range(256)) * (8 * 4096)
                    writer.write(payload)
                    sending = asyncio.create_task(writer.drain())
                    await asyncio.wait_for(paused.wait(), TIMEOUT)
                    self.assertGreater(
                        wrapped[0].transport.get_write_buffer_size(), 1024
                    )
                    self.assertEqual(wrapped[0].writes, wrapped[0].paused_at)
                    origin.release.set()
                    await asyncio.wait_for(sending, TIMEOUT)
                    writer.write_eof()
                    self.assertEqual(
                        await asyncio.wait_for(reader.readexactly(32), TIMEOUT),
                        hashlib.sha256(payload).digest(),
                    )
                finally:
                    origin.release.set()
                    writer.close()
                    await asyncio.wait_for(writer.wait_closed(), TIMEOUT)
                    if sending is not None:
                        await asyncio.wait_for(sending, TIMEOUT)
            await proxy.stop_connections()
            self.assertEqual(origin.received, payload)
            self.assertFalse(proxy.handlers)
            self.assertFalse(proxy.writers)
            self.assertFalse(proxy.protocols)

    async def test_partial_proxy_openings_close_without_origin_io(self):
        for mode in ("http", "https", "socks5"):
            async with servers(mode) as (
                origin,
                proxy,
                run,
                tunnels,
                _,
                proxy_certificate,
            ):
                reader, writer = await open_proxy(proxy, proxy_certificate)
                writer.write(b"\x05" if mode == "socks5" else b"CON")
                await writer.drain()
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), TIMEOUT)
                await proxy.stop_connections()
                self.assertFalse(run.connections)
                self.assertTrue(
                    all(opening.upstream is None for opening in tunnels.openings)
                )
                self.assertFalse(proxy.writers)
                self.assertFalse(proxy.handlers)
                self.assertFalse(proxy.protocols)

    async def test_unknown_close_wait_error_is_retained_until_socket_retirement_retry(
        self,
    ):
        async with raw_tunnel() as (_, proxy):
            original = asyncio.open_connection
            wrapped = []
            error = OSError("deliberate close-wait failure")

            async def tracked(*args, **kwargs):
                reader, writer = await original(*args, **kwargs)
                if args == proxy.origin:
                    writer = NativeDrainWriter(writer, asyncio.Event())
                    wrapped.append(writer)
                return reader, writer

            with patch(
                "scripts.capture.websocket_tunnel.asyncio.open_connection", new=tracked
            ):
                reader, writer = await connect(proxy)
                try:
                    writer.write(b"native-close")
                    await writer.drain()
                    writer.write_eof()
                    await asyncio.wait_for(reader.readexactly(32), TIMEOUT)
                finally:
                    writer.close()
                    await asyncio.wait_for(writer.wait_closed(), TIMEOUT)
                wrapped[0].closed_error = error
                with self.assertRaises(BaseException) as raised:
                    await proxy.stop_connections()
                self.assertIn(error, failures(raised.exception))
                self.assertIn(wrapped[0], proxy.writers)
                await proxy.close()
                self.assertFalse(proxy.writers)
                self.assertFalse(proxy.handlers)
                self.assertFalse(proxy.protocols)

    async def test_second_pump_creation_failure_retires_first_pump_and_real_sockets(
        self,
    ):
        error = RuntimeError("deliberate second-pump creation failure")
        proxy = None
        with self.assertRaises(BaseException) as raised:
            async with raw_tunnel() as (_, proxy):
                original = asyncio.create_task

                def create(operation):
                    if operation.cr_code.co_name == "inward":
                        raise error
                    return original(operation)

                with patch(
                    "scripts.capture.websocket_tunnel.asyncio.create_task", new=create
                ):
                    reader, writer = await connect(proxy)
                    try:
                        self.assertEqual(
                            await asyncio.wait_for(reader.read(), TIMEOUT), b""
                        )
                    finally:
                        writer.close()
                        await asyncio.wait_for(writer.wait_closed(), TIMEOUT)
                    await proxy.stop_connections()
        self.assertIn(error, failures(raised.exception))
        self.assertFalse(proxy.writers)
        self.assertFalse(proxy.handlers)
        self.assertFalse(proxy.protocols)
        self.assertFalse(
            any(
                "TunnelServer._handle.<locals>" in task.get_coro().__qualname__
                for task in asyncio.all_tasks()
                if not task.done()
            )
        )

    async def test_capture_repeats_own_fresh_scripted_drivers_and_correlated_complete_runs(
        self,
    ):
        async with servers("https") as (
            origin,
            proxy,
            _,
            _,
            certificate,
            proxy_certificate,
        ):
            count = []

            @contextlib.asynccontextmanager
            async def drive(plan, url):
                count.append(url)
                tls = await open_tunnel(
                    proxy, certificate, proxy_certificate, alpn=("h2",)
                )
                peer = await open_h2(tls)
                primary = None

                async def exchange():
                    parts = urlsplit(url)
                    body = await peer.get(parts.path + "?" + parts.query)
                    socket_url = urlsplit(
                        re.search(rb'const socketUrl = "([^"]+)"', body)
                        .group(1)
                        .decode()
                    )
                    done = (
                        re.search(rb'const doneUrl = "([^"]+)"', body).group(1).decode()
                    )
                    result = await ScriptedBrowser(url).h2_websocket(peer, socket_url)
                    await peer.get(done + "&" + urlencode(result))

                task = asyncio.create_task(exchange())
                try:
                    yield
                    await asyncio.wait_for(task, 20)
                except BaseException as error:
                    primary = error
                cleanup = []
                if not task.done():
                    task.cancel()
                results = await asyncio.gather(task, return_exceptions=True)
                for result in results:
                    if (
                        isinstance(result, BaseException)
                        and result is not primary
                        and not isinstance(result, asyncio.CancelledError)
                    ):
                        cleanup.append(result)
                try:
                    await peer.close()
                except BaseException as error:
                    cleanup.append(error)
                raise_capture_failures(primary, tuple(cleanup))

            # The pre-started empty run has no owners; the real capture owns two
            # distinct run tokens and invokes a new driver context for each.
            with patch(
                "scripts.capture.tunnelled_websocket.ProxyBrowserDriver", new=drive
            ):
                runs = await capture_through_proxy(
                    origin,
                    proxy,
                    SCENARIOS["accept"],
                    None,
                    repeat=2,
                    run_timeout=20,
                    observation=0,
                )
            self.assertEqual(len(count), 2)
            self.assertNotEqual(count[0], count[1])
            self.assertEqual(len(runs), 2)
            for run in runs:
                self.assertFalse(run.origin.timed_out)
                self.assertEqual(run.origin.results[0]["opened"], "true")
                self.assertEqual(run.origin.results[0]["echoed"], "5")
                self.assertEqual(len(run.origin.websockets), 1)
                self.assertEqual(run.origin.websockets[0].protocol, "h2")
                self.assertEqual(
                    [opening.origin_connection for opening in run.openings], [0]
                )
            self.assertFalse(proxy.handlers)
            self.assertFalse(origin.handlers)
