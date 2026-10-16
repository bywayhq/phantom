"""Fresh H3 clients remain usable after an owned Windows UDP disconnect."""

import asyncio
import dataclasses
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from scripts.capture.sse_multiplexed import H3ReconnectServer
from scripts.capture.sse_reconnect import (
    CATALOG,
    CONNECTION_CLEANUP_SECONDS,
    NO_CONTENT,
    ScenarioRun,
)
from scripts.capture.tests.test_sse_reconnect_h3 import H3EventSource


class H3ListenerReuseTests(unittest.IsolatedAsyncioTestCase):
    @unittest.skipUnless(sys.platform == "win32", "Windows Proactor UDP ICMP delivery")
    async def test_fresh_client_after_real_cleanup_error_receives_verified_h3(self):
        server = H3ReconnectServer()
        await server.start("127.0.0.1", 0)
        scenario = dataclasses.replace(
            CATALOG[0], attempts=(NO_CONTENT,), observation_seconds=0
        )
        first = ScenarioRun(scenario, "before-native-disconnect")
        server.run = first
        client = H3EventSource(server.url(first))
        started = False
        cleanup = None
        entered, release, observed = asyncio.Event(), asyncio.Event(), asyncio.Event()
        old_transport, old_endpoint = server.transport, server.endpoint
        old_socket = old_transport.get_extra_info("socket")
        old_address = server.address
        errors, receive_futures = [], []
        original_error = server.udp_error

        def observe(error):
            errors.append(error)
            receive_futures.append(old_transport._read_fut)
            original_error(error)
            observed.set()

        server.udp_error = observe
        try:
            await asyncio.wait_for(client.start(server), 2)
            started = True
            stream = server.url(first).replace(first.page_path(), first.stream_path())
            self.assertEqual((await client.fetch(stream, ()))[0], 204)
            await asyncio.wait_for(first.done.wait(), 2)
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
            old_transport.sendto(b"closed-owned-peer", peer_address)
            await asyncio.wait_for(observed.wait(), 2)
            self.assertEqual([error.winerror for error in errors], [1234])
            self.assertEqual(receive_futures, [None])
            self.assertFalse(old_transport.is_closing())
            self.assertIsNone(old_transport._read_fut)
            self.assertFalse(server.failures)
            self.assertEqual(
                [code for _, code in first.udp_cleanup_disconnects], [1234]
            )
            release.set()
            await asyncio.wait_for(cleanup, 2)
            server.udp_error = original_error

            second = ScenarioRun(scenario, "after-native-disconnect")
            server.run = second
            client = H3EventSource(server.url(second))
            await asyncio.wait_for(client.start(server), 2)
            started = True
            stream = server.url(second).replace(
                second.page_path(), second.stream_path()
            )
            self.assertEqual((await client.fetch(stream, ()))[0], 204)
            await asyncio.wait_for(second.done.wait(), 2)
            self.assertEqual(second.connections[0].protocol, "h3")
            self.assertIsNot(second, first)
            self.assertEqual(server.address, old_address)
            self.assertIsNot(server.endpoint, old_endpoint)
            self.assertTrue(old_transport.is_closing())
            self.assertEqual(old_socket.fileno(), -1)
            self.assertFalse(server.failures)
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

    async def test_final_close_never_replaces_listener(self):
        server = H3ReconnectServer()
        await server.start("127.0.0.1", 0)
        transport = server.transport
        server.replace_listener = True
        with patch.object(server, "start", new=AsyncMock()) as start:
            await server.close()
            start.assert_not_awaited()
        self.assertTrue(transport.is_closing())
        self.assertTrue(server.retired.done())

    async def test_failed_rebind_keeps_retired_endpoint_reportable_and_closeable(self):
        server = H3ReconnectServer()
        await server.start("127.0.0.1", 0)
        transport, endpoint, retired = server.transport, server.endpoint, server.retired
        server.replace_listener = True
        failure = OSError("injected replacement bind failure")
        try:
            with (
                patch.object(
                    asyncio.get_running_loop(),
                    "create_datagram_endpoint",
                    new=AsyncMock(side_effect=failure),
                ),
                self.assertRaises(OSError) as raised,
            ):
                await server.finish_run()
            self.assertIs(raised.exception, failure)
            self.assertIs(server.transport, transport)
            self.assertIs(server.endpoint, endpoint)
            self.assertIs(server.retired, retired)
            self.assertTrue(retired.done())
            self.assertTrue(transport.is_closing())
            self.assertTrue(server.replace_listener)
        finally:
            # A failed shielded collector remains owned and reportable on retry.
            with self.assertRaises(OSError) as raised:
                await server.close()
            self.assertIs(raised.exception, failure)

    async def test_retirement_failure_prevents_rebind_and_close_retries_owner(self):
        server = H3ReconnectServer()
        await server.start("127.0.0.1", 0)
        server.replace_listener = True
        failure = RuntimeError("injected endpoint close failure")
        try:
            with (
                patch.object(server.endpoint, "close", side_effect=failure),
                patch.object(server, "start", new=AsyncMock()) as start,
            ):
                with self.assertRaises(RuntimeError) as raised:
                    await server.finish_run()
                self.assertIs(raised.exception, failure)
                start.assert_not_awaited()
            self.assertFalse(server.retired.done())
            self.assertFalse(server.transport.is_closing())
        finally:
            with self.assertRaises(RuntimeError) as raised:
                await server.close()
            self.assertIs(raised.exception, failure)
            self.assertTrue(server.retired.done())
            self.assertTrue(server.transport.is_closing())

    async def test_old_callbacks_cannot_retire_or_wake_new_listener_run(self):
        server = H3ReconnectServer()
        await server.start("127.0.0.1", 0)
        old_endpoint = server.endpoint
        old_retired = server.retired
        server.replace_listener = True
        try:
            await server.finish_run()
            current_retired = server.retired
            run = ScenarioRun(CATALOG[0], "new-listener-owner")
            server.run = run
            self.assertIsNot(old_retired, current_retired)
            self.assertTrue(old_retired.done())
            old_endpoint.datagram_received(b"old-datagram", ("127.0.0.1", 1))
            old_endpoint.connection_lost(None)
            self.assertFalse(current_retired.done())
            self.assertFalse(run.done.is_set())
            self.assertFalse(run.connections)
            failure = OSError("late retired-endpoint error")
            old_endpoint.error_received(failure)
            self.assertIs(server.failures[-1], failure)
            self.assertFalse(run.done.is_set())
            self.assertFalse(run.udp_cleanup_disconnects)
        finally:
            with self.assertRaises(ConnectionError):
                await server.close()
            self.assertTrue(server.retired.done())

    async def test_replacement_uses_remaining_original_cleanup_budget(self):
        server = H3ReconnectServer()
        await server.start("127.0.0.1", 0)
        server.replace_listener = True
        loop = asyncio.get_running_loop()
        original_retire = server.retire_listener
        observed = []
        original_wait_for = asyncio.wait_for
        clock = loop.time()
        retirement_cost = 1.0
        runtime = SimpleNamespace(**vars(asyncio))
        runtime.get_running_loop = lambda: SimpleNamespace(
            time=lambda: clock,
            create_future=loop.create_future,
            create_datagram_endpoint=loop.create_datagram_endpoint,
        )

        async def retire(deadline):
            nonlocal clock
            observed.append(deadline)
            await original_retire(deadline)
            # Charge known work without relying on a Windows clock tick.
            clock += retirement_cost
            observed.append(clock)

        async def wait_for(operation, timeout):
            if getattr(operation, "cr_code", None) is server.start.__code__:
                observed.append(timeout)
            return await original_wait_for(operation, timeout)

        runtime.wait_for = wait_for
        try:
            with (
                patch.object(server, "retire_listener", side_effect=retire),
                patch("scripts.capture.sse_multiplexed.asyncio", runtime),
            ):
                await server.finish_run()
            deadline, retired_at, remaining = observed
            self.assertLessEqual(remaining, deadline - retired_at)
            self.assertLess(remaining, CONNECTION_CLEANUP_SECONDS)
            self.assertGreater(remaining, 0)
            self.assertEqual(remaining, CONNECTION_CLEANUP_SECONDS - retirement_cost)
        finally:
            await server.close()
