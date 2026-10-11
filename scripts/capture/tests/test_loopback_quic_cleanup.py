"""Cleanup contracts for actual loopback QUIC client transports."""

import asyncio
import contextlib
import ssl
import unittest

from aioquic.asyncio import QuicConnectionProtocol
from aioquic.asyncio.server import QuicServer
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import (
    ConnectionTerminated,
    HandshakeCompleted,
    PingAcknowledged,
)
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate

from scripts.capture.http2_session import HOSTNAME, generate_certificate
from scripts.capture.reserved_ports import open_past_reserved_ports
from scripts.capture.tests.loopback_quic import connect_loopback

CONTROL_TIMEOUT = 5.0
ALPN = ["cleanup-test"]


class CloseFailure(RuntimeError):
    pass


class WaitClosedFailure(RuntimeError):
    pass


class BodyFailure(RuntimeError):
    pass


class BackupFailure(RuntimeError):
    def __init__(self, failures):
        super().__init__("loopback resource backup failed")
        self.failures = tuple(failures)


class EndpointObservation:
    def __init__(self):
        self.transport = None
        self.socket = None
        self.lost = asyncio.get_running_loop().create_future()

    def acquired(self, transport):
        self.transport = transport
        self.socket = transport.get_extra_info("socket")

    def connection_lost(self, error):
        if not self.lost.done():
            self.lost.set_result(error)


class ObservedProtocol(QuicConnectionProtocol):
    def __init__(self, *args, resources, endpoint=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.endpoint = endpoint
        self.handshake = asyncio.Event()
        self.terminated = False
        self.pings = []
        self.close_failure = None
        self.wait_failure = None
        self.close_returned = False
        self.wait_returned = False
        self.observe_cancellation = False
        self.pending_wait = asyncio.get_running_loop().create_future()
        self.waiter = None
        self.wait_cancellation = None
        resources.protocols.append(self)

    def connection_made(self, transport):
        super().connection_made(transport)
        if self.endpoint is not None:
            self.endpoint.acquired(transport)

    def connection_lost(self, error):
        super().connection_lost(error)
        if self.endpoint is not None:
            self.endpoint.connection_lost(error)

    def quic_event_received(self, event):
        super().quic_event_received(event)
        if isinstance(event, HandshakeCompleted):
            self.handshake.set()
        elif isinstance(event, ConnectionTerminated):
            self.terminated = True
        elif isinstance(event, PingAcknowledged):
            self.pings.append(event.uid)

    def close(self, *args, **kwargs):
        super().close(*args, **kwargs)
        self.close_returned = True
        if self.close_failure is not None:
            raise self.close_failure

    async def wait_closed(self):
        handle = None
        if self.observe_cancellation:
            handle = asyncio.get_running_loop().call_soon(self.observe_pending_wait)
        try:
            await super().wait_closed()
            self.wait_returned = True
        except asyncio.CancelledError as error:
            self.wait_cancellation = error
            raise
        finally:
            if handle is not None:
                handle.cancel()

        if self.wait_failure is not None:
            raise self.wait_failure

    def observe_pending_wait(self):
        for waiter in self._closed._waiters:
            if not waiter.done():
                self.waiter = waiter
                self.pending_wait.set_result(None)
                return

        self.pending_wait.set_exception(
            AssertionError("actual QUIC close waiter was not pending")
        )


class ObservedServer(QuicServer):
    def __init__(self, resources, **kwargs):
        super().__init__(**kwargs)
        self.endpoint = resources.server_endpoint
        resources.server = self

    def connection_made(self, transport):
        super().connection_made(transport)
        self.endpoint.acquired(transport)

    def connection_lost(self, error):
        super().connection_lost(error)
        self.endpoint.connection_lost(error)


class LoopbackResources:
    def __init__(self):
        self.server_endpoint = EndpointObservation()
        self.client_endpoint = EndpointObservation()
        self.protocols = []
        self.tasks = []
        self.observed_tasks = set()
        self.server = None
        self.client = None
        self.port = None
        self.body_ready = asyncio.Event()
        self.first_cancellation = None

    async def start(self):
        certificate = generate_certificate()
        configuration = QuicConfiguration(is_client=False, alpn_protocols=ALPN)
        configuration.certificate = load_pem_x509_certificate(
            certificate.certificate_pem
        )
        configuration.private_key = load_pem_private_key(
            certificate.private_key_pem, password=None
        )

        transport, _ = await open_past_reserved_ports(
            lambda host, port: asyncio.get_running_loop().create_datagram_endpoint(
                lambda: ObservedServer(
                    self,
                    configuration=configuration,
                    create_protocol=lambda *args, **kwargs: ObservedProtocol(
                        *args, resources=self, **kwargs
                    ),
                ),
                local_addr=(host, port),
            ),
            "127.0.0.1",
            0,
        )
        self.port = transport.get_extra_info("sockname")[1]

    def create_client(self, connection):
        self.client = ObservedProtocol(
            connection, resources=self, endpoint=self.client_endpoint
        )
        return self.client

    async def target(self, body, *, wait_connected=True):
        configuration = QuicConfiguration(
            is_client=True,
            alpn_protocols=ALPN,
            server_name=HOSTNAME,
            verify_mode=ssl.CERT_NONE,
        )
        try:
            async with connect_loopback(
                self.port,
                configuration,
                self.create_client,
                wait_connected=wait_connected,
            ) as client:
                if not wait_connected:
                    client.transmit()
                    await client.wait_connected()
                await client.ping()
                await body(client)
        except BaseException as error:
            return error

        return None

    def spawn_target(self, body, *, wait_connected=True):
        task = asyncio.create_task(self.target(body, wait_connected=wait_connected))
        self.tasks.append(task)
        return task

    async def outcome(self, task):
        done, _ = await asyncio.wait({task}, timeout=CONTROL_TIMEOUT)
        if not done:
            raise AssertionError("loopback target did not finish before watchdog")
        self.observed_tasks.add(task)
        return task.result()

    async def backup(self):
        failures = []
        pending = {task for task in self.tasks if not task.done()}
        for task in pending:
            task.cancel()

        waiters = []
        try:
            for protocol in self.protocols:
                waiters.extend(protocol._ping_waiters.values())
                if protocol._connected_waiter is not None:
                    waiters.append(protocol._connected_waiter)
                try:
                    QuicConnectionProtocol.close(protocol)
                except BaseException as error:
                    failures.append(error)

            for protocol in self.protocols:
                try:
                    await asyncio.wait_for(
                        QuicConnectionProtocol.wait_closed(protocol), CONTROL_TIMEOUT
                    )
                except BaseException as error:
                    failures.append(error)
        finally:
            for endpoint in (self.client_endpoint, self.server_endpoint):
                if endpoint.transport is not None:
                    try:
                        endpoint.transport.close()
                    except BaseException as error:
                        failures.append(error)

            for protocol in self.protocols:
                # Backup owns scheduled work if protocol termination did not complete.
                for handle in (protocol._timer, protocol._transmit_task):
                    if handle is not None:
                        handle.cancel()

        if self.tasks:
            try:
                done, unfinished = await asyncio.wait(
                    self.tasks, timeout=CONTROL_TIMEOUT
                )
            except BaseException as error:
                failures.append(error)
                done = {task for task in self.tasks if task.done()}
                unfinished = set(self.tasks) - done

            for task in done:
                if task in self.observed_tasks:
                    continue
                try:
                    result = task.result()
                    if isinstance(result, BaseException):
                        failures.append(result)
                except asyncio.CancelledError as error:
                    if task not in pending:
                        failures.append(error)
                except BaseException as error:
                    failures.append(error)
            if unfinished:
                failures.append(AssertionError("owned loopback tasks did not stop"))

        for endpoint in (self.client_endpoint, self.server_endpoint):
            if endpoint.transport is not None:
                try:
                    error = await asyncio.wait_for(
                        asyncio.shield(endpoint.lost), CONTROL_TIMEOUT
                    )
                    if error is not None:
                        failures.append(error)
                    if endpoint.socket.fileno() != -1:
                        raise AssertionError("backup left an actual UDP socket open")
                except BaseException as error:
                    failures.append(error)

        for waiter in waiters:
            if waiter.done() and not waiter.cancelled():
                error = waiter.exception()
                if error is not None:
                    failures.append(error)
        if (
            self.client is not None
            and self.client.pending_wait.done()
            and not self.client.pending_wait.cancelled()
        ):
            error = self.client.pending_wait.exception()
            if error is not None:
                failures.append(error)
        return failures


@contextlib.asynccontextmanager
async def ready_resources():
    resources = LoopbackResources()
    primary = None
    try:
        await resources.start()
        yield resources
    except BaseException as error:
        primary = error
        raise
    finally:
        failures = await resources.backup()
        if failures:
            backup = BackupFailure(failures)
            if primary is None:
                raise backup
            primary.test_backup_failure = backup


class LoopbackCleanupTests(unittest.IsolatedAsyncioTestCase):
    def assert_ready(self, resources):
        client = resources.client
        self.assertTrue(client.handshake.is_set())
        self.assertTrue(client.pings)
        self.assertTrue(
            any(
                peer is not client and peer.handshake.is_set()
                for peer in resources.protocols
            )
        )
        self.assertEqual(resources.client_endpoint.socket.getsockname()[0], "127.0.0.1")

    async def assert_transport_closed(self, resources):
        endpoint = resources.client_endpoint
        self.assertTrue(endpoint.transport.is_closing())
        self.assertIsNone(
            await asyncio.wait_for(asyncio.shield(endpoint.lost), CONTROL_TIMEOUT)
        )
        self.assertEqual(endpoint.socket.fileno(), -1)

    async def test_healthy_context_closes_actual_udp_transport(self):
        async with ready_resources() as resources:

            async def body(client):
                self.assert_ready(resources)

            result = await resources.outcome(resources.spawn_target(body))
            self.assertIsNone(result)
            self.assertTrue(resources.client.terminated)
            await self.assert_transport_closed(resources)

    async def test_explicit_connection_wait_closes_actual_udp_transport(self):
        async with ready_resources() as resources:

            async def body(client):
                self.assert_ready(resources)

            result = await resources.outcome(
                resources.spawn_target(body, wait_connected=False)
            )
            self.assertIsNone(result)
            self.assertTrue(resources.client.terminated)
            await self.assert_transport_closed(resources)

    async def test_close_failure_still_closes_actual_udp_transport(self):
        failure = CloseFailure("controlled error after actual QUIC close")
        async with ready_resources() as resources:

            async def body(client):
                self.assert_ready(resources)
                client.close_failure = failure

            result = await resources.outcome(resources.spawn_target(body))
            self.assertIs(result, failure)
            self.assertTrue(resources.client.close_returned)
            await self.assert_transport_closed(resources)

    async def test_wait_failure_still_closes_actual_udp_transport(self):
        failure = WaitClosedFailure("controlled error after actual QUIC termination")
        async with ready_resources() as resources:

            async def body(client):
                self.assert_ready(resources)
                client.wait_failure = failure

            result = await resources.outcome(resources.spawn_target(body))
            self.assertIs(result, failure)
            self.assertTrue(resources.client.wait_returned)
            self.assertTrue(resources.client.terminated)
            self.assertTrue(resources.client._closed.is_set())
            await self.assert_transport_closed(resources)

    async def test_body_failure_preserves_original_cause_and_cleanup(self):
        original_cause = LookupError("original body cause")
        primary = BodyFailure("controlled body failure")
        primary.__cause__ = original_cause
        cleanup = WaitClosedFailure("controlled error after actual QUIC termination")
        async with ready_resources() as resources:

            async def body(client):
                self.assert_ready(resources)
                client.wait_failure = cleanup
                raise primary

            result = await resources.outcome(resources.spawn_target(body))
            self.assertTrue(resources.client.terminated)
            self.assertIs(result, primary)
            self.assertIs(result.__cause__, original_cause)
            self.assertIs(result.capture_cleanup_failure, cleanup)
            await self.assert_transport_closed(resources)

    async def test_renewed_cancellation_preserves_first_and_closes_transport(self):
        async with ready_resources() as resources:

            async def body(client):
                self.assert_ready(resources)
                client.observe_cancellation = True
                resources.body_ready.set()
                try:
                    await asyncio.Event().wait()
                except asyncio.CancelledError as error:
                    resources.first_cancellation = error
                    raise

            target = resources.spawn_target(body)

            async def cancel_twice():
                await asyncio.wait_for(resources.body_ready.wait(), CONTROL_TIMEOUT)
                self.assertTrue(target.cancel("first cancellation"))
                await asyncio.wait_for(
                    asyncio.shield(resources.client.pending_wait), CONTROL_TIMEOUT
                )
                self.assertIsNotNone(resources.first_cancellation)
                self.assertFalse(resources.client.waiter.done())
                self.assertTrue(target.cancel("renewed cancellation"))

            controller = asyncio.create_task(cancel_twice())
            resources.tasks.append(controller)
            self.assertIsNone(await resources.outcome(controller))
            result = await resources.outcome(target)

            first = resources.first_cancellation
            second = resources.client.wait_cancellation
            self.assertIsInstance(first, asyncio.CancelledError)
            self.assertIsInstance(second, asyncio.CancelledError)
            self.assertIsNot(first, second)
            self.assertEqual(first.args, ("first cancellation",))
            self.assertEqual(second.args, ("renewed cancellation",))
            self.assertTrue(resources.client.waiter.cancelled())
            self.assertIs(result, first)
            self.assertIs(result.capture_cleanup_failure, second)
            await self.assert_transport_closed(resources)
