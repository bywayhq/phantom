"""Capture startup controls with real loopback peers and a controlled driver."""

import asyncio
import ssl
import unittest
from contextlib import ExitStack, suppress
from pathlib import Path
from unittest.mock import patch

import h2.config
import h2.connection
import h2.events

from scripts.capture import alt_svc_race as race

DEADLINE = 5.0
HOST = "127.0.0.1"
DATAGRAM = b"race-startup-literal-datagram"
ORIGINAL_BIND = race.bind_udp
ORIGINAL_RESERVE = race.reserve_ports
ORIGINAL_UDP = race.UdpAlternative
ORIGINAL_TCP = race.Http2Origin
ORIGINAL_DATAGRAM = race.BlackholeProtocol.datagram_received


class StartupFailure(Exception):
    pass


class CleanupFailure(Exception):
    pass


def contains_identity(error, expected):
    pending = [error]
    visited = set()
    while pending:
        current = pending.pop()
        if current is expected:
            return True

        if current is None or id(current) in visited:
            continue

        visited.add(id(current))
        pending.extend((current.__cause__, current.__context__))

    return False


class CaptureResources:
    """Independent backup retains actual resources before each injected exit."""

    def __init__(self, case):
        self.case = case
        self.primary = StartupFailure(f"controlled startup: {case}")
        self.cleanup = CleanupFailure("controlled first UDP cleanup")
        self.sockets = []
        self.senders = []
        self.udp = []
        self.tcp = []
        self.writers = []
        self.handlers = []
        self.capture = None
        self.binds = 0
        self.received = {}
        self.deliveries = {}
        self.h2_exchanges = []
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self.cancelled = None
        self.outcome = None
        self.cleanup_calls = []
        self.stack = ExitStack()
        self.loop = asyncio.get_running_loop()
        self.previous_handler = self.loop.get_exception_handler()

    def reserve(self, host):
        udp, tcp = ORIGINAL_RESERVE(host)
        self.sockets.extend((udp, tcp))
        return udp, tcp

    async def bind(self, host):
        self.binds += 1
        if self.case == "second-bind" and self.binds == 2:
            await self.raw_datagram(self.sockets[2])
            raise self.primary
        sock = await ORIGINAL_BIND(host)
        self.sockets.append(sock)
        return sock

    async def raw_datagram(self, target):
        sender = await ORIGINAL_BIND(HOST)
        self.senders.append(sender)

        if sender.sendto(DATAGRAM, target.getsockname()) != len(DATAGRAM):
            raise AssertionError("earlier reservation datagram was not sent")
        target.settimeout(DEADLINE)
        try:
            data, _ = target.recvfrom(256)
        finally:
            target.setblocking(False)

        if data != DATAGRAM:
            raise AssertionError(
                "earlier reservation did not receive the literal datagram"
            )

    def datagram(self, protocol, data, address):
        name = protocol.recorder.listener
        self.received.setdefault(name, []).append(data)
        ORIGINAL_DATAGRAM(protocol, data, address)
        self.deliveries[name].set()

    async def udp_exchange(self, alternative):
        name = alternative.recorder.listener
        self.deliveries[name] = asyncio.Event()
        sender = await ORIGINAL_BIND(HOST)
        self.senders.append(sender)
        address = alternative.transport.get_extra_info("sockname")
        if sender.sendto(DATAGRAM, address) != len(DATAGRAM):
            raise AssertionError("blackhole listener datagram was not sent")

        await asyncio.wait_for(self.deliveries[name].wait(), DEADLINE)
        if self.received[name] != [DATAGRAM]:
            raise AssertionError(
                "blackhole listener did not receive the literal datagram"
            )

    async def h2_exchange(self, server, path):
        context = ssl.create_default_context()
        context.load_verify_locations(
            cadata=server.certificate.certificate_pem.decode()
        )
        context.set_alpn_protocols(["h2"])
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                HOST, server.origin.port, ssl=context, server_hostname=race.HOSTNAME
            ),
            DEADLINE,
        )
        self.writers.append(writer)
        primary = None
        try:
            if writer.get_extra_info("ssl_object").selected_alpn_protocol() != "h2":
                raise AssertionError("startup peer did not negotiate H2")

            client = h2.connection.H2Connection(
                h2.config.H2Configuration(client_side=True, header_encoding=None)
            )
            client.initiate_connection()
            client.send_headers(
                1,
                [
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", f"{race.HOSTNAME}:{server.origin.port}".encode()),
                    (b":path", path.encode()),
                ],
                end_stream=True,
            )
            writer.write(client.data_to_send())
            await asyncio.wait_for(writer.drain(), DEADLINE)
            status = None
            body = bytearray()
            ended = False
            while not ended:
                data = await asyncio.wait_for(reader.read(65536), DEADLINE)
                if not data:
                    raise EOFError("startup H2 response ended before END_STREAM")
                for event in client.receive_data(data):
                    if isinstance(event, h2.events.ResponseReceived):
                        status = dict(event.headers)[b":status"]
                    elif isinstance(event, h2.events.DataReceived):
                        body.extend(event.data)
                        client.acknowledge_received_data(
                            event.flow_controlled_length, event.stream_id
                        )
                    elif isinstance(event, h2.events.StreamEnded):
                        ended = True
                writer.write(client.data_to_send())
                await asyncio.wait_for(writer.drain(), DEADLINE)

            result = (path, status, bytes(body))
            self.h2_exchanges.append(result)
            return result
        except BaseException as error:
            primary = error
            raise
        finally:
            try:
                writer.close()
                with suppress(
                    ConnectionResetError, ConnectionAbortedError, BrokenPipeError
                ):
                    await asyncio.wait_for(writer.wait_closed(), DEADLINE)
            except BaseException as cleanup:
                if primary is not None:
                    raise primary from cleanup
                raise

    def install(self):
        resources = self

        def observe_datagram(protocol, data, address):
            resources.datagram(protocol, data, address)

        class ObservedUdp(ORIGINAL_UDP):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                resources.udp.append(self)
                if (
                    resources.case == "construction"
                    and self.recorder.listener == "earlier-1"
                ):
                    raise resources.primary

            async def start(self, sock):
                await super().start(sock)

                await resources.udp_exchange(self)
                name = self.recorder.listener
                if resources.case == "origin-start" and name == "origin":
                    raise resources.primary
                if resources.case == "later-start" and name == "earlier-0":
                    raise resources.primary
                if resources.case == "cancel-start" and name == "earlier-0":
                    resources.entered.set()
                    try:
                        await resources.release.wait()
                    except asyncio.CancelledError as error:
                        resources.cancelled = error
                        raise

            def close(self):
                resources.cleanup_calls.append(self.recorder.listener)
                if (
                    resources.case in {"cleanup", "combined"}
                    and self.recorder.listener == "origin"
                ):
                    raise resources.cleanup
                super().close()

        class ObservedTcp(ORIGINAL_TCP):
            def __init__(self, origin, certificate):
                super().__init__(origin, certificate)
                self.certificate = certificate
                resources.tcp.append(self)

            async def start(self, sock):
                await super().start(sock)

                result = await resources.h2_exchange(self, "/r/startup")
                if result != ("/r/startup", b"200", b"ok"):
                    raise AssertionError(
                        "TCP startup did not serve the literal response"
                    )
                if resources.case == "tcp-start":
                    raise resources.primary

            async def handle(self, reader, writer):
                resources.handlers.append(asyncio.current_task())
                await super().handle(reader, writer)

            async def close(self):
                resources.cleanup_calls.append("tcp")
                await super().close()

        class ControlledDriver:
            browser = None

            def __init__(self, plan, url):
                self.plan = plan
                self.url = url

            async def __aenter__(self):
                if resources.case == "combined":
                    raise resources.primary

                result = await resources.h2_exchange(
                    resources.tcp[0], "/done?results=%5B%5D"
                )
                if result != ("/done?results=%5B%5D", b"204", b""):
                    raise AssertionError(
                        "controlled driver did not finish the actual page route"
                    )

                return self

            async def __aexit__(self, *details):
                return None

        self.stack.enter_context(patch.object(race, "reserve_ports", self.reserve))
        self.stack.enter_context(patch.object(race, "bind_udp", self.bind))
        self.stack.enter_context(patch.object(race, "UdpAlternative", ObservedUdp))
        self.stack.enter_context(patch.object(race, "Http2Origin", ObservedTcp))
        self.stack.enter_context(
            patch.object(race.BlackholeProtocol, "datagram_received", observe_datagram)
        )
        self.stack.enter_context(patch.object(race, "BrowserDriver", ControlledDriver))

    def closed(self):
        return (
            all(sock.fileno() == -1 for sock in self.sockets)
            and all(
                udp.transport is None or udp.transport.is_closing() for udp in self.udp
            )
            and all(
                tcp.server is None or not tcp.server.is_serving() for tcp in self.tcp
            )
        )

    async def closed_before_backup(self):
        # Observe asynchronous close completion; this timer is not readiness.
        completed = self.loop.create_future()
        scheduled = None

        def inspect():
            nonlocal scheduled
            if self.closed():
                if not completed.done():
                    completed.set_result(True)
            else:
                scheduled = self.loop.call_later(0.001, inspect)

        inspect()
        try:
            await asyncio.wait_for(completed, 0.2)
        except asyncio.TimeoutError:
            return False
        finally:
            if scheduled is not None:
                scheduled.cancel()

        return True

    async def backup(self):
        self.release.set()
        errors = []
        if self.capture is not None:
            requested_abort = not self.capture.done()
            if requested_abort:
                self.capture.cancel()
            try:
                await asyncio.wait_for(self.capture, DEADLINE)
            except asyncio.CancelledError as error:
                if not requested_abort and self.cancelled is None:
                    errors.append(error)
            except BaseException as error:
                if error is not self.primary and error is not self.cleanup:
                    errors.append(error)
        for udp in self.udp:
            try:
                ORIGINAL_UDP.close(udp)
            except BaseException as error:
                errors.append(error)
        for tcp in self.tcp:
            try:
                await asyncio.wait_for(ORIGINAL_TCP.close(tcp), DEADLINE)
            except BaseException as error:
                errors.append(error)
        for writer in self.writers:
            try:
                writer.transport.abort()
            except BaseException as error:
                errors.append(error)
        for sock in (*self.sockets, *self.senders):
            try:
                sock.close()
            except BaseException as error:
                errors.append(error)
        for handler in self.handlers:
            if not handler.done():
                handler.cancel()
        for handler in self.handlers:
            try:
                await asyncio.wait_for(handler, DEADLINE)
            except asyncio.CancelledError:
                pass
            except BaseException as error:
                errors.append(error)
        self.stack.close()
        self.loop.set_exception_handler(self.previous_handler)
        if errors:
            raise AssertionError(
                f"independent resource backup failed: {errors!r}"
            ) from errors[0]

    async def capture_run(self):
        scenario = race.Scenario(
            "startup", "startup ownership", "blackhole", (), ("blackhole", "blackhole")
        )
        try:
            return await race.capture_run(
                scenario,
                listen_host=HOST,
                browser="chrome",
                executable=None,
                headless=True,
                netlog=Path("controlled-startup-netlog.json"),
                timeout=DEADLINE,
            )
        except BaseException as error:
            self.outcome = error
            raise


class CaptureStartupTests(unittest.IsolatedAsyncioTestCase):
    async def run_fault(self, case):
        resources = CaptureResources(case)
        self.addAsyncCleanup(resources.backup)
        resources.install()
        observed = None
        try:
            resources.capture = asyncio.create_task(resources.capture_run())
            await asyncio.wait_for(resources.capture, 15)
        except BaseException as error:
            observed = error
        closed = await resources.closed_before_backup()
        return resources, observed, closed

    async def test_healthy_capture_closes_actual_blackhole_and_h2_listeners(self):
        resources = CaptureResources("healthy")
        self.addAsyncCleanup(resources.backup)
        resources.install()

        resources.capture = asyncio.create_task(resources.capture_run())
        result = await asyncio.wait_for(resources.capture, 15)
        closed = await resources.closed_before_backup()

        self.assertEqual(
            resources.h2_exchanges,
            [("/r/startup", b"200", b"ok"), ("/done?results=%5B%5D", b"204", b"")],
        )
        self.assertEqual(result.run.page_results, [])
        self.assertTrue(result.run.done.is_set())
        self.assertEqual(
            resources.received,
            {name: [DATAGRAM] for name in ("origin", "earlier-0", "earlier-1")},
        )
        self.assertTrue(closed, "healthy capture left acquired listener resources open")

    async def test_later_udp_bind_failure_closes_the_earlier_reservations(self):
        resources, observed, closed = await self.run_fault("second-bind")

        self.assertIs(observed, resources.primary)
        self.assertEqual(resources.binds, 2)
        self.assertEqual(len(resources.sockets), 3)
        self.assertTrue(closed, "later bind failure abandoned earlier actual sockets")

    async def test_owner_construction_failure_closes_all_acquired_sockets(self):
        resources, observed, closed = await self.run_fault("construction")

        self.assertIs(observed, resources.primary)
        self.assertEqual(len(resources.udp), 3)
        self.assertEqual(len(resources.sockets), 4)
        self.assertTrue(closed, "owner construction failure abandoned actual sockets")

    async def test_origin_start_failure_closes_the_transferred_datagram_socket(self):
        resources, observed, closed = await self.run_fault("origin-start")

        self.assertIs(observed, resources.primary)
        self.assertEqual(resources.received, {"origin": [DATAGRAM]})
        self.assertIsNotNone(resources.udp[0].transport)
        self.assertTrue(closed, "origin startup failure abandoned its actual transport")

    async def test_later_alternative_start_failure_closes_both_started_transports(self):
        resources, observed, closed = await self.run_fault("later-start")

        self.assertIs(observed, resources.primary)
        self.assertEqual(
            resources.received, {"origin": [DATAGRAM], "earlier-0": [DATAGRAM]}
        )

        self.assertTrue(
            closed, "later startup failure abandoned earlier actual transports"
        )

    async def test_tcp_start_failure_closes_the_actual_h2_listener(self):
        resources, observed, closed = await self.run_fault("tcp-start")

        self.assertIs(observed, resources.primary)
        self.assertEqual(resources.h2_exchanges, [("/r/startup", b"200", b"ok")])
        self.assertIsNotNone(resources.tcp[0].server)
        self.assertTrue(closed, "TCP startup failure abandoned its actual server")

    async def test_startup_cancellation_keeps_its_identity_and_closes_transferred_sockets(
        self,
    ):
        resources = CaptureResources("cancel-start")
        self.addAsyncCleanup(resources.backup)
        resources.install()
        resources.capture = asyncio.create_task(resources.capture_run())
        await asyncio.wait_for(resources.entered.wait(), DEADLINE)
        self.assertEqual(
            resources.received, {"origin": [DATAGRAM], "earlier-0": [DATAGRAM]}
        )
        resources.capture.cancel()
        observed = None
        try:
            await asyncio.wait_for(resources.capture, DEADLINE)
        except asyncio.CancelledError as error:
            observed = error
        closed = await resources.closed_before_backup()

        self.assertIsNotNone(resources.cancelled)
        self.assertIsInstance(observed, asyncio.CancelledError)
        self.assertIs(resources.outcome, resources.cancelled)
        self.assertTrue(
            closed, "startup cancellation abandoned acquired sockets/transports"
        )

    async def test_failed_first_cleanup_still_closes_later_udp_and_tcp_owners(self):
        resources, observed, _ = await self.run_fault("cleanup")
        later_closed = all(
            udp.transport.is_closing() for udp in resources.udp[1:]
        ) and all(sock.fileno() == -1 for sock in resources.sockets[2:])
        tcp_closed = (
            not resources.tcp[0].server.is_serving()
            and resources.sockets[1].fileno() == -1
        )

        self.assertIs(observed, resources.cleanup)
        self.assertEqual(
            resources.h2_exchanges[-1], ("/done?results=%5B%5D", b"204", b"")
        )
        self.assertTrue(
            later_closed and tcp_closed,
            "first cleanup failure skipped acquired sibling owners",
        )

    async def test_primary_startup_failure_retains_the_independent_cleanup_cause(self):
        resources, observed, _ = await self.run_fault("combined")

        self.assertEqual(resources.h2_exchanges, [("/r/startup", b"200", b"ok")])
        self.assertIn("origin", resources.cleanup_calls)
        self.assertIs(
            observed, resources.primary, "cleanup replaced the original startup failure"
        )
        self.assertTrue(
            contains_identity(observed, resources.cleanup),
            "primary failure discarded its actual cleanup cause",
        )
