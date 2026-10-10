"""Allocation failures retain actual paired or standalone loopback sockets."""

import errno
import socket
import unittest
from unittest.mock import patch

from scripts.capture import alt_svc_race as race

HOST = "127.0.0.1"
DATAGRAM = b"socket-allocation-literal-datagram"
NATIVE_SOCKET = socket.socket
NATIVE_RESERVE = race.reserve_ports


class SocketResources:
    def __init__(self, case):
        self.case = case
        self.failure = OSError(errno.EIO, f"controlled allocation: {case}")
        self.sockets = []
        self.calls = 0
        self.witness = None
        self.patcher = None

    def install(self):
        resources = self

        class ObservedSocket(NATIVE_SOCKET):
            def listen(self, backlog):
                super().listen(backlog)
                if resources.case == "reserve-listen":
                    resources.observe(self)
                    raise resources.failure

            def setblocking(self, blocking):
                super().setblocking(blocking)
                if blocking:
                    return

                if self.type == socket.SOCK_STREAM:
                    stage = "reserve-tcp-block"
                elif resources.case.startswith("reserve-"):
                    stage = "reserve-udp-block"
                else:
                    stage = "bind-udp-block"

                if resources.case == stage:
                    resources.observe(self)
                    raise resources.failure

        def create(*args, **kwargs):
            resources.calls += 1
            if resources.case == "reserve-second-create" and resources.calls == 2:
                resources.observe(resources.sockets[0])
                raise resources.failure

            sock = ObservedSocket(*args, **kwargs)
            resources.sockets.append(sock)
            return sock

        self.patcher = patch.object(race.socket, "socket", create)
        self.patcher.start()

    def observe(self, target):
        sockets = [
            {
                "fd": sock.fileno(),
                "type": sock.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE),
                "address": sock.getsockname(),
                "accepting": sock.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN),
                "blocking": sock.getblocking(),
            }
            for sock in self.sockets
        ]
        marker = None
        if self.case in {"reserve-udp-block", "bind-udp-block"}:
            if target.sendto(DATAGRAM, target.getsockname()) != len(DATAGRAM):
                raise AssertionError("allocation datagram was not sent")

            target.settimeout(5)
            try:
                marker, _ = target.recvfrom(256)
            finally:
                NATIVE_SOCKET.setblocking(target, False)

            if marker != DATAGRAM:
                raise AssertionError("allocated socket did not receive its datagram")

        self.witness = {"sockets": sockets, "marker": marker}

    def backup(self):
        errors = []
        try:
            for sock in self.sockets:
                try:
                    NATIVE_SOCKET.close(sock)
                except BaseException as error:
                    errors.append(error)
        finally:
            if self.patcher is not None:
                self.patcher.stop()

        if errors:
            raise AssertionError("native socket backup failed") from errors[0]


class SocketAllocationTests(unittest.IsolatedAsyncioTestCase):
    def resources(self, case):
        resources = SocketResources(case)
        self.addCleanup(resources.backup)
        resources.install()
        return resources

    def candidate(self):
        udp, tcp = NATIVE_RESERVE(HOST)
        try:
            self.assertEqual(udp.getsockname(), tcp.getsockname())
            return udp.getsockname()[1]
        finally:
            udp.close()
            tcp.close()

    def assert_pair_witness(self, resources, expected_blocking):
        witness = resources.witness
        self.assertIsNotNone(witness)
        self.assertEqual(len(witness["sockets"]), 2)
        udp, tcp = witness["sockets"]
        self.assertGreaterEqual(udp["fd"], 0)
        self.assertGreaterEqual(tcp["fd"], 0)
        self.assertEqual(
            (udp["type"], tcp["type"]), (socket.SOCK_DGRAM, socket.SOCK_STREAM)
        )
        self.assertEqual(udp["address"], tcp["address"])
        self.assertEqual(udp["address"][0], HOST)
        self.assertGreater(udp["address"][1], 0)
        self.assertEqual(tcp["accepting"], 1)
        self.assertEqual((udp["blocking"], tcp["blocking"]), expected_blocking)

    async def test_healthy_allocation_returns_live_paired_and_standalone_sockets(self):
        port = self.candidate()
        resources = self.resources("healthy")
        udp, tcp = race.reserve_ports(HOST, [port])
        standalone = await race.bind_udp(HOST)

        self.assertEqual(resources.sockets, [udp, tcp, standalone])
        self.assertEqual(udp.getsockname(), tcp.getsockname())
        self.assertEqual(tcp.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN), 1)
        self.assertTrue(all(sock.fileno() >= 0 for sock in resources.sockets))
        self.assertTrue(all(not sock.getblocking() for sock in resources.sockets))

        standalone.sendto(DATAGRAM, standalone.getsockname())
        standalone.settimeout(5)
        try:
            received, _ = standalone.recvfrom(256)
        finally:
            NATIVE_SOCKET.setblocking(standalone, False)
        self.assertEqual(received, DATAGRAM)

    async def test_second_socket_creation_failure_closes_the_actual_first_socket(self):
        port = self.candidate()
        resources = self.resources("reserve-second-create")
        with self.assertRaises(OSError) as raised:
            race.reserve_ports(HOST, [port])

        self.assertIs(raised.exception, resources.failure)
        self.assertEqual(resources.calls, 2)
        self.assertEqual(len(resources.witness["sockets"]), 1)
        witness = resources.witness["sockets"][0]
        self.assertGreaterEqual(witness["fd"], 0)
        self.assertEqual(witness["type"], socket.SOCK_DGRAM)
        self.assertEqual(len(resources.sockets), 1)
        self.assertEqual(
            resources.sockets[0].fileno(),
            -1,
            "second construction failure left its actual first socket open",
        )

    async def test_listen_failure_closes_both_actual_bound_sockets(self):
        port = self.candidate()
        resources = self.resources("reserve-listen")
        with self.assertRaises(OSError) as raised:
            race.reserve_ports(HOST, [port])

        self.assertIs(raised.exception, resources.failure)
        self.assert_pair_witness(resources, (True, True))
        self.assertTrue(
            all(sock.fileno() == -1 for sock in resources.sockets),
            "listen failure left actual paired sockets open",
        )

    async def test_tcp_nonblocking_failure_closes_both_actual_bound_sockets(self):
        port = self.candidate()
        resources = self.resources("reserve-tcp-block")
        with self.assertRaises(OSError) as raised:
            race.reserve_ports(HOST, [port])

        self.assertIs(raised.exception, resources.failure)
        self.assert_pair_witness(resources, (True, False))
        self.assertTrue(
            all(sock.fileno() == -1 for sock in resources.sockets),
            "TCP setup failure left actual paired sockets open",
        )

    async def test_udp_nonblocking_failure_closes_both_actual_bound_sockets(self):
        port = self.candidate()
        resources = self.resources("reserve-udp-block")
        with self.assertRaises(OSError) as raised:
            race.reserve_ports(HOST, [port])

        self.assertIs(raised.exception, resources.failure)
        self.assert_pair_witness(resources, (False, False))
        self.assertEqual(resources.witness["marker"], DATAGRAM)
        self.assertTrue(
            all(sock.fileno() == -1 for sock in resources.sockets),
            "UDP setup failure left actual paired sockets open",
        )

    async def test_standalone_nonblocking_failure_closes_the_actual_bound_udp_socket(
        self,
    ):
        resources = self.resources("bind-udp-block")
        with self.assertRaises(OSError) as raised:
            await race.bind_udp(HOST)

        self.assertIs(raised.exception, resources.failure)
        self.assertEqual(len(resources.witness["sockets"]), 1)
        witness = resources.witness["sockets"][0]
        self.assertEqual(witness["address"][0], HOST)
        self.assertGreater(witness["address"][1], 0)
        self.assertGreaterEqual(witness["fd"], 0)
        self.assertEqual(resources.witness["marker"], DATAGRAM)
        self.assertEqual(
            resources.sockets[0].fileno(),
            -1,
            "standalone setup failure left its actual UDP socket open",
        )
