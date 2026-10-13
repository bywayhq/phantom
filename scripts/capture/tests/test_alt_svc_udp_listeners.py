import unittest
from types import SimpleNamespace

from scripts.capture.alt_svc_race import (
    HOSTNAME,
    SCENARIOS,
    BlackholeProtocol,
    Origin,
    UdpAlternative,
    generate_certificate,
    new_run,
    udp_listeners,
)


class UdpListenerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.origin = Origin(SCENARIOS["two-alternatives"], 20001, [20002])
        self.run = new_run()
        self.origin.begin(self.run)
        self.address = ("127.0.0.1", 31001)
        certificate = generate_certificate(HOSTNAME)
        self.earlier_owner = UdpAlternative(
            self.origin, certificate, "blackhole", "earlier-0"
        )
        self.current_owner = UdpAlternative(self.origin, certificate, "blackhole")
        self.earlier = self.earlier_owner.recorder
        self.current = self.current_owner.recorder

    def test_reused_source_address_keeps_each_listeners_datagrams(self) -> None:
        earlier = BlackholeProtocol(self.earlier, self.earlier_owner)
        current = BlackholeProtocol(self.current, self.current_owner)

        earlier.datagram_received(b"first", self.address)
        current.datagram_received(b"second", self.address)
        earlier.datagram_received(b"third", self.address)

        self.assertEqual(
            udp_listeners(self.run),
            (("earlier-0", 1, 2, 0), ("origin", 1, 1, 0)),
        )

    def test_peer_lookup_uses_its_own_listener_and_does_not_create_records(
        self,
    ) -> None:
        quic = SimpleNamespace(_network_paths=[SimpleNamespace(addr=self.address)])
        self.earlier.datagram(self.address)

        self.assertIsNone(self.current.peer_for(quic))
        earlier = self.earlier.peer_for(quic)
        self.assertIsNotNone(earlier)
        self.assertEqual(earlier.listener, "earlier-0")

        self.current.datagram(self.address)
        current = self.current.peer_for(quic)
        self.assertIsNotNone(current)
        self.assertIsNot(current, earlier)
        self.assertEqual(current.listener, "origin")
        self.assertNotEqual(current.index, earlier.index)
        self.assertIs(self.current.peer_for(quic), current)
        self.assertEqual(len(self.run.udp), 2)
