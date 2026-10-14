import unittest

from aioquic.buffer import Buffer
from aioquic.h3.exceptions import InvalidStreamTypeError
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection, QuicConnectionError
from aioquic.quic.packet import (
    QuicFrameType,
    QuicPacketType,
    QuicTransportParameters,
    push_quic_transport_parameters,
)
from aioquic.quic.packet_builder import QuicPacketBuilder, QuicPacketBuilderStop
from aioquic.tls import Epoch

from scripts.conformance.connect_udp_peer import (
    MAX_OUTER_PACKET,
    MAX_UDP,
    Capsules,
    DatagramH3,
    H3Relay,
    datagram_fits,
    decode,
    target,
    varint,
)


class CapsuleTests(unittest.TestCase):
    def test_all_integer_widths_preserve_values(self):
        for value in (0, 63, 64, 16383, 16384, (1 << 30) - 1, 1 << 30, (1 << 62) - 1):
            with self.subTest(value=value):
                encoded = varint(value)
                self.assertEqual(decode(encoded), (value, len(encoded)))
                for prefix in range(len(encoded)):
                    self.assertIsNone(decode(encoded[:prefix]))
        for value in (-1, 1 << 62):
            with self.assertRaises(ValueError):
                varint(value)

    def test_fragmented_capsules_keep_context_zero_order(self):
        parser = Capsules()
        values = [b"one", b"two", b""]
        wire = b"".join(
            b"\x00" + varint(len(value) + 1) + b"\x00" + value for value in values
        )
        decoded = []
        for byte in wire:
            decoded.extend(parser.feed(bytes([byte])))
        self.assertEqual(decoded, values)
        parser.finish()

    def test_unknown_type_and_context_do_not_become_udp_payloads(self):
        parser = Capsules()
        self.assertEqual(
            parser.feed(b"\x2a\x03xyz\x00\x04\x02abc\x00\x04\x00end"), [b"end"]
        )
        parser.finish()

    def test_capsule_bounds_missing_context_and_truncation_are_errors(self):
        for wire in (b"\x00" + varint(MAX_UDP + 9), b"\x00\x00"):
            with self.assertRaises(ValueError):
                Capsules().feed(wire)
        parser = Capsules()
        parser.feed(b"\x00\x04\x00en")
        with self.assertRaises(ValueError):
            parser.finish()
        with self.assertRaises(ValueError):
            Capsules().feed(b"a" * (2 * (MAX_UDP + 16) + 1))

    def test_target_is_explicit_extended_connect_to_loopback(self):
        headers = [
            (b":method", b"CONNECT"),
            (b":protocol", b"connect-udp"),
            (b"capsule-protocol", b"?1"),
            (b":path", b"/.well-known/masque/udp/127.0.0.1/443/"),
        ]
        self.assertEqual(target(headers), ("127.0.0.1", 443))
        for old, replacement in (
            (b"127.0.0.1", b"8.8.8.8"),
            (b"443", b"0"),
            (b"udp/", b"other/"),
        ):
            changed = [(n, v.replace(old, replacement)) for n, v in headers]
            with self.assertRaises(ValueError):
                target(changed)
        with self.assertRaises(ValueError):
            target([(n, v) for n, v in headers if n != b":protocol"])


class DatagramTests(unittest.TestCase):
    def connection(self, packet_size=MAX_OUTER_PACKET, cid_size=8, remote_limit=65536):
        quic = QuicConnection(
            configuration=QuicConfiguration(
                is_client=True, max_datagram_size=packet_size, alpn_protocols=["h3"]
            )
        )
        quic.connect(("127.0.0.1", 443), now=0)
        quic._peer_cid.cid = b"c" * cid_size
        quic._remote_max_datagram_frame_size = remote_limit
        return quic

    def native_write(self, quic, stream, data):
        builder = QuicPacketBuilder(
            host_cid=quic.host_cid,
            peer_cid=quic._peer_cid.cid,
            version=quic._version,
            is_client=True,
            max_datagram_size=quic._max_datagram_size,
        )
        builder.start_packet(QuicPacketType.ONE_RTT, quic._cryptos[Epoch.ONE_RTT])
        quic._write_datagram_frame(
            builder, varint(stream // 4) + data, QuicFrameType.DATAGRAM_WITH_LENGTH
        )

    def test_preflight_matches_native_packet_capacity_at_width_boundaries(self):
        for packet_size in (1200, 1400, MAX_OUTER_PACKET):
            for cid_size in (0, 8, 20):
                for stream in (0, 252, 256, 65532, 65536):
                    quic = self.connection(packet_size, cid_size)
                    for length in range(packet_size - 45, packet_size):
                        data = bytes(length)
                        with self.subTest(
                            packet=packet_size, cid=cid_size, stream=stream, size=length
                        ):
                            try:
                                self.native_write(quic, stream, data)
                                written = True
                            except QuicPacketBuilderStop:
                                written = False
                            self.assertEqual(datagram_fits(quic, stream, data), written)

    def test_actual_1391_byte_http_datagram_fits_the_1472_peer_path(self):
        quic = self.connection()
        http = DatagramH3(quic)
        data = bytes(1391)
        self.assertTrue(http.send_datagram(0, data))
        self.assertEqual(list(quic._datagrams_pending), [b"\x00" + data])
        self.native_write(quic, 0, data)
        old_path = self.connection(packet_size=1400)
        self.assertFalse(datagram_fits(old_path, 0, data))
        with self.assertRaises(QuicPacketBuilderStop):
            self.native_write(old_path, 0, data)

    def test_oversized_datagram_does_not_block_a_following_sibling(self):
        quic = self.connection()
        http = DatagramH3(quic)
        self.assertFalse(http.send_datagram(0, bytes(MAX_OUTER_PACKET)))
        self.assertEqual(list(quic._datagrams_pending), [])
        self.assertTrue(http.send_datagram(4, b"\x00following"))
        self.assertEqual(list(quic._datagrams_pending), [b"\x01\x00following"])
        self.native_write(quic, 4, b"\x00following")

    def test_remote_frame_limit_and_absence_prevent_enqueue(self):
        quic = self.connection(remote_limit=64)
        http = DatagramH3(quic)
        self.assertTrue(http.send_datagram(0, bytes(61)))
        self.assertFalse(http.send_datagram(0, bytes(62)))
        self.assertEqual([len(data) for data in quic._datagrams_pending], [62])
        quic._remote_max_datagram_frame_size = None
        self.assertFalse(http.send_datagram(4, b"small"))
        self.assertEqual([len(data) for data in quic._datagrams_pending], [62])
        with self.assertRaises(InvalidStreamTypeError):
            http.send_datagram(2, b"invalid stream")


class ReceiveLimitTests(unittest.IsolatedAsyncioTestCase):
    def parameters(self, quic, limit):
        buffer = Buffer(capacity=256)
        push_quic_transport_parameters(
            buffer,
            QuicTransportParameters(
                initial_source_connection_id=quic._remote_initial_source_connection_id,
                original_destination_connection_id=quic._original_destination_connection_id,
                max_udp_payload_size=limit,
                max_datagram_frame_size=64,
            ),
        )
        return buffer.data

    async def test_actual_transport_parameters_lower_path_without_bypassing_validation(
        self,
    ):
        quic = QuicConnection(
            configuration=QuicConfiguration(
                is_client=True, max_datagram_size=MAX_OUTER_PACKET
            )
        )
        relay = H3Relay(quic, stats=None, challenge=False)
        quic._parse_transport_parameters(self.parameters(quic, 1200))
        self.assertEqual(quic._max_datagram_size, 1200)
        self.assertEqual(quic._remote_max_datagram_frame_size, 64)
        quic._parse_transport_parameters(self.parameters(quic, 65527))
        self.assertEqual(quic._max_datagram_size, 1200)
        with self.assertRaises(QuicConnectionError):
            quic._parse_transport_parameters(self.parameters(quic, 1199))
        self.assertEqual(quic._max_datagram_size, 1200)
        self.assertEqual(relay.flows, {})


if __name__ == "__main__":
    unittest.main()
