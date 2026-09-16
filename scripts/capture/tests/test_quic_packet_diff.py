import json
import unittest

from aioquic.quic.crypto import CryptoContext, CryptoPair
from aioquic.quic.packet import (
    QuicPacketType,
    QuicProtocolVersion,
    encode_long_header_first_byte,
)
from aioquic.tls import CipherSuite

from scripts.capture.http3_wire import push_varint
from scripts.capture.quic_packet_diff import QuicPacketCapture
from scripts.capture.quic_summary import (
    FrameKind,
    NormalizedPacket,
    StreamFrame,
    SymbolicSpan,
)

VERSION = QuicProtocolVersion.VERSION_1
CIPHER_SUITE = CipherSuite.AES_128_GCM_SHA256
DESTINATION_CID = bytes.fromhex("8394c8f03e515708")
SOURCE_CID = bytes.fromhex("f067a5502a4262b5")
CLIENT_RANDOM = bytes(range(32))
HANDSHAKE_SECRET = bytes(range(32, 64))
APPLICATION_SECRET = bytes(range(64, 96))


def key_log_line(label: str, secret: bytes) -> str:
    return f"{label} {CLIENT_RANDOM.hex()} {secret.hex()}\n"


def crypto_frame(data: bytes, offset: int = 0) -> bytes:
    return b"\x06" + push_varint(offset, 1) + push_varint(len(data), 1) + data


def stream_frame(
    stream_id: int, data: bytes, *, offset: int = 0, fin: bool = False
) -> bytes:
    frame_type = 0x0A | int(fin)
    if offset:
        frame_type |= 0x04
    encoded = bytes([frame_type]) + push_varint(stream_id, 1)
    if offset:
        encoded += push_varint(offset, 1)
    return encoded + push_varint(len(data), 1) + data


def long_packet(
    packet_type: QuicPacketType,
    payload: bytes,
    packet_number: int,
    crypto: CryptoContext,
    *,
    destination_cid: bytes = DESTINATION_CID,
) -> bytes:
    first_byte = encode_long_header_first_byte(VERSION, packet_type, 0)
    prefix = (
        bytes([first_byte])
        + int(VERSION).to_bytes(4, "big")
        + bytes([len(destination_cid)])
        + destination_cid
        + bytes([len(SOURCE_CID)])
        + SOURCE_CID
    )
    if packet_type == QuicPacketType.INITIAL:
        prefix += b"\x00"
    protected_length = 1 + len(payload) + 16
    header = prefix + push_varint(protected_length, 2) + bytes([packet_number])
    return crypto.encrypt_packet(header, payload, packet_number)


def short_packet(payload: bytes, packet_number: int, crypto: CryptoContext) -> bytes:
    header = b"\x40" + DESTINATION_CID + bytes([packet_number])
    return crypto.encrypt_packet(header, payload, packet_number)


def client_initial_crypto() -> CryptoPair:
    crypto = CryptoPair()
    crypto.setup_initial(cid=DESTINATION_CID, is_client=True, version=VERSION)
    return crypto


def client_traffic_crypto(secret: bytes) -> CryptoContext:
    crypto = CryptoContext()
    crypto.setup(cipher_suite=CIPHER_SUITE, secret=secret, version=VERSION)
    return crypto


class QuicPacketDiffTests(unittest.TestCase):
    def test_authenticates_initial_and_normalizes_frame_kinds(self) -> None:
        crypto = client_initial_crypto()
        try:
            packet = long_packet(
                QuicPacketType.INITIAL,
                b"\x01" + crypto_frame(b"client hello") + b"\x00\x00",
                0,
                crypto.send,
            )
        finally:
            crypto.teardown()

        capture = QuicPacketCapture()
        capture.add_datagram(packet)
        summary = capture.summarize(
            cipher_suite=CIPHER_SUITE,
            short_header_cid_length=len(DESTINATION_CID),
        )

        self.assertEqual(
            summary.packets,
            (
                NormalizedPacket(
                    "initial",
                    (FrameKind("ping"), FrameKind("crypto"), FrameKind("padding")),
                ),
            ),
        )
        self.assertEqual(capture.buffered_datagram_count, 0)
        self.assertEqual(capture.buffered_secret_count, 0)

    def test_reuses_original_initial_keys_after_destination_cid_changes(self) -> None:
        crypto = client_initial_crypto()
        try:
            first = long_packet(
                QuicPacketType.INITIAL,
                crypto_frame(b"client hello"),
                0,
                crypto.send,
            )
            retransmission = long_packet(
                QuicPacketType.INITIAL,
                crypto_frame(b"client hello", offset=12),
                1,
                crypto.send,
                destination_cid=bytes.fromhex("0102030405060708"),
            )
        finally:
            crypto.teardown()

        capture = QuicPacketCapture()
        capture.add_datagram(first)
        capture.add_datagram(retransmission)
        summary = capture.summarize(
            cipher_suite=CIPHER_SUITE,
            short_header_cid_length=len(DESTINATION_CID),
        )

        self.assertEqual(
            summary.packets,
            (
                NormalizedPacket("initial", (FrameKind("crypto"),)),
                NormalizedPacket("initial", (FrameKind("crypto"),)),
            ),
        )

    def test_decrypts_coalesced_handshake_and_later_one_rtt_streams(self) -> None:
        initial = client_initial_crypto()
        handshake = client_traffic_crypto(HANDSHAKE_SECRET)
        application = client_traffic_crypto(APPLICATION_SECRET)
        try:
            initial_packet = long_packet(
                QuicPacketType.INITIAL,
                crypto_frame(b"initial"),
                0,
                initial.send,
            )
            handshake_packet = long_packet(
                QuicPacketType.HANDSHAKE,
                b"\x01" + crypto_frame(b"finished"),
                0,
                handshake,
            )
            application_packet = short_packet(
                stream_frame(2, b"settings!!")
                + stream_frame(0, b"head", fin=True)
                + b"\x01",
                0,
                application,
            )
        finally:
            initial.teardown()
            handshake.teardown()
            application.teardown()

        capture = QuicPacketCapture()
        capture.write(key_log_line("CLIENT_HANDSHAKE_TRAFFIC_SECRET", HANDSHAKE_SECRET))
        capture.write(key_log_line("CLIENT_TRAFFIC_SECRET_0", APPLICATION_SECRET))
        capture.add_datagram(initial_packet + handshake_packet)
        capture.add_datagram(application_packet)
        summary = capture.summarize(
            cipher_suite=CIPHER_SUITE,
            short_header_cid_length=len(DESTINATION_CID),
            spans=(
                SymbolicSpan("control_settings_prefix", 2, 0, 4),
                SymbolicSpan("request_headers", 0, 0, 4),
            ),
        )

        self.assertEqual(
            [packet.space for packet in summary.packets],
            [
                "initial",
                "handshake",
                "1rtt",
            ],
        )
        self.assertEqual(
            summary.packets[2].frames,
            (
                StreamFrame("stream", 2, 0, 10, False, ("control_settings_prefix",)),
                StreamFrame("stream", 0, 0, 4, True, ("request_headers",)),
                FrameKind("ping"),
            ),
        )

    def test_summary_serialization_contains_no_payload_or_secret_fields(self) -> None:
        crypto = client_initial_crypto()
        try:
            packet = long_packet(
                QuicPacketType.INITIAL,
                crypto_frame(b"do not serialize me"),
                0,
                crypto.send,
            )
        finally:
            crypto.teardown()
        capture = QuicPacketCapture()
        capture.add_datagram(packet)
        encoded = json.dumps(
            capture.summarize(
                cipher_suite=CIPHER_SUITE,
                short_header_cid_length=len(DESTINATION_CID),
            ).as_dict(),
            sort_keys=True,
        )

        self.assertNotIn("do not serialize me", encoded)
        for forbidden in ("secret", "keylog", "payload", "ciphertext"):
            self.assertNotIn(forbidden, encoded.lower())

    def test_rejects_sensitive_or_material_bearing_span_labels(self) -> None:
        for label in (
            "request_payload",
            "traffic_secret",
            "authorization",
            "cookie",
            "proxy_authorization",
        ):
            with self.subTest(label=label), self.assertRaises(ValueError):
                SymbolicSpan(label, 0, 0, 1)

    def test_finish_datagrams_freezes_boundary_without_closing_key_log(self) -> None:
        crypto = client_initial_crypto()
        try:
            packet = long_packet(
                QuicPacketType.INITIAL,
                crypto_frame(b"client hello"),
                0,
                crypto.send,
            )
        finally:
            crypto.teardown()

        capture = QuicPacketCapture()
        capture.add_datagram(packet)
        capture.finish_datagrams()
        capture.add_datagram(b"ignored after request boundary")
        capture.write(key_log_line("CLIENT_HANDSHAKE_TRAFFIC_SECRET", HANDSHAKE_SECRET))
        summary = capture.summarize(
            cipher_suite=CIPHER_SUITE,
            short_header_cid_length=len(DESTINATION_CID),
        )

        self.assertEqual(len(summary.packets), 1)

    def test_rejects_wrong_secret_and_clears_capture(self) -> None:
        initial = client_initial_crypto()
        handshake = client_traffic_crypto(HANDSHAKE_SECRET)
        try:
            initial_packet = long_packet(
                QuicPacketType.INITIAL, crypto_frame(b"initial"), 0, initial.send
            )
            handshake_packet = long_packet(
                QuicPacketType.HANDSHAKE,
                crypto_frame(b"finished"),
                0,
                handshake,
            )
        finally:
            initial.teardown()
            handshake.teardown()

        capture = QuicPacketCapture()
        capture.write(
            key_log_line("CLIENT_HANDSHAKE_TRAFFIC_SECRET", bytes([0xFF]) * 32)
        )
        capture.add_datagram(initial_packet + handshake_packet)
        with self.assertRaisesRegex(ValueError, "authenticate or decode"):
            capture.summarize(
                cipher_suite=CIPHER_SUITE,
                short_header_cid_length=len(DESTINATION_CID),
            )
        self.assertEqual(capture.buffered_datagram_count, 0)
        self.assertEqual(capture.buffered_secret_count, 0)
        with self.assertRaises(RuntimeError):
            capture.add_datagram(b"later")

    def test_rejects_malformed_and_duplicate_key_log_lines(self) -> None:
        malformed = QuicPacketCapture()
        with self.assertRaisesRegex(ValueError, "invalid NSS key-log line"):
            malformed.write("CLIENT_TRAFFIC_SECRET_0 broken\n")
        self.assertEqual(malformed.buffered_secret_count, 0)

        wrong_length = QuicPacketCapture()
        with self.assertRaisesRegex(ValueError, "field length"):
            wrong_length.write(key_log_line("CLIENT_TRAFFIC_SECRET_0", b"too short"))
        self.assertEqual(wrong_length.buffered_secret_count, 0)

        duplicate = QuicPacketCapture()
        line = key_log_line("CLIENT_TRAFFIC_SECRET_0", APPLICATION_SECRET)
        duplicate.write(line)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            duplicate.write(line)
        self.assertEqual(duplicate.buffered_secret_count, 0)

    def test_enforces_datagram_count_and_byte_bounds(self) -> None:
        count = QuicPacketCapture(max_datagrams=1)
        count.add_datagram(b"one")
        with self.assertRaisesRegex(ValueError, "count"):
            count.add_datagram(b"two")
        self.assertEqual(count.buffered_datagram_count, 0)

        size = QuicPacketCapture(max_datagram_bytes=3)
        with self.assertRaisesRegex(ValueError, "bytes"):
            size.add_datagram(b"four")
        self.assertEqual(size.buffered_datagram_count, 0)

    def test_enforces_key_log_count_and_size_bounds(self) -> None:
        count = QuicPacketCapture(max_key_log_lines=1)
        count.write(key_log_line("SERVER_TRAFFIC_SECRET_0", APPLICATION_SECRET))
        with self.assertRaisesRegex(ValueError, "line count"):
            count.write(key_log_line("CLIENT_TRAFFIC_SECRET_0", APPLICATION_SECRET))

        size = QuicPacketCapture(max_key_log_chars=3)
        with self.assertRaisesRegex(ValueError, "text"):
            size.write("four")

    def test_rejects_unsupported_frame_and_clears_capture(self) -> None:
        crypto = client_initial_crypto()
        try:
            packet = long_packet(
                QuicPacketType.INITIAL,
                push_varint(63, 1) + b"\x00\x00\x00",
                0,
                crypto.send,
            )
        finally:
            crypto.teardown()
        capture = QuicPacketCapture()
        capture.add_datagram(packet)
        with self.assertRaisesRegex(ValueError, "unsupported QUIC frame"):
            capture.summarize(
                cipher_suite=CIPHER_SUITE,
                short_header_cid_length=len(DESTINATION_CID),
            )
        self.assertEqual(capture.buffered_datagram_count, 0)


if __name__ == "__main__":
    unittest.main()
