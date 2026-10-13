from __future__ import annotations

import errno
import socket
import threading
import unittest
from contextlib import suppress
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

from aioquic.buffer import Buffer
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.crypto import CryptoPair
from aioquic.quic.packet import QuicPacketType, encode_long_header_first_byte

from scripts.capture import ip_literal_client_hello as capture
from scripts.capture.browser_launch import LaunchPlan
from scripts.capture.ip_literal_client_hello import (
    client_hello_from_initials,
    client_hello_from_records,
    crypto_frames,
    read_varint,
    render_fixture,
    url_host,
)


def record(content_type: int, fragment: bytes) -> bytes:
    return bytes([content_type, 3, 1]) + len(fragment).to_bytes(2, "big") + fragment


def client_initials() -> list[bytes]:
    connection = QuicConnection(
        configuration=QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    )
    connection.connect(("127.0.0.1", 443), now=0.0)
    return [datagram for datagram, _ in connection.datagrams_to_send(now=0.0)]


def initial(
    payload: bytes, *, cid: bytes = b"12345678", version: int = 1, number: int = 0
) -> bytes:
    # Controlled small packets keep native encryption's sample and buffer in bounds.
    payload += bytes(32)
    header = Buffer(capacity=128)
    header.push_uint8(encode_long_header_first_byte(version, QuicPacketType.INITIAL, 0))
    header.push_uint32(version)
    header.push_uint8(len(cid))
    header.push_bytes(cid)
    header.push_uint8(0)
    header.push_uint_var(0)
    header.push_uint_var(len(payload) + 17)
    header.push_uint8(number)
    crypto = CryptoPair()
    try:
        crypto.setup_initial(cid=cid, is_client=True, version=version)
        return crypto.send.encrypt_packet(header.data, payload, number)
    finally:
        crypto.teardown()


class ClientHelloFromRecordsTest(unittest.TestCase):
    def test_joins_a_client_hello_split_across_records(self) -> None:
        hello = b"\x01\x00\x00\x06abcdef"
        data = record(0x16, hello[:5]) + record(0x16, hello[5:])
        self.assertEqual(client_hello_from_records(data), hello)

    def test_waits_for_the_rest_of_a_record_or_message(self) -> None:
        hello = b"\x01\x00\x00\x06abcdef"
        self.assertIsNone(client_hello_from_records(record(0x16, hello)[:-1]))
        self.assertIsNone(client_hello_from_records(record(0x16, hello[:7])))

    def test_skips_records_of_other_content_types(self) -> None:
        hello = b"\x01\x00\x00\x01z"
        data = record(0x14, b"\x01") + record(0x16, hello)
        self.assertEqual(client_hello_from_records(data), hello)

    def test_rejects_oversized_declarations_and_excess_records(self) -> None:
        with self.assertRaisesRegex(ValueError, "byte limit"):
            client_hello_from_records(record(0x16, b"\x01\x01\x00\x00"))
        with self.assertRaisesRegex(ValueError, "record count"):
            client_hello_from_records(record(0x14, b"") * 129)


class ClientHelloFromInitialsTest(unittest.TestCase):
    def test_reads_the_client_hello_of_a_client_initial(self) -> None:
        hello = client_hello_from_initials(client_initials())
        self.assertIsNotNone(hello)
        assert hello is not None
        self.assertEqual(hello[0], 0x01)
        self.assertEqual(len(hello), 4 + int.from_bytes(hello[1:4], "big"))

    def test_keeps_the_first_connection(self) -> None:
        first = client_initials()
        hello = client_hello_from_initials(first)
        self.assertEqual(client_hello_from_initials(first + client_initials()), hello)

    def test_ignores_datagrams_that_are_not_initials(self) -> None:
        self.assertIsNone(client_hello_from_initials([b"\x40\x01\x02"]))

    def test_an_authentication_failure_does_not_select_a_connection(self) -> None:
        invalid = bytearray(initial(b"\x06\x00\x05\x01\x00\x00\x01x", cid=b"bad-cid!"))
        invalid[-1] ^= 1
        valid = client_initials()
        self.assertEqual(
            client_hello_from_initials([bytes(invalid), *valid]),
            client_hello_from_initials(valid),
        )

    def test_matching_overlaps_and_repeated_offsets_keep_all_crypto_bytes(self) -> None:
        hello = b"\x01\x00\x00\x06abcdef"
        payload = (
            b"\x06\x00\x07"
            + hello[:7]
            + b"\x06\x00\x05"
            + hello[:5]
            + b"\x06\x05\x05"
            + hello[5:]
        )
        self.assertEqual(client_hello_from_initials([initial(payload)]), hello)

    def test_conflicting_repeated_offsets_are_rejected(self) -> None:
        payload = b"\x06\x00\x05\x01\x00\x00\x01x\x06\x00\x01\x02"
        with self.assertRaisesRegex(ValueError, "conflicting overlap"):
            client_hello_from_initials([initial(payload)])

    def test_a_version_change_with_the_same_cid_cannot_supply_crypto_bytes(
        self,
    ) -> None:
        first = initial(b"\x06\x00\x06\x01\x00\x00\x06ab")
        other = initial(b"\x06\x00\x01\x02", version=0x6B3343CF)
        tail = initial(b"\x06\x06\x04cdef", number=1)
        self.assertEqual(
            client_hello_from_initials([first, other, tail]),
            b"\x01\x00\x00\x06abcdef",
        )

    def test_oversized_sparse_crypto_offsets_fail_without_reconstruction(self) -> None:
        # Offset 65536 is a four-byte QUIC integer; even one byte exceeds 64 KiB.
        with self.assertRaisesRegex(ValueError, "CRYPTO.*byte limit"):
            client_hello_from_initials([initial(b"\x06\x80\x01\x00\x00\x01x")])

    def test_incomplete_samples_and_oversized_headers_never_enter_native_decryption(
        self,
    ) -> None:
        for token, remainder in ((b"", 17), (bytes(1500), 20)):
            header = Buffer(capacity=2048)
            header.push_uint8(0xC0)
            header.push_uint32(1)
            header.push_uint8(8)
            header.push_bytes(b"12345678")
            header.push_uint8(0)
            header.push_uint_var(len(token))
            header.push_bytes(token)
            header.push_uint_var(remainder)
            packet = header.data + bytes(remainder)
            with (
                self.subTest(token_bytes=len(token), remainder=remainder),
                patch(
                    "aioquic.quic.crypto.CryptoContext.decrypt_packet",
                    side_effect=AssertionError("unsafe native decrypt was entered"),
                ) as decrypt,
                self.assertRaises(ValueError),
            ):
                client_hello_from_initials([packet])
            decrypt.assert_not_called()


class CryptoFramesTest(unittest.TestCase):
    def test_reads_crypto_frames_past_padding_ping_and_ack(self) -> None:
        payload = bytes([0x00, 0x01, 0x02, 5, 0, 0, 3, 0x06, 0x00, 0x02]) + b"hi"
        self.assertEqual(crypto_frames(payload), [(0, b"hi")])

    def test_truncated_integers_crypto_and_ack_extents_are_rejected(self) -> None:
        malformed = (
            b"\x40",
            b"\x06\x00\x02x",
            b"\x02\x01\x00\x00\x02",
            b"\x02\x00\x00\x01\x00\x00\x00",
            b"\x03\x05\x00\x00\x03\x00\x00",
            b"\x02\x00\x00\x40\x81\x00",
        )
        for payload in malformed:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                crypto_frames(payload)

    def test_varint_offsets_cannot_index_outside_the_input(self) -> None:
        for data, offset in ((b"", 0), (b"a", -1), (b"a", 1), (b"\xc0\x00", 0)):
            with self.subTest(data=data, offset=offset), self.assertRaises(ValueError):
                read_varint(data, offset)

    def test_valid_ack_ecn_and_matching_fragment_extents_are_preserved(self) -> None:
        payload = b"\x03\x05\x00\x01\x03\x00\x00\x00\x01\x02\x06\x00\x02hi"
        self.assertEqual(crypto_frames(payload), [(0, b"hi")])


class CaptureOwnershipTest(unittest.TestCase):
    def test_nonfinite_or_nonpositive_deadlines_acquire_nothing(self) -> None:
        plan = LaunchPlan("firefox", Path("unused"), headless=True)
        for value in (float("nan"), float("inf"), -1.0, 0.0):
            for operation in (capture.capture_tcp, capture.capture_quic):
                with (
                    self.subTest(timeout=value, transport=operation.__name__),
                    patch.object(capture, "_Capture") as owner,
                    patch.object(capture, "LaunchedBrowser") as browser,
                    self.assertRaisesRegex(ValueError, "finite and positive"),
                ):
                    operation(plan, "127.0.0.1", socket.AF_INET, value)
                owner.assert_not_called()
                browser.assert_not_called()

    def test_failed_tcp_launch_and_worker_io_collect_the_accepted_connection(
        self,
    ) -> None:
        def observe(worker_failure: bool) -> None:
            owner = capture._Capture()
            entered = threading.Event()
            second_read = threading.Event()
            primary = OSError(errno.EACCES, "browser launch failed")
            io_failure = OSError(errno.EIO, "accepted socket read failed")
            cleanup = OSError(errno.EIO, "browser cleanup failed")
            started = []
            peers = []
            native_start = threading.Thread.start
            native_read = capture.read_client_hello
            reads = []

            def start(thread: threading.Thread) -> None:
                started.append(thread)
                native_start(thread)

            class FailedRead:
                def __init__(self, connection: socket.socket) -> None:
                    self.connection = connection

                def settimeout(self, timeout: float) -> None:
                    self.connection.settimeout(timeout)

                def recv(self, _: int) -> bytes:
                    second_read.set()
                    raise io_failure

            def read(connection: socket.socket, stop: threading.Event) -> bytes | None:
                entered.set()
                reads.append(connection)
                failed = worker_failure and len(reads) == 2
                return native_read(
                    FailedRead(connection) if failed else connection, stop
                )

            class Browser:
                def __init__(self, _: LaunchPlan, url: str) -> None:
                    parsed = urlsplit(url)
                    self.address = (parsed.hostname, parsed.port)

                def __enter__(self) -> Browser:
                    peer = socket.create_connection(self.address, timeout=5)
                    peers.append(peer)
                    hello = (
                        b"\x01\x00\x00\x06abcdef"
                        if worker_failure
                        else b"\x01\x00\x00\x06ab"
                    )
                    peer.sendall(record(0x16, hello))
                    if not entered.wait(5):
                        raise TimeoutError("TCP worker did not accept its peer")
                    if not worker_failure:
                        raise primary
                    return self

                def __exit__(self, *_: object) -> None:
                    peer = socket.create_connection(self.address, timeout=5)
                    peers.append(peer)
                    peer.sendall(record(0x16, b"\x01\x00\x00\x06ab"))
                    if not second_read.wait(5):
                        raise TimeoutError("TCP worker did not observe the later peer")
                    raise cleanup

            plan = LaunchPlan("firefox", Path("unused"), headless=True)
            expected = capture._CaptureFailures if worker_failure else OSError
            try:
                with (
                    patch.object(capture, "_Capture", return_value=owner),
                    patch.object(capture, "LaunchedBrowser", Browser),
                    patch.object(capture, "read_client_hello", read),
                    patch.object(threading.Thread, "start", start),
                    self.assertRaises(expected) as raised,
                ):
                    capture.capture_tcp(plan, "127.0.0.1", socket.AF_INET, 5)
                if worker_failure:
                    self.assertIsInstance(raised.exception, capture._CaptureFailures)
                    self.assertIs(raised.exception.primary, cleanup)
                    self.assertEqual(raised.exception.cleanup, (io_failure,))
                    self.assertEqual(owner.records, [b"\x01\x00\x00\x06abcdef"])
                else:
                    self.assertIs(raised.exception, primary)
                self.assertTrue(started)
                self.assertTrue(all(not thread.is_alive() for thread in started))
                self.assertEqual(owner.threads, [])
                self.assertEqual(owner.sockets, [])
                for peer in peers:
                    peer.settimeout(5)
                    # Closing an unread accepted request can reset its peer.
                    with suppress(ConnectionResetError, ConnectionAbortedError):
                        self.assertEqual(peer.recv(1), b"")
            finally:
                # Backup follows the original outcome and ownership assertions.
                owner.stop.set()
                for bound in tuple(owner.sockets):
                    bound.close()
                for thread in started:
                    thread.join(5)
                for peer in peers:
                    peer.close()

        for worker_failure in (False, True):
            with self.subTest(worker_failure=worker_failure):
                observe(worker_failure)

    def test_partial_quic_socket_acquisition_closes_the_original_udp_socket(
        self,
    ) -> None:
        owner = capture._Capture()
        primary = OSError(errno.EMFILE, "TCP socket acquisition failed")
        acquired = []
        native_open = owner.open_socket

        def open_socket(family: socket.AddressFamily, kind: int) -> socket.socket:
            if acquired:
                raise primary
            bound = native_open(family, kind)
            acquired.append(bound)
            return bound

        plan = LaunchPlan("firefox", Path("unused"), headless=True)
        try:
            with (
                patch.object(capture, "_Capture", return_value=owner),
                patch.object(owner, "open_socket", open_socket),
                patch.object(capture, "LaunchedBrowser") as browser,
                self.assertRaises(OSError) as raised,
            ):
                capture.capture_quic(plan, "127.0.0.1", socket.AF_INET, 5)
            self.assertIs(raised.exception, primary)
            browser.assert_not_called()
            self.assertEqual(len(acquired), 1)
            self.assertEqual(acquired[0].fileno(), -1)
            self.assertEqual(owner.sockets, [])
        finally:
            for bound in acquired:
                bound.close()

    def test_second_worker_start_failure_joins_the_started_udp_worker(self) -> None:
        owner = capture._Capture()
        primary = RuntimeError("TCP worker start failed")
        attempts = []
        sockets = []
        native_start = threading.Thread.start
        native_open = owner.open_socket

        def start(thread: threading.Thread) -> None:
            attempts.append(thread)
            if len(attempts) == 2:
                raise primary
            native_start(thread)

        def open_socket(family: socket.AddressFamily, kind: int) -> socket.socket:
            bound = native_open(family, kind)
            sockets.append(bound)
            return bound

        plan = LaunchPlan("firefox", Path("unused"), headless=True)
        try:
            with (
                patch.object(capture, "_Capture", return_value=owner),
                patch.object(owner, "open_socket", open_socket),
                patch.object(threading.Thread, "start", start),
                patch.object(capture, "LaunchedBrowser") as browser,
                self.assertRaises(capture._CaptureFailures) as raised,
            ):
                capture.capture_quic(plan, "127.0.0.1", socket.AF_INET, 5)
            browser.assert_not_called()
            self.assertIs(raised.exception.primary, primary)
            self.assertEqual(len(raised.exception.cleanup), 1)
            self.assertIsInstance(raised.exception.cleanup[0], TimeoutError)
            self.assertEqual(len(attempts), 2)
            self.assertFalse(attempts[0].is_alive())
            self.assertEqual(len(owner.threads), 1)
            self.assertIs(owner.threads[0][0], attempts[1])
            self.assertIs(raised.exception.capture, owner)
            self.assertTrue(sockets)
            self.assertTrue(all(bound.fileno() == -1 for bound in sockets))
            self.assertEqual(owner.sockets, [])
        finally:
            owner.stop.set()
            for bound in sockets:
                bound.close()
            for thread in attempts:
                if thread.ident is not None:
                    thread.join(5)


class CommandLineTest(unittest.TestCase):
    def test_version_probe_has_a_deadline_and_preserves_its_timeout(self) -> None:
        command = [str(Path("firefox")), "--version"]
        primary = capture.subprocess.TimeoutExpired(
            command, 5, output=b"partial version", stderr=b"original probe stderr"
        )
        with (
            patch.object(capture.subprocess, "run", side_effect=primary) as probe,
            patch.object(capture, "capture_tcp") as tcp,
            patch.object(capture, "write_text_fixture") as write,
            self.assertRaises(capture.subprocess.TimeoutExpired) as raised,
        ):
            capture.main(
                [
                    "--firefox-path",
                    "firefox",
                    "--transport",
                    "tcp",
                    "--family",
                    "ipv4",
                    "--output",
                    "unused.txt",
                ]
            )
        probe.assert_called_once_with(
            command, capture_output=True, text=True, check=True, timeout=5
        )
        self.assertIs(raised.exception, primary)
        self.assertEqual(raised.exception.output, b"partial version")
        self.assertEqual(raised.exception.stderr, b"original probe stderr")
        tcp.assert_not_called()
        write.assert_not_called()


class RenderFixtureTest(unittest.TestCase):
    def test_records_the_preferences_and_every_client_hello(self) -> None:
        fixture = render_fixture(
            "Mozilla Firefox 157.0",
            f"https://{url_host('::1')}:4433/",
            (("security.tls.ech.grease_size", 87),),
            (b"\x01\x00", b"\x01\x01"),
            None,
        )
        self.assertEqual(
            fixture,
            "client_version=Mozilla Firefox 157.0\n"
            "url=https://[::1]:4433/\n"
            "prefs=security.tls.ech.grease_size=87\n"
            "client_hello_0_hex=0100\n"
            "client_hello_1_hex=0101\n",
        )

    def test_records_the_datagram_count_of_a_quic_capture(self) -> None:
        fixture = render_fixture("v", "https://127.0.0.1:1/", (), (), 4)
        self.assertIn("prefs=\ndatagrams=4\n", fixture)


if __name__ == "__main__":
    unittest.main()
