import unittest

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection

from scripts.capture.ip_literal_client_hello import (
    client_hello_from_initials,
    client_hello_from_records,
    crypto_frames,
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


class CryptoFramesTest(unittest.TestCase):
    def test_reads_crypto_frames_past_padding_ping_and_ack(self) -> None:
        payload = bytes([0x00, 0x01, 0x02, 5, 0, 0, 3, 0x06, 0x00, 0x02]) + b"hi"
        self.assertEqual(crypto_frames(payload), {0: b"hi"})


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
