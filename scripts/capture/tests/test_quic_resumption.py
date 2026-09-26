import asyncio
import ssl
import unittest
from pathlib import Path

from aioquic.asyncio import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration

from scripts.capture.http2_session import HOSTNAME, generate_certificate
from scripts.capture.quic_resumption import (
    EARLY_DATA,
    FORMAT,
    PRE_SHARED_KEY,
    SCENARIOS,
    ClientHelloShape,
    RunResult,
    chromium_extra_arguments,
    compare_shapes,
    count_packets,
    is_reserved_version,
    launch_plan,
    parse_client_hello,
    render_fixture,
    serving,
)
from scripts.capture.tests.loopback_quic import connect_loopback

ROOT = Path(__file__).resolve().parents[3]
CHROME_CLIENT_HELLO = (
    ROOT
    / "fixtures/http3/chrome/154.0.8037.58/windows-11-26200/quic-client-hello-1.txt"
)


def retained_client_hello() -> bytes:
    for line in CHROME_CLIENT_HELLO.read_text(encoding="ascii").splitlines():
        if line.startswith("handshake_hex="):
            return bytes.fromhex(line.split("=", 1)[1])
    raise AssertionError("fixture has no handshake_hex line")


def encode_client_hello(message: bytes, extensions) -> bytes:
    """Replace the extension block of `message` with `extensions`, in order."""
    shape = parse_client_hello(message)
    old_block = b"".join(
        extension.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body
        for extension, body in shape.extensions
    )
    prefix = message[4 : len(message) - len(old_block) - 2]
    block = b"".join(
        extension.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body
        for extension, body in extensions
    )
    body = prefix + len(block).to_bytes(2, "big") + block
    return b"\x01" + len(body).to_bytes(3, "big") + body


def resumed_from(message: bytes) -> bytes:
    extensions = list(parse_client_hello(message).extensions)
    extensions.insert(3, (EARLY_DATA, b""))
    identity = b"\x00\x40" + bytes(64) + bytes(4)
    binder = b"\x30" + bytes(48)
    psk = (
        len(identity).to_bytes(2, "big")
        + identity
        + len(binder).to_bytes(2, "big")
        + binder
    )
    extensions.append((PRE_SHARED_KEY, psk))
    return encode_client_hello(message, extensions)


class ClientHelloShapeTests(unittest.TestCase):
    def test_retained_chrome_client_hello_parses_without_resumption(self) -> None:
        shape = parse_client_hello(retained_client_hello())
        self.assertEqual(shape.key_share_groups(), (0x11EC, 0x001D))
        self.assertEqual(shape.psk_key_exchange_modes(), (1,))
        self.assertIsNone(shape.pre_shared_key())
        self.assertIsNone(shape.extension(EARLY_DATA))
        self.assertIn("grease", shape.transport_parameter_ids())
        self.assertIsNone(shape.initial_rtt_us())
        versions = shape.version_information()
        self.assertEqual(versions[0], "00000001")
        self.assertEqual(sorted(versions), ["00000001", "00000001", "grease"])

    def test_reserved_versions_match_the_rfc_9000_pattern(self) -> None:
        self.assertTrue(is_reserved_version(bytes.fromhex("1a2a3afa")))
        self.assertFalse(is_reserved_version(bytes.fromhex("00000001")))
        self.assertFalse(is_reserved_version(bytes.fromhex("6b3343cf")))

    def test_resumed_shape_reports_only_the_added_extensions(self) -> None:
        fresh = retained_client_hello()
        resumed = parse_client_hello(resumed_from(fresh))
        self.assertEqual(resumed.pre_shared_key(), ((64,), (48,)))
        self.assertEqual(
            compare_shapes(parse_client_hello(fresh), resumed),
            [
                "added_extensions=002a,0029",
                "removed_extensions=none",
                "extension_multiset_equal_without_added=true",
                "cipher_suites_equal=true",
                "key_share_groups_equal=true",
                "ech_grease_length_equal=true",
                "changed_extension_bodies=none",
                "added_transport_parameters=none",
                "removed_transport_parameters=none",
                "changed_transport_parameters=none",
            ],
        )

    def test_truncated_client_hello_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            parse_client_hello(retained_client_hello()[:-1])
        with self.assertRaises(ValueError):
            parse_client_hello(b"\x02\x00\x00\x00")

    def test_empty_shape_has_no_derived_fields(self) -> None:
        shape = ClientHelloShape((), ())
        self.assertEqual(shape.key_share_groups(), ())
        self.assertEqual(shape.transport_parameters(), {})


class PacketCountTests(unittest.TestCase):
    def test_coalesced_zero_rtt_and_short_header_packets_are_named(self) -> None:
        connection_id = bytes(range(8))
        zero_rtt = (
            bytes([0xD0])
            + (1).to_bytes(4, "big")
            + bytes([8])
            + connection_id
            + bytes([8])
            + connection_id
            + bytes([0x40, 20])
            + bytes(20)
        )
        short = bytes([0x40]) + connection_id + bytes(24)
        self.assertEqual(count_packets(zero_rtt + short, 8), ["0rtt", "1rtt"])

    def test_malformed_datagram_is_counted_as_unparsed(self) -> None:
        self.assertEqual(count_packets(bytes([0xC0, 0, 0]), 8), ["unparsed"])


class LaunchTests(unittest.TestCase):
    def test_chromium_forces_quic_on_the_origin_without_field_trials(self) -> None:
        arguments = chromium_extra_arguments(
            "127.0.0.1", 4433, "spki", field_trial_config=False
        )
        self.assertIn(f"--origin-to-force-quic-on={HOSTNAME}:4433", arguments)
        self.assertIn("--ignore-certificate-errors-spki-list=spki", arguments)
        self.assertIn("--disable-field-trial-config", arguments)
        self.assertNotIn(
            "--disable-field-trial-config",
            chromium_extra_arguments(
                "127.0.0.1", 4433, "spki", field_trial_config=True
            ),
        )

    def test_firefox_maps_the_origin_to_h3_and_trusts_the_test_root(self) -> None:
        plan = launch_plan(
            "firefox",
            Path("firefox.exe"),
            headless=True,
            listen_host="127.0.0.1",
            port=4433,
            certificate=generate_certificate(),
            field_trial_config=False,
        )
        preferences = dict(plan.firefox_preferences)
        self.assertEqual(
            preferences["network.http.http3.alt-svc-mapping-for-testing"],
            f"{HOSTNAME};h3=:4433",
        )
        self.assertIs(
            preferences["network.http.http3.disable_when_third_party_roots_found"],
            False,
        )
        self.assertEqual(
            [name for name, _ in plan.profile_files], ["cert_override.txt"]
        )


class Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.finished: dict[int, asyncio.Future] = {}

    def request(self, method: str, path: str, body: bytes = b"") -> asyncio.Future:
        stream_id = self._quic.get_next_available_stream_id()
        self.http.send_headers(
            stream_id,
            [
                (b":method", method.encode()),
                (b":scheme", b"https"),
                (b":authority", HOSTNAME.encode()),
                (b":path", path.encode()),
            ],
            end_stream=not body,
        )
        if body:
            self.http.send_data(stream_id, body, end_stream=True)
        self.transmit()
        future = asyncio.get_running_loop().create_future()
        self.finished[stream_id] = future
        return future

    def quic_event_received(self, event) -> None:
        for http_event in self.http.handle_event(event):
            if (
                isinstance(http_event, (HeadersReceived, DataReceived))
                and http_event.stream_ended
            ):
                future = self.finished.get(http_event.stream_id)
                if future is not None and not future.done():
                    future.set_result(None)


async def exercise(scenario_name: str) -> RunResult:
    """Drive one fresh and one resumed aioquic connection through the server."""
    scenario = SCENARIOS[scenario_name]
    tickets = []
    async with serving(scenario, "127.0.0.1", generate_certificate()) as (run, port):
        configuration = QuicConfiguration(
            is_client=True,
            alpn_protocols=H3_ALPN,
            server_name=HOSTNAME,
            verify_mode=ssl.CERT_NONE,
        )
        async with connect_loopback(
            port,
            configuration,
            create_protocol=Client,
            session_ticket_handler=tickets.append,
        ) as client:
            await asyncio.wait_for(client.request("GET", "/"), 5)
            await asyncio.wait_for(client.request("GET", "/retire"), 5)
            await asyncio.sleep(0.2)
        resumed = QuicConfiguration(
            is_client=True,
            alpn_protocols=H3_ALPN,
            server_name=HOSTNAME,
            verify_mode=ssl.CERT_NONE,
            session_ticket=tickets[-1],
        )
        async with connect_loopback(
            port,
            resumed,
            create_protocol=Client,
            wait_connected=False,
        ) as client:
            early = client.request("GET", "/early")
            await client.wait_connected()
            late = client.request("POST", "/late", b"phantom")
            await asyncio.wait_for(asyncio.gather(early, late), 5)
            await asyncio.wait_for(client.request("GET", "/done"), 5)
    return RunResult(run, port, "scripted", timed_out=False)


class LoopbackTests(unittest.TestCase):
    def test_resumed_connection_records_ticket_and_zero_rtt_request(self) -> None:
        result = asyncio.run(exercise("accept"))
        run = result.run
        self.assertEqual(len(run.connections), 2)
        fresh, resumed = run.connections
        self.assertEqual(fresh.tickets_issued, 1)
        self.assertEqual(fresh.ticket_max_early_data_size, 0xFFFFFFFF)
        self.assertEqual(fresh.closed_by, "server")
        self.assertTrue(resumed.resumed)
        self.assertEqual(resumed.psk_ticket_from, 0)
        self.assertTrue(resumed.early_data_accepted)
        self.assertGreater(resumed.packets.get("0rtt", 0), 0)
        spaces = {
            request.path: resumed.stream_spaces[request.stream_id]
            for request in run.requests
            if request.connection == 1
        }
        self.assertEqual(spaces["/early"], ["0rtt"])
        self.assertEqual(spaces["/late"], ["1rtt"])
        late = next(request for request in run.requests if request.path == "/late")
        self.assertEqual((late.method, late.body_bytes), ("POST", 7))
        # aioquic opens its control, QPACK encoder, and QPACK decoder streams
        # when the connection starts and writes each type byte at once.
        streams = resumed.unidirectional_streams
        self.assertEqual(list(streams), [2, 6, 10])
        self.assertEqual(
            {stream_id: stream.stream_type for stream_id, stream in streams.items()},
            {2: 0x00, 6: 0x02, 10: 0x03},
        )
        self.assertEqual(streams[10].first_frame_bytes, 1)
        self.assertGreater(streams[2].first_frame_bytes, 1)

        fixture = render_fixture(
            SCENARIOS["accept"],
            [result],
            client="aioquic",
            client_version="1.3.0",
            operating_system="test",
            launch_mode="scripted",
            listen_host="127.0.0.1",
        )
        lines = fixture.splitlines()
        self.assertEqual(lines[0], f"format={FORMAT}")
        self.assertIn("summary_later_connections_resumed=1", lines)
        self.assertIn("summary_request=GET /early:0rtt:1", lines)
        self.assertIn("run_0_connection_1_psk_ticket_from=connection_0", lines)
        self.assertIn(
            "run_0_connection_1_versus_connection_0_added_extensions=002a,0029",
            lines,
        )
        self.assertIn("run_0_connection_1_unidirectional_streams=2,6,10", lines)
        self.assertTrue(
            any(
                line.startswith(
                    "run_0_connection_1_unidirectional_stream_10="
                    "type:0x03,space:1rtt,first_frame_bytes:1,first_ms:"
                )
                for line in lines
            )
        )
        self.assertTrue(fixture.endswith("\n"))
        self.assertNotIn("\r", fixture)

    def test_rejected_early_data_still_resumes_the_ticket(self) -> None:
        run = asyncio.run(exercise("reject")).run
        resumed = run.connections[1]
        self.assertTrue(resumed.resumed)
        self.assertEqual(resumed.psk_ticket_from, 0)
        self.assertFalse(resumed.early_data_accepted)
        self.assertGreater(resumed.packets.get("0rtt", 0), 0)
        self.assertNotIn("0rtt", sum(resumed.stream_spaces.values(), []))


if __name__ == "__main__":
    unittest.main()
