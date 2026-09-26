import asyncio
import ssl
import struct
import unittest
from pathlib import Path

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import ConnectionTerminated, ResponseReceived, StreamEnded

from scripts.capture.browser_launch import LaunchedBrowser
from scripts.capture.cookie_crumbs import CaptureMetadata
from scripts.capture.http2_session import (
    HOSTNAME,
    ConnectionRecord,
    generate_certificate,
)
from scripts.capture.snapshot import (
    FORMAT,
    SnapshotRun,
    client_hello_records,
    hello_message,
    launch_plan,
    page_url,
    problems,
    render_snapshot,
    reserve_shared_port,
    serving,
    split_snapshot,
    summary_lines,
)
from scripts.capture.snapshot_compare import compare, compare_hello, fields
from scripts.capture.tests.loopback_quic import connect_loopback

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures"
CHROME = "154.0.8037.58/windows-11-26200"
CERTIFICATE = generate_certificate()
TIMEOUT = 20.0
METADATA = CaptureMetadata(
    client="scripted",
    client_version="1.0",
    operating_system="test",
    listen_address="127.0.0.1:0",
    launch_mode="scripted",
    launch_arguments="none",
)


def retained(path: str) -> dict[str, str]:
    return fields((FIXTURES / path).read_text(encoding="utf-8"))


def vector(width: int, body: bytes) -> bytes:
    return len(body).to_bytes(width, "big") + body


def client_hello(extensions: list[tuple[int, bytes]]) -> bytes:
    """A TLS 1.3 ClientHello handshake message with extensions in order."""
    body = (
        b"\x03\x03"
        + bytes(32)
        + vector(1, bytes(32))
        + vector(2, struct.pack(">HH", 0x1A1A, 0x1301))
        + b"\x01\x00"
        + vector(
            2, b"".join(struct.pack(">H", k) + vector(2, v) for k, v in extensions)
        )
    )
    return b"\x01" + vector(3, body)


class ClientHelloTests(unittest.TestCase):
    def test_summary_reproduces_the_retained_chrome_summary(self) -> None:
        values = retained(f"tls/chrome/{CHROME}/client-hello.txt")
        records = [bytes.fromhex(values[f"record_{i}_hex"]) for i in range(1)]
        expected = [
            f"{key}={values[key]}"
            for key in (
                "legacy_version",
                "cipher_suites",
                "extension_types",
                "supported_groups",
                "ec_point_formats",
                "signature_algorithms",
                "alpn_protocols_hex",
                "supported_versions",
                "key_share_groups",
                "server_name_hex",
            )
        ]
        self.assertEqual(summary_lines(hello_message(records)), expected)
        self.assertEqual(client_hello_records(b"".join(records)), records)

    def test_summary_reads_the_retained_quic_client_hello(self) -> None:
        values = retained(f"http3/chrome/{CHROME}/quic-client-hello-1.txt")
        summary = fields(
            "\n".join(summary_lines(bytes.fromhex(values["handshake_hex"])))
        )
        self.assertEqual(summary["cipher_suites"], "0x1301,0x1302,0x1303")
        self.assertEqual(summary["alpn_protocols_hex"], b"h3".hex())
        self.assertEqual(summary["server_name_hex"], HOSTNAME.encode().hex())

    def test_records_stop_at_the_end_of_the_client_hello(self) -> None:
        message = client_hello([(0x0000, b"")])
        record = b"\x16\x03\x01" + vector(2, message)
        self.assertEqual(
            client_hello_records(record + b"\x14\x03\x03\x00\x01\x01"), [record]
        )
        with self.assertRaisesRegex(ValueError, "no complete ClientHello"):
            client_hello_records(record[:-1])


class ComparisonTests(unittest.TestCase):
    ALPS = (0x44CD, bytes.fromhex("0003026832"))

    def test_chromium_permutation_is_not_a_difference(self) -> None:
        old = client_hello([(0x0A0A, b""), (0x0017, b""), self.ALPS])
        new = client_hello([(0x3A3A, b""), self.ALPS, (0x0017, b"")])
        self.assertEqual(compare_hello("tls", new, old, permuted=True), [])

    def test_firefox_permutation_is_a_difference(self) -> None:
        old = client_hello([(0x0017, b""), self.ALPS])
        new = client_hello([self.ALPS, (0x0017, b"")])
        report = compare_hello("tls", new, old, permuted=False)
        self.assertEqual(len(report), 1)
        self.assertIn("extension_types", report[0])

    def test_a_changed_extension_body_is_a_difference(self) -> None:
        old = client_hello([self.ALPS])
        new = client_hello([(0x44CD, bytes.fromhex("0003026833"))])
        self.assertEqual(
            compare_hello("tls", new, old, permuted=True),
            ["tls.extension 0x44cd: retained 0003026832, snapshot 0003026833"],
        )

    def test_key_share_and_grease_values_are_normalized(self) -> None:
        def hello(grease: int, key: bytes) -> bytes:
            groups = vector(2, struct.pack(">HH", grease, 0x001D))
            share = vector(2, struct.pack(">H", 0x001D) + vector(2, key))
            return client_hello([(0x000A, groups), (0x0033, share)])

        new, old = hello(0x2A2A, bytes(32)), hello(0x8A8A, bytes(range(32)))
        self.assertEqual(compare_hello("tls", new, old, permuted=False), [])

    def test_a_layer_missing_from_the_snapshot_is_a_difference(self) -> None:
        values = retained(f"tls/chrome/{CHROME}/client-hello.txt")
        text = f"format={FORMAT}\noperating_system={values['operating_system']}\n"
        report = compare(text, FIXTURES, "chrome")
        for layer in ("tls", "h2", "h2_navigation", "quic_client_hello", "h3", "hints"):
            self.assertTrue(
                any(line.startswith(f"differs {layer}: missing") for line in report),
                layer,
            )

    def test_unparseable_evidence_is_noted_and_makes_the_run_partial(self) -> None:
        run = SnapshotRun("feedc0de", 1, 2, 0.1)
        record = ConnectionRecord("tls", 0.0, protocol="h2")
        record.client_chunks.append((0.0, b"GET / HTTP/1.1\r\n\r\n"))
        run.connections.append(record)
        text = render_snapshot(run, METADATA)
        self.assertIn("preface", fields(text)["h2_error"])
        self.assertIn("http3=not-used", problems(text))


# -- Scripted run over loopback, with Python clients -----------------------


def client_tls_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["h2"])
    return context


async def h2_session(port: int, token: str) -> dict[str, dict[bytes, bytes]]:
    """Load `/` and `/fetch` on one HTTP/2 session and read its GOAWAY."""
    reader, writer = await asyncio.open_connection(
        "127.0.0.1", port, ssl=client_tls_context(), server_hostname=HOSTNAME
    )
    connection = H2Connection(H2Configuration(client_side=True, header_encoding=None))
    connection.initiate_connection()
    responses: dict[str, dict[bytes, bytes]] = {}
    for path in ("/", "/fetch"):
        stream_id = connection.get_next_available_stream_id()
        connection.send_headers(
            stream_id,
            [
                (b":method", b"GET"),
                (b":authority", f"{HOSTNAME}:{port}".encode()),
                (b":scheme", b"https"),
                (b":path", f"{path}?run={token}".encode()),
                (b"sec-ch-ua", b'"Scripted";v="1"'),
            ],
            end_stream=True,
        )
        writer.write(connection.data_to_send())
        ended = False
        while not ended or "goaway" not in responses and path == "/fetch":
            data = await reader.read(65536)
            if not data:
                break
            for event in connection.receive_data(data):
                if isinstance(event, ResponseReceived):
                    responses[path] = dict(event.headers)
                ended |= isinstance(event, StreamEnded) and event.stream_id == stream_id
                if isinstance(event, ConnectionTerminated):
                    responses["goaway"] = {}
            writer.write(connection.data_to_send())
    writer.close()
    return responses


class H3Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.waiters: dict[int, asyncio.Future] = {}

    def quic_event_received(self, event) -> None:
        for http_event in self.http.handle_event(event):
            if isinstance(http_event, (HeadersReceived, DataReceived)):
                waiter = self.waiters.get(http_event.stream_id)
                if http_event.stream_ended and waiter and not waiter.done():
                    waiter.set_result(None)

    async def get(self, port: int, path: str) -> None:
        stream_id = self._quic.get_next_available_stream_id()
        self.http.send_headers(
            stream_id,
            [
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", f"{HOSTNAME}:{port}".encode()),
                (b":path", path.encode()),
                (b"sec-ch-ua", b'"Scripted";v="1"'),
            ],
            end_stream=True,
        )
        self.waiters[stream_id] = asyncio.get_running_loop().create_future()
        self.transmit()
        await self.waiters[stream_id]


async def h3_session(port: int, token: str) -> None:
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=H3_ALPN,
        server_name=HOSTNAME,
        verify_mode=ssl.CERT_NONE,
    )
    async with connect_loopback(port, configuration, H3Client) as client:
        await client.get(port, f"/next?run={token}")
        await client.get(port, f"/fetch?run={token}")


async def http1_requests(port: int, token: str) -> None:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    for path in ("/plain", "/done"):
        writer.write(
            f"GET {path}?run={token} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
            "User-Agent: scripted\r\n\r\n".encode()
        )
        head = await reader.readuntil(b"\r\n\r\n")
        length = next(
            int(line.split(b":")[1])
            for line in head.split(b"\r\n")
            if line.lower().startswith(b"content-length")
        )
        await reader.readexactly(length)
    writer.close()


async def scripted_run():
    async with serving(CERTIFICATE, "feedc0de", 0.05) as run:
        responses = await asyncio.wait_for(h2_session(run.port, run.token), TIMEOUT)
        await asyncio.wait_for(h3_session(run.port, run.token), TIMEOUT)
        await asyncio.wait_for(http1_requests(run.plain_port, run.token), TIMEOUT)
        await asyncio.wait_for(run.done.wait(), TIMEOUT)
    return run, responses


class ScriptedRunTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.scripted, cls.responses = asyncio.run(scripted_run())
        cls.text = render_snapshot(cls.scripted, METADATA)
        cls.values = fields(cls.text)

    def test_first_response_requests_hints_and_fetch_advertises_h3(self) -> None:
        start, fetch = self.responses["/"], self.responses["/fetch"]
        self.assertIn(b"sec-ch-ua-full-version-list", start[b"accept-ch"])
        self.assertEqual(start[b"critical-ch"], start[b"accept-ch"])
        self.assertNotIn(b"alt-svc", start)
        self.assertEqual(
            fetch[b"alt-svc"], f'h3=":{self.scripted.port}"; ma=86400'.encode()
        )
        self.assertIn("goaway", self.responses)

    def test_requests_are_recorded_per_protocol_in_order(self) -> None:
        self.assertEqual(
            [(r.protocol, r.record.kind) for r in self.scripted.requests],
            [
                ("h2", "start"),
                ("h2", "fetch"),
                ("h3", "next"),
                ("h3", "fetch"),
                ("http/1.1", "plain"),
                ("http/1.1", "done"),
            ],
        )

    def test_snapshot_holds_every_layer_without_problems(self) -> None:
        values = self.values
        self.assertEqual(problems(self.text), [])
        self.assertEqual(values["tls.format"], "phantom-client-hello-v2")
        self.assertEqual(values["tls.server_name_hex"], HOSTNAME.encode().hex())
        self.assertEqual(values["h2.frame_count"], "1")
        self.assertIn("priority:none", values["request_0_headers"])
        self.assertEqual(
            values["quic_client_hello.format"], "phantom-quic-client-hello-v1"
        )
        self.assertEqual(values["h3.alpn"], "h3")
        self.assertNotIn("h3.format", values)
        self.assertEqual(values["request_4_field_order"], "Host,User-Agent")
        self.assertEqual(values["hints_second_navigation"], "next")
        self.assertEqual(values["hint_0"], 'default|sec-ch-ua|"Scripted";v="1"')

    def test_split_writes_only_the_drop_in_fixtures(self) -> None:
        sections = split_snapshot(self.text)
        self.assertEqual(
            sorted(sections), ["client-hello.txt", "quic-client-hello.txt"]
        )
        hello = sections["client-hello.txt"].splitlines()
        self.assertEqual(hello[0], "format=phantom-client-hello-v2")
        self.assertTrue(hello[-1].startswith("server_name_hex="))
        quic = fields(sections["quic-client-hello.txt"])
        self.assertEqual(
            quic["handshake_hex"], self.values["quic_client_hello.handshake_hex"]
        )


class AndroidLaunchTests(unittest.TestCase):
    ADB = Path("adb")

    def android_launch(self, browser: str):
        plan = launch_plan(browser, self.ADB, True, 9450, 9451, CERTIFICATE)
        return plan, LaunchedBrowser(
            plan, page_url(browser, 9450, "t")
        ).android_launch()

    def test_chromium_opens_the_page_by_intent_over_the_emulator_route(self) -> None:
        plan, launch = self.android_launch("chrome-android")
        self.assertEqual(plan.launch_mode, "android-intent")
        self.assertEqual(launch.url, f"https://{HOSTNAME}:9450/?run=t")
        self.assertIn(
            f"--host-resolver-rules=MAP {HOSTNAME} 10.0.2.2, MAP * ~NOTFOUND, "
            "EXCLUDE 127.0.0.1",
            launch.arguments,
        )
        self.assertIn(
            f"--ignore-certificate-errors-spki-list={CERTIFICATE.spki_sha256_base64}",
            launch.arguments,
        )
        # `/plain` names the device's own 127.0.0.1.
        self.assertEqual(launch.reverse, (9450, 9451))

    def test_opera_opens_localhost_without_switches(self) -> None:
        _, launch = self.android_launch("opera-android")
        self.assertEqual(launch.url, "https://localhost:9450/?run=t")
        self.assertEqual(launch.arguments, ())
        self.assertIsNone(launch.configuration())

    def test_firefox_gets_preferences_but_no_certificate_override(self) -> None:
        plan, launch = self.android_launch("firefox-android")
        self.assertEqual(plan.profile_files, ())
        self.assertIn(("network.dns.localDomains", HOSTNAME), launch.preferences)
        self.assertEqual(launch.reverse, (9450, 9451))
        desktop = launch_plan("firefox", self.ADB, True, 9450, 9451, CERTIFICATE)
        self.assertEqual(
            [name for name, _ in desktop.profile_files], ["cert_override.txt"]
        )


class PortTests(unittest.TestCase):
    def test_tcp_and_udp_share_one_loopback_port(self) -> None:
        tcp, udp = reserve_shared_port()
        try:
            self.assertEqual(tcp.getsockname(), udp.getsockname())
            self.assertEqual(tcp.getsockname()[0], "127.0.0.1")
        finally:
            tcp.close()
            udp.close()


if __name__ == "__main__":
    unittest.main()
