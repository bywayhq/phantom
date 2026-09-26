import asyncio
import ssl
import struct
import tempfile
import unittest
from pathlib import Path

from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import ConnectionTerminated, ResponseReceived, StreamEnded

from scripts.capture.http2_session import (
    CONNECTION_PREFACE,
    HOSTNAME,
    ConnectionRecord,
    generate_certificate,
)
from scripts.capture.snapshot import (
    FORMAT,
    CaptureMetadata,
    HelloSummary,
    SnapshotRun,
    akamai_http2,
    client_hello_records,
    ja3,
    ja4,
    raw_frames,
    render_snapshot,
    reserve_shared_port,
    serving,
    split_snapshot,
    startup_frames,
    summary_lines,
)
from scripts.capture.snapshot_compare import compare_tls, degrease, fields

CERTIFICATE = generate_certificate()
TIMEOUT = 20.0
METADATA = CaptureMetadata(
    client="scripted",
    client_version="1.0",
    operating_system="test",
    launch_mode="scripted",
    launch_arguments="none",
)
# FoxIO's published JA4 example: a Chrome ClientHello with these ciphers,
# these extensions besides SNI and ALPN, and these signature algorithms.
JA4_CIPHERS = (
    0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9,
    0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035,
)  # fmt: skip
JA4_EXTENSIONS = (
    0x0005, 0x000A, 0x000B, 0x000D, 0x0012, 0x0015, 0x0017, 0x001B,
    0x0023, 0x002B, 0x002D, 0x0033, 0x4469, 0xFF01,
)  # fmt: skip
JA4_SIGNATURES = (0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601)


def u16s(values) -> bytes:
    return b"".join(struct.pack(">H", value) for value in values)


def vector(width: int, body: bytes) -> bytes:
    return len(body).to_bytes(width, "big") + body


def client_hello(extensions: list[tuple[int, bytes]], ciphers=JA4_CIPHERS) -> bytes:
    """A TLS 1.3 ClientHello handshake message with extensions in order."""
    body = (
        b"\x03\x03"
        + bytes(32)
        + vector(1, bytes(32))
        + vector(2, u16s(ciphers))
        + b"\x01\x00"
        + vector(2, b"".join(u16s([k]) + vector(2, v) for k, v in extensions))
    )
    return b"\x01" + vector(3, body)


def chrome_like_extensions() -> list[tuple[int, bytes]]:
    name = HOSTNAME.encode()
    extensions = [
        (0x0A0A, b""),
        (0x0000, vector(2, b"\x00" + vector(2, name))),
        (0x0010, vector(2, vector(1, b"h2") + vector(1, b"http/1.1"))),
        (0x000A, vector(2, u16s([0x2A2A, 0x001D, 0x0017]))),
        (0x000B, vector(1, b"\x00")),
        (0x000D, vector(2, u16s(JA4_SIGNATURES))),
        (0x002B, vector(1, u16s([0x3A3A, 0x0304, 0x0303]))),
        (0x0033, vector(2, u16s([0x001D]) + vector(2, bytes(32)))),
    ]
    listed = {kind for kind, _ in extensions}
    extensions.extend((kind, b"") for kind in JA4_EXTENSIONS if kind not in listed)
    return extensions


def frame(kind: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    return (
        len(payload).to_bytes(3, "big")
        + bytes([kind, flags])
        + stream_id.to_bytes(4, "big")
        + payload
    )


def records(message: bytes, size: int) -> bytes:
    return b"".join(
        b"\x16\x03\x01" + vector(2, message[offset : offset + size])
        for offset in range(0, len(message), size)
    )


class ClientHelloTests(unittest.TestCase):
    def test_records_stop_at_the_end_of_the_client_hello(self) -> None:
        message = client_hello(chrome_like_extensions())
        raw = records(message, 100) + b"\x14\x03\x03\x00\x01\x01"
        split = client_hello_records(raw)
        self.assertEqual(b"".join(r[5:] for r in split), message)
        with self.assertRaisesRegex(ValueError, "no complete ClientHello"):
            client_hello_records(records(message, 100)[:-1])

    def test_summary_uses_the_capture_client_hello_spelling(self) -> None:
        summary = HelloSummary.parse(client_hello(chrome_like_extensions()))
        lines = dict(line.split("=", 1) for line in summary_lines(summary))
        self.assertEqual(lines["legacy_version"], "0x0303")
        self.assertEqual(lines["supported_groups"], "0x2a2a,0x001d,0x0017")
        self.assertEqual(lines["ec_point_formats"], "0x00")
        self.assertEqual(lines["alpn_protocols_hex"], "6832,687474702f312e31")
        self.assertEqual(lines["supported_versions"], "0x3a3a,0x0304,0x0303")
        self.assertEqual(lines["key_share_groups"], "0x001d")
        self.assertEqual(lines["server_name_hex"], HOSTNAME.encode().hex())
        self.assertTrue(lines["extension_types"].startswith("0x0a0a,0x0000,0x0010"))

    def test_ja4_matches_the_published_chrome_example(self) -> None:
        summary = HelloSummary.parse(client_hello(chrome_like_extensions()))
        self.assertEqual(ja4(summary, "t"), "t13d1516h2_8daaf6152771_e5627efa2ab1")
        self.assertTrue(ja4(summary, "q").startswith("q13d1516h2_"))

    def test_ja3_drops_grease_and_keeps_extension_order(self) -> None:
        summary = HelloSummary.parse(
            client_hello(chrome_like_extensions(), ciphers=(0x1A1A, 0x1301))
        )
        version, ciphers, extensions, groups, formats = ja3(summary).split(",")
        self.assertEqual((version, ciphers), ("771", "4865"))
        self.assertTrue(extensions.startswith("0-16-10-11-13-43-51-"))
        self.assertEqual((groups, formats), ("29-23", "0"))


class Http2Tests(unittest.TestCase):
    def test_startup_frames_and_akamai_fingerprint(self) -> None:
        settings = b"".join(
            struct.pack(">HI", identifier, value)
            for identifier, value in ((1, 65536), (2, 0), (4, 6291456), (6, 262144))
        )
        stream = (
            CONNECTION_PREFACE
            + frame(0x4, 0, 0, settings)
            + frame(0x8, 0, 0, struct.pack(">I", 15663105))
            + frame(0x2, 0, 3, struct.pack(">IB", 0x80000000, 200))
            + frame(0x1, 0x25, 1, struct.pack(">IB", 0x80000000, 255) + bytes([0x82]))
            + frame(0x8, 0, 1, struct.pack(">I", 1))
        )
        frames = raw_frames(stream)
        self.assertEqual([f[3] for f in startup_frames(frames)], [0x4, 0x8, 0x2])
        self.assertEqual(
            akamai_http2(frames, [b":method", b":authority", b":scheme", b":path"]),
            "1:65536;2:0;4:6291456;6:262144|15663105|3:1:0:201|m,a,s,p",
        )

    def test_raw_frames_require_the_preface(self) -> None:
        with self.assertRaisesRegex(ValueError, "preface"):
            raw_frames(b"GET / HTTP/1.1\r\n\r\n")

    def test_unparseable_evidence_is_noted_not_fatal(self) -> None:
        run = SnapshotRun("feedc0de", 1, 2, 0.1)
        record = ConnectionRecord("tls", 0.0, protocol="h2")
        record.client_chunks.append((0.0, b"GET / HTTP/1.1\r\n\r\n"))
        run.connections.append(record)
        values = fields(render_snapshot(run, METADATA, "127.0.0.1", 1.0))
        self.assertIn("preface", values["h2_error"])
        self.assertEqual(values["http3"], "not-used")


class ComparisonTests(unittest.TestCase):
    def test_permuted_extensions_are_not_a_difference(self) -> None:
        old = {"extension_types": "0x0a0a,0x0000,0x0010", "cipher_suites": "0x1a1a"}
        new = {"extension_types": "0x0010,0x0000,0x3a3a", "cipher_suites": "0x2a2a"}
        self.assertEqual(
            compare_tls("tls", new, old),
            ["tls.extension_types: same set, order permuted"],
        )
        self.assertEqual(degrease("0xfafa,0x1301"), "GREASE,0x1301")

    def test_added_extensions_are_named(self) -> None:
        report = compare_tls(
            "tls",
            {"extension_types": "0x0000,0x0029"},
            {"extension_types": "0x0000"},
        )
        self.assertEqual(
            report, ["tls.extension_types: added ['0x0029'], removed none"]
        )


# -- Scripted end-to-end run over loopback, with Python clients ------------


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
        while not ended:
            data = await reader.read(65536)
            if not data:
                raise ConnectionError("server closed the session")
            for event in connection.receive_data(data):
                if isinstance(event, ResponseReceived):
                    responses[path] = dict(event.headers)
                ended |= isinstance(event, StreamEnded) and event.stream_id == stream_id
                if isinstance(event, ConnectionTerminated):
                    responses["goaway"] = {}
            writer.write(connection.data_to_send())
    if "goaway" not in responses:
        data = await reader.read(65536)
        for event in connection.receive_data(data):
            if isinstance(event, ConnectionTerminated):
                responses["goaway"] = {}
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
        is_client=True, alpn_protocols=H3_ALPN, server_name=HOSTNAME
    )
    configuration.verify_mode = ssl.CERT_NONE
    async with connect(
        "127.0.0.1", port, configuration=configuration, create_protocol=H3Client
    ) as client:
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
    async with serving("127.0.0.1", CERTIFICATE, "feedc0de", 0.05) as run:
        responses = await asyncio.wait_for(h2_session(run.port, run.token), TIMEOUT)
        await asyncio.wait_for(h3_session(run.port, run.token), TIMEOUT)
        await asyncio.wait_for(http1_requests(run.plain_port, run.token), TIMEOUT)
        await asyncio.wait_for(run.done.wait(), TIMEOUT)
    return run, responses


class ScriptedRunTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.scripted, cls.responses = asyncio.run(scripted_run())
        cls.text = render_snapshot(cls.scripted, METADATA, "127.0.0.1", 1.0)
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
        kinds = [
            (request.protocol, request.record.kind)
            for request in self.scripted.requests
        ]
        self.assertEqual(
            kinds,
            [
                ("h2", "start"),
                ("h2", "fetch"),
                ("h3", "next"),
                ("h3", "fetch"),
                ("http/1.1", "plain"),
                ("http/1.1", "done"),
            ],
        )

    def test_snapshot_holds_every_layer(self) -> None:
        values = self.values
        self.assertEqual(values["format"], FORMAT)
        self.assertEqual(values["http3"], "used")
        self.assertEqual(values["timed_out"], "false")
        self.assertEqual(values["tls.format"], "phantom-client-hello-v2")
        self.assertEqual(values["tls.server_name_hex"], HOSTNAME.encode().hex())
        self.assertEqual(
            values["h2.preface_hex"], "505249202a20485454502f322e300d0a0d0a534d0d0a0d0a"
        )
        self.assertTrue(values["h2.akamai"].endswith("|m,a,s,p"))
        self.assertEqual(
            values["quic_client_hello.format"], "phantom-quic-client-hello-v1"
        )
        self.assertEqual(values["h3_startup.format"], "phantom-http3-client-startup-v2")
        self.assertEqual(values["h3_startup.alpn"], "h3")
        self.assertTrue(values["quic_ja4"].startswith("q13d"))
        self.assertTrue(values["h3_fingerprint"].endswith("|m,s,a,p"))
        self.assertEqual(values["request_4_field_order"], "Host,User-Agent")
        self.assertEqual(values["hints_second_navigation"], "next")
        self.assertEqual(values["hint_0"], 'default|sec-ch-ua|"Scripted";v="1"')

    def test_split_writes_the_embedded_legacy_fixtures(self) -> None:
        sections = split_snapshot(self.text)
        self.assertEqual(
            sorted(sections),
            ["client-hello.txt", "http3-client-startup.txt", "quic-client-hello.txt"],
        )
        hello = sections["client-hello.txt"].splitlines()
        self.assertEqual(hello[0], "format=phantom-client-hello-v2")
        self.assertTrue(hello[-1].startswith("server_name_hex="))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "client-hello.txt"
            path.write_text(sections["client-hello.txt"], encoding="utf-8")
            self.assertEqual(
                fields(path.read_text(encoding="utf-8"))["record_count"], "1"
            )


class PortTests(unittest.TestCase):
    def test_tcp_and_udp_share_one_loopback_port(self) -> None:
        tcp, udp = reserve_shared_port("127.0.0.1")
        try:
            self.assertEqual(tcp.getsockname(), udp.getsockname())
            self.assertEqual(tcp.getsockname()[0], "127.0.0.1")
        finally:
            tcp.close()
            udp.close()


if __name__ == "__main__":
    unittest.main()
