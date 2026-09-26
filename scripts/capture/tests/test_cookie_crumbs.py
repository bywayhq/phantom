import asyncio
import ssl
import unittest
from pathlib import Path

import pylsqpack
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import StreamEnded

from scripts.capture.cookie_crumbs import (
    FORMAT,
    PROBE_COOKIES,
    SCENARIOS,
    CaptureMetadata,
    CookieRun,
    TcpServer,
    check_field,
    check_inserted_cookies,
    encoder_instructions,
    field_section,
    fixture,
    is_probe_cookie,
)
from scripts.capture.http2_session import HOSTNAME, generate_certificate

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "cookies"
CERTIFICATE = generate_certificate()
METADATA = CaptureMetadata(
    client="scripted",
    client_version="0",
    operating_system="test",
    listen_address="127.0.0.1:0",
    launch_mode="scripted",
    launch_arguments="none",
)
JOINED = "; ".join(PROBE_COOKIES).encode()
TIMEOUT = 20.0


def fixture_values(path: Path) -> dict[str, str]:
    lines = path.read_text(encoding="ascii").splitlines()
    return dict(line.split("=", 1) for line in lines)


def record(text: str) -> dict[str, str]:
    return dict(item.split(":", 1) for item in text.split(","))


async def h2_requests(port: int, token: str, cookie: bytes) -> None:
    """Send `/start`, then `/page` and `/done` with `cookie`, over one session."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["h2"])
    reader, writer = await asyncio.open_connection(
        "127.0.0.1", port, ssl=context, server_hostname=HOSTNAME
    )
    connection = H2Connection(H2Configuration(client_side=True, header_encoding=None))
    connection.initiate_connection()
    for path, carries_cookie in (("/start", False), ("/page", True), ("/done", True)):
        stream_id = connection.get_next_available_stream_id()
        headers = [
            (b":method", b"GET"),
            (b":authority", HOSTNAME.encode()),
            (b":scheme", b"https"),
            (b":path", f"{path}?run={token}".encode()),
            (b"accept", b"*/*"),
        ]
        if carries_cookie:
            headers.append((b"cookie", cookie))
        connection.send_headers(stream_id, headers, end_stream=True)
        writer.write(connection.data_to_send())
        await writer.drain()
        ended = False
        while not ended:
            data = await reader.read(65536)
            if not data:
                raise ConnectionError("server closed the session")
            for event in connection.receive_data(data):
                ended |= isinstance(event, StreamEnded) and event.stream_id == stream_id
            writer.write(connection.data_to_send())
    writer.close()


async def scripted_h2_run(cookie: bytes) -> CookieRun:
    server = TcpServer(CERTIFICATE)
    await server.start("127.0.0.1")
    try:
        run = CookieRun("feedc0de", observation_seconds=0.05)
        server.run = run
        await asyncio.wait_for(
            h2_requests(server.tls_address[1], run.token, cookie), TIMEOUT
        )
        await asyncio.wait_for(run.done.wait(), TIMEOUT)
        return run
    finally:
        server.run = None
        await server.close()


class ScriptedCaptureTests(unittest.TestCase):
    def test_h2_fixture_keeps_each_cookie_representation_in_order(self) -> None:
        run = asyncio.run(scripted_h2_run(JOINED))
        text = fixture(SCENARIOS["h2"], [run], METADATA, 4096)
        values = dict(line.split("=", 1) for line in text.splitlines())

        self.assertEqual(values["format"], FORMAT)
        self.assertEqual(values["run_0_request_count"], "3")
        self.assertIn("kind:page", values["run_0_request_1"])
        self.assertEqual(
            values["run_0_request_1_field_order"],
            ":method,:authority,:scheme,:path,accept,cookie",
        )
        field = record(values["run_0_request_1_field_5"])
        self.assertEqual(bytes.fromhex(field["value_hex"]), JOINED)

    def test_fixture_refuses_a_cookie_that_is_not_a_probe(self) -> None:
        run = asyncio.run(scripted_h2_run(b"session=secret"))
        with self.assertRaisesRegex(ValueError, "not a probe"):
            fixture(SCENARIOS["h2"], [run], METADATA, 4096)


class RetainedFieldTests(unittest.TestCase):
    def test_probe_cookies_pass_in_any_split(self) -> None:
        self.assertTrue(is_probe_cookie(JOINED))
        self.assertTrue(is_probe_cookie(PROBE_COOKIES[1].encode()))
        self.assertFalse(is_probe_cookie(JOINED + b"; other=1"))

    def test_credentials_are_refused(self) -> None:
        with self.assertRaisesRegex(ValueError, "credential"):
            check_field(b"Authorization", b"Basic eA==")

    def test_inserted_cookies_that_are_not_probes_are_refused(self) -> None:
        # Insert with static name reference 5 (`cookie`), a raw 14-byte value.
        stream = b"\x02\xc5\x0esession=secret"
        with self.assertRaisesRegex(ValueError, "not a probe"):
            check_inserted_cookies(encoder_instructions(stream))
        check_inserted_cookies(encoder_instructions(b"\x02\xc5\x04pa=1"))


class QpackParserTests(unittest.TestCase):
    def test_field_lines_reference_the_entries_the_encoder_inserted(self) -> None:
        encoder = pylsqpack.Encoder()
        stream = b"\x02" + encoder.apply_settings(4096, 16)
        fields = [(b":method", b"GET"), (b"x-probe", b"1")]
        fields += [(b"cookie", cookie.encode()) for cookie in PROBE_COOKIES]
        # lsqpack inserts a field only once it has seen it before.
        for stream_id in (0, 4, 8):
            instructions, block = encoder.encode(stream_id, fields)
            stream += instructions
        parsed = encoder_instructions(stream)
        inserted = {item.inserted: item for item in parsed if item.inserted is not None}

        section = field_section(block, 4096)
        self.assertEqual(len(section.lines), len(fields))
        referenced = [line for line in section.lines if line.absolute is not None]
        self.assertTrue(referenced, "the last block used no dynamic entry")
        for line, (name, value) in zip(section.lines, fields, strict=True):
            if line.absolute is not None:
                entry = inserted[line.absolute]
                self.assertEqual(entry.value.decoded(), value, name)

    def test_retained_http3_fixtures_parse_to_their_recorded_field_lines(self) -> None:
        paths = sorted(FIXTURES.glob("*/*/*/crumbs-h3.txt"))
        self.assertEqual(len(paths), 5)
        for path in paths:
            values = fixture_values(path)
            capacity = int(values["server_qpack_max_table_capacity"])
            requests = [key for key in values if key.endswith("_block_hex")]
            self.assertTrue(requests, path)
            for key in requests:
                prefix = key.removesuffix("_block_hex")
                section = field_section(bytes.fromhex(values[key]), capacity)
                count = int(values[f"{prefix}_field_count"])
                self.assertEqual(len(section.lines), count, key)
                for index, line in enumerate(section.lines):
                    recorded = record(values[f"{prefix}_field_{index}"])
                    self.assertEqual(recorded["repr"], line.representation)
                    self.assertEqual(recorded["table"], line.table)


if __name__ == "__main__":
    unittest.main()
