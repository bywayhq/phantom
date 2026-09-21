import asyncio
import contextlib
import dataclasses
import re
import ssl
import unittest
import zlib
from urllib.parse import urlencode, urlsplit

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.errors import ErrorCodes
from h2.events import (
    DataReceived,
    RemoteSettingsChanged,
    ResponseReceived,
    StreamEnded,
    StreamReset,
    WindowUpdated,
)
from hpack import NeverIndexedHeaderTuple

from scripts.capture.http2_session import (
    HOSTNAME,
    CaptureServer,
    analyze_http2,
    decode_header_block,
    frame_details,
    generate_certificate,
    hpack_representations,
)
from scripts.capture.http2_websocket import (
    CATALOG,
    CORPUS,
    FORMAT,
    SCENARIOS,
    CaptureMetadata,
    capture_scenario,
    fixture,
    main,
    page,
)
from scripts.capture.websocket_frames import (
    CLOSE,
    DEFLATE_TAIL,
    FrameReader,
    client_frame,
)

METADATA = CaptureMetadata(
    client="scripted WebSocket",
    client_version="0",
    operating_system="test",
    tls_listen_address="127.0.0.1:0",
    plain_listen_address="127.0.0.1:0",
    launch_mode="scripted",
    launch_arguments="none",
)
CERTIFICATE = generate_certificate()
TIMEOUT = 20.0


def client_context(alpn):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(list(alpn))
    return context


@dataclasses.dataclass
class SendPolicy:
    """The scripted client's per-message compression and fragmentation."""

    compress_at_least: int | None = None
    fragment_size: int | None = None

    def frames(self, compressor, opcode, payload):
        rsv1 = False
        if (
            self.compress_at_least is not None
            and len(payload) >= self.compress_at_least
        ):
            payload = compressor.compress(payload) + compressor.flush(zlib.Z_SYNC_FLUSH)
            payload = payload[: -len(DEFLATE_TAIL)]
            rsv1 = True
        size = self.fragment_size or max(len(payload), 1)
        chunks = [
            payload[index : index + size] for index in range(0, len(payload), size)
        ]
        chunks = chunks or [b""]
        output = []
        for index, chunk in enumerate(chunks):
            output.append(
                client_frame(
                    opcode if index == 0 else 0,
                    chunk,
                    fin=index == len(chunks) - 1,
                    rsv1=rsv1 and index == 0,
                )
            )
        return b"".join(output)


class ScriptedH2:
    """A minimal H2 client over TLS with a background frame pump."""

    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.connection = H2Connection(
            H2Configuration(client_side=True, header_encoding=None)
        )
        self.events = []
        self.changed = asyncio.Event()
        self.settings_received = False
        self.task = None

    @classmethod
    async def open(cls, port):
        reader, writer = await asyncio.open_connection(
            "127.0.0.1",
            port,
            ssl=client_context(("h2", "http/1.1")),
            server_hostname=HOSTNAME,
        )
        client = cls(reader, writer)
        client.connection.initiate_connection()
        await client.flush()
        client.task = asyncio.create_task(client.pump())
        await client.wait(lambda: client.settings_received)
        return client

    async def flush(self):
        data = self.connection.data_to_send()
        if data:
            self.writer.write(data)
            await self.writer.drain()

    async def pump(self):
        while True:
            data = await self.reader.read(65536)
            if not data:
                self.changed.set()
                return
            events = self.connection.receive_data(data)
            for event in events:
                if isinstance(event, RemoteSettingsChanged):
                    self.settings_received = True
                if isinstance(event, DataReceived) and event.flow_controlled_length:
                    self.connection.acknowledge_received_data(
                        event.flow_controlled_length, event.stream_id
                    )
            self.events.extend(events)
            await self.flush()
            self.changed.set()

    async def wait(self, predicate):
        async def loop():
            while not predicate():
                self.changed.clear()
                if predicate():
                    return
                await self.changed.wait()

        await asyncio.wait_for(loop(), TIMEOUT)

    def stream_events(self, stream_id, kind):
        return [
            event
            for event in self.events
            if isinstance(event, kind) and event.stream_id == stream_id
        ]

    async def get(self, path):
        stream_id = self.connection.get_next_available_stream_id()
        self.connection.send_headers(
            stream_id,
            [
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", HOSTNAME.encode()),
                (b":path", path.encode()),
            ],
            end_stream=True,
        )
        await self.flush()
        await self.wait(lambda: self.stream_events(stream_id, StreamEnded))
        return b"".join(
            event.data for event in self.stream_events(stream_id, DataReceived)
        )

    async def send_all(self, stream_id, data):
        view = memoryview(data)
        while view:
            window = min(
                self.connection.local_flow_control_window(stream_id),
                self.connection.max_outbound_frame_size,
            )
            if window <= 0:
                await self.wait_for_window(len(self.events))
                continue
            self.connection.send_data(stream_id, bytes(view[:window]))
            view = view[window:]
            await self.flush()

    async def wait_for_window(self, seen):
        await self.wait(
            lambda: any(
                isinstance(event, WindowUpdated) for event in self.events[seen:]
            )
        )

    async def close(self):
        if self.task is not None:
            self.task.cancel()
            with contextlib.suppress(asyncio.CancelledError, ConnectionError):
                await self.task
        self.writer.close()


class ScriptedBrowser:
    """Loads the capture page, then opens its WebSocket like a browser would."""

    def __init__(
        self,
        page_url,
        *,
        connect_fields=None,
        priority=None,
        upgrade_fields=None,
        send_policy=None,
        fallback_alpn=("http/1.1",),
    ):
        self.page_url = page_url
        self.connect_fields = connect_fields
        self.priority = priority or {}
        self.upgrade_fields = upgrade_fields
        self.send_policy = send_policy or SendPolicy()
        self.fallback_alpn = fallback_alpn
        self.page_client = None
        self.socket_client = None

    async def run(self):
        parts = urlsplit(self.page_url)
        target = f"{parts.path}?{parts.query}"
        if parts.scheme == "https":
            self.page_client = await ScriptedH2.open(parts.port)
            body = await self.page_client.get(target)
        else:
            body = await http1_get(parts.port, target)
        socket_url = re.search(rb'const socketUrl = "([^"]+)"', body).group(1)
        done = re.search(rb'const doneUrl = "([^"]+)"', body).group(1).decode()
        result = await self.websocket(urlsplit(socket_url.decode()))
        done_target = done + "&" + urlencode(result)
        if self.page_client is not None:
            await self.page_client.get(done_target)
        else:
            await http1_get(parts.port, done_target)

    async def websocket(self, url):
        client = self.page_client
        if url.scheme == "wss" and client is None and "h2" in self.fallback_alpn:
            client = self.socket_client = await ScriptedH2.open(url.port)
        if (
            url.scheme == "wss"
            and client is not None
            and client.connection.remote_settings.get(8) == 1
        ):
            return await self.h2_websocket(client, url)
        return await self.h1_websocket(url)

    async def h2_websocket(self, client, url):
        for _ in range(2):
            stream_id = client.connection.get_next_available_stream_id()
            fields = self.connect_fields or [
                (b":method", b"CONNECT"),
                (b":protocol", b"websocket"),
                (b":scheme", b"https"),
                (b":path", f"{url.path}?{url.query}".encode()),
                (b":authority", url.netloc.encode()),
                (b"sec-websocket-version", b"13"),
                (b"sec-websocket-extensions", b"permessage-deflate"),
            ]
            path = f"{url.path}?{url.query}".encode()
            fields = [
                item
                if isinstance(item, NeverIndexedHeaderTuple)
                else (item[0], item[1].replace(b"{path}", path))
                for item in fields
            ]
            client.connection.send_headers(stream_id, fields, **self.priority)
            await client.flush()
            await client.wait(
                lambda stream_id=stream_id: (
                    client.stream_events(stream_id, ResponseReceived)
                    or client.stream_events(stream_id, StreamReset)
                )
            )
            if client.stream_events(stream_id, StreamReset):
                continue
            [response] = client.stream_events(stream_id, ResponseReceived)
            headers = dict(response.headers)
            if headers[b":status"] != b"200" or headers.get(
                b"sec-websocket-extensions", b"permessage-deflate"
            ) not in {b"permessage-deflate"}:
                with contextlib.suppress(Exception):
                    client.connection.reset_stream(stream_id, ErrorCodes.CANCEL)
                    await client.flush()
                return {"opened": "false", "code": "1006"}
            return await self.exchange_h2(client, stream_id)
        return {"opened": "false", "code": "1006"}

    async def exchange_h2(self, client, stream_id):
        compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
        for message in CORPUS:
            await client.send_all(
                stream_id,
                self.send_policy.frames(compressor, message.opcode, message.payload),
            )
        reader = FrameReader()
        received = []
        consumed = 0

        def echoes():
            nonlocal consumed
            events = client.stream_events(stream_id, DataReceived)
            for event in events[consumed:]:
                received.extend(reader.feed(event.data))
            consumed = len(events)
            return len(received)

        await client.wait(lambda: echoes() >= len(CORPUS))
        await client.send_all(stream_id, client_frame(CLOSE, b"\x03\xe8"))
        await client.wait(lambda: echoes() > len(CORPUS))
        return {"opened": "true", "code": "1000", "echoed": str(len(CORPUS))}

    async def h1_websocket(self, url):
        if url.scheme == "wss":
            reader, writer = await asyncio.open_connection(
                "127.0.0.1",
                url.port,
                ssl=client_context(self.fallback_alpn),
                server_hostname=HOSTNAME,
            )
        else:
            reader, writer = await asyncio.open_connection("127.0.0.1", url.port)
        try:
            target = f"{url.path}?{url.query}"
            fields = self.upgrade_fields or [
                f"Host: {url.netloc}".encode(),
                b"Connection: Upgrade",
                b"Upgrade: websocket",
                b"Sec-WebSocket-Version: 13",
                b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
                b"Sec-WebSocket-Extensions: permessage-deflate",
            ]
            writer.write(
                b"\r\n".join([f"GET {target} HTTP/1.1".encode(), *fields]) + b"\r\n\r\n"
            )
            await writer.drain()
            head = await reader.readuntil(b"\r\n\r\n")
            if not head.startswith(b"HTTP/1.1 101"):
                return {"opened": "false", "code": "1006"}
            compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
            for message in CORPUS:
                writer.write(
                    self.send_policy.frames(compressor, message.opcode, message.payload)
                )
            writer.write(client_frame(CLOSE, b"\x03\xe8"))
            await writer.drain()
            frames = FrameReader()
            received = []
            while not any(frame.opcode == CLOSE for frame in received):
                data = await reader.read(65536)
                if not data:
                    break
                received.extend(frames.feed(data))
            return {"opened": "true", "code": "1000", "echoed": str(len(received) - 1)}
        finally:
            writer.close()


async def http1_get(port, target):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(
            f"GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode()
        )
        await writer.drain()
        head = await reader.readuntil(b"\r\n\r\n")
        length = int(re.search(rb"content-length: (\d+)", head).group(1))
        return await reader.readexactly(length)
    finally:
        writer.close()


def driver(**options):
    @contextlib.asynccontextmanager
    async def drive(url):
        browser = ScriptedBrowser(url, **options)
        task = asyncio.create_task(browser.run())
        try:
            yield
            await asyncio.wait_for(task, TIMEOUT)
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, ConnectionError):
                await task
            for client in (browser.page_client, browser.socket_client):
                if client is not None:
                    await client.close()

    return drive


async def capture(name, **options):
    server = CaptureServer(CERTIFICATE)
    await server.start("127.0.0.1")
    try:
        [run] = await capture_scenario(
            server,
            SCENARIOS[name],
            repeat=1,
            run_timeout=TIMEOUT,
            observation_seconds=0.2,
            drive=driver(**options),
        )
        return run
    finally:
        await server.close()


def fixture_fields(text):
    fields = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in fields:
            raise AssertionError(f"invalid fixture line: {line!r}")
        fields[key] = value
    return fields


def h2_connection(run):
    return next(
        record
        for record in run.connections
        if record.protocol == "h2" and record.client_chunks
    )


def frame_log(run, record):
    return [
        (frame.direction, frame.type_name, frame.stream_id, frame_details(frame))
        for frame in analyze_http2(record).frames
    ]


class Http2WebSocketTests(unittest.TestCase):
    def test_connect_headers_retain_representation_and_order(self) -> None:
        fields = [
            (b":method", b"CONNECT"),
            (b":scheme", b"https"),
            (b":authority", HOSTNAME.encode()),
            (b":path", b"{path}"),
            (b":protocol", b"websocket"),
            NeverIndexedHeaderTuple(b"x-phantom-secretish", b"value"),
            (b"sec-websocket-version", b"13"),
        ]
        run = asyncio.run(
            capture(
                "accept",
                connect_fields=fields,
                priority={
                    "priority_weight": 147,
                    "priority_depends_on": 0,
                    "priority_exclusive": True,
                },
            )
        )

        analysis = analyze_http2(h2_connection(run))
        connect = next(
            block
            for block in analysis.client_headers
            if block.field(b":method") == b"CONNECT"
        )
        self.assertEqual(
            [item.name for item in connect.fields],
            [name for name, _ in fields],
        )
        self.assertEqual(connect.fields[5].representation, "never-indexed")
        self.assertEqual(connect.fields[0].representation, "incremental")
        self.assertEqual(
            (connect.priority.exclusive, connect.priority.weight), (True, 147)
        )
        self.assertTrue(connect.flags & 0x20)
        text = fixture(SCENARIOS["accept"], [run], METADATA)
        lines = fixture_fields(text)
        self.assertEqual(lines["format"], FORMAT)
        key = next(
            name[: -len("_field_order")]
            for name, value in lines.items()
            if name.endswith("_field_order") and ":protocol" in value
        )
        self.assertEqual(
            lines[key + "_field_order"],
            ":method,:scheme,:authority,:path,:protocol,x-phantom-secretish,"
            "sec-websocket-version",
        )
        self.assertIn("priority:exclusive:true,depends_on:0,weight:147", lines[key])
        self.assertEqual(bytes.fromhex(lines[key + "_block_hex"]), connect.block)
        self.assertTrue(lines[key + "_field_5"].startswith("repr:never-indexed,"))

    def test_hpack_walker_classifies_every_representation(self) -> None:
        def literal(text):
            return bytes([len(text)]) + text

        block = (
            b"\x3f\xe1\x1f"  # size update to 4096
            + b"\x82"  # indexed :method GET
            + b"\x44"
            + literal(b"/a")  # incremental, indexed name :path
            + b"\x00"
            + literal(b"x-plain")
            + literal(b"1")  # without indexing, new name
            + b"\x10"
            + literal(b"x-never")
            + literal(b"2")  # never indexed, new name
        )
        from hpack import Decoder

        fields = decode_header_block(Decoder(), block)

        self.assertEqual(
            [item.representation for item in hpack_representations(block)],
            [
                "size-update",
                "indexed",
                "incremental",
                "without-indexing",
                "never-indexed",
            ],
        )
        self.assertEqual(
            [(item.name, item.value) for item in fields],
            [
                (None, None),
                (b":method", b"GET"),
                (b":path", b"/a"),
                (b"x-plain", b"1"),
                (b"x-never", b"2"),
            ],
        )
        self.assertEqual(fields[0].index, 4096)
        self.assertEqual((fields[3].index, fields[3].name_huffman), (0, False))

    def test_missing_connect_protocol_records_http1_fallback_connection(self) -> None:
        run = asyncio.run(capture("no-connect-protocol"))

        page_connection = run.connections[0]
        [settings] = [
            details
            for direction, kind, _, details in frame_log(run, page_connection)
            if direction == "server" and kind == "SETTINGS" and details
        ]
        self.assertNotIn("8=", settings[0])
        fallback = run.connections[1]
        self.assertEqual(fallback.client_hello.alpn_offer, ("http/1.1",))
        self.assertEqual(fallback.protocol, "http/1.1")
        [websocket] = run.websockets
        self.assertEqual((websocket.protocol, websocket.connection), ("http/1.1", 1))
        upgrade = run.requests[websocket.request]
        self.assertEqual(
            upgrade.header_lines[1:3], [b"Connection: Upgrade", b"Upgrade: websocket"]
        )
        lines = fixture_fields(
            fixture(SCENARIOS["no-connect-protocol"], [run], METADATA)
        )
        self.assertIn("alpn_offer:http/1.1,", lines["run_0_connection_1"])
        self.assertEqual(
            bytes.fromhex(lines[f"run_0_request_{websocket.request}_header_1"]),
            b"Connection: Upgrade",
        )

    def test_rejected_connect_records_stream_termination(self) -> None:
        run = asyncio.run(capture("reject-403"))

        [websocket] = run.websockets
        self.assertEqual((websocket.outcome, websocket.status), ("rejected", 403))
        stream = websocket.stream_id
        log = [
            (direction, kind, details)
            for direction, kind, stream_id, details in frame_log(
                run, h2_connection(run)
            )
            if stream_id == stream
        ]
        self.assertEqual(log[0][:2], ("client", "HEADERS"))
        self.assertEqual(log[1][:2], ("server", "HEADERS"))
        self.assertIn(("server", "DATA"), [entry[:2] for entry in log])
        self.assertEqual(log[-1], ("client", "RST_STREAM", ["error:CANCEL"]))
        self.assertEqual(run.results[0]["opened"], "false")

    def test_refused_stream_records_reset_and_retry(self) -> None:
        run = asyncio.run(capture("refused-stream"))

        refused, retried = run.websockets
        self.assertEqual((refused.outcome, retried.outcome), ("refused", "accepted"))
        self.assertIn(
            ("server", "RST_STREAM", refused.stream_id, ["error:REFUSED_STREAM"]),
            frame_log(run, h2_connection(run)),
        )
        self.assertGreater(retried.stream_id, refused.stream_id)
        lines = fixture_fields(fixture(SCENARIOS["refused-stream"], [run], METADATA))
        self.assertIn("outcome:refused", lines["run_0_websocket_0"])
        self.assertEqual(lines["run_0_websocket_1_message_count"], str(len(CORPUS)))

    def test_send_policy_records_rsv1_per_message(self) -> None:
        policy = SendPolicy(compress_at_least=100, fragment_size=40000)

        run = asyncio.run(capture("accept-deflate", send_policy=policy))

        [websocket] = run.websockets
        self.assertEqual(websocket.selected_extensions, b"permessage-deflate")
        lines = fixture_fields(fixture(SCENARIOS["accept-deflate"], [run], METADATA))
        messages = [lines[f"run_0_websocket_0_message_{index}"] for index in range(5)]
        self.assertEqual(
            [re.search(r"rsv1:(\w+)", message).group(1) for message in messages],
            ["false", "false", "true", "true", "true"],
        )
        self.assertEqual(
            [re.search(r"corpus:(\w+)", message).group(1) for message in messages],
            ["0", "1", "2", "3", "4"],
        )
        self.assertIn("frame_lengths:40000;", messages[3])
        self.assertNotIn("wire_length:1048576", messages[4])
        self.assertIn("decoded_length:1048576", messages[4])
        self.assertEqual(
            lines["run_0_websocket_0_control_0"],
            "opcode:8,length:2,close_code:1000,after_message:5",
        )

    def test_extension_mismatch_records_unoffered_selection(self) -> None:
        run = asyncio.run(capture("extension-mismatch"))

        [websocket] = run.websockets
        self.assertEqual(websocket.outcome, "extension-mismatch")
        lines = fixture_fields(
            fixture(SCENARIOS["extension-mismatch"], [run], METADATA)
        )
        self.assertEqual(
            bytes.fromhex(lines["run_0_websocket_0_extensions_selected_hex"]),
            b"x-phantom-unoffered",
        )
        self.assertEqual(lines["run_0_websocket_0_message_count"], "0")

    def test_fresh_origin_records_first_connection_alpn_offer(self) -> None:
        run = asyncio.run(capture("fresh-origin", fallback_alpn=("h2", "http/1.1")))

        tls = [record for record in run.connections if record.listener == "tls"]
        self.assertEqual(tls[0].client_hello.alpn_offer, ("h2", "http/1.1"))
        self.assertEqual(tls[0].client_hello.server_name, HOSTNAME)
        self.assertEqual(tls[0].alpn, "h2")

    def test_http1_upgrade_records_request_lines_in_order(self) -> None:
        fields = [
            b"Host: 127.0.0.1",
            b"upgrade: websocket",
            b"X-Order: 1",
            b"CONNECTION: Upgrade",
            b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
            b"Sec-WebSocket-Version: 13",
            b"Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits",
        ]

        run = asyncio.run(
            capture(
                "h1-accept-deflate",
                upgrade_fields=fields,
                send_policy=SendPolicy(compress_at_least=1),
            )
        )

        [websocket] = run.websockets
        self.assertEqual(run.requests[websocket.request].header_lines, fields)
        lines = fixture_fields(fixture(SCENARIOS["h1-accept-deflate"], [run], METADATA))
        self.assertIn("rsv1:false", lines["run_0_websocket_0_message_0"])
        self.assertIn("rsv1:true", lines["run_0_websocket_0_message_1"])
        self.assertEqual(lines["run_0_websocket_0_message_count"], "5")

    def test_fixture_refuses_credential_bearing_fields(self) -> None:
        cases = {
            "accept": {
                "connect_fields": [
                    (b":method", b"CONNECT"),
                    (b":protocol", b"websocket"),
                    (b":scheme", b"https"),
                    (b":path", b"{path}"),
                    (b":authority", HOSTNAME.encode()),
                    (b"cookie", b"session=secret"),
                ]
            },
            "h1-accept": {
                "upgrade_fields": [
                    b"Host: 127.0.0.1",
                    b"Connection: Upgrade",
                    b"Upgrade: websocket",
                    b"Authorization: Basic cGhhbnRvbTo=",
                    b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
                ]
            },
        }
        for name, options in cases.items():
            with self.subTest(scenario=name):
                run = asyncio.run(capture(name, **options))
                with self.assertRaises(ValueError):
                    fixture(SCENARIOS[name], [run], METADATA)

    def test_page_rebuilds_the_retained_corpus(self) -> None:
        body = page("wss://example.test/echo", "token").decode()

        self.assertIn(f"xorshift32({0x5048414E}, {len(CORPUS[3].payload)})", body)
        self.assertIn(f"new Uint8Array({len(CORPUS[4].payload)})", body)
        self.assertEqual([len(message.payload) for message in CORPUS][:3], [0, 1, 100])

    def test_listener_rejects_non_loopback_address(self) -> None:
        with self.assertRaises(ValueError):
            asyncio.run(CaptureServer(CERTIFICATE).start("0.0.0.0"))
        for listen in ("192.0.2.1", "not-an-address"):
            with self.subTest(listen=listen), self.assertRaises(SystemExit):
                main(
                    [
                        "--browser",
                        "manual",
                        "--client-version",
                        "0",
                        "--listen",
                        listen,
                        "--output-dir",
                        "unused",
                    ]
                )

    def test_catalog_names_are_unique(self) -> None:
        self.assertEqual(len({scenario.name for scenario in CATALOG}), len(CATALOG))


if __name__ == "__main__":
    unittest.main()
