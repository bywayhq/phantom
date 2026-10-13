import asyncio
import contextlib
import dataclasses
import errno
import re
import ssl
import unittest
import zlib
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlencode, urlsplit

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.errors import ErrorCodes
from h2.events import (
    DataReceived,
    RemoteSettingsChanged,
    RequestReceived,
    ResponseReceived,
    StreamEnded,
    StreamReset,
    WindowUpdated,
)
from hpack import NeverIndexedHeaderTuple

from scripts.capture.http2_analysis import (
    Http2Frame,
    analyze_http2,
    decode_header_block,
    frame_details,
    hpack_representations,
    parse_priority,
    split_frames,
    strip_padding,
)
from scripts.capture.http2_session import (
    HOSTNAME,
    CaptureRun,
    CaptureServer,
    ClientHello,
    ConnectionRecord,
    Http1Session,
    MalformedCaptureError,
    PlainChannel,
    generate_certificate,
    peer_disconnected,
)
from scripts.capture.http2_websocket import (
    CATALOG,
    CORPUS,
    FORMAT,
    SCENARIOS,
    CaptureMetadata,
    capture_scenario,
    fixture,
    launch_plan,
    main,
    page,
    urls,
)
from scripts.capture.http2_websocket import (
    run as run_capture,
)
from scripts.capture.websocket_frames import (
    CLOSE,
    DEFLATE_TAIL,
    EchoPeer,
    FrameReader,
    client_frame,
    encode_frame,
    summarize_send_policy,
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
PEER_CLEANUP_TIMEOUT = 5.0


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


class ScriptedPeerFailures(Exception):
    def __init__(self, primary, cleanup, owner):
        self.primary = primary
        self.cleanup = tuple(cleanup)
        self.owner = owner
        self.previous_cause = primary.__cause__ if primary is not None else None
        self.previous_context = primary.__context__ if primary is not None else None
        super().__init__("scripted WebSocket peer cleanup failed")


def raise_scripted_failures(primary, cleanup, owner):
    cleanup = [error for error in cleanup if error is not primary]
    if cleanup:
        packet = ScriptedPeerFailures(primary, cleanup, owner)
        if primary is not None:
            raise primary from packet
        raise cleanup[0] from packet

    if primary is not None:
        raise primary


class ScriptedH2:
    """A minimal H2 client over TLS with a background frame pump."""

    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.events = []
        self.changed = asyncio.Event()
        self.settings_received = False
        self.task = None
        self.pump_observed = False
        self.cancel_requested = False
        self.close_task = None
        self.closed = None
        self.failures = []
        self.connection = H2Connection(
            H2Configuration(client_side=True, header_encoding=None)
        )

    @classmethod
    async def open(cls, port):
        reader, writer = await asyncio.open_connection(
            "127.0.0.1",
            port,
            ssl=client_context(("h2", "http/1.1")),
            server_hostname=HOSTNAME,
        )
        client = cls.__new__(cls)
        try:
            client.__init__(reader, writer)
            client.connection.initiate_connection()
            await client.flush()
            work = client.pump()
            try:
                client.task = asyncio.create_task(work)
            except BaseException:
                work.close()
                raise
            await client.wait(lambda: client.settings_received)
        except BaseException as error:
            await client.close(error)
        return client

    async def flush(self):
        data = self.connection.data_to_send()
        if data:
            self.writer.write(data)
            await self.writer.drain()

    async def pump(self):
        try:
            while True:
                data = await self.reader.read(65536)
                if not data:
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
        finally:
            self.changed.set()

    async def wait(self, predicate):
        async def loop():
            while not predicate():
                if self.task is not None and self.task.done():
                    self.task.result()
                    raise EOFError("scripted HTTP2 peer ended before its response")

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

    def failed(self, error):
        if not any(previous is error for previous in self.failures):
            self.failures.append(error)

    async def collect(self, task):
        deadline = asyncio.get_running_loop().time() + PEER_CLEANUP_TIMEOUT
        while not task.done():
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                self.failed(
                    TimeoutError("scripted HTTP2 peer cleanup is still pending")
                )
                return False
            try:
                await asyncio.wait((task,), timeout=remaining)
            except BaseException as error:
                self.failed(error)
        return True

    async def close_work(self):
        if self.task is not None and self.task.done() and not self.pump_observed:
            self.observe_pump()

        if self.task is not None and not self.task.done():
            self.cancel_requested = True
            self.task.cancel()

        try:
            self.writer.close()
        except BaseException as error:
            self.failed(error)
            try:
                self.writer.transport.abort()
            except BaseException as cleanup:
                self.failed(cleanup)

        if self.closed is None:
            work = self.writer.wait_closed()
            try:
                self.closed = asyncio.create_task(work)
            except BaseException as error:
                work.close()
                self.failed(error)

        if (
            self.task is not None
            and not self.pump_observed
            and await self.collect(self.task)
        ):
            self.observe_pump()

        if self.closed is not None and await self.collect(self.closed):
            try:
                self.closed.result()
            except BaseException as error:
                if not peer_disconnected(error) or error.__cause__ is not None:
                    self.failed(error)

    def observe_pump(self):
        self.pump_observed = True
        try:
            self.task.result()
        except asyncio.CancelledError as error:
            if not self.cancel_requested or error.__cause__ is not None:
                self.failed(error)
        except BaseException as error:
            self.failed(error)

    def start_close(self):
        if self.close_task is None or self.close_task.done():
            work = self.close_work()
            try:
                self.close_task = asyncio.create_task(work)
            except BaseException as error:
                work.close()
                self.failed(error)

    async def close(self, primary=None):
        self.start_close()
        if self.close_task is not None and await self.collect(self.close_task):
            try:
                self.close_task.result()
            except BaseException as error:
                self.failed(error)

        if primary is None and self.failures:
            primary = self.failures[0]
        raise_scripted_failures(primary, self.failures, self)


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
        self.task = None
        self.cancel_requested = False
        self.close_task = None
        self.writers = []
        self.closed = {}
        self.failures = []

    def failed(self, error):
        if not any(previous is error for previous in self.failures):
            self.failures.append(error)

    async def collect(self, task):
        deadline = asyncio.get_running_loop().time() + PEER_CLEANUP_TIMEOUT
        while not task.done():
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                self.failed(TimeoutError("scripted browser cleanup is still pending"))
                return False
            try:
                await asyncio.wait((task,), timeout=remaining)
            except BaseException as error:
                self.failed(error)
        return True

    async def retire(self, writer, primary=None):
        failures = []
        try:
            writer.close()
        except BaseException as error:
            failures.append(error)
            self.failed(error)
            try:
                writer.transport.abort()
            except BaseException as cleanup:
                failures.append(cleanup)
                self.failed(cleanup)

        waiter = self.closed.get(writer)
        if waiter is None:
            work = writer.wait_closed()
            try:
                waiter = asyncio.create_task(work)
                self.closed[writer] = waiter
            except BaseException as error:
                work.close()
                failures.append(error)
                self.failed(error)

        if waiter is not None:
            seen = len(self.failures)
            collected = await self.collect(waiter)
            failures.extend(self.failures[seen:])
            if collected:
                try:
                    waiter.result()
                except BaseException as error:
                    if not peer_disconnected(error) or error.__cause__ is not None:
                        failures.append(error)
                        self.failed(error)

        raise_scripted_failures(primary, failures, self)

    async def close_work(self):
        if self.task is not None and not self.task.done():
            self.cancel_requested = True
            self.task.cancel()

        for writer in self.writers:
            try:
                writer.close()
            except BaseException as error:
                self.failed(error)
                try:
                    writer.transport.abort()
                except BaseException as cleanup:
                    self.failed(cleanup)

        for client in (self.page_client, self.socket_client):
            if client is not None:
                client.start_close()

        for client in (self.page_client, self.socket_client):
            if client is not None:
                try:
                    await client.close()
                except BaseException as error:
                    self.failed(error)

        for writer in self.writers:
            try:
                await self.retire(writer)
            except BaseException as error:
                self.failed(error)

        if self.task is not None and await self.collect(self.task):
            try:
                self.task.result()
            except asyncio.CancelledError as error:
                if not self.cancel_requested or error.__cause__ is not None:
                    self.failed(error)
            except BaseException as error:
                self.failed(error)

    async def close(self, primary=None):
        if self.close_task is None or self.close_task.done():
            work = self.close_work()
            try:
                self.close_task = asyncio.create_task(work)
            except BaseException as error:
                work.close()
                self.failed(error)

        if self.close_task is not None and await self.collect(self.close_task):
            try:
                self.close_task.result()
            except BaseException as error:
                self.failed(error)

        if primary is None and self.failures:
            primary = self.failures[0]
        raise_scripted_failures(primary, self.failures, self)

    async def run(self):
        parts = urlsplit(self.page_url)
        target = f"{parts.path}?{parts.query}"
        if parts.scheme == "https":
            self.page_client = await ScriptedH2.open(parts.port)
            body = await self.page_client.get(target)
        else:
            body = await http1_get(parts.port, target, self)
        socket_url = re.search(rb'const socketUrl = "([^"]+)"', body).group(1)
        done = re.search(rb'const doneUrl = "([^"]+)"', body).group(1).decode()
        result = await self.websocket(urlsplit(socket_url.decode()))
        done_target = done + "&" + urlencode(result)
        if self.page_client is not None:
            await self.page_client.get(done_target)
        else:
            await http1_get(parts.port, done_target, self)

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
        self.writers.append(writer)
        primary = None
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
        except BaseException as error:
            primary = error
            raise
        finally:
            await self.retire(writer, primary)


async def http1_get(port, target, browser):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    browser.writers.append(writer)
    primary = None
    try:
        writer.write(
            f"GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode()
        )
        await writer.drain()
        head = await reader.readuntil(b"\r\n\r\n")
        length = int(re.search(rb"content-length: (\d+)", head).group(1))
        return await reader.readexactly(length)
    except BaseException as error:
        primary = error
        raise
    finally:
        await browser.retire(writer, primary)


def driver(**options):
    @contextlib.asynccontextmanager
    async def drive(url):
        browser = ScriptedBrowser(url, **options)
        primary = None
        work = browser.run()
        try:
            browser.task = asyncio.create_task(work)
            yield
            done, _ = await asyncio.wait((browser.task,), timeout=TIMEOUT)
            if not done:
                raise TimeoutError("scripted browser did not complete")
            browser.task.result()
        except BaseException as error:
            primary = error
            if browser.task is None:
                work.close()
        await browser.close(primary)

    return drive


async def capture(name, **options):
    server = CaptureServer(CERTIFICATE)
    primary = None
    cleanup = []
    try:
        await server.start("127.0.0.1")
        [run] = await capture_scenario(
            server,
            SCENARIOS[name],
            repeat=1,
            run_timeout=TIMEOUT,
            observation_seconds=0.2,
            drive=driver(**options),
        )
    except BaseException as error:
        primary = error

    try:
        await server.close()
    except BaseException as error:
        cleanup.append(error)
    raise_scripted_failures(primary, cleanup, server)
    return run


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


class CaptureBoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def test_same_batch_cancelled_requests_leave_another_stream_usable(self):
        server = CaptureServer(CERTIFICATE)
        await server.start("127.0.0.1")
        run = CaptureRun("cancel", SCENARIOS["accept"].policy, {"tls": b"usable"})
        server.begin_run(run)
        client = None
        batches = []
        original_receive = H2Connection.receive_data

        def receive(connection, data):
            events = original_receive(connection, data)
            if not connection.config.client_side:
                batches.append(events)
            return events

        fields = [
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", HOSTNAME.encode()),
            (b":path", b"/ws.html?run=cancel"),
        ]
        try:
            client = await ScriptedH2.open(server.tls_address[1])
            client.connection.send_headers(1, fields, end_stream=True)
            client.connection.reset_stream(1, ErrorCodes.CANCEL)
            client.connection.send_headers(
                3,
                [
                    (b":method", b"CONNECT"),
                    (b":protocol", b"websocket"),
                    (b":scheme", b"https"),
                    (b":authority", HOSTNAME.encode()),
                    (b":path", b"/echo?run=cancel"),
                    (b"sec-websocket-version", b"13"),
                ],
            )
            client.connection.reset_stream(3, ErrorCodes.CANCEL)
            client.connection.send_headers(5, fields, end_stream=True)
            with patch.object(H2Connection, "receive_data", receive):
                await client.flush()
                await client.wait(lambda: client.stream_events(5, StreamEnded))

            self.assertTrue(
                any(
                    {
                        event.stream_id
                        for event in batch
                        if isinstance(event, RequestReceived)
                    }
                    == {1, 3, 5}
                    and {
                        event.stream_id
                        for event in batch
                        if isinstance(event, StreamReset)
                    }
                    == {1, 3}
                    for batch in batches
                ),
                "the original native input did not contain one complete cancellation batch",
            )
            [response] = client.stream_events(5, ResponseReceived)
            self.assertEqual(dict(response.headers)[b":status"], b"200")
            self.assertEqual(
                b"".join(event.data for event in client.stream_events(5, DataReceived)),
                b"usable",
            )
            self.assertEqual(run.request_count, 3)
            self.assertEqual(run.websockets, [])
            self.assertEqual(
                [
                    block.stream_id
                    for block in analyze_http2(run.connections[0]).client_headers
                ],
                [1, 3, 5],
            )
            self.assertEqual(server.accept_failures, [])
        finally:
            if client is not None:
                await client.close()
            server.run = None
            await server.close()

    async def test_complete_request_head_accepts_65536_and_rejects_65537(self):
        for size in (65536, 65537):
            prefix = b"GET / HTTP/1.1\r\nX-Padding: "
            head = prefix + b"x" * (size - len(prefix) - 4) + b"\r\n\r\n"
            reader = asyncio.StreamReader()
            reader.feed_data(head)
            reader.feed_eof()
            record = ConnectionRecord("plain", 0.0)
            run = CaptureRun("boundary", SCENARIOS["h1-accept"].policy, {})
            session = Http1Session(
                PlainChannel(reader, None, record, run.now), run, 0, "http/1.1"
            )
            with self.subTest(size=size):
                if size == 65536:
                    self.assertEqual(await session.read_head(), head)
                else:
                    with self.assertRaisesRegex(ValueError, "request head exceeds"):
                        await session.read_head()

    def test_complete_client_hello_vectors_are_checked_without_losing_partial_input(
        self,
    ):
        valid = b"\x03\x03" + bytes(32) + b"\x00\x00\x02\x13\x01\x01\x00\x00\x00"
        for body in (valid[:34], valid[:-1], valid + b"x"):
            handshake = b"\x01" + len(body).to_bytes(3, "big") + body
            wire = b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake
            hello = ClientHello()
            hello.feed(wire[:-1])
            self.assertFalse(hello.complete)
            with self.assertRaises(MalformedCaptureError):
                hello.feed(wire[-1:])
        handshake = b"\x01" + len(valid).to_bytes(3, "big") + valid
        hello = ClientHello()
        hello.feed(b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake)
        self.assertTrue(hello.complete)

    def test_h2_extents_and_continuation_stream_are_checked(self):
        with self.assertRaises(MalformedCaptureError):
            strip_padding(Http2Frame("client", 0, 0, 8, 1, b""))
        with self.assertRaises(MalformedCaptureError):
            parse_priority(bytes(4))
        headers = b"\x00\x00\x01\x01\x00\x00\x00\x00\x01\x82"
        wrong_continuation = b"\x00\x00\x00\x09\x04\x00\x00\x00\x03"
        with self.assertRaisesRegex(MalformedCaptureError, "matching header block"):
            split_frames([(0, headers + wrong_continuation)], "client", preface=False)
        frames, trailing = split_frames([(0, headers[:-1])], "client", preface=False)
        self.assertEqual(frames, [])
        self.assertEqual(trailing, 9)

    def test_decoded_messages_and_frame_retention_have_finite_limits(self):
        compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
        raw = b"x" * (16 * 1024 * 1024 + 1)
        compressed = compressor.compress(raw) + compressor.flush(zlib.Z_SYNC_FLUSH)
        wire = encode_frame(2, compressed[:-4], rsv1=True, mask=b"1234")
        with self.assertRaisesRegex(ValueError, "decoded WebSocket bytes"):
            EchoPeer(inflate=True).feed(wire)
        with self.assertRaisesRegex(ValueError, "decoded WebSocket bytes"):
            summarize_send_policy(wire, inflate=True)
        with self.assertRaisesRegex(ValueError, "frame count"):
            FrameReader().feed(b"\x89\x00" * 16385)

    async def test_nonfinite_durations_fail_before_certificate_or_listener_acquisition(
        self,
    ):
        for timeout, observation in (
            (float("nan"), 0),
            (float("inf"), 0),
            (1, float("inf")),
            (1, -1),
        ):
            args = SimpleNamespace(
                repeat=1,
                run_timeout=timeout,
                observation=observation,
                browser="manual",
                listen="127.0.0.1",
                scenario=["h1-accept"],
            )
            with patch(
                "scripts.capture.http2_websocket.generate_certificate"
            ) as acquire:
                with self.assertRaises(ValueError):
                    await run_capture(args)
                acquire.assert_not_called()

    async def test_ipv6_listener_page_urls_and_firefox_routes_agree(self):
        server = CaptureServer(CERTIFICATE)
        try:
            await server.start("::1")
        except OSError as error:
            if error.errno in (errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL):
                self.skipTest("native runner does not provide IPv6 loopback")
            raise
        writer = None
        try:
            run = CaptureRun("ipv6", SCENARIOS["h1-accept"].policy, {})
            page_url, socket_url = urls(server, SCENARIOS["h1-accept"], run.token)
            run.pages = {"plain": page(socket_url, run.token)}
            server.begin_run(run)
            self.assertEqual(urlsplit(page_url).hostname, "::1")
            self.assertEqual(urlsplit(socket_url).hostname, "::1")
            reader, writer = await asyncio.open_connection(
                "::1", server.plain_address[1]
            )
            writer.write(b"GET /ws.html?run=ipv6 HTTP/1.1\r\nHost: [::1]\r\n\r\n")
            await writer.drain()
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), TIMEOUT)
            length = int(re.search(rb"content-length: (\d+)", head).group(1))
            body = await asyncio.wait_for(reader.readexactly(length), TIMEOUT)
            self.assertEqual(body, run.pages["plain"])
            args = SimpleNamespace(
                browser="firefox",
                browser_path=None,
                headful=False,
                firefox_skip_tls_trust=True,
            )
            plan = launch_plan(args, CERTIFICATE, "::1", server.tls_address[1])
            self.assertFalse(dict(plan.firefox_preferences)["network.dns.disableIPv6"])
        finally:
            if writer is not None:
                writer.close()
                await writer.wait_closed()
            server.run = None
            await server.close()


if __name__ == "__main__":
    unittest.main()
