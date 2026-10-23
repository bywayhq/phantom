"""Record HTTP/3 resource requests and replayable client streams."""

from __future__ import annotations

import asyncio
import json
import re
import secrets
from collections.abc import Sequence
from dataclasses import dataclass, field
from importlib import metadata

import pylsqpack
from aioquic.asyncio import QuicConnectionProtocol
from aioquic.asyncio.server import QuicServer
from aioquic.h3.connection import H3Connection, Setting
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import (
    ConnectionTerminated,
    ProtocolNegotiated,
    StreamDataReceived,
    StreamReset,
)

from . import http_lifecycle as lifecycle
from .browser_launch import BrowserDriver
from .cookie_crumbs import (
    check_inserted_fields,
    encoder_instructions,
    qpack_integer,
)
from .fixture_file import write_text_fixture
from .http2_session import HOSTNAME, generate_certificate
from .http3_wire import is_h3_grease, parse_settings, pull_varint
from .http_lifecycle_resources import MAX_PEER_BYTES, SAFE_FIELDS, ResourceCapture
from .quic_resumption import load_certificate
from .reserved_ports import open_past_reserved_ports

MAX_EVENTS = 8192
MAX_STREAMS = 64


@dataclass(frozen=True)
class StreamEvent:
    stream: int
    offset: int
    data: bytes
    ended: bool


@dataclass
class StreamCapture:
    events: list[StreamEvent] = field(default_factory=list)
    streams: dict[int, bytearray] = field(default_factory=dict)
    ended: set[int] = field(default_factory=set)
    settings: dict[int, int] | None = None

    def retain(self, event: StreamDataReceived, resources: ResourceCapture) -> None:
        if len(self.events) >= MAX_EVENTS:
            raise ValueError("resource HTTP/3 stream event limit exceeded")
        if event.stream_id in self.ended:
            raise ValueError("resource HTTP/3 data arrived after stream FIN")
        if event.stream_id not in self.streams and len(self.streams) >= MAX_STREAMS:
            raise ValueError("resource HTTP/3 stream limit exceeded")
        if resources.retained + len(event.data) > MAX_PEER_BYTES:
            raise ValueError("resource peer bytes exceed the capture limit")
        data = self.streams.setdefault(event.stream_id, bytearray())
        self.events.append(
            StreamEvent(event.stream_id, len(data), bytes(event.data), event.end_stream)
        )
        data.extend(event.data)
        resources.retained += len(event.data)
        if event.end_stream:
            self.ended.add(event.stream_id)

    def replay(self, fields: dict[int, tuple[tuple[bytes, bytes], ...]]) -> None:
        """Decode retained request bytes independently of the live H3 connection."""
        if self.settings is None:
            raise ValueError("resource HTTP/3 server settings are missing")
        decoder = pylsqpack.Decoder(
            self.settings.get(Setting.QPACK_MAX_TABLE_CAPACITY, 0),
            self.settings.get(Setting.QPACK_BLOCKED_STREAMS, 0),
        )
        buffers: dict[int, bytearray] = {}
        offsets: dict[int, int] = {}
        kinds: dict[int, int] = {}
        critical: dict[int, int] = {}
        decoded: dict[int, tuple[tuple[bytes, bytes], ...]] = {}
        blocked: set[int] = set()
        headers: set[int] = set()
        control_settings = False

        def compare(stream: int, values: Sequence[tuple[bytes, bytes]]) -> None:
            actual = tuple(values)
            if stream in decoded or fields.get(stream) != actual:
                raise ValueError("resource HTTP/3 bytes disagree with owned fields")
            decoded[stream] = actual

        for event in self.events:
            data = buffers.setdefault(event.stream, bytearray())
            if len(data) != event.offset:
                raise ValueError("resource HTTP/3 stream offsets are inconsistent")
            data.extend(event.data)
            offset = offsets.get(event.stream, 0)
            if event.stream % 4 == 2:
                if event.stream not in kinds:
                    stream_type = pull_varint(data, 0)
                    if stream_type is None:
                        continue
                    kind, offset = stream_type
                    kinds[event.stream] = kind
                    if kind in {0, 2, 3}:
                        if kind in critical:
                            raise ValueError("resource HTTP/3 critical stream repeats")
                        critical[kind] = event.stream
                kind = kinds[event.stream]
                if kind in {0, 2, 3} and event.ended:
                    raise ValueError("resource HTTP/3 critical stream ended")
                if kind == 2:
                    for stream in decoder.feed_encoder(bytes(data[offset:])):
                        _, values = decoder.resume_header(stream)
                        blocked.remove(stream)
                        compare(stream, values)
                    offsets[event.stream] = len(data)
                    continue
                if kind == 3:
                    offsets[event.stream] = len(data)
                    continue
                if kind != 0:
                    if len(data) != offset:
                        raise ValueError("resource HTTP/3 unknown stream has payload")
                    offsets[event.stream] = offset
                    continue
            elif event.stream % 4 != 0:
                raise ValueError("resource HTTP/3 client stream ID is invalid")

            while offset < len(data):
                start = offset
                frame_type = pull_varint(data, offset)
                if frame_type is None:
                    break
                kind, width = frame_type
                offset += width
                frame_length = pull_varint(data, offset)
                if frame_length is None:
                    offset = start
                    break
                length, width = frame_length
                offset += width
                if length > len(data) - offset:
                    offset = start
                    break
                payload = bytes(data[offset : offset + length])
                offset += length
                if event.stream % 4 == 2:
                    if not control_settings:
                        if kind != 4:
                            raise ValueError("resource HTTP/3 control lacks SETTINGS")
                        parse_settings(payload)
                        control_settings = True
                    elif kind == 4:
                        raise ValueError("resource HTTP/3 SETTINGS repeats")
                    elif kind in {7, 13}:
                        value = pull_varint(payload, 0)
                        if value is None or value[1] != len(payload):
                            raise ValueError(
                                "resource HTTP/3 control identifier is malformed"
                            )
                    elif kind in {0xF0700, 0xF0701}:
                        value = pull_varint(payload, 0)
                        if (
                            value is None
                            or re.fullmatch(
                                rb"(?:u=[0-7](?:, i)?|i)", payload[value[1] :]
                            )
                            is None
                        ):
                            raise ValueError(
                                "resource HTTP/3 priority update is unsupported"
                            )
                    elif not is_h3_grease(kind):
                        raise ValueError(
                            "resource HTTP/3 control frame contains unapproved data"
                        )
                    continue
                if kind == 1:
                    if event.stream in headers:
                        raise ValueError("resource HTTP/3 request has trailers")
                    headers.add(event.stream)
                    try:
                        _, values = decoder.feed_header(event.stream, payload)
                    except pylsqpack.StreamBlocked:
                        blocked.add(event.stream)
                    else:
                        compare(event.stream, values)
                elif kind != 0 or payload:
                    raise ValueError("resource HTTP/3 request has unapproved data")
            offsets[event.stream] = offset

        if not control_settings or blocked or decoded != fields:
            raise ValueError("resource HTTP/3 request replay is incomplete")
        if any(offsets.get(stream, 0) != len(data) for stream, data in buffers.items()):
            raise ValueError("resource HTTP/3 stream ends with an incomplete frame")
        if any(stream not in self.ended for stream in fields):
            raise ValueError("resource HTTP/3 request stream is incomplete")
        encoder = self.streams.get(critical.get(2, -1), bytearray())
        instructions = encoder_instructions(bytes(encoder))
        check_inserted_fields(instructions)
        allowed_values = {value for values in fields.values() for _, value in values}
        inserted: dict[int, tuple[bytes, bytes]] = {}
        static_decoder = pylsqpack.Decoder(0, 0)
        for item in instructions:
            if item.inserted is None:
                continue
            if item.name is not None:
                name = item.name.decoded()
            elif item.table == "static":
                # Resolve the RFC static table through the same pinned decoder.
                index = item.index
                reference = (
                    bytes([0xC0 | index]) if index < 63 else bytes([0xFF, index - 63])
                )
                _, entry = static_decoder.feed_header(0, b"\x00\x00" + reference)
                name = entry[0][0]
            else:
                name = inserted[item.inserted - 1 - item.index][0]
            value = (
                item.value.decoded()
                if item.value is not None
                else inserted[item.inserted - 1 - item.index][1]
            )
            inserted[item.inserted] = (name, value)
            if name.decode("ascii") not in SAFE_FIELDS:
                raise ValueError("resource QPACK insert has an unapproved field name")
            if value not in allowed_values:
                raise ValueError("resource QPACK insert has an unowned field value")
        decoder_stream = self.streams.get(critical.get(3, -1), bytearray())
        if decoder_stream:
            _, offset = pull_varint(decoder_stream, 0)
            while offset < len(decoder_stream):
                prefix = 7 if decoder_stream[offset] & 0x80 else 6
                _, offset = qpack_integer(decoder_stream, offset, prefix)

    def lines(self, index: int) -> list[str]:
        prefix = f"resource_connection_{index}_h3"
        lines = [f"{prefix}_event_count={len(self.events)}"]
        lines.extend(
            f"{prefix}_event_{n}=stream:{event.stream},offset:{event.offset},"
            f"fin:{str(event.ended).lower()},data_hex:{event.data.hex()}"
            for n, event in enumerate(self.events)
        )
        lines.extend(
            f"{prefix}_server_setting_{key}={value}"
            for key, value in (self.settings or {}).items()
        )
        return lines


class ResourceProtocol(QuicConnectionProtocol):
    def __init__(self, *args, owner: ResourceServer, **kwargs) -> None:
        if owner.stopping:
            raise ValueError("resource HTTP/3 origin is stopping")
        if len(owner.protocols) >= lifecycle.MAX_CONNECTIONS:
            raise ValueError("resource HTTP/3 connection limit exceeded")
        super().__init__(*args, **kwargs)
        self.owner = owner
        self.index = len(owner.protocols)
        self.record = lifecycle.ConnectionRecord(self.index, "main", owner.run.now())
        self.capture = StreamCapture()
        self.http: H3Connection | None = None
        self.pending: set[int] = set()
        owner.protocols.append(self)
        owner.run.connections.append(self.record)

    def datagram_received(self, data, addr) -> None:
        try:
            super().datagram_received(data, addr)
        except Exception as error:
            self.owner.failed(error)

    def _handle_timer(self) -> None:
        try:
            super()._handle_timer()
        except Exception as error:
            self.owner.failed(error)

    def transmit(self) -> None:
        try:
            super().transmit()
        except Exception as error:
            self.owner.failed(error)

    def quic_event_received(self, event) -> None:
        try:
            self.handle(event)
        except Exception as error:
            self.owner.failed(error)

    def handle(self, event) -> None:
        if isinstance(event, ConnectionTerminated):
            self.record.eof = self.owner.run.now()
            self.owner.run.connection_ended.set()
            if event.error_code not in {0, 0x100}:
                raise ValueError(
                    f"resource QUIC connection failed: {event.error_code}, "
                    f"frame_type={event.frame_type}, "
                    f"reason={json.dumps(event.reason_phrase[:512])}"
                )
            if not self.owner.stopping and self.owner.run.page_result != "resources:ok":
                raise ValueError(
                    "resource QUIC connection closed before page completion"
                )
            return
        if self.owner.stopping or self.owner.run.failure is not None:
            return
        if isinstance(event, ProtocolNegotiated):
            if event.alpn_protocol != "h3":
                raise ValueError("resource origin did not negotiate h3")
            self.record.alpn = "h3"
            self.http = H3Connection(self._quic)
            self.capture.settings = self.http.sent_settings
        if isinstance(event, StreamReset):
            raise ValueError("resource HTTP/3 request stream reset")
        if isinstance(event, StreamDataReceived):
            self.capture.retain(event, self.owner.resources)
        if self.http is None:
            return
        for item in self.http.handle_event(event):
            if isinstance(item, HeadersReceived):
                self.owner.resources.observe(
                    self.index, item.stream_id, item.headers, None
                )
                self.pending.add(item.stream_id)
                if item.stream_ended:
                    self.respond(item.stream_id)
            elif isinstance(item, DataReceived):
                if item.data or item.stream_id not in self.pending:
                    raise ValueError("resource HTTP/3 request body is unsupported")
                if item.stream_ended:
                    self.respond(item.stream_id)
        if self.http._is_done:
            raise ValueError("resource HTTP/3 peer violated the protocol")

    def respond(self, stream: int) -> None:
        self.pending.remove(stream)
        resource = next(
            item
            for item in self.owner.resources.requests
            if item.connection == self.index and item.stream == stream
        )
        fields = dict(resource.fields)
        target = fields[b":path"].decode("ascii")
        run = self.owner.run
        run.select(self.index, target)
        request = lifecycle.RequestRecord(
            self.index,
            stream,
            run.now() * 1000,
            "GET",
            resource.path,
            [name.decode("ascii") for name, _ in resource.fields],
            {},
        )
        run.add_request(request)
        reply = lifecycle.reply_for("resources", "GET", resource.path, {}, run)
        request.status = reply.status
        self.http.send_headers(
            stream,
            [
                (b":status", b"200"),
                (b"content-length", str(len(reply.body)).encode()),
                *((name.encode(), value.encode()) for name, value in reply.fields),
            ],
        )
        self.http.send_data(stream, reply.body, end_stream=True)
        self.transmit()
        self.owner.resources.responded.add(resource.path)
        if resource.path == "/done":
            run.finish(target, self.index)


class ResourceServer(QuicServer):
    """Own the resource protocols, their callbacks and the UDP retirement."""

    def __init__(self, run: lifecycle.Run, configuration: QuicConfiguration) -> None:
        self.run = run
        self.resources = run.resources
        self.protocols: list[ResourceProtocol] = []
        self.errors: list[BaseException] = []
        self.stopping = False
        self.retired = asyncio.get_running_loop().create_future()
        self.cleanup: asyncio.Task | None = None
        super().__init__(
            configuration=configuration,
            create_protocol=lambda *args, **kwargs: ResourceProtocol(
                *args, owner=self, **kwargs
            ),
        )

    def failed(self, error: BaseException) -> None:
        if not any(item is error for item in self.errors):
            self.errors.append(error)
        if self.run.failure is None:
            self.run.failure = error
        self.run.failure_ready.set()

    def datagram_received(self, data, addr) -> None:
        if self.run.failure is not None:
            return
        try:
            super().datagram_received(data, addr)
        except Exception as error:
            self.failed(error)

    def error_received(self, error) -> None:
        if self.run.failure is None:
            self.failed(error)

    def connection_lost(self, error) -> None:
        if error is not None:
            self.failed(error)
        elif not self.stopping:
            self.failed(ConnectionError("resource QUIC transport retired unexpectedly"))
        if not self.retired.done():
            self.retired.set_result(None)

    async def start(self, host: str) -> int:
        async def open_at(host: str, port: int):
            return await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: self, local_addr=(host, port)
            )

        transport, _ = await open_past_reserved_ports(open_at, host, 0)
        return transport.get_extra_info("sockname")[1]

    async def wait_done(self, timeout: float) -> None:
        tasks = []
        try:
            for ready in (self.run.done, self.run.failure_ready):
                operation = ready.wait()
                try:
                    tasks.append(asyncio.create_task(operation))
                except BaseException:
                    operation.close()
                    raise
            ready, _ = await asyncio.wait(
                tasks, timeout=timeout, return_when=asyncio.FIRST_COMPLETED
            )
            if self.errors:
                raise self.errors[0]
            if not ready:
                raise TimeoutError(
                    "resource HTTP/3 page exceeded its deadline; state="
                    + self.run.failure_state()
                )
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def collect(self) -> None:
        self.stopping = True
        if self.run.completion is not None:
            self.run.completion.cancel()
        deadline = asyncio.get_running_loop().time() + lifecycle.CLEANUP_SECONDS
        waits = []
        try:
            for protocol in self.protocols:
                try:
                    protocol.close()
                except BaseException as error:
                    self.failed(error)
                operation = protocol.wait_closed()
                try:
                    waits.append(asyncio.create_task(operation))
                except BaseException:
                    operation.close()
                    raise
            if waits:
                _, pending = await asyncio.wait(
                    waits,
                    timeout=max(0, deadline - asyncio.get_running_loop().time() - 1),
                )
                if pending:
                    self.failed(
                        TimeoutError(
                            "resource QUIC connection cleanup exceeded its deadline"
                        )
                    )
        except BaseException as error:
            self.failed(error)
        finally:
            if self._transport is not None:
                try:
                    self._transport.abort()
                except BaseException as error:
                    self.failed(error)
                    try:
                        self._transport.close()
                    except BaseException as cleanup:
                        self.failed(cleanup)
                try:
                    await asyncio.wait_for(
                        asyncio.shield(self.retired),
                        max(0, deadline - asyncio.get_running_loop().time()),
                    )
                except BaseException as error:
                    self.failed(error)
            for task in waits:
                if not task.done():
                    task.cancel()
            results = await asyncio.gather(*waits, return_exceptions=True)
            for error in results:
                if isinstance(error, BaseException) and not isinstance(
                    error, asyncio.CancelledError
                ):
                    self.failed(error)
            for protocol in self.protocols:
                for name in ("_timer", "_transmit_task"):
                    handle = getattr(protocol, name)
                    if handle is not None:
                        try:
                            handle.cancel()
                        except BaseException as error:
                            self.failed(error)
                        else:
                            setattr(protocol, name, None)

    async def close(self, primary: BaseException | None = None) -> None:
        if self.cleanup is None:
            operation = self.collect()
            try:
                self.cleanup = asyncio.create_task(operation)
            except BaseException as error:
                operation.close()
                self.failed(error)
                lifecycle._raise_lifecycle_failures(primary, self.errors, self)
            self.cleanup.add_done_callback(self.observe_cleanup)
        # An interrupted caller still joins the owned, deadline-bounded cleanup.
        while not self.cleanup.done():
            try:
                await asyncio.shield(self.cleanup)
            except BaseException as error:
                self.failed(error)
        self.observe_cleanup(self.cleanup)
        lifecycle._raise_lifecycle_failures(primary, self.errors, self)

    def observe_cleanup(self, task: asyncio.Task) -> None:
        try:
            task.result()
        except BaseException as error:
            self.failed(error)

    def evidence(self) -> list[str]:
        self.resources.check_complete(self.run.page_result)
        lines = [
            "resource_protocol=h3",
            f"resource_aioquic_version={metadata.version('aioquic')}",
            f"resource_pylsqpack_version={metadata.version('pylsqpack')}",
        ]
        for protocol in self.protocols:
            fields = {
                request.stream: request.fields
                for request in self.resources.requests
                if request.connection == protocol.index
            }
            protocol.capture.replay(fields)
            lines.extend(protocol.capture.lines(protocol.index))
        lines.extend(self.resources.field_lines())
        return lines


async def capture(args) -> None:
    if metadata.version("aioquic") != "1.3.0":
        raise ValueError("aioquic 1.3.0 is required")
    certificate = generate_certificate()
    run = lifecycle.Run("resources", secrets.token_hex(8), round(args.idle * 1000))
    configuration = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
    load_certificate(configuration, certificate)
    owner = ResourceServer(run, configuration)
    primary = None
    remote_close = None
    try:
        port = await owner.start(args.listen)
        run.resources = ResourceCapture(run.token, port, "h3")
        owner.resources = run.resources
        plan = lifecycle.launch_plan(args, certificate, (port,))
        url = f"https://{HOSTNAME}:{port}/start?run={run.token}"
        async with BrowserDriver(plan, url) as driver:
            await owner.wait_done(60)
            if driver.browser is None or driver.browser.profile is None:
                raise RuntimeError("the browser has no remote profile")
            remote_close = run.now()
            await lifecycle.close_browser(args.browser, driver.browser.profile, run)
            await asyncio.wait_for(lifecycle.all_ended(run), lifecycle.CLOSE_GRACE)
    except BaseException as error:
        primary = error
    await owner.close(primary)
    arguments = (
        plan.recorded_arguments(url)
        .replace(certificate.spki_sha256_base64, "<certificate-spki>")
        .replace(f":{port}", ":<port>")
        .replace(run.token, "<token>")
    )
    output = lifecycle.fixture(
        args, plan, arguments, run, remote_close, resource_lines=owner.evidence()
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_text_fixture(args.output_dir / "resources.txt", output)
