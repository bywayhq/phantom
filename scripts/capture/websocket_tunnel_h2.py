"""Bounded classic CONNECT streams on the existing HTTPS capture owner."""

from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass, field

import h2.events
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.errors import ErrorCodes
from h2.settings import SettingCodes, Settings

from .http2_session import (
    CONNECTION_PREFACE,
    HOSTNAME,
    MAX_H2_FRAMES,
    MAX_HEADER_FIELDS,
    MAX_REQUEST_HEAD,
    READ_SIZE,
    CaptureFailures,
    CaptureLimitError,
    TlsChannel,
    peer_disconnected,
    raise_capture_failures,
)
from .websocket_tunnel import (
    HANDSHAKE_SECONDS,
    IDLE_SECONDS,
    SENSITIVE,
    Opening,
    TunnelServer,
)

MAX_STREAMS = 32
# The connection receive window is never enlarged beyond its RFC 9113 default.
MAX_PENDING_INPUT = 65535


@dataclass
class TunnelStream:
    opening: Opening
    incoming: deque[tuple[bytes, int]] = field(default_factory=deque)
    readable: asyncio.Event = field(default_factory=asyncio.Event)
    writable: asyncio.Event = field(default_factory=asyncio.Event)
    ended: bool = False
    reset: bool = False
    task: asyncio.Task | None = None
    failure: BaseException | None = None


class Http2Tunnel:
    def __init__(
        self, owner: TunnelServer, channel: TlsChannel, opening: Opening
    ) -> None:
        self.owner, self.channel, self.opening = owner, channel, opening
        self.run = owner.tunnel_run.origin
        self.index = next(
            index
            for index, record in enumerate(owner.tunnel_run.proxy_connections)
            if record is opening
        )
        self.connection = H2Connection(
            H2Configuration(client_side=False, header_encoding=None)
        )
        self.connection.local_settings = Settings(
            client=False,
            initial_values={
                SettingCodes.MAX_CONCURRENT_STREAMS: MAX_STREAMS,
                SettingCodes.MAX_HEADER_LIST_SIZE: MAX_REQUEST_HEAD,
            },
        )
        del self.connection.local_settings[SettingCodes.ENABLE_PUSH]
        self.streams: dict[int, TunnelStream] = {}
        self.pending_input = 0
        self.write_lock = asyncio.Lock()
        self.frame_head = bytearray()
        self.frame_remaining = len(CONNECTION_PREFACE)
        self.frame_count = 0
        self.batch_resets: set[int] = set()

    async def flush(self) -> None:
        async with self.write_lock:
            await asyncio.wait_for(
                self.channel.write(self.connection.data_to_send()), IDLE_SECONDS
            )

    async def serve(self) -> None:
        reading = None
        primary = None
        try:
            self.connection.initiate_connection()
            await self.flush()
            while True:
                if reading is None:
                    operation = self.read()
                    try:
                        reading = asyncio.create_task(operation)
                    except BaseException:
                        operation.close()
                        raise
                tasks = {reading, *(stream.task for stream in self.streams.values())}
                done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for stream_id, stream in list(self.streams.items()):
                    if stream.task in done:
                        self.retire(stream_id, stream)
                if reading in done:
                    data = reading.result()
                    reading = None
                    if not data:
                        self.opening.outcome = "client-eof"
                        break
                    self.count_frames(data)
                    events = self.connection.receive_data(data)
                    if any(
                        isinstance(event, h2.events.ConnectionTerminated)
                        for event in events
                    ):
                        self.opening.outcome = "goaway"
                        break
                    # h2 applies a whole batch before returning its events.
                    self.batch_resets = {
                        event.stream_id
                        for event in events
                        if isinstance(event, h2.events.StreamReset)
                    }
                    for event in events:
                        self.handle(event)
                await self.flush()
        except BaseException as error:
            primary = error
        cleanup = []
        if reading is not None:
            if not reading.done():
                reading.cancel()
            results = await asyncio.gather(reading, return_exceptions=True)
            cleanup.extend(
                result
                for result in results
                if isinstance(result, BaseException)
                and not isinstance(result, asyncio.CancelledError)
                and result is not primary
            )
        for stream in self.streams.values():
            if not stream.task.done():
                stream.reset = True
                stream.opening.outcome = "connection-closed"
                stream.task.cancel()
        if self.streams:
            await asyncio.gather(
                *(stream.task for stream in self.streams.values()),
                return_exceptions=True,
            )
        for stream_id, stream in list(self.streams.items()):
            try:
                self.retire(stream_id, stream)
            except BaseException as error:
                if error is not primary:
                    cleanup.append(error)
        raise_capture_failures(primary, tuple(cleanup))

    async def read(self) -> bytes:
        return await asyncio.wait_for(self.channel.read(), IDLE_SECONDS)

    def count_frames(self, data: bytes) -> None:
        position = 0
        while position < len(data):
            if self.frame_remaining:
                size = min(self.frame_remaining, len(data) - position)
                self.frame_remaining -= size
                position += size
                continue
            size = min(9 - len(self.frame_head), len(data) - position)
            self.frame_head.extend(data[position : position + size])
            position += size
            if len(self.frame_head) == 9:
                self.frame_count += 1
                if self.frame_count > MAX_H2_FRAMES:
                    raise CaptureLimitError("H2 proxy frame count exceeds the limit")
                self.frame_remaining = int.from_bytes(self.frame_head[:3], "big")
                self.frame_head.clear()

    def handle(self, event: h2.events.Event) -> None:
        if isinstance(event, h2.events.RequestReceived):
            self.request(event.stream_id, tuple(event.headers))
        elif isinstance(event, h2.events.TrailersReceived):
            self.reset(event.stream_id, ErrorCodes.PROTOCOL_ERROR, "trailers-refused")
        elif isinstance(event, h2.events.DataReceived):
            stream = self.streams.get(event.stream_id)
            if stream is None or stream.reset:
                self.connection.acknowledge_received_data(
                    event.flow_controlled_length, event.stream_id
                )
                return
            self.pending_input += event.flow_controlled_length
            if self.pending_input > MAX_PENDING_INPUT:
                raise CaptureLimitError("H2 proxy pending input exceeds the limit")
            stream.incoming.append((event.data, event.flow_controlled_length))
            stream.readable.set()
        elif isinstance(event, h2.events.StreamEnded):
            stream = self.streams.get(event.stream_id)
            if stream is not None:
                stream.ended = True
                stream.readable.set()
        elif isinstance(event, h2.events.StreamReset):
            self.reset(event.stream_id, None, "client-reset")
        elif isinstance(
            event, (h2.events.WindowUpdated, h2.events.RemoteSettingsChanged)
        ):
            for stream in self.streams.values():
                stream.writable.set()

    def request(self, stream_id: int, headers: tuple[tuple[bytes, bytes], ...]) -> None:
        self.run.request()
        if (
            len(headers) > MAX_HEADER_FIELDS
            or sum(len(name) + len(value) for name, value in headers) > MAX_REQUEST_HEAD
        ):
            raise CaptureLimitError("H2 proxy opening exceeds the header limit")
        if any(name in SENSITIVE for name, _ in headers):
            raise ValueError("credential or cookie field refused by the H2 proxy")
        record = Opening(
            self.opening.connection,
            self.opening.peer,
            tls_version=self.opening.tls_version,
            stream_id=stream_id,
            proxy_connection=self.index,
            headers=headers,
        )
        self.owner.tunnel_run.openings.append(record)
        if stream_id in self.batch_resets:
            record.outcome = "client-reset"
            record.finished = self.run.now()
            return
        pseudo = [(name, value) for name, value in headers if name.startswith(b":")]
        target = dict(pseudo).get(b":authority")
        listen, port = self.owner.origin
        literal = f"[{listen}]" if ":" in listen else listen
        valid = (
            len(pseudo) == 2
            and {name for name, _ in pseudo} == {b":method", b":authority"}
            and dict(pseudo).get(b":method") == b"CONNECT"
            and target in {f"{HOSTNAME}:{port}".encode(), f"{literal}:{port}".encode()}
            and not any(
                name in {b"content-length", b"transfer-encoding"}
                or (name == b"host" and value != target)
                for name, value in headers
            )
        )
        if not valid:
            record.outcome = "rejected"
            self.reply(record, 403, end_stream=True)
            record.finished = self.run.now()
            return
        if len(self.streams) >= MAX_STREAMS:
            raise CaptureLimitError("H2 proxy active stream count exceeds the limit")
        stream = TunnelStream(record)
        operation = self.relay(stream_id, stream)
        try:
            stream.task = asyncio.create_task(operation)
        except BaseException:
            operation.close()
            raise
        self.streams[stream_id] = stream

    def reply(self, record: Opening, status: int, *, end_stream: bool = False) -> None:
        record.status = status
        self.connection.send_headers(
            record.stream_id,
            [(b":status", str(status).encode())],
            end_stream=end_stream,
        )

    def reset(self, stream_id: int, code: ErrorCodes | None, outcome: str) -> None:
        stream = self.streams.get(stream_id)
        if stream is not None:
            stream.reset = True
            stream.opening.outcome = outcome
            stream.task.cancel()
        if code is not None and stream_id not in self.batch_resets:
            self.connection.reset_stream(stream_id, error_code=code)

    def credit(self, stream_id: int, size: int) -> None:
        self.pending_input -= size
        self.connection.acknowledge_received_data(size, stream_id)

    def retire(self, stream_id: int, stream: TunnelStream) -> None:
        try:
            stream.task.result()
        except asyncio.CancelledError as cancellation:
            error = stream.failure or cancellation
            if not stream.reset:
                raise
            if isinstance(error.__cause__, CaptureFailures):
                raise_capture_failures(None, error.__cause__.cleanup)
        finally:
            while stream.incoming:
                _, size = stream.incoming.popleft()
                self.credit(stream_id, size)
            stream.opening.finished = self.run.now()
            del self.streams[stream_id]

    async def outward(
        self, stream_id: int, stream: TunnelStream, writer: asyncio.StreamWriter
    ) -> None:
        while True:
            while stream.incoming:
                data, size = stream.incoming.popleft()
                try:
                    writer.write(data)
                    await asyncio.wait_for(writer.drain(), IDLE_SECONDS)
                finally:
                    # A cancelled drain discards these bytes, rather than queuing
                    # them again. h2 returns only connection credit after reset.
                    self.credit(stream_id, size)
                await self.flush()
            if stream.ended:
                if writer.can_write_eof() and not writer.is_closing():
                    writer.write_eof()
                return
            stream.readable.clear()
            await asyncio.wait_for(stream.readable.wait(), IDLE_SECONDS)

    async def inward(
        self, stream_id: int, stream: TunnelStream, reader: asyncio.StreamReader
    ) -> None:
        while True:
            # One bounded read can observe EOF even with no DATA credit.
            data = await asyncio.wait_for(reader.read(READ_SIZE), IDLE_SECONDS)
            if not data:
                self.connection.end_stream(stream_id)
                await self.flush()
                return
            position = 0
            while position < len(data):
                size = min(
                    self.connection.local_flow_control_window(stream_id),
                    self.connection.max_outbound_frame_size,
                    len(data) - position,
                )
                if size <= 0:
                    stream.writable.clear()
                    await asyncio.wait_for(stream.writable.wait(), IDLE_SECONDS)
                    continue
                self.connection.send_data(stream_id, data[position : position + size])
                position += size
                await self.flush()

    async def relay(self, stream_id: int, stream: TunnelStream) -> None:
        record = stream.opening
        upstream = None
        pumps = []
        primary = None
        handled = None
        try:
            try:
                reader, upstream = await asyncio.wait_for(
                    asyncio.open_connection(*self.owner.origin), HANDSHAKE_SECONDS
                )
            except ConnectionRefusedError:
                record.outcome = "origin-refused"
                self.reply(record, 502, end_stream=True)
                await self.flush()
                return
            self.owner.writers.add(upstream)
            record.upstream = upstream.get_extra_info("sockname")
            self.reply(record, 200)
            await self.flush()
            record.outcome = "forwarded"
            for direction, endpoint in (
                (self.outward, upstream),
                (self.inward, reader),
            ):
                operation = direction(stream_id, stream, endpoint)
                try:
                    pumps.append(asyncio.create_task(operation))
                except BaseException:
                    operation.close()
                    raise
            done, pending = await asyncio.wait(
                pumps, return_when=asyncio.FIRST_COMPLETED
            )
            for task in done:
                task.result()
            # END_STREAM closes one direction; the other may still carry data.
            for task in pending:
                await asyncio.wait_for(task, IDLE_SECONDS)
            record.outcome = "origin-eof"
        except BaseException as error:
            handled = error
            if peer_disconnected(error):
                record.outcome = "peer-disconnected"
                self.connection.reset_stream(stream_id, ErrorCodes.CONNECT_ERROR)
            else:
                primary = error
                stream.failure = error
        finally:
            cleanup = []
            for task in pumps:
                if not task.done():
                    task.cancel()
            if pumps:
                results = await asyncio.gather(*pumps, return_exceptions=True)
                cleanup.extend(
                    result
                    for result in results
                    if isinstance(result, BaseException)
                    and not isinstance(result, asyncio.CancelledError)
                    and result is not handled
                )
            if upstream is not None:
                try:
                    self.owner.release(upstream)
                except BaseException as error:
                    cleanup.append(error)
            raise_capture_failures(primary, tuple(cleanup))
