"""Bounded loopback CONNECT/SOCKS5 relay for decrypted WebSocket captures."""

from __future__ import annotations

import asyncio
import ipaddress
from dataclasses import dataclass, field

from .http2_session import (
    HOSTNAME,
    MAX_REQUEST_HEAD,
    CaptureRun,
    CaptureServer,
    Certificate,
    ConnectionRecord,
    PlainChannel,
    TlsChannel,
    peer_disconnected,
    raise_capture_failures,
)

PROXY_HOST = "proxy.phantom.test"
MODES = ("http", "https", "socks5")
HANDSHAKE_SECONDS = 10.0
IDLE_SECONDS = 30.0
SENSITIVE = {b"authorization", b"proxy-authorization", b"cookie"}
FIELD_NAME = (
    b"!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)


class RejectedOpening(Exception):
    """An unforwardable opening; only the fixed refusal response is retained."""

    def __init__(self, message: str, reply: bytes = b"") -> None:
        self.reply = reply
        super().__init__(message)


class TunnelOrigin(CaptureServer):
    """Correlate each accepted TCP socket without changing origin TLS handling."""

    def __init__(self, certificate: Certificate) -> None:
        super().__init__(certificate)
        self.endpoints: dict[int, tuple] = {}

    def accept(self, listener, writer):
        run, record, index = super().accept(listener, writer)
        self.endpoints[id(record)] = writer.get_extra_info("peername")
        return run, record, index


@dataclass
class Opening:
    connection: ConnectionRecord
    peer: tuple
    head: bytes = b""
    reply: bytes = b""
    outcome: str = "pending"
    upstream: tuple | None = None
    origin_connection: int | None = None
    tls_version: str | None = None
    finished: float | None = None


@dataclass
class TunnelRun:
    origin: CaptureRun
    openings: list[Opening] = field(default_factory=list)


class OpeningReader:
    def __init__(self, channel: PlainChannel) -> None:
        self.channel = channel
        self.buffer = bytearray()

    async def exact(self, size: int) -> bytes:
        while len(self.buffer) < size:
            data = await self.channel.read()
            if not data:
                raise RejectedOpening("truncated opening")
            self.buffer.extend(data)
        result = bytes(self.buffer[:size])
        del self.buffer[:size]
        return result

    async def head(self) -> bytes:
        while True:
            end = self.buffer.find(b"\r\n\r\n")
            if end >= 0:
                if end + 4 > MAX_REQUEST_HEAD:
                    raise RejectedOpening("opening exceeds limit")
                return await self.exact(end + 4)
            if len(self.buffer) >= MAX_REQUEST_HEAD:
                raise RejectedOpening("opening exceeds limit")
            data = await self.channel.read()
            if not data:
                raise RejectedOpening("truncated opening")
            self.buffer.extend(data)


def connect_head(head: bytes, listen: str, port: int) -> None:
    lines = head[:-4].split(b"\r\n")
    try:
        method, target, version = lines[0].split(b" ")
        text = target.decode("ascii")
    except (ValueError, UnicodeError) as error:
        raise RejectedOpening("malformed CONNECT") from error
    literal = f"[{listen}]" if ":" in listen else listen
    expected = {f"{HOSTNAME}:{port}", f"{literal}:{port}"}
    if method != b"CONNECT" or version != b"HTTP/1.1" or text not in expected:
        raise RejectedOpening("CONNECT target refused")
    hosts = []
    for line in lines[1:]:
        name, colon, value = line.partition(b":")
        if (
            not colon
            or not name
            or any(byte not in FIELD_NAME for byte in name)
            or any(byte < 32 or byte == 127 for byte in value if byte != 9)
        ):
            raise RejectedOpening("malformed CONNECT field")
        name = name.lower()
        if name in SENSITIVE:
            raise RejectedOpening("credential or cookie field refused")
        if name in {b"content-length", b"transfer-encoding"}:
            raise RejectedOpening("CONNECT body refused")
        if name == b"host":
            hosts.append(value.strip())
    if hosts != [target]:
        raise RejectedOpening("CONNECT Host must match its target")


class TunnelServer(CaptureServer):
    """One relay listener; the existing capture owner collects every socket."""

    def __init__(self, mode: str, certificate: Certificate, origin: tuple[str, int]):
        if mode not in MODES or not ipaddress.ip_address(origin[0]).is_loopback:
            raise ValueError("a loopback origin and explicit proxy mode are required")
        if not 1 <= origin[1] <= 65535:
            raise ValueError("origin must have an actual listener port")
        super().__init__(certificate)
        self.context.set_alpn_protocols(["http/1.1"])
        self.mode = mode
        self.origin = origin
        self.address: tuple[str, int] | None = None
        self.tunnel_run: TunnelRun | None = None

    async def start(self) -> None:
        try:
            server = await asyncio.get_running_loop().create_server(
                lambda: self.new_protocol(self.mode),
                self.origin[0],
                0,
                start_serving=False,
            )
            self.servers.append(server)
            self.address = server.sockets[0].getsockname()[:2]
            ready = asyncio.Event()
            operation = self.wait_listener(server, ready)
            try:
                task = asyncio.create_task(operation)
            except BaseException:
                operation.close()
                raise
            self.listener_waits[task] = (server, False)
            task.add_done_callback(self.wait_finished)
            await ready.wait()
            if task.done():
                task.result()
            await server.start_serving()
        except BaseException as primary:
            cleanup = []
            try:
                await self.close()
            except BaseException as error:
                cleanup.append(error)
            raise_capture_failures(primary, tuple(cleanup))

    def begin_run(self, run: CaptureRun) -> TunnelRun:
        super().begin_run(run)
        self.tunnel_run = TunnelRun(run)
        return self.tunnel_run

    async def stop_connections(self) -> None:
        self.run = None
        await super().stop_connections()

    async def _socks(self, reader: OpeningReader, record: Opening) -> bytes:
        version, count = await reader.exact(2)
        methods = await reader.exact(count)
        if version != 5 or methods != b"\x00":
            raise RejectedOpening(
                "only unauthenticated SOCKS5 is supported", b"\x05\xff"
            )
        await reader.channel.write(b"\x05\x00")
        record.reply += b"\x05\x00"
        prefix = await reader.exact(4)
        if prefix[:3] != b"\x05\x01\x00":
            raise RejectedOpening("SOCKS5 CONNECT required")
        kind = prefix[3]
        if kind == 3:
            length = await reader.exact(1)
            address = length + await reader.exact(length[0])
            try:
                host = address[1:].decode("ascii")
            except UnicodeError as error:
                raise RejectedOpening("invalid SOCKS5 domain") from error
        elif kind in {1, 4}:
            address = await reader.exact(4 if kind == 1 else 16)
            host = str(ipaddress.ip_address(address))
        else:
            raise RejectedOpening("invalid SOCKS5 address kind")
        port = await reader.exact(2)
        if (
            host not in {HOSTNAME, self.origin[0]}
            or int.from_bytes(port, "big") != self.origin[1]
        ):
            raise RejectedOpening("SOCKS5 target refused")
        record.head = bytes((version, count)) + methods + prefix + address + port
        return b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00"

    async def _opening(self, channel, record):
        reader = OpeningReader(channel)
        if self.mode == "socks5":
            reply = await self._socks(reader, record)
            record.connection.protocol = "socks5"
        else:
            head = await reader.head()
            connect_head(head, *self.origin)
            record.head = head
            record.connection.protocol = "http/1.1"
            reply = b"HTTP/1.1 200 Connection Established\r\n\r\n"
        return reader, reply

    def refusal(self, code: int) -> bytes:
        if self.mode == "socks5":
            return bytes((5, code, 0, 1, 0, 0, 0, 0, 0, 0))
        status = b"403 Forbidden" if code == 2 else b"502 Bad Gateway"
        return (
            b"HTTP/1.1 "
            + status
            + b"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )

    async def _handle(self, listener, reader, writer) -> None:
        run, _, _ = self.handlers[asyncio.current_task()]
        record = Opening(
            ConnectionRecord(listener, run.now()), writer.get_extra_info("peername")
        )
        if self.tunnel_run is None or self.tunnel_run.origin is not run:
            raise RuntimeError("accepted tunnel lost its retained run")
        self.tunnel_run.openings.append(record)
        channel = PlainChannel(reader, writer, record.connection, run.now, run)
        upstream = None
        pumps = []
        primary = None
        handled_error = None
        try:
            if self.mode == "https":
                channel = TlsChannel(
                    self.context, reader, writer, record.connection, run.now, run
                )
                await asyncio.wait_for(channel.handshake(), HANDSHAKE_SECONDS)
                record.tls_version = channel.tls.version()
            try:
                opening, reply = await asyncio.wait_for(
                    self._opening(channel, record), HANDSHAKE_SECONDS
                )
            except RejectedOpening as error:
                if record.connection.client_eof is not None:
                    record.outcome = "peer-disconnected"
                    return
                record.outcome = "rejected"
                reply = error.reply or self.refusal(2)
                record.reply += reply
                await channel.write(reply)
                return
            try:
                incoming, upstream = await asyncio.wait_for(
                    asyncio.open_connection(*self.origin), HANDSHAKE_SECONDS
                )
            except ConnectionRefusedError:
                record.outcome = "origin-refused"
                reply = self.refusal(5)
                record.reply += reply
                await channel.write(reply)
                return
            self.writers.add(upstream)
            record.upstream = upstream.get_extra_info("sockname")
            if self.mode == "socks5":
                bound = ipaddress.ip_address(record.upstream[0])
                reply = (
                    bytes((5, 0, 0, 1 if bound.version == 4 else 4))
                    + bound.packed
                    + record.upstream[1].to_bytes(2, "big")
                )
            record.reply += reply
            await channel.write(reply)
            record.outcome = "forwarded"
            if opening.buffer:
                upstream.write(opening.buffer)
                await asyncio.wait_for(upstream.drain(), IDLE_SECONDS)

            async def outward():
                while data := await asyncio.wait_for(channel.read(), IDLE_SECONDS):
                    upstream.write(data)
                    await asyncio.wait_for(upstream.drain(), IDLE_SECONDS)
                return "client-eof"

            async def inward():
                while data := await asyncio.wait_for(
                    incoming.read(65536), IDLE_SECONDS
                ):
                    await asyncio.wait_for(channel.write(data), IDLE_SECONDS)
                return "origin-eof"

            for direction in (outward, inward):
                operation = direction()
                try:
                    pumps.append(asyncio.create_task(operation))
                except BaseException:
                    operation.close()
                    raise
            done, _ = await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
            if pumps[0] in done:
                record.outcome = pumps[0].result()
                if upstream.can_write_eof() and not upstream.is_closing():
                    upstream.write_eof()
                # A peer half-close must not truncate the origin's final bytes.
                record.outcome = await asyncio.wait_for(pumps[1], IDLE_SECONDS)
            else:
                record.outcome = pumps[1].result()
        except BaseException as error:
            handled_error = error
            peer_handshake = (
                isinstance(channel, TlsChannel)
                and error is channel.peer_handshake_failure
            )
            peer_io = error is channel.peer_io_failure
            if peer_disconnected(error) or peer_handshake or peer_io:
                record.outcome = "peer-disconnected"
            else:
                record.outcome = type(error).__name__
                primary = error
        finally:
            cleanup = []
            for task in pumps:
                if not task.done():
                    task.cancel()
            if pumps:
                results = await asyncio.gather(*pumps, return_exceptions=True)
                for result in results:
                    if (
                        isinstance(result, BaseException)
                        and not isinstance(result, asyncio.CancelledError)
                        and result is not handled_error
                    ):
                        cleanup.append(result)
            for owner in (upstream, writer):
                if owner is not None:
                    try:
                        self.release(owner)
                    except BaseException as error:
                        cleanup.append(error)
            record.finished = run.now()
            # Bounds are charged before dropping duplicate encrypted origin bytes.
            # Only the validated proxy opening and ClientHello survive serialization.
            record.connection.client_chunks.clear()
            record.connection.server_chunks.clear()
            raise_capture_failures(primary, tuple(cleanup))


def correlate(run: TunnelRun, origin: TunnelOrigin) -> None:
    matched = set()
    for opening in run.openings:
        if opening.upstream is None:
            continue
        indices = [
            index
            for index, connection in enumerate(run.origin.connections)
            if origin.endpoints[id(connection)] == opening.upstream
        ]
        if len(indices) != 1 or indices[0] in matched:
            raise ValueError("tunnel must correlate with exactly one origin connection")
        opening.origin_connection = indices[0]
        matched.add(indices[0])
    if matched != set(range(len(run.origin.connections))):
        raise ValueError("origin connection bypassed the selected tunnel")
