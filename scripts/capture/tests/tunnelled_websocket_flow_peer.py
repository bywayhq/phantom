"""Owned actual TCP origin and native writer probes for relay flow controls."""

import asyncio
import contextlib
import hashlib
import socket

from scripts.capture.http2_session import (
    CaptureRun,
    ServerPolicy,
    generate_certificate,
    raise_capture_failures,
)
from scripts.capture.tests.tunnelled_websocket_peer import TIMEOUT
from scripts.capture.websocket_tunnel import TunnelServer


class NativeDrainWriter:
    """Observe an actual paused native writer without replacing its drain."""

    def __init__(self, writer, paused):
        self.writer, self.paused = writer, paused
        self.transport = writer.transport
        self.writes = 0
        self.buffered_at_pause = None
        self.pending_drains = 0
        self.read_checks = 0
        self.undrained_write = False
        self.closed_error = None
        self.transport.set_write_buffer_limits(high=1024, low=512)
        writer.get_extra_info("socket").setsockopt(
            socket.SOL_SOCKET, socket.SO_SNDBUF, 4096
        )

    def write(self, data):
        self.writes += 1
        self.undrained_write = True
        self.writer.write(data)

    def check_read(self):
        self.read_checks += 1
        if self.undrained_write:
            raise AssertionError("relay read before its native drain completed")

    async def drain(self):
        buffered = self.transport.get_write_buffer_size()
        if buffered <= 1024:
            await self.writer.drain()
        else:
            draining = asyncio.create_task(self.writer.drain())
            try:
                # Poll the real drain once. A high buffer alone can disappear
                # into the kernel before an observer gets its next loop turn.
                await asyncio.wait((draining,), timeout=0)
                if not draining.done():
                    self.buffered_at_pause = buffered
                    self.pending_drains += 1
                    self.paused.set()
                await draining
            except BaseException as error:
                if not draining.done():
                    draining.cancel()
                results = await asyncio.gather(draining, return_exceptions=True)
                raise_capture_failures(
                    error,
                    tuple(
                        result
                        for result in results
                        if isinstance(result, BaseException)
                        and result is not error
                        and not isinstance(result, asyncio.CancelledError)
                    ),
                )
        self.undrained_write = False

    def get_extra_info(self, name):
        return self.writer.get_extra_info(name)

    def can_write_eof(self):
        return self.writer.can_write_eof()

    def write_eof(self):
        self.writer.write_eof()

    def is_closing(self):
        return self.writer.is_closing()

    def close(self):
        self.writer.close()

    async def wait_closed(self):
        await self.writer.wait_closed()
        if self.closed_error is not None:
            error, self.closed_error = self.closed_error, None
            raise error


class RawOrigin:
    def __init__(self, *, held=False):
        self.held = held
        self.release, self.accepted = asyncio.Event(), asyncio.Event()
        self.tasks, self.writers = [], set()
        self.received = b""

    async def start(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if self.held:
                # Bound the receive window before the handshake. Pausing the
                # asyncio reader alone still leaves the kernel free to receive.
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
            listener.bind(("127.0.0.1", 0))
            listener.setblocking(False)
            self.server = await asyncio.start_server(self.accept, sock=listener)
        except BaseException:
            listener.close()
            raise
        self.address = self.server.sockets[0].getsockname()[:2]

    def accept(self, reader, writer):
        self.writers.add(writer)
        self.tasks.append(asyncio.create_task(self.exchange(reader, writer)))

    async def exchange(self, reader, writer):
        try:
            if self.held:
                writer.transport.pause_reading()
            self.accepted.set()
            if self.held:
                await self.release.wait()
                writer.transport.resume_reading()
            chunks, count = [], 0
            while data := await reader.read(65536):
                count += len(data)
                if count > 8 * 1024 * 1024:
                    raise ValueError("scripted origin byte bound exceeded")
                chunks.append(data)
            self.received = b"".join(chunks)
            writer.write(hashlib.sha256(self.received).digest())
            await writer.drain()
        finally:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), TIMEOUT)
            self.writers.discard(writer)

    async def close(self):
        self.release.set()
        self.server.close()
        await self.server.wait_closed()
        for writer in self.writers:
            writer.close()
        if self.tasks:
            results = await asyncio.wait_for(
                asyncio.gather(*self.tasks, return_exceptions=True), TIMEOUT
            )
            raise_capture_failures(
                None,
                tuple(
                    result for result in results if isinstance(result, BaseException)
                ),
            )


@contextlib.asynccontextmanager
async def raw_tunnel(*, held=False):
    origin, proxy, primary = RawOrigin(held=held), None, None
    try:
        await origin.start()
        proxy = TunnelServer("http", generate_certificate(), origin.address)
        await proxy.start()
        proxy.begin_run(CaptureRun("raw", ServerPolicy(), {}))
        yield origin, proxy
    except BaseException as error:
        primary = error
    cleanup = []
    origin.release.set()
    for owner in (proxy, origin):
        if owner is not None:
            try:
                await owner.close()
            except BaseException as error:
                cleanup.append(error)
    raise_capture_failures(primary, tuple(cleanup))


async def connect(proxy):
    reader, writer = await asyncio.open_connection(*proxy.address)
    try:
        target = f"server.phantom.test:{proxy.origin[1]}".encode()
        writer.write(
            b"CONNECT " + target + b" HTTP/1.1\r\nHost: " + target + b"\r\n\r\n"
        )
        await writer.drain()
        if not (await reader.readuntil(b"\r\n\r\n")).startswith(b"HTTP/1.1 200"):
            raise AssertionError("CONNECT rejected")
        return reader, writer
    except BaseException:
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), TIMEOUT)
        raise
