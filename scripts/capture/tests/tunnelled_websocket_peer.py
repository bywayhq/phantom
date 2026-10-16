"""Scripted nested TLS client for the tunnelled WebSocket wire controls."""

import asyncio
import contextlib
import ssl

from scripts.capture.http2_session import (
    HOSTNAME,
    CaptureRun,
    ServerPolicy,
    generate_certificate,
    raise_capture_failures,
)
from scripts.capture.tests.test_http2_websocket import ScriptedH2
from scripts.capture.websocket_tunnel import PROXY_HOST, TunnelOrigin, TunnelServer

TIMEOUT = 5.0


def context(certificate, alpn):
    result = ssl.create_default_context(cadata=certificate.certificate_pem.decode())
    result.set_alpn_protocols(list(alpn))
    return result


class TunnelTls:
    """Client TLS over the proxy stream, including TLS inside HTTPS CONNECT."""

    def __init__(self, reader, writer, certificate, alpn):
        self.reader, self.writer = reader, writer
        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.tls = context(certificate, alpn).wrap_bio(
            self.incoming, self.outgoing, server_hostname=HOSTNAME
        )
        self.buffer = bytearray()
        self.transport = writer.transport

    def output(self):
        pending = self.outgoing.read()
        if pending:
            self.writer.write(pending)

    async def handshake(self):
        while True:
            try:
                self.tls.do_handshake()
            except ssl.SSLWantReadError:
                self.output()
                await self.writer.drain()
                data = await self.reader.read(65536)
                if not data:
                    raise EOFError("proxy ended before origin TLS handshake") from None
                self.incoming.write(data)
            else:
                self.output()
                await self.writer.drain()
                return

    def write(self, data):
        for offset in range(0, len(data), 32768):
            self.tls.write(data[offset : offset + 32768])
        self.output()

    async def drain(self):
        await self.writer.drain()

    async def decrypted(self, size=65536):
        while True:
            try:
                return self.tls.read(size)
            except ssl.SSLWantReadError:
                self.output()
                await self.writer.drain()
                data = await self.reader.read(65536)
                if not data:
                    return b""
                self.incoming.write(data)
            except ssl.SSLZeroReturnError:
                return b""

    async def read(self, size=65536):
        if self.buffer:
            result = bytes(self.buffer[:size])
            del self.buffer[:size]
            return result
        return await self.decrypted(size)

    async def readexactly(self, count):
        result = bytearray()
        while len(result) < count:
            data = await self.read(count - len(result))
            if not data:
                raise EOFError("origin TLS ended before expected bytes")
            result.extend(data)
        return bytes(result)

    async def readuntil(self, separator):
        while True:
            position = self.buffer.find(separator)
            if position >= 0:
                size = position + len(separator)
                result = bytes(self.buffer[:size])
                del self.buffer[:size]
                return result
            data = await self.decrypted()
            if not data:
                raise EOFError("origin TLS ended before expected delimiter")
            self.buffer.extend(data)
            if len(self.buffer) > 2 * 1024 * 1024:
                raise ValueError("scripted response exceeded its bound")

    def close(self):
        self.writer.close()

    def is_closing(self):
        return self.writer.is_closing()

    async def wait_closed(self):
        await self.writer.wait_closed()

    def get_extra_info(self, name, default=None):
        return (
            self.tls
            if name == "ssl_object"
            else self.writer.get_extra_info(name, default)
        )


async def open_proxy(proxy, proxy_certificate):
    kwargs = {}
    if proxy.mode == "https":
        kwargs = {
            "ssl": context(proxy_certificate, ("http/1.1",)),
            "server_hostname": PROXY_HOST,
        }
    return await asyncio.wait_for(
        asyncio.open_connection(*proxy.address, **kwargs), TIMEOUT
    )


async def open_tunnel(proxy, origin_certificate, proxy_certificate, *, alpn, fields=()):
    reader, writer = await open_proxy(proxy, proxy_certificate)
    try:
        if proxy.mode == "socks5":
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            if await reader.readexactly(2) != b"\x05\x00":
                raise AssertionError("SOCKS5 greeting rejected")
            name = HOSTNAME.encode()
            head = (
                b"\x05\x01\x00\x03"
                + bytes((len(name),))
                + name
                + proxy.origin[1].to_bytes(2, "big")
            )
            writer.write(head)
            await writer.drain()
            if (await reader.readexactly(10))[:2] != b"\x05\x00":
                raise AssertionError("SOCKS5 CONNECT rejected")
        else:
            target = f"{HOSTNAME}:{proxy.origin[1]}".encode()
            head = (
                b"\r\n".join(
                    [b"CONNECT " + target + b" HTTP/1.1", b"Host: " + target, *fields]
                )
                + b"\r\n\r\n"
            )
            writer.write(head)
            await writer.drain()
            if not (await reader.readuntil(b"\r\n\r\n")).startswith(b"HTTP/1.1 200"):
                raise AssertionError("CONNECT rejected")
        tls = TunnelTls(reader, writer, origin_certificate, alpn)
        await asyncio.wait_for(tls.handshake(), TIMEOUT)
        return tls
    except BaseException as primary:
        cleanup = []
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), TIMEOUT)
        except BaseException as error:
            cleanup.append(error)
        raise_capture_failures(primary, tuple(cleanup))


async def open_h2(tls):
    peer = ScriptedH2(tls, tls)
    try:
        peer.connection.initiate_connection()
        await peer.flush()
        operation = peer.pump()
        try:
            peer.task = asyncio.create_task(operation)
        except BaseException:
            operation.close()
            raise
        await peer.wait(lambda: peer.settings_received)
        return peer
    except BaseException as error:
        await peer.close(error)


@contextlib.asynccontextmanager
async def servers(mode):
    certificate, proxy_certificate = (
        generate_certificate(),
        generate_certificate(PROXY_HOST),
    )
    origin = TunnelOrigin(certificate)
    proxy = None
    primary = None
    try:
        await origin.start("127.0.0.1")
        run = CaptureRun(
            "scripted",
            ServerPolicy(),
            {"tls": b"owned page"},
            observation_seconds=0,
        )
        origin.begin_run(run)
        proxy = TunnelServer(mode, proxy_certificate, origin.tls_address)
        await proxy.start()
        tunnel_run = proxy.begin_run(run)
        yield origin, proxy, run, tunnel_run, certificate, proxy_certificate
    except BaseException as error:
        primary = error
    cleanup = []
    for server in (proxy, origin):
        if server is not None:
            try:
                await server.close()
            except BaseException as error:
                cleanup.append(error)
    raise_capture_failures(primary, tuple(cleanup))
