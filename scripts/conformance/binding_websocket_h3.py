"""Bounded RFC 9220 peer for native WebSocket ownership and cancellation tests."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import (
    ConnectionTerminated,
    ProtocolNegotiated,
    QuicEvent,
    StopSendingReceived,
    StreamReset,
)

try:
    from .aioquic_versions import serve_past_reserved_ports
    from .loopback_tls import generate_loopback_certificate
except ImportError:  # installed fixture execution
    from aioquic_versions import serve_past_reserved_ports
    from loopback_tls import generate_loopback_certificate

CANCELLED = 0x10C
LIMIT_SECONDS = 30
ECHO_FRAMES = ((1, b"hello"), (2, b"\x00\xff"), (8, b"\x03\xe8done"))


def event(name: str) -> None:
    print(json.dumps({"event": name}), flush=True)


def write_json(path: Path, value: dict) -> None:
    data = json.dumps(value).encode()
    if len(data) > 65536:
        raise ValueError("peer receipt exceeds its bound")
    path.write_bytes(data)


class WebSocketProtocol(QuicConnectionProtocol):
    def __init__(self, *args, owner: Peer, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.owner = owner
        self.http = None
        self.requests = {}
        self.echo = bytearray()
        self.frames = 0
        self.resets = {}
        self.released = False
        owner.protocols.append(self)

    def quic_event_received(self, value: QuicEvent) -> None:
        try:
            self.receive(value)
        except Exception as error:
            self.owner.fail(error)
            self.close(error_code=0x102, reason_phrase="test peer rejected input")

    def receive(self, value: QuicEvent) -> None:
        if isinstance(value, ProtocolNegotiated):
            if value.alpn_protocol != "h3" or len(self.owner.protocols) != 1:
                raise ValueError("expected one HTTP/3 connection")
            self.http = H3Connection(self._quic)
        if isinstance(value, ConnectionTerminated) and (
            not self.owner.complete or value.error_code not in (0, 0x100)
        ):
            raise ValueError("connection terminated before scenario completion")
        if isinstance(value, (StreamReset, StopSendingReceived)):
            self.cancelled(value)
        if self.http is None:
            return
        for message in self.http.handle_event(value):
            if isinstance(message, HeadersReceived):
                self.headers(message)
            elif isinstance(message, DataReceived):
                self.data(message)

    def cancelled(self, value: StreamReset | StopSendingReceived) -> None:
        if value.stream_id != self.requests.get("/cancel"):
            raise ValueError("unexpected cancellation of an unrelated stream")
        if value.error_code != CANCELLED or "/healthy" not in self.requests:
            raise ValueError("invalid cancellation code or missing live sibling")
        kind = "reset_stream" if isinstance(value, StreamReset) else "stop_sending"
        self.resets[kind] = value.error_code
        if len(self.resets) == 2 and not self.released:
            self.released = True
            self.http.send_data(self.requests["/healthy"], b"healthy", end_stream=True)
            self.transmit()
            event("cancelled")

    def headers(self, message: HeadersReceived) -> None:
        fields = dict(message.headers)
        path = fields.get(b":path", b"").decode("ascii")
        expected = (
            ("/warm", "/reject")
            if self.owner.reject
            else ("/warm", "/echo", "/cancel", "/healthy", "/reuse")
        )
        if len(self.requests) >= len(expected) or path != expected[len(self.requests)]:
            raise ValueError("unexpected request order or trailers")
        self.requests[path] = message.stream_id
        websocket = path in ("/echo", "/cancel", "/reject")
        if fields.get(b":method") != (b"CONNECT" if websocket else b"GET"):
            raise ValueError("unexpected request method")
        if websocket:
            if fields.get(b":protocol") != b"websocket" or message.stream_ended:
                raise ValueError("expected an open RFC 9220 CONNECT stream")
            if any(name in fields for name in (b"connection", b"upgrade")):
                raise ValueError("HTTP/1-only opening fields on HTTP/3")
            if path == "/echo":
                if fields.get(b"sec-websocket-protocol") != b"chat":
                    raise ValueError("missing requested WebSocket subprotocol")
                headers = [(b":status", b"200"), (b"sec-websocket-protocol", b"chat")]
            elif path == "/reject":
                headers = [
                    (b":status", b"403"),
                    (b"x-duplicate", b"one"),
                    (b"x-duplicate", b"two"),
                ]
            else:
                headers = [(b":status", b"200")]
            self.http.send_headers(message.stream_id, headers)
            if path == "/reject":
                self.http.send_data(message.stream_id, b"de", end_stream=False)
                event("rejected")
        else:
            self.http.send_headers(message.stream_id, [(b":status", b"200")])
            if path == "/healthy":
                event("live")
            else:
                if path == "/reuse" and not self.released:
                    raise ValueError("reuse preceded selected-stream cancellation")
                self.http.send_data(message.stream_id, b"ok", end_stream=True)
                if path == "/reuse":
                    self.complete()
        self.transmit()

    def data(self, message: DataReceived) -> None:
        if message.stream_id != self.requests.get("/echo"):
            if message.data:
                raise ValueError("unexpected request DATA")
            return
        self.echo.extend(message.data)
        if len(self.echo) > 4096:
            raise ValueError("WebSocket frame exceeds peer bound")
        while len(self.echo) >= 2:
            first, second = self.echo[:2]
            size = second & 127
            if first & 0xF0 != 0x80 or second & 0x80 == 0 or size >= 126:
                raise ValueError("expected a short, masked, unfragmented client frame")
            if len(self.echo) < 6 + size:
                break
            key = self.echo[2:6]
            payload = bytes(
                byte ^ key[index % 4]
                for index, byte in enumerate(self.echo[6 : 6 + size])
            )
            del self.echo[: 6 + size]
            if (
                self.frames >= len(ECHO_FRAMES)
                or (first & 15, payload) != ECHO_FRAMES[self.frames]
            ):
                raise ValueError("unexpected WebSocket frame or order")
            self.frames += 1
            self.http.send_data(
                message.stream_id,
                bytes((first, size)) + payload,
                end_stream=self.frames == len(ECHO_FRAMES),
            )
            self.transmit()
        if message.stream_ended and (self.frames != 3 or self.echo):
            raise ValueError("WebSocket ended before its complete close handshake")

    def release_rejection(self) -> None:
        if (
            not self.owner.reject
            or "/reject" not in self.requests
            or self.owner.complete
        ):
            raise ValueError("unexpected rejection-body release")
        self.http.send_data(self.requests["/reject"], b"nied", end_stream=True)
        self.transmit()
        self.complete()

    def complete(self) -> None:
        self.owner.complete = True
        write_json(
            self.owner.directory / "result.json",
            {
                "connections": len(self.owner.protocols),
                "streams": self.requests,
                "frames": self.frames,
                "cancellations": self.resets,
                "healthy_released": self.released,
                "rejected": self.owner.reject,
            },
        )
        event("complete")


class Peer:
    def __init__(self, directory: Path, reject: bool) -> None:
        self.directory = directory
        self.reject = reject
        self.protocols = []
        self.failure = asyncio.get_running_loop().create_future()
        self.complete = False

    def fail(self, error: Exception) -> None:
        if not self.failure.done():
            self.failure.set_result(error)

    def callback_failed(self, _loop: asyncio.AbstractEventLoop, context: dict) -> None:
        self.fail(context.get("exception") or RuntimeError("peer callback failed"))


async def run(directory: Path, reject: bool) -> None:
    await asyncio.to_thread(directory.mkdir, exist_ok=True)
    certificate = await asyncio.to_thread(generate_loopback_certificate, directory)
    owner = Peer(directory, reject)
    configuration = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
    configuration.load_cert_chain(
        certificate.certificate_pem, certificate.private_key_pem
    )
    server = await serve_past_reserved_ports(
        lambda: serve(
            "127.0.0.1",
            0,
            configuration=configuration,
            create_protocol=lambda *args, **kwargs: WebSocketProtocol(
                *args, owner=owner, **kwargs
            ),
        )
    )
    loop = asyncio.get_running_loop()
    previous = loop.get_exception_handler()
    loop.set_exception_handler(owner.callback_failed)
    command = None
    try:
        port = server._transport.get_extra_info("sockname")[1]
        write_json(
            directory / "ready.json",
            {
                "url": f"https://127.0.0.1:{port}",
                "root_der": list(certificate.root_der.read_bytes()),
            },
        )
        event("ready")
        async with asyncio.timeout(LIMIT_SECONDS):
            while True:
                command = asyncio.create_task(asyncio.to_thread(sys.stdin.readline))
                done, _ = await asyncio.wait(
                    {command, owner.failure}, return_when=asyncio.FIRST_COMPLETED
                )
                if owner.failure in done:
                    raise owner.failure.result()
                instruction = command.result().strip()
                if instruction == "release" and len(owner.protocols) == 1:
                    owner.protocols[0].release_rejection()
                elif instruction == "stop" and owner.complete:
                    break
                else:
                    raise ValueError("unexpected command or incomplete scenario")
        for protocol in owner.protocols:
            protocol.close(error_code=0x100)
        await asyncio.wait_for(
            asyncio.gather(*(p.wait_closed() for p in owner.protocols)), 5
        )
        if owner.failure.done():
            raise owner.failure.result()
    finally:
        server.close()
        if command is not None and not command.done():
            command.cancel()
        loop.set_exception_handler(previous)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--reject", action="store_true")
    args = parser.parse_args()
    try:
        asyncio.run(run(args.directory, args.reject))
    except Exception as error:
        write_json(
            args.directory / "error.json",
            {"error": type(error).__name__, "message": str(error)},
        )
        raise


if __name__ == "__main__":
    main()
