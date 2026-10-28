"""Bounded HTTP/3 EventSource reconnection peer for public bindings."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import threading
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

LIMIT_SECONDS = 30
CANCELLED = 0x10C


def event(name: str) -> None:
    print(json.dumps({"event": name}), flush=True)


def write_json(path: Path, value: dict) -> None:
    data = json.dumps(value).encode()
    if len(data) > 65536:
        raise ValueError("peer receipt exceeds its bound")
    path.write_bytes(data)


def stop_command() -> asyncio.Future[str]:
    loop = asyncio.get_running_loop()
    command = loop.create_future()
    descriptor = sys.stdin.fileno()

    def complete(value: str | Exception) -> None:
        if command.done():
            return
        if isinstance(value, Exception):
            command.set_exception(value)
        else:
            command.set_result(value)

    def read() -> None:
        try:
            line = bytearray()
            while len(line) < 6 and not line.endswith(b"\n"):
                chunk = os.read(descriptor, 6 - len(line))
                if not chunk:
                    break
                line.extend(chunk)
            value = line.decode("ascii")
        except Exception as error:
            value = error
        try:
            loop.call_soon_threadsafe(complete, value)
        except RuntimeError:
            # The peer already exited; the daemon owns no buffered stdin lock.
            return

    # Raw reads avoid a TextIO lock during finalization. A daemon cannot keep
    # this single-command subprocess alive after its deadline or peer failure.
    threading.Thread(target=read, name="events-peer-stop", daemon=True).start()
    return command


class EventsProtocol(QuicConnectionProtocol):
    def __init__(self, *args, owner: Peer, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.owner = owner
        self.http = None
        self.requests = []
        self.event_requests = 0
        self.healthy = None
        self.released = False
        self.rejected = None
        self.cancellations = []
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
            if value.stream_id != self.rejected or value.error_code != CANCELLED:
                raise ValueError("unexpected cancellation of an unrelated stream")
            self.cancellations.append(type(value).__name__)
        if self.http is None:
            return
        for message in self.http.handle_event(value):
            if isinstance(message, HeadersReceived):
                self.headers(message)
            elif isinstance(message, DataReceived) and message.data:
                raise ValueError("GET request contained DATA")

    def headers(self, message: HeadersReceived) -> None:
        fields = dict(message.headers)
        path = fields.get(b":path", b"").decode("ascii")
        expected = {
            None: ("/events", "/healthy", "/events", "/events", "/reuse"),
            "initial": ("/events", "/reuse"),
            "reconnect": ("/events", "/events", "/reuse"),
        }[self.owner.reject]
        if (
            len(self.requests) >= len(expected)
            or path != expected[len(self.requests)]
            or fields.get(b":method") != b"GET"
            or any(item["stream"] == message.stream_id for item in self.requests)
        ):
            raise ValueError("unexpected request order, method or trailers")
        self.requests.append(
            {
                "path": path,
                "stream": message.stream_id,
                "headers": [
                    [name.decode("ascii"), value.decode("ascii")]
                    for name, value in message.headers
                ],
            }
        )
        if path == "/events":
            self.event_requests += 1
            expected_id = (None, b"7", b"9")[self.event_requests - 1]
            ids = [value for name, value in message.headers if name == b"last-event-id"]
            if ids != ([] if expected_id is None else [expected_id]):
                raise ValueError("missing, repeated or incorrect reconnect event ID")
            if fields.get(b"accept") != b"text/event-stream":
                raise ValueError("missing EventSource Accept field")
            rejected = self.owner.reject == "initial" or (
                self.owner.reject == "reconnect" and self.event_requests == 2
            )
            status = b"200"
            if rejected:
                status = b"403"
            elif self.event_requests == 3:
                status = b"204"
            self.http.send_headers(
                message.stream_id,
                [(b":status", status), (b"content-type", b"text/event-stream")],
                end_stream=status == b"204",
            )
            if rejected:
                self.rejected = message.stream_id
                self.http.send_data(message.stream_id, b"private", end_stream=True)
                event("rejected")
            elif status == b"200":
                payload = (
                    b"id: 7\nretry: 0\ndata: first\n\n"
                    if self.event_requests == 1
                    else b"id: 9\ndata: second\n\n"
                )
                self.http.send_data(message.stream_id, payload, end_stream=True)
            else:
                if self.healthy is None:
                    raise ValueError("terminal response has no live sibling")
                self.http.send_data(self.healthy, b"healthy", end_stream=True)
                self.released = True
        else:
            self.http.send_headers(message.stream_id, [(b":status", b"200")])
            if path == "/healthy":
                self.healthy = message.stream_id
                event("live")
            else:
                if self.rejected is None and not self.released:
                    raise ValueError("reuse preceded scenario completion")
                self.http.send_data(message.stream_id, b"ok", end_stream=True)
                self.owner.complete = True
                write_json(
                    self.owner.directory / "result.json",
                    {
                        "connections": len(self.owner.protocols),
                        "requests": self.requests,
                        "healthy_released": self.released,
                        "rejection": self.owner.reject,
                        "cancellations": self.cancellations,
                    },
                )
                event("complete")
        self.transmit()


class Peer:
    def __init__(self, directory: Path, reject: str | None) -> None:
        self.directory = directory
        self.reject = reject
        self.protocols = []
        self.complete = False
        self.failure = asyncio.get_running_loop().create_future()

    def fail(self, error: Exception) -> None:
        if not self.failure.done():
            self.failure.set_result(error)

    def callback_failed(self, _loop: asyncio.AbstractEventLoop, context: dict) -> None:
        self.fail(context.get("exception") or RuntimeError("peer callback failed"))


async def run(directory: Path, reject: str | None) -> None:
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
            create_protocol=lambda *args, **kwargs: EventsProtocol(
                *args, owner=owner, **kwargs
            ),
        )
    )
    loop = asyncio.get_running_loop()
    previous = loop.get_exception_handler()
    loop.set_exception_handler(owner.callback_failed)
    command = stop_command()
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
        done, _ = await asyncio.wait(
            {command, owner.failure},
            timeout=LIMIT_SECONDS,
            return_when=asyncio.FIRST_COMPLETED,
        )
        if owner.failure in done:
            raise owner.failure.result()
        if (
            command not in done
            or command.result().strip() != "stop"
            or not owner.complete
        ):
            raise ValueError("missing controlled shutdown or incomplete scenario")
        for protocol in owner.protocols:
            protocol.close(error_code=0x100)
        await asyncio.wait_for(
            asyncio.gather(*(p.wait_closed() for p in owner.protocols)), 5
        )
        if owner.failure.done():
            raise owner.failure.result()
    finally:
        server.close()
        command.cancel()
        loop.set_exception_handler(previous)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--reject", choices=("initial", "reconnect"))
    args = parser.parse_args()
    try:
        asyncio.run(run(args.directory, args.reject))
    except Exception as error:
        write_json(
            args.directory / "error.json",
            {
                "error": type(error).__name__,
                "message": str(error),
            },
        )
        raise


if __name__ == "__main__":
    main()
