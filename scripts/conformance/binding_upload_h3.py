"""Independent loopback HTTP/3 upload cancellation peer for public bindings."""

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
    StopSendingReceived,
    StreamReset,
)

try:
    from .aioquic_versions import serve_past_reserved_ports
    from .loopback_tls import generate_loopback_certificate
except ImportError:  # direct installed fixture execution
    from aioquic_versions import serve_past_reserved_ports
    from loopback_tls import generate_loopback_certificate

LIMIT_SECONDS = 20
CANCELLED = 0x10C
MULTIPART_PREFIX = (
    b'--binding-h3\r\nContent-Disposition: form-data; name="file"\r\n'
    b"Content-Type: application/octet-stream\r\n\r\n"
)


def event(name):
    print(json.dumps({"event": name}), flush=True)


def write_json(path, value):
    data = json.dumps(value).encode()
    if len(data) > 65536:
        raise ValueError("peer receipt exceeds its bound")
    path.write_bytes(data)


class UploadProtocol(QuicConnectionProtocol):
    def __init__(self, *args, owner, **kwargs):
        super().__init__(*args, **kwargs)
        self.owner = owner
        self.http = None
        self.requests = {}
        self.upload_bytes = 0
        self.selected = None
        self.healthy = None
        self.resets = {}
        self.live = False
        self.released = False
        owner.protocols.append(self)

    def quic_event_received(self, value):
        try:
            self.receive(value)
        except Exception as error:
            self.owner.fail(error)
            self.close(error_code=0x102, reason_phrase="test peer rejected input")

    def receive(self, value):
        if isinstance(value, ProtocolNegotiated):
            if value.alpn_protocol != "h3" or len(self.owner.protocols) != 1:
                raise ValueError("expected one HTTP/3 connection")
            self.http = H3Connection(self._quic)
        if isinstance(value, ConnectionTerminated):
            if not self.owner.stopping:
                raise ValueError("connection terminated before controlled shutdown")
            if value.error_code not in (0, 0x100):
                raise ValueError("connection terminated with an error")
        if isinstance(value, (StreamReset, StopSendingReceived)):
            if value.stream_id != self.selected or value.error_code != CANCELLED:
                raise ValueError("unexpected stream cancellation or code")
            if not self.live:
                raise ValueError("selected stream cancelled before live sibling")
            kind = "reset_stream" if isinstance(value, StreamReset) else "stop_sending"
            self.resets[kind] = value.error_code
            if len(self.resets) == 2 and not self.released:
                self.released = True
                self.http.send_data(self.healthy, b"healthy", end_stream=True)
                self.transmit()
                event("cancelled")
        if self.http is None:
            return
        for message in self.http.handle_event(value):
            if isinstance(message, HeadersReceived):
                self.headers(message)
            elif isinstance(message, DataReceived):
                if message.stream_id != self.selected:
                    if message.data:
                        raise ValueError("GET request contained DATA")
                    continue
                if message.stream_ended:
                    raise ValueError("unexpected request DATA or completed upload")
                end = self.upload_bytes + len(message.data)
                if message.data != self.owner.expected_upload[self.upload_bytes : end]:
                    raise ValueError("unexpected upload payload")
                self.upload_bytes = end
                if self.upload_bytes == len(self.owner.expected_upload):
                    self.http.send_headers(self.selected, [(b":status", b"200")])
                    self.http.send_data(self.selected, b"a", end_stream=False)
                    self.transmit()
            self.publish_live()

    def headers(self, message):
        fields = dict(message.headers)
        path = fields.get(b":path")
        expected = (b"/warm", b"/upload", b"/healthy", b"/reuse")
        if len(self.requests) >= 4 or path != expected[len(self.requests)]:
            raise ValueError("unexpected request order or trailers")
        if message.stream_id in self.requests.values():
            raise ValueError("request reused a stream")
        self.requests[path.decode()] = message.stream_id
        method = b"POST" if path == b"/upload" else b"GET"
        if fields.get(b":method") != method:
            raise ValueError("unexpected request method")
        if path == b"/upload":
            if message.stream_ended or b"content-length" in fields:
                raise ValueError(
                    "selected upload must have an unfinished unknown length"
                )
            self.selected = message.stream_id
            if self.owner.multipart and fields.get(b"content-type") != (
                b"multipart/form-data; boundary=binding-h3"
            ):
                raise ValueError("unexpected multipart content type")
            return
        if path == b"/healthy":
            self.healthy = message.stream_id
            self.http.send_headers(self.healthy, [(b":status", b"200")])
        else:
            if path == b"/reuse" and not self.released:
                raise ValueError("connection reuse preceded selected cancellation")
            self.http.send_headers(message.stream_id, [(b":status", b"200")])
            self.http.send_data(message.stream_id, b"ok", end_stream=True)
        self.transmit()
        if path == b"/reuse":
            write_json(self.owner.directory / "result.json", self.receipt())
            event("complete")

    def publish_live(self):
        if (
            not self.live
            and self.upload_bytes == len(self.owner.expected_upload)
            and self.healthy is not None
        ):
            self.live = True
            event("live")

    def receipt(self):
        return {
            "protocol": "h3",
            "connections": len(self.owner.protocols),
            "streams": self.requests,
            "upload_bytes": self.upload_bytes,
            "cancellations": self.resets,
            "healthy_released": self.released,
        }


class Peer:
    def __init__(self, directory, multipart=False):
        self.directory = directory
        self.protocols = []
        self.failure = asyncio.get_running_loop().create_future()
        self.stopping = False
        self.multipart = multipart
        self.expected_upload = (MULTIPART_PREFIX if multipart else b"") + b"U" * 1024

    def fail(self, error):
        if not self.failure.done():
            self.failure.set_result(error)

    def callback_failed(self, _loop, context):
        self.fail(context.get("exception") or RuntimeError("peer callback failed"))


async def run(directory, multipart=False):
    directory.mkdir(exist_ok=True)
    certificate = generate_loopback_certificate(directory)
    owner = Peer(directory, multipart)
    configuration = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
    configuration.load_cert_chain(
        certificate.certificate_pem, certificate.private_key_pem
    )
    server = await serve_past_reserved_ports(
        lambda: serve(
            "127.0.0.1",
            0,
            configuration=configuration,
            create_protocol=lambda *args, **kwargs: UploadProtocol(
                *args, owner=owner, **kwargs
            ),
        )
    )
    loop = asyncio.get_running_loop()
    previous_handler = loop.get_exception_handler()
    loop.set_exception_handler(owner.callback_failed)
    command = asyncio.create_task(asyncio.to_thread(sys.stdin.readline))
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
        if command not in done or command.result().strip() != "stop":
            raise ValueError("missing controlled shutdown command")
        if len(owner.protocols) != 1 or len(owner.protocols[0].requests) != 4:
            raise ValueError("incomplete public binding exchange")
        owner.stopping = True
        for protocol in owner.protocols:
            protocol.close(error_code=0x100)
        await asyncio.wait_for(
            asyncio.gather(*(p.wait_closed() for p in owner.protocols)), 5
        )
        if owner.failure.done():
            raise owner.failure.result()
    except Exception:
        event("failed")
        raise
    finally:
        server.close()
        if not command.done():
            command.cancel()
        loop.set_exception_handler(previous_handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--multipart", action="store_true")
    args = parser.parse_args()
    try:
        asyncio.run(run(args.directory, args.multipart))
    except Exception as error:
        write_json(
            args.directory / "error.json",
            {"error": type(error).__name__, "message": str(error)},
        )
        raise


if __name__ == "__main__":
    main()
