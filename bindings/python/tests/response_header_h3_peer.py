"""Raw QPACK response fields for the three public binding header controls."""

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3_ALPN, H3Connection, encode_frame
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, ProtocolNegotiated

# Reuse the installed conformance helpers selected by the existing H3 setup.
sys.path.insert(0, str(Path(os.environ["PHANTOM_H3_PEER_SCRIPT"]).resolve().parent))
from aioquic_versions import serve_past_reserved_ports  # noqa: E402
from loopback_tls import generate_loopback_certificate  # noqa: E402

# RFC 9204: zero dynamic references, indexed static :status=200 (index 25),
# then literal-name fields. 0x23 has N=0; 0x33 has N=1. No Huffman coding.
BLOCK = b"\x00\x00\xd9\x23x-a\x05first\x33x-b\x02\x80B\x23x-a\x04last"


class Protocol(QuicConnectionProtocol):
    def __init__(self, *args, owner, **kwargs):
        super().__init__(*args, **kwargs)
        self.owner = owner
        self.http = None
        self.paths = []
        owner.protocols.append(self)

    def quic_event_received(self, value):
        try:
            if isinstance(value, ProtocolNegotiated):
                if value.alpn_protocol != "h3" or len(self.owner.protocols) != 1:
                    raise ValueError("expected one HTTP/3 connection")
                self.http = H3Connection(self._quic)
            if isinstance(value, ConnectionTerminated) and not self.owner.stopping:
                raise ValueError("connection ended before controlled shutdown")
            if self.http is None:
                return
            for message in self.http.handle_event(value):
                if isinstance(message, DataReceived) and message.data:
                    raise ValueError("GET request contained DATA")
                if not isinstance(message, HeadersReceived):
                    continue
                fields = dict(message.headers)
                expected = b"/one" if not self.paths else b"/two"
                if (
                    len(self.paths) >= 2
                    or fields.get(b":method") != b"GET"
                    or fields.get(b":path") != expected
                    or not message.stream_ended
                ):
                    raise ValueError("unexpected request or trailers")
                self.paths.append(expected)
                self._quic.send_stream_data(
                    message.stream_id,
                    encode_frame(1, BLOCK) + encode_frame(0, b"ok"),
                    end_stream=True,
                )
                self.transmit()
        except Exception as error:
            if not self.owner.failure.done():
                self.owner.failure.set_result(error)
            self.close(error_code=0x102)


async def run(directory):
    directory.mkdir(exist_ok=True)
    certificate = generate_loopback_certificate(directory)
    configuration = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
    configuration.load_cert_chain(
        certificate.certificate_pem, certificate.private_key_pem
    )
    loop = asyncio.get_running_loop()

    class Owner:
        protocols = []
        stopping = False
        failure = loop.create_future()

    owner = Owner()
    previous_handler = loop.get_exception_handler()

    def failed_callback(_loop, context):
        if not owner.failure.done():
            owner.failure.set_result(
                context.get("exception") or RuntimeError("peer callback failed")
            )

    loop.set_exception_handler(failed_callback)
    server = await serve_past_reserved_ports(
        lambda: serve(
            "127.0.0.1",
            0,
            configuration=configuration,
            create_protocol=lambda *args, **kwargs: Protocol(
                *args, owner=owner, **kwargs
            ),
        )
    )
    command = asyncio.create_task(asyncio.to_thread(sys.stdin.readline))
    try:
        port = server._transport.get_extra_info("sockname")[1]
        (directory / "ready.json").write_text(
            json.dumps(
                {
                    "url": f"https://127.0.0.1:{port}",
                    "root_der": list(certificate.root_der.read_bytes()),
                }
            ),
            encoding="utf-8",
        )
        print('{"event":"ready"}', flush=True)
        done, _ = await asyncio.wait(
            {command, owner.failure}, timeout=20, return_when=asyncio.FIRST_COMPLETED
        )
        if owner.failure in done:
            raise owner.failure.result()
        if command not in done or command.result().strip() != "stop":
            raise ValueError("missing controlled shutdown")
        if len(owner.protocols) != 1 or owner.protocols[0].paths != [b"/one", b"/two"]:
            raise ValueError("incomplete same-connection requests")
        owner.stopping = True
        for protocol in owner.protocols:
            protocol.close(error_code=0x100)
        await asyncio.wait_for(
            asyncio.gather(*(protocol.wait_closed() for protocol in owner.protocols)), 5
        )
        if owner.failure.done():
            raise owner.failure.result()
    finally:
        server.close()
        command.cancel()
        loop.set_exception_handler(previous_handler)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    asyncio.run(run(parser.parse_args().directory))
