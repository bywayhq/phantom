"""Independent h2 peer checks cancellation on a shared cleartext connection."""

import asyncio
import gzip
import socket
import threading
import unittest

import h2.config
import h2.connection
import h2.events
from phantom_http import AsyncClient, BodyLimitExceeded, ContentDecoding, Header

PROFILE = "chrome/154.0.8037.97/windows-11-26200/r1"


class H2Peer:
    def __init__(self, *, overflow_body=b"a"):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
        self.listener.settimeout(8)
        self.url = f"http://127.0.0.1:{self.listener.getsockname()[1]}"
        self.reset = threading.Event()
        self.error = None
        self.requests = []
        self.headers = []
        self.reset_code = None
        self.reset_stream = None
        self.premature_close = False
        self.overflow_body = overflow_body
        self.worker = threading.Thread(target=self.run, daemon=True)

    def __enter__(self):
        self.worker.start()
        return self

    def __exit__(self, *_):
        self.listener.close()
        self.worker.join(8)
        if self.worker.is_alive():
            raise AssertionError("HTTP/2 peer did not stop")
        if self.error is not None:
            raise self.error

    def run(self):
        try:
            stream, _ = self.listener.accept()
            with stream:
                stream.settimeout(8)
                connection = h2.connection.H2Connection(
                    config=h2.config.H2Configuration(client_side=False)
                )
                connection.initiate_connection()
                stream.sendall(connection.data_to_send())
                healthy = None
                overflow = None
                while data := stream.recv(65536):
                    for event in connection.receive_data(data):
                        if isinstance(event, h2.events.RequestReceived):
                            path = dict(event.headers)[b":path"]
                            self.requests.append((event.stream_id, path))
                            self.headers.append(event.headers)
                            fields = [(":status", "200")]
                            if path == b"/decode-overflow":
                                fields.append(("content-encoding", "gzip"))
                            connection.send_headers(event.stream_id, fields)
                            if path == b"/stall":
                                connection.send_data(event.stream_id, b"a")
                            elif path in (b"/overflow", b"/decode-overflow"):
                                overflow = event.stream_id
                            elif path == b"/healthy":
                                healthy = event.stream_id
                                if overflow is not None:
                                    connection.send_data(
                                        overflow,
                                        gzip.compress(b"hello", mtime=0)
                                        if self.requests[0][1] == b"/decode-overflow"
                                        else self.overflow_body,
                                    )
                            else:
                                connection.send_data(
                                    event.stream_id, b"hello", end_stream=True
                                )
                        elif isinstance(event, h2.events.StreamReset):
                            self.reset_code = event.error_code
                            self.reset_stream = event.stream_id
                            self.reset.set()
                            if healthy is not None:
                                connection.send_data(healthy, b"hello", end_stream=True)
                        elif isinstance(event, h2.events.ConnectionTerminated):
                            self.premature_close = len(self.requests) != 3
                            return
                    output = connection.data_to_send()
                    if output:
                        stream.sendall(output)
                self.premature_close = len(self.requests) != 3
        except Exception as error:
            self.error = error


class MultiplexingTests(unittest.IsolatedAsyncioTestCase):
    async def test_sensitive_header_never_indexes_and_duplicate_order_is_preserved(
        self,
    ):
        with H2Peer() as peer:
            async with AsyncClient(
                profile=PROFILE, protocol="h2", timeout_ms=5000
            ) as client:
                for path in ("/first", "/second", "/third"):
                    response = await client.request(
                        "GET",
                        peer.url + path,
                        headers=[
                            ("x-duplicate", b"one"),
                            Header("x-secret", b"private", sensitive=True),
                            ("x-duplicate", b"two"),
                        ],
                    )
                    self.assertEqual(await response.read(max_bytes=5), b"hello")
            self.assertEqual(len(peer.headers), 3)
            for headers in peer.headers:
                supplied = [field for field in headers if field[0].startswith(b"x-")]
                self.assertEqual(
                    supplied,
                    [
                        (b"x-duplicate", b"one"),
                        (b"x-secret", b"private"),
                        (b"x-duplicate", b"two"),
                    ],
                )
                self.assertFalse(supplied[1].indexable)
        self.assertFalse(peer.premature_close)

    async def test_cancel_one_body_keeps_other_stream_and_connection(self):
        await self.check_body_isolation("chunk")

    async def test_cancel_collection_keeps_other_stream_and_connection(self):
        await self.check_body_isolation("collect")

    async def test_collection_overflow_keeps_other_stream_and_connection(self):
        await self.check_body_isolation("overflow")

    async def test_decoded_stream_limit_keeps_other_stream_and_connection(self):
        await self.check_body_isolation("decoded")

    async def check_body_isolation(self, operation):
        with H2Peer() as peer:
            async with AsyncClient(
                profile=PROFILE, protocol="h2", timeout_ms=5000
            ) as client:
                path = {
                    "overflow": "/overflow",
                    "decoded": "/decode-overflow",
                }.get(operation, "/stall")
                stalled = await client.request(
                    "GET",
                    peer.url + path,
                    headers=[("accept-encoding", "gzip")]
                    if operation == "decoded"
                    else (),
                    content_decoding=ContentDecoding.advertised(4)
                    if operation == "decoded"
                    else None,
                )
                self.assertEqual(stalled.protocol, "h2")
                if operation not in ("overflow", "decoded"):
                    self.assertEqual(await stalled.read_chunk(), b"a")
                healthy = await client.request("GET", peer.url + "/healthy")
                other = asyncio.create_task(healthy.read(max_bytes=5))
                if operation in ("overflow", "decoded"):
                    with self.assertRaises(BodyLimitExceeded):
                        await stalled.read(
                            max_bytes=10 if operation == "decoded" else 0
                        )
                    if operation == "decoded":
                        self.assertEqual(stalled.decoded_content_codings, ("gzip",))
                else:
                    pending = asyncio.create_task(
                        stalled.read_chunk()
                        if operation == "chunk"
                        else stalled.read(max_bytes=20)
                    )
                    await asyncio.sleep(0.05)
                    self.assertFalse(other.done())
                    pending.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await pending
                self.assertTrue(await asyncio.to_thread(peer.reset.wait, 5))
                self.assertEqual(peer.reset_code, 8)  # HTTP/2 CANCEL
                self.assertEqual(peer.reset_stream, peer.requests[0][0])
                self.assertIsNone(await stalled.read_chunk())
                self.assertEqual(await other, b"hello")
                reused = await client.request("GET", peer.url + "/reuse")
                self.assertEqual(await reused.read(max_bytes=5), b"hello")
                self.assertEqual(
                    [path for _, path in peer.requests],
                    [path.encode(), b"/healthy", b"/reuse"],
                )
                self.assertEqual(len({stream for stream, _ in peer.requests}), 3)
        self.assertFalse(peer.premature_close)
