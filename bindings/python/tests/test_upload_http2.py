"""Zero-window uploads cancel one stream while a live sibling survives."""

import asyncio
import socket
import threading
import unittest

import h2.config
import h2.connection
import h2.events
import h2.settings
from phantom_http import AsyncClient, TimeoutError, TimeoutOverrides

PROFILE = "chrome/154.0.8037.97/windows-11-26200/r1"


class Peer:
    def __init__(self):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
        self.listener.settimeout(5)
        self.url = f"http://127.0.0.1:{self.listener.getsockname()[1]}"
        self.selected = threading.Event()
        self.reset = threading.Event()
        self.reset_code = None
        self.reset_stream = None
        self.data_bytes = 0
        self.requests = []
        self.complete_upload = False
        self.error = None
        self.worker = threading.Thread(target=self.run, daemon=True)

    def __enter__(self):
        self.worker.start()
        return self

    def __exit__(self, *_):
        self.listener.close()
        self.worker.join(5)
        if self.worker.is_alive():
            raise AssertionError("upload HTTP/2 peer did not settle")
        if self.error is not None:
            raise self.error

    def run(self):
        try:
            stream, _ = self.listener.accept()
            with stream:
                stream.settimeout(5)
                connection = h2.connection.H2Connection(
                    config=h2.config.H2Configuration(client_side=False)
                )
                connection.local_settings = h2.settings.Settings(
                    client=False,
                    initial_values={h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 0},
                )
                connection.initiate_connection()
                stream.sendall(connection.data_to_send())
                healthy = None
                while data := stream.recv(65536):
                    for event in connection.receive_data(data):
                        if isinstance(event, h2.events.RequestReceived):
                            headers = dict(event.headers)
                            path = headers[b":path"]
                            self.requests.append((event.stream_id, path, headers))
                            if path in (b"/upload", b"/early", b"/complete"):
                                self.selected.set()
                                if path == b"/early":
                                    connection.send_headers(
                                        event.stream_id, [(":status", "200")]
                                    )
                                    connection.send_data(event.stream_id, b"a")
                                if path == b"/complete":
                                    self.complete_upload = True
                                    connection.send_headers(
                                        event.stream_id, [(":status", "200")]
                                    )
                                    connection.send_data(
                                        event.stream_id, b"early", end_stream=True
                                    )
                            elif path == b"/healthy":
                                healthy = event.stream_id
                                connection.send_headers(healthy, [(":status", "200")])
                                if self.complete_upload:
                                    connection.send_data(
                                        healthy, b"hello", end_stream=True
                                    )
                            else:
                                connection.send_headers(
                                    event.stream_id, [(":status", "200")]
                                )
                                connection.send_data(
                                    event.stream_id, b"hello", end_stream=True
                                )
                        elif isinstance(event, h2.events.DataReceived):
                            self.data_bytes += len(event.data)
                        elif isinstance(event, h2.events.StreamReset):
                            self.reset_code = event.error_code
                            self.reset_stream = event.stream_id
                            self.reset.set()
                            if healthy is None:
                                raise AssertionError(
                                    "selected stream reset before live healthy sibling"
                                )
                            connection.send_data(healthy, b"hello", end_stream=True)
                        elif isinstance(event, h2.events.ConnectionTerminated):
                            if len(self.requests) != 4:
                                raise AssertionError(
                                    "HTTP/2 connection closed before reuse"
                                )
                            return
                    output = connection.data_to_send()
                    if output:
                        stream.sendall(output)
                if len(self.requests) != 4:
                    raise AssertionError(
                        "expected warmup, upload, healthy and reused connection"
                    )
        except BaseException as error:
            self.error = error


class UploadMultiplexingTests(unittest.IsolatedAsyncioTestCase):
    async def test_zero_window_upload_cancellation_preserves_live_sibling(self):
        await self.check_upload(False)

    async def test_total_deadline_closes_unread_early_response_and_producer(self):
        await self.check_upload(True)

    async def test_complete_early_response_abandons_one_shot_upload(self):
        pulled = []
        closed = asyncio.Event()

        async def chunks():
            try:
                pulled.append(True)
                yield b"x" * 1048576
                await asyncio.Future()
            finally:
                closed.set()

        with Peer() as peer:
            async with AsyncClient(
                profile=PROFILE, protocol="h2", timeout_ms=5000
            ) as client:
                warm = await client.request("GET", peer.url + "/warmup")
                self.assertEqual(await warm.read(max_bytes=5), b"hello")
                async with await client.request(
                    "POST", peer.url + "/complete", body=chunks()
                ) as response:
                    self.assertEqual(await response.read(max_bytes=5), b"early")
                if pulled:
                    self.assertTrue(closed.is_set())
                self.assertLessEqual(len(pulled), 1)
                for path in ("/healthy", "/reuse"):
                    response = await client.request("GET", peer.url + path)
                    self.assertEqual(await response.read(max_bytes=5), b"hello")
                self.assertEqual(peer.data_bytes, 0)
                self.assertIsNone(peer.reset_code)
                self.assertEqual(len(peer.requests), 4)

    async def check_upload(self, early):
        closed = asyncio.Event()
        pulled = []

        async def chunks():
            try:
                pulled.append(True)
                yield b"x" * 1048576
                await asyncio.Future()
            finally:
                closed.set()

        with Peer() as peer:
            async with AsyncClient(
                profile=PROFILE, protocol="h2", timeout_ms=5000
            ) as client:
                warm = await client.request("GET", peer.url + "/warmup")
                self.assertEqual(await warm.read(max_bytes=5), b"hello")
                request = asyncio.create_task(
                    client.request(
                        "POST",
                        peer.url + ("/early" if early else "/upload"),
                        body=chunks(),
                        body_length=None if early else 1048576,
                        timeouts=TimeoutOverrides(total=1 if early else None),
                    )
                )
                self.assertTrue(await asyncio.to_thread(peer.selected.wait, 5))
                response = await request if early else None
                healthy = await client.request("GET", peer.url + "/healthy")
                other = asyncio.create_task(healthy.read(max_bytes=5))
                if early:
                    # No response-body poll drives this deadline or producer cleanup.
                    await asyncio.wait_for(closed.wait(), 5)
                    with self.assertRaises(TimeoutError) as caught:
                        await response.read(max_bytes=5)
                    self.assertEqual(caught.exception.timeout_phase, "total")
                else:
                    request.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await request
                self.assertTrue(await asyncio.to_thread(peer.reset.wait, 5))
                self.assertEqual(peer.reset_code, 8)
                self.assertEqual(peer.reset_stream, peer.requests[1][0])
                self.assertEqual(peer.data_bytes, 0)
                self.assertEqual(await other, b"hello")
                await asyncio.wait_for(closed.wait(), 5)
                self.assertLessEqual(len(pulled), 1)
                reuse = await client.request("GET", peer.url + "/reuse")
                self.assertEqual(await reuse.read(max_bytes=5), b"hello")
                fields = peer.requests[1][2]
                if early:
                    self.assertNotIn(b"content-length", fields)
                else:
                    self.assertEqual(fields[b"content-length"], b"1048576")
                self.assertEqual(len({item[0] for item in peer.requests}), 4)
