"""Independent h2 peer checks cancellation on a shared cleartext connection."""

import asyncio
import socket
import threading
import unittest

import h2.config
import h2.connection
import h2.events
from phantom_http import AsyncClient

PROFILE = "chrome/154.0.8037.97/windows-11-26200/r1"


class H2Peer:
    def __init__(self):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
        self.listener.settimeout(8)
        self.url = f"http://127.0.0.1:{self.listener.getsockname()[1]}"
        self.reset = threading.Event()
        self.error = None
        self.requests = []
        self.reset_code = None
        self.reset_stream = None
        self.premature_close = False
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
                while data := stream.recv(65536):
                    for event in connection.receive_data(data):
                        if isinstance(event, h2.events.RequestReceived):
                            path = dict(event.headers)[b":path"]
                            self.requests.append((event.stream_id, path))
                            connection.send_headers(
                                event.stream_id, [(":status", "200")]
                            )
                            if path == b"/stall":
                                connection.send_data(event.stream_id, b"a")
                            elif path == b"/healthy":
                                healthy = event.stream_id
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
    async def test_cancel_one_body_keeps_other_stream_and_connection(self):
        with H2Peer() as peer:
            async with AsyncClient(
                profile=PROFILE, protocol="h2", timeout_ms=5000
            ) as client:
                stalled = await client.request("GET", peer.url + "/stall")
                self.assertEqual(stalled.protocol, "h2")
                self.assertEqual(await stalled.read_chunk(), b"a")
                healthy = await client.request("GET", peer.url + "/healthy")
                pending = asyncio.create_task(stalled.read_chunk())
                other = asyncio.create_task(healthy.read(max_bytes=5))
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
                    [b"/stall", b"/healthy", b"/reuse"],
                )
                self.assertEqual(len({stream for stream, _ in peer.requests}), 3)
        self.assertFalse(peer.premature_close)
