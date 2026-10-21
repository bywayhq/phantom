"""Shared native transfer controls exercised against independent HTTP peers."""

import asyncio
import unittest

import phantom_http
from phantom_http import (
    AsyncClient,
    Client,
    ContentDecoding,
    Error,
    RedirectPolicy,
    TimeoutOverrides,
    TransferControl,
    TransferLimits,
    TransferSnapshot,
)
from test_client import OPTIONS
from test_content_decoding import GZIP, PAYLOAD, DecodingHandler
from test_http2 import PROFILE, H2Peer
from test_settings_transport import SettingsHandler, peer


class ReplayHandler(SettingsHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_POST(self):
        length = int(self.headers["Content-Length"])
        body = self.rfile.read(length)
        self.server.requests.append((self.path, body))
        self.send_response(307 if self.path == "/redirect" else 200)
        if self.path == "/redirect":
            self.send_header("Location", "/final")
        payload = b"" if self.path == "/redirect" else b"hello"
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
        self.wfile.flush()


class TransferSyncTests(unittest.TestCase):
    def test_native_boundary_rejects_bool_negative_overflow_and_zero_rates(self):
        for index in range(4):
            for value in (True, False, -1, 2**64, 0.5, "private"):
                fields = [None] * 4
                fields[index] = value
                with (
                    self.subTest(index=index),
                    self.assertRaises(phantom_http._native.NativeError) as caught,
                ):
                    phantom_http._native.NativeTransferControl(*fields)
                self.assertEqual(caught.exception.args[0], "input")
                self.assertNotIn("private", str(caught.exception))
        for fields in ((None, None, 0, None), (None, None, None, 0)):
            with self.assertRaises(phantom_http._native.NativeError):
                phantom_http._native.NativeTransferControl(*fields)
        owner = phantom_http._native.NativeTransferControl(0, 2**64 - 1, 1, 2**64 - 1)
        self.assertEqual(owner.snapshot(), (0, 0, 0, 0, 0))

    def test_byte_resend_counts_each_attempt_and_independent_controls_stay_empty(self):
        control = TransferControl(
            limits=TransferLimits(upload_bytes=6, download_bytes=5)
        )
        independent = TransferControl()
        with peer() as server:
            server.RequestHandlerClass = ReplayHandler
            with (
                Client(**OPTIONS) as client,
                client.request(
                    "POST",
                    server.url + "/redirect",
                    body=b"abc",
                    redirect_policy=RedirectPolicy.limited(1),
                    transfer_control=control,
                ) as response,
            ):
                self.assertEqual(response.redirects_followed, 1)
                self.assertEqual(response.read(max_bytes=5), b"hello")
            self.assertEqual(
                server.requests, [("/redirect", b"abc"), ("/final", b"abc")]
            )
        self.assertEqual(control.snapshot(), TransferSnapshot(6, 6, 5, 5, 5))
        self.assertEqual(independent.snapshot(), TransferSnapshot(0, 0, 0, 0, 0))

    def test_gzip_encoded_cap_and_decoded_counters_preserve_remaining_cursor(self):
        control = TransferControl(limits=TransferLimits(download_bytes=len(GZIP)))
        with peer() as server:
            server.RequestHandlerClass = DecodingHandler
            with Client(**OPTIONS) as client:
                with client.request(
                    "GET",
                    server.url,
                    headers=[("Accept-Encoding", "gzip")],
                    content_decoding=ContentDecoding.advertised(5),
                    transfer_control=control,
                ) as response:
                    chunks = response.iter_bytes(1)
                    try:
                        self.assertEqual(next(chunks), PAYLOAD[:1])
                        counts = control.snapshot()
                        self.assertEqual(counts.download_encoded_bytes, len(GZIP))
                        self.assertGreaterEqual(counts.download_decoded_bytes, 1)
                        self.assertLessEqual(
                            counts.download_decoded_bytes, len(PAYLOAD)
                        )
                        self.assertEqual(b"".join(chunks), PAYLOAD[1:])
                    finally:
                        chunks.close()
                counts = control.snapshot()
                self.assertEqual(counts.download_reserved_bytes, len(GZIP))
                self.assertEqual(counts.download_decoded_bytes, len(PAYLOAD))
                rejected = TransferControl(limits=TransferLimits(download_bytes=0))
                with client.request(
                    "GET", server.url, transfer_control=rejected
                ) as response:
                    with self.assertRaises(Error) as caught:
                        response.read(max_bytes=100)
                    self.assertEqual(caught.exception.kind, "transfer")
                    self.assertEqual(caught.exception.protocol, "h1")
                    self.assertEqual(response.read(max_bytes=100), b"")
                self.assertEqual(rejected.snapshot(), TransferSnapshot(0, 0, 0, 0, 0))


class TransferAsyncTests(unittest.IsolatedAsyncioTestCase):
    async def test_upload_cap_preserves_typed_error_and_closes_producer(self):
        class Source:
            pulls = 0
            closed = False

            def __aiter__(self):
                return self

            async def __anext__(self):
                self.pulls += 1
                if self.pulls == 1:
                    return b"abc"
                raise StopAsyncIteration

            async def aclose(self):
                self.closed = True

        source = Source()
        control = TransferControl(limits=TransferLimits(upload_bytes=0))
        with peer() as server:
            server.RequestHandlerClass = ReplayHandler
            async with AsyncClient(**OPTIONS) as client:
                with self.assertRaises(Error) as caught:
                    await client.request(
                        "POST",
                        server.url + "/final",
                        body=source,
                        body_length=3,
                        transfer_control=control,
                    )
                self.assertEqual(caught.exception.kind, "transfer")
                self.assertTrue(source.closed)
                self.assertGreaterEqual(source.pulls, 1)
                self.assertEqual(control.snapshot(), TransferSnapshot(0, 0, 0, 0, 0))
                healthy = await client.request("GET", server.url + "/healthy")
                self.assertEqual(await healthy.read(max_bytes=5), b"hello")

    async def test_concurrent_requests_share_one_cap_across_independent_clients(self):
        control = TransferControl(limits=TransferLimits(download_bytes=5))
        with peer() as server:
            async with (
                AsyncClient(**OPTIONS) as first,
                AsyncClient(**OPTIONS) as second,
            ):

                async def read(client):
                    response = await client.request(
                        "GET", server.url, transfer_control=control
                    )
                    async with response:
                        return await response.read(max_bytes=5)

                results = await asyncio.gather(
                    read(first), read(second), return_exceptions=True
                )
                self.assertEqual(results.count(b"hello"), 1)
                failures = [result for result in results if isinstance(result, Error)]
                self.assertEqual(len(failures), 1, results)
                self.assertEqual(failures[0].kind, "transfer")
                self.assertEqual(control.snapshot(), TransferSnapshot(0, 0, 5, 5, 5))
                with self.assertRaises(TypeError):
                    await first.request("GET", server.url, transfer_control={})
            self.assertEqual(len(server.requests), 2)

    async def test_cancel_paced_body_retains_reservation_and_live_h2_sibling(self):
        control = TransferControl(limits=TransferLimits(download_bytes_per_second=1))
        with H2Peer(overflow_body=b"x" * 8192) as server:
            async with AsyncClient(
                profile=PROFILE, protocol="h2", timeout_ms=5000
            ) as client:
                selected = await client.request(
                    "GET",
                    server.url + "/overflow",
                    transfer_control=control,
                    timeouts=TimeoutOverrides(total=None),
                )
                healthy = await client.request("GET", server.url + "/healthy")
                other = asyncio.create_task(healthy.read(max_bytes=5))
                pending = asyncio.create_task(selected.read(max_bytes=65536))

                async def reserved():
                    # The core exposes counters, without a notification callback.
                    while control.snapshot().download_reserved_bytes == 0:  # noqa: ASYNC110
                        await asyncio.sleep(0)

                try:
                    await asyncio.wait_for(reserved(), 5)
                    before = control.snapshot()
                    self.assertEqual(before.download_encoded_bytes, 0)
                    self.assertEqual(before.download_decoded_bytes, 0)
                    self.assertFalse(pending.done())
                    self.assertFalse(other.done())
                    pending.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await pending
                    self.assertTrue(await asyncio.to_thread(server.reset.wait, 5))
                    self.assertEqual(server.reset_code, 8)
                    self.assertEqual(server.reset_stream, server.requests[0][0])
                    self.assertEqual(await other, b"hello")
                    self.assertEqual(control.snapshot(), before)
                    self.assertIsNone(await selected.read_chunk())
                    reused = await client.request("GET", server.url + "/reuse")
                    self.assertEqual(await reused.read(max_bytes=5), b"hello")
                    self.assertEqual(len(server.requests), 3)
                finally:
                    pending.cancel()
                    other.cancel()
                    await asyncio.gather(pending, other, return_exceptions=True)
                    await selected.aclose()
                    await healthy.aclose()
        self.assertFalse(server.premature_close)
