"""Core multipart encoding against independent HTTP/1 and HTTP/2 peers."""

import asyncio
import tempfile
import unittest
from pathlib import Path

from phantom_http import (
    AsyncClient,
    AttemptBudget,
    Client,
    Error,
    MultipartPart,
    PreparedBodyError,
    RedirectPolicy,
    StreamingMultipartBody,
    TimeoutError,
    TimeoutOverrides,
    UploadError,
)
from test_request_bodies import Handler
from test_upload_http2 import Peer as H2Peer
from test_uploads import PROFILE, server


class Source:
    def __init__(self, values=(), failure=None):
        self.values = iter(values)
        self.failure = failure
        self.pulls = 0
        self.closes = 0
        self.closed = asyncio.Event()

    def __aiter__(self):
        return self

    async def __anext__(self):
        self.pulls += 1
        if self.failure is not None:
            raise self.failure
        try:
            return next(self.values)
        except StopIteration:
            raise StopAsyncIteration from None

    async def aclose(self):
        self.closes += 1
        self.closed.set()


def streamed(source, maximum=4096, later=None):
    parts = [MultipartPart.stream("tag", source)]
    if later is not None:
        parts.append(MultipartPart.stream("later", later))
    return StreamingMultipartBody(parts, boundary="B", maximum_bytes=maximum)


class AbortedHandler(Handler):
    def do_POST(self):
        self.connection.settimeout(5)
        self.server.records.append(("aborted", self.path))
        self.close_connection = True
        while True:
            line = self.rfile.readline()
            if not line:
                return
            length = int(line.split(b";", 1)[0], 16)
            if length == 0:
                raise AssertionError("failed multipart completed its chunked body")
            if len(self.read_exact(length)) != length or self.read_exact(2) != b"\r\n":
                raise AssertionError("invalid chunk before multipart failure")


class StreamingMultipartTests(unittest.IsolatedAsyncioTestCase):
    async def test_mixed_fields_preserve_literal_wire_bytes_and_content_type_position(
        self,
    ):
        source = Source([b"stream\x00", b"\xff"])
        expected = (
            b'--B\r\nContent-Disposition: form-data; name="tag"\r\n\r\none\r\ntwo\r\n'
            b'--B\r\nContent-Disposition: form-data; name="tag"\r\n'
            b"Content-Type: application/octet-stream\r\n\r\n\x00\xff\r\n"
            b'--B\r\nContent-Disposition: form-data; name="tag"; filename="a%22.bin"\r\n'
            b"Content-Type: application/octet-stream\r\n\r\nstream\x00\xff\r\n"
            b'--B\r\nContent-Disposition: form-data; name="disk"; filename="data.bin"\r\n'
            b"Content-Type: Text/Plain\r\n\r\nfile\r\n--B--\r\n"
        )
        with tempfile.TemporaryDirectory() as temporary, server(Handler) as (peer, url):
            path = Path(temporary) / "payload"
            path.write_bytes(b"file")
            body = StreamingMultipartBody(
                [
                    MultipartPart("tag", "one\ntwo"),
                    MultipartPart("tag", b"\x00\xff"),
                    MultipartPart.stream("tag", source, filename='a".bin'),
                    MultipartPart.file(
                        "disk", path, filename="data.bin", content_type="Text/Plain"
                    ),
                ],
                boundary="B",
                maximum_bytes=len(expected),
            )
            async with AsyncClient(
                profile=PROFILE, protocol="h1", context="raw"
            ) as client:
                response = await client.request(
                    "POST",
                    url,
                    body=body,
                    headers=[
                        ("X-Before", "1"),
                        ("Content-Type", body.content_type),
                        ("X-After", "2"),
                    ],
                )
                self.assertEqual(await response.read(max_bytes=0), b"")
            fields = peer.records[0][2]
            self.assertEqual(peer.records[0][3], expected)
            position = [name for name, _ in fields].index("Content-Type")
            self.assertEqual(
                [name for name, _ in fields][position - 1 : position + 2],
                ["X-Before", "Content-Type", "X-After"],
            )
            self.assertIn(("Transfer-Encoding", "chunked"), fields)
            self.assertFalse(
                any(name.lower() == "content-length" for name, _ in fields)
            )
        self.assertEqual(source.closes, 1)

    async def test_file_is_not_opened_until_the_earlier_source_finishes(self):
        entered, release = asyncio.Event(), asyncio.Event()

        class Held(Source):
            async def __anext__(self):
                entered.set()
                await release.wait()
                raise StopAsyncIteration

        first = Held()
        with tempfile.TemporaryDirectory() as temporary, server(Handler) as (peer, url):
            path = Path(temporary) / "created-after-demand"
            body = StreamingMultipartBody(
                [
                    MultipartPart.stream("first", first),
                    MultipartPart.file("file", path),
                ],
                boundary="B",
                maximum_bytes=4096,
            )
            async with AsyncClient(
                profile=PROFILE, protocol="h1", context="raw", timeout_ms=5000
            ) as client:
                request = asyncio.create_task(
                    client.request(
                        "POST",
                        url,
                        body=body,
                        headers=[("Content-Type", body.content_type)],
                    )
                )
                try:
                    await asyncio.wait_for(entered.wait(), 2)
                    self.assertFalse(path.exists())
                    path.write_bytes(b"opened-later")
                    release.set()
                    response = await request
                    await response.read(max_bytes=0)
                    self.assertIn(b"opened-later", peer.records[0][3])
                finally:
                    release.set()
                    request.cancel()
                    await asyncio.gather(request, return_exceptions=True)
        self.assertEqual(first.closes, 1)

    async def test_encoded_cap_and_split_boundary_collision_abort_all_sources(self):
        expected = (
            b'--B\r\nContent-Disposition: form-data; name="tag"\r\n'
            b"Content-Type: application/octet-stream\r\n\r\npayload\r\n--B--\r\n"
        )
        for values, maximum, kind in (
            ([b"payload"], len(expected) - 1, "too_large"),
            ([b"--", b"B"], 4096, "boundary_collision"),
        ):
            with self.subTest(kind=kind), server(AbortedHandler) as (_, url):
                source, later = Source(values), Source()
                body = streamed(source, maximum)
                # Keep a later owned source in the collision case; the cap oracle
                # above is the independently serialized one-part body.
                if kind == "boundary_collision":
                    body = streamed(source, maximum, later)
                async with AsyncClient(
                    profile=PROFILE, protocol="h1", context="raw"
                ) as client:
                    with self.assertRaises(PreparedBodyError) as caught:
                        await client.request(
                            "POST",
                            url,
                            body=body,
                            headers=[("Content-Type", body.content_type)],
                        )
                    self.assertEqual(caught.exception.kind, kind)
                self.assertEqual(source.closes, 1)
                if kind == "boundary_collision":
                    self.assertEqual((later.pulls, later.closes), (0, 1))

    async def test_invalid_placement_and_zero_total_fail_before_attempt_and_pull(self):
        for mode in ("missing", "mismatch", "zero"):
            with self.subTest(mode=mode), server(Handler) as (peer, url):
                source, later = Source(), Source()
                body = streamed(source, later=later)
                budget = AttemptBudget(1)
                headers = (
                    []
                    if mode == "missing"
                    else [
                        (
                            "Content-Type",
                            "wrong" if mode == "mismatch" else body.content_type,
                        )
                    ]
                )
                async with AsyncClient(
                    profile=PROFILE, protocol="h1", context="raw"
                ) as client:
                    with self.assertRaises(Error) as caught:
                        await client.request(
                            "POST",
                            url,
                            body=body,
                            headers=headers,
                            budget=budget,
                            timeouts=TimeoutOverrides(total=0)
                            if mode == "zero"
                            else None,
                        )
                    self.assertEqual(
                        caught.exception.kind,
                        "timeout" if mode == "zero" else "invalid_header",
                    )
                self.assertEqual(budget.remaining, 1)
                self.assertEqual(peer.records, [])
                self.assertEqual((source.pulls, later.pulls), (0, 0))
                self.assertEqual((source.closes, later.closes), (1, 1))

    async def test_source_failure_preserves_original_and_closes_later_source(self):
        original = RuntimeError("private multipart source")

        class Failed(Source):
            async def __anext__(self):
                if self.pulls:
                    raise original
                return await super().__anext__()

        first, later = Failed([b"payload"]), Source()
        body = streamed(first, later=later)
        with server(AbortedHandler) as (_, url):
            async with AsyncClient(
                profile=PROFILE, protocol="h1", context="raw"
            ) as client:
                with self.assertRaises(UploadError) as caught:
                    await client.request(
                        "POST",
                        url,
                        body=body,
                        headers=[("Content-Type", body.content_type)],
                    )
                self.assertIs(caught.exception.original, original)
                self.assertNotIn("private", str(caught.exception))
        self.assertEqual((first.closes, later.closes, later.pulls), (1, 1, 0))

    async def test_redirect_refuses_to_replay_and_early_final_closes_unstarted_sources(
        self,
    ):
        with server(Handler) as (peer, url):
            async with AsyncClient(
                profile=PROFILE, protocol="h1", context="raw"
            ) as client:
                source = Source([b"payload"])
                body = streamed(source)
                budget = AttemptBudget(2)
                with self.assertRaises(Error) as caught:
                    await client.request(
                        "POST",
                        url + "/redirect",
                        body=body,
                        headers=[("Content-Type", body.content_type)],
                        budget=budget,
                        redirect_policy=RedirectPolicy.limited(1),
                    )
                self.assertEqual(caught.exception.kind, "request_body")
                self.assertEqual(budget.remaining, 1)
                self.assertEqual(source.closes, 1)
                self.assertEqual([entry[1] for entry in peer.records], ["/redirect"])
                first, later = Source([b"unused"]), Source()
                body = streamed(first, later=later)
                response = await client.request(
                    "POST",
                    url + "/early",
                    body=body,
                    headers=[("Content-Type", body.content_type)],
                    expect_continue_ms=5000,
                )
                self.assertEqual(response.status, 417)
                await response.aclose()
                self.assertEqual((first.closes, later.closes), (1, 1))
                self.assertLessEqual(first.pulls, 1)
                self.assertEqual(later.pulls, 0)

    async def test_http2_cancel_and_unread_total_preserve_live_sibling(self):
        for early in (False, True):
            with self.subTest(early=early), H2Peer() as peer:
                first, later = Source([b"U" * 1024]), Source()
                body = streamed(first, later=later)
                async with AsyncClient(
                    profile=PROFILE, protocol="h2", context="raw", timeout_ms=5000
                ) as client:
                    warm = await client.request("GET", peer.url + "/warmup")
                    self.assertEqual(await warm.read(max_bytes=5), b"hello")
                    request = asyncio.create_task(
                        client.request(
                            "POST",
                            peer.url + ("/early" if early else "/upload"),
                            body=body,
                            headers=[("content-type", body.content_type)],
                            timeouts=TimeoutOverrides(total=1 if early else None),
                        )
                    )
                    try:
                        self.assertTrue(await asyncio.to_thread(peer.selected.wait, 5))
                        healthy = await client.request(
                            "GET",
                            peer.url + "/healthy",
                            timeouts=TimeoutOverrides(total=None),
                        )
                        if early:
                            response = await request
                            # No read or close drives the selected total deadline.
                            await asyncio.wait_for(later.closed.wait(), 5)
                            with self.assertRaises(TimeoutError) as caught:
                                await response.read(max_bytes=5)
                            self.assertEqual(caught.exception.timeout_phase, "total")
                        else:
                            request.cancel()
                            with self.assertRaises(asyncio.CancelledError):
                                await request
                        self.assertTrue(await asyncio.to_thread(peer.reset.wait, 5))
                        self.assertEqual(
                            (peer.reset_stream, peer.reset_code),
                            (peer.requests[1][0], 8),
                        )
                        self.assertEqual(await healthy.read(max_bytes=5), b"hello")
                        self.assertEqual(peer.data_bytes, 0)
                        self.assertNotIn(b"content-length", peer.requests[1][2])
                        self.assertEqual((first.closes, later.closes), (1, 1))
                        self.assertEqual(later.pulls, 0)
                        reuse = await client.request("GET", peer.url + "/reuse")
                        self.assertEqual(await reuse.read(max_bytes=5), b"hello")
                    finally:
                        request.cancel()
                        await asyncio.gather(request, return_exceptions=True)


class SyncMultipartTests(unittest.TestCase):
    def test_sync_source_closes_and_unknown_length_uses_chunked(self):
        class Sync:
            closes = 0

            def __init__(self):
                self.values = iter([b"one", b"two"])

            def __iter__(self):
                return self

            def __next__(self):
                return next(self.values)

            def close(self):
                self.closes += 1

        source = Sync()
        body = streamed(source)
        with (
            server(Handler) as (peer, url),
            Client(profile=PROFILE, protocol="h1", context="raw") as client,
        ):
            with client.request(
                "POST", url, body=body, headers=[("Content-Type", body.content_type)]
            ) as response:
                self.assertEqual(response.read(max_bytes=0), b"")
            self.assertEqual(
                peer.records[0][3],
                b'--B\r\nContent-Disposition: form-data; name="tag"\r\n'
                b"Content-Type: application/octet-stream\r\n\r\nonetwo\r\n--B--\r\n",
            )
        self.assertEqual(source.closes, 1)
