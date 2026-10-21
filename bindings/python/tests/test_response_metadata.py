"""Core response metadata survives body reads without enabling redirect policies."""

import types
import unittest

from phantom_http import AsyncClient, AsyncResponse, Client, Response, ResponseHeader
from test_client import OPTIONS, server


class MetadataFacadeTests(unittest.TestCase):
    def test_sync_and_async_properties_forward_actual_values_without_mutating_headers(
        self,
    ):
        headers = [("x-duplicate", b"one", False), ("x-duplicate", b"two", True)]
        native = types.SimpleNamespace(
            status=200,
            protocol="h2",
            headers=headers,
            url="https://origin.invalid/final?encoded=%2F",
            redirects_followed=2,
            connection_setup_retries=3,
        )
        asynchronous = AsyncResponse(native)
        synchronous = Response(None, asynchronous)
        for response in (asynchronous, synchronous):
            self.assertEqual(response.url, native.url)
            self.assertEqual(response.redirects_followed, 2)
            self.assertEqual(response.connection_setup_retries, 3)
            self.assertEqual(
                response.headers,
                tuple(ResponseHeader(*field) for field in headers),
            )
            with self.assertRaises(AttributeError):
                response.url = "different"
            with self.assertRaises(AttributeError):
                response.redirects_followed = 0
            with self.assertRaises(AttributeError):
                response.connection_setup_retries = 0


class SyncMetadataTests(unittest.TestCase):
    def test_default_redirect_is_not_followed_and_metadata_survives_partial_close(self):
        with server() as (peer, origin), Client(**OPTIONS) as client:
            url = origin + "/redirect?encoded=%2F&x=1&x=2"
            response = client.request("GET", url)
            chunks = response.iter_bytes(2)
            try:
                self.assertEqual(response.status_code, 302)
                self.assertEqual(response.url, url)
                self.assertEqual(response.redirects_followed, 0)
                self.assertEqual(response.connection_setup_retries, 0)
                self.assertEqual(next(chunks), b"he")
            finally:
                try:
                    chunks.close()
                finally:
                    response.close()
            self.assertEqual(response.url, url)
            self.assertEqual(response.redirects_followed, 0)
            self.assertEqual(response.connection_setup_retries, 0)
        self.assertEqual(
            [request[0] for request in peer.requests], [url.removeprefix(origin)]
        )


class AsyncMetadataTests(unittest.IsolatedAsyncioTestCase):
    async def test_effective_joined_url_and_default_counts_survive_body_completion(
        self,
    ):
        with server() as (peer, origin):
            async with (
                AsyncClient(**OPTIONS, base_url=origin + "/base/") as client,
                await client.request("GET", "../redirect?encoded=%2F") as response,
            ):
                self.assertEqual(response.status_code, 302)
                self.assertEqual(response.url, origin + "/redirect?encoded=%2F")
                self.assertEqual(response.redirects_followed, 0)
                self.assertEqual(response.connection_setup_retries, 0)
                self.assertEqual(await response.read(max_bytes=5), b"hello")
                self.assertEqual(response.url, origin + "/redirect?encoded=%2F")
        self.assertEqual(
            [request[0] for request in peer.requests], ["/redirect?encoded=%2F"]
        )
